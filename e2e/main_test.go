// run with docker-compose up --build --abort-on-container-exit

package e2e_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

const testprivatekey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDURkx99uaw1KddraZcLpB5kfMrWwvUz2fPOoArLcpz9QAAAJC+j0+Svo9P
kgAAAAtzc2gtZWQyNTUxOQAAACDURkx99uaw1KddraZcLpB5kfMrWwvUz2fPOoArLcpz9Q
AAAEDcQgdh2z2r/6blq0ziJ1l6s6IAX8C+9QHfAH931cHNO9RGTH325rDUp12tplwukHmR
8ytbC9TPZ886gCstynP1AAAADWJvbGlhbkB1YnVudHU=
-----END OPENSSH PRIVATE KEY-----
`

const testpublickey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINRGTH325rDUp12tplwukHmR8ytbC9TPZ886gCstynP1`

const waitTimeout = time.Second * 10

func waitForEndpointReady(addr string) {
	waitForEndpointReadyWithTimeout(addr, waitTimeout)
}

func waitForEndpointReadyWithTimeout(addr string, timeout time.Duration) {
	now := time.Now()
	timeout = max(timeout, waitTimeout)
	for {
		if time.Since(now) > timeout {
			log.Panic("timeout waiting for endpoint " + addr)
		}

		conn, err := net.Dial("tcp", addr)
		if err == nil {
			log.Printf("endpoint %s is ready", addr)
			if err := conn.Close(); err != nil {
				log.Printf("failed to close conn: %v", err)
			}
			break
		}
		time.Sleep(time.Second)
	}
}

func runCmd(cmd string, args ...string) (*exec.Cmd, io.Writer, io.Reader, error) {
	newargs := append([]string{cmd}, args...)
	newargs = append([]string{"-i0", "-o0", "-e0"}, newargs...)
	c := exec.Command("stdbuf", newargs...)
	c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	f, err := pty.Start(c)
	if err != nil {
		return nil, nil, nil, err
	}

	var buf bytes.Buffer
	r := io.TeeReader(f, &buf)
	go func() {
		_, _ = io.Copy(os.Stdout, r)
	}()

	log.Printf("starting %v", c.Args)

	return c, f, &buf, nil
}

func runCmdAndWait(cmd string, args ...string) error {
	c, _, _, err := runCmd(cmd, args...)
	if err != nil {
		return err
	}

	return c.Wait()
}

func waitForStdoutContains(stdout io.Reader, text string, cb func(string)) {
	st := time.Now()
	for {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, text) {
				cb(line)
				return
			}
		}

		if time.Since(st) > waitTimeout {
			log.Panicf("timeout waiting for [%s] from prompt", text)
			return
		}

		time.Sleep(time.Second) // stdout has no data yet
	}
}

func enterPassword(stdin io.Writer, stdout io.Reader, password string) {
	waitForStdoutContains(stdout, "'s password", func(_ string) {
		_, _ = fmt.Fprintf(stdin, "%v\n", password)
		log.Printf("got password prompt, sending password")
	})
}

func checkSharedFileContent(t *testing.T, targetfie string, expected string) {
	f, err := os.Open(fmt.Sprintf("/shared/%v", targetfie))
	if err != nil {
		t.Errorf("failed to open shared file, %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("failed to close file: %v", err)
		}
	}()

	b, err := io.ReadAll(f)
	if err != nil {
		t.Errorf("failed to read shared file, %v", err)
	}

	if string(b) != expected {
		t.Errorf("shared file content mismatch, expected %v, got %v", expected, string(b))
	}
}

func killCmd(c *exec.Cmd) {
	if c.Process != nil {
		if err := c.Process.Kill(); err != nil {
			log.Printf("failed to kill ssh process, %v", err)
		}
	}
}

func runAndGetStdout(cmd string, args ...string) ([]byte, error) {
	c, _, stdout, err := runCmd(cmd, args...)

	if err != nil {
		return nil, err
	}

	if err := c.Wait(); err != nil {
		return nil, err
	}

	return io.ReadAll(stdout)
}

func nextAvaliablePort() int {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Panic(err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			log.Printf("failed to close listener: %v", err)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func nextAvailablePiperAddress() (string, string) {
	port := strconv.Itoa(nextAvaliablePort())
	return net.JoinHostPort("127.0.0.1", (port)), port
}

func TestMain(m *testing.M) {

	if os.Getenv("SSHPIPERD_E2E_TEST") != "1" {
		log.Printf("skipping e2e test")
		os.Exit(0)
		return
	}

	_ = runCmdAndWait("ssh", "-V")

	for _, ep := range []string{
		"host-password:2222",
		"host-publickey:2222",
	} {
		waitForEndpointReady(ep)
	}

	os.Exit(m.Run())
}

// SSHTestParams defines all parameters for a flexible SSH test.
type SSHTestParams struct {
	T                *testing.T
	PiperPort        string
	Username         string
	Host             string // e.g. 127.0.0.1
	KeyPath          string // private key path
	IdentitiesOnly   bool
	Command          string       // command to run
	Password         string       // password for password auth
	PasswordRequired bool         // if true, always try password auth; if false, never try, even if Password is set
	WaitFor          string       // string to wait for in stdout (e.g. SSHREADY)
	StdinTrigger     string       // string to send to stdin after WaitFor
	ExpectSuccess    bool         // expect SSH to succeed
	CheckFile        bool         // check shared file content
	ExpectedText     string       // expected file content
	TargetFile       string       // shared file name
	SSHBin           string       // ssh binary (default: ssh)
	ExtraOpts        []string     // extra ssh options
	StderrCheck      func([]byte) // custom check for stderr (for negative tests)
}

// mustGenKey generates a new SSH key at keyPath, failing the test on error.
func mustGenKey(t *testing.T, keyPath string) {
	if err := runCmdAndWait("rm", "-f", keyPath); err != nil {
		t.Errorf("failed to remove key: %v", err)
	}
	if err := runCmdAndWait("ssh-keygen", "-N", "", "-f", keyPath); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
}

// mustKeyScan runs ssh-keyscan for the given host/port, failing the test on error.
func mustKeyScan(t *testing.T, port, host string) []byte {
	out, err := runAndGetStdout("ssh-keyscan", "-p", port, host)
	if err != nil {
		t.Fatalf("failed to run ssh-keyscan for %s:%s: %v", host, port, err)
	}
	return out
}

// runSSHTestUnified runs a flexible SSH test covering password, key, CA, multi-CA, and negative/positive cases.
func runSSHTestUnified(p SSHTestParams) {
	t := p.T
	sshBin := p.SSHBin
	if sshBin == "" {
		sshBin = "ssh"
	}
	args := []string{"-v", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-p", p.PiperPort, "-l", p.Username}
	if p.KeyPath != "" {
		args = append(args, "-i", p.KeyPath)
	}
	if p.IdentitiesOnly {
		args = append(args, "-o", "IdentitiesOnly=yes")
	}
	if p.ExtraOpts != nil {
		args = append(args, p.ExtraOpts...)
	}
	host := p.Host
	if host == "" {
		host = "127.0.0.1"
	}
	args = append(args, host)
	if p.Command != "" {
		args = append(args, p.Command)
	}
	c, stdin, stdout, err := runCmd(sshBin, args...)
	if p.ExpectSuccess {
		if err != nil {
			t.Errorf("failed to ssh: %v", err)
			return
		}
		defer killCmd(c)
		if p.PasswordRequired {
			enterPassword(stdin, stdout, p.Password)
		}
		if p.WaitFor != "" {
			waitForStdoutContains(stdout, p.WaitFor, func(_ string) {
				if p.StdinTrigger != "" {
					if _, err := fmt.Fprintf(stdin, "%v\n", p.StdinTrigger); err != nil {
						t.Errorf("Failed to write to stdin: %v", err)
					}
				}
			})
		}
		time.Sleep(time.Second * 3)
		if p.CheckFile {
			if p.TargetFile == "" {
				t.Errorf("TargetFile must be set when CheckFile is true")
				return
			}
			checkSharedFileContent(t, p.TargetFile, p.ExpectedText)
		}
	} else {
		if err == nil {
			killCmd(c)
			t.Errorf("Expected SSH to fail, but it succeeded")
		} else {
			out, _ := io.ReadAll(stdout)
			if p.StderrCheck != nil {
				p.StderrCheck(out)
			} else if !bytes.Contains(out, []byte("Permission denied")) && !bytes.Contains(out, []byte("no matching pipe")) {
				t.Errorf("SSH failed for unexpected reason: %s", out)
			}
		}
	}
}

// mustMkdirTemp creates a temp directory and fails the test on error.
func mustMkdirTemp(t *testing.T, dir, pattern string) string {
	d, err := os.MkdirTemp(dir, pattern)
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	return d
}
