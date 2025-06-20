// Package framework provides a comprehensive E2E testing framework for SSHPiper
package framework

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestFramework provides utilities for E2E testing
type TestFramework struct {
	t           *testing.T
	tempDir     string
	sshPiperCmd *exec.Cmd
	sshPiperPort int
	plugins     map[string]*PluginInstance
}

// PluginInstance represents a running plugin
type PluginInstance struct {
	Name    string
	Binary  string
	Args    []string
	Cmd     *exec.Cmd
	DataDir string
}

// NewTestFramework creates a new test framework instance
func NewTestFramework(t *testing.T) *TestFramework {
	tempDir, err := os.MkdirTemp("", "sshpiper-e2e-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	return &TestFramework{
		t:           t,
		tempDir:     tempDir,
		sshPiperPort: getFreePort(),
		plugins:     make(map[string]*PluginInstance),
	}
}

// Cleanup cleans up all resources
func (f *TestFramework) Cleanup() {
	// Stop SSHPiper
	if f.sshPiperCmd != nil && f.sshPiperCmd.Process != nil {
		f.sshPiperCmd.Process.Kill()
		f.sshPiperCmd.Wait()
	}

	// Stop all plugins
	for _, plugin := range f.plugins {
		if plugin.Cmd != nil && plugin.Cmd.Process != nil {
			plugin.Cmd.Process.Kill()
			plugin.Cmd.Wait()
		}
	}

	// Clean up temp directory
	os.RemoveAll(f.tempDir)
}

// StartSSHPiper starts the main SSHPiper daemon
func (f *TestFramework) StartSSHPiper(pluginNames ...string) error {
	args := []string{
		"--address", "127.0.0.1",
		"--port", fmt.Sprintf("%d", f.sshPiperPort),
		"--log-level", "debug",
	}

	// Add plugin arguments
	for _, name := range pluginNames {
		plugin, ok := f.plugins[name]
		if !ok {
			return fmt.Errorf("plugin %s not registered", name)
		}
		args = append(args, plugin.Binary)
		args = append(args, plugin.Args...)
		if len(pluginNames) > 1 {
			args = append(args, "--")
		}
	}

	f.sshPiperCmd = exec.Command("./bin/sshpiperd", args...)
	f.sshPiperCmd.Stdout = os.Stdout
	f.sshPiperCmd.Stderr = os.Stderr

	if err := f.sshPiperCmd.Start(); err != nil {
		return fmt.Errorf("failed to start sshpiperd: %v", err)
	}

	// Wait for SSHPiper to be ready
	return f.waitForPort(f.sshPiperPort, 10*time.Second)
}

// RegisterPlugin registers a plugin for use in tests
func (f *TestFramework) RegisterPlugin(name, binary string, args ...string) *PluginInstance {
	dataDir := filepath.Join(f.tempDir, name)
	os.MkdirAll(dataDir, 0755)

	plugin := &PluginInstance{
		Name:    name,
		Binary:  binary,
		Args:    args,
		DataDir: dataDir,
	}

	f.plugins[name] = plugin
	return plugin
}

// CreateSSHKeyPair creates an SSH key pair for testing
func (f *TestFramework) CreateSSHKeyPair() (privateKey []byte, publicKey []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Private key
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	privateKey = pem.EncodeToMemory(privateKeyPEM)

	// Public key
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	publicKey = ssh.MarshalAuthorizedKey(pub)

	return privateKey, publicKey, nil
}

// TempDir returns the temp directory for this framework
func (f *TestFramework) TempDir() string {
	return f.tempDir
}

// Contains checks if str contains substr
func (f *TestFramework) Contains(str, substr string) bool {
	return strings.Contains(str, substr)
}

// CreateDockerContainer creates a test Docker container (placeholder)
func (f *TestFramework) CreateDockerContainer(t *testing.T, labels map[string]string) string {
	// This is a placeholder - real implementation would use Docker API
	return "test-container-id"
}

// RemoveDockerContainer removes a test Docker container (placeholder)
func (f *TestFramework) RemoveDockerContainer(containerID string) {
	// This is a placeholder - real implementation would use Docker API
}

// KubectlApply applies Kubernetes YAML (placeholder)
func (f *TestFramework) KubectlApply(yaml string) error {
	// This is a placeholder - real implementation would use kubectl or K8s client
	return nil
}

// Kubeconfig returns the path to kubeconfig (placeholder)
func (f *TestFramework) Kubeconfig() string {
	return filepath.Join(f.tempDir, "kubeconfig")
}

// HostKey represents an SSH host key
type HostKey struct {
	PrivateKey []byte
	PublicKey  []byte
}

// GenerateHostKey generates an SSH host key for testing
func (f *TestFramework) GenerateHostKey(t *testing.T) *HostKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate host key: %v", err)
	}

	// Private key
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	privateKey := pem.EncodeToMemory(privateKeyPEM)

	// Public key
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create public key: %v", err)
	}
	publicKey := ssh.MarshalAuthorizedKey(pub)

	return &HostKey{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
}

// CreateUpstreamServerWithHostKey creates an SSH server with specific host key
func (f *TestFramework) CreateUpstreamServerWithHostKey(t *testing.T, port int, hostKey *HostKey, users map[string]string) *SSHServer {
	server := &SSHServer{
		Port:     port,
		Users:    users,
		Commands: make(map[string]string),
		HostKey:  hostKey,
	}

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	return server
}

// CAKey represents a CA key for certificate testing
type CAKey struct {
	PrivateKey []byte
	PublicKey  []byte
}

// GenerateCAAndUserCert generates a CA key and user certificate
func (f *TestFramework) GenerateCAAndUserCert(t *testing.T, username string) (*CAKey, ssh.Signer) {
	// Generate CA key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	caSigner, err := ssh.NewSignerFromKey(caKey)
	if err != nil {
		t.Fatalf("Failed to create CA signer: %v", err)
	}

	// Generate user key
	userKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate user key: %v", err)
	}

	userPub, err := ssh.NewPublicKey(&userKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create user public key: %v", err)
	}

	// Create certificate
	cert := &ssh.Certificate{
		Key:         userPub,
		CertType:    ssh.UserCert,
		KeyId:       username,
		ValidBefore: ssh.CertTimeInfinity,
		ValidAfter:  0,
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("Failed to sign certificate: %v", err)
	}

	// Create certified signer
	userSigner, err := ssh.NewSignerFromKey(userKey)
	if err != nil {
		t.Fatalf("Failed to create user signer: %v", err)
	}
	
	certSigner, err := ssh.NewCertSigner(cert, userSigner)
	if err != nil {
		t.Fatalf("Failed to create cert signer: %v", err)
	}

	caPublicKey := ssh.MarshalAuthorizedKey(caSigner.PublicKey())
	
	return &CAKey{
		PrivateKey: pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(caKey),
		}),
		PublicKey: caPublicKey,
	}, certSigner
}

// WriteFile writes a file to the temp directory
func (f *TestFramework) WriteFile(path string, content []byte) error {
	fullPath := filepath.Join(f.tempDir, path)
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(fullPath, content, 0600)
}

// ConnectSSH connects to SSHPiper with the given config
func (f *TestFramework) ConnectSSH(user string, auth ssh.AuthMethod) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	addr := fmt.Sprintf("127.0.0.1:%d", f.sshPiperPort)
	return ssh.Dial("tcp", addr, config)
}

// RunCommand runs a command via SSH and returns output
func (f *TestFramework) RunCommand(client *ssh.Client, cmd string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	output, err := session.CombinedOutput(cmd)
	return string(output), err
}

// CreateUpstreamServer creates a test SSH server
func (f *TestFramework) CreateUpstreamServer(port int, users map[string]string) (*SSHServer, error) {
	server := &SSHServer{
		Port:     port,
		Users:    users,
		Commands: make(map[string]string),
	}

	if err := server.Start(); err != nil {
		return nil, err
	}

	return server, nil
}

// SSHServer represents a test SSH server
type SSHServer struct {
	Port           int
	Users          map[string]string // username -> password
	Commands       map[string]string // command -> response
	AuthorizedKeys map[string][]byte // username -> authorized keys
	HostKey        *HostKey
	listener       net.Listener
}

// Start starts the SSH server
func (s *SSHServer) Start() error {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if expectedPass, ok := s.Users[c.User()]; ok && expectedPass == string(pass) {
				return &ssh.Permissions{
					Extensions: map[string]string{
						"user": c.User(),
					},
				}, nil
			}
			return nil, fmt.Errorf("invalid credentials")
		},
	}

	// Use provided host key or generate one
	var signer ssh.Signer
	if s.HostKey != nil {
		key, err := ssh.ParsePrivateKey(s.HostKey.PrivateKey)
		if err != nil {
			return err
		}
		signer = key
	} else {
		// Generate host key
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		signer, err = ssh.NewSignerFromKey(key)
		if err != nil {
			return err
		}
	}
	config.AddHostKey(signer)

	// Start listening
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.Port))
	if err != nil {
		return err
	}
	s.listener = listener

	go s.acceptConnections(config)
	return nil
}

// Stop stops the SSH server
func (s *SSHServer) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *SSHServer) acceptConnections(config *ssh.ServerConfig) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConnection(conn, config)
	}
}

func (s *SSHServer) handleConnection(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		go s.handleChannel(channel, requests)
	}
}

func (s *SSHServer) handleChannel(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "exec":
			cmd := string(req.Payload[4:])
			req.Reply(true, nil)

			// Check if we have a predefined response
			if response, ok := s.Commands[cmd]; ok {
				io.WriteString(channel, response)
			} else {
				io.WriteString(channel, fmt.Sprintf("Command executed: %s\n", cmd))
			}
			channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			return

		case "shell":
			req.Reply(true, nil)
			io.WriteString(channel, "Test SSH Server\n$ ")
			// Simple echo shell
			buf := make([]byte, 1024)
			for {
				n, err := channel.Read(buf)
				if err != nil {
					return
				}
				channel.Write(buf[:n])
			}

		default:
			req.Reply(false, nil)
		}
	}
}

// Helper functions

func getFreePort() int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func (f *TestFramework) waitForPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for port %d", port)
}

// AssertNoError fails the test if err is not nil
func (f *TestFramework) AssertNoError(err error, msg string) {
	if err != nil {
		f.t.Fatalf("%s: %v", msg, err)
	}
}

// AssertEqual fails the test if expected != actual
func (f *TestFramework) AssertEqual(expected, actual interface{}, msg string) {
	if expected != actual {
		f.t.Fatalf("%s: expected %v, got %v", msg, expected, actual)
	}
}

// AssertContains fails the test if str doesn't contain substr
func (f *TestFramework) AssertContains(str, substr, msg string) {
	if !strings.Contains(str, substr) {
		f.t.Fatalf("%s: %q does not contain %q", msg, str, substr)
	}
}