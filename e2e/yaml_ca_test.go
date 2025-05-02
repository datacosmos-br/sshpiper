package e2e_test

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
)

const testCAPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDURkx99uaw1KddraZcLpB5kfMrWwvUz2fPOoArLcpz9QAAAJC+j0+Svo9P
kgAAAAtzc2gtZWQyNTUxOQAAACDURkx99uaw1KddraZcLpB5kfMrWwvUz2fPOoArLcpz9Q
AAAEDcQgdh2z2r/6blq0ziJ1l6s6IAX8C+9QHfAH931cHNO9RGTH325rDUp12tplwukHmR
8ytbC9TPZ886gCstynP1AAAADWJvbGlhbkB1YnVudHU=
-----END OPENSSH PRIVATE KEY-----`

const testCAPublicKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINRGTH325rDUp12tplwukHmR8ytbC9TPZ886gCstynP1`

const testYamlConfig = `
version: "1.0"
pipes:
- from:
    - username: "testuser"
      trusted_user_ca_keys_data: %s
  to:
    host: host-password:2222
    username: "user"
    ignore_hostkey: true
    private_key_data: %s
`

func TestYamlCA(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "sshpiper-ca-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create config file
	configPath := filepath.Join(tmpDir, "config.yaml")
	yamlContent := fmt.Sprintf(testYamlConfig,
		base64.StdEncoding.EncodeToString([]byte(testCAPublicKey)),
		base64.StdEncoding.EncodeToString([]byte(testprivatekey)))

	if err := os.WriteFile(configPath, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Start sshpiperd with yaml plugin
	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p", piperport,
		"/sshpiperd/plugins/yaml",
		"--config", configPath,
		"--no-check-perm")

	if err != nil {
		t.Errorf("Failed to run sshpiperd: %v", err)
	}
	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	// Generate a user certificate signed by the CA
	userKeyPath := filepath.Join(tmpDir, "user_key")
	if err := os.WriteFile(userKeyPath, []byte(testprivatekey), 0600); err != nil {
		t.Fatalf("Failed to write user key: %v", err)
	}

	caKeyPath := filepath.Join(tmpDir, "ca_key")
	if err := os.WriteFile(caKeyPath, []byte(testCAPrivateKey), 0600); err != nil {
		t.Fatalf("Failed to write CA key: %v", err)
	}

	// Generate user certificate signed by the CA
	keygen, _, _, err := runCmd("ssh-keygen",
		"-s", caKeyPath,
		"-I", "testuser",
		"-n", "testuser",
		"-V", "+1d",
		userKeyPath+".pub")

	if err != nil {
		t.Fatalf("Failed to generate user certificate: %v", err)
	}
	defer killCmd(keygen)

	// Test SSH connection with certificate
	randtext := uuid.New().String()
	targetfile := uuid.New().String()

	c, stdin, stdout, err := runCmd(
		"ssh-9.8p1",
		"-v",
		"-i", userKeyPath,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "RequestTTY=yes",
		"-p", piperport,
		"-l", "testuser",
		"127.0.0.1",
		fmt.Sprintf(`sh -c "echo SSHREADY && sleep 1 && echo -n %v > /shared/%v"`, randtext, targetfile))

	if err != nil {
		t.Errorf("Failed to ssh to piper with certificate: %v", err)
	}
	defer killCmd(c)

	waitForStdoutContains(stdout, "SSHREADY", func(_ string) {
		_, _ = stdin.Write([]byte(fmt.Sprintf("%v\n", "triggerping")))
	})

	time.Sleep(time.Second * 3) // wait for file flush

	checkSharedFileContent(t, targetfile, randtext)
}
