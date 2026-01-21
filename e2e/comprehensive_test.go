//go:build e2e
// +build e2e

package e2e

import (
	"fmt"
	"testing"
	"time"

	"github.com/tg123/sshpiper/e2e/framework"
	"golang.org/x/crypto/ssh"
)

// TestYAMLPluginE2E tests the YAML plugin end-to-end
func TestYAMLPluginE2E(t *testing.T) {
	fw := framework.NewTestFramework(t)
	defer fw.Cleanup()

	// Generate SSH keys for testing
	clientPrivKey, clientPubKey, err := fw.CreateSSHKeyPair()
	fw.AssertNoError(err, "Failed to create client SSH key pair")

	upstreamPrivKey, upstreamPubKey, err := fw.CreateSSHKeyPair()
	fw.AssertNoError(err, "Failed to create upstream SSH key pair")

	// Create YAML configuration
	yamlConfig := fmt.Sprintf(`
pipes:
  - from:
      - username: testuser
        authorized_keys_data: %s
    to:
      host: 127.0.0.1:2223
      username: upstream-user
      private_key_data: %s
`, clientPubKey, upstreamPrivKey)

	// Write YAML config
	err = fw.WriteFile("yaml-config/pipes.yaml", []byte(yamlConfig))
	fw.AssertNoError(err, "Failed to write YAML config")

	// Register YAML plugin
	fw.RegisterPlugin("yaml", "./bin/sshpiperd-yaml",
		"--config", fw.TempDir()+"/yaml-config/pipes.yaml",
		"--no-check-perm")

	// Start upstream SSH server
	upstreamServer, err := fw.CreateUpstreamServer(2223, map[string]string{
		"upstream-user": "upstream-pass",
	})
	fw.AssertNoError(err, "Failed to create upstream server")
	defer upstreamServer.Stop()

	// Add authorized key to upstream server
	upstreamServer.AuthorizedKeys = map[string][]byte{
		"upstream-user": upstreamPubKey,
	}

	// Start SSHPiper
	err = fw.StartSSHPiper("yaml")
	fw.AssertNoError(err, "Failed to start SSHPiper")

	// Connect to SSHPiper
	signer, err := ssh.ParsePrivateKey(clientPrivKey)
	fw.AssertNoError(err, "Failed to parse client private key")

	client, err := fw.ConnectSSH("testuser", ssh.PublicKeys(signer))
	fw.AssertNoError(err, "Failed to connect to SSHPiper")
	defer client.Close()

	// Run command through the tunnel
	output, err := fw.RunCommand(client, "echo hello from upstream")
	fw.AssertNoError(err, "Failed to run command")
	fw.AssertContains(output, "hello from upstream", "Unexpected command output")
}

// TestDockerPluginE2E tests the Docker plugin end-to-end
func TestDockerPluginE2E(t *testing.T) {
	fw := framework.NewTestFramework(t)
	defer fw.Cleanup()

	// This test requires Docker to be running
	// We'll create a test container with SSH enabled

	// Register Docker plugin
	fw.RegisterPlugin("docker", "./bin/sshpiperd-docker")

	// Start SSHPiper
	err := fw.StartSSHPiper("docker")
	fw.AssertNoError(err, "Failed to start SSHPiper")

	// Create a test Docker container with labels
	containerID := fw.CreateDockerContainer(t, map[string]string{
		"sshpiper.username": "testuser",
		"sshpiper.password": "testpass",
		"sshpiper.upstream": "upstream-container:22",
	})
	defer fw.RemoveDockerContainer(containerID)

	// Connect to SSHPiper with password
	client, err := fw.ConnectSSH("testuser", ssh.Password("testpass"))
	fw.AssertNoError(err, "Failed to connect to SSHPiper")
	defer client.Close()

	// Verify connection works
	output, err := fw.RunCommand(client, "hostname")
	fw.AssertNoError(err, "Failed to run command")
	fw.AssertContains(output, "upstream-container", "Unexpected hostname")
}

// TestKubernetesPluginE2E tests the Kubernetes plugin with Kind
func TestKubernetesPluginE2E(t *testing.T) {
	fw := framework.NewTestFramework(t)
	defer fw.Cleanup()

	// This test requires Kind cluster to be running
	// It should be started by make e2e-kind

	// Create a Pipe CRD
	pipeCRD := `
apiVersion: sshpiper.com/v1beta1
kind: Pipe
metadata:
  name: test-pipe
  namespace: default
spec:
  from:
    - username: testuser
      authorized_keys_data: c3NoLXJzYSBBQUFBQjN...
  to:
    host: upstream-service.default.svc.cluster.local:22
    username: upstream-user
`

	// Apply the CRD
	err := fw.KubectlApply(pipeCRD)
	fw.AssertNoError(err, "Failed to apply Pipe CRD")

	// Register Kubernetes plugin
	fw.RegisterPlugin("kubernetes", "./bin/sshpiperd-kubernetes",
		"--kubeconfig", fw.Kubeconfig())

	// Start SSHPiper
	err = fw.StartSSHPiper("kubernetes")
	fw.AssertNoError(err, "Failed to start SSHPiper")

	// Test connection would go here
	// In a real test, we'd deploy an upstream SSH service in the cluster
}

// TestMultiplePluginsE2E tests multiple plugins working together
func TestMultiplePluginsE2E(t *testing.T) {
	fw := framework.NewTestFramework(t)
	defer fw.Cleanup()

	// Create YAML config for user1
	yamlConfig := `
pipes:
  - from:
      - username: user1
    to:
      host: 127.0.0.1:2224
      password: yaml-upstream-pass
`
	err := fw.WriteFile("multi-yaml/pipes.yaml", []byte(yamlConfig))
	fw.AssertNoError(err, "Failed to write YAML config")

	// Create fixed config for user2
	fw.RegisterPlugin("yaml", "./bin/sshpiperd-yaml",
		"--config", fw.TempDir()+"/multi-yaml/pipes.yaml",
		"--no-check-perm")

	fw.RegisterPlugin("fixed", "./bin/sshpiperd-fixed",
		"--target", "127.0.0.1:2225",
		"--username", "fixed-upstream-user",
		"--password", "fixed-upstream-pass",
		"--allowed-users", "user2")

	// Start upstream servers
	yamlUpstream, err := fw.CreateUpstreamServer(2224, map[string]string{
		"upstream-user": "yaml-upstream-pass",
	})
	fw.AssertNoError(err, "Failed to create YAML upstream")
	defer yamlUpstream.Stop()

	fixedUpstream, err := fw.CreateUpstreamServer(2225, map[string]string{
		"fixed-upstream-user": "fixed-upstream-pass",
	})
	fw.AssertNoError(err, "Failed to create fixed upstream")
	defer fixedUpstream.Stop()

	// Start SSHPiper with both plugins
	err = fw.StartSSHPiper("yaml", "fixed")
	fw.AssertNoError(err, "Failed to start SSHPiper")

	// Test user1 (should go through YAML plugin)
	client1, err := fw.ConnectSSH("user1", ssh.Password("anypass"))
	fw.AssertNoError(err, "Failed to connect as user1")
	defer client1.Close()

	output1, err := fw.RunCommand(client1, "echo yaml")
	fw.AssertNoError(err, "Failed to run command as user1")
	fw.AssertContains(output1, "yaml", "Unexpected output for user1")

	// Test user2 (should go through fixed plugin)
	client2, err := fw.ConnectSSH("user2", ssh.Password("anypass"))
	fw.AssertNoError(err, "Failed to connect as user2")
	defer client2.Close()

	output2, err := fw.RunCommand(client2, "echo fixed")
	fw.AssertNoError(err, "Failed to run command as user2")
	fw.AssertContains(output2, "fixed", "Unexpected output for user2")
}

// TestAuthenticationMethodsE2E tests various authentication methods
func TestAuthenticationMethodsE2E(t *testing.T) {
	fw := framework.NewTestFramework(t)
	defer fw.Cleanup()

	tests := []struct {
		name       string
		yamlConfig string
		authMethod ssh.AuthMethod
		shouldPass bool
	}{
		{
			name: "password authentication",
			yamlConfig: `
pipes:
  - from:
      - username: passuser
        htpasswd_data: cGFzc3VzZXI6JDJ5JDEwJDhFaXhLd0NmMVNzQkUzSTVTLkUyYWVRdno0M1llWXRHVHZEUE1WWE1BLjNKeENTTWFMUlhh
    to:
      host: 127.0.0.1:2226
`,
			authMethod: ssh.Password("testpass"),
			shouldPass: true,
		},
		{
			name: "wrong password",
			yamlConfig: `
pipes:
  - from:
      - username: passuser
        htpasswd_data: cGFzc3VzZXI6JDJ5JDEwJDhFaXhLd0NmMVNzQkUzSTVTLkUyYWVRdno0M1llWXRHVHZEUE1WWE1BLjNKeENTTWFMUlhh
    to:
      host: 127.0.0.1:2226
`,
			authMethod: ssh.Password("wrongpass"),
			shouldPass: false,
		},
		{
			name: "public key authentication",
			yamlConfig: `
pipes:
  - from:
      - username: keyuser
        authorized_keys_data: %s
    to:
      host: 127.0.0.1:2226
`,
			authMethod: nil, // Will be set with proper key
			shouldPass: true,
		},
	}

	// Create upstream server
	upstream, err := fw.CreateUpstreamServer(2226, map[string]string{
		"upstream": "pass",
	})
	fw.AssertNoError(err, "Failed to create upstream")
	defer upstream.Stop()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up previous configs
			fw.Cleanup()
			fw = framework.NewTestFramework(t)

			// Handle public key test
			config := tt.yamlConfig
			if tt.name == "public key authentication" {
				privKey, pubKey, err := fw.CreateSSHKeyPair()
				fw.AssertNoError(err, "Failed to create key pair")

				config = fmt.Sprintf(tt.yamlConfig, pubKey)

				signer, err := ssh.ParsePrivateKey(privKey)
				fw.AssertNoError(err, "Failed to parse private key")
				tt.authMethod = ssh.PublicKeys(signer)
			}

			// Write config
			err := fw.WriteFile("auth-test/pipes.yaml", []byte(config))
			fw.AssertNoError(err, "Failed to write config")

			// Register plugin
			fw.RegisterPlugin("yaml", "./bin/sshpiperd-yaml",
				"--config", fw.TempDir()+"/auth-test/pipes.yaml",
				"--no-check-perm")

			// Start SSHPiper
			err = fw.StartSSHPiper("yaml")
			fw.AssertNoError(err, "Failed to start SSHPiper")

			// Try to connect
			username := "passuser"
			if tt.name == "public key authentication" {
				username = "keyuser"
			}

			client, err := fw.ConnectSSH(username, tt.authMethod)
			if tt.shouldPass {
				fw.AssertNoError(err, "Expected successful connection")
				client.Close()
			} else {
				if err == nil {
					t.Error("Expected connection to fail but it succeeded")
					client.Close()
				}
			}
		})
	}
}

// TestStressE2E performs stress testing
func TestStressE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	fw := framework.NewTestFramework(t)
	defer fw.Cleanup()

	// Create simple YAML config
	yamlConfig := `
pipes:
  - from:
      - username: "user.*"
        username_regex_match: true
    to:
      host: 127.0.0.1:2227
      username: upstream
`
	err := fw.WriteFile("stress/pipes.yaml", []byte(yamlConfig))
	fw.AssertNoError(err, "Failed to write config")

	// Create upstream server
	upstream, err := fw.CreateUpstreamServer(2227, map[string]string{
		"upstream": "pass",
	})
	fw.AssertNoError(err, "Failed to create upstream")
	defer upstream.Stop()

	// Register plugin
	fw.RegisterPlugin("yaml", "./bin/sshpiperd-yaml",
		"--config", fw.TempDir()+"/stress/pipes.yaml",
		"--no-check-perm")

	// Start SSHPiper
	err = fw.StartSSHPiper("yaml")
	fw.AssertNoError(err, "Failed to start SSHPiper")

	// Run concurrent connections
	concurrency := 50
	iterations := 100
	errors := make(chan error, concurrency*iterations)
	done := make(chan bool)

	for i := 0; i < concurrency; i++ {
		go func(workerID int) {
			for j := 0; j < iterations; j++ {
				username := fmt.Sprintf("user%d", workerID)
				client, err := fw.ConnectSSH(username, ssh.Password("anypass"))
				if err != nil {
					errors <- fmt.Errorf("worker %d iteration %d: connect failed: %v", workerID, j, err)
					continue
				}

				output, err := fw.RunCommand(client, fmt.Sprintf("echo test-%d-%d", workerID, j))
				if err != nil {
					errors <- fmt.Errorf("worker %d iteration %d: command failed: %v", workerID, j, err)
				} else if !fw.Contains(output, fmt.Sprintf("test-%d-%d", workerID, j)) {
					errors <- fmt.Errorf("worker %d iteration %d: unexpected output: %s", workerID, j, output)
				}

				client.Close()
			}
			done <- true
		}(i)
	}

	// Wait for all workers
	timeout := time.After(5 * time.Minute)
	completed := 0

	for completed < concurrency {
		select {
		case <-done:
			completed++
		case err := <-errors:
			t.Error(err)
		case <-timeout:
			t.Fatal("Stress test timed out")
		}
	}

	// Check for any remaining errors
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

// TestSecurityE2E tests security features
func TestSecurityE2E(t *testing.T) {
	fw := framework.NewTestFramework(t)
	defer fw.Cleanup()

	// Test 1: Host key verification
	t.Run("HostKeyVerification", func(t *testing.T) {
		// Generate host key for upstream
		upstreamHostKey := fw.GenerateHostKey(t)

		yamlConfig := fmt.Sprintf(`
pipes:
  - from:
      - username: secureuser
    to:
      host: 127.0.0.1:2228
      known_hosts_data: %s
      ignore_hostkey: false
`, upstreamHostKey.PublicKey)

		err := fw.WriteFile("security/pipes.yaml", []byte(yamlConfig))
		fw.AssertNoError(err, "Failed to write config")

		// Start upstream with specific host key
		upstream := fw.CreateUpstreamServerWithHostKey(t, 2228, upstreamHostKey, map[string]string{
			"upstream": "pass",
		})
		defer upstream.Stop()

		fw.RegisterPlugin("yaml", "./bin/sshpiperd-yaml",
			"--config", fw.TempDir()+"/security/pipes.yaml",
			"--no-check-perm")

		err = fw.StartSSHPiper("yaml")
		fw.AssertNoError(err, "Failed to start SSHPiper")

		// Connection should succeed with correct host key
		client, err := fw.ConnectSSH("secureuser", ssh.Password("anypass"))
		fw.AssertNoError(err, "Failed to connect with valid host key")
		client.Close()
	})

	// Test 2: Certificate-based authentication
	t.Run("CertificateAuth", func(t *testing.T) {
		// Generate CA key and user certificate
		caKey, userCert := fw.GenerateCAAndUserCert(t, "certuser")

		yamlConfig := fmt.Sprintf(`
pipes:
  - from:
      - username: certuser
        trusted_user_ca_keys_data: %s
    to:
      host: 127.0.0.1:2229
`, caKey.PublicKey)

		err := fw.WriteFile("cert/pipes.yaml", []byte(yamlConfig))
		fw.AssertNoError(err, "Failed to write config")

		upstream, err := fw.CreateUpstreamServer(2229, map[string]string{
			"upstream": "pass",
		})
		fw.AssertNoError(err, "Failed to create upstream")
		defer upstream.Stop()

		fw.RegisterPlugin("yaml", "./bin/sshpiperd-yaml",
			"--config", fw.TempDir()+"/cert/pipes.yaml",
			"--no-check-perm")

		err = fw.StartSSHPiper("yaml")
		fw.AssertNoError(err, "Failed to start SSHPiper")

		// Connect with certificate
		client, err := fw.ConnectSSH("certuser", ssh.PublicKeys(userCert))
		fw.AssertNoError(err, "Expected successful certificate auth")
		client.Close()
	})
}
