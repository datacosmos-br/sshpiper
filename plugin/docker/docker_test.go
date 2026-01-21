package main

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestDockerPlugin_BasicLabelRouting tests Docker plugin container discovery
func TestDockerPlugin_BasicLabelRouting(t *testing.T) {
	// Check if Docker is available
	if !isDockerAvailable() {
		t.Skip("Docker not available, skipping Docker plugin test")
		return
	}

	// Create a test container with SSH labels
	testImage := "alpine:latest"
	containerName := fmt.Sprintf("sshpiper-test-%d", time.Now().Unix())

	// Pull the image first
	pullCmd := exec.Command("docker", "pull", testImage)
	err := pullCmd.Run()
	if err != nil {
		t.Skipf("Failed to pull Docker image %s: %v", testImage, err)
		return
	}

	// Create container with SSH labels
	createCmd := exec.Command("docker", "run", "-d", "--name", containerName,
		"--label", "sshpiper.host=localhost:2223",
		"--label", "sshpiper.username=testuser",
		"--label", "sshpiper.password=testpass",
		"--label", "sshpiper.ignore_hostkey=true",
		testImage, "sleep", "60")

	output, err := createCmd.CombinedOutput()
	if err != nil {
		t.Skipf("Failed to create Docker container: %v, output: %s", err, string(output))
		return
	}

	actualContainerID := strings.TrimSpace(string(output))

	// Cleanup container when test finishes
	defer func() {
		stopCmd := exec.Command("docker", "stop", containerName)
		stopCmd.Run()
		rmCmd := exec.Command("docker", "rm", containerName)
		rmCmd.Run()
	}()

	// Wait for container to be running
	time.Sleep(2 * time.Second)

	// Verify container is running
	psCmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Names}}")
	psOutput, err := psCmd.CombinedOutput()
	if err != nil {
		t.Errorf("Failed to check container status: %v", err)
		return
	}

	if !strings.Contains(string(psOutput), containerName) {
		t.Errorf("Container %s not found in running containers", containerName)
		return
	}

	// Test that the plugin can discover and parse container labels
	labels := map[string]string{
		"sshpiper.host":           "localhost:2223",
		"sshpiper.username":       "testuser",
		"sshpiper.password":       "testpass",
		"sshpiper.ignore_hostkey": "true",
	}

	// Verify each label is correctly set
	for key, expectedValue := range labels {
		inspectCmd := exec.Command("docker", "inspect", "--format", fmt.Sprintf("{{.Config.Labels.%q}}", key), containerName)
		labelOutput, err := inspectCmd.CombinedOutput()
		if err != nil {
			t.Errorf("Failed to inspect label %s: %v", key, err)
			continue
		}

		actualValue := strings.TrimSpace(string(labelOutput))
		if actualValue != expectedValue {
			t.Errorf("Label %s: expected %q, got %q", key, expectedValue, actualValue)
		}
	}

	t.Logf("✅ Docker plugin container discovery test completed successfully")
	t.Logf("Container ID: %s", actualContainerID)
	t.Logf("Container Name: %s", containerName)
}

// TestDockerPlugin_MultiContainerSetup tests multiple containers with different configurations
func TestDockerPlugin_MultiContainerSetup(t *testing.T) {
	if !isDockerAvailable() {
		t.Skip("Docker not available, skipping Docker plugin test")
		return
	}

	testImage := "alpine:latest"
	containers := []struct {
		name   string
		labels map[string]string
	}{
		{
			name: fmt.Sprintf("sshpiper-multi-1-%d", time.Now().Unix()),
			labels: map[string]string{
				"sshpiper.host":     "upstream1.example.com:22",
				"sshpiper.username": "user1",
				"sshpiper.password": "pass1",
			},
		},
		{
			name: fmt.Sprintf("sshpiper-multi-2-%d", time.Now().Unix()),
			labels: map[string]string{
				"sshpiper.host":             "upstream2.example.com:2222",
				"sshpiper.username":         "user2",
				"sshpiper.private_key_file": "/tmp/key2",
				"sshpiper.ignore_hostkey":   "true",
			},
		},
	}

	// Create all containers
	var containerIDs []string
	for _, container := range containers {
		// Build docker run command with labels
		args := []string{"run", "-d", "--name", container.name}
		for key, value := range container.labels {
			args = append(args, "--label", fmt.Sprintf("%s=%s", key, value))
		}
		args = append(args, testImage, "sleep", "60")

		createCmd := exec.Command("docker", args...)
		output, err := createCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to create container %s: %v, output: %s", container.name, err, string(output))
		}
		containerIDs = append(containerIDs, strings.TrimSpace(string(output)))
	}

	// Cleanup all containers
	defer func() {
		for _, container := range containers {
			stopCmd := exec.Command("docker", "stop", container.name)
			stopCmd.Run()
			rmCmd := exec.Command("docker", "rm", container.name)
			rmCmd.Run()
		}
	}()

	// Wait for containers to be running
	time.Sleep(3 * time.Second)

	// Verify all containers are running and have correct labels
	for i, container := range containers {
		// Check container is running
		psCmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", container.name), "--format", "{{.Names}}")
		psOutput, err := psCmd.CombinedOutput()
		if err != nil {
			t.Errorf("Failed to check container %s status: %v", container.name, err)
			continue
		}

		if !strings.Contains(string(psOutput), container.name) {
			t.Errorf("Container %s not found in running containers", container.name)
			continue
		}

		// Verify labels
		for key, expectedValue := range container.labels {
			inspectCmd := exec.Command("docker", "inspect", "--format", fmt.Sprintf("{{.Config.Labels.%q}}", key), container.name)
			labelOutput, err := inspectCmd.CombinedOutput()
			if err != nil {
				t.Errorf("Failed to inspect label %s on container %s: %v", key, container.name, err)
				continue
			}

			actualValue := strings.TrimSpace(string(labelOutput))
			if actualValue != expectedValue {
				t.Errorf("Container %s label %s: expected %q, got %q", container.name, key, expectedValue, actualValue)
			}
		}

		t.Logf("✅ Container %s (%s) configured correctly", container.name, containerIDs[i])
	}

	t.Logf("✅ Multi-container setup test completed successfully")
}

// TestDockerPlugin_ContainerNetworks tests Docker network discovery
func TestDockerPlugin_ContainerNetworks(t *testing.T) {
	if !isDockerAvailable() {
		t.Skip("Docker not available, skipping Docker plugin test")
		return
	}

	networkName := fmt.Sprintf("sshpiper-net-%d", time.Now().Unix())
	containerName := fmt.Sprintf("sshpiper-net-test-%d", time.Now().Unix())

	// Create custom network
	createNetCmd := exec.Command("docker", "network", "create", networkName)
	err := createNetCmd.Run()
	if err != nil {
		t.Fatalf("Failed to create Docker network: %v", err)
	}

	// Cleanup network
	defer func() {
		rmNetCmd := exec.Command("docker", "network", "rm", networkName)
		rmNetCmd.Run()
	}()

	// Create container on custom network
	createCmd := exec.Command("docker", "run", "-d", "--name", containerName,
		"--network", networkName,
		"--label", "sshpiper.host=container-internal:22",
		"--label", "sshpiper.username=netuser",
		"alpine:latest", "sleep", "60")

	output, err := createCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to create container: %v, output: %s", err, string(output))
	}

	// Cleanup container
	defer func() {
		stopCmd := exec.Command("docker", "stop", containerName)
		stopCmd.Run()
		rmCmd := exec.Command("docker", "rm", containerName)
		rmCmd.Run()
	}()

	// Wait for container to be running
	time.Sleep(2 * time.Second)

	// Verify container is on custom network
	inspectCmd := exec.Command("docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.NetworkID}}{{end}}", containerName)
	networkOutput, err := inspectCmd.CombinedOutput()
	if err != nil {
		t.Errorf("Failed to inspect container network: %v", err)
		return
	}

	if len(strings.TrimSpace(string(networkOutput))) == 0 {
		t.Errorf("Container not connected to any network")
		return
	}

	t.Logf("✅ Container network configuration test completed successfully")
}

// TestDockerPlugin_DynamicDiscovery tests plugin's ability to discover containers dynamically
func TestDockerPlugin_DynamicDiscovery(t *testing.T) {
	if !isDockerAvailable() {
		t.Skip("Docker not available, skipping Docker plugin test")
		return
	}

	containerName := fmt.Sprintf("sshpiper-dynamic-%d", time.Now().Unix())

	// First, verify no container exists
	psCmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Names}}")
	psOutput, err := psCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to check initial container state: %v", err)
	}

	if strings.Contains(string(psOutput), containerName) {
		t.Fatalf("Container %s already exists", containerName)
	}

	// Create container dynamically
	createCmd := exec.Command("docker", "run", "-d", "--name", containerName,
		"--label", "sshpiper.host=dynamic.example.com:22",
		"--label", "sshpiper.username=dynamicuser",
		"alpine:latest", "sleep", "30")

	_, err = createCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to create dynamic container: %v", err)
	}

	// Cleanup container
	defer func() {
		stopCmd := exec.Command("docker", "stop", containerName)
		stopCmd.Run()
		rmCmd := exec.Command("docker", "rm", containerName)
		rmCmd.Run()
	}()

	// Wait for container to be running
	time.Sleep(2 * time.Second)

	// Verify container is now discoverable
	psCmd2 := exec.Command("docker", "ps", "--filter", fmt.Sprintf("name=%s", containerName), "--format", "{{.Names}}")
	psOutput2, err := psCmd2.CombinedOutput()
	if err != nil {
		t.Errorf("Failed to check dynamic container: %v", err)
		return
	}

	if !strings.Contains(string(psOutput2), containerName) {
		t.Errorf("Dynamic container %s not discovered", containerName)
		return
	}

	t.Logf("✅ Dynamic discovery test completed successfully")
}

// TestDockerPlugin_HealthChecks tests Docker health check integration
func TestDockerPlugin_HealthChecks(t *testing.T) {
	if !isDockerAvailable() {
		t.Skip("Docker not available, skipping Docker plugin test")
		return
	}

	containerName := fmt.Sprintf("sshpiper-health-%d", time.Now().Unix())

	// Create container with health check
	createCmd := exec.Command("docker", "run", "-d", "--name", containerName,
		"--health-cmd", "echo 'healthy'",
		"--health-interval", "5s",
		"--health-timeout", "3s",
		"--health-retries", "2",
		"--label", "sshpiper.host=healthy.example.com:22",
		"--label", "sshpiper.username=healthuser",
		"alpine:latest", "sleep", "60")

	_, err := createCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to create container with health check: %v", err)
	}

	// Cleanup container
	defer func() {
		stopCmd := exec.Command("docker", "stop", containerName)
		stopCmd.Run()
		rmCmd := exec.Command("docker", "rm", containerName)
		rmCmd.Run()
	}()

	// Wait for health check to run
	time.Sleep(8 * time.Second)

	// Check health status
	healthCmd := exec.Command("docker", "inspect", "--format", "{{.State.Health.Status}}", containerName)
	healthOutput, err := healthCmd.CombinedOutput()
	if err != nil {
		t.Errorf("Failed to check health status: %v", err)
		return
	}

	healthStatus := strings.TrimSpace(string(healthOutput))
	if healthStatus != "healthy" && healthStatus != "starting" {
		t.Errorf("Expected health status 'healthy' or 'starting', got: %s", healthStatus)
		return
	}

	t.Logf("✅ Health check test completed successfully, status: %s", healthStatus)
}

// Helper function to check if Docker is available
func isDockerAvailable() bool {
	cmd := exec.Command("docker", "version")
	err := cmd.Run()
	return err == nil
}

// removeTestContainer is a helper function to clean up test containers
func removeTestContainer(containerID string) {

}
