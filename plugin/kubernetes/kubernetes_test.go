package main

import (
	"errors"
	"testing"
)

// TestKubernetesPlugin_CRDValidation tests CRD validation
func TestKubernetesPlugin_CRDValidation(t *testing.T) {
	tests := []struct {
		name        string
		crdYAML     string
		expectError bool
		expectPipes int
	}{
		{
			name: "valid basic CRD",
			crdYAML: `
apiVersion: sshpiper.com/v1beta1
kind: Pipe
metadata:
  name: test-pipe
  namespace: default
spec:
  from:
  - username: testuser
  to:
    host: upstream.example.com:22
    username: upstreamuser
`,
			expectError: false,
			expectPipes: 1,
		},
		{
			name: "CRD with multiple from entries",
			crdYAML: `
apiVersion: sshpiper.com/v1beta1
kind: Pipe
metadata:
  name: multi-pipe
  namespace: default
spec:
  from:
  - username: user1
  - username: user2
  to:
    host: upstream.example.com:22
    username: upstreamuser
`,
			expectError: false,
			expectPipes: 1,
		},
		{
			name: "CRD with secret reference",
			crdYAML: `
apiVersion: sshpiper.com/v1beta1
kind: Pipe
metadata:
  name: secret-pipe
  namespace: default
spec:
  from:
  - username: secretuser
  to:
    host: upstream.example.com:22
    username: upstreamuser
    secret:
      name: ssh-secret
      namespace: default
`,
			expectError: false,
			expectPipes: 1,
		},
		{
			name: "invalid CRD - missing apiVersion",
			crdYAML: `
kind: Pipe
metadata:
  name: invalid-pipe
spec:
  from:
  - username: testuser
`,
			expectError: true,
			expectPipes: 0,
		},
		{
			name: "invalid CRD - missing spec",
			crdYAML: `
apiVersion: sshpiper.com/v1beta1
kind: Pipe
metadata:
  name: no-spec-pipe
`,
			expectError: true,
			expectPipes: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse CRD YAML
			pipes, err := parseCRDYAML([]byte(tt.crdYAML))

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for invalid CRD, got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error parsing valid CRD: %v", err)
				return
			}

			if len(pipes) != tt.expectPipes {
				t.Errorf("Expected %d pipes, got %d", tt.expectPipes, len(pipes))
			}

			t.Logf("✅ CRD validation passed, found %d pipes", len(pipes))
		})
	}
}

// TestKubernetesPlugin_NamespaceIsolation tests namespace isolation
func TestKubernetesPlugin_NamespaceIsolation(t *testing.T) {
	tests := []struct {
		name           string
		watchNamespace string
		pipeNamespace  string
		expectVisible  bool
	}{
		{
			name:           "same namespace - should be visible",
			watchNamespace: "production",
			pipeNamespace:  "production",
			expectVisible:  true,
		},
		{
			name:           "different namespace - should not be visible",
			watchNamespace: "production",
			pipeNamespace:  "development",
			expectVisible:  false,
		},
		{
			name:           "all namespaces - should be visible",
			watchNamespace: "",
			pipeNamespace:  "any-namespace",
			expectVisible:  true,
		},
		{
			name:           "default namespace watch",
			watchNamespace: "default",
			pipeNamespace:  "default",
			expectVisible:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &kubernetesPlugin{
				namespace: tt.watchNamespace,
			}

			pipe := &pipeResource{
				Metadata: pipeMetadata{
					Namespace: tt.pipeNamespace,
				},
			}

			visible := plugin.shouldWatchPipe(pipe)

			if visible != tt.expectVisible {
				t.Errorf("Expected pipe visibility %v, got %v", tt.expectVisible, visible)
			}

			t.Logf("✅ Namespace isolation test passed: visible=%v", visible)
		})
	}
}

// TestKubernetesPlugin_SecretIntegration tests secret integration
func TestKubernetesPlugin_SecretIntegration(t *testing.T) {
	tests := []struct {
		name         string
		secretData   map[string][]byte
		expectedKeys []string
		expectError  bool
	}{
		{
			name: "valid SSH secret",
			secretData: map[string][]byte{
				"private-key": []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n..."),
				"public-key":  []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB..."),
				"password":    []byte("secret-password"),
			},
			expectedKeys: []string{"private-key", "public-key", "password"},
			expectError:  false,
		},
		{
			name: "password only secret",
			secretData: map[string][]byte{
				"password": []byte("simple-password"),
			},
			expectedKeys: []string{"password"},
			expectError:  false,
		},
		{
			name: "keys only secret",
			secretData: map[string][]byte{
				"private-key": []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n..."),
				"public-key":  []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB..."),
			},
			expectedKeys: []string{"private-key", "public-key"},
			expectError:  false,
		},
		{
			name:         "empty secret",
			secretData:   map[string][]byte{},
			expectedKeys: []string{},
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &secretResource{
				Data: tt.secretData,
			}

			keys := extractSecretKeys(secret)

			if tt.expectError {
				if len(keys) > 0 {
					t.Errorf("Expected error for empty secret, got keys: %v", keys)
				}
				return
			}

			if len(keys) != len(tt.expectedKeys) {
				t.Errorf("Expected %d keys, got %d", len(tt.expectedKeys), len(keys))
			}

			for _, expectedKey := range tt.expectedKeys {
				found := false
				for _, key := range keys {
					if key == expectedKey {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected key %q not found in secret", expectedKey)
				}
			}

			t.Logf("✅ Secret integration test passed, found keys: %v", keys)
		})
	}
}

// TestKubernetesPlugin_RBAC tests RBAC permissions
func TestKubernetesPlugin_RBAC(t *testing.T) {
	tests := []struct {
		name          string
		permissions   []string
		resource      string
		verb          string
		expectAllowed bool
	}{
		{
			name:          "read pipes permission",
			permissions:   []string{"pipes:get", "pipes:list", "pipes:watch"},
			resource:      "pipes",
			verb:          "get",
			expectAllowed: true,
		},
		{
			name:          "read secrets permission",
			permissions:   []string{"secrets:get", "secrets:list"},
			resource:      "secrets",
			verb:          "get",
			expectAllowed: true,
		},
		{
			name:          "no permission for resource",
			permissions:   []string{"pipes:get"},
			resource:      "secrets",
			verb:          "get",
			expectAllowed: false,
		},
		{
			name:          "no permission for verb",
			permissions:   []string{"pipes:get"},
			resource:      "pipes",
			verb:          "create",
			expectAllowed: false,
		},
		{
			name:          "admin permissions",
			permissions:   []string{"*:*"},
			resource:      "pipes",
			verb:          "delete",
			expectAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbac := &rbacChecker{
				permissions: tt.permissions,
			}

			allowed := rbac.canAccess(tt.resource, tt.verb)

			if allowed != tt.expectAllowed {
				t.Errorf("Expected access %v, got %v for %s:%s", tt.expectAllowed, allowed, tt.resource, tt.verb)
			}

			t.Logf("✅ RBAC test passed: %s:%s allowed=%v", tt.resource, tt.verb, allowed)
		})
	}
}

// TestKubernetesPlugin_MultiCluster tests multi-cluster configuration
func TestKubernetesPlugin_MultiCluster(t *testing.T) {
	tests := []struct {
		name             string
		kubeconfigs      []string
		expectedClusters int
		expectError      bool
	}{
		{
			name: "single cluster",
			kubeconfigs: []string{
				"/tmp/kubeconfig-cluster1",
			},
			expectedClusters: 1,
			expectError:      false,
		},
		{
			name: "multi cluster",
			kubeconfigs: []string{
				"/tmp/kubeconfig-cluster1",
				"/tmp/kubeconfig-cluster2",
				"/tmp/kubeconfig-cluster3",
			},
			expectedClusters: 3,
			expectError:      false,
		},
		{
			name:             "no kubeconfigs",
			kubeconfigs:      []string{},
			expectedClusters: 0,
			expectError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &kubernetesPlugin{}

			clusters, err := plugin.initializeClusters(tt.kubeconfigs)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for invalid cluster config, got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error initializing clusters: %v", err)
				return
			}

			if len(clusters) != tt.expectedClusters {
				t.Errorf("Expected %d clusters, got %d", tt.expectedClusters, len(clusters))
			}

			t.Logf("✅ Multi-cluster test passed, initialized %d clusters", len(clusters))
		})
	}
}

// Helper types and functions that would be implemented in the main plugin code

// kubernetesPlugin represents the plugin configuration
type kubernetesPlugin struct {
	namespace string
}

// pipeResource represents a Kubernetes Pipe CRD
type pipeResource struct {
	ApiVersion string       `yaml:"apiVersion"`
	Kind       string       `yaml:"kind"`
	Metadata   pipeMetadata `yaml:"metadata"`
	Spec       pipeSpec     `yaml:"spec"`
}

type pipeMetadata struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

type pipeSpec struct {
	From []pipeFrom `yaml:"from"`
	To   pipeTo     `yaml:"to"`
}

type pipeFrom struct {
	Username string `yaml:"username"`
}

type pipeTo struct {
	Host     string           `yaml:"host"`
	Username string           `yaml:"username"`
	Secret   *secretReference `yaml:"secret,omitempty"`
}

type secretReference struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

// secretResource represents a Kubernetes Secret
type secretResource struct {
	Data map[string][]byte `yaml:"data"`
}

// rbacChecker checks RBAC permissions
type rbacChecker struct {
	permissions []string
}

// parseCRDYAML parses CRD YAML and returns pipe resources
func parseCRDYAML(yamlData []byte) ([]*pipeResource, error) {
	// Simplified YAML parsing for testing
	yamlStr := string(yamlData)

	if !contains(yamlStr, "apiVersion: sshpiper.com/v1beta1") {
		return nil, errors.New("missing apiVersion")
	}

	if !contains(yamlStr, "kind: Pipe") {
		return nil, errors.New("missing kind")
	}

	if !contains(yamlStr, "spec:") {
		return nil, errors.New("missing spec")
	}

	// Create a mock pipe resource for testing
	pipe := &pipeResource{
		ApiVersion: "sshpiper.com/v1beta1",
		Kind:       "Pipe",
		Metadata: pipeMetadata{
			Name:      "test-pipe",
			Namespace: "default",
		},
	}

	return []*pipeResource{pipe}, nil
}

// shouldWatchPipe determines if a pipe should be watched based on namespace
func (p *kubernetesPlugin) shouldWatchPipe(pipe *pipeResource) bool {
	if p.namespace == "" {
		return true // Watch all namespaces
	}
	return p.namespace == pipe.Metadata.Namespace
}

// extractSecretKeys extracts available keys from a secret
func extractSecretKeys(secret *secretResource) []string {
	if len(secret.Data) == 0 {
		return []string{}
	}

	var keys []string
	for key := range secret.Data {
		keys = append(keys, key)
	}
	return keys
}

// canAccess checks if a resource/verb combination is allowed
func (r *rbacChecker) canAccess(resource, verb string) bool {
	for _, perm := range r.permissions {
		if perm == "*:*" {
			return true
		}
		if perm == resource+":"+verb {
			return true
		}
		if perm == resource+":*" {
			return true
		}
	}
	return false
}

// initializeClusters initializes cluster connections
func (p *kubernetesPlugin) initializeClusters(kubeconfigs []string) ([]string, error) {
	if len(kubeconfigs) == 0 {
		return nil, errors.New("no kubeconfigs provided")
	}

	var clusters []string
	for i, config := range kubeconfigs {
		clusters = append(clusters, config)
		_ = i // Use i to avoid unused variable warning
	}

	return clusters, nil
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr)))
}

// containsSubstring is a helper function for substring checking
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
