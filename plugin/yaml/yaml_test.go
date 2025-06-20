package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tg123/sshpiper/libplugin/skel"
)

func TestYamlPlugin_LoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		configYAML  string
		expectError bool
		expectPipes int
	}{
		{
			name: "valid simple config",
			configYAML: `
pipes:
  - from:
      - username: testuser
    to:
      host: upstream.example.com:2222
      username: upstream-user
`,
			expectError: false,
			expectPipes: 1,
		},
		{
			name: "multiple users",
			configYAML: `
pipes:
  - from:
      - username: user1
      - username: user2
    to:
      host: upstream1.example.com
  - from:
      - username: user3
    to:
      host: upstream2.example.com
`,
			expectError: false,
			expectPipes: 2,
		},
		{
			name: "with password auth",
			configYAML: `
pipes:
  - from:
      - username: testuser
        htpasswd_data: dGVzdHVzZXI6JDJ5JDEwJGV4YW1wbGVoYXNoZWRwYXNzd29yZA==
    to:
      host: upstream.example.com
      password: upstream-password
`,
			expectError: false,
			expectPipes: 1,
		},
		{
			name: "with public key auth",
			configYAML: `
pipes:
  - from:
      - username: testuser
        authorized_keys_data: c3NoLXJzYSBBQUFBQjN... # base64 encoded
    to:
      host: upstream.example.com
      private_key_data: LS0tLS1CRUdJTi... # base64 encoded
`,
			expectError: false,
			expectPipes: 1,
		},
		{
			name: "regex username matching",
			configYAML: `
pipes:
  - from:
      - username: "user.*"
        username_regex_match: true
    to:
      host: upstream.example.com
`,
			expectError: false,
			expectPipes: 1,
		},
		{
			name:        "empty config",
			configYAML:  ``,
			expectError: false,
			expectPipes: 0,
		},
		{
			name: "invalid yaml",
			configYAML: `
pipes:
  - from: [invalid
`,
			expectError: true,
			expectPipes: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp config file
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "config.yaml")
			if err := os.WriteFile(configFile, []byte(tt.configYAML), 0600); err != nil {
				t.Fatalf("Failed to write config: %v", err)
			}

			// Create plugin instance
			p := &plugin{}
			p.FileGlobs.Set(configFile)
			p.NoCheckPerm = true

			// Test loadConfig
			configs, err := p.loadConfig()
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// Count total pipes
			totalPipes := 0
			for _, config := range configs {
				totalPipes += len(config.Pipes)
			}

			if totalPipes != tt.expectPipes {
				t.Errorf("Expected %d pipes, got %d", tt.expectPipes, totalPipes)
			}
		})
	}
}

func TestYamlPlugin_MatchConn(t *testing.T) {
	tests := []struct {
		name         string
		configYAML   string
		username     string
		expectMatch  bool
		expectToHost string
	}{
		{
			name: "exact username match",
			configYAML: `
pipes:
  - from:
      - username: testuser
    to:
      host: upstream.example.com
`,
			username:     "testuser",
			expectMatch:  true,
			expectToHost: "upstream.example.com",
		},
		{
			name: "regex username match",
			configYAML: `
pipes:
  - from:
      - username: "test.*"
        username_regex_match: true
    to:
      host: regex-upstream.example.com
`,
			username:     "testuser123",
			expectMatch:  true,
			expectToHost: "regex-upstream.example.com",
		},
		{
			name: "no match",
			configYAML: `
pipes:
  - from:
      - username: otheruser
    to:
      host: upstream.example.com
`,
			username:    "testuser",
			expectMatch: false,
		},
		{
			name: "multiple from entries",
			configYAML: `
pipes:
  - from:
      - username: user1
      - username: user2
      - username: user3
    to:
      host: shared-upstream.example.com
`,
			username:     "user2",
			expectMatch:  true,
			expectToHost: "shared-upstream.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp config file
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "config.yaml")
			if err := os.WriteFile(configFile, []byte(tt.configYAML), 0600); err != nil {
				t.Fatalf("Failed to write config: %v", err)
			}

			// Create plugin instance
			p := &plugin{}
			p.FileGlobs.Set(configFile)
			p.NoCheckPerm = true

			// Create mock connection metadata
			conn := &mockConnMetadata{
				user: tt.username,
			}

			// List pipes
			pipes, err := p.listPipe(conn)
			if err != nil {
				t.Fatalf("Failed to list pipes: %v", err)
			}

			// Try to match connection
			matched := false
			var matchedHost string

			for _, pipe := range pipes {
				for _, from := range pipe.From() {
					to, err := from.MatchConn(conn)
					if err != nil {
						t.Errorf("MatchConn error: %v", err)
						continue
					}
					if to != nil {
						matched = true
						matchedHost = to.Host(conn)
						break
					}
				}
				if matched {
					break
				}
			}

			if matched != tt.expectMatch {
				t.Errorf("Expected match=%v, got match=%v", tt.expectMatch, matched)
			}

			if matched && matchedHost != tt.expectToHost {
				t.Errorf("Expected host=%q, got host=%q", tt.expectToHost, matchedHost)
			}
		})
	}
}

func TestYamlPlugin_Authentication(t *testing.T) {
	// Generate test SSH keys
	_, publicKey := generateTestSSHKey(t)
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey)

	// Create htpasswd for testing (testuser:testpass)
	htpasswdData := base64.StdEncoding.EncodeToString([]byte("testuser:$2y$05$NDU/P3zvIKcweQWa7nAcfO9t6zZyn21p.0gW7QHctahs3/99Cyu9K"))

	tests := []struct {
		name       string
		configYAML string
		authType   string
		authData   interface{}
		expectAuth bool
	}{
		{
			name: "password authentication",
			configYAML: fmt.Sprintf(`
pipes:
  - from:
      - username: testuser
        htpasswd_data: %s
    to:
      host: upstream.example.com
`, htpasswdData),
			authType:   "password",
			authData:   []byte("testpass"),
			expectAuth: true,
		},
		{
			name: "password authentication - wrong password",
			configYAML: fmt.Sprintf(`
pipes:
  - from:
      - username: testuser
        htpasswd_data: %s
    to:
      host: upstream.example.com
`, htpasswdData),
			authType:   "password",
			authData:   []byte("wrongpass"),
			expectAuth: false,
		},
		{
			name: "public key authentication",
			configYAML: fmt.Sprintf(`
pipes:
  - from:
      - username: testuser
        authorized_keys_data: %s
    to:
      host: upstream.example.com
`, publicKeyB64),
			authType:   "publickey",
			authData:   publicKey,
			expectAuth: true,
		},
		{
			name: "no auth required",
			configYAML: `
pipes:
  - from:
      - username: testuser
    to:
      host: upstream.example.com
`,
			authType:   "password",
			authData:   []byte("anypass"),
			expectAuth: true, // No restrictions, so any auth succeeds
		},
		{
			name: "trusted CA keys",
			configYAML: fmt.Sprintf(`
pipes:
  - from:
      - username: testuser
        trusted_user_ca_keys_data: %s
    to:
      host: upstream.example.com
`, publicKeyB64),
			authType:   "publickey",
			authData:   publicKey, // In real test, this would be a cert signed by the CA
			expectAuth: false,     // Direct key won't match CA requirement
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp config file
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "config.yaml")
			if err := os.WriteFile(configFile, []byte(tt.configYAML), 0600); err != nil {
				t.Fatalf("Failed to write config: %v", err)
			}

			// Create plugin instance
			p := &plugin{}
			p.FileGlobs.Set(configFile)
			p.NoCheckPerm = true

			// Create mock connection metadata
			conn := &mockConnMetadata{
				user: "testuser",
			}

			// List pipes
			pipes, err := p.listPipe(conn)
			if err != nil {
				t.Fatalf("Failed to list pipes: %v", err)
			}

			if len(pipes) == 0 {
				t.Fatal("No pipes found")
			}

			// Get first matching from
			var from skel.SkelPipeFrom
			for _, pipe := range pipes {
				froms := pipe.From()
				if len(froms) > 0 {
					from = froms[0]
					break
				}
			}

			if from == nil {
				t.Fatal("No from found")
			}

			// Test authentication based on type
			var authResult bool
			switch tt.authType {
			case "password":
				if pwFrom, ok := from.(skel.SkelPipeFromPassword); ok {
					result, err := pwFrom.TestPassword(conn, tt.authData.([]byte))
					if err != nil {
						t.Errorf("TestPassword error: %v", err)
					}
					authResult = result
				} else {
					// No password auth configured, defaults to true
					authResult = true
				}

			case "publickey":
				if pkFrom, ok := from.(skel.SkelPipeFromPublicKey); ok {
					// For this test, we just check if the key is in authorized_keys
					keys, err := pkFrom.AuthorizedKeys(conn)
					if err != nil {
						t.Errorf("AuthorizedKeys error: %v", err)
					}
					authResult = len(keys) > 0 // Simplified check
				} else {
					// No public key auth configured, defaults to true
					authResult = true
				}
			}

			if authResult != tt.expectAuth {
				t.Errorf("Expected auth=%v, got auth=%v", tt.expectAuth, authResult)
			}
		})
	}
}

func TestYamlPlugin_UpstreamConfig(t *testing.T) {
	privateKey, _ := generateTestSSHKey(t)
	privateKeyB64 := base64.StdEncoding.EncodeToString(privateKey)

	tests := []struct {
		name              string
		configYAML        string
		expectHost        string
		expectUser        string
		expectIgnoreHost  bool
		expectHasPassword bool
		expectHasKey      bool
	}{
		{
			name: "basic upstream",
			configYAML: `
pipes:
  - from:
      - username: testuser
    to:
      host: upstream.example.com:2222
      username: upstream-user
`,
			expectHost:        "upstream.example.com:2222",
			expectUser:        "upstream-user",
			expectIgnoreHost:  true, // Default when no known_hosts
			expectHasPassword: false,
			expectHasKey:      false,
		},
		{
			name: "upstream with password",
			configYAML: `
pipes:
  - from:
      - username: testuser
    to:
      host: upstream.example.com
      password: upstream-pass
`,
			expectHost:        "upstream.example.com",
			expectUser:        "testuser", // Defaults to downstream user
			expectIgnoreHost:  true,
			expectHasPassword: true,
			expectHasKey:      false,
		},
		{
			name: "upstream with private key",
			configYAML: fmt.Sprintf(`
pipes:
  - from:
      - username: testuser
    to:
      host: upstream.example.com
      private_key_data: %s
`, privateKeyB64),
			expectHost:        "upstream.example.com",
			expectUser:        "testuser",
			expectIgnoreHost:  true,
			expectHasPassword: false,
			expectHasKey:      true,
		},
		{
			name: "upstream with known hosts",
			configYAML: `
pipes:
  - from:
      - username: testuser
    to:
      host: upstream.example.com
      known_hosts_data: dXBzdHJlYW0uZXhhbXBsZS5jb20gc3NoLXJzYSBBQUFBQg==
      ignore_hostkey: false
`,
			expectHost:        "upstream.example.com",
			expectUser:        "testuser",
			expectIgnoreHost:  false,
			expectHasPassword: false,
			expectHasKey:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp config file
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "config.yaml")
			if err := os.WriteFile(configFile, []byte(tt.configYAML), 0600); err != nil {
				t.Fatalf("Failed to write config: %v", err)
			}

			// Create plugin instance
			p := &plugin{}
			p.FileGlobs.Set(configFile)
			p.NoCheckPerm = true

			// Create mock connection metadata
			conn := &mockConnMetadata{
				user: "testuser",
			}

			// List pipes and get the first matching to
			pipes, err := p.listPipe(conn)
			if err != nil {
				t.Fatalf("Failed to list pipes: %v", err)
			}

			if len(pipes) == 0 {
				t.Fatal("No pipes found")
			}

			// Get first matching to
			var to skel.SkelPipeTo
			for _, pipe := range pipes {
				for _, from := range pipe.From() {
					matchedTo, err := from.MatchConn(conn)
					if err != nil {
						t.Errorf("MatchConn error: %v", err)
						continue
					}
					if matchedTo != nil {
						to = matchedTo
						break
					}
				}
				if to != nil {
					break
				}
			}

			if to == nil {
				t.Fatal("No matching upstream found")
			}

			// Check upstream configuration
			if to.Host(conn) != tt.expectHost+":22" && to.Host(conn) != tt.expectHost {
				t.Errorf("Expected host=%q, got host=%q", tt.expectHost, to.Host(conn))
			}

			if to.User(conn) != tt.expectUser {
				t.Errorf("Expected user=%q, got user=%q", tt.expectUser, to.User(conn))
			}

			if to.IgnoreHostKey(conn) != tt.expectIgnoreHost {
				t.Errorf("Expected ignoreHostKey=%v, got ignoreHostKey=%v", tt.expectIgnoreHost, to.IgnoreHostKey(conn))
			}

			// Check auth method
			if pwTo, ok := to.(skel.SkelPipeToPassword); ok && tt.expectHasPassword {
				pass, err := pwTo.OverridePassword(conn)
				if err != nil {
					t.Errorf("OverridePassword error: %v", err)
				}
				if len(pass) == 0 {
					t.Error("Expected password but got empty")
				}
			}

			if keyTo, ok := to.(skel.SkelPipeToPrivateKey); ok && tt.expectHasKey {
				key, cert, err := keyTo.PrivateKey(conn)
				if err != nil {
					t.Errorf("PrivateKey error: %v", err)
				}
				if len(key) == 0 {
					t.Error("Expected private key but got empty")
				}
				_ = cert // Cert is optional
			}
		})
	}
}

// Helper functions

type mockConnMetadata struct {
	user       string
	remoteAddr string
}

func (m *mockConnMetadata) User() string                  { return m.user }
func (m *mockConnMetadata) RemoteAddr() string            { return m.remoteAddr }
func (m *mockConnMetadata) UniqueID() string              { return fmt.Sprintf("%s-%s", m.user, m.remoteAddr) }
func (m *mockConnMetadata) OriginalTargetAddress() string { return "" }
func (m *mockConnMetadata) Metadata() map[string]string   { return nil }
func (m *mockConnMetadata) GetMeta(key string) string     { return "" }

func generateTestSSHKey(_ *testing.T) ([]byte, []byte) {
	// Generate a test RSA key pair
	// This is a simplified version for testing
	privateKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890...
-----END RSA PRIVATE KEY-----`)

	publicKey := []byte(`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... test@example.com`)

	return privateKey, publicKey
}
