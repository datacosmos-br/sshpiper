package libplugin

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestStandardTestPassword(t *testing.T) {
	tests := []struct {
		name         string
		htpasswdData string
		htpasswdFile string
		username     string
		password     string
		expectAuth   bool
	}{
		{
			name:         "valid password with data",
			htpasswdData: "dGVzdHVzZXI6JDJ5JDA1JE5EVS9QM3p2SUtjd2VRV2E3bkFjZk85dDZ6WnluMjFwLjBnVzdRSGN0YWhzMy85OUN5dTlLCg==",
			username:     "testuser",
			password:     "testpass",
			expectAuth:   true,
		},
		{
			name:         "invalid password with data",
			htpasswdData: "dGVzdHVzZXI6JDJ5JDEwJDhFaXhLd0NmMVNzQkUzSTVTLkUyYWVRdno0M1llWXRHVHZEUE1WWE1BLjNKeENTTWFMUlhh",
			username:     "testuser",
			password:     "wrongpass",
			expectAuth:   false,
		},
		{
			name:       "no auth restrictions",
			username:   "testuser",
			password:   "anypass",
			expectAuth: true,
		},
		{
			name:         "user not found",
			htpasswdData: "dGVzdHVzZXI6JDJ5JDEwJDhFaXhLd0NmMVNzQkUzSTVTLkUyYWVRdno0M1llWXRHVHZEUE1WWE1BLjNKeENTTWFMUlhh",
			username:     "otheruser",
			password:     "testpass",
			expectAuth:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := StandardTestPassword(tt.htpasswdData, tt.htpasswdFile, tt.username, []byte(tt.password))
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if result != tt.expectAuth {
				t.Errorf("Expected auth=%v, got auth=%v", tt.expectAuth, result)
			}
		})
	}
}

func TestStandardAuthorizedKeys(t *testing.T) {
	tests := []struct {
		name      string
		keysData  string
		keysFile  string
		expectLen int
	}{
		{
			name:      "base64 encoded keys",
			keysData:  base64.StdEncoding.EncodeToString([]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC test@example.com")),
			expectLen: 1,
		},
		{
			name:      "raw keys data",
			keysData:  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC test@example.com",
			expectLen: 1,
		},
		{
			name:      "no keys",
			expectLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Handle file test
			tmpDir := t.TempDir()
			var keysFile string
			if tt.keysFile != "" {
				keysFile = filepath.Join(tmpDir, "authorized_keys")
				err := os.WriteFile(keysFile, []byte(tt.keysFile), 0600)
				if err != nil {
					t.Fatalf("Failed to write keys file: %v", err)
				}
			}

			envVars := map[string]string{
				"DOWNSTREAM_USER": "testuser",
			}

			keys, err := StandardAuthorizedKeys(tt.keysData, keysFile, envVars, tmpDir)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if tt.expectLen == 0 {
				if keys != nil {
					t.Errorf("Expected no keys, got: %v", string(keys))
				}
			} else {
				if keys == nil {
					t.Error("Expected keys but got nil")
				}
			}
		})
	}
}

func TestStandardTrustedUserCAKeys(t *testing.T) {
	tests := []struct {
		name        string
		caKeysData  string
		caKeysFile  string
		expectError bool
	}{
		{
			name:       "base64 encoded CA keys",
			caKeysData: base64.StdEncoding.EncodeToString([]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC ca@example.com")),
		},
		{
			name:       "raw CA keys data",
			caKeysData: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC ca@example.com",
		},
		{
			name: "no CA keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			envVars := map[string]string{
				"DOWNSTREAM_USER": "testuser",
			}

			keys, err := StandardTrustedUserCAKeys(tt.caKeysData, tt.caKeysFile, envVars, tmpDir)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tt.caKeysData != "" && keys == nil {
					t.Error("Expected CA keys but got nil")
				}
			}
		})
	}
}

func TestStandardPrivateKey(t *testing.T) {
	privateKeyPEM := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef...
-----END RSA PRIVATE KEY-----`

	tests := []struct {
		name       string
		keyData    string
		keyFile    string
		expectKeys bool
	}{
		{
			name:       "base64 encoded private key",
			keyData:    base64.StdEncoding.EncodeToString([]byte(privateKeyPEM)),
			expectKeys: true,
		},
		{
			name:       "raw private key data",
			keyData:    privateKeyPEM,
			expectKeys: true,
		},
		{
			name:       "no private key",
			expectKeys: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			envVars := map[string]string{
				"DOWNSTREAM_USER": "testuser",
			}

			privKey, pubKey, err := StandardPrivateKey(tt.keyData, tt.keyFile, envVars, tmpDir)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if tt.expectKeys {
				if privKey == nil {
					t.Error("Expected private key but got nil")
				}
				// Public key is optional and may be nil
			} else {
				if privKey != nil {
					t.Error("Expected no private key but got one")
				}
			}

			_ = pubKey // pubKey is optional
		})
	}
}

func TestStandardOverridePassword(t *testing.T) {
	tests := []struct {
		name         string
		passwordData string
		passwordFile string
		expectPass   bool
	}{
		{
			name:         "base64 encoded password",
			passwordData: base64.StdEncoding.EncodeToString([]byte("secret123")),
			expectPass:   true,
		},
		{
			name:         "raw password data",
			passwordData: "secret123",
			expectPass:   true,
		},
		{
			name:       "no password",
			expectPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			envVars := map[string]string{
				"DOWNSTREAM_USER": "testuser",
			}

			password, err := StandardOverridePassword(tt.passwordData, tt.passwordFile, envVars, tmpDir)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if tt.expectPass {
				if password == nil {
					t.Error("Expected password but got nil")
				}
			} else {
				if password != nil {
					t.Error("Expected no password but got one")
				}
			}
		})
	}
}

func TestLooksLikeBase64(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"SGVsbG8gV29ybGQ=", true},     // "Hello World" in base64
		{"simple-password", false},     // Simple text
		{"", false},                    // Empty string
		{"abc", false},                 // Too short
		{"SGVsbG8gV29ybGQhISE=", true}, // Valid base64
		{"not-base64-data!", false},    // Contains invalid chars
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := looksLikeBase64(tt.input)
			if result != tt.expected {
				t.Errorf("looksLikeBase64(%q) = %v; want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestStandardIgnoreHostKey(t *testing.T) {
	tests := []struct {
		name           string
		ignoreHostKey  bool
		knownHostsData string
		knownHostsFile string
		expectedIgnore bool
	}{
		{
			name:           "explicit ignore",
			ignoreHostKey:  true,
			expectedIgnore: true,
		},
		{
			name:           "no known hosts configured",
			ignoreHostKey:  false,
			expectedIgnore: true, // Default to ignore when no known hosts
		},
		{
			name:           "known hosts data provided",
			ignoreHostKey:  false,
			knownHostsData: "example.com ssh-rsa AAAAB3...",
			expectedIgnore: false,
		},
		{
			name:           "known hosts file provided",
			ignoreHostKey:  false,
			knownHostsFile: "/etc/ssh/known_hosts",
			expectedIgnore: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StandardIgnoreHostKey(tt.ignoreHostKey, tt.knownHostsData, tt.knownHostsFile)
			if result != tt.expectedIgnore {
				t.Errorf("Expected ignore=%v, got ignore=%v", tt.expectedIgnore, result)
			}
		})
	}
}
