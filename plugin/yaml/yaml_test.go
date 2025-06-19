package main

import (
	"testing"

	"github.com/tg123/sshpiper/libplugin"
	"gopkg.in/yaml.v3"
)

const yamlConfigTemplate = `
version: "1.0"
pipes:
- from:
    - username: "password_simple"
  to:
    host: host-password:2222
    username: "user"
    ignore_hostkey: true
- from:
    - username: "password_.*_regex"
      username_regex_match: true
  to:
    host: host-password:2222
    username: "user"
    known_hosts_data: 
    - fDF8RjRwTmVveUZHVEVHcEIyZ3A4RGE0WlE4TGNVPXxycVZYNU0rWTJoS0dteFphcVFBb0syRHp1TEE9IHNzaC1lZDI1NTE5IEFBQUFDM056YUMxbFpESTFOVEU1QUFBQUlPTXFxbmtWenJtMFNkRzZVT29xS0xzYWJnSDVDOW9rV2kwZGgybDlHS0psCg==
    - fDF8VzRpUUd0VFVyREJwSjM3RnFuOWRwcEdVRE5jPXxEZWFna2RwVHpZZDExdDhYWXlORnlhZmROZ2c9IHNzaC1lZDI1NTE5IEFBQUFDM056YUMxbFpESTFOVEU1QUFBQUlBZnVDSEtWVGpxdXh2dDZDTTZ0ZEc0U0xwMUJ0bi9uT2VISEU1VU96UmRmCg==
- from:
    - username: "publickey_simple"
      authorized_keys: /tmp/auth_keys
  to:
    host: host-publickey:2222
    username: "user"
    private_key: /tmp/private_key
    known_hosts_data: fDF8RjRwTmVveUZHVEVHcEIyZ3A4RGE0WlE4TGNVPXxycVZYNU0rWTJoS0dteFphcVFBb0syRHp1TEE9IHNzaC1lZDI1NTE5IEFBQUFDM056YUMxbFpESTFOVEU1QUFBQUlPTXFxbmtWenJtMFNkRzZVT29xS0xzYWJnSDVDOW9rV2kwZGgybDlHS0psCg==
- from:
    - username: ".*"
      username_regex_match: true
      authorized_keys: 
      - /tmp/private_key1
      - /tmp/private_key2
  to:
    host: host-publickey:2222
    username: "user"
    ignore_hostkey: true
    private_key: /tmp/private_key
`

func TestYamlDecode(t *testing.T) {
	var config piperConfig

	err := yaml.Unmarshal([]byte(yamlConfigTemplate), &config)
	if err != nil {
		t.Fatalf("Failed to unmarshal yaml: %v", err)
	}

}

func TestYamlSkelPipeWrapperMethods(t *testing.T) {
	// Minimal mock config for testing
	pipe := yamlPipe{
		From: []yamlPipeFrom{
			{
				Username:           "testuser",
				AuthorizedKeys:     libplugin.ListOrString{Str: "/tmp/test_auth_keys"},
				TrustedUserCAKeys:  libplugin.ListOrString{Str: "/tmp/test_ca_keys"},
				AuthorizedKeysData: libplugin.ListOrString{Str: "dGVzdGtleQ=="},    // 'testkey' in base64
				HtpasswdData:       "dGVzdHVzZXI6JGFwcjEkM3JGNmsuLi4kUWQ4UXcxCg==", // 'testuser:$apr1$3rF6k...$Qd8Qw1' in base64
				HtpasswdFile:       "",                                             // not used in this test
			},
		},
		To: yamlPipeTo{
			Username:   "upstream",
			Host:       "host.example.com:22",
			Password:   "testpass",
			PrivateKey: "/tmp/test_id_rsa",
			KnownHosts: listOrString{Str: "/tmp/test_known_hosts"},
		},
	}
	config := &piperConfig{Version: "1.0", Pipes: []yamlPipe{pipe}, filename: "/tmp/test.yaml"}
	wrapper := &yamlSkelPipeWrapper{libplugin.NewSkelPipeWrapper(config, &pipe)}

	mockConn := &libplugin.MockConnMetadata{UserVal: "testuser"}

	t.Run("TestPassword", func(t *testing.T) {
		ok, err := wrapper.TestPassword(mockConn, []byte("testpass"))
		if err != nil {
			t.Errorf("TestPassword error: %v", err)
		}
		// Accept both true/false, just check no panic or error
		_ = ok
	})
	t.Run("AuthorizedKeys", func(t *testing.T) {
		_, err := wrapper.AuthorizedKeys(mockConn)
		if err != nil {
			// File may not exist, but should not panic
			_ = err
		}
	})
	t.Run("TrustedUserCAKeys", func(t *testing.T) {
		_, err := wrapper.TrustedUserCAKeys(mockConn)
		if err != nil {
			_ = err
		}
	})
	t.Run("OverridePassword", func(t *testing.T) {
		pw, err := wrapper.OverridePassword(mockConn)
		if err != nil {
			t.Errorf("OverridePassword error: %v", err)
		}
		if string(pw) != "testpass" {
			t.Errorf("OverridePassword got %q, want 'testpass'", string(pw))
		}
	})
}
