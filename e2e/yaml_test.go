package e2e_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
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
    - username: "^password_.*_regex$"
      username_regex_match: true
  to:
    host: host-password:2222
    username: "user"
    known_hosts_data: 
    # github.com
    - fDF8RjRwTmVveUZHVEVHcEIyZ3A4RGE0WlE4TGNVPXxycVZYNU0rWTJoS0dteFphcVFBb0syRHp1TEE9IHNzaC1lZDI1NTE5IEFBQUFDM056YUMxbFpESTFOVEU1QUFBQUlPTXFxbmtWenJtMFNkRzZVT29xS0xzYWJnSDVDOW9rV2kwZGgybDlHS0psCg==
    - {{ .KnownHostsKey }}
    - {{ .KnownHostsPass }}
- from:
    - username: "^password_(.+?)_regex_expand$"
      username_regex_match: true
  to:
    host: host-password:2222
    username: "$1"
    known_hosts_data: {{ .KnownHostsPass }}
- from:
    - username: "publickey_simple"
      authorized_keys: {{ .AuthorizedKeys_Simple }}
  to:
    host: host-publickey:2222
    username: "user"
    private_key: {{ .PrivateKey }}
    known_hosts_data: {{ .KnownHostsKey }}
- from:
    - username: "cert"
      trusted_user_ca_keys: {{ .TrustedUserCAKeys }}
  to:
    host: host-publickey:2222
    username: "user"
    ignore_hostkey: true
    private_key: {{ .PrivateKey }}
- from:
    - groupname: "testgroup"
      authorized_keys: {{ .AuthorizedKeys_Simple }}
  to:
    host: host-publickey:2222
    username: "user"
    private_key: {{ .PrivateKey }}
    known_hosts_data: {{ .KnownHostsKey }}
- from:
    - groupname: "testgroup"
  to:
    host: host-password:2222
    username: "user"
    ignore_hostkey: true
- from:
    - username: ".*"
      username_regex_match: true
      authorized_keys: 
        - {{ .AuthorizedKeys_Simple }}
        - {{ .AuthorizedKeys_Catchall }}
  to:
    host: host-publickey:2222
    username: "user"
    ignore_hostkey: true
    private_key: {{ .PrivateKey }}
- from:
    - username: "testuser"
      trusted_user_ca_keys: {{ .CA1PubKey }}
  to:
    host: host-publickey:2222
    username: "user"
    ignore_hostkey: true
    private_key: {{ .PrivateKey }}
- from:
    - username: ".*"
      username_regex_match: true
      trusted_user_ca_keys: {{ .CA2PubKey }}
  to:
    host: host-publickey:2222
    username: "user"
    ignore_hostkey: true
    private_key: {{ .PrivateKey }}
`

func TestYaml(t *testing.T) {
	yamldir := mustMkdirTemp(t, "", "")

	parsedYamlTmpl := template.Must(template.New("yaml").Parse(yamlConfigTemplate))

	// Main test keys
	mustGenKey(t, path.Join(yamldir, "id_rsa_simple"))
	mustGenKey(t, path.Join(yamldir, "id_rsa_catchall"))
	mustGenKey(t, path.Join(yamldir, "id_rsa"))
	if err := runCmdAndWait("/bin/cp", path.Join(yamldir, "id_rsa.pub"), "/publickey_authorized_keys/authorized_keys"); err != nil {
		t.Errorf("failed to copy public key: %v", err)
	}
	mustGenKey(t, path.Join(yamldir, "ca_key"))
	mustGenKey(t, path.Join(yamldir, "user_ca_key"))
	if err := runCmdAndWait("ssh-keygen", "-s", path.Join(yamldir, "ca_key"), "-I", "cert", "-n", "cert", "-V", "+1w", path.Join(yamldir, "user_ca_key.pub")); err != nil {
		t.Errorf("failed to sign user ca key: %v", err)
	}

	// CA test keys (shared for all ca_cert_auth subtests)
	caTestDir := mustMkdirTemp(t, "", "sshpiper-ca-test")
	// Use static CA key for CA cert tests
	caPriv := "/config/sshd/trusted-ca.key"
	caPub := "/config/sshd/trusted-ca.pub"
	userKey := filepath.Join(caTestDir, "user_key")
	mustGenKey(t, userKey)
	if err := runCmdAndWait("ssh-keygen", "-s", caPriv, "-I", "testuser", "-n", "testuser", "-V", "+1d", userKey+".pub"); err != nil {
		t.Fatalf("Failed to sign user key: %v", err)
	}
	invaliduserKey := filepath.Join(caTestDir, "invaliduser_key")
	mustGenKey(t, invaliduserKey)
	if err := runCmdAndWait("ssh-keygen", "-s", caPriv, "-I", "invaliduser", "-n", "invaliduser", "-V", "+1d", invaliduserKey+".pub"); err != nil {
		t.Fatalf("Failed to sign user key: %v", err)
	}
	ca2Priv := "/config/sshd/trusted-ca2.key"
	ca2Pub := "/config/sshd/trusted-ca2.pub"
	userKey2 := filepath.Join(caTestDir, "user_key2")
	mustGenKey(t, userKey2)
	if err := runCmdAndWait("ssh-keygen", "-s", ca2Priv, "-I", "anyusername", "-n", "anyusername", "-V", "+1d", userKey2+".pub"); err != nil {
		t.Fatalf("Failed to sign user key with ca2: %v", err)
	}

	// Main test config file (now includes all pipes)
	mainConfigPath := path.Join(yamldir, "config.yaml")
	f, err := os.OpenFile(mainConfigPath, os.O_RDWR|os.O_CREATE, 0400)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	knownHostsKeyData := mustKeyScan(t, "2222", "host-publickey")
	knownHostsPassData := mustKeyScan(t, "2222", "host-password")

	if err := parsedYamlTmpl.ExecuteTemplate(f, "yaml", map[string]interface{}{
		"KnownHostsKey":           base64.StdEncoding.EncodeToString(knownHostsKeyData),
		"KnownHostsPass":          base64.StdEncoding.EncodeToString(knownHostsPassData),
		"PrivateKey":              path.Join(yamldir, "id_rsa"),
		"AuthorizedKeys_Simple":   path.Join(yamldir, "id_rsa_simple.pub"),
		"AuthorizedKeys_Catchall": path.Join(yamldir, "id_rsa_catchall.pub"),
		"TrustedUserCAKeys":       path.Join(yamldir, "ca_key.pub"),
		"CA1PubKey":               caPub,
		"CA2PubKey":               ca2Pub,
	}); err != nil {
		t.Fatalf("Failed to write yaml file %v", err)
	}
	_ = f.Close()
	_ = runCmdAndWait("cat", "-n", mainConfigPath)

	piperaddr, piperport := nextAvailablePiperAddress()
	piper, _, _, err := runCmd("/sshpiperd/sshpiperd", "-p", piperport, "/sshpiperd/plugins/yaml", "--config", mainConfigPath)
	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}
	defer killCmd(piper)
	waitForEndpointReady(piperaddr)

	t.Run("password_simple", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfile := uuid.New().String()
		runSSHTestUnified(SSHTestParams{
			T:                t,
			PiperPort:        piperport,
			Username:         "password_simple",
			Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
			Password:         "pass",
			PasswordRequired: true,
			ExpectSuccess:    true,
			CheckFile:        true,
			ExpectedText:     randtext,
			TargetFile:       targetfile,
		})
	})
	t.Run("password_regex", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfile := uuid.New().String()
		runSSHTestUnified(SSHTestParams{
			T:                t,
			PiperPort:        piperport,
			Username:         "password_XXX_regex",
			Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
			Password:         "pass",
			PasswordRequired: true,
			ExpectSuccess:    true,
			CheckFile:        true,
			ExpectedText:     randtext,
			TargetFile:       targetfile,
		})
	})
	t.Run("password_regex_expand", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfile := uuid.New().String()
		runSSHTestUnified(SSHTestParams{
			T:                t,
			PiperPort:        piperport,
			Username:         "password_user_regex_expand",
			Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
			Password:         "pass",
			PasswordRequired: true,
			ExpectSuccess:    true,
			CheckFile:        true,
			ExpectedText:     randtext,
			TargetFile:       targetfile,
		})
	})
	t.Run("publickey_simple", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfile := uuid.New().String()
		runSSHTestUnified(SSHTestParams{
			T:                t,
			PiperPort:        piperport,
			Username:         "publickey_simple",
			KeyPath:          path.Join(yamldir, "id_rsa_simple"),
			Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
			PasswordRequired: false,
			ExpectSuccess:    true,
			CheckFile:        true,
			ExpectedText:     randtext,
			TargetFile:       targetfile,
		})
	})
	t.Run("catch_all", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfile := uuid.New().String()
		runSSHTestUnified(SSHTestParams{
			T:                t,
			PiperPort:        piperport,
			Username:         "anyusername",
			KeyPath:          path.Join(yamldir, "id_rsa_catchall"),
			Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
			PasswordRequired: false,
			ExpectSuccess:    true,
			CheckFile:        true,
			ExpectedText:     randtext,
			TargetFile:       targetfile,
		})
	})
	t.Run("publickey_simple_withmultiple_keyfile", func(t *testing.T) {
		wrongkeydir := mustMkdirTemp(t, "", "")
		wrongkeyfile := path.Join(wrongkeydir, "key")
		mustGenKey(t, wrongkeyfile)
		// Try both wrong and correct key
		args := []string{"-v", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-p", piperport, "-l", "publickey_simple", "-i", wrongkeyfile, "-i", path.Join(yamldir, "id_rsa_simple"), "127.0.0.1"}
		randtext := uuid.New().String()
		targetfie := uuid.New().String()
		args = append(args, fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie))
		c, _, _, err := runCmd("ssh", args...)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}
		defer killCmd(c)
		time.Sleep(time.Second)
		checkSharedFileContent(t, targetfie, randtext)
	})
	t.Run("ssh_cert", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfile := uuid.New().String()
		runSSHTestUnified(SSHTestParams{
			T:                t,
			PiperPort:        piperport,
			Username:         "cert",
			KeyPath:          path.Join(yamldir, "user_ca_key"),
			Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
			PasswordRequired: false,
			ExpectSuccess:    true,
			CheckFile:        true,
			ExpectedText:     randtext,
			TargetFile:       targetfile,
		})
	})
	t.Run("group_routing_key", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfile := uuid.New().String()
		runSSHTestUnified(SSHTestParams{
			T:                t,
			PiperPort:        piperport,
			Username:         "testgroupuser",
			KeyPath:          path.Join(yamldir, "id_rsa_simple"),
			Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
			PasswordRequired: false,
			ExpectSuccess:    true,
			CheckFile:        true,
			ExpectedText:     randtext,
			TargetFile:       targetfile,
		})
	})
	t.Run("group_routing_password", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfile := uuid.New().String()
		runSSHTestUnified(SSHTestParams{
			T:                t,
			PiperPort:        piperport,
			Username:         "testgroupuser",
			Password:         "pass",
			PasswordRequired: true,
			Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile),
			ExpectSuccess:    true,
			CheckFile:        true,
			ExpectedText:     randtext,
			TargetFile:       targetfile,
		})
	})

	// CA CERT AUTH: single sshpiperd instance, both positive and negative in subtests
	t.Run("ca_cert_auth", func(t *testing.T) {
		t.Run("testuser", func(t *testing.T) {
			randtext := uuid.New().String()
			targetfile := uuid.New().String()
			runSSHTestUnified(SSHTestParams{
				T:                t,
				PiperPort:        piperport,
				Username:         "testuser",
				KeyPath:          userKey,
				IdentitiesOnly:   true,
				Command:          fmt.Sprintf(`sh -c "echo SSHREADY && sleep 1 && echo -n %v > /shared/%v"`, randtext, targetfile),
				WaitFor:          "SSHREADY",
				StdinTrigger:     "triggerping",
				PasswordRequired: false,
				ExpectSuccess:    true,
				CheckFile:        true,
				ExpectedText:     randtext,
				TargetFile:       targetfile,
			})
		})
		t.Run("invaliduserca", func(t *testing.T) {
			runSSHTestUnified(SSHTestParams{
				T:                t,
				PiperPort:        piperport,
				Username:         "invaliduser",
				KeyPath:          invaliduserKey,
				IdentitiesOnly:   true,
				Command:          "echo shouldfail",
				PasswordRequired: false,
				ExpectSuccess:    false,
				StderrCheck: func(out []byte) {
					if !bytes.Contains(out, []byte("Permission denied")) && !bytes.Contains(out, []byte("no matching pipe")) {
						t.Errorf("SSH failed for unexpected reason: %s", out)
					}
				},
			})
		})
		t.Run("anyusername", func(t *testing.T) {
			randtext := uuid.New().String()
			targetfile := uuid.New().String()
			runSSHTestUnified(SSHTestParams{
				T:                t,
				PiperPort:        piperport,
				Username:         "anyusername",
				KeyPath:          userKey2,
				IdentitiesOnly:   true,
				Command:          fmt.Sprintf(`sh -c "echo SSHREADY && sleep 1 && echo -n %v > /shared/%v"`, randtext, targetfile),
				WaitFor:          "SSHREADY",
				StdinTrigger:     "triggerping",
				PasswordRequired: false,
				ExpectSuccess:    true,
				CheckFile:        true,
				ExpectedText:     randtext,
				TargetFile:       targetfile,
			})
		})
	})
}
