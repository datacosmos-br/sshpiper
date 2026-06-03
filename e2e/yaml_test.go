package e2e_test

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"os"
	"path"
	"strings"
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
# Same downstream username "certroute", routed to a different upstream host
# purely by which CA signed the client certificate (the user/CA/host triple).
- from:
    - username: "certroute"
      trusted_user_ca_keys: {{ .TrustedUserCAKeys_A }}
  to:
    host: host-publickey:2222
    username: "user"
    ignore_hostkey: true
    private_key: {{ .PrivateKey }}
- from:
    - username: "certroute"
      trusted_user_ca_keys: {{ .TrustedUserCAKeys_B }}
  to:
    host: host-password:2222
    username: "user"
    ignore_hostkey: true
    password: "pass"
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
`

func TestYaml(t *testing.T) {
	yamldir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	yamlfile, err := os.OpenFile(path.Join(yamldir, "config.yaml"), os.O_RDWR|os.O_CREATE, 0o400)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	{
		// simple key
		if err := runCmdAndWait("rm", "-f", path.Join(yamldir, "id_rsa_simple")); err != nil {
			t.Errorf("failed to remove id_rsa: %v", err)
		}

		if err := runCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			path.Join(yamldir, "id_rsa_simple"),
		); err != nil {
			t.Errorf("failed to generate private key: %v", err)
		}

		// catch all key
		if err := runCmdAndWait("rm", "-f", path.Join(yamldir, "id_rsa_catchall")); err != nil {
			t.Errorf("failed to remove id_rsa: %v", err)
		}

		if err := runCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			path.Join(yamldir, "id_rsa_catchall"),
		); err != nil {
			t.Errorf("failed to generate private key: %v", err)
		}

		// upstream key
		if err := runCmdAndWait("rm", "-f", path.Join(yamldir, "id_rsa")); err != nil {
			t.Errorf("failed to remove id_rsa: %v", err)
		}

		if err := runCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			path.Join(yamldir, "id_rsa"),
		); err != nil {
			t.Errorf("failed to generate private key: %v", err)
		}

		if err := runCmdAndWait(
			"/bin/cp",
			path.Join(yamldir, "id_rsa.pub"),
			authorizedKeysPath,
		); err != nil {
			t.Errorf("failed to copy public key: %v", err)
		}

		// ssh ca
		if err := runCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			path.Join(yamldir, "ca_key"),
		); err != nil {
			t.Errorf("failed to generate ca key: %v", err)
		}

		if err := runCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			path.Join(yamldir, "user_ca_key"),
		); err != nil {
			t.Errorf("failed to generate user ca key: %v", err)
		}

		if err := runCmdAndWait(
			"ssh-keygen",
			"-s",
			path.Join(yamldir, "ca_key"),
			"-I",
			"cert",
			"-n",
			"cert",
			"-V",
			"+1w",
			path.Join(yamldir, "user_ca_key.pub"),
		); err != nil {
			t.Errorf("failed to sign user ca key: %v", err)
		}

		// CA-based routing fixtures: two trusted CAs (A, B) plus one untrusted
		// CA (C), and a single user key signed by each so that only the issuing
		// CA differs between connections.
		for _, ca := range []string{"ca_key_a", "ca_key_b", "ca_key_c"} {
			if err := runCmdAndWait("ssh-keygen", "-N", "", "-f", path.Join(yamldir, ca)); err != nil {
				t.Errorf("failed to generate %v: %v", ca, err)
			}
		}

		if err := runCmdAndWait("ssh-keygen", "-N", "", "-f", path.Join(yamldir, "route_key")); err != nil {
			t.Errorf("failed to generate route_key: %v", err)
		}

		for ca, certfile := range map[string]string{
			"ca_key_a": "route_key-a-cert.pub",
			"ca_key_b": "route_key-b-cert.pub",
			"ca_key_c": "route_key-c-cert.pub",
		} {
			if err := runCmdAndWait(
				"ssh-keygen",
				"-s", path.Join(yamldir, ca),
				"-I", "certroute",
				"-n", "certroute",
				"-V", "+1w",
				path.Join(yamldir, "route_key.pub"),
			); err != nil {
				t.Errorf("failed to sign route_key with %v: %v", ca, err)
			}
			if err := runCmdAndWait("/bin/cp", path.Join(yamldir, "route_key-cert.pub"), path.Join(yamldir, certfile)); err != nil {
				t.Errorf("failed to stage cert %v: %v", certfile, err)
			}
		}

	}

	knownHostsKeyData, err := runAndGetStdout(
		"ssh-keyscan",
		"-p",
		"2222",
		"host-publickey",
	)
	if err != nil {
		t.Errorf("failed to run ssh-keyscan: %v", err)
	}

	knownHostsPassData, err := runAndGetStdout(
		"ssh-keyscan",
		"-p",
		"2222",
		"host-password",
	)
	if err != nil {
		t.Errorf("failed to run ssh-keyscan : %v", err)
	}
	if err := template.Must(template.New("yaml").Parse(yamlConfigTemplate)).ExecuteTemplate(yamlfile, "yaml", struct {
		KnownHostsKey  string
		KnownHostsPass string
		PrivateKey     string

		AuthorizedKeys_Simple   string
		AuthorizedKeys_Catchall string

		TrustedUserCAKeys   string
		TrustedUserCAKeys_A string
		TrustedUserCAKeys_B string
	}{
		KnownHostsKey:  base64.StdEncoding.EncodeToString(knownHostsKeyData),
		KnownHostsPass: base64.StdEncoding.EncodeToString(knownHostsPassData),
		PrivateKey:     path.Join(yamldir, "id_rsa"),

		AuthorizedKeys_Simple:   path.Join(yamldir, "id_rsa_simple.pub"),
		AuthorizedKeys_Catchall: path.Join(yamldir, "id_rsa_catchall.pub"),

		TrustedUserCAKeys:   path.Join(yamldir, "ca_key.pub"),
		TrustedUserCAKeys_A: path.Join(yamldir, "ca_key_a.pub"),
		TrustedUserCAKeys_B: path.Join(yamldir, "ca_key_b.pub"),
	}); err != nil {
		t.Fatalf("Failed to write yaml file %v", err)
	}

	// dump config.yaml to stdout
	_ = runCmdAndWait("cat", "-n", path.Join(yamldir, "config.yaml"))

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/yaml",
		"--config",
		yamlfile.Name(),
	)
	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)
	waitForEndpointReady(piperaddr)

	t.Run("password_simple", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, stdin, stdout, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"password_simple",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("password_regex", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, stdin, stdout, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"password_XXX_regex",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("password_regex_expand", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, stdin, stdout, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"password_user_regex_expand",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("publickey_simple", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, _, _, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"publickey_simple",
			"-i",
			path.Join(yamldir, "id_rsa_simple"),
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("catch_all", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, _, _, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"anyusername",
			"-i",
			path.Join(yamldir, "id_rsa_catchall"),
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("publickey_simple_withmultiple_keyfile", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		wrongkeydir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Errorf("failed to create temp key file: %v", err)
		}

		wrongkeyfile := path.Join(wrongkeydir, "key")

		if err := runCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			wrongkeyfile,
		); err != nil {
			t.Errorf("failed to generate key: %v", err)
		}

		c, _, _, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"publickey_simple",
			"-i",
			wrongkeyfile,
			"-i",
			path.Join(yamldir, "id_rsa_simple"),
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("ssh_cert", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, _, _, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-o",
			fmt.Sprintf("CertificateFile=%v", path.Join(yamldir, "user_ca_key-cert.pub")),
			"-p",
			piperport,
			"-l",
			"cert",
			"-i",
			path.Join(yamldir, "user_ca_key"),
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("group_routing_key", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, _, _, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"testgroupuser",
			"-i",
			path.Join(yamldir, "id_rsa_simple"),
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("group_routing_password", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, stdin, stdout, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"testgroupuser",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	// cert_ca_routing proves the user/CA/host triple: the same downstream
	// username "certroute", with the same signed key, is routed to a different
	// upstream host depending only on which CA issued the presented certificate,
	// and a certificate from an untrusted CA is rejected.
	t.Run("cert_ca_routing", func(t *testing.T) {
		// serverIPForCert connects as "certroute" with the given certificate and
		// returns the upstream server IP observed via $SSH_CONNECTION.
		serverIPForCert := func(certfile string) string {
			targetfie := uuid.New().String()
			c, _, _, err := runCmd(
				"ssh",
				"-o", "StrictHostKeyChecking=no",
				"-o", "UserKnownHostsFile=/dev/null",
				"-o", "PreferredAuthentications=publickey",
				"-o", fmt.Sprintf("CertificateFile=%v", path.Join(yamldir, certfile)),
				"-p", piperport,
				"-l", "certroute",
				"-i", path.Join(yamldir, "route_key"),
				"127.0.0.1",
				fmt.Sprintf(`sh -c "echo -n $SSH_CONNECTION > /shared/%v"`, targetfie),
			)
			if err != nil {
				t.Errorf("failed to ssh to piper with %v: %v", certfile, err)
			}
			defer killCmd(c)

			time.Sleep(time.Second) // wait for file flush

			b, err := os.ReadFile(fmt.Sprintf("/shared/%v", targetfie))
			if err != nil {
				t.Errorf("failed to read shared file for %v: %v", certfile, err)
				return ""
			}
			fields := strings.Fields(string(b))
			if len(fields) < 3 {
				t.Errorf("unexpected $SSH_CONNECTION %q for %v", string(b), certfile)
				return ""
			}
			return fields[2] // server IP
		}

		ipA := serverIPForCert("route_key-a-cert.pub")
		ipB := serverIPForCert("route_key-b-cert.pub")

		if ipA == "" || ipB == "" {
			t.Fatalf("missing upstream server IP: A=%q B=%q", ipA, ipB)
		}
		if ipA == ipB {
			t.Errorf("CA-based routing failed: both certs reached the same upstream %v", ipA)
		}

		// A certificate signed by an untrusted CA must not match any pipe.
		err := runCmdAndWait(
			"ssh",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "BatchMode=yes",
			"-o", "PreferredAuthentications=publickey",
			"-o", fmt.Sprintf("CertificateFile=%v", path.Join(yamldir, "route_key-c-cert.pub")),
			"-p", piperport,
			"-l", "certroute",
			"-i", path.Join(yamldir, "route_key"),
			"127.0.0.1",
			"true",
		)
		if err == nil {
			t.Errorf("expected connection with untrusted CA certificate to be rejected")
		}
	})
}
