package e2e_test

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
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
        - {{ .AuthorizedKeys_Simple }}
        - {{ .AuthorizedKeys_Catchall }}
  to:
    host: host-publickey:2222
    username: "user"
    ignore_hostkey: true
    private_key: {{ .PrivateKey }}
`

func setupTestEnvironment(t *testing.T) (string, *os.File) {
	t.Helper()
	yamldir, err := os.MkdirTemp("", "")
	require.NoError(t, err, "Failed to create temp dir")

	yamlfile, err := os.OpenFile(path.Join(yamldir, "config.yaml"), os.O_RDWR|os.O_CREATE, 0400)
	require.NoError(t, err, "Failed to create temp file")

	return yamldir, yamlfile
}

func generateKeys(t *testing.T, yamldir string) {
	t.Helper()
	keyPairs := []string{"id_rsa_simple", "id_rsa_catchall", "id_rsa"}

	for _, keyName := range keyPairs {
		require.NoError(t, runCmdAndWait("rm", "-f", path.Join(yamldir, keyName)))
		require.NoError(t, runCmdAndWait(
			"ssh-keygen",
			"-N",
			"",
			"-f",
			path.Join(yamldir, keyName),
		))
	}

	require.NoError(t, runCmdAndWait(
		"/bin/cp",
		path.Join(yamldir, "id_rsa.pub"),
		"/publickey_authorized_keys/authorized_keys",
	))

	// Generate CA keys
	require.NoError(t, runCmdAndWait(
		"ssh-keygen",
		"-N",
		"",
		"-f",
		path.Join(yamldir, "ca_key"),
	))

	require.NoError(t, runCmdAndWait(
		"ssh-keygen",
		"-N",
		"",
		"-f",
		path.Join(yamldir, "user_ca_key"),
	))

	require.NoError(t, runCmdAndWait(
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
	))
}

func TestYaml(t *testing.T) {
	yamldir, yamlfile := setupTestEnvironment(t)
	generateKeys(t, yamldir)
	knownHostsKeyData, err := runAndGetStdout("ssh-keyscan", "-p", "2222", "host-publickey")
	require.NoError(t, err, "Failed to run ssh-keyscan for host-publickey")
	knownHostsPassData, err := runAndGetStdout("ssh-keyscan", "-p", "2222", "host-password")
	require.NoError(t, err, "Failed to run ssh-keyscan for host-password")

	templateData := struct {
		KnownHostsKey           string
		KnownHostsPass          string
		PrivateKey              string
		AuthorizedKeys_Simple   string
		AuthorizedKeys_Catchall string
		TrustedUserCAKeys       string
	}{
		KnownHostsKey:           base64.StdEncoding.EncodeToString(knownHostsKeyData),
		KnownHostsPass:          base64.StdEncoding.EncodeToString(knownHostsPassData),
		PrivateKey:              path.Join(yamldir, "id_rsa"),
		AuthorizedKeys_Simple:   path.Join(yamldir, "id_rsa_simple.pub"),
		AuthorizedKeys_Catchall: path.Join(yamldir, "id_rsa_catchall.pub"),
		TrustedUserCAKeys:       path.Join(yamldir, "ca_key.pub"),
	}

	require.NoError(t, template.Must(template.New("yaml").Parse(yamlConfigTemplate)).ExecuteTemplate(yamlfile, "yaml", templateData))

	piperaddr, piperport := nextAvailablePiperAddress()
	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/yaml",
		"--config",
		yamlfile.Name(),
	)
	require.NoError(t, err, "Failed to run sshpiperd")
	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	testCases := []struct {
		name     string
		username string
		keyPath  string
		usePass  bool
	}{
		{"password_simple", "password_simple", "", true},
		{"password_regex", "password_XXX_regex", "", true},
		{"password_regex_expand", "password_user_regex_expand", "", true},
		{"publickey_simple", "publickey_simple", path.Join(yamldir, "id_rsa_simple"), false},
		{"catch_all", "anyusername", path.Join(yamldir, "id_rsa_catchall"), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			randtext := uuid.New().String()
			targetfile := uuid.New().String()

			args := []string{
				"-v",
				"-o", "StrictHostKeyChecking=no",
				"-o", "UserKnownHostsFile=/dev/null",
				"-p", piperport,
				"-l", tc.username,
			}

			if tc.keyPath != "" {
				args = append(args, "-i", tc.keyPath)
			}

			args = append(args, "127.0.0.1", fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfile))
			c, stdin, stdout, err := runCmd("ssh", args...)
			require.NoError(t, err, "Failed to ssh to piper")
			defer killCmd(c)

			if tc.usePass {
				enterPassword(stdin, stdout, "pass")
			}

			time.Sleep(time.Second)
			checkSharedFileContent(t, targetfile, randtext)
		})
	}
}

func TestGroupRoutingPassword(t *testing.T) {
	waitForEndpointReady("host-password:2222")
	randtext := uuid.New().String()
	targetfile := uuid.New().String()

	c, stdin, stdout, err := runCmd(
		"ssh",
		"-v",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-p", "2222",
		"-l", "testuser",
		"host-password",
		fmt.Sprintf(`sh -c \"echo -n %v > /shared/%v\"`, randtext, targetfile),
	)
	require.NoError(t, err, "Failed to ssh to piper")
	defer killCmd(c)

	enterPassword(stdin, stdout, "pass")

	time.Sleep(time.Second)
	checkSharedFileContent(t, targetfile, randtext)
}

func TestInvalidPassword(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()
	piper, _, _, err := runCmd("/sshpiperd/sshpiperd", "-p", piperport, "/sshpiperd/plugins/fixed", "--target", "host-password:2222")
	require.NoError(t, err)
	defer killCmd(piper)
	waitForEndpointReady(piperaddr)

	c, stdin, stdout, err := runCmd("ssh", "-v", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-p", piperport, "-l", "user", "127.0.0.1")
	require.NoError(t, err)
	defer killCmd(c)
	enterPassword(stdin, stdout, "wrongpassword")
	time.Sleep(time.Second)
	s, _ := io.ReadAll(stdout)
	require.Contains(t, string(s), "Permission denied", "Expected permission denied for wrong password")
}

func TestMultiFactorAuth(t *testing.T) {
	t.Skip("Multi-factor auth test not implemented: requires plugin/config that enforces both public key and password.")
}

func TestCRDInvalidManifest(t *testing.T) {
	t.Skip("CRD validation test not implemented: requires k8s cluster and invalid manifest application.")
}

func TestParallelSessions(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()
	piper, _, _, err := runCmd("/sshpiperd/sshpiperd", "-p", piperport, "/sshpiperd/plugins/fixed", "--target", "host-password:2222")
	require.NoError(t, err)
	defer killCmd(piper)
	waitForEndpointReady(piperaddr)

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c, stdin, stdout, err := runCmd("ssh", "-v", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-p", piperport, "-l", "user", "127.0.0.1")
			require.NoError(t, err)
			defer killCmd(c)
			enterPassword(stdin, stdout, "pass")
			time.Sleep(time.Second)
			_ = stdout
		}(i)
	}
	wg.Wait()
}

func TestPluginChaining(t *testing.T) {
	t.Skip("Plugin chaining test not implemented: requires multi-plugin orchestration.")
}
