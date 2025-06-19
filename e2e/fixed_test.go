package e2e_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestFixed(t *testing.T) {

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/fixed",
		"--target",
		"host-password:2222",
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	for _, tc := range []struct {
		name string
		bin  string
	}{
		{
			name: "without-sshping",
			bin:  "ssh-8.0p1",
		},
		{
			name: "with-sshping",
			bin:  "ssh-9.8p1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			randtext := uuid.New().String()
			targetfie := uuid.New().String()

			runSSHTestUnified(SSHTestParams{
				T:                t,
				PiperPort:        piperport,
				Username:         "user",
				Password:         "pass",
				PasswordRequired: true,
				SSHBin:           tc.bin,
				Command:          fmt.Sprintf(`sh -c "echo SSHREADY && sleep 1 && echo -n %v > /shared/%v"`, randtext, targetfie),
				WaitFor:          "SSHREADY",
				StdinTrigger:     "triggerping",
				ExpectSuccess:    true,
				CheckFile:        true,
				ExpectedText:     randtext,
				TargetFile:       targetfie,
			})
		})
	}

}

func TestHostkeyParam(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()
	keyparam := base64.StdEncoding.EncodeToString([]byte(testprivatekey))

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"--server-key-data",
		keyparam,
		"/sshpiperd/plugins/fixed",
		"--target",
		"host-password:2222",
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	b, err := runAndGetStdout(
		"ssh-keyscan",
		"-p",
		piperport,
		"127.0.0.1",
	)

	if !strings.Contains(string(b), testpublickey) {
		t.Errorf("failed to get correct hostkey, %v", err)
	}
}
