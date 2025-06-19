package e2e_test

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/google/uuid"
)

func TestDocker(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/docker",
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	t.Run("password", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		runSSHTestUnified(SSHTestParams{
			T:                t,
			PiperPort:        piperport,
			Username:         "pass",
			Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
			Password:         "pass",
			PasswordRequired: true,
			ExpectSuccess:    true,
			CheckFile:        true,
			ExpectedText:     randtext,
			TargetFile:       targetfie,
		})
	})

	t.Run("key", func(t *testing.T) {
		keyfiledir := mustMkdirTemp(t, "", "")
		keyfile := path.Join(keyfiledir, "key")

		if err := os.WriteFile(keyfile, []byte(testprivatekey), 0400); err != nil {
			t.Errorf("failed to write to test key: %v", err)
		}

		if err := os.WriteFile("/publickey_authorized_keys/authorized_keys", []byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINRGTH325rDUp12tplwukHmR8ytbC9TPZ886gCstynP1`), 0400); err != nil {
			t.Errorf("failed to write to authorized_keys: %v", err)
		}

		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		runSSHTestUnified(SSHTestParams{
			T:                t,
			PiperPort:        piperport,
			Username:         "anyuser",
			KeyPath:          keyfile,
			Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
			PasswordRequired: false,
			ExpectSuccess:    true,
			CheckFile:        true,
			ExpectedText:     randtext,
			TargetFile:       targetfie,
		})
	})
}
