package e2e_test

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestConnMeta(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/testsetmetaplugin",
		"--targetaddr",
		"host-password:2222",
		"--",
		"/sshpiperd/plugins/testgetmetaplugin",
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	randtext := uuid.New().String()
	targetfie := uuid.New().String()

	runSSHTestUnified(SSHTestParams{
		T:                t,
		PiperPort:        piperport,
		Username:         "user",
		Password:         "pass",
		PasswordRequired: true,
		Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		ExpectSuccess:    true,
		CheckFile:        true,
		ExpectedText:     randtext,
		TargetFile:       targetfie,
	})
}
