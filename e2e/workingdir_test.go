package e2e_test

import (
	"fmt"
	"log"
	"os"
	"path"
	"testing"

	"github.com/google/uuid"
)

const workingdir = "/shared/workingdir"

func ensureWorkingDirectory() {
	err := os.MkdirAll(workingdir, 0700)
	if err != nil {
		log.Panicf("failed to create working directory %s: %v", workingdir, err)
	}
}

func TestWorkingDirectory(t *testing.T) {

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/workingdir",
		"--root",
		workingdir,
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	ensureWorkingDirectory()

	t.Run("bypassword", func(t *testing.T) {
		userdir := path.Join(workingdir, "bypassword")

		{
			if err := os.MkdirAll(userdir, 0700); err != nil {
				t.Errorf("failed to create working directory %s: %v", userdir, err)
			}

			if err := os.WriteFile(path.Join(userdir, "sshpiper_upstream"), []byte("user@host-password:2222"), 0400); err != nil {
				t.Errorf("failed to write upstream file: %v", err)
			}
		}

		{
			b := mustKeyScan(t, "2222", "host-password")
			if err := os.WriteFile(path.Join(userdir, "known_hosts"), b, 0400); err != nil {
				t.Errorf("failed to write known_hosts: %v", err)
			}
		}

		{
			randtext := uuid.New().String()
			targetfie := uuid.New().String()

			runSSHTestUnified(SSHTestParams{
				T:                t,
				PiperPort:        piperport,
				Username:         "bypassword",
				Password:         "pass",
				PasswordRequired: true,
				Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
				ExpectSuccess:    true,
				CheckFile:        true,
				ExpectedText:     randtext,
				TargetFile:       targetfie,
			})
		}
	})

	t.Run("bypublickey", func(t *testing.T) {
		userdir := path.Join(workingdir, "bypublickey")
		if err := os.MkdirAll(userdir, 0700); err != nil {
			t.Errorf("failed to create working directory %s: %v", userdir, err)
		}

		if err := os.WriteFile(path.Join(userdir, "sshpiper_upstream"), []byte("user@host-publickey:2222"), 0400); err != nil {
			t.Errorf("failed to write upstream file: %v", err)
		}

		{
			b := mustKeyScan(t, "2222", "host-publickey")
			if err := os.WriteFile(path.Join(userdir, "known_hosts"), b, 0400); err != nil {
				t.Errorf("failed to write known_hosts: %v", err)
			}
		}

		keydir := mustMkdirTemp(t, "", "")

		{
			mustGenKey(t, path.Join(keydir, "id_rsa"))

			if err := runCmdAndWait(
				"/bin/cp",
				path.Join(keydir, "id_rsa.pub"),
				path.Join(userdir, "authorized_keys"),
			); err != nil {
				t.Errorf("failed to copy public key: %v", err)
			}

			if err := runCmdAndWait(
				"chmod",
				"0400",
				path.Join(userdir, "authorized_keys"),
			); err != nil {
				t.Errorf("failed to chmod public key: %v", err)
			}

			// set upstream key
			mustGenKey(t, path.Join(userdir, "id_rsa"))

			if err := runCmdAndWait(
				"/bin/cp",
				path.Join(userdir, "id_rsa.pub"),
				"/publickey_authorized_keys/authorized_keys",
			); err != nil {
				t.Errorf("failed to copy public key: %v", err)
			}
		}

		{
			randtext := uuid.New().String()
			targetfie := uuid.New().String()

			runSSHTestUnified(SSHTestParams{
				T:             t,
				PiperPort:     piperport,
				Username:      "bypublickey",
				KeyPath:       path.Join(keydir, "id_rsa"),
				Command:       fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
				ExpectSuccess: true,
				CheckFile:     true,
				ExpectedText:  randtext,
				TargetFile:    targetfie,
			})
		}
	})
}
