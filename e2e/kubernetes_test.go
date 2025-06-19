package e2e_test

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestKubernetes(t *testing.T) {
	piperhost := "host-k8s-proxy"
	piperport := "2222"
	piperaddr := piperhost + ":" + piperport
	waitForEndpointReadyWithTimeout(piperaddr, time.Minute*5)

	pubkeycases := []struct {
		title string
		user  string
	}{
		{
			title: "key_pubkey_cacthall",
			user:  "anyuser",
		},
		{
			title: "key_custom_field",
			user:  "custom_field",
		},
		{
			title: "key_authorizedfile",
			user:  "authorizedfile",
		},
		{
			title: "key_public_ca",
			user:  "hostcapublickey",
		},
		{
			title: "key_to_pass",
			user:  "keytopass",
		},
	}

	for _, testcase := range pubkeycases {
		t.Run(testcase.title, func(t *testing.T) {
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
				Username:         testcase.user,
				Host:             piperhost,
				KeyPath:          keyfile,
				Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
				ExpectSuccess:    true,
				CheckFile:        true,
				ExpectedText:     randtext,
				TargetFile:       targetfie,
				PasswordRequired: false,
			})
		})
	}

	passwordcases := []struct {
		title    string
		user     string
		password string
	}{
		{
			title:    "password",
			user:     "pass",
			password: "pass",
		},
		{
			title:    "password_htpwd",
			user:     "htpwd",
			password: "htpassword",
		},
		{
			title:    "password_htpasswd_file",
			user:     "htpwdfile",
			password: "htpasswordfile",
		},
	}

	for _, testcase := range passwordcases {
		t.Run(testcase.title, func(t *testing.T) {
			randtext := uuid.New().String()
			targetfie := uuid.New().String()
			runSSHTestUnified(SSHTestParams{
				T:                t,
				PiperPort:        piperport,
				Username:         testcase.user,
				Host:             piperhost,
				Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
				Password:         testcase.password,
				PasswordRequired: true,
				ExpectSuccess:    true,
				CheckFile:        true,
				ExpectedText:     randtext,
				TargetFile:       targetfie,
			})
		})
	}

	t.Run("fallback to password", func(t *testing.T) {
		randtext := uuid.New().String()
		targetfie := uuid.New().String()
		keyfiledir := mustMkdirTemp(t, "", "")
		keyfile := path.Join(keyfiledir, "key")
		mustGenKey(t, keyfile)
		runSSHTestUnified(SSHTestParams{
			T:                t,
			PiperPort:        piperport,
			Username:         "pass",
			Host:             piperhost,
			KeyPath:          keyfile,
			Command:          fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
			Password:         "pass",
			PasswordRequired: true,
			ExpectSuccess:    true,
			CheckFile:        true,
			ExpectedText:     randtext,
			TargetFile:       targetfie,
		})
	})
}
