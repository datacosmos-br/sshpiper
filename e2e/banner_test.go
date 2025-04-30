package e2e_test

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBanner(t *testing.T) {
	t.Run("banner via command line argument", func(t *testing.T) {
		piperaddr, piperport := nextAvailablePiperAddress()
		randtext := uuid.New().String()

		piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
			"--banner-text",
			randtext,
			"-p",
			piperport,
			"/sshpiperd/plugins/fixed",
			"--target",
			"host-password:2222",
		)
		require.NoError(t, err, "failed to run sshpiperd")
		defer killCmd(piper)

		waitForEndpointReady(piperaddr)

		c, _, stdout, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"user",
			"127.0.0.1",
		)
		require.NoError(t, err, "failed to ssh to piper")
		defer killCmd(c)

		waitForStdoutContains(stdout, randtext, func(output string) {
			assert.Contains(t, output, randtext, "banner text not found in output")
		})
	})

	t.Run("banner via file", func(t *testing.T) {
		piperaddr, piperport := nextAvailablePiperAddress()
		randtext := uuid.New().String()

		bannerfile, err := os.CreateTemp("", "banner")
		require.NoError(t, err, "failed to create temp file")
		defer func() {
			if err := os.Remove(bannerfile.Name()); err != nil {
				t.Logf("failed to remove temp banner file: %v", err)
			}
		}()

		_, err = bannerfile.WriteString(randtext)
		require.NoError(t, err, "failed to write to temp file")

		err = bannerfile.Close()
		require.NoError(t, err, "failed to close temp file")

		piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
			"--banner-file",
			bannerfile.Name(),
			"-p",
			piperport,
			"/sshpiperd/plugins/fixed",
			"--target",
			"host-password:2222",
		)
		require.NoError(t, err, "failed to run sshpiperd")
		defer killCmd(piper)

		waitForEndpointReady(piperaddr)

		c, _, stdout, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"user",
			"127.0.0.1",
		)
		require.NoError(t, err, "failed to ssh to piper")
		defer killCmd(c)

		waitForStdoutContains(stdout, randtext, func(output string) {
			assert.Contains(t, output, randtext, "banner text from file not found in output")
		})

		t.Run("banner from upstream", func(t *testing.T) {
			piperaddr, piperport := nextAvailablePiperAddress()

			piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
				"-p",
				piperport,
				"/sshpiperd/plugins/fixed",
				"--target",
				"host-password:2222",
			)
			require.NoError(t, err, "failed to run sshpiperd")
			defer killCmd(piper)

			waitForEndpointReady(piperaddr)

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
				"user",
				"127.0.0.1",
			)
			require.NoError(t, err, "failed to ssh to piper")
			defer killCmd(c)

			enterPassword(stdin, stdout, "wrongpass")

			waitForStdoutContains(stdout, "sshpiper banner from upstream test", func(output string) {
				assert.Contains(t, output, "sshpiper banner from upstream test", "upstream banner not found in output")
			})
		})
	})
}
