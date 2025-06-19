//go:build e2e

package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {

<<<<<<< HEAD
	libplugin.RunPluginEntrypoint(&libplugin.PluginEntrypoint{
		Name: "getmeta",
		CreateConfig: func(c *cli.Context) (*libplugin.PluginConfig, error) {

			return &libplugin.PluginConfig{
				PasswordCallback: func(conn libplugin.PluginConnMetadata, password []byte) (*libplugin.Upstream, error) {

=======
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name: "getmeta",
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {

			return &libplugin.SshPiperPluginConfig{
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {

>>>>>>> upstream/master
					target := conn.GetMeta("targetaddr")

					host, port, err := libplugin.SplitHostPortForSSH(target)
					if err != nil {
						return nil, err
					}

					log.Info("routing to ", target)
					return &libplugin.Upstream{
						Host:          host,
						Port:          int32(port),
						IgnoreHostKey: true,
						Auth:          libplugin.AuthPasswordCreate(password),
					}, nil
				},
			}, nil
		},
	})
}
