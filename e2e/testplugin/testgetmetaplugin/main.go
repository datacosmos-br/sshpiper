//go:build full || e2e

package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {
	libplugin.RunPluginEntrypoint(&libplugin.PluginEntrypoint{
		Name:  "testgetmetaplugin",
		Usage: "test plugin for getting metadata",
		CreateConfig: func(c *cli.Context) (*libplugin.PluginConfig, error) {
			return &libplugin.PluginConfig{
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					return &libplugin.Upstream{
						UserName:      "user",
						Host:          "host-password",
						Port:          2222,
						IgnoreHostKey: true,
						Auth: &libplugin.Upstream_Password{
							Password: &libplugin.UpstreamPasswordAuth{
								Password: string(password),
							},
						},
					}, nil
				},
			}, nil
		},
	})
}
