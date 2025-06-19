//go:build e2e

package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {

	libplugin.RunPluginEntrypoint(&libplugin.PluginEntrypoint{
		Name: "setmeta",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "targetaddr",
				Required: true,
			},
		},
		CreateConfig: func(ctx *cli.Context) (*libplugin.PluginConfig, error) {
			return &libplugin.PluginConfig{

				NoClientAuthCallback: func(conn libplugin.ConnMetadata) (*libplugin.Upstream, error) {

					return &libplugin.Upstream{
						Auth: libplugin.AuthNextPluginCreate(map[string]string{
							"targetaddr": ctx.String("targetaddr"),
						}),
					}, nil
				},
			}, nil
		},
	})
}
