package main

import (
	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/skel"
	"github.com/urfave/cli/v2"
)

func main() {
	libplugin.RunPluginEntrypoint(&libplugin.PluginEntrypoint{
		Name:  "docker",
		Usage: "sshpiperd docker plugin, see config in https://github.com/tg123/sshpiper/tree/master/plugin/docker",
		CreateConfig: func(c *cli.Context) (*libplugin.PluginConfig, error) {
			plugin, err := newDockerPlugin()
			if err != nil {
				return nil, err
			}

			skel := skel.NewSkelPlugin(plugin.listPipe)
			return skel.CreateConfig(), nil
		},
	})
}
