// Package libplugin: Plugin Entrypoint and CLI Template Helpers for SSHPiper Plugins
//
// Provides helpers for defining a plugin's CLI entrypoint, configuration, and server startup logic in a reusable, idiomatic way.
//
// # Features
//   - PluginEntrypoint: Struct for plugin CLI entrypoint and configuration
//   - RunPluginEntrypoint: Runs a plugin using the provided PluginEntrypoint
//
// # Usage Example
//
//	libplugin.RunPluginEntrypoint(&libplugin.PluginEntrypoint{
//		Name:  "myplugin",
//		Usage: "my sshpiper plugin",
//		Flags: []cli.Flag{...},
//		CreateConfig: func(c *cli.Context) (*libplugin.PluginConfig, error) { ... },
//	})
package libplugin

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

// PluginEntrypoint defines the structure for a plugin's CLI entrypoint and configuration.
//
// Use this struct to specify the plugin's name, usage, CLI flags, log formatter, and a function to create the plugin config.
//
// Example:
//
//	plugin := &libplugin.PluginEntrypoint{
//		Name:  "example",
//		Usage: "example plugin",
//		Flags: []cli.Flag{...},
//		LogFormatter: &logrus.TextFormatter{},
//		CreateConfig: func(c *cli.Context) (*libplugin.PluginConfig, error) { ... },
//	}
//
//	libplugin.RunPluginEntrypoint(plugin)
type PluginEntrypoint struct {
	// Name is the CLI name of the plugin.
	Name string
	// Usage is the CLI usage description.
	Usage string
	// Flags are the CLI flags for the plugin.
	Flags []cli.Flag
	// LogFormatter is the logrus formatter to use for plugin logging.
	LogFormatter logrus.Formatter
	// CreateConfig is a function that returns the plugin's PluginConfig.
	CreateConfig func(c *cli.Context) (*PluginConfig, error)
}

// RunPluginEntrypoint runs a plugin using the provided PluginEntrypoint.
//
// This sets up the CLI, parses flags, and starts the plugin server using the configuration returned by PluginEntrypoint.CreateConfig.
//
// Example:
//
//	libplugin.RunPluginEntrypoint(&libplugin.PluginEntrypoint{...})
func RunPluginEntrypoint(e *PluginEntrypoint) {
	app := &cli.App{
		Name:            e.Name,
		Usage:           e.Usage,
		Flags:           e.Flags,
		HideHelpCommand: true,
		HideHelp:        true,
		Writer:          os.Stderr,
		ErrWriter:       os.Stderr,
		Action: func(c *cli.Context) error {
			if e == nil {
				return fmt.Errorf("plugin entrypoint is nil")
			}

			if e.CreateConfig == nil {
				return fmt.Errorf("plugin entrypoint create config is nil")
			}

			config, err := e.CreateConfig(c)
			if err != nil {
				return err
			}

			p, err := PluginServerFromStdio(*config)
			if err != nil {
				return err
			}

			PluginLogrusConfig(p, e.LogFormatter, nil)
			return p.Serve()
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "cannot start plugin: %v\n", err)
	}
}
