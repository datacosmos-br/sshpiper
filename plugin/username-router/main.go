//go:build full || e2e

package main

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func parseTargetUser(raw string) (target string, username string, err error) {
	// Expect format: [target:port]+user
	parts := strings.SplitN(raw, "+", 2)
	if len(parts) != 2 {
		err = fmt.Errorf("invalid format (expected target:port+user)")
		return
	}

	target = parts[0]
	username = parts[1]
	return
}

func main() {
	libplugin.RunPluginEntrypoint(&libplugin.PluginEntrypoint{
		Name:  "username-router",
		Usage: "routing based on target inside username, format: 'target:port+realuser@sshpiper-host'",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "ignore-hostkey",
				Usage:   "ignore host key validation (SECURITY RISK: enables MITM attacks)",
				EnvVars: []string{"SSHPIPERD_USERNAME_ROUTER_IGNORE_HOSTKEY"},
				Value:   false, // Secure default
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.PluginConfig, error) {
			ignoreHostKey := c.Bool("ignore-hostkey")

			// Log security warning if host key validation is disabled
			if ignoreHostKey {
				log.Warn("SECURITY WARNING: Host key validation is disabled. This makes connections vulnerable to MITM attacks.")
			}

			return &libplugin.PluginConfig{
				PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
					// Validate inputs
					if conn == nil {
						return nil, fmt.Errorf("connection metadata cannot be nil")
					}

					if len(password) == 0 {
						return nil, fmt.Errorf("password cannot be empty")
					}

					username := conn.User()
					if username == "" {
						return nil, fmt.Errorf("username cannot be empty")
					}

					address, user, err := parseTargetUser(username)
					if err != nil {
						return nil, fmt.Errorf("invalid username format %q: %w", username, err)
					}

					host, port, err := libplugin.SplitHostPortForSSH(address)
					if err != nil {
						return nil, fmt.Errorf("invalid target address %q: %w", address, err)
					}

					// Validate host and user
					if host == "" {
						return nil, fmt.Errorf("target host cannot be empty")
					}

					if user == "" {
						return nil, fmt.Errorf("target user cannot be empty")
					}

					// Validate port range
					if port <= 0 || port > 65535 {
						return nil, fmt.Errorf("invalid port %d (must be 1-65535)", port)
					}

					log.Infof("routing to %s:%d with user %s (hostkey validation: %v)", host, port, user, !ignoreHostKey)
					return &libplugin.Upstream{
						UserName:      user,
						Host:          host,
						Port:          int32(port),
						IgnoreHostKey: ignoreHostKey, // Now configurable
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
