package main

import (
	"fmt"
	"math/rand"
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {

	libplugin.RunPluginEntrypoint(&libplugin.PluginEntrypoint{
		Name:  "simplemath",
		Usage: "sshpiperd simplemath plugin, do math before ssh login",
		CreateConfig: func(_ *cli.Context) (*libplugin.PluginConfig, error) {
			return &libplugin.PluginConfig{
				KeyboardInteractiveCallback: func(conn libplugin.ConnMetadata, client libplugin.KeyboardInteractiveChallenge) (*libplugin.Upstream, error) {
					if conn == nil {
						return nil, fmt.Errorf("connection metadata cannot be nil")
					}

					// Initial challenge message
					_, _ = client("", "lets do math", "", false)

					for {
						a := rand.Intn(10)
						b := rand.Intn(10)
						expectedAnswer := a + b

						ans, err := client("", "", fmt.Sprintf("what is %v + %v = ", a, b), true)
						if err != nil {
							log.WithFields(log.Fields{
								"user":  conn.User(),
								"addr":  conn.RemoteAddr(),
								"error": err.Error(),
							}).Warn("simplemath challenge failed")
							return nil, err
						}

						// Validate answer (no logging of actual answer for security)
						if ans == fmt.Sprintf("%v", expectedAnswer) {
							log.WithFields(log.Fields{
								"user": conn.User(),
								"addr": conn.RemoteAddr(),
							}).Info("simplemath challenge completed successfully")

							return &libplugin.Upstream{
								Auth: libplugin.AuthNextPluginCreate(map[string]string{
									"a":   strconv.Itoa(a),
									"b":   strconv.Itoa(b),
									"ans": ans,
								}),
							}, nil
						}

						// Log failed attempt without exposing the answer
						log.WithFields(log.Fields{
							"user": conn.User(),
							"addr": conn.RemoteAddr(),
						}).Debug("simplemath challenge incorrect, retrying")
					}
				},
			}, nil
		},
	})
}
