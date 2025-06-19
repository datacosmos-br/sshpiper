package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {
	// Run the failtoban plugin entrypoint.
	libplugin.RunPluginEntrypoint(&libplugin.PluginEntrypoint{
		Name:  "failtoban",
		Usage: "failtoban plugin, block ip after too many auth failures",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "max-failures",
				Usage:   "max failures",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_MAX_FAILURES"},
				Value:   5,
			},
			&cli.DurationFlag{
				Name:    "ban-duration",
				Usage:   "ban duration",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_BAN_DURATION"},
				Value:   60 * time.Minute,
			},
			&cli.BoolFlag{
				Name:    "log-only",
				Usage:   "log only mode, no ban, useful for working with other tools like fail2ban",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_LOG_ONLY"},
				Value:   false,
			},
			&cli.StringSliceFlag{
				Name:    "ignore-ip",
				Usage:   "ignore ip, will not ban host matches from these ip addresses",
				EnvVars: []string{"SSHPIPERD_FAILTOBAN_IGNORE_IP"},
				Value:   cli.NewStringSlice(),
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.PluginConfig, error) {
			maxFailures := c.Int("max-failures")
			banDuration := c.Duration("ban-duration")
			logOnly := c.Bool("log-only")
			ignoreIP := c.StringSlice("ignore-ip")

			banCache := libplugin.NewBanCache(maxFailures, banDuration)
			whitelist := libplugin.BuildIPSet(ignoreIP)

			// register signal handler for cache flush
			go func() {
				sigChan := make(chan os.Signal, 1)
				signal.Notify(sigChan, syscall.SIGHUP)
				for range sigChan {
					banCache.Flush()
					log.Info("failtoban: cache reset due to SIGHUP")
				}
			}()

			return &libplugin.PluginConfig{
				NoClientAuthCallback: func(conn libplugin.PluginConnMetadata) (*libplugin.Upstream, error) {
					// in case someone put the failtoban plugin before other plugins
					return &libplugin.Upstream{
						Auth: libplugin.AuthNextPluginCreate(map[string]string{}),
					}, nil
				},
				NewConnectionCallback: func(conn libplugin.PluginConnMetadata) error {
					if logOnly {
						return nil
					}
					ip, _, _ := net.SplitHostPort(conn.RemoteAddr())
					ip0, _ := netip.ParseAddr(ip)
					if whitelist != nil && whitelist.Contains(ip0) {
						log.Debugf("failtoban: %v in whitelist, ignored.", ip0)
						return nil
					}
					banned, err := banCache.CheckAndAdd(ip)
					if err != nil {
						return err
					}
					if banned {
						return fmt.Errorf("failtoban: ip %v too many auth failures", ip)
					}
					return nil
				},
				UpstreamAuthFailureCallback: func(conn libplugin.PluginConnMetadata, method string, err error, allowmethods []string) {
					ip, _, _ := net.SplitHostPort(conn.RemoteAddr())
					ip0, _ := netip.ParseAddr(ip)
					if whitelist != nil && whitelist.Contains(ip0) {
						log.Debugf("failtoban: %v in whitelist, ignored.", ip0)
						return
					}
					failed := banCache.Increment(ip)
					log.Warnf("failtoban: %v auth failed. current status: fail %v times, max allowed %v", ip, failed, maxFailures)
				},
				PipeCreateErrorCallback: func(remoteAddr string, err error) {
					ip, _, _ := net.SplitHostPort(remoteAddr)
					ip0, _ := netip.ParseAddr(ip)
					if whitelist != nil && whitelist.Contains(ip0) {
						log.Debugf("failtoban: %v in whitelist, ignored.", ip0)
						return
					}
					failed := banCache.Increment(ip)
					log.Warnf("failtoban: %v pipe create failed, reason %v. current status: fail %v times, max allowed %v", ip, err, failed, maxFailures)
				},
			}, nil
		},
	})
}
