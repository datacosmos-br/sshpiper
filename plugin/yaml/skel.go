// Package main implements the YAML plugin for sshpiperd.
package main

import (
	"os/user"
	"path/filepath"
	"regexp"
	"slices"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/skel"
)

// plugin implements the YAML plugin entrypoint.
type plugin struct {
	FileGlobs   cli.StringSlice
	NoCheckPerm bool
}

// newYamlPlugin returns a new YAML plugin instance.
func newYamlPlugin() *plugin {
	return &plugin{}
}

type skelpipeToWrapper struct {
	config *piperConfig

	username string
	to       *yamlPipeTo
}

type skelpipeToPasswordWrapper struct {
	skelpipeToWrapper
}

func (s *skelpipeToPasswordWrapper) User(_ libplugin.ConnMetadata) string {
	return s.username
}

type skelpipeToPrivateKeyWrapper struct {
	skelpipeToWrapper
}

func (s *skelpipeToPrivateKeyWrapper) User(_ libplugin.ConnMetadata) string {
	return s.username
}

// Define missing wrapper structures for YAML plugin
type skelpipeWrapper struct {
	config *piperConfig
	pipe   *yamlPipe
}

type skelpipeFromWrapper struct {
	config *piperConfig
	from   *yamlPipeFrom
	to     *yamlPipeTo
}

type skelpipePublicKeyWrapper struct {
	skelpipeFromWrapper
}

// AuthorizedKeys implements SkelPipeFromPublicKey interface
func (s *skelpipePublicKeyWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	envVars := map[string]string{
		"DOWNSTREAM_USER": conn.User(),
	}
	return libplugin.StandardAuthorizedKeys(s.from.AuthorizedKeysData.Str, s.from.AuthorizedKeys.Str, envVars, filepath.Dir(s.config.filename))
}

// TrustedUserCAKeys implements SkelPipeFromPublicKey interface
func (s *skelpipePublicKeyWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	envVars := map[string]string{
		"DOWNSTREAM_USER": conn.User(),
	}
	return libplugin.StandardTrustedUserCAKeys(s.from.TrustedUserCAKeysData.Str, s.from.TrustedUserCAKeys.Str, envVars, filepath.Dir(s.config.filename))
}

type skelpipePasswordWrapper struct {
	skelpipeFromWrapper
}

// TestPassword implements SkelPipeFromPassword interface
func (s *skelpipePasswordWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	return libplugin.StandardTestPassword(s.from.HtpasswdData, s.from.HtpasswdFile, conn.User(), password)
}

func (s *skelpipeWrapper) From() []skel.SkelPipeFrom {
	var froms []skel.SkelPipeFrom
	for _, f := range s.pipe.From {

		w := &skelpipeFromWrapper{
			config: s.config,
			from:   &f,
			to:     &s.pipe.To,
		}

		if f.SupportPublicKey() {
			froms = append(froms, &skelpipePublicKeyWrapper{
				skelpipeFromWrapper: *w,
			})
		} else {
			froms = append(froms, &skelpipePasswordWrapper{
				skelpipeFromWrapper: *w,
			})
		}
	}
	// Return the actual froms array with YAML pipe configurations
	return froms
}

func (s *skelpipeToWrapper) Host(_ libplugin.ConnMetadata) string {
	return s.to.Host
}

func (s *skelpipeToWrapper) IgnoreHostKey(_ libplugin.ConnMetadata) bool {
	return libplugin.StandardIgnoreHostKey(s.to.IgnoreHostkey, s.to.KnownHostsData.Str, s.to.KnownHosts.Str)
}

func (s *skelpipeToWrapper) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	return s.config.loadFileOrDecodeMany(s.to.KnownHosts, s.to.KnownHostsData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   s.username,
	})
}

func (s *skelpipeFromWrapper) MatchConn(conn libplugin.ConnMetadata) (skel.SkelPipeTo, error) {
	username := conn.User()
	targetuser := s.to.Username

	var matched bool
	if s.from.Username != "" {
		matched = s.from.Username == username
		if s.from.UsernameRegexMatch {
			// RESTORED: Real regex functionality
			re, err := regexp.Compile(s.from.Username)
			if err != nil {
				return nil, err
			}
			matched = re.MatchString(username)

			// Handle group matching if specified
			if s.from.Groupname != "" {
				// Get user groups for group-based matching
				usr, err := user.Lookup(username)
				if err != nil {
					log.Errorf("Failed to lookup user %s: %v", username, err)
					return nil, err
				}
				userGroups, err := getUserGroups(usr)
				if err != nil {
					log.Errorf("Failed to get groups for user %s: %v", username, err)
					return nil, err
				}
				matched = slices.Contains(userGroups, s.from.Groupname)
			}
		}
		if targetuser == "" {
			targetuser = username
		}
		if matched {
			// Create a simple wrapper for the TO configuration
			wrapper := &skelpipeToWrapper{
				config:   s.config,
				username: targetuser,
				to:       s.to,
			}

			// Return appropriate wrapper based on authentication method
			if s.to.PrivateKey != "" || s.to.PrivateKeyData != "" {
				return &skelpipeToPrivateKeyWrapper{skelpipeToWrapper: *wrapper}, nil
			} else {
				return &skelpipeToPasswordWrapper{skelpipeToWrapper: *wrapper}, nil
			}
		}
		return nil, nil
	}
	return nil, nil
}

func (s *skelpipeToPrivateKeyWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	// Use standard helper for private key loading
	envVars := map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   s.username,
	}
	return libplugin.StandardPrivateKey(s.to.PrivateKeyData, s.to.PrivateKey, envVars, filepath.Dir(s.config.filename))
}

func (p *plugin) loadConfig() ([]piperConfig, error) {
	var configs []piperConfig
	_, err := libplugin.LoadYAMLConfigFiles(p.FileGlobs.Value(), p.NoCheckPerm, &configs)
	if err != nil {
		return nil, err
	}
	return configs, nil
}

func (p *plugin) listPipe(_ libplugin.ConnMetadata) ([]skel.SkelPipe, error) {
	configs, err := p.loadConfig()
	if err != nil {
		return nil, err
	}

	var pipes []skel.SkelPipe
	for _, config := range configs {
		for _, pipe := range config.Pipes {
			wrapper := &skelpipeWrapper{
				config: &config,
				pipe:   &pipe,
			}
			pipes = append(pipes, wrapper)

		}
	}

	return pipes, nil
}

func getUserGroups(usr *user.User) ([]string, error) {
	groupIds, err := usr.GroupIds()
	if err != nil {
		log.Errorf("[ERROR] getUserGroups(): Failure retrieving group IDs for %q: %T - %v", usr.Username, err, err)
		return nil, err
	}

	var groups []string
	for _, groupId := range groupIds {
		grp, err := user.LookupGroupId(groupId)
		if err != nil {
			log.Errorf("[ERROR] getUserGroups(): Failure retrieving group name for %q: %T - %v", usr.Username, err, err)
			return nil, err
		}
		groups = append(groups, grp.Name)
	}

	return groups, nil
}
