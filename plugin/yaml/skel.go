// Package main implements the YAML plugin for sshpiperd.
package main

import (
	"errors"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"

	log "github.com/sirupsen/logrus"

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

type skelpipeToPrivateKeyWrapper struct {
	skelpipeToWrapper
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
	return libplugin.ListPipeGeneric(
		func() ([]interface{}, error) {
			var out []interface{}
			for i := range configs {
				for j := range configs[i].Pipes {
					out = append(out, &configs[i].Pipes[j])
				}
			}
			return out, nil
		},
		func(pipe interface{}) libplugin.SkelPipe {
			return &yamlSkelPipeWrapper{libplugin.NewSkelPipeWrapper(&configs[0], pipe.(*yamlPipe))}
		},
	)
}

// yamlSkelPipeWrapper wraps a YAML pipe for use with the SkelPipe interface.
// It delegates generic SkelPipe logic to libplugin and provides YAML-specific connection matching.
type yamlSkelPipeWrapper struct {
	libplugin.SkelPipeWrapper
}

func (s *skelpipeToWrapper) Host(conn libplugin.ConnMetadata) string {
	return s.to.Host
}

func (s *skelpipeToWrapper) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	return s.to.IgnoreHostkey
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
			re, err := regexp.Compile(s.from.Username)
			if err != nil {
				return nil, err
			}
			fromPipeGroup := f.Groupname
			matched = slices.Contains(userGroups, fromPipeGroup)
		}
		if targetuser == "" {
			targetuser = username
		}
		if matched {
			if err := libplugin.ValidateRequiredFields(to, "Host"); err != nil {
				return nil, err
			}
			knownHostsFn := libplugin.BuildKnownHostsFn(
				to.KnownHosts.Str,
				to.KnownHostsData.Str,
				map[string]string{
					"DOWNSTREAM_USER": conn.User(),
					"UPSTREAM_USER":   targetuser,
				},
				filepath.Dir(config.filename),
			)
			toWrap := libplugin.NewSkelPipeToWrapper(config, to, targetuser, to.Host, to.IgnoreHostkey, knownHostsFn)
			return &toWrap, nil
		}
		return nil, nil
	}
	return libplugin.FromGeneric(config, to, fromSpecs, matchConnFn, nil)
}

// ValidateCertificate validates an SSH certificate for a downstream connection using the configured trusted CA keys.
// It loads all trusted CA keys from the YAML pipe's 'from' specs and delegates to libplugin.MatchAndValidateCACert.
func (s *yamlSkelPipeWrapper) ValidateCertificate(conn libplugin.PluginConnMetadata, pubKey ssh.PublicKey) error {
	config := s.Plugin.(*piperConfig)
	pipe := s.Pipe.(*yamlPipe)
	fromSpecs := libplugin.ExtractSpecs(pipe.From)
	return libplugin.ValidateCertificateFromSpecs(
		fromSpecs,
		conn,
		pubKey,
		filepath.Dir(config.filename),
		[]string{"TrustedUserCAKeys", "TrustedUserCAKeysData", "trusted_user_ca_keys", "trusted_user_ca_keys_data", "ca-key"},
	)
}

// TestPassword checks the password using generic logic (Vault, file, base64).
func (s *yamlSkelPipeWrapper) TestPassword(conn libplugin.PluginConnMetadata, password []byte) (bool, error) {
	pipe := s.Pipe.(*yamlPipe)
	fromSpecs := libplugin.ExtractSpecs(pipe.From)
	return libplugin.CheckPasswordFromSpecs(fromSpecs, conn.User(), password)
}

// AuthorizedKeys loads authorized keys from all 'from' specs using generic aggregation.
func (s *yamlSkelPipeWrapper) AuthorizedKeys(conn libplugin.PluginConnMetadata) ([]byte, error) {
	pipe := s.Pipe.(*yamlPipe)
	fromSpecs := libplugin.ExtractSpecs(pipe.From)
	return libplugin.AggregateFieldsFromSpecs(
		fromSpecs,
		[]string{"authorized_keys", "authorized_keys_data", "ssh-key"},
		[]string{"AuthorizedKeys"},
		[]string{"AuthorizedKeysData"},
		conn,
		filepath.Dir(s.Plugin.(*piperConfig).filename),
	)
}

// TrustedUserCAKeys loads CA keys from all 'from' specs using generic aggregation.
func (s *yamlSkelPipeWrapper) TrustedUserCAKeys(conn libplugin.PluginConnMetadata) ([]byte, error) {
	pipe := s.Pipe.(*yamlPipe)
	fromSpecs := libplugin.ExtractSpecs(pipe.From)
	return libplugin.AggregateFieldsFromSpecs(
		fromSpecs,
		[]string{"trusted_user_ca_keys", "trusted_user_ca_keys_data", "ca-key"},
		[]string{"TrustedUserCAKeys"},
		[]string{"TrustedUserCAKeysData"},
		conn,
		filepath.Dir(s.Plugin.(*piperConfig).filename),
	)
}

func (s *skelpipeToPrivateKeyWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	p, err := s.config.loadFileOrDecode(s.to.PrivateKey, s.to.PrivateKeyData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   s.username,
	})
	if err != nil {
		return nil, nil, err
	}
	if len(val) > 0 {
		return val, nil, nil
	}
	return nil, nil, nil
}

// OverridePassword loads an override password for upstream authentication if present or from Vault.
func (s *yamlSkelPipeWrapper) OverridePassword(conn libplugin.PluginConnMetadata) ([]byte, error) {
	pipe := s.Pipe.(*yamlPipe)
	to := &pipe.To
	val, err := libplugin.GetPasswordFieldFromSpecs(
		[]interface{}{to},
		[]string{"Password"},
	)
	if err != nil {
		return nil, err
	}
	if val != "" {
		return []byte(val), nil
	}
	return nil, nil
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
