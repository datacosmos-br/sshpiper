// Package main implements the YAML plugin for sshpiperd.
package main

import (
	"bytes"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"

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

func (s *skelpipeToPasswordWrapper) User(conn libplugin.ConnMetadata) string {
	return s.username
}

type skelpipeToPrivateKeyWrapper struct {
	skelpipeToWrapper
}

func (s *skelpipeToPrivateKeyWrapper) User(conn libplugin.ConnMetadata) string {
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

type skelpipePasswordWrapper struct {
	skelpipeFromWrapper
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

// ValidateCertificate validates an SSH certificate for a downstream connection using the configured trusted CA keys.
// It loads all trusted CA keys from the YAML pipe's 'from' specs and delegates to libplugin.MatchAndValidateCACert.
func (s *yamlSkelPipeWrapper) ValidateCertificate(conn libplugin.ConnMetadata, pubKey ssh.PublicKey) error {
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

// TestPassword checks the password using libplugin.StandardTestPassword.
func (s *yamlSkelPipeWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	pipe := s.Pipe.(*yamlPipe)
	// Aggregate htpasswd data from all from specs
	var htpasswdData, htpasswdFile string
	for _, from := range pipe.From {
		if from.HtpasswdData != "" {
			htpasswdData = from.HtpasswdData
			break
		}
		if from.HtpasswdFile != "" {
			htpasswdFile = from.HtpasswdFile
			break
		}
	}
	return libplugin.StandardTestPassword(htpasswdData, htpasswdFile, conn.User(), password)
}

// AuthorizedKeys loads authorized keys from all 'from' specs using libplugin.StandardAuthorizedKeys.
func (s *yamlSkelPipeWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	pipe := s.Pipe.(*yamlPipe)
	var keysSources [][]byte
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	baseDir := filepath.Dir(s.Plugin.(*piperConfig).filename)

	// Process each from spec using standard helper
	for _, from := range pipe.From {
		// Extract authorized keys data and file from ListOrString
		var keysData, keysFile string
		if from.AuthorizedKeysData.Any() {
			// Get first available data source
			if from.AuthorizedKeysData.Str != "" {
				keysData = from.AuthorizedKeysData.Str
			} else if len(from.AuthorizedKeysData.List) > 0 {
				keysData = from.AuthorizedKeysData.List[0]
			}
		}
		if from.AuthorizedKeys.Any() {
			// Get first available file source
			if from.AuthorizedKeys.Str != "" {
				keysFile = from.AuthorizedKeys.Str
			} else if len(from.AuthorizedKeys.List) > 0 {
				keysFile = from.AuthorizedKeys.List[0]
			}
		}

		// Use standard helper for this from spec
		keys, err := libplugin.StandardAuthorizedKeys(keysData, keysFile, envVars, baseDir)
		if err != nil {
			return nil, err
		}
		if keys != nil {
			keysSources = append(keysSources, keys)
		}
	}

	if len(keysSources) == 0 {
		return nil, nil
	}

	return bytes.Join(keysSources, []byte("\n")), nil
}

// TrustedUserCAKeys loads CA keys from all 'from' specs using libplugin.StandardTrustedUserCAKeys.
func (s *yamlSkelPipeWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	pipe := s.Pipe.(*yamlPipe)
	var keysSources [][]byte
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	baseDir := filepath.Dir(s.Plugin.(*piperConfig).filename)

	// Process each from spec using standard helper
	for _, from := range pipe.From {
		// Extract trusted CA keys data and file from ListOrString
		var caKeysData, caKeysFile string
		if from.TrustedUserCAKeysData.Any() {
			// Get first available data source
			if from.TrustedUserCAKeysData.Str != "" {
				caKeysData = from.TrustedUserCAKeysData.Str
			} else if len(from.TrustedUserCAKeysData.List) > 0 {
				caKeysData = from.TrustedUserCAKeysData.List[0]
			}
		}
		if from.TrustedUserCAKeys.Any() {
			// Get first available file source
			if from.TrustedUserCAKeys.Str != "" {
				caKeysFile = from.TrustedUserCAKeys.Str
			} else if len(from.TrustedUserCAKeys.List) > 0 {
				caKeysFile = from.TrustedUserCAKeys.List[0]
			}
		}

		// Use standard helper for this from spec
		caKeys, err := libplugin.StandardTrustedUserCAKeys(caKeysData, caKeysFile, envVars, baseDir)
		if err != nil {
			return nil, err
		}
		if caKeys != nil {
			keysSources = append(keysSources, caKeys)
		}
	}

	if len(keysSources) == 0 {
		return nil, nil
	}

	return bytes.Join(keysSources, []byte("\n")), nil
}

func (s *skelpipeToPrivateKeyWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	// Use standard helper for private key loading
	envVars := map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   s.username,
	}
	return libplugin.StandardPrivateKey(s.to.PrivateKeyData, s.to.PrivateKey, envVars, filepath.Dir(s.config.filename))
}

// OverridePassword loads an override password using libplugin.StandardOverridePassword.
func (s *yamlSkelPipeWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	pipe := s.Pipe.(*yamlPipe)
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	return libplugin.StandardOverridePassword(pipe.To.Password, "", envVars, filepath.Dir(s.Plugin.(*piperConfig).filename))
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
