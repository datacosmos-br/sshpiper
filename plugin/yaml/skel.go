package main

import (
	"fmt"
	"os/user"
	"regexp"
	"slices"

	"github.com/tg123/sshpiper/libplugin"
)

type skelpipeWrapper struct {
	pipe   *yamlPipe
	config *piperConfig
}
type skelpipeFromWrapper struct {
	config *piperConfig

	from *yamlPipeFrom
	to   *yamlPipeTo
}
type skelpipePasswordWrapper struct {
	skelpipeFromWrapper
}

type skelpipePublicKeyWrapper struct {
	skelpipeFromWrapper
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

func (s *skelpipeWrapper) From() []libplugin.SkelPipeFrom {
	var froms []libplugin.SkelPipeFrom
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
	return froms
}

func (s *skelpipeToWrapper) User(conn libplugin.ConnMetadata) string {
	return s.username
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

func (s *skelpipeFromWrapper) MatchConn(conn libplugin.ConnMetadata) (libplugin.SkelPipeTo, error) {
	user := conn.User()

	targetuser := s.to.Username

	var matched bool
	if s.from.Username != "" {
		matched = s.from.Username == user
		if s.from.UsernameRegexMatch {
			re, err := regexp.Compile(s.from.Username)
			if err != nil {
				return nil, err
			}

			matched = re.MatchString(user)

			if matched {
				targetuser = re.ReplaceAllString(user, s.to.Username)
			}
		}
	} else if s.from.Groupname != "" {
		userGroups, err := getUserGroups(user)
		if err != nil {
			return nil, err
		}
		fromPipeGroup := s.from.Groupname
		matched = slices.Contains(userGroups, fromPipeGroup)
	}

	if targetuser == "" {
		targetuser = user
	}

	if matched {

		if s.to.PrivateKey != "" || s.to.PrivateKeyData != "" {
			return &skelpipeToPrivateKeyWrapper{
				skelpipeToWrapper: skelpipeToWrapper{
					config:   s.config,
					username: targetuser,
					to:       s.to,
				},
			}, nil
		}

		return &skelpipeToPasswordWrapper{
			skelpipeToWrapper: skelpipeToWrapper{
				config:   s.config,
				username: targetuser,
				to:       s.to,
			},
		}, nil
	}

	return nil, nil
}

func (s *skelpipePasswordWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	return true, nil // yaml do not test input password
}

func (s *skelpipePublicKeyWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return s.config.loadFileOrDecodeMany(s.from.AuthorizedKeys, s.from.AuthorizedKeysData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
	})
}

func (s *skelpipePublicKeyWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	// If VaultCAPath is provided in the YAML config, retrieve the CA from Vault.
	if s.from.VaultCAPath != "" {
		secretData, err := libplugin.GetSecret(s.from.VaultCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve Vault secret from %s: %v", s.from.VaultCAPath, err)
		}
		// Expect the CA key under "ssh-ca"
		caStr, ok := secretData["ssh-ca"].(string)
		if !ok || caStr == "" {
			return nil, fmt.Errorf("CA key not found in Vault secret at %s", s.from.VaultCAPath)
		}
		return []byte(caStr), nil
	}

	// Otherwise, fallback to loading from file or inline data.
	return s.config.loadFileOrDecodeMany(s.from.TrustedUserCAKeys, s.from.TrustedUserCAKeysData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
	})
}

func (s *skelpipeToPrivateKeyWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	// If VaultPrivateKeyPath is provided in the YAML config, retrieve the key from Vault.
	if s.to.VaultPrivateKeyPath != "" {
		secretData, err := libplugin.GetSecret(s.to.VaultPrivateKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to retrieve Vault secret from %s: %v", s.to.VaultPrivateKeyPath, err)
		}
		keyStr, ok := secretData["ssh-privatekey"].(string)
		if !ok || keyStr == "" {
			return nil, nil, fmt.Errorf("private key not found in Vault secret at %s", s.to.VaultPrivateKeyPath)
		}
		var pubStr string
		if v, ok := secretData["ssh-publickey-cert"].(string); ok {
			pubStr = v
		}
		return []byte(keyStr), []byte(pubStr), nil
	}

	// Fallback to current method (loading from file or inline base64 data).
	p, err := s.config.loadFileOrDecode(s.to.PrivateKey, s.to.PrivateKeyData, map[string]string{
		"DOWNSTREAM_USER": conn.User(),
		"UPSTREAM_USER":   s.username,
	})

	if err != nil {
		return nil, nil, err
	}

	return p, nil, nil
}

func (s *skelpipeToPasswordWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	// If VaultPasswordPath is provided in the YAML config, retrieve the password from Vault.
	if s.to.VaultPasswordPath != "" {
		secretData, err := libplugin.GetSecret(s.to.VaultPasswordPath)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve Vault secret from %s: %v", s.to.VaultPasswordPath, err)
		}
		pwd, ok := secretData["password"].(string)
		if !ok || pwd == "" {
			return nil, fmt.Errorf("password not found in Vault secret at %s", s.to.VaultPasswordPath)
		}
		return []byte(pwd), nil
	}

	// Fallback: if no Vault path is provided, try to load from file/inline data via existing mechanism.
	return nil, nil
}

func (p *plugin) listPipe(_ libplugin.ConnMetadata) ([]libplugin.SkelPipe, error) {
	configs, err := p.loadConfig()
	if err != nil {
		return nil, err
	}

	var pipes []libplugin.SkelPipe
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

func getUserGroups(userName string) ([]string, error) {
	usr, err := user.Lookup(userName)
	if err != nil {
		return nil, err
	}

	groupIds, err := usr.GroupIds()
	if err != nil {
		return nil, err
	}

	var groups []string
	for _, groupId := range groupIds {
		grp, err := user.LookupGroupId(groupId)
		if err != nil {
			return nil, err
		}
		groups = append(groups, grp.Name)
	}

	return groups, nil
}
