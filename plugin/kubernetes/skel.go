package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/skel"
	piperv1beta1 "github.com/tg123/sshpiper/plugin/kubernetes/apis/sshpiper/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// skelpipeWrapper implements libplugin.SkelPipeFrom/To for Kubernetes Pipe CRD.
type skelpipeWrapper struct {
	libplugin.SkelPipeWrapper
	plugin *plugin
	pipe   *piperv1beta1.Pipe
}

type skelpipeFromWrapper struct {
	skelpipeWrapper
}

func (s *skelpipeFromWrapper) MatchConn(conn libplugin.ConnMetadata) (skel.SkelPipeTo, error) {
	user := conn.User()
	matched := false
	targetuser := s.pipe.Spec.To.Username

	if targetuser == "" {
		targetuser = user
	}

	// Check each from spec for matching user
	for _, from := range s.pipe.Spec.From {
		if from.Username == user {
			matched = true
			break
		}
		if from.UsernameRegexMatch {
			re, err := regexp.Compile(from.Username)
			if err != nil {
				return nil, err
			}
			if re.MatchString(user) {
				matched = true
				break
			}
		}
	}

	if matched {
		wrapper := &skelpipeToWrapper{
			skelpipeWrapper: s.skelpipeWrapper,
			username:        targetuser,
		}

		if s.pipe.Spec.To.PrivateKeySecret.Name != "" {
			return &skelpipeToPrivateKeyWrapper{skelpipeToWrapper: *wrapper}, nil
		} else {
			return &skelpipeToPasswordWrapper{skelpipeToWrapper: *wrapper}, nil
		}
	}
	return nil, nil
}

type skelpipePasswordWrapper struct {
	skelpipeFromWrapper
}

type skelpipePublicKeyWrapper struct {
	skelpipeFromWrapper
}

type skelpipeToWrapper struct {
	skelpipeWrapper
	username string
}

func (s *skelpipeToWrapper) User(conn libplugin.ConnMetadata) string {
	return s.username
}

func (s *skelpipeToWrapper) Host(conn libplugin.ConnMetadata) string {
	return s.pipe.Spec.To.Host
}

func (s *skelpipeToWrapper) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	return s.pipe.Spec.To.IgnoreHostkey
}

func (s *skelpipeToWrapper) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.pipe.Spec.To.KnownHostsData)
}

type skelpipeToPasswordWrapper struct {
	skelpipeToWrapper
}

type skelpipeToPrivateKeyWrapper struct {
	skelpipeToWrapper
}

// TestPassword delegates to libplugin.StandardTestPassword for password authentication.
func (s *skelpipeWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	// Aggregate htpasswd data from all from specs
	var htpasswdData, htpasswdFile string
	for _, from := range s.pipe.Spec.From {
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

// AuthorizedKeys loads authorized keys using libplugin.StandardAuthorizedKeys with Kubernetes secrets support.
func (s *skelpipeWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	var keysSources [][]byte
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}

	// Process each from spec
	for _, from := range s.pipe.Spec.From {
		// Use standard helper for file/data sources
		keys, err := libplugin.StandardAuthorizedKeys(from.AuthorizedKeysData, from.AuthorizedKeysFile, envVars, "/")
		if err != nil {
			return nil, err
		}
		if keys != nil {
			keysSources = append(keysSources, keys)
		}

		// Add Kubernetes secret if specified
		if from.AuthorizedKeysSecret.Name != "" {
			log.Debugf("loading authorized keys from secret %v", from.AuthorizedKeysSecret.Name)
			anno := s.pipe.GetAnnotations()

			secret, err := s.plugin.k8sclient.CoreV1().Secrets(s.pipe.Namespace).Get(context.Background(), from.AuthorizedKeysSecret.Name, metav1.GetOptions{})
			if err != nil {
				return nil, err
			}

			for _, k := range []string{anno["sshpiper.com/authorizedkeys_field_name"], anno["authorizedkeys_field_name"], "authorized_keys", "authorizedkeys", "ssh-authorizedkeys"} {
				data := secret.Data[k]
				if data != nil {
					log.Debugf("found authorized keys in secret %v/%v", from.AuthorizedKeysSecret.Name, k)
					keysSources = append(keysSources, data)
					break
				}
			}
		}
	}

	if len(keysSources) == 0 {
		return nil, nil
	}

	return bytes.Join(keysSources, []byte("\n")), nil
}

// TrustedUserCAKeys loads trusted CA keys using libplugin.StandardTrustedUserCAKeys with Kubernetes secrets support.
func (s *skelpipeWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	var keysSources [][]byte
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}

	// Process each from spec
	for _, from := range s.pipe.Spec.From {
		// Use standard helper for file/data sources
		caKeys, err := libplugin.StandardTrustedUserCAKeys(from.TrustedUserCAKeysData, from.TrustedUserCAKeysFile, envVars, "/")
		if err != nil {
			return nil, err
		}
		if caKeys != nil {
			keysSources = append(keysSources, caKeys)
		}

		// Add Kubernetes secret if specified
		if from.TrustedUserCAKeysSecret.Name != "" {
			log.Debugf("loading trusted user CA keys from secret %v", from.TrustedUserCAKeysSecret.Name)
			anno := s.pipe.GetAnnotations()

			secret, err := s.plugin.k8sclient.CoreV1().Secrets(s.pipe.Namespace).Get(context.Background(), from.TrustedUserCAKeysSecret.Name, metav1.GetOptions{})
			if err != nil {
				return nil, fmt.Errorf("failed to get trusted user CA keys secret %s: %w", from.TrustedUserCAKeysSecret.Name, err)
			}

			// Try different field names in order of preference
			for _, k := range []string{
				anno["sshpiper.com/trusted_user_ca_keys_field_name"],
				anno["trusted_user_ca_keys_field_name"],
				"trusted_user_ca_keys",
				"trusted-user-ca-keys",
				"ca_keys",
				"ca-keys",
			} {
				if k != "" {
					data := secret.Data[k]
					if data != nil {
						log.Debugf("found trusted user CA keys in secret %v/%v", from.TrustedUserCAKeysSecret.Name, k)
						keysSources = append(keysSources, data)
						break
					}
				}
			}
		}
	}

	if len(keysSources) == 0 {
		return nil, nil
	}

	return bytes.Join(keysSources, []byte("\n")), nil
}

func (s *skelpipeWrapper) From() []skel.SkelPipeFrom {
	w := skelpipeFromWrapper{
		skelpipeWrapper: *s,
	}

	if len(s.pipe.Spec.From) > 0 {
		// Check if any from spec has authorized keys
		hasKeys := false
		for _, f := range s.pipe.Spec.From {
			if f.AuthorizedKeysData != "" || f.AuthorizedKeysFile != "" || f.AuthorizedKeysSecret.Name != "" {
				hasKeys = true
				break
			}
		}

		if hasKeys {
			return []skel.SkelPipeFrom{&skelpipePublicKeyWrapper{
				skelpipeFromWrapper: w,
			}}
		} else {
			return []skel.SkelPipeFrom{&skelpipePasswordWrapper{
				skelpipeFromWrapper: w,
			}}
		}
	}
	return nil
}

func loadStringAndFile(base64orraw string, filepath string) ([][]byte, error) {
	all := make([][]byte, 0, 2)

	if base64orraw != "" {
		data, err := base64.StdEncoding.DecodeString(base64orraw)
		if err != nil {
			data = []byte(base64orraw)
		}
		all = append(all, data)
	}

	if filepath != "" {
		data, err := os.ReadFile(filepath)
		if err != nil {
			return nil, err
		}
		all = append(all, data)
	}

	return all, nil
}

func (p *plugin) listPipe(_ libplugin.ConnMetadata) ([]skel.SkelPipe, error) {
	kpipes, err := p.list()
	if err != nil {
		return nil, err
	}

	var pipes []skel.SkelPipe
	for _, pipe := range kpipes {
		pipePtr, ok := pipe.(*piperv1beta1.Pipe)
		if !ok {
			continue // Skip invalid pipe types
		}
		wrapper := &skelpipeWrapper{
			SkelPipeWrapper: libplugin.SkelPipeWrapper{
				Plugin: p,
				Pipe:   pipePtr,
			},
			plugin: p,
			pipe:   pipePtr,
		}
		pipes = append(pipes, wrapper)
	}
	return pipes, nil
}
