package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
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
	log.WithFields(log.Fields{
		"operation": "match_conn",
		"user":      conn.User(),
		"remote":    conn.RemoteAddr(),
	}).Debug("Matching connection to Kubernetes pipe")

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
				return nil, fmt.Errorf("failed to compile username regex: %w", err)
			}
			if re.MatchString(user) {
				matched = true
				break
			}
		}
	}

	if matched {
		log.WithFields(log.Fields{
			"user":        user,
			"target_user": targetuser,
		}).Info("Successfully matched connection")

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

	log.WithFields(log.Fields{
		"user": user,
	}).Debug("No matching pipe found for user")

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
	log.WithFields(log.Fields{
		"operation": "test_password",
		"user":      conn.User(),
	}).Debug("Testing password authentication")

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

	success, err := libplugin.StandardTestPassword(htpasswdData, htpasswdFile, conn.User(), password)
	if err != nil {
		return false, fmt.Errorf("password authentication failed: %w", err)
	}

	if success {
		log.WithFields(log.Fields{
			"user": conn.User(),
		}).Info("Password authentication successful")
	}

	return success, nil
}

// AuthorizedKeys loads authorized keys using libplugin.StandardAuthorizedKeys with Kubernetes secrets support.
func (s *skelpipeWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	log.WithFields(log.Fields{
		"operation": "authorized_keys",
		"user":      conn.User(),
	}).Debug("Loading authorized keys")

	var keysSources [][]byte
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}

	// Process each from spec
	for _, from := range s.pipe.Spec.From {
		// Use standard helper for file/data sources
		keys, err := libplugin.StandardAuthorizedKeys(from.AuthorizedKeysData, from.AuthorizedKeysFile, envVars, "/")
		if err != nil {
			return nil, fmt.Errorf("failed to load standard authorized keys: %w", err)
		}
		if keys != nil {
			keysSources = append(keysSources, keys)
		}

		// Add Kubernetes secret if specified
		if from.AuthorizedKeysSecret.Name != "" {
			log.WithFields(log.Fields{
				"secret_name": from.AuthorizedKeysSecret.Name,
				"namespace":   s.pipe.Namespace,
			}).Debug("Loading authorized keys from Kubernetes secret")

			anno := s.pipe.GetAnnotations()

			secret, err := s.plugin.k8sclient.CoreV1().Secrets(s.pipe.Namespace).Get(context.Background(), from.AuthorizedKeysSecret.Name, metav1.GetOptions{})
			if err != nil {
				return nil, fmt.Errorf("failed to get authorized keys secret %s: %w", from.AuthorizedKeysSecret.Name, err)
			}

			for _, k := range []string{anno["sshpiper.com/authorizedkeys_field_name"], anno["authorizedkeys_field_name"], "authorized_keys", "authorizedkeys", "ssh-authorizedkeys"} {
				data := secret.Data[k]
				if data != nil {
					log.WithFields(log.Fields{
						"secret_name": from.AuthorizedKeysSecret.Name,
						"field_name":  k,
					}).Debug("Found authorized keys in secret")
					keysSources = append(keysSources, data)
					break
				}
			}
		}
	}

	if len(keysSources) == 0 {
		log.Debug("No authorized keys found")
		return nil, nil
	}

	result := bytes.Join(keysSources, []byte("\n"))
	log.WithFields(log.Fields{
		"keys_count": len(keysSources),
		"total_size": len(result),
	}).Info("Successfully loaded authorized keys")

	return result, nil
}

// TrustedUserCAKeys loads trusted CA keys using libplugin.StandardTrustedUserCAKeys with Kubernetes secrets support.
func (s *skelpipeWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	log.WithFields(log.Fields{
		"operation": "trusted_user_ca_keys",
		"user":      conn.User(),
	}).Debug("Loading trusted user CA keys")

	var keysSources [][]byte
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}

	// Process each from spec
	for _, from := range s.pipe.Spec.From {
		// Use standard helper for file/data sources
		caKeys, err := libplugin.StandardTrustedUserCAKeys(from.TrustedUserCAKeysData, from.TrustedUserCAKeysFile, envVars, "/")
		if err != nil {
			return nil, fmt.Errorf("failed to load standard trusted user CA keys: %w", err)
		}
		if caKeys != nil {
			keysSources = append(keysSources, caKeys)
		}

		// Add Kubernetes secret if specified
		if from.TrustedUserCAKeysSecret.Name != "" {
			log.WithFields(log.Fields{
				"secret_name": from.TrustedUserCAKeysSecret.Name,
				"namespace":   s.pipe.Namespace,
			}).Debug("Loading trusted user CA keys from Kubernetes secret")

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
						log.WithFields(log.Fields{
							"secret_name": from.TrustedUserCAKeysSecret.Name,
							"field_name":  k,
						}).Debug("Found trusted user CA keys in secret")
						keysSources = append(keysSources, data)
						break
					}
				}
			}
		}
	}

	if len(keysSources) == 0 {
		log.Debug("No trusted user CA keys found")
		return nil, nil
	}

	result := bytes.Join(keysSources, []byte("\n"))
	log.WithFields(log.Fields{
		"keys_count": len(keysSources),
		"total_size": len(result),
	}).Info("Successfully loaded trusted user CA keys")

	return result, nil
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
