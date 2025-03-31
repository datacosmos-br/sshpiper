package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"regexp"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/go-htpasswd"
	"github.com/tg123/sshpiper/libplugin"
	piperv1beta1 "github.com/tg123/sshpiper/plugin/kubernetes/apis/sshpiper/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type skelpipeWrapper struct {
	plugin *plugin

	pipe *piperv1beta1.Pipe
}

type skelpipeFromWrapper struct {
	plugin *plugin

	pipe *piperv1beta1.Pipe
	from *piperv1beta1.FromSpec
	to   *piperv1beta1.ToSpec
}

type skelpipePasswordWrapper struct {
	skelpipeFromWrapper
}

type skelpipePublicKeyWrapper struct {
	skelpipeFromWrapper
}

type skelpipeToWrapper struct {
	plugin *plugin

	pipe     *piperv1beta1.Pipe
	username string
	to       *piperv1beta1.ToSpec
}

type skelpipeToPasswordWrapper struct {
	skelpipeToWrapper
}

type skelpipeToPrivateKeyWrapper struct {
	skelpipeToWrapper
}

func (s *skelpipeWrapper) From() []libplugin.SkelPipeFrom {
	var froms []libplugin.SkelPipeFrom
	for _, f := range s.pipe.Spec.From {

		w := &skelpipeFromWrapper{
			plugin: s.plugin,
			pipe:   s.pipe,
			from:   &f,
			to:     &s.pipe.Spec.To,
		}

		if len(f.AuthorizedKeysData) > 0 || len(f.AuthorizedKeysFile) > 0 {
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
	khSources, err := loadStringAndFile(
		s.to.KnownHostsData,
		s.to.KnownHostsFile,
	)
	if err != nil {
		return nil, err
	}
	return bytes.Join(khSources, []byte("\n")), nil
}

func (s *skelpipeFromWrapper) MatchConn(conn libplugin.ConnMetadata) (libplugin.SkelPipeTo, error) {
	user := conn.User()

	matched := s.from.Username == user
	targetuser := s.to.Username

	if targetuser == "" {
		targetuser = user
	}

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

	if matched {

		if s.to.PrivateKeySecret.Name != "" {
			return &skelpipeToPrivateKeyWrapper{
				skelpipeToWrapper: skelpipeToWrapper{
					plugin:   s.plugin,
					pipe:     s.pipe,
					username: targetuser,
					to:       s.to,
				},
			}, nil
		}

		return &skelpipeToPasswordWrapper{
			skelpipeToWrapper: skelpipeToWrapper{
				plugin:   s.plugin,
				pipe:     s.pipe,
				username: targetuser,
				to:       s.to,
			},
		}, nil
	}

	return nil, nil
}

func (s *skelpipePasswordWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {

	pwds, err := loadStringAndFile(s.from.HtpasswdData, s.from.HtpasswdFile)
	if err != nil {
		return false, err
	}

	pwdmatched := len(pwds) == 0

	for _, data := range pwds {
		log.Debugf("try to match password using htpasswd")
		auth, err := htpasswd.NewFromReader(bytes.NewReader(data), htpasswd.DefaultSystems, nil)
		if err != nil {
			return false, err
		}

		if auth.Match(conn.User(), string(password)) {
			pwdmatched = true
		}
	}

	return pwdmatched, nil
}

func (s *skelpipePublicKeyWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	byteSlices, err := loadStringAndFile(s.from.AuthorizedKeysData, s.from.AuthorizedKeysFile)
	if err != nil {
		return nil, err
	}

	return bytes.Join(byteSlices, []byte("\n")), nil
}

func (s *skelpipePublicKeyWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	caSources, err := loadStringAndFile(
		s.from.TrustedUserCAKeysData,
		s.from.TrustedUserCAKeysFile,
	)
	if err != nil {
		return nil, err
	}
	return bytes.Join(caSources, []byte("\n")), nil
}

func (s *skelpipeToPrivateKeyWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {

	log.Debugf("mapping to %v private key using secret %v", s.to.Host, s.to.PrivateKeySecret.Name)
	secret, err := s.plugin.k8sclient.Secrets(s.pipe.Namespace).Get(context.Background(), s.to.PrivateKeySecret.Name, metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}

	anno := s.pipe.GetAnnotations()
	var publicKey []byte
	var privateKey []byte

	for _, k := range []string{anno["privatekey_field_name"], "ssh-privatekey", "privatekey"} {
		data := secret.Data[k]
		if data != nil {
			log.Debugf("found private key in secret %v/%v", s.to.PrivateKeySecret.Name, k)
			privateKey = data
			break
		}
	}

	for _, k := range []string{anno["publickey_field_name"], "ssh-publickey-cert", "publickey-cert", "ssh-publickey", "publickey"} {
		data := secret.Data[k]
		if data != nil {
			log.Debugf("found publickey key cert in secret %v/%v", s.to.PrivateKeySecret.Name, k)
			publicKey = data
			break
		}
	}

	return privateKey, publicKey, nil
}

func (s *skelpipeToPasswordWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	if s.to.PasswordSecret.Name != "" {
		log.Debugf("mapping to %v password using secret %v", s.to.Host, s.to.PasswordSecret.Name)
		secret, err := s.plugin.k8sclient.Secrets(s.pipe.Namespace).Get(context.Background(), s.to.PasswordSecret.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}

		anno := s.pipe.GetAnnotations()
		for _, k := range []string{anno["password_field_name"], "password"} {
			data := secret.Data[k]
			if data != nil {
				log.Debugf("found password in secret %v/%v", s.to.PasswordSecret.Name, k)
				return data, nil
			}
		}

		log.Warnf("password field not found in secret %v", s.to.PasswordSecret.Name)
	}

	return nil, nil
}

func loadStringAndFile(base64orraw []string, filepath []string) ([][]byte, error) {
	var all [][]byte

	for _, dataStr := range base64orraw {
		// Attempt base64 decode; if that fails, treat it as raw data.
		if decoded, err := base64.StdEncoding.DecodeString(dataStr); err == nil {
			all = append(all, decoded)
		} else {
			all = append(all, []byte(dataStr))
		}
	}

	for _, path := range filepath {
		// Expand placeholders and environment variables.
		expanded := os.Expand(path, func(placeholderName string) string {
			return os.Getenv(placeholderName)
		})
		data, err := os.ReadFile(expanded)
		if err != nil {
			return nil, err
		}
		all = append(all, data)
	}

	return all, nil
}

func (p *plugin) listPipe(_ libplugin.ConnMetadata) ([]libplugin.SkelPipe, error) {
	kpipes, err := p.list()
	if err != nil {
		return nil, err
	}

	var pipes []libplugin.SkelPipe
	for _, pipe := range kpipes {
		wrapper := &skelpipeWrapper{
			plugin: p,
			pipe:   pipe,
		}
		pipes = append(pipes, wrapper)

	}

	return pipes, nil
}
