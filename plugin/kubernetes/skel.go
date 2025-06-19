package main

import (
	"path/filepath"
	"regexp"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/skel"
	piperv1beta1 "github.com/tg123/sshpiper/plugin/kubernetes/apis/sshpiper/v1beta1"
)

// skelpipeWrapper implements libplugin.SkelPipeFrom/To for Kubernetes Pipe CRD.
type skelpipeWrapper struct {
	plugin *plugin
	pipe   *piperv1beta1.Pipe
}

<<<<<<< HEAD
// From returns the list of SkelPipeFrom for this pipe.
func (s *skelpipeWrapper) From() []libplugin.SkelPipeFrom {
	fromSpecs := make([]interface{}, len(s.pipe.Spec.From))
	for i := range s.pipe.Spec.From {
		fromSpecs[i] = &s.pipe.Spec.From[i]
	}
	to := &s.pipe.Spec.To
	matchConnFn := func(from interface{}, conn libplugin.PluginConnMetadata) (libplugin.SkelPipeTo, error) {
		f := from.(*piperv1beta1.FromSpec)
		user := conn.User()
		targetuser := to.Username
		matched := f.Username == user
		if targetuser == "" {
			targetuser = user
		}
		if f.UsernameRegexMatch {
			re, err := regexp.Compile(f.Username)
			if err != nil {
				return nil, err
			}
			matched = re.MatchString(user)
			if matched {
				targetuser = re.ReplaceAllString(user, to.Username)
			}
=======
func (s *skelpipeWrapper) From() []skel.SkelPipeFrom {
	var froms []skel.SkelPipeFrom
	for _, f := range s.pipe.Spec.From {

		w := &skelpipeFromWrapper{
			plugin: s.plugin,
			pipe:   s.pipe,
			from:   &f,
			to:     &s.pipe.Spec.To,
		}

		if f.AuthorizedKeysData != "" || f.AuthorizedKeysFile != "" || f.AuthorizedKeysSecret.Name != "" {
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
	return base64.StdEncoding.DecodeString(s.to.KnownHostsData)
}

func (s *skelpipeFromWrapper) MatchConn(conn libplugin.ConnMetadata) (skel.SkelPipeTo, error) {
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
>>>>>>> upstream/master
		}
		if matched {
			knownHostsFn := func(conn libplugin.PluginConnMetadata) ([]byte, error) {
				return libplugin.KnownHostsLoader(
					libplugin.ListOrString{Str: to.KnownHostsData},
					libplugin.ListOrString{},
					map[string]string{"DOWNSTREAM_USER": conn.User(), "UPSTREAM_USER": targetuser},
					filepath.Dir("/"),
				)(conn)
			}
			toWrap := libplugin.NewSkelPipeToWrapper(s.plugin, to, targetuser, to.Host, to.IgnoreHostkey, knownHostsFn)
			return &toWrap, nil
		}
		return nil, nil
	}
	return libplugin.FromGeneric(s.plugin, to, fromSpecs, matchConnFn, nil)
}

<<<<<<< HEAD
// listPipe returns all SkelPipe instances for the plugin.
func (p *plugin) listPipe(_ libplugin.PluginConnMetadata) ([]libplugin.SkelPipe, error) {
	return libplugin.ListPipeGeneric(
		func() ([]interface{}, error) {
			pipes, err := p.list()
			if err != nil {
				return nil, err
			}
			out := make([]interface{}, len(pipes))
			copy(out, pipes)
			return out, nil
		},
		func(pipe interface{}) libplugin.SkelPipe {
			return &skelpipeWrapper{plugin: p, pipe: pipe.(*piperv1beta1.Pipe)}
		},
	)
}

// TestPassword checks the password using Kubernetes Secret, Vault, or generic logic.
func (s *skelpipeWrapper) TestPassword(conn libplugin.PluginConnMetadata, password []byte) (bool, error) {
	to := &s.pipe.Spec.To
	anno := libplugin.GetAnnotations(s.pipe)
	fieldNames := libplugin.ResolveFieldNames(anno, "password_field_name", "password")
	if to.PasswordSecret.Name != "" {
		data, err := libplugin.LoadKubernetesSecretField(s.pipe.Namespace, to.PasswordSecret.Name, fieldNames, s.plugin.k8sclient)
=======
func (s *skelpipePasswordWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	pwds, err := loadStringAndFile(s.from.HtpasswdData, s.from.HtpasswdFile)
	if err != nil {
		return false, err
	}

	pwdmatched := len(pwds) == 0

	for _, data := range pwds {
		log.Debugf("try to match password using htpasswd")
		auth, err := htpasswd.NewFromReader(bytes.NewReader(data), htpasswd.DefaultSystems, nil)
>>>>>>> upstream/master
		if err != nil {
			return false, err
		}
		return string(data) == string(password), nil
	}
<<<<<<< HEAD
	if to.VaultKVPath != "" {
		data, err := libplugin.LoadVaultSecretField(to.VaultKVPath, fieldNames)
=======

	return pwdmatched, nil // yaml do not test input password
}

func (s *skelpipePublicKeyWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	byteSlices, err := loadStringAndFile(s.from.AuthorizedKeysData, s.from.AuthorizedKeysFile)
	if err != nil {
		return nil, err
	}

	if s.from.AuthorizedKeysSecret.Name != "" {
		log.Debugf("mapping to %v authorized keys using secret %v", s.pipe.Spec.To.Host, s.from.AuthorizedKeysSecret.Name)
		anno := s.pipe.GetAnnotations()

		secret, err := s.plugin.k8sclient.Secrets(s.pipe.Namespace).Get(context.Background(), s.from.AuthorizedKeysSecret.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}

		for _, k := range []string{anno["sshpiper.com/authorizedkeys_field_name"], anno["authorizedkeys_field_name"], "authorized_keys", "authorizedkeys", "ssh-authorizedkeys"} {
			data := secret.Data[k]
			if data != nil {
				log.Debugf("found authorized keys in secret %v/%v", s.from.AuthorizedKeysSecret.Name, k)
				byteSlices = append(byteSlices, data)
				break
			}
		}

	}

	return bytes.Join(byteSlices, []byte("\n")), nil
}

func (s *skelpipePublicKeyWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	return nil, nil // TODO support trusted_user_ca_keys
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

	for _, k := range []string{anno["sshpiper.com/privatekey_field_name"], anno["privatekey_field_name"], "ssh-privatekey", "privatekey"} {
		data := secret.Data[k]
		if data != nil {
			log.Debugf("found private key in secret %v/%v", s.to.PrivateKeySecret.Name, k)
			privateKey = data
			break
		}
	}

	if anno["no_ca_publickey"] != "true" && anno["sshpiper.com/no_ca_publickey"] != "true" {
		for _, k := range []string{anno["sshpiper.com/publickey_field_name"], anno["publickey_field_name"], "ssh-publickey-cert", "publickey-cert", "ssh-publickey", "publickey"} {
			data := secret.Data[k]
			if data != nil {
				log.Debugf("found publickey key cert in secret %v/%v", s.to.PrivateKeySecret.Name, k)
				publicKey = data
				break
			}
		}
	}

	return privateKey, publicKey, nil
}

func (s *skelpipeToPasswordWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	if s.to.PasswordSecret.Name != "" {
		log.Debugf("mapping to %v password using secret %v", s.to.Host, s.to.PasswordSecret.Name)
		secret, err := s.plugin.k8sclient.Secrets(s.pipe.Namespace).Get(context.Background(), s.to.PasswordSecret.Name, metav1.GetOptions{})
>>>>>>> upstream/master
		if err != nil {
			return false, err
		}
		return string(data) == string(password), nil
	}
	fromSpecs := libplugin.ToInterfaceSlice(s.pipe.Spec.From)
	return libplugin.CheckPasswordFromSpecs(fromSpecs, conn.User(), password)
}

<<<<<<< HEAD
// AuthorizedKeys loads authorized keys from Kubernetes Secret, Vault, or generic logic.
func (s *skelpipeWrapper) AuthorizedKeys(conn libplugin.PluginConnMetadata) ([]byte, error) {
	anno := libplugin.GetAnnotations(s.pipe)
	fieldNames := libplugin.ResolveFieldNames(anno, "authorizedkeys_field_name", "authorized_keys", "authorized_keys_data")
	to := &s.pipe.Spec.To
	if to.VaultKVPath != "" {
		data, err := libplugin.LoadVaultSecretField(to.VaultKVPath, fieldNames)
		if err == nil && len(data) > 0 {
			return data, nil
=======
func loadStringAndFile(base64orraw string, filepath string) ([][]byte, error) {
	all := make([][]byte, 0, 2)

	if base64orraw != "" {
		data, err := base64.StdEncoding.DecodeString(base64orraw)
		if err != nil {
			data = []byte(base64orraw)
>>>>>>> upstream/master
		}
	}
	return libplugin.AggregateFieldsFromSpecs(
		libplugin.ToInterfaceSlice(s.pipe.Spec.From),
		[]string{"authorized_keys", "authorized_keys_data", "ssh-key"},
		[]string{"AuthorizedKeysFile"},
		[]string{"AuthorizedKeysData"},
		conn,
		"",
	)
}

<<<<<<< HEAD
// TrustedUserCAKeys loads CA keys from Kubernetes Secret, Vault, or generic logic.
func (s *skelpipeWrapper) TrustedUserCAKeys(conn libplugin.PluginConnMetadata) ([]byte, error) {
	anno := libplugin.GetAnnotations(s.pipe)
	fieldNames := libplugin.ResolveFieldNames(anno, "cakey_field_name", "trusted_user_ca_keys", "trusted_user_ca_keys_data")
	to := &s.pipe.Spec.To
	if to.VaultKVPath != "" {
		data, err := libplugin.LoadVaultSecretField(to.VaultKVPath, fieldNames)
		if err == nil && len(data) > 0 {
			return data, nil
=======
func (p *plugin) listPipe(_ libplugin.ConnMetadata) ([]skel.SkelPipe, error) {
	kpipes, err := p.list()
	if err != nil {
		return nil, err
	}

	var pipes []skel.SkelPipe
	for _, pipe := range kpipes {
		wrapper := &skelpipeWrapper{
			plugin: p,
			pipe:   pipe,
>>>>>>> upstream/master
		}
	}
	return libplugin.AggregateFieldsFromSpecs(
		libplugin.ToInterfaceSlice(s.pipe.Spec.From),
		[]string{"trusted_user_ca_keys", "trusted_user_ca_keys_data", "ca-key"},
		[]string{"TrustedUserCAKeysFile"},
		[]string{"TrustedUserCAKeysData"},
		conn,
		"",
	)
}

// KnownHosts loads known_hosts data using the generic loader.
func (s *skelpipeWrapper) KnownHosts(conn libplugin.PluginConnMetadata) ([]byte, error) {
	to := &s.pipe.Spec.To
	return libplugin.KnownHostsLoader(
		libplugin.ListOrString{Str: to.KnownHostsData},
		libplugin.ListOrString{},
		map[string]string{"DOWNSTREAM_USER": conn.User()},
		filepath.Dir("/"),
	)(conn)
}
