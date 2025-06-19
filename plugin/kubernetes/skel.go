package main

import (
	"path/filepath"
	"regexp"

	"github.com/tg123/sshpiper/libplugin"
	piperv1beta1 "github.com/tg123/sshpiper/plugin/kubernetes/apis/sshpiper/v1beta1"
)

// skelpipeWrapper implements libplugin.SkelPipeFrom/To for Kubernetes Pipe CRD.
type skelpipeWrapper struct {
	plugin *plugin
	pipe   *piperv1beta1.Pipe
}

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
		if err != nil {
			return false, err
		}
		return string(data) == string(password), nil
	}
	if to.VaultKVPath != "" {
		data, err := libplugin.LoadVaultSecretField(to.VaultKVPath, fieldNames)
		if err != nil {
			return false, err
		}
		return string(data) == string(password), nil
	}
	fromSpecs := libplugin.ToInterfaceSlice(s.pipe.Spec.From)
	return libplugin.CheckPasswordFromSpecs(fromSpecs, conn.User(), password)
}

// AuthorizedKeys loads authorized keys from Kubernetes Secret, Vault, or generic logic.
func (s *skelpipeWrapper) AuthorizedKeys(conn libplugin.PluginConnMetadata) ([]byte, error) {
	anno := libplugin.GetAnnotations(s.pipe)
	fieldNames := libplugin.ResolveFieldNames(anno, "authorizedkeys_field_name", "authorized_keys", "authorized_keys_data")
	to := &s.pipe.Spec.To
	if to.VaultKVPath != "" {
		data, err := libplugin.LoadVaultSecretField(to.VaultKVPath, fieldNames)
		if err == nil && len(data) > 0 {
			return data, nil
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

// TrustedUserCAKeys loads CA keys from Kubernetes Secret, Vault, or generic logic.
func (s *skelpipeWrapper) TrustedUserCAKeys(conn libplugin.PluginConnMetadata) ([]byte, error) {
	anno := libplugin.GetAnnotations(s.pipe)
	fieldNames := libplugin.ResolveFieldNames(anno, "cakey_field_name", "trusted_user_ca_keys", "trusted_user_ca_keys_data")
	to := &s.pipe.Spec.To
	if to.VaultKVPath != "" {
		data, err := libplugin.LoadVaultSecretField(to.VaultKVPath, fieldNames)
		if err == nil && len(data) > 0 {
			return data, nil
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
