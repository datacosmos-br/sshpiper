package main

import (
	"github.com/tg123/sshpiper/libplugin"
)

type yamlPipeFrom struct {
	Username              string                 `yaml:"username,omitempty"`
	Groupname             string                 `yaml:"groupname,omitempty"`
	UsernameRegexMatch    bool                   `yaml:"username_regex_match,omitempty"`
	AuthorizedKeys        libplugin.ListOrString `yaml:"authorized_keys,omitempty"`
	AuthorizedKeysData    libplugin.ListOrString `yaml:"authorized_keys_data,omitempty"`
	TrustedUserCAKeys     libplugin.ListOrString `yaml:"trusted_user_ca_keys,omitempty"`
	TrustedUserCAKeysData libplugin.ListOrString `yaml:"trusted_user_ca_keys_data,omitempty"`
	VaultKVPath           string                 `yaml:"vault_kv_path,omitempty"`
	HtpasswdData          string                 `yaml:"htpasswd_data,omitempty"`
	HtpasswdFile          string                 `yaml:"htpasswd_file,omitempty"`
}

func (f yamlPipeFrom) SupportPublicKey() bool {
	return f.AuthorizedKeys.Any() || f.AuthorizedKeysData.Any() || f.TrustedUserCAKeys.Any() || f.TrustedUserCAKeysData.Any()
}

type yamlPipeTo struct {
	Username       string       `yaml:"username,omitempty"`
	Host           string       `yaml:"host"`
	Password       string       `yaml:"password,omitempty"`
	PrivateKey     string       `yaml:"private_key,omitempty"`
	PrivateKeyData string       `yaml:"private_key_data,omitempty"`
	KnownHosts     listOrString `yaml:"known_hosts,omitempty"`
	KnownHostsData listOrString `yaml:"known_hosts_data,omitempty"`
	IgnoreHostkey  bool         `yaml:"ignore_hostkey,omitempty"`
}

type listOrString struct {
	List []string
	Str  string
}

func (l *listOrString) Any() bool {
	return len(l.List) > 0 || l.Str != ""
}

func (l *listOrString) Combine() []string {
	if l.Str != "" {
		return append(l.List, l.Str)
	}
	return l.List
}

func (l *listOrString) UnmarshalYAML(value *yaml.Node) error {
	// Try to unmarshal as a list
	var list []string
	if err := value.Decode(&list); err == nil {
		l.List = list
		return nil
	}
	// Try to unmarshal as a string
	var str string
	if err := value.Decode(&str); err == nil {
		l.Str = str
		return nil
	}
	return fmt.Errorf("failed to unmarshal OneOfType")
}

type yamlPipe struct {
	From []yamlPipeFrom `yaml:"from,flow"`
	To   yamlPipeTo     `yaml:"to,flow"`
}

type piperConfig struct {
	Version string     `yaml:"version"`
	Pipes   []yamlPipe `yaml:"pipes,flow"`

	filename string
}
