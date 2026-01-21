package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/tg123/sshpiper/libplugin"
	"gopkg.in/yaml.v3"
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

// loadFileOrDecodeMany loads configuration from files or inline data with proper variable substitution
func (c *piperConfig) loadFileOrDecodeMany(files listOrString, data listOrString, variables map[string]string) ([]byte, error) {
	var result []byte

	// Process files - actually read from filesystem
	for _, file := range files.Combine() {
		if file == "" {
			continue
		}

		// Apply variable substitution to file path
		processedFile := c.expandVariables(file, variables)

		// Read actual file content
		content, err := os.ReadFile(processedFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", processedFile, err)
		}

		// Apply variable substitution to file content
		processedContent := c.expandVariables(string(content), variables)
		result = append(result, []byte(processedContent)...)
		if !strings.HasSuffix(processedContent, "\n") {
			result = append(result, '\n')
		}
	}

	// Process inline data with proper base64 handling
	for _, dataStr := range data.Combine() {
		if dataStr == "" {
			continue
		}

		// Try to decode as base64 first
		if decoded, err := base64.StdEncoding.DecodeString(dataStr); err == nil {
			// Apply variable substitution to decoded content
			processedData := c.expandVariables(string(decoded), variables)
			result = append(result, []byte(processedData)...)
		} else {
			// Treat as raw data and apply variable substitution
			processedData := c.expandVariables(dataStr, variables)
			result = append(result, []byte(processedData)...)
		}

		if !strings.HasSuffix(string(result), "\n") {
			result = append(result, '\n')
		}
	}

	return result, nil
}

// expandVariables performs variable substitution using the provided variable map
func (c *piperConfig) expandVariables(template string, variables map[string]string) string {
	result := template
	for key, value := range variables {
		// Replace ${VAR} and $VAR patterns
		result = strings.ReplaceAll(result, "${"+key+"}", value)
		result = strings.ReplaceAll(result, "$"+key, value)
	}
	return result
}
