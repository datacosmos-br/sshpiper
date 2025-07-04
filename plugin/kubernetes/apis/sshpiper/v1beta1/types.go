package v1beta1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Pipe struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec PipeSpec `json:"spec"`
}

type PipeSpec struct {
	From []FromSpec `json:"from"`
	To   ToSpec     `json:"to"`
}

type FromSpec struct {
	Username                string                      `json:"username"`
	UsernameRegexMatch      bool                        `json:"username_regex_match,omitempty"`
	AuthorizedKeysData      string                      `json:"authorized_keys_data,omitempty"`
	AuthorizedKeysFile      string                      `json:"authorized_keys_file,omitempty"`
	AuthorizedKeysSecret    corev1.LocalObjectReference `json:"authorized_keys_secret,omitempty"`
	TrustedUserCAKeysData   string                      `json:"trusted_user_ca_keys_data,omitempty"`
	TrustedUserCAKeysFile   string                      `json:"trusted_user_ca_keys_file,omitempty"`
	TrustedUserCAKeysSecret corev1.LocalObjectReference `json:"trusted_user_ca_keys_secret,omitempty"`
	HtpasswdData            string                      `json:"htpasswd_data,omitempty"`
	HtpasswdFile            string                      `json:"htpasswd_file,omitempty"`
}

type ToSpec struct {
	Username         string                      `json:"username,omitempty"`
	Host             string                      `json:"host"`
	PrivateKeySecret corev1.LocalObjectReference `json:"private_key_secret,omitempty"`
	PasswordSecret   corev1.LocalObjectReference `json:"password_secret,omitempty"`
	KnownHostsData   string                      `json:"known_hosts_data,omitempty"`
	IgnoreHostkey    bool                        `json:"ignore_hostkey,omitempty"`
	VaultKVPath      string                      `json:"vault_kv_path,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type PipeList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []Pipe `json:"items"`
}
