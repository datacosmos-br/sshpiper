// Package libplugin provides SSH key, certificate, and known_hosts utility helpers for plugins.
//
// This file contains:
//   - VerifyHostKeyFromKnownHosts: Verifies an SSH host key using known_hosts data
//   - MatchAndValidateCACert: Validates an SSH certificate against trusted CA data
//   - ParseAuthorizedKey: Parses an SSH authorized key from bytes
//
// These helpers are used by plugins to securely verify host keys, validate SSH certificates, and parse authorized keys.
//
// Example usage:
//
//	err := VerifyHostKeyFromKnownHosts(reader, hostname, netaddr, key)
//	err := MatchAndValidateCACert(conn, pubKey, trustedCAData)
//	key, err := ParseAuthorizedKey(data)
package libplugin

import (
	"bytes"
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// VerifyHostKeyFromKnownHosts verifies an SSH host key using known_hosts data.
func VerifyHostKeyFromKnownHosts(knownhostsData io.Reader, hostname, netaddr string, key []byte) error {
	hostKeyCallback, err := knownhosts.NewFromReader(knownhostsData)
	if err != nil {
		return err
	}

	pub, err := ssh.ParsePublicKey(key)
	if err != nil {
		return err
	}

	addr, err := net.ResolveTCPAddr("tcp", netaddr)
	if err != nil {
		return err
	}

	return hostKeyCallback(hostname, addr, pub)
}

// MatchAndValidateCACert validates an SSH certificate against trusted CA data.
// Returns an error if the certificate is not valid or not signed by a trusted CA.
func MatchAndValidateCACert(conn PluginConnMetadata, pubKey ssh.PublicKey, trustedCAData []byte) error {
	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return errors.New("not a certificate")
	}
	checker := ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool {
			data := trustedCAData
			for len(data) > 0 {
				auth, _, _, rest, err := ssh.ParseAuthorizedKey(data)
				if err != nil {
					break
				}
				if auth != nil && bytes.Equal(auth.Marshal(), k.Marshal()) {
					return true
				}
				data = rest
			}
			return false
		},
	}
	return checker.CheckCert(conn.User(), cert)
}

// ParseAuthorizedKey parses an SSH authorized key from bytes.
func ParseAuthorizedKey(data []byte) (ssh.PublicKey, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	return key, err
}

// KnownHostsLoader returns a closure for known_hosts loading from file, base64, or Vault.
// Accepts ListOrString for both file and data, and allows per-connection variable expansion.
func KnownHostsLoader(knownHostsFiles, knownHostsData ListOrString, vars map[string]string, baseDir string) func(conn PluginConnMetadata) ([]byte, error) {
	return func(conn PluginConnMetadata) ([]byte, error) {
		// Merge vars with connection metadata if needed
		return LoadFileOrBase64Many(
			knownHostsFiles,
			knownHostsData,
			vars,
			baseDir,
		)
	}
}
