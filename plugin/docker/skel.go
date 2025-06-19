// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements. See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership. The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

package main

import (
	"fmt"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/skel"
)

// DockerPipeWrapper wraps the standard plugin wrapper with Docker-specific functionality
type DockerPipeWrapper struct {
	*libplugin.StandardPluginWrapper
	workingDir string
}

// NewDockerPipeWrapper creates a new Docker plugin wrapper
func NewDockerPipeWrapper(workingDir string) *DockerPipeWrapper {
	wrapper := libplugin.NewStandardPluginWrapper("docker", "1.0.0", "Docker SSH plugin with standardized helpers")
	return &DockerPipeWrapper{
		StandardPluginWrapper: wrapper,
		workingDir:            workingDir,
	}
}

// TestPassword implements password authentication using standard helpers with Docker-specific paths
func (d *DockerPipeWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
	var upstream *libplugin.Upstream
	err := d.LogOperation("test_password", func() error {
		passwordFile := filepath.Join(d.workingDir, "password")
		passwordData := ""

		result, err := libplugin.StandardTestPassword(passwordData, passwordFile, conn.User(), password)
		if err != nil {
			return d.ErrorHandler.WrapError("password_test", err)
		}

		if !result {
			return fmt.Errorf("authentication failed for user %s", conn.User())
		}

		// Create upstream connection
		upstream = &libplugin.Upstream{
			Host:          d.Config.ConnectionData.Host,
			Port:          d.Config.ConnectionData.Port,
			UserName:      conn.User(),
			IgnoreHostKey: d.Config.ConnectionData.IgnoreHostKey,
			Auth: &libplugin.Upstream_Password{
				Password: &libplugin.UpstreamPasswordAuth{
					Password: string(password),
				},
			},
		}

		d.Metrics.IncrementCounter("password_auth_success")
		d.Logger.Info("password authentication successful", log.Fields{
			"user": conn.User(),
			"from": conn.RemoteAddr(),
		})

		return nil
	})

	return upstream, err
}

// AuthorizedKeys implements public key authentication using standard helpers with Docker-specific paths
func (d *DockerPipeWrapper) AuthorizedKeys(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
	var upstream *libplugin.Upstream
	err := d.LogOperation("authorized_keys", func() error {
		keysFile := filepath.Join(d.workingDir, "authorized_keys")
		keysData := ""
		envVars := map[string]string{
			"USER":        conn.User(),
			"REMOTE_ADDR": conn.RemoteAddr(),
		}

		result, err := libplugin.StandardAuthorizedKeys(keysData, keysFile, envVars, d.workingDir)
		if err != nil {
			return d.ErrorHandler.WrapError("authorized_keys", err)
		}

		if len(result) == 0 {
			return fmt.Errorf("no authorized keys found for user %s", conn.User())
		}

		// Create upstream connection
		upstream = &libplugin.Upstream{
			Host:          d.Config.ConnectionData.Host,
			Port:          d.Config.ConnectionData.Port,
			UserName:      conn.User(),
			IgnoreHostKey: d.Config.ConnectionData.IgnoreHostKey,
			Auth: &libplugin.Upstream_PrivateKey{
				PrivateKey: &libplugin.UpstreamPrivateKeyAuth{
					PrivateKey: result,
				},
			},
		}

		d.Metrics.IncrementCounter("publickey_auth_success")
		d.Logger.Info("public key authentication successful", log.Fields{
			"user": conn.User(),
			"from": conn.RemoteAddr(),
		})

		return nil
	})

	return upstream, err
}

// TrustedUserCAKeys implements CA key authentication using standard helpers with Docker-specific paths
func (d *DockerPipeWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
	var upstream *libplugin.Upstream
	err := d.LogOperation("trusted_user_ca_keys", func() error {
		caKeysFile := filepath.Join(d.workingDir, "ca_keys")
		caKeysData := ""
		envVars := map[string]string{
			"USER":        conn.User(),
			"REMOTE_ADDR": conn.RemoteAddr(),
		}

		result, err := libplugin.StandardTrustedUserCAKeys(caKeysData, caKeysFile, envVars, d.workingDir)
		if err != nil {
			return d.ErrorHandler.WrapError("trusted_user_ca_keys", err)
		}

		if len(result) == 0 {
			return fmt.Errorf("no trusted CA keys found for user %s", conn.User())
		}

		// Create upstream connection
		upstream = &libplugin.Upstream{
			Host:          d.Config.ConnectionData.Host,
			Port:          d.Config.ConnectionData.Port,
			UserName:      conn.User(),
			IgnoreHostKey: d.Config.ConnectionData.IgnoreHostKey,
			Auth: &libplugin.Upstream_PrivateKey{
				PrivateKey: &libplugin.UpstreamPrivateKeyAuth{
					CaPublicKey: result,
				},
			},
		}

		d.Metrics.IncrementCounter("ca_auth_success")
		d.Logger.Info("CA key authentication successful", log.Fields{
			"user": conn.User(),
			"from": conn.RemoteAddr(),
		})

		return nil
	})

	return upstream, err
}

// KnownHosts implements host key verification using standard helpers with Docker-specific paths
func (d *DockerPipeWrapper) KnownHosts(conn libplugin.ConnMetadata, hostname, netaddr string, key []byte) error {
	return d.LogOperation("known_hosts", func() error {
		knownHostsFile := filepath.Join(d.workingDir, "known_hosts")
		knownHostsData := ""
		envVars := map[string]string{
			"USER":     conn.User(),
			"HOSTNAME": hostname,
			"NETADDR":  netaddr,
		}

		result, err := libplugin.StandardKnownHosts(knownHostsData, knownHostsFile, envVars, d.workingDir)
		if err != nil {
			return d.ErrorHandler.WrapError("known_hosts", err)
		}

		if len(result) == 0 {
			d.Logger.Debug("no known hosts configured, allowing connection", log.Fields{
				"hostname": hostname,
				"netaddr":  netaddr,
			})
			return nil
		}

		d.Metrics.IncrementCounter("known_hosts_verified")
		d.Logger.Debug("known hosts verification successful", log.Fields{
			"hostname": hostname,
			"netaddr":  netaddr,
		})

		return nil
	})
}

// PrivateKey implements private key loading using standard helpers with Docker-specific paths
func (d *DockerPipeWrapper) PrivateKey(conn libplugin.ConnMetadata) (*libplugin.Upstream, error) {
	var upstream *libplugin.Upstream
	err := d.LogOperation("private_key", func() error {
		privateKeyFile := filepath.Join(d.workingDir, "id_rsa")
		privateKeyData := ""
		envVars := map[string]string{
			"USER":        conn.User(),
			"REMOTE_ADDR": conn.RemoteAddr(),
		}

		privateKey, caPublicKey, err := libplugin.StandardPrivateKey(privateKeyData, privateKeyFile, envVars, d.workingDir)
		if err != nil {
			return d.ErrorHandler.WrapError("private_key", err)
		}

		if len(privateKey) == 0 {
			return fmt.Errorf("no private key found for user %s", conn.User())
		}

		// Create upstream connection
		upstream = &libplugin.Upstream{
			Host:          d.Config.ConnectionData.Host,
			Port:          d.Config.ConnectionData.Port,
			UserName:      conn.User(),
			IgnoreHostKey: d.Config.ConnectionData.IgnoreHostKey,
			Auth: &libplugin.Upstream_PrivateKey{
				PrivateKey: &libplugin.UpstreamPrivateKeyAuth{
					PrivateKey:  privateKey,
					CaPublicKey: caPublicKey,
				},
			},
		}

		d.Metrics.IncrementCounter("private_key_loaded")
		d.Logger.Info("private key loaded successfully", log.Fields{
			"user": conn.User(),
			"from": conn.RemoteAddr(),
		})

		return nil
	})

	return upstream, err
}

// OverridePassword implements password override using standard helpers with Docker-specific paths
func (d *DockerPipeWrapper) OverridePassword(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
	var upstream *libplugin.Upstream
	err := d.LogOperation("override_password", func() error {
		overridePasswordFile := filepath.Join(d.workingDir, "override_password")
		overridePasswordData := ""
		envVars := map[string]string{
			"USER":        conn.User(),
			"REMOTE_ADDR": conn.RemoteAddr(),
		}

		result, err := libplugin.StandardOverridePassword(overridePasswordData, overridePasswordFile, envVars, d.workingDir)
		if err != nil {
			return d.ErrorHandler.WrapError("override_password", err)
		}

		if len(result) == 0 {
			// No override, use original password
			upstream = &libplugin.Upstream{
				Host:          d.Config.ConnectionData.Host,
				Port:          d.Config.ConnectionData.Port,
				UserName:      conn.User(),
				IgnoreHostKey: d.Config.ConnectionData.IgnoreHostKey,
				Auth: &libplugin.Upstream_Password{
					Password: &libplugin.UpstreamPasswordAuth{
						Password: string(password),
					},
				},
			}
		} else {
			// Use override password
			upstream = &libplugin.Upstream{
				Host:          d.Config.ConnectionData.Host,
				Port:          d.Config.ConnectionData.Port,
				UserName:      conn.User(),
				IgnoreHostKey: d.Config.ConnectionData.IgnoreHostKey,
				Auth: &libplugin.Upstream_Password{
					Password: &libplugin.UpstreamPasswordAuth{
						Password: string(result),
					},
				},
			}
		}

		d.Metrics.IncrementCounter("password_override_applied")
		d.Logger.Info("password override processed", log.Fields{
			"user":          conn.User(),
			"from":          conn.RemoteAddr(),
			"override_used": len(result) > 0,
		})

		return nil
	})

	return upstream, err
}

// IgnoreHostKey implements host key ignoring using standard helpers
func (d *DockerPipeWrapper) IgnoreHostKey(conn libplugin.ConnMetadata, hostname, netaddr string, key []byte) error {
	return d.LogOperation("ignore_host_key", func() error {
		knownHostsFile := filepath.Join(d.workingDir, "known_hosts")
		knownHostsData := ""

		ignoreResult := libplugin.StandardIgnoreHostKey(d.Config.ConnectionData.IgnoreHostKey, knownHostsData, knownHostsFile)
		if !ignoreResult {
			return fmt.Errorf("host key verification failed for %s", hostname)
		}

		d.Metrics.IncrementCounter("host_key_ignored")
		d.Logger.Debug("host key ignored", log.Fields{
			"hostname": hostname,
			"netaddr":  netaddr,
		})

		return nil
	})
}

// dockerSkelPipeWrapper wraps a dockerPipe for use with the SkelPipe interface.
// It delegates all generic SkelPipe logic to libplugin and provides Docker-specific connection matching.
type dockerSkelPipeWrapper struct {
	libplugin.SkelPipeWrapper
	plugin *plugin
	pipe   *dockerPipe
}

type dockerSkelPipeFromWrapper struct {
	dockerSkelPipeWrapper
}

func (s *dockerSkelPipeFromWrapper) MatchConn(conn libplugin.ConnMetadata) (skel.SkelPipeTo, error) {
	user := conn.User()
	matched := s.pipe.ClientUsername == user || s.pipe.ClientUsername == ""
	targetuser := s.pipe.ContainerUsername

	if targetuser == "" {
		targetuser = user
	}

	if matched {
		wrapper := &dockerSkelPipeToWrapper{
			dockerSkelPipeWrapper: s.dockerSkelPipeWrapper,
			username:              targetuser,
		}

		if s.pipe.PrivateKeyData != "" || s.pipe.PrivateKeyFile != "" {
			return &dockerSkelPipeToPrivateKeyWrapper{dockerSkelPipeToWrapper: *wrapper}, nil
		} else {
			return &dockerSkelPipeToPasswordWrapper{dockerSkelPipeToWrapper: *wrapper}, nil
		}
	}
	return nil, nil
}

type dockerSkelPipePasswordWrapper struct {
	dockerSkelPipeFromWrapper
}

type dockerSkelPipePublicKeyWrapper struct {
	dockerSkelPipeFromWrapper
}

type dockerSkelPipeToWrapper struct {
	dockerSkelPipeWrapper
	username string
}

func (s *dockerSkelPipeToWrapper) User(conn libplugin.ConnMetadata) string {
	return s.username
}

func (s *dockerSkelPipeToWrapper) Host(conn libplugin.ConnMetadata) string {
	return s.pipe.Host
}

func (s *dockerSkelPipeToWrapper) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	// Use standard helper for host key ignoring logic
	return libplugin.StandardIgnoreHostKey(false, s.pipe.KnownHostsData, s.pipe.KnownHostsFile)
}

func (s *dockerSkelPipeToWrapper) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	// Use standard helper for known hosts loading
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	return libplugin.StandardKnownHosts(s.pipe.KnownHostsData, s.pipe.KnownHostsFile, envVars, filepath.Dir("/"))
}

type dockerSkelPipeToPasswordWrapper struct {
	dockerSkelPipeToWrapper
}

type dockerSkelPipeToPrivateKeyWrapper struct {
	dockerSkelPipeToWrapper
}

func (s *dockerSkelPipeToPrivateKeyWrapper) PrivateKey(conn libplugin.ConnMetadata) ([]byte, []byte, error) {
	// Use standard helper for private key loading
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	return libplugin.StandardPrivateKey(s.pipe.PrivateKeyData, s.pipe.PrivateKeyFile, envVars, filepath.Dir("/"))
}

// TestPassword delegates to libplugin.StandardTestPassword for password authentication.
func (s *dockerSkelPipeWrapper) TestPassword(conn libplugin.ConnMetadata, password []byte) (bool, error) {
	p := s.Pipe.(*dockerPipe)
	return libplugin.StandardTestPassword(p.HtpasswdData, p.HtpasswdFile, conn.User(), password)
}

// AuthorizedKeys loads authorized keys using libplugin.StandardAuthorizedKeys.
func (s *dockerSkelPipeWrapper) AuthorizedKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	p := s.Pipe.(*dockerPipe)
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	return libplugin.StandardAuthorizedKeys(p.AuthorizedKeysData, p.AuthorizedKeysFile, envVars, filepath.Dir("/"))
}

// TrustedUserCAKeys loads trusted CA keys using libplugin.StandardTrustedUserCAKeys.
func (s *dockerSkelPipeWrapper) TrustedUserCAKeys(conn libplugin.ConnMetadata) ([]byte, error) {
	p := s.Pipe.(*dockerPipe)
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	return libplugin.StandardTrustedUserCAKeys(p.TrustedUserCAKeysData, p.TrustedUserCAKeysFile, envVars, filepath.Dir("/"))
}

// KnownHosts loads known hosts using libplugin.StandardKnownHosts.
func (s *dockerSkelPipeWrapper) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	p := s.Pipe.(*dockerPipe)
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	return libplugin.StandardKnownHosts(p.KnownHostsData, p.KnownHostsFile, envVars, filepath.Dir("/"))
}

// OverridePassword loads an override password using libplugin.StandardOverridePassword.
func (s *dockerSkelPipeWrapper) OverridePassword(conn libplugin.ConnMetadata) ([]byte, error) {
	envVars := map[string]string{"DOWNSTREAM_USER": conn.User()}
	return libplugin.StandardOverridePassword("", "", envVars, filepath.Dir("/"))
}

func (s *dockerSkelPipeWrapper) From() []skel.SkelPipeFrom {
	w := dockerSkelPipeFromWrapper{
		dockerSkelPipeWrapper: *s,
	}

	if s.pipe.PrivateKeyData != "" || s.pipe.PrivateKeyFile != "" || s.pipe.AuthorizedKeysData != "" || s.pipe.AuthorizedKeysFile != "" {
		return []skel.SkelPipeFrom{&dockerSkelPipePublicKeyWrapper{
			dockerSkelPipeFromWrapper: w,
		}}
	} else {
		return []skel.SkelPipeFrom{&dockerSkelPipePasswordWrapper{
			dockerSkelPipeFromWrapper: w,
		}}
	}
}

func (p *plugin) listPipe(_ libplugin.ConnMetadata) ([]skel.SkelPipe, error) {
	dpipes, err := p.list()
	if err != nil {
		return nil, err
	}

	var pipes []skel.SkelPipe
	for _, pipe := range dpipes {
		wrapper := &dockerSkelPipeWrapper{
			SkelPipeWrapper: libplugin.NewSkelPipeWrapper(p, &pipe),
			plugin:          p,
			pipe:            &pipe,
		}
		pipes = append(pipes, wrapper)
	}

	return pipes, nil
}
