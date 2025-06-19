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
	"path/filepath"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/skel"
)

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
