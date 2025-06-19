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
}

<<<<<<< HEAD
// From returns the list of SkelPipeFrom for this Docker pipe.
// It uses libplugin.FromGeneric to construct the list, providing Docker-specific matchConn logic.
func (s *dockerSkelPipeWrapper) From() []libplugin.SkelPipeFrom {
	pipe := s.Pipe.(*dockerPipe)
	fromSpecs := []interface{}{pipe}
	matchConnFn := func(from interface{}, conn libplugin.PluginConnMetadata) (libplugin.SkelPipeTo, error) {
		p := from.(*dockerPipe)
		user := conn.User()
		matched := libplugin.MatchUserOrEmpty(p.ClientUsername, user)
		targetuser := libplugin.ResolveTargetUser(p.ContainerUsername, user)
		if matched {
			knownHostsFn := libplugin.BuildKnownHostsFn(
				p.KnownHostsFile,
				p.KnownHostsData,
				map[string]string{"DOWNSTREAM_USER": conn.User(), "UPSTREAM_USER": targetuser},
				filepath.Dir("/"),
			)
			to := libplugin.NewSkelPipeToWrapper(s.Plugin, p, targetuser, p.Host, true, knownHostsFn)
			return &to, nil
=======
type skelpipeFromWrapper struct {
	skelpipeWrapper
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

type skelpipeToPasswordWrapper struct {
	skelpipeToWrapper
}

type skelpipeToPrivateKeyWrapper struct {
	skelpipeToWrapper
}

func (s *skelpipeWrapper) From() []skel.SkelPipeFrom {
	w := skelpipeFromWrapper{
		skelpipeWrapper: *s,
	}

	if s.pipe.PrivateKey != "" || s.pipe.AuthorizedKeys != "" {
		return []skel.SkelPipeFrom{&skelpipePublicKeyWrapper{
			skelpipeFromWrapper: w,
		}}
	} else {
		return []skel.SkelPipeFrom{&skelpipePasswordWrapper{
			skelpipeFromWrapper: w,
		}}
	}
}

func (s *skelpipeToWrapper) User(conn libplugin.ConnMetadata) string {
	return s.username
}

func (s *skelpipeToWrapper) Host(conn libplugin.ConnMetadata) string {
	return s.pipe.Host
}

func (s *skelpipeToWrapper) IgnoreHostKey(conn libplugin.ConnMetadata) bool {
	return true // TODO support this
}

func (s *skelpipeToWrapper) KnownHosts(conn libplugin.ConnMetadata) ([]byte, error) {
	return nil, nil // TODO support this
}

func (s *skelpipeFromWrapper) MatchConn(conn libplugin.ConnMetadata) (skel.SkelPipeTo, error) {
	user := conn.User()

	matched := s.pipe.ClientUsername == user || s.pipe.ClientUsername == ""
	targetuser := s.pipe.ContainerUsername

	if targetuser == "" {
		targetuser = user
	}

	if matched {

		if s.pipe.PrivateKey != "" {
			return &skelpipeToPrivateKeyWrapper{
				skelpipeToWrapper: skelpipeToWrapper{
					skelpipeWrapper: s.skelpipeWrapper,
					username:        targetuser,
				},
			}, nil
>>>>>>> upstream/master
		}
		return nil, nil
	}
	return libplugin.FromGeneric(s.Plugin, pipe, fromSpecs, matchConnFn, nil)
}

// TestPassword delegates to libplugin.CheckHtpasswdPasswordFields for password authentication.
func (s *dockerSkelPipeWrapper) TestPassword(conn libplugin.PluginConnMetadata, password []byte) (bool, error) {
	p := s.Pipe.(*dockerPipe)
	return libplugin.CheckHtpasswdPasswordFields(p.HtpasswdData, p.HtpasswdFile, conn.User(), password)
}

// AuthorizedKeys loads authorized keys using libplugin.LoadSecretFieldWithFallback.
func (s *dockerSkelPipeWrapper) AuthorizedKeys(conn libplugin.PluginConnMetadata) ([]byte, error) {
	p := s.Pipe.(*dockerPipe)
	return libplugin.LoadSecretFieldWithFallback(p.VaultKVPath, "authorized_keys", p.AuthorizedKeysFile, p.AuthorizedKeysData, map[string]string{"DOWNSTREAM_USER": conn.User()}, filepath.Dir("/"))
}

// TrustedUserCAKeys loads trusted CA keys using libplugin.LoadSecretFieldWithFallback.
func (s *dockerSkelPipeWrapper) TrustedUserCAKeys(conn libplugin.PluginConnMetadata) ([]byte, error) {
	p := s.Pipe.(*dockerPipe)
	return libplugin.LoadSecretFieldWithFallback(p.VaultKVPath, "trusted_user_ca_keys", p.TrustedUserCAKeysFile, p.TrustedUserCAKeysData, map[string]string{"DOWNSTREAM_USER": conn.User()}, filepath.Dir("/"))
}

// KnownHosts loads known hosts using libplugin.LoadSecretFieldWithFallback.
func (s *dockerSkelPipeWrapper) KnownHosts(conn libplugin.PluginConnMetadata) ([]byte, error) {
	p := s.Pipe.(*dockerPipe)
	return libplugin.LoadSecretFieldWithFallback(p.VaultKVPath, "known_hosts", p.KnownHostsFile, p.KnownHostsData, map[string]string{"DOWNSTREAM_USER": conn.User()}, filepath.Dir("/"))
}

// PrivateKey loads the private key for upstream authentication using file, data, or Vault.
// Supports dockerPipe.PrivateKeyFile, PrivateKeyData, and VaultKVPath.
func (s *dockerSkelPipeWrapper) PrivateKey(conn libplugin.PluginConnMetadata) ([]byte, []byte, error) {
	p := s.Pipe.(*dockerPipe)
	key, err := libplugin.LoadSecretFieldWithFallback(p.VaultKVPath, "private_key", p.PrivateKeyFile, p.PrivateKeyData, map[string]string{"DOWNSTREAM_USER": conn.User()}, filepath.Dir("/"))
	if err != nil {
		return nil, nil, err
	}
	return key, nil, nil
}

// OverridePassword loads an override password for upstream authentication using Vault if configured.
// Supports dockerPipe.VaultKVPath.
func (s *dockerSkelPipeWrapper) OverridePassword(conn libplugin.PluginConnMetadata) ([]byte, error) {
	p := s.Pipe.(*dockerPipe)
	return libplugin.LoadSecretFieldWithFallback(p.VaultKVPath, "password", "", "", map[string]string{"DOWNSTREAM_USER": conn.User()}, filepath.Dir("/"))
}

<<<<<<< HEAD
// listPipe loads all Docker pipes and returns them as SkelPipe instances using libplugin.ListPipeGeneric.
func (p *plugin) listPipe(_ libplugin.PluginConnMetadata) ([]libplugin.SkelPipe, error) {
	return libplugin.ListPipeGeneric(
		func() ([]interface{}, error) {
			dpipes, err := p.list()
			if err != nil {
				return nil, err
			}
			out := make([]interface{}, len(dpipes))
			for i := range dpipes {
				out[i] = &dpipes[i]
			}
			return out, nil
		},
		func(pipe interface{}) libplugin.SkelPipe {
			return &dockerSkelPipeWrapper{libplugin.NewSkelPipeWrapper(p, pipe.(*dockerPipe))}
		},
	)
=======
func (p *plugin) listPipe(_ libplugin.ConnMetadata) ([]skel.SkelPipe, error) {
	dpipes, err := p.list()
	if err != nil {
		return nil, err
	}

	var pipes []skel.SkelPipe
	for _, pipe := range dpipes {
		wrapper := &skelpipeWrapper{
			plugin: p,
			pipe:   &pipe,
		}
		pipes = append(pipes, wrapper)

	}

	return pipes, nil
>>>>>>> upstream/master
}
