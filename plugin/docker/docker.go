package main

import (
	"context"
	"fmt"
	"net"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
)

// dockerPipe defines the configuration for a Docker plugin pipe.
// All key, certificate, and password fields must use *File, *Data, or VaultKVPath for generic loading.
type dockerPipe struct {
	// ClientUsername is the downstream username to match.
	ClientUsername string
	// ContainerUsername is the username to use for the container's SSHD.
	ContainerUsername string
	// Host is the container's IP address (with optional port).
	Host string
	// HtpasswdData is the base64-encoded htpasswd data for password auth.
	HtpasswdData string
	// HtpasswdFile is the file path to htpasswd data for password auth.
	HtpasswdFile string
	// AuthorizedKeysData is the base64-encoded authorized_keys data for public key auth.
	AuthorizedKeysData string
	// AuthorizedKeysFile is the file path to authorized_keys data for public key auth.
	AuthorizedKeysFile string
	// TrustedUserCAKeysData is the base64-encoded CA keys for cert auth.
	TrustedUserCAKeysData string
	// TrustedUserCAKeysFile is the file path to CA keys for cert auth.
	TrustedUserCAKeysFile string
	// KnownHostsData is the base64-encoded known_hosts data for host key verification.
	KnownHostsData string
	// KnownHostsFile is the file path to known_hosts data for host key verification.
	KnownHostsFile string
	// PrivateKeyData is the base64-encoded private key for upstream auth.
	PrivateKeyData string
	// PrivateKeyFile is the file path to private key for upstream auth.
	PrivateKeyFile string
	// VaultKVPath is the Vault path for secret loading (password, private key, etc.).
	VaultKVPath string
}

type plugin struct {
	dockerCli *client.Client
}

func newDockerPlugin() (*plugin, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &plugin{
		dockerCli: cli,
	}, nil
}

// list queries Docker for containers and builds dockerPipe configs from labels.
func (p *plugin) list() ([]dockerPipe, error) {
	containers, err := p.dockerCli.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		return nil, err
	}

	var pipes []dockerPipe
	for _, c := range containers {
		pipe := dockerPipe{
			ClientUsername:        c.Labels["sshpiper.username"],
			ContainerUsername:     c.Labels["sshpiper.container_username"],
			HtpasswdData:          c.Labels["sshpiper.htpasswd_data"],
			HtpasswdFile:          c.Labels["sshpiper.htpasswd_file"],
			AuthorizedKeysData:    c.Labels["sshpiper.authorized_keys_data"],
			AuthorizedKeysFile:    c.Labels["sshpiper.authorized_keys_file"],
			TrustedUserCAKeysData: c.Labels["sshpiper.trusted_user_ca_keys_data"],
			TrustedUserCAKeysFile: c.Labels["sshpiper.trusted_user_ca_keys_file"],
			KnownHostsData:        c.Labels["sshpiper.known_hosts_data"],
			KnownHostsFile:        c.Labels["sshpiper.known_hosts_file"],
			PrivateKeyData:        c.Labels["sshpiper.private_key_data"],
			PrivateKeyFile:        c.Labels["sshpiper.private_key_file"],
			VaultKVPath:           c.Labels["sshpiper.vault_kv_path"],
		}

		if pipe.ClientUsername == "" && pipe.AuthorizedKeysData == "" && pipe.AuthorizedKeysFile == "" {
			log.Debugf("skipping container %v without sshpiper.username or authorized_keys", c.ID)
			continue
		}

		var hostcandidates []*network.EndpointSettings
		for _, network := range c.NetworkSettings.Networks {
			if network.IPAddress != "" {
				hostcandidates = append(hostcandidates, network)
			}
		}
		if len(hostcandidates) == 0 {
			return nil, fmt.Errorf("no ip address found for container %v", c.ID)
		}
		pipe.Host = hostcandidates[0].IPAddress
		if len(hostcandidates) > 1 {
			netname := c.Labels["sshpiper.network"]
			if netname == "" {
				return nil, fmt.Errorf("multiple networks found for container %v, please specify sshpiper.network", c.ID)
			}
			net, err := p.dockerCli.NetworkInspect(context.Background(), netname, network.InspectOptions{})
			if err != nil {
				log.Warnf("cannot list network %v for container %v: %v", netname, c.ID, err)
				continue
			}
			for _, hostcandidate := range hostcandidates {
				if hostcandidate.NetworkID == net.ID {
					pipe.Host = hostcandidate.IPAddress
					break
				}
			}
		}
		port := c.Labels["sshpiper.port"]
		if port != "" {
			pipe.Host = net.JoinHostPort(pipe.Host, port)
		}
		pipes = append(pipes, pipe)
	}
	return pipes, nil
}
