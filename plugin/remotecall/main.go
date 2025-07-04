package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

func createRemoteCaller(c *cli.Context) (*RemoteCall, error) {
	remoteCall, err := InitRemoteCall(
		c.String(userClusterMappingEndpoint),
		c.String(userClusterMappingEndpointToken),
		c.Bool(userClusterMappingEndpointIsSocket),
		c.String(userClusterMappingEndpointSocketEndpoint),
		c.Generic(remoteAuthEndpoints).(*StringMapFlag).Value,
		c.Generic(remoteAuthEndpointsSecret).(*StringMapFlag).Value,
		c.Generic(remoteEndpoints).(*StringMapFlag).Value,
		c.Path(mappingKeyPath),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating remote caller: %w", err)
	}

	return remoteCall, nil
}

func generateUpstreamUserName(response *UserKeyAuthResponse) string {
	return "user" + "." + response.Data.UUID
}

const (
	remoteAuthEndpoints       = "remote-auth-endpoint"
	remoteAuthEndpointsSecret = "remote-auth-endpoint-secret"

	remoteEndpoints = "remote-endpoints"

	userClusterMappingEndpoint               = "user-cluster-endpoint"
	userClusterMappingEndpointIsSocket       = "user-cluster-endpoint-is-socket"
	userClusterMappingEndpointSocketEndpoint = "user-cluster-endpoint-socket-endpoint"
	userClusterMappingEndpointToken          = "user-cluster-endpoint-token"

	mappingKeyPath = "mapping-key-path"
)

func main() {
	libplugin.RunPluginEntrypoint(&libplugin.PluginEntrypoint{
		Name:  "remote call",
		Usage: "sshpiperd remote plugin",
		Flags: []cli.Flag{
			&cli.GenericFlag{
				Name:     remoteAuthEndpoints,
				Usage:    "cluster-url map for remote endpoint for retrieving user's private key(given as prod1=url)",
				EnvVars:  []string{"SSHPIPERD_PRIVATE_KEY_ENDPOINTS"},
				Value:    &StringMapFlag{},
				Required: true,
			},
			&cli.GenericFlag{
				Name:     remoteAuthEndpointsSecret,
				Usage:    "cluster-secret map for cluster-url for auth(given as prod1=token)",
				EnvVars:  []string{"SSHPIPERD_PRIVATE_KEY_ENDPOINTS_SECRET"},
				Value:    &StringMapFlag{},
				Required: true,
			},
			&cli.GenericFlag{
				Name:     remoteEndpoints,
				Usage:    "path to remote endpoint for forwarding traffic(given as prod1=url)",
				EnvVars:  []string{"SSHPIPERD_IN_CLUSTER_ENDPOINTS"},
				Value:    &StringMapFlag{},
				Required: true,
			},
			&cli.StringFlag{
				Name:    userClusterMappingEndpoint,
				Usage:   "endpoint for getting user to cluster mapping",
				EnvVars: []string{"SSHPIPERD_USER_MAPPING_ENDPOINT"},
			},
			&cli.BoolFlag{
				Name:     userClusterMappingEndpointIsSocket,
				Usage:    "endpoint for getting user to cluster mapping is socket?",
				EnvVars:  []string{"SSHPIPERD_USER_MAPPING_ENDPOINT_IS_SOCKET"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    userClusterMappingEndpointSocketEndpoint,
				Usage:   "endpoint for getting user to cluster mapping via socket",
				EnvVars: []string{"SSHPIPERD_USER_MAPPING_SOCKET_ENDPOINT"},
			},
			&cli.StringFlag{
				Name:    userClusterMappingEndpointToken,
				Usage:   "auth token(added to header) for getting user to cluster mapping",
				EnvVars: []string{"SSHPIPERD_USER_MAPPING_ENDPOINT_TOKEN"},
			},
			&cli.PathFlag{
				Name:    mappingKeyPath,
				Usage:   "mapping key path for upstream (base64 encoded content)",
				EnvVars: []string{"SSHPIPERD_MAPPING_KEY_PATH"},
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.PluginConfig, error) {
			return createConfig(c)
		},
	})
}

func createConfig(c *cli.Context) (*libplugin.PluginConfig, error) {
	caller, err := createRemoteCaller(c)
	if err != nil {
		return nil, fmt.Errorf("error creating remote caller: %w", err)
	}

	return &libplugin.PluginConfig{
		PublicKeyCallbackNew: func(conn libplugin.ConnMetadata, key []byte, keytype string) (*libplugin.Upstream, error) {
			return getPublicKeyCallback(conn, key, keytype, caller)
		},
	}, nil
}

func getPublicKeyCallback(
	conn libplugin.ConnMetadata,
	key []byte,
	keytype string,
	caller *RemoteCall,
) (*libplugin.Upstream, error) {
	clusterName, err := caller.GetClusterName(conn.User())
	log.Debugf("username %s", conn.User())
	if err != nil {
		return nil, fmt.Errorf("error getting cluster name from user: %w", err)
	}

	clusterAuthnURL, err := caller.GetUpstreamAuthenticatorURL(clusterName)
	if err != nil {
		return nil, fmt.Errorf("error getting authenticator url from cluster name: %w", err)
	}
	log.Debugf("completed getting upstream auth url %s", clusterAuthnURL)

	authResponse, err := caller.AuthenticateKey(key, keytype, clusterAuthnURL, clusterName, conn.User())
	if err != nil {
		return nil, fmt.Errorf("error authenticating to clusterUrl %q: %w", clusterAuthnURL, err)
	}
	log.Debugf("completed  auth resp %v", authResponse)

	k := caller.MapKey()

	log.Debugf("mapped key %v", k)
	prikey, err := ssh.ParsePrivateKey(k)
	if err != nil {
		log.Fatalf("Failed to parse public key: %v", err)
		return nil, fmt.Errorf("error parsing public key: %w", err)
	}

	plainKey := ssh.MarshalAuthorizedKey(prikey.PublicKey())
	log.Debugf("mapped public key %v", string(plainKey))

	inClusterSvcUrl, err := caller.GetUpstreamSvcURL(clusterName)
	if err != nil {
		return nil, fmt.Errorf("error getting upstream url for cluster %q: %w", clusterName, err)
	}
	log.Debugf("completed  incluster resp %s", inClusterSvcUrl)

	host, port, err := libplugin.SplitHostPortForSSH(inClusterSvcUrl)
	if err != nil {
		return nil, fmt.Errorf("error getting host port for in cluster svc url %q: %w",
			inClusterSvcUrl, err)
	}

	v := libplugin.Upstream{
		Host:          host,
		Port:          int32(port),
		UserName:      generateUpstreamUserName(authResponse),
		Auth:          libplugin.AuthPrivateKeyCreate(k),
		IgnoreHostKey: true,
	}
	log.Debugf("final data: %v", &v)

	return &v, nil
}
