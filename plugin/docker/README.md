# docker plugin for sshpiperd

This plugin queries dockerd for containers and creates pipes to them.

## Usage

```bash
sshpiperd docker
```

Start a container with sshpiper labels (example for password auth):

```bash
docker run -d \
  -e USER_NAME=user \
  -e USER_PASSWORD=pass \
  -e PASSWORD_ACCESS=true \
  -l sshpiper.username=pass \
  -l sshpiper.container_username=user \
  -l sshpiper.port=2222 \
  -l sshpiper.htpasswd_data=$(base64 -w0 /etc/htpasswd) \
  lscr.io/linuxserver/openssh-server
```

Connect to piper:

```bash
ssh -l pass piper
```

### Config docker connection

Docker connection is configured with environment variables below:

<https://pkg.go.dev/github.com/docker/docker/client#FromEnv>

* DOCKER_HOST: to set the url to the docker server, default "unix:///var/run/docker.sock"
* DOCKER_API_VERSION: to set the version of the API to reach, leave empty for latest.
* DOCKER_CERT_PATH: to load the TLS certificates from.
* DOCKER_TLS_VERIFY: to enable or disable TLS verification, off by default.

### Container Labels for plugin

* `sshpiper.username`: username to filter containers by `downstream`'s username. Leave empty to auth with `authorized_keys` only.
* `sshpiper.container_username`: username of container's sshd
* `sshpiper.port`: port of container's sshd
* `sshpiper.htpasswd_data` / `sshpiper.htpasswd_file`: base64 or file path for htpasswd data (password auth)
* `sshpiper.authorized_keys_data` / `sshpiper.authorized_keys_file`: base64 or file path for authorized_keys (public key auth)
* `sshpiper.trusted_user_ca_keys_data` / `sshpiper.trusted_user_ca_keys_file`: base64 or file path for CA keys (certificate auth)
* `sshpiper.known_hosts_data` / `sshpiper.known_hosts_file`: base64 or file path for known_hosts (host key verification)
* `sshpiper.private_key_data` / `sshpiper.private_key_file`: base64 or file path for private key (upstream auth)
* `sshpiper.vault_kv_path`: Vault path for secret loading (password, private key, etc.)

### Vault Integration

If `sshpiper.vault_kv_path` is set, the plugin will attempt to load secrets (e.g., `password`, `private_key`) from Vault at the specified path. This allows secure, dynamic secret management for container pipes.

---

All key, password, and certificate fields support both base64 (`*_data`) and file (`*_file`) label variants, as well as Vault integration. Deprecated fields (`authorized_keys`, `private_key`) are no longer supported.
