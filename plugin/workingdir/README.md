# Working Directory plugin for sshpiperd

`Working Dir` is a `/home`-like directory.
sshpiperd read files from `workingdir/[username]/` to know upstream's configuration.

e.g.

```ascii
workingdir tree

.
├── github
│   └── sshpiper_upstream
└── linode
    └── sshpiper_upstream
```

when `ssh sshpiper_host -l github`,
sshpiper reads `workingdir/github/sshpiper_upstream` and the connect to the upstream.

## Usage

```bash
sshpiperd workingdir --root /var/sshpiper
```

### options (allow supported read from environments)

```bash
--allow-baduser-name  allow bad username (default: false) [$SSHPIPERD_WORKINGDIR_ALLOWBADUSERNAME]
--no-check-perm       disable 0400 checking (default: false) [$SSHPIPERD_WORKINGDIR_NOCHECKPERM]
--no-password-auth    disable password authentication and only use public key authentication (default: false) [$SSHPIPERD_WORKINGDIR_NOPASSWORD_AUTH]
--root value          path to root working directory (default: "/var/sshpiper") [$SSHPIPERD_WORKINGDIR_ROOT]
--strict-hostkey      upstream host public key must be in known_hosts file, otherwise drop the connection (default: false) [$SSHPIPERD_WORKINGDIR_STRICTHOSTKEY]
```

## User files

*These file MUST NOT be accessible to group or other. (chmod og-rwx filename)*

* sshpiper_upstream

  * line starts with `#` are treated as comment
  * only the first not comment line will be parsed
  * if no port was given, 22 will be used as default
  * if `user@` was defined, username to upstream will be the mapped one

```bash
# comment
[user@]upstream[:22]
```

```bash
e.g. 

git@github.com

google.com:12345

```

* authorized_keys
  
   OpenSSH format `authorized_keys` (see `~/.ssh/authorized_keys`). `downstream`'s public key must be in this file to get verified in order to use `id_rsa` to login to `upstream`.

* id_rsa

   RSA key for upstream.

* known_hosts

   when `--strict-hostkey` is set, upstream server's public key must present in known_hosts

## Recursive mode (--recursive-search)

`--recursive-search` will search all sub directories of the `username` directory to find the `downstream` key in `authorized_keys` file.

```bash
├── git
│   ├── bitbucket
│   │   └── sshpiper_upstream
│   ├── github
│   │   ├── authorized_keys
│   │   ├── id_rsa
│   │   └── sshpiper_upstream
│   └── gitlab
│       └── sshpiper_upstream
├── linode....
```

## TOTP

`--check-totp` will check the TOTP 2FA before connecting to the upstream, compatible with all [RFC6238](https://datatracker.ietf.org/doc/html/rfc6238) authenticator, for example: `google authenticator`, `azure authenticator`.

the secret should be stored in `totp` file in working directory.
for example:

```bash
/var/sshpiper/username/totp
```

## FAQ

* Q: Why sshpiperd still asks for password even I disabled password auth in upstream (different behavior from `v0`)
   A: You may want `--no-password-auth`, see <https://github.com/tg123/sshpiper/issues/97>
* Q: What if I want to use a different key type for the SSH server instead of RSA?
   A: The [`workingdir` plugin hard-codes for `id_rsa` for simplicity](https://github.com/tg123/sshpiper/issues/554#issue-2959158335). Consider a different plugin like `yaml` if you need more flexibility.

Below is a complete YAML CRD definition for the Pipe resource, updated to support a single Vault KV path for each side. In the "from" section, the new field `vault_kv_path` allows you to specify the Vault KV path from which to retrieve the trusted CA keys (expecting a key `"ssh-ca"`). In the "to" section, the new field `vault_kv_path` allows you to retrieve all required upstream secrets (expecting keys `"ssh-privatekey"`, optionally `"ssh-publickey-cert"`, and `"password"`).

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: pipes.sshpiper.com
spec:
  group: sshpiper.com
  names:
    kind: Pipe
    listKind: PipeList
    plural: pipes
    singular: pipe
  scope: Namespaced
  versions:
  - name: v1beta1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        required:
          - spec
        properties:
          apiVersion:
            type: string
            description: "API version of the resource."
          kind:
            type: string
            description: "Kind of the resource."
          metadata:
            type: object
          spec:
            type: object
            required:
              - from
              - to
            properties:
              from:
                type: array
                items:
                  type: object
                  required:
                    - username
                  properties:
                    username:
                      type: string
                      description: "Username to match on incoming connection."
                    username_regex_match:
                      type: boolean
                      description: "If true, treat username as a regular expression."
                    groupname:
                      type: string
                      description: "Optional group name for matching."
                    authorized_keys_data:
                      oneOf:
                        - type: array
                          items:
                            type: string
                        - type: string
                      description: "Base64 inline data for authorized_keys."
                    authorized_keys_file:
                      oneOf:
                        - type: array
                          items:
                            type: string
                        - type: string
                      description: "Path(s) to authorized_keys file(s)."
                    trusted_user_ca_keys_data:
                      oneOf:
                        - type: array
                          items:
                            type: string
                        - type: string
                      description: "Base64 inline data for trusted CA keys (fallback)."
                    trusted_user_ca_keys_file:
                      oneOf:
                        - type: array
                          items:
                            type: string
                        - type: string
                      description: "Path(s) to trusted CA keys file(s) (fallback)."
                    vault_kv_path:
                      type: string
                      description: "Vault KV path to retrieve all secrets for the 'from' side (expects key 'ssh-ca')."
              to:
                type: object
                required:
                  - host
                properties:
                  host:
                    type: string
                    description: "Destination host (host:port) for routing."
                  username:
                    type: string
                    description: "Username for authentication on the destination."
                  ignore_hostkey:
                    type: boolean
                    description: "If true, ignore host key verification."
                  known_hosts_data:
                    oneOf:
                      - type: array
                        items:
                          type: string
                      - type: string
                    description: "Base64 inline data for known_hosts."
                  known_hosts:
                    oneOf:
                      - type: array
                        items:
                          type: string
                      - type: string
                    description: "Path(s) to known_hosts file(s)."
                  private_key:
                    type: string
                    description: "Path to the private key (fallback)."
                  private_key_data:
                    type: string
                    description: "Base64 inline data for the private key (fallback)."
                  password:
                    type: string
                    description: "Password for authentication (fallback)."
                  vault_kv_path:
                    type: string
                    description: "Vault KV path to retrieve all secrets for the 'to' side (expects keys 'ssh-privatekey', optionally 'ssh-publickey-cert', and 'password')."
        additionalPrinterColumns:
        - jsonPath: .spec.from[0].username
          name: FromUser
          type: string
        - jsonPath: .spec.to.username
          name: ToUser
          type: string
        - jsonPath: .spec.to.host
          name: ToHost
          type: string
```

#### Vault Integration (Single KV Path)

This CRD allows you to configure your Pipe resource to fetch all required secrets directly from a single Vault KV path.

* **In the "from" section**:  
  Use the `vault_kv_path` field to specify the Vault path where your trusted CA key is stored.  
  The Vault secret must include the key `"ssh-ca"` containing the CA public key.

* **In the "to" section**:  
  Use the `vault_kv_path` field to specify the Vault path where all upstream secrets are stored.  
  The Vault secret must include:  
  * `"ssh-privatekey"`: The upstream private key.  
  * Optionally, `"ssh-publickey-cert"`: The corresponding public key certificate.  
  * `"password"`: The upstream password (if using password authentication).

#### Example YAML Configuration (sshpiperd.yaml)

```yaml
version: "1.0"
pipes:
  # Pipe for upstream password authentication.
  - from:
      - username: ".*"
        username_regex_match: true
        vault_kv_path: "secret/ssh/teleport-ca"
    to:
      host: "upstream-password.example.com:22"
      username: "targetuser"
      vault_kv_path: "secret/ssh/upstream-password-credentials"
  # Pipe for upstream private key authentication.
  - from:
      - username: ".*"
        username_regex_match: true
        vault_kv_path: "secret/ssh/teleport-ca"
    to:
      host: "upstream-privatekey.example.com:22"
      username: "targetuser"
      vault_kv_path: "secret/ssh/upstream-privatekey-credentials"
```

#### Storing Secrets in Vault

1. **For the CA key**:  
   * **Vault Path**: `secret/ssh/teleport-ca`  
   * **Secret Data** (JSON example):

     ```json
     {
       "ssh-ca": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD..."
     }
     ```

2. **For upstream password credentials**:  
   * **Vault Path**: `secret/ssh/upstream-password-credentials`  
   * **Secret Data**:

     ```json
     {
       "password": "your_upstream_password"
     }
     ```

3. **For upstream private key credentials**:  
   * **Vault Path**: `secret/ssh/upstream-privatekey-credentials`  
   * **Secret Data**:

     ```json
     {
       "ssh-privatekey": "-----BEGIN PRIVATE KEY-----\nMIIEv...",
       "ssh-publickey-cert": "ssh-rsa-cert-v01@openssh.com AAAAB3..."
     }
     ```

#### Deploying in Kubernetes

1. **Update Your CRD**:  
   Apply the above CRD definition so that your Pipe resources support the new `vault_kv_path` fields.

2. **Create a ConfigMap**:  
   Create a ConfigMap containing your YAML configuration file (e.g. `sshpiperd.yaml`).

3. **Deploy sshpiperd**:  
   Ensure your sshpiperd deployment includes the correct environment variables for Vault (`VAULT_ADDR` and `VAULT_TOKEN`), and mount the ConfigMap so that the YAML config is available.

Example Deployment snippet:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sshpiperd
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sshpiperd
  template:
    metadata:
      labels:
        app: sshpiperd
    spec:
      containers:
      - name: sshpiperd
        image: your-custom-sshpiperd:latest
        args: ["yaml", "--config", "/config/sshpiperd.yaml"]
        env:
          - name: VAULT_ADDR
            value: "https://vault.example.com"
          - name: VAULT_TOKEN
            valueFrom:
              secretKeyRef:
                name: vault-credentials
                key: token
        volumeMounts:
          - name: config
            mountPath: /config
      volumes:
        - name: config
          configMap:
            name: sshpiperd-config
```

Below is a complete YAML CRD definition for the Pipe resource, updated to support a single Vault KV path for each side. In the "from" section, the new field `vault_kv_path` allows you to specify the Vault KV path from which to retrieve the trusted CA keys (expecting a key `"ssh-ca"`). In the "to" section, the new field `vault_kv_path` allows you to retrieve all required upstream secrets (expecting keys `"ssh-privatekey"`, optionally `"ssh-publickey-cert"`, and `"password"`).

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: pipes.sshpiper.com
spec:
  group: sshpiper.com
  names:
    kind: Pipe
    listKind: PipeList
    plural: pipes
    singular: pipe
  scope: Namespaced
  versions:
  - name: v1beta1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        required:
          - spec
        properties:
          apiVersion:
            type: string
            description: "API version of the resource."
          kind:
            type: string
            description: "Kind of the resource."
          metadata:
            type: object
          spec:
            type: object
            required:
              - from
              - to
            properties:
              from:
                type: array
                items:
                  type: object
                  required:
                    - username
                  properties:
                    username:
                      type: string
                      description: "Username to match on incoming connection."
                    username_regex_match:
                      type: boolean
                      description: "If true, treat username as a regular expression."
                    groupname:
                      type: string
                      description: "Optional group name for matching."
                    authorized_keys_data:
                      oneOf:
                        - type: array
                          items:
                            type: string
                        - type: string
                      description: "Base64 inline data for authorized_keys."
                    authorized_keys_file:
                      oneOf:
                        - type: array
                          items:
                            type: string
                        - type: string
                      description: "Path(s) to authorized_keys file(s)."
                    trusted_user_ca_keys_data:
                      oneOf:
                        - type: array
                          items:
                            type: string
                        - type: string
                      description: "Base64 inline data for trusted CA keys (fallback)."
                    trusted_user_ca_keys_file:
                      oneOf:
                        - type: array
                          items:
                            type: string
                        - type: string
                      description: "Path(s) to trusted CA keys file(s) (fallback)."
                    vault_kv_path:
                      type: string
                      description: "Vault KV path to retrieve all secrets for the 'from' side (expects key 'ssh-ca')."
              to:
                type: object
                required:
                  - host
                properties:
                  host:
                    type: string
                    description: "Destination host (host:port) for routing."
                  username:
                    type: string
                    description: "Username for authentication on the destination."
                  ignore_hostkey:
                    type: boolean
                    description: "If true, ignore host key verification."
                  known_hosts_data:
                    oneOf:
                      - type: array
                        items:
                          type: string
                      - type: string
                    description: "Base64 inline data for known_hosts."
                  known_hosts:
                    oneOf:
                      - type: array
                        items:
                          type: string
                      - type: string
                    description: "Path(s) to known_hosts file(s)."
                  private_key:
                    type: string
                    description: "Path to the private key (fallback)."
                  private_key_data:
                    type: string
                    description: "Base64 inline data for the private key (fallback)."
                  password:
                    type: string
                    description: "Password for authentication (fallback)."
                  vault_kv_path:
                    type: string
                    description: "Vault KV path to retrieve all secrets for the 'to' side (expects keys 'ssh-privatekey', optionally 'ssh-publickey-cert', and 'password')."
        additionalPrinterColumns:
        - jsonPath: .spec.from[0].username
          name: FromUser
          type: string
        - jsonPath: .spec.to.username
          name: ToUser
          type: string
        - jsonPath: .spec.to.host
          name: ToHost
          type: string
```

#### Vault Integration (Single KV Path)

This CRD allows you to configure your Pipe resource to fetch all required secrets directly from a single Vault KV path.

* **In the "from" section**:  
  Use the `vault_kv_path` field to specify the Vault path where your trusted CA key is stored.  
  The Vault secret must include the key `"ssh-ca"` containing the CA public key.

* **In the "to" section**:  
  Use the `vault_kv_path` field to specify the Vault path where all upstream secrets are stored.  
  The Vault secret must include:  
  * `"ssh-privatekey"`: The upstream private key.  
  * Optionally, `"ssh-publickey-cert"`: The corresponding public key certificate.  
  * `"password"`: The upstream password (if using password authentication).

#### Example YAML Configuration (sshpiperd.yaml)

```yaml
version: "1.0"
pipes:
  # Pipe for upstream password authentication.
  - from:
      - username: ".*"
        username_regex_match: true
        vault_kv_path: "secret/ssh/teleport-ca"
    to:
      host: "upstream-password.example.com:22"
      username: "targetuser"
      vault_kv_path: "secret/ssh/upstream-password-credentials"
  # Pipe for upstream private key authentication.
  - from:
      - username: ".*"
        username_regex_match: true
        vault_kv_path: "secret/ssh/teleport-ca"
    to:
      host: "upstream-privatekey.example.com:22"
      username: "targetuser"
      vault_kv_path: "secret/ssh/upstream-privatekey-credentials"
```

#### Storing Secrets in Vault

1. **For the CA key**:  
   * **Vault Path**: `secret/ssh/teleport-ca`  
   * **Secret Data** (JSON example):

     ```json
     {
       "ssh-ca": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD..."
     }
     ```

2. **For upstream password credentials**:  
   * **Vault Path**: `secret/ssh/upstream-password-credentials`  
   * **Secret Data**:

     ```json
     {
       "password": "your_upstream_password"
     }
     ```

3. **For upstream private key credentials**:  
   * **Vault Path**: `secret/ssh/upstream-privatekey-credentials`  
   * **Secret Data**:

     ```json
     {
       "ssh-privatekey": "-----BEGIN PRIVATE KEY-----\nMIIEv...",
       "ssh-publickey-cert": "ssh-rsa-cert-v01@openssh.com AAAAB3..."
     }
     ```

#### Deploying in Kubernetes

1. **Update Your CRD**:  
   Apply the above CRD definition so that your Pipe resources support the new `vault_kv_path` fields.

2. **Create a ConfigMap**:  
   Create a ConfigMap containing your YAML configuration file (e.g. `sshpiperd.yaml`).

3. **Deploy sshpiperd**:  
   Ensure your sshpiperd deployment includes the correct environment variables for Vault (`VAULT_ADDR` and `VAULT_TOKEN`), and mount the ConfigMap so that the YAML config is available.

Example Deployment snippet:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sshpiperd
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sshpiperd
  template:
    metadata:
      labels:
        app: sshpiperd
    spec:
      containers:
      - name: sshpiperd
        image: your-custom-sshpiperd:latest
        args: ["yaml", "--config", "/config/sshpiperd.yaml"]
        env:
          - name: VAULT_ADDR
            value: "https://vault.example.com"
          - name: VAULT_TOKEN
            valueFrom:
              secretKeyRef:
                name: vault-credentials
                key: token
        volumeMounts:
          - name: config
            mountPath: /config
      volumes:
        - name: config
          configMap:
            name: sshpiperd-config
```
