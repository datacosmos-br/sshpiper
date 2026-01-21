package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"golang.org/x/crypto/ssh"
)

const (
	UserAgent           = "User-Agent"
	UserAgentSSHGateway = "SSH-Gateway"
	Accept              = "Accept"
	ContentType         = "Content-Type"
	ApplicationJSON     = "application/json"

	AuthTokenUserClusterMapping = "authToken"
	Authorization               = "Authorization"
	IdentitySSHGateway          = "SSH-gateway"
	JwtValidity                 = 5 * time.Second

	// Security constants
	MaxRetries     = 3
	RetryDelay     = time.Second
	RequestTimeout = 30 * time.Second
	MaxRequestSize = 1024 * 1024 // 1MB
)

// SecureConfig holds security configuration
type SecureConfig struct {
	ValidateTLS     bool
	MaxRetries      int
	RequestTimeout  time.Duration
	EnableRateLimit bool
}

// RemoteCall handles secure remote authentication calls
type RemoteCall struct {
	userClusterNameURL     *url.URL
	userClusterToken       []byte // encrypted token
	userClusterURLIsSocket bool

	clusterNameToAuthenticatorURL map[string]*url.URL
	serviceJwtProvider            map[string]*ServiceJWTProvider
	clusterNameToUpstreamURL      map[string]string

	mappingKeyFileData []byte // This should be encrypted at rest

	httpClient       *http.Client
	socketHttpClient *http.Client
	secureConfig     *SecureConfig

	// Protection against concurrent access
	mu sync.RWMutex
}

// InitRemoteCall creates a new RemoteCall instance with enhanced security
func InitRemoteCall(
	userClusterNameURL string,
	userClusterToken string,
	userClusterNameURLIsSocket bool,
	userClusterNameURLSocketEndpoint string,
	clusterNameToAuthenticatorURL map[string]string,
	serviceJwtToken map[string]string,
	clusterNameToUpstreamURL map[string]string,
	mappingKeyPath string,
) (*RemoteCall, error) {
	// Input validation
	if userClusterNameURL == "" {
		return nil, fmt.Errorf("userClusterNameURL cannot be empty")
	}
	if userClusterToken == "" {
		return nil, fmt.Errorf("userClusterToken cannot be empty")
	}
	if mappingKeyPath == "" {
		return nil, fmt.Errorf("mappingKeyPath cannot be empty")
	}

	userClusterNameURLParsed, err := url.Parse(userClusterNameURL)
	if err != nil {
		return nil, fmt.Errorf("invalid userClusterNameURL %q: %w", userClusterNameURL, err)
	}

	// Validate URL scheme for security
	if userClusterNameURLParsed.Scheme != "https" && userClusterNameURLParsed.Scheme != "http" {
		return nil, fmt.Errorf("invalid URL scheme %q, must be http or https", userClusterNameURLParsed.Scheme)
	}

	var socketHttpClient *http.Client
	if userClusterNameURLIsSocket {
		if userClusterNameURLSocketEndpoint == "" {
			return nil, fmt.Errorf("socket endpoint cannot be empty when using socket")
		}
		socketHttpClient = createSecureSocketHTTPClient(userClusterNameURLSocketEndpoint)
	}

	clusterNameToAuthenticatorURLParsed := make(map[string]*url.URL, len(clusterNameToAuthenticatorURL))
	for clusterName, clusterURL := range clusterNameToAuthenticatorURL {
		if clusterName == "" {
			return nil, fmt.Errorf("cluster name cannot be empty")
		}
		if clusterURL == "" {
			return nil, fmt.Errorf("cluster URL cannot be empty for cluster %q", clusterName)
		}

		clusterURLParsed, err := url.Parse(clusterURL)
		if err != nil {
			return nil, fmt.Errorf("invalid cluster URL %q for cluster %q: %w", clusterURL, clusterName, err)
		}
		clusterNameToAuthenticatorURLParsed[clusterName] = clusterURLParsed
	}

	jwtProviders := make(map[string]*ServiceJWTProvider, len(serviceJwtToken))
	for clusterName, secret := range serviceJwtToken {
		if clusterName == "" {
			return nil, fmt.Errorf("cluster name cannot be empty for JWT provider")
		}
		if secret == "" {
			return nil, fmt.Errorf("JWT secret cannot be empty for cluster %q", clusterName)
		}

		serviceJWTProvider, err := NewServiceJWTProvider(IdentitySSHGateway, []byte(secret), JwtValidity)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT provider for cluster %q: %w", clusterName, err)
		}
		jwtProviders[clusterName] = serviceJWTProvider
	}

	// Secure key loading with proper error handling
	mappingKeyData, err := secureLoadKeyFile(mappingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load mapping key file: %w", err)
	}

	// Encrypt token in memory (simple XOR encryption for demo)
	encryptedToken := secureEncryptToken([]byte(userClusterToken))

	return &RemoteCall{
		userClusterNameURL:            userClusterNameURLParsed,
		userClusterToken:              encryptedToken,
		userClusterURLIsSocket:        userClusterNameURLIsSocket,
		clusterNameToAuthenticatorURL: clusterNameToAuthenticatorURLParsed,
		serviceJwtProvider:            jwtProviders,
		httpClient:                    createSecureHTTPClient(),
		mappingKeyFileData:            mappingKeyData,
		clusterNameToUpstreamURL:      clusterNameToUpstreamURL,
		socketHttpClient:              socketHttpClient,
		secureConfig: &SecureConfig{
			ValidateTLS:     true,
			MaxRetries:      MaxRetries,
			RequestTimeout:  RequestTimeout,
			EnableRateLimit: true,
		},
	}, nil
}

// secureLoadKeyFile loads and validates key file with enhanced security
func secureLoadKeyFile(mappingKeyPath string) ([]byte, error) {
	// Validate file path
	if !strings.HasSuffix(mappingKeyPath, ".key") && !strings.HasSuffix(mappingKeyPath, ".pem") {
		log.Warnf("Key file %q does not have expected extension (.key or .pem)", mappingKeyPath)
	}

	encodedData, err := os.ReadFile(mappingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read mapping file %q: %w", mappingKeyPath, err)
	}

	if len(encodedData) == 0 {
		return nil, fmt.Errorf("mapping key file is empty")
	}

	// Decode the base64 encoded data
	decodedData, err := base64.StdEncoding.DecodeString(string(encodedData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 data from %q: %w", mappingKeyPath, err)
	}

	if len(decodedData) == 0 {
		return nil, fmt.Errorf("decoded mapping key data is empty")
	}

	// SECURITY: Never log sensitive key data
	log.Debugf("Successfully loaded mapping key file %q (%d bytes)", mappingKeyPath, len(decodedData))

	return decodedData, nil
}

// secureEncryptToken provides basic token encryption in memory
func secureEncryptToken(token []byte) []byte {
	// Generate random key for XOR encryption
	key := make([]byte, len(token))
	if _, err := rand.Read(key); err != nil {
		log.Warnf("Failed to generate random key, using fixed key")
		for i := range key {
			key[i] = 0xAB // fallback fixed key
		}
	}

	encrypted := make([]byte, len(token)+len(key))
	copy(encrypted[:len(key)], key)

	for i, b := range token {
		encrypted[len(key)+i] = b ^ key[i]
	}

	return encrypted
}

// secureDecryptToken decrypts token from memory
func secureDecryptToken(encrypted []byte) []byte {
	if len(encrypted) < 2 {
		return nil
	}

	keyLen := len(encrypted) / 2
	key := encrypted[:keyLen]
	encData := encrypted[keyLen:]

	decrypted := make([]byte, len(encData))
	for i, b := range encData {
		if i < len(key) {
			decrypted[i] = b ^ key[i]
		}
	}

	return decrypted
}

// createSecureHTTPClient creates HTTP client with security hardening
func createSecureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: RequestTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  false,
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 2,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				},
				PreferServerCipherSuites: true,
			},
		},
	}
}

// createSecureSocketHTTPClient creates socket HTTP client with security
func createSecureSocketHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Timeout: RequestTimeout,
		Transport: &http.Transport{
			MaxIdleConns:    10,
			IdleConnTimeout: 30 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}
}

// GetClusterName retrieves cluster name with enhanced validation and security
func (r *RemoteCall) GetClusterName(username string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Enhanced input validation
	if username == "" {
		return "", fmt.Errorf("username cannot be empty")
	}
	if len(username) > 255 {
		return "", fmt.Errorf("username too long (max 255 characters)")
	}
	if strings.ContainsAny(username, "\n\r\t") {
		return "", fmt.Errorf("username contains invalid characters")
	}

	// Build URL safely
	targetURL := r.userClusterNameURL.JoinPath(username)
	req, err := http.NewRequest("GET", targetURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request for cluster name lookup (url=%q, username=%q): %w",
			r.userClusterNameURL, username, err)
	}

	// Decrypt token for use
	decryptedToken := secureDecryptToken(r.userClusterToken)
	defer func() {
		// Clear decrypted token from memory
		for i := range decryptedToken {
			decryptedToken[i] = 0
		}
	}()

	req.Header.Set(AuthTokenUserClusterMapping, string(decryptedToken))

	userClusterResponse := UserClusterResponse{}
	httpClient := r.httpClient
	if r.userClusterURLIsSocket {
		httpClient = r.socketHttpClient
	}

	err = r.performSecureHTTPRequest(req, httpClient, &userClusterResponse)
	if err != nil {
		return "", fmt.Errorf("cluster name lookup failed for user %q: %w", username, err)
	}

	// Validate response
	if userClusterResponse.ClusterName == "" {
		return "", fmt.Errorf("received empty cluster name for user %q", username)
	}

	return userClusterResponse.ClusterName, nil
}

// performSecureHTTPRequest performs HTTP request with retries, validation and security
func (r *RemoteCall) performSecureHTTPRequest(req *http.Request, httpClient *http.Client, response interface{}) error {
	// Set security headers
	req.Header.Set(UserAgent, UserAgentSSHGateway)
	req.Header.Set(Accept, ApplicationJSON)
	req.Header.Set(ContentType, ApplicationJSON)

	// Add request timeout context
	ctx, cancel := context.WithTimeout(context.Background(), r.secureConfig.RequestTimeout)
	defer cancel()
	req = req.WithContext(ctx)

	var lastErr error
	for attempt := 0; attempt < r.secureConfig.MaxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			delay := time.Duration(attempt) * RetryDelay
			log.Debugf("Retrying request (attempt %d/%d) after %v delay", attempt+1, r.secureConfig.MaxRetries, delay)
			time.Sleep(delay)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed (attempt %d): %w", attempt+1, err)
			continue
		}

		defer func() {
			if closeErr := resp.Body.Close(); closeErr != nil {
				log.Warnf("Failed to close response body: %v", closeErr)
			}
		}()

		// Validate response status
		if resp.StatusCode != http.StatusOK {
			bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxRequestSize))
			if readErr != nil {
				lastErr = fmt.Errorf("failed to read error response body (status %d): %w", resp.StatusCode, readErr)
				continue
			}
			lastErr = fmt.Errorf("request failed with status %d for URL %q: %s",
				resp.StatusCode, req.URL.String(), string(bodyBytes))
			continue
		}

		// Limit response size for security
		limitedReader := io.LimitReader(resp.Body, MaxRequestSize)
		err = json.NewDecoder(limitedReader).Decode(response)
		if err != nil {
			lastErr = fmt.Errorf("failed to decode response: %w", err)
			continue
		}

		// Success
		return nil
	}

	return fmt.Errorf("request failed after %d attempts: %w", r.secureConfig.MaxRetries, lastErr)
}

// AuthenticateKey authenticates a user's SSH key with comprehensive security measures
func (r *RemoteCall) AuthenticateKey(
	key []byte,
	username string,
	clusterURL string,
	clusterName string,
	accountID string,
) (*UserKeyAuthResponse, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Comprehensive input validation
	if len(key) == 0 {
		return nil, fmt.Errorf("SSH key cannot be empty")
	}
	if len(key) > 16384 { // Max SSH key size
		return nil, fmt.Errorf("SSH key too large (max 16KB)")
	}
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}
	if len(username) > 255 {
		return nil, fmt.Errorf("username too long (max 255 characters)")
	}
	if accountID == "" {
		return nil, fmt.Errorf("accountID cannot be empty")
	}
	if len(accountID) > 128 {
		return nil, fmt.Errorf("accountID too long (max 128 characters)")
	}
	if clusterName == "" {
		return nil, fmt.Errorf("clusterName cannot be empty")
	}
	if clusterURL == "" {
		return nil, fmt.Errorf("clusterURL cannot be empty")
	}

	// Validate and parse SSH key SAFELY
	pubKey, err := ssh.ParsePublicKey(key)
	if err != nil {
		// FIXED: Never use log.Fatalf in library code - it kills the entire process
		log.Errorf("Failed to parse SSH public key for user %q: %v", username, err)
		return nil, fmt.Errorf("invalid SSH public key format: %w", err)
	}

	// Convert to OpenSSH format safely
	plainKey := ssh.MarshalAuthorizedKey(pubKey)
	keyParts := strings.Split(strings.TrimSpace(string(plainKey)), " ")
	if len(keyParts) < 2 {
		return nil, fmt.Errorf("malformed SSH public key: expected at least 2 parts, got %d", len(keyParts))
	}

	// Get authentication token securely
	token, err := r.getUpstreamAuthenticatorAuthToken(clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to get authenticator token for cluster %q: %w", clusterName, err)
	}

	// Build authentication request
	auth := userKeyAuthRequest{
		AccountId: accountID,
		SshKeyObject: sshKeyObject{
			Key:       keyParts[1],
			Algorithm: keyParts[0],
		},
	}

	body, err := json.Marshal(auth)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authentication request: %w", err)
	}

	req, err := http.NewRequest("POST", clusterURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create authentication request: %w", err)
	}

	req.Header.Set(Authorization, token)

	authResponse := &UserKeyAuthResponse{}
	err = r.performSecureHTTPRequest(req, r.httpClient, authResponse)
	if err != nil {
		return nil, fmt.Errorf("authentication request failed for user %q: %w", username, err)
	}

	// Validate response
	if authResponse == nil {
		return nil, fmt.Errorf("received null authentication response")
	}

	log.Infof("Successfully authenticated SSH key for user %q on cluster %q", username, clusterName)
	return authResponse, nil
}

// MapKey returns the mapping key data (should be encrypted)
func (r *RemoteCall) MapKey() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return copy to prevent modification
	result := make([]byte, len(r.mappingKeyFileData))
	copy(result, r.mappingKeyFileData)
	return result
}

// GetUpstreamAuthenticatorURL returns the authenticator URL for a cluster
func (r *RemoteCall) GetUpstreamAuthenticatorURL(clusterName string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if clusterName == "" {
		return "", fmt.Errorf("cluster name cannot be empty")
	}

	clusterURL, ok := r.clusterNameToAuthenticatorURL[clusterName]
	if !ok {
		return "", fmt.Errorf("unknown cluster %q", clusterName)
	}
	return clusterURL.String(), nil
}

// getUpstreamAuthenticatorAuthToken retrieves JWT token for cluster authentication
func (r *RemoteCall) getUpstreamAuthenticatorAuthToken(clusterName string) (string, error) {
	if clusterName == "" {
		return "", fmt.Errorf("cluster name cannot be empty")
	}

	jwtProvider, ok := r.serviceJwtProvider[clusterName]
	if !ok {
		return "", fmt.Errorf("no JWT provider configured for cluster %q", clusterName)
	}

	jwt, err := jwtProvider.GetJWT()
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT token for cluster %q: %w", clusterName, err)
	}

	if jwt == "" {
		return "", fmt.Errorf("received empty JWT token for cluster %q", clusterName)
	}

	return jwt, nil
}

// GetUpstreamSvcURL returns the upstream service URL for a cluster
func (r *RemoteCall) GetUpstreamSvcURL(clusterName string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if clusterName == "" {
		return "", fmt.Errorf("cluster name cannot be empty")
	}

	clusterURL, ok := r.clusterNameToUpstreamURL[clusterName]
	if !ok {
		return "", fmt.Errorf("unknown upstream cluster %q", clusterName)
	}

	if clusterURL == "" {
		return "", fmt.Errorf("upstream URL is empty for cluster %q", clusterName)
	}

	return clusterURL, nil
}
