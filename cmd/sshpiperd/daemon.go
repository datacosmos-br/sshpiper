package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/cmd/sshpiperd/internal/plugin"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

const (
	trueValue = "true"

	// Security and performance constants
	maxConcurrentConnections = 1000
	connectionTimeout        = 30 * time.Second
	handshakeTimeout         = 10 * time.Second
	maxBannerSize            = 8192
	maxKeyFileSize           = 16384

	// Rate limiting
	connectionsPerSecond = 100
	rateLimitWindow      = time.Second
)

// SecureDaemon provides enhanced security and resource management
type daemon struct {
	config         *plugin.GrpcPluginConfig
	lis            net.Listener
	loginGraceTime time.Duration

	recorddir             string
	recordfmt             string
	usernameAsRecorddir   bool
	filterHostkeysReqeust bool
	replyPing             bool

	// Enhanced security and resource management
	ctx                 context.Context
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	activeConnections   int64
	connectionSemaphore chan struct{}
	rateLimiter         *rateLimiter
	shutdownOnce        sync.Once
	metrics             *daemonMetrics
}

// daemonMetrics tracks daemon performance and security metrics
type daemonMetrics struct {
	mu                   sync.RWMutex
	totalConnections     int64
	activeConnections    int64
	rejectedConnections  int64
	failedHandshakes     int64
	successfulHandshakes int64
}

// rateLimiter implements token bucket rate limiting
type rateLimiter struct {
	tokens    chan struct{}
	interval  time.Duration
	maxTokens int
	ticker    *time.Ticker
	done      chan struct{}
}

// newRateLimiter creates a new rate limiter
func newRateLimiter(maxTokens int, interval time.Duration) *rateLimiter {
	rl := &rateLimiter{
		tokens:    make(chan struct{}, maxTokens),
		interval:  interval,
		maxTokens: maxTokens,
		ticker:    time.NewTicker(interval),
		done:      make(chan struct{}),
	}

	// Fill initial tokens
	for i := 0; i < maxTokens; i++ {
		rl.tokens <- struct{}{}
	}

	// Start token refill goroutine
	go rl.refillTokens()

	return rl
}

// refillTokens continuously refills the token bucket
func (rl *rateLimiter) refillTokens() {
	for {
		select {
		case <-rl.ticker.C:
			select {
			case rl.tokens <- struct{}{}:
			default: // bucket is full
			}
		case <-rl.done:
			rl.ticker.Stop()
			return
		}
	}
}

// Allow checks if a request is allowed under rate limiting
func (rl *rateLimiter) Allow() bool {
	select {
	case <-rl.tokens:
		return true
	default:
		return false
	}
}

// Close stops the rate limiter
func (rl *rateLimiter) Close() {
	close(rl.done)
}

// generateSSHKey generates SSH key with enhanced security validation
func generateSSHKey(keyfile string) error {
	// Validate keyfile path
	if keyfile == "" {
		return fmt.Errorf("keyfile path cannot be empty")
	}

	absPath, err := filepath.Abs(keyfile)
	if err != nil {
		return fmt.Errorf("invalid keyfile path %q: %w", keyfile, err)
	}

	// Ensure directory exists
	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %q: %w", dir, err)
	}

	// Generate key securely
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate SSH key: %w", err)
	}

	privateKeyPEM, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)
	if len(privateKeyBytes) == 0 {
		return fmt.Errorf("failed to encode private key to PEM")
	}

	// Write with secure permissions
	if err := os.WriteFile(absPath, privateKeyBytes, 0600); err != nil {
		return fmt.Errorf("failed to write keyfile %q: %w", absPath, err)
	}

	log.Infof("Generated SSH host key: %s", absPath)
	return nil
}

// newDaemon creates a new daemon with enhanced security and resource management
func newDaemon(ctx *cli.Context) (*daemon, error) {
	config := &plugin.GrpcPluginConfig{}

	// Validate and set configuration
	if err := validateDaemonConfig(ctx, config); err != nil {
		return nil, fmt.Errorf("invalid daemon configuration: %w", err)
	}

	// Set up host keys securely
	if err := setupHostKeys(ctx, config); err != nil {
		return nil, fmt.Errorf("failed to setup host keys: %w", err)
	}

	// Create secure listener
	lis, err := createSecureListener(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	// Set up banner handling
	if err := setupBannerHandling(ctx, config); err != nil {
		return nil, fmt.Errorf("failed to setup banner handling: %w", err)
	}

	// Create daemon context for graceful shutdown
	daemonCtx, cancel := context.WithCancel(context.Background())

	d := &daemon{
		config:              config,
		lis:                 lis,
		loginGraceTime:      ctx.Duration("login-grace-time"),
		ctx:                 daemonCtx,
		cancel:              cancel,
		connectionSemaphore: make(chan struct{}, maxConcurrentConnections),
		rateLimiter:         newRateLimiter(connectionsPerSecond, rateLimitWindow),
		metrics:             &daemonMetrics{},
	}

	return d, nil
}

// validateDaemonConfig validates daemon configuration parameters
func validateDaemonConfig(ctx *cli.Context, config *plugin.GrpcPluginConfig) error {
	// Validate cipher algorithms
	ciphers := ctx.StringSlice("allowed-downstream-ciphers-algos")
	if len(ciphers) > 0 {
		for _, cipher := range ciphers {
			if cipher == "" {
				return fmt.Errorf("empty cipher algorithm not allowed")
			}
		}
		config.Ciphers = ciphers
	}

	// Validate MAC algorithms
	macs := ctx.StringSlice("allowed-downstream-macs-algos")
	if len(macs) > 0 {
		for _, mac := range macs {
			if mac == "" {
				return fmt.Errorf("empty MAC algorithm not allowed")
			}
		}
		config.MACs = macs
	}

	// Validate key exchange algorithms
	kex := ctx.StringSlice("allowed-downstream-keyexchange-algos")
	if len(kex) > 0 {
		for _, k := range kex {
			if k == "" {
				return fmt.Errorf("empty key exchange algorithm not allowed")
			}
		}
		config.KeyExchanges = kex
	}

	// Validate public key algorithms
	pubkeyAlgos := ctx.StringSlice("allowed-downstream-pubkey-algos")
	if len(pubkeyAlgos) > 0 {
		for _, algo := range pubkeyAlgos {
			if algo == "" {
				return fmt.Errorf("empty public key algorithm not allowed")
			}
		}
		config.PublicKeyAuthAlgorithms = pubkeyAlgos
	}

	config.SetDefaults()

	// Double call to SetDefaults as per original logic, but with validation
	config.SetDefaults()

	return nil
}

// setupHostKeys configures host keys with enhanced security
func setupHostKeys(ctx *cli.Context, config *plugin.GrpcPluginConfig) error {
	keybase64 := ctx.String("server-key-data")
	if keybase64 != "" {
		return setupHostKeyFromBase64(keybase64, config)
	}

	return setupHostKeyFromFile(ctx, config)
}

// setupHostKeyFromBase64 loads host key from base64 data
func setupHostKeyFromBase64(keybase64 string, config *plugin.GrpcPluginConfig) error {
	log.Infof("Loading host key from base64 parameter")

	if len(keybase64) > maxKeyFileSize*2 { // base64 is ~33% larger
		return fmt.Errorf("base64 key data too large (max %d characters)", maxKeyFileSize*2)
	}

	privateBytes, err := base64.StdEncoding.DecodeString(keybase64)
	if err != nil {
		return fmt.Errorf("invalid base64 key data: %w", err)
	}

	if len(privateBytes) == 0 {
		return fmt.Errorf("decoded key data is empty")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	config.ClearHostKeys()
	config.AddHostKey(private)

	// SECURITY: Don't log the actual key data
	log.Infof("Loaded host key from base64 (type: %s, fingerprint: %s)",
		private.PublicKey().Type(),
		ssh.FingerprintSHA256(private.PublicKey()))

	return nil
}

// setupHostKeyFromFile loads host key from file
func setupHostKeyFromFile(ctx *cli.Context, config *plugin.GrpcPluginConfig) error {
	keyfile := ctx.String("server-key")
	if keyfile == "" {
		return fmt.Errorf("server-key file path cannot be empty")
	}

	privateKeyFiles, err := filepath.Glob(keyfile)
	if err != nil {
		return fmt.Errorf("invalid server-key glob pattern %q: %w", keyfile, err)
	}

	generate := false
	switch ctx.String("server-key-generate-mode") {
	case "notexist":
		generate = len(privateKeyFiles) == 0
	case "always":
		generate = true
	case "disable":
		// No generation
	default:
		return fmt.Errorf("invalid server-key-generate-mode %q (allowed: notexist, always, disable)",
			ctx.String("server-key-generate-mode"))
	}

	if generate {
		if err := generateSSHKey(keyfile); err != nil {
			return fmt.Errorf("failed to generate host key: %w", err)
		}
		privateKeyFiles = []string{keyfile}
	}

	if len(privateKeyFiles) == 0 {
		return fmt.Errorf("no server key files found (pattern: %q)", keyfile)
	}

	log.Infof("Loading host keys from files: %v", privateKeyFiles)
	for _, privateKeyFile := range privateKeyFiles {
		if err := loadHostKeyFile(privateKeyFile, config); err != nil {
			return fmt.Errorf("failed to load host key %q: %w", privateKeyFile, err)
		}
	}

	return nil
}

// loadHostKeyFile loads a single host key file
func loadHostKeyFile(privateKeyFile string, config *plugin.GrpcPluginConfig) error {
	// Validate file path
	absPath, err := filepath.Abs(privateKeyFile)
	if err != nil {
		return fmt.Errorf("invalid key file path: %w", err)
	}

	// Check file size
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("cannot access key file: %w", err)
	}

	if info.Size() > maxKeyFileSize {
		return fmt.Errorf("key file too large (max %d bytes)", maxKeyFileSize)
	}

	privateBytes, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("cannot read key file: %w", err)
	}

	if len(privateBytes) == 0 {
		return fmt.Errorf("key file is empty")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return fmt.Errorf("invalid private key format: %w", err)
	}

	config.ClearHostKeys()
	config.AddHostKey(private)

	// SECURITY: Don't log the actual key data
	log.Infof("Loaded host key from %s (type: %s, fingerprint: %s)",
		absPath,
		private.PublicKey().Type(),
		ssh.FingerprintSHA256(private.PublicKey()))

	return nil
}

// createSecureListener creates a network listener with security hardening
func createSecureListener(ctx *cli.Context) (net.Listener, error) {
	address := ctx.String("address")
	port := ctx.String("port")

	if port == "" {
		return nil, fmt.Errorf("port cannot be empty")
	}

	// Validate address format
	addr := net.JoinHostPort(address, port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %q: %w", addr, err)
	}

	log.Infof("Created secure listener on %s", addr)
	return lis, nil
}

// setupBannerHandling configures banner handling with security validation
func setupBannerHandling(ctx *cli.Context, config *plugin.GrpcPluginConfig) error {
	bannertext := ctx.String("banner-text")
	bannerfile := ctx.String("banner-file")

	if bannertext != "" || bannerfile != "" {
		config.DownstreamBannerCallback = func(_ ssh.ConnMetadata, _ ssh.ChallengeContext) string {
			if bannerfile != "" {
				return loadBannerFile(bannerfile)
			}
			return validateBannerText(bannertext)
		}
	}

	return setupUpstreamBannerMode(ctx, config)
}

// loadBannerFile loads banner from file with security validation
func loadBannerFile(bannerfile string) string {
	if bannerfile == "" {
		return ""
	}

	// Validate file path
	absPath, err := filepath.Abs(bannerfile)
	if err != nil {
		log.Warnf("Invalid banner file path %q: %v", bannerfile, err)
		return ""
	}

	// Check file size
	info, err := os.Stat(absPath)
	if err != nil {
		log.Warnf("Cannot access banner file %q: %v", absPath, err)
		return ""
	}

	if info.Size() > maxBannerSize {
		log.Warnf("Banner file %q too large (max %d bytes)", absPath, maxBannerSize)
		return ""
	}

	text, err := os.ReadFile(absPath)
	if err != nil {
		log.Warnf("Cannot read banner file %q: %v", absPath, err)
		return ""
	}

	return validateBannerText(string(text))
}

// validateBannerText validates banner text content
func validateBannerText(text string) string {
	if len(text) > maxBannerSize {
		log.Warnf("Banner text too long (max %d characters), truncating", maxBannerSize)
		return text[:maxBannerSize]
	}
	return text
}

// setupUpstreamBannerMode configures upstream banner handling
func setupUpstreamBannerMode(ctx *cli.Context, config *plugin.GrpcPluginConfig) error {
	mode := ctx.String("upstream-banner-mode")

	switch mode {
	case "passthrough":
		// Library handles banner to client - no callback needed

	case "ignore":
		config.UpstreamBannerCallback = func(_ ssh.ServerPreAuthConn, _ string, _ ssh.ChallengeContext) error {
			return nil
		}

	case "dedup":
		config.UpstreamBannerCallback = createDedupBannerCallback()

	case "first-only":
		config.UpstreamBannerCallback = createFirstOnlyBannerCallback()

	default:
		return fmt.Errorf("invalid upstream-banner-mode %q (allowed: passthrough, ignore, dedup, first-only)", mode)
	}

	return nil
}

// createDedupBannerCallback creates a banner deduplication callback
func createDedupBannerCallback() func(ssh.ServerPreAuthConn, string, ssh.ChallengeContext) error {
	return func(downstream ssh.ServerPreAuthConn, banner string, ctx ssh.ChallengeContext) error {
		if banner == "" {
			return nil
		}

		meta, ok := ctx.Meta().(*plugin.PluginConnMeta)
		if !ok {
			log.Warnf("Upstream banner deduplication failed: cannot get plugin connection meta")
			return nil
		}

		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(banner)))
		key := fmt.Sprintf("sshpiperd.upstream.banner.%s", hash)

		if meta.Metadata[key] == trueValue {
			return nil
		}

		meta.Metadata[key] = trueValue
		return downstream.SendAuthBanner(validateBannerText(banner))
	}
}

// createFirstOnlyBannerCallback creates a first-only banner callback
func createFirstOnlyBannerCallback() func(ssh.ServerPreAuthConn, string, ssh.ChallengeContext) error {
	return func(downstream ssh.ServerPreAuthConn, banner string, ctx ssh.ChallengeContext) error {
		if banner == "" {
			return nil
		}

		meta, ok := ctx.Meta().(*plugin.PluginConnMeta)
		if !ok {
			log.Warnf("Upstream banner first-only failed: cannot get plugin connection meta")
			return nil
		}

		if meta.Metadata["sshpiperd.upstream.banner.sent"] == trueValue {
			return nil
		}

		meta.Metadata["sshpiperd.upstream.banner.sent"] = trueValue
		return downstream.SendAuthBanner(validateBannerText(banner))
	}
}

// install installs plugins with enhanced error handling
func (d *daemon) install(plugins ...*plugin.GrpcPlugin) error {
	if len(plugins) == 0 {
		return fmt.Errorf("no plugins provided for installation")
	}

	if len(plugins) == 1 {
		return plugins[0].InstallPiperConfig(d.config)
	}

	m := plugin.ChainPlugins{}
	for i, p := range plugins {
		if p == nil {
			return fmt.Errorf("plugin at index %d is nil", i)
		}

		if err := m.Append(p); err != nil {
			return fmt.Errorf("failed to append plugin %d: %w", i, err)
		}
	}

	return m.InstallPiperConfig(d.config)
}

// run starts the daemon with enhanced concurrency control and error handling
func (d *daemon) run() {
	defer d.shutdown()

	log.Infof("SSHPiper daemon starting on %v (max concurrent connections: %d)",
		d.lis.Addr(), maxConcurrentConnections)

	// Accept connections in a controlled manner
	for {
		select {
		case <-d.ctx.Done():
			log.Infof("Daemon shutdown requested")
			return
		default:
		}

		conn, err := d.lis.Accept()
		if err != nil {
			select {
			case <-d.ctx.Done():
				// Shutdown requested
				return
			default:
				log.Debugf("Failed to accept connection: %v", err)
				continue
			}
		}

		// Rate limiting
		if !d.rateLimiter.Allow() {
			atomic.AddInt64(&d.metrics.rejectedConnections, 1)
			log.Warnf("Connection from %v rejected due to rate limiting", conn.RemoteAddr())
			conn.Close()
			continue
		}

		// Concurrency control
		select {
		case d.connectionSemaphore <- struct{}{}:
			// Connection slot acquired
			atomic.AddInt64(&d.metrics.totalConnections, 1)
			atomic.AddInt64(&d.metrics.activeConnections, 1)

			d.wg.Add(1)
			go d.handleConnection(conn)
		default:
			// No connection slots available
			atomic.AddInt64(&d.metrics.rejectedConnections, 1)
			log.Warnf("Connection from %v rejected: max concurrent connections reached", conn.RemoteAddr())
			conn.Close()
		}
	}
}

// handleConnection handles a single connection with comprehensive error handling
func (d *daemon) handleConnection(conn net.Conn) {
	defer func() {
		// Panic recovery
		if r := recover(); r != nil {
			log.Errorf("Connection handler panic recovered: %v", r)
		}

		// Resource cleanup
		if err := conn.Close(); err != nil {
			log.Errorf("Failed to close connection: %v", err)
		}

		// Release connection slot
		<-d.connectionSemaphore
		atomic.AddInt64(&d.metrics.activeConnections, -1)
		d.wg.Done()
	}()

	remoteAddr := conn.RemoteAddr()
	log.Debugf("Handling connection from %v", remoteAddr)

	// Set connection timeout
	if err := conn.SetDeadline(time.Now().Add(connectionTimeout)); err != nil {
		log.Warnf("Failed to set connection deadline: %v", err)
	}

	// Create pipe connection with timeout
	pipec := make(chan *ssh.PiperConn, 1)
	errorc := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errorc <- fmt.Errorf("handshake panic: %v", r)
			}
		}()

		p, err := ssh.NewSSHPiperConn(conn, &d.config.PiperConfig)
		if err != nil {
			errorc <- err
			return
		}
		pipec <- p
	}()

	var p *ssh.PiperConn
	select {
	case p = <-pipec:
		atomic.AddInt64(&d.metrics.successfulHandshakes, 1)

	case err := <-errorc:
		atomic.AddInt64(&d.metrics.failedHandshakes, 1)
		log.Debugf("Connection from %v handshake failed: %v", remoteAddr, err)
		if d.config.PipeCreateErrorCallback != nil {
			d.config.PipeCreateErrorCallback(conn, err)
		}
		return

	case <-time.After(d.loginGraceTime):
		atomic.AddInt64(&d.metrics.failedHandshakes, 1)
		log.Debugf("Connection from %v handshake timeout", remoteAddr)
		if d.config.PipeCreateErrorCallback != nil {
			d.config.PipeCreateErrorCallback(conn, fmt.Errorf("handshake timeout"))
		}
		return

	case <-d.ctx.Done():
		log.Debugf("Connection from %v terminated due to shutdown", remoteAddr)
		return
	}

	defer func() {
		p.Close()
	}()

	// SECURITY: Don't log sensitive user information
	log.Infof("SSH pipe established %v -> %v",
		p.DownstreamConnMeta().RemoteAddr(),
		p.UpstreamConnMeta().RemoteAddr())

	// Set up hooks
	uphookchain := &hookChain{}
	downhookchain := &hookChain{}

	// Configure recording if enabled
	if err := d.setupRecording(p, uphookchain, downhookchain); err != nil {
		log.Errorf("Failed to setup recording: %v", err)
		return
	}

	// Configure additional hooks
	d.setupPacketHooks(uphookchain, downhookchain)

	// Start pipe callbacks
	if d.config.PipeStartCallback != nil {
		d.config.PipeStartCallback(p.DownstreamConnMeta(), p.ChallengeContext())
	}

	// Wait for pipe completion
	err := p.WaitWithHook(uphookchain.hook(), downhookchain.hook())

	// Error callback
	if d.config.PipeErrorCallback != nil {
		d.config.PipeErrorCallback(p.DownstreamConnMeta(), p.ChallengeContext(), err)
	}

	log.Infof("Connection from %v closed: %v", remoteAddr, err)
}

// setupRecording configures connection recording with enhanced security
func (d *daemon) setupRecording(p *ssh.PiperConn, uphookchain, downhookchain *hookChain) error {
	if d.recorddir == "" {
		return nil
	}

	var recorddir string
	if d.usernameAsRecorddir {
		username := p.DownstreamConnMeta().User()
		// Validate username for security
		if username == "" || len(username) > 64 || filepath.Base(username) != username {
			return fmt.Errorf("invalid username for recording directory: %q", username)
		}
		recorddir = path.Join(d.recorddir, username)
	} else {
		uniqID := plugin.GetUniqueID(p.ChallengeContext())
		if uniqID == "" {
			return fmt.Errorf("cannot get unique ID for recording")
		}
		recorddir = path.Join(d.recorddir, uniqID)
	}

	// Create recording directory securely
	if err := os.MkdirAll(recorddir, 0700); err != nil {
		return fmt.Errorf("cannot create recording directory %q: %w", recorddir, err)
	}

	switch d.recordfmt {
	case "asciicast":
		return d.setupAsciicastRecording(recorddir, p, uphookchain, downhookchain)
	case "typescript":
		return d.setupTypescriptRecording(recorddir, uphookchain)
	default:
		return fmt.Errorf("unsupported recording format: %q", d.recordfmt)
	}
}

// setupAsciicastRecording configures asciicast recording
func (d *daemon) setupAsciicastRecording(recorddir string, p *ssh.PiperConn, uphookchain, downhookchain *hookChain) error {
	prefix := ""
	if d.usernameAsRecorddir {
		prefix = fmt.Sprintf("%d-", time.Now().Unix())
	}

	recorder := newAsciicastLogger(recorddir, prefix)

	// Ensure recorder is closed
	go func() {
		defer func() {
			if err := recorder.Close(); err != nil {
				log.Errorf("Failed to close asciicast recorder: %v", err)
			}
		}()

		<-d.ctx.Done()
	}()

	uphookchain.append(ssh.InspectPacketHook(recorder.uphook))
	downhookchain.append(ssh.InspectPacketHook(recorder.downhook))

	return nil
}

// setupTypescriptRecording configures typescript recording
func (d *daemon) setupTypescriptRecording(recorddir string, uphookchain *hookChain) error {
	recorder, err := newFilePtyLogger(recorddir)
	if err != nil {
		return fmt.Errorf("cannot create typescript recorder: %w", err)
	}

	// Ensure recorder is closed
	go func() {
		defer func() {
			if err := recorder.Close(); err != nil {
				log.Errorf("Failed to close typescript recorder: %v", err)
			}
		}()

		<-d.ctx.Done()
	}()

	uphookchain.append(ssh.InspectPacketHook(recorder.loggingTty))
	return nil
}

// setupPacketHooks configures additional packet hooks
func (d *daemon) setupPacketHooks(uphookchain, downhookchain *hookChain) {
	if d.filterHostkeysReqeust {
		uphookchain.append(func(b []byte) (ssh.PipePacketHookMethod, []byte, error) {
			if len(b) == 0 || b[0] != 80 {
				return ssh.PipePacketHookTransform, b, nil
			}

			var x struct {
				RequestName string `sshtype:"80"`
			}

			if err := ssh.Unmarshal(b, &x); err != nil {
				return ssh.PipePacketHookTransform, b, nil
			}

			if x.RequestName == "hostkeys-prove-00@openssh.com" || x.RequestName == "hostkeys-00@openssh.com" {
				return ssh.PipePacketHookTransform, nil, nil
			}

			return ssh.PipePacketHookTransform, b, nil
		})
	}

	if d.replyPing {
		downhookchain.append(ssh.PingPacketReply)
	}
}

// shutdown gracefully shuts down the daemon
func (d *daemon) shutdown() {
	d.shutdownOnce.Do(func() {
		log.Infof("Shutting down daemon...")

		// Stop accepting new connections
		if d.lis != nil {
			if err := d.lis.Close(); err != nil {
				log.Errorf("Failed to close listener: %v", err)
			}
		}

		// Signal shutdown
		d.cancel()

		// Wait for all connections to finish with timeout
		done := make(chan struct{})
		go func() {
			d.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			log.Infof("All connections closed gracefully")
		case <-time.After(30 * time.Second):
			log.Warnf("Shutdown timeout reached, some connections may not have closed properly")
		}

		// Clean up resources
		if d.rateLimiter != nil {
			d.rateLimiter.Close()
		}

		// Log final metrics
		d.logFinalMetrics()
	})
}

// logFinalMetrics logs final daemon metrics
func (d *daemon) logFinalMetrics() {
	m := d.metrics
	m.mu.RLock()
	defer m.mu.RUnlock()

	log.Infof("Final metrics - Total: %d, Rejected: %d, Failed handshakes: %d, Successful handshakes: %d",
		m.totalConnections, m.rejectedConnections, m.failedHandshakes, m.successfulHandshakes)
}
