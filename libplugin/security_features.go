package libplugin

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// SimpleRateLimiter provides basic rate limiting functionality
type SimpleRateLimiter struct {
	requests     []time.Time
	maxRequests  int
	window       time.Duration
	mutex        sync.Mutex
}

// NewSimpleRateLimiter creates a new simple rate limiter
func NewSimpleRateLimiter(maxRequests int, window time.Duration) *SimpleRateLimiter {
	return &SimpleRateLimiter{
		requests:    make([]time.Time, 0),
		maxRequests: maxRequests,
		window:      window,
	}
}

// Allow checks if a request is allowed under the rate limit
func (rl *SimpleRateLimiter) Allow() bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	now := time.Now()
	cutoff := now.Add(-rl.window)
	
	// Remove old requests outside the window
	validRequests := make([]time.Time, 0)
	for _, reqTime := range rl.requests {
		if reqTime.After(cutoff) {
			validRequests = append(validRequests, reqTime)
		}
	}
	rl.requests = validRequests
	
	// Check if we can allow this request
	if len(rl.requests) >= rl.maxRequests {
		return false
	}
	
	// Add this request
	rl.requests = append(rl.requests, now)
	return true
}

// SecurityManager manages advanced security features
type SecurityManager struct {
	// Configuration
	config          AdvancedSecurityConfig
	
	// Rate limiting
	rateLimiters    map[string]*SimpleRateLimiter
	rateMutex       sync.RWMutex
	
	// Intrusion detection
	intrusionDetector *IntrusionDetector
	
	// IP management
	bannedIPs       map[string]BannedIPInfo
	suspiciousIPs   map[string]SuspiciousIPInfo
	ipMutex         sync.RWMutex
	
	// Authentication tracking
	authAttempts    map[string]AuthAttemptInfo
	authMutex       sync.RWMutex
	
	// Observability integration
	observability   *ObservabilityManager
	logger          *StandardLogger
	
	// Context and lifecycle
	ctx             context.Context
	cancel          context.CancelFunc
	enabled         bool
}

// AdvancedSecurityConfig configures the security manager with advanced features  
type AdvancedSecurityConfig struct {
	// Global settings
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	
	// Rate limiting configuration
	RateLimit             AdvancedRateLimitConfig `yaml:"rate_limit" json:"rate_limit"`
	
	// Intrusion detection configuration
	IntrusionDetection    IntrusionConfig `yaml:"intrusion_detection" json:"intrusion_detection"`
	
	// IP filtering configuration
	IPFiltering           IPFilteringConfig `yaml:"ip_filtering" json:"ip_filtering"`
	
	// Authentication security
	AuthSecurity          AuthSecurityConfig `yaml:"auth_security" json:"auth_security"`
	
	// Monitoring and alerting
	Monitoring            SecurityMonitoringConfig `yaml:"monitoring" json:"monitoring"`
}

// AdvancedRateLimitConfig configures advanced rate limiting
type AdvancedRateLimitConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	
	// Global rate limits
	GlobalRequestsPerSecond int         `yaml:"global_requests_per_second" json:"global_requests_per_second"`
	GlobalBurstSize       int           `yaml:"global_burst_size" json:"global_burst_size"`
	
	// Per-IP rate limits
	PerIPRequestsPerSecond int          `yaml:"per_ip_requests_per_second" json:"per_ip_requests_per_second"`
	PerIPBurstSize        int           `yaml:"per_ip_burst_size" json:"per_ip_burst_size"`
	
	// Per-user rate limits
	PerUserRequestsPerSecond int        `yaml:"per_user_requests_per_second" json:"per_user_requests_per_second"`
	PerUserBurstSize      int           `yaml:"per_user_burst_size" json:"per_user_burst_size"`
	
	// Cleanup intervals
	CleanupInterval       time.Duration `yaml:"cleanup_interval" json:"cleanup_interval"`
	InactiveTimeout       time.Duration `yaml:"inactive_timeout" json:"inactive_timeout"`
}

// IntrusionConfig configures intrusion detection
type IntrusionConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	
	// Failure thresholds
	MaxFailureAttempts    int           `yaml:"max_failure_attempts" json:"max_failure_attempts"`
	FailureWindow         time.Duration `yaml:"failure_window" json:"failure_window"`
	
	// Suspicious activity detection
	SuspiciousThreshold   int           `yaml:"suspicious_threshold" json:"suspicious_threshold"`
	SuspiciousWindow      time.Duration `yaml:"suspicious_window" json:"suspicious_window"`
	
	// Automatic response
	AutoBan               bool          `yaml:"auto_ban" json:"auto_ban"`
	BanDuration           time.Duration `yaml:"ban_duration" json:"ban_duration"`
	EscalationEnabled     bool          `yaml:"escalation_enabled" json:"escalation_enabled"`
	
	// Pattern detection
	PatternDetection      PatternDetectionConfig `yaml:"pattern_detection" json:"pattern_detection"`
}

// PatternDetectionConfig configures attack pattern detection
type PatternDetectionConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	BruteForceDetection   bool          `yaml:"brute_force_detection" json:"brute_force_detection"`
	DictionaryAttackDetection bool      `yaml:"dictionary_attack_detection" json:"dictionary_attack_detection"`
	ScanningDetection     bool          `yaml:"scanning_detection" json:"scanning_detection"`
	
	// Pattern thresholds
	BruteForceThreshold   int           `yaml:"brute_force_threshold" json:"brute_force_threshold"`
	DictionaryThreshold   int           `yaml:"dictionary_threshold" json:"dictionary_threshold"`
	ScanningThreshold     int           `yaml:"scanning_threshold" json:"scanning_threshold"`
	
	// Time windows
	BruteForceWindow      time.Duration `yaml:"brute_force_window" json:"brute_force_window"`
	DictionaryWindow      time.Duration `yaml:"dictionary_window" json:"dictionary_window"`
	ScanningWindow        time.Duration `yaml:"scanning_window" json:"scanning_window"`
}

// IPFilteringConfig configures IP-based filtering
type IPFilteringConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	
	// Whitelist/blacklist
	Whitelist             []string      `yaml:"whitelist" json:"whitelist"`
	Blacklist             []string      `yaml:"blacklist" json:"blacklist"`
	
	// Geographic filtering
	GeoFiltering          GeoFilteringConfig `yaml:"geo_filtering" json:"geo_filtering"`
	
	// Dynamic IP management
	DynamicFiltering      DynamicFilteringConfig `yaml:"dynamic_filtering" json:"dynamic_filtering"`
}

// GeoFilteringConfig configures geographic IP filtering
type GeoFilteringConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	AllowedCountries      []string      `yaml:"allowed_countries" json:"allowed_countries"`
	BlockedCountries      []string      `yaml:"blocked_countries" json:"blocked_countries"`
	AllowPrivateIPs       bool          `yaml:"allow_private_ips" json:"allow_private_ips"`
	AllowLocalhost        bool          `yaml:"allow_localhost" json:"allow_localhost"`
}

// DynamicFilteringConfig configures dynamic IP filtering
type DynamicFilteringConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	AutoWhitelist         bool          `yaml:"auto_whitelist" json:"auto_whitelist"`
	WhitelistThreshold    int           `yaml:"whitelist_threshold" json:"whitelist_threshold"`
	WhitelistDuration     time.Duration `yaml:"whitelist_duration" json:"whitelist_duration"`
}

// AuthSecurityConfig configures authentication security
type AuthSecurityConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	
	// Password security
	PasswordComplexity    PasswordComplexityConfig `yaml:"password_complexity" json:"password_complexity"`
	
	// Account lockout
	AccountLockout        AccountLockoutConfig `yaml:"account_lockout" json:"account_lockout"`
	
	// Session security
	SessionSecurity       SessionSecurityConfig `yaml:"session_security" json:"session_security"`
	
	// Multi-factor authentication
	MFA                   MFAConfig     `yaml:"mfa" json:"mfa"`
}

// PasswordComplexityConfig configures password complexity requirements
type PasswordComplexityConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	MinLength             int           `yaml:"min_length" json:"min_length"`
	RequireUppercase      bool          `yaml:"require_uppercase" json:"require_uppercase"`
	RequireLowercase      bool          `yaml:"require_lowercase" json:"require_lowercase"`
	RequireNumbers        bool          `yaml:"require_numbers" json:"require_numbers"`
	RequireSpecialChars   bool          `yaml:"require_special_chars" json:"require_special_chars"`
	ForbiddenPatterns     []string      `yaml:"forbidden_patterns" json:"forbidden_patterns"`
}

// AccountLockoutConfig configures account lockout policies
type AccountLockoutConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	MaxAttempts           int           `yaml:"max_attempts" json:"max_attempts"`
	LockoutDuration       time.Duration `yaml:"lockout_duration" json:"lockout_duration"`
	ResetOnSuccess        bool          `yaml:"reset_on_success" json:"reset_on_success"`
}

// SessionSecurityConfig configures session security
type SessionSecurityConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	MaxSessionDuration    time.Duration `yaml:"max_session_duration" json:"max_session_duration"`
	IdleTimeout           time.Duration `yaml:"idle_timeout" json:"idle_timeout"`
	MaxConcurrentSessions int           `yaml:"max_concurrent_sessions" json:"max_concurrent_sessions"`
	SessionValidation     bool          `yaml:"session_validation" json:"session_validation"`
}

// MFAConfig configures multi-factor authentication
type MFAConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	RequiredForAdmin      bool          `yaml:"required_for_admin" json:"required_for_admin"`
	RequiredForRemote     bool          `yaml:"required_for_remote" json:"required_for_remote"`
	TOTPEnabled           bool          `yaml:"totp_enabled" json:"totp_enabled"`
	SMSEnabled            bool          `yaml:"sms_enabled" json:"sms_enabled"`
	EmailEnabled          bool          `yaml:"email_enabled" json:"email_enabled"`
}

// SecurityMonitoringConfig configures security monitoring
type SecurityMonitoringConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	LogLevel              string        `yaml:"log_level" json:"log_level"`
	AlertingEnabled       bool          `yaml:"alerting_enabled" json:"alerting_enabled"`
	
	// Metrics collection
	MetricsEnabled        bool          `yaml:"metrics_enabled" json:"metrics_enabled"`
	MetricsInterval       time.Duration `yaml:"metrics_interval" json:"metrics_interval"`
	
	// Event logging
	EventLogging          EventLoggingConfig `yaml:"event_logging" json:"event_logging"`
}

// EventLoggingConfig configures security event logging
type EventLoggingConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	LogAuthAttempts       bool          `yaml:"log_auth_attempts" json:"log_auth_attempts"`
	LogConnectionEvents   bool          `yaml:"log_connection_events" json:"log_connection_events"`
	LogSecurityEvents     bool          `yaml:"log_security_events" json:"log_security_events"`
	LogAdminActions       bool          `yaml:"log_admin_actions" json:"log_admin_actions"`
	FormatJSON            bool          `yaml:"format_json" json:"format_json"`
}

// BannedIPInfo tracks information about banned IPs
type BannedIPInfo struct {
	IP                    string        `json:"ip"`
	BannedAt              time.Time     `json:"banned_at"`
	ExpiresAt             time.Time     `json:"expires_at"`
	Reason                string        `json:"reason"`
	FailureCount          int           `json:"failure_count"`
	LastActivity          time.Time     `json:"last_activity"`
	AutoBanned            bool          `json:"auto_banned"`
}

// SuspiciousIPInfo tracks information about suspicious IPs
type SuspiciousIPInfo struct {
	IP                    string        `json:"ip"`
	FirstSeen             time.Time     `json:"first_seen"`
	LastSeen              time.Time     `json:"last_seen"`
	FailureCount          int           `json:"failure_count"`
	SuspiciousPatterns    []string      `json:"suspicious_patterns"`
	ThreatLevel           ThreatLevel   `json:"threat_level"`
}

// AuthAttemptInfo tracks authentication attempts
type AuthAttemptInfo struct {
	Username              string        `json:"username"`
	IP                    string        `json:"ip"`
	Timestamp             time.Time     `json:"timestamp"`
	Success               bool          `json:"success"`
	FailureReason         string        `json:"failure_reason,omitempty"`
	UserAgent             string        `json:"user_agent,omitempty"`
}

// ThreatLevel represents the threat level of an IP
type ThreatLevel string

const (
	ThreatLevelLow      ThreatLevel = "low"
	ThreatLevelMedium   ThreatLevel = "medium"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelCritical ThreatLevel = "critical"
)

// IntrusionDetector provides intrusion detection capabilities
type IntrusionDetector struct {
	config              IntrusionConfig
	attackPatterns      map[string]*AttackPattern
	mutex               sync.RWMutex
	logger              *StandardLogger
	observability       *ObservabilityManager
}

// AttackPattern tracks patterns of attacks
type AttackPattern struct {
	PatternType         string        `json:"pattern_type"`
	IP                  string        `json:"ip"`
	FirstDetected       time.Time     `json:"first_detected"`
	LastDetected        time.Time     `json:"last_detected"`
	EventCount          int           `json:"event_count"`
	Severity            ThreatLevel   `json:"severity"`
	Blocked             bool          `json:"blocked"`
}

// NewSecurityManager creates a new security manager
func NewSecurityManager(config AdvancedSecurityConfig, observability *ObservabilityManager) (*SecurityManager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	logger := NewStandardLogger("security")
	
	// Create intrusion detector
	intrusionDetector := &IntrusionDetector{
		config:         config.IntrusionDetection,
		attackPatterns: make(map[string]*AttackPattern),
		logger:         logger,
		observability:  observability,
	}
	
	sm := &SecurityManager{
		config:            config,
		rateLimiters:      make(map[string]*SimpleRateLimiter),
		intrusionDetector: intrusionDetector,
		bannedIPs:         make(map[string]BannedIPInfo),
		suspiciousIPs:     make(map[string]SuspiciousIPInfo),
		authAttempts:      make(map[string]AuthAttemptInfo),
		observability:     observability,
		logger:            logger,
		ctx:               ctx,
		cancel:            cancel,
		enabled:           config.Enabled,
	}
	
	if !config.Enabled {
		logger.Info("security manager disabled by configuration")
		return sm, nil
	}
	
	logger.Info("security manager initialized", log.Fields{
		"rate_limit_enabled":      config.RateLimit.Enabled,
		"intrusion_detection":     config.IntrusionDetection.Enabled,
		"ip_filtering_enabled":    config.IPFiltering.Enabled,
		"auth_security_enabled":   config.AuthSecurity.Enabled,
	})
	
	return sm, nil
}

// Start begins security monitoring and enforcement
func (sm *SecurityManager) Start() error {
	if !sm.enabled {
		return nil
	}
	
	sm.logger.Info("starting security manager")
	
	// Start cleanup goroutines
	if sm.config.RateLimit.Enabled {
		go sm.cleanupRateLimiters()
	}
	
	if sm.config.IntrusionDetection.Enabled {
		go sm.monitorIntrusionPatterns()
	}
	
	go sm.cleanupExpiredBans()
	
	sm.logger.Info("security manager started successfully")
	return nil
}

// Stop gracefully shuts down the security manager
func (sm *SecurityManager) Stop() error {
	if !sm.enabled {
		return nil
	}
	
	sm.logger.Info("stopping security manager")
	sm.cancel()
	sm.logger.Info("security manager stopped")
	return nil
}

// CheckRateLimit checks if a request should be rate limited
func (sm *SecurityManager) CheckRateLimit(ctx context.Context, identifier string, rateLimitType string) (bool, error) {
	if !sm.enabled || !sm.config.RateLimit.Enabled {
		return true, nil
	}
	
	sm.rateMutex.Lock()
	defer sm.rateMutex.Unlock()
	
	limiter, exists := sm.rateLimiters[identifier]
	if !exists {
		var maxRequests int
		var window time.Duration = 1 * time.Second
		
		switch rateLimitType {
		case "ip":
			maxRequests = sm.config.RateLimit.PerIPRequestsPerSecond
		case "user":
			maxRequests = sm.config.RateLimit.PerUserRequestsPerSecond
		case "global":
			maxRequests = sm.config.RateLimit.GlobalRequestsPerSecond
		default:
			return true, nil
		}
		
		limiter = NewSimpleRateLimiter(maxRequests, window)
		sm.rateLimiters[identifier] = limiter
	}
	
	allowed := limiter.Allow()
	
	if !allowed {
		sm.observability.RecordSecurityEvent(ctx, "rate_limit_exceeded",
			String("identifier", identifier),
			String("type", rateLimitType),
		)
		
		sm.logger.Warn("rate limit exceeded", log.Fields{
			"identifier": identifier,
			"type":       rateLimitType,
		})
	}
	
	return allowed, nil
}

// CheckIPAllowed checks if an IP address is allowed
func (sm *SecurityManager) CheckIPAllowed(ctx context.Context, ip string) (bool, string) {
	if !sm.enabled || !sm.config.IPFiltering.Enabled {
		return true, ""
	}
	
	// Check if IP is banned
	sm.ipMutex.RLock()
	if banInfo, exists := sm.bannedIPs[ip]; exists {
		sm.ipMutex.RUnlock()
		
		if time.Now().Before(banInfo.ExpiresAt) {
			sm.observability.RecordSecurityEvent(ctx, "blocked_banned_ip",
				String("ip", ip),
				String("reason", banInfo.Reason),
			)
			return false, fmt.Sprintf("IP banned: %s", banInfo.Reason)
		}
		
		// Ban expired, remove it
		sm.ipMutex.Lock()
		delete(sm.bannedIPs, ip)
		sm.ipMutex.Unlock()
		sm.observability.RecordSecurityEvent(ctx, "unban_ip",
			String("ip", ip),
			String("reason", "expired"),
		)
	} else {
		sm.ipMutex.RUnlock()
	}
	
	// Check blacklist
	for _, blacklistedIP := range sm.config.IPFiltering.Blacklist {
		if sm.matchIPPattern(ip, blacklistedIP) {
			sm.observability.RecordSecurityEvent(ctx, "blocked_blacklisted_ip",
				String("ip", ip),
			)
			return false, "IP in blacklist"
		}
	}
	
	// Check whitelist (if not empty, only whitelisted IPs are allowed)
	if len(sm.config.IPFiltering.Whitelist) > 0 {
		whitelisted := false
		for _, whitelistedIP := range sm.config.IPFiltering.Whitelist {
			if sm.matchIPPattern(ip, whitelistedIP) {
				whitelisted = true
				break
			}
		}
		
		if !whitelisted {
			sm.observability.RecordSecurityEvent(ctx, "blocked_not_whitelisted",
				String("ip", ip),
			)
			return false, "IP not in whitelist"
		}
	}
	
	return true, ""
}

// RecordAuthAttempt records an authentication attempt
func (sm *SecurityManager) RecordAuthAttempt(ctx context.Context, username, ip string, success bool, failureReason string) {
	if !sm.enabled {
		return
	}
	
	attemptInfo := AuthAttemptInfo{
		Username:      username,
		IP:            ip,
		Timestamp:     time.Now(),
		Success:       success,
		FailureReason: failureReason,
	}
	
	sm.authMutex.Lock()
	sm.authAttempts[fmt.Sprintf("%s_%s_%d", ip, username, time.Now().Unix())] = attemptInfo
	sm.authMutex.Unlock()
	
	// Record observability metrics
	if success {
		sm.observability.RecordSecurityEvent(ctx, "auth_attempt",
			String("username", username),
			String("ip", ip),
			Bool("success", true),
		)
	} else {
		sm.observability.RecordSecurityEvent(ctx, "auth_failure",
			String("username", username),
			String("ip", ip),
			String("reason", failureReason),
		)
		
		// Check for intrusion patterns
		if sm.config.IntrusionDetection.Enabled {
			sm.checkIntrusionPatterns(ctx, ip, username, failureReason)
		}
	}
	
	// Log event
	if sm.config.Monitoring.EventLogging.LogAuthAttempts {
		fields := log.Fields{
			"username": username,
			"ip":       ip,
			"success":  success,
		}
		if !success {
			fields["failure_reason"] = failureReason
		}
		
		if success {
			sm.logger.Info("authentication attempt", fields)
		} else {
			sm.logger.Warn("authentication failed", fields)
		}
	}
}

// checkIntrusionPatterns checks for intrusion patterns and takes action
func (sm *SecurityManager) checkIntrusionPatterns(ctx context.Context, ip, username, failureReason string) {
	// Count recent failures from this IP
	sm.authMutex.RLock()
	recentFailures := 0
	cutoff := time.Now().Add(-sm.config.IntrusionDetection.FailureWindow)
	
	for _, attempt := range sm.authAttempts {
		if attempt.IP == ip && !attempt.Success && attempt.Timestamp.After(cutoff) {
			recentFailures++
		}
	}
	sm.authMutex.RUnlock()
	
	// Check if threshold exceeded
	if recentFailures >= sm.config.IntrusionDetection.MaxFailureAttempts {
		sm.markSuspiciousIP(ctx, ip, "excessive_failures")
		
		if sm.config.IntrusionDetection.AutoBan {
			sm.banIP(ctx, ip, sm.config.IntrusionDetection.BanDuration, "automatic_ban_excessive_failures")
		}
	}
	
	// Check for specific attack patterns
	if sm.config.IntrusionDetection.PatternDetection.Enabled {
		sm.intrusionDetector.detectAttackPatterns(ctx, ip, username, failureReason)
	}
}

// markSuspiciousIP marks an IP as suspicious
func (sm *SecurityManager) markSuspiciousIP(ctx context.Context, ip, reason string) {
	sm.ipMutex.Lock()
	defer sm.ipMutex.Unlock()
	
	now := time.Now()
	if info, exists := sm.suspiciousIPs[ip]; exists {
		info.LastSeen = now
		info.FailureCount++
		info.SuspiciousPatterns = append(info.SuspiciousPatterns, reason)
		
		// Escalate threat level
		if info.FailureCount > 10 {
			info.ThreatLevel = ThreatLevelCritical
		} else if info.FailureCount > 5 {
			info.ThreatLevel = ThreatLevelHigh
		} else if info.FailureCount > 2 {
			info.ThreatLevel = ThreatLevelMedium
		}
		
		sm.suspiciousIPs[ip] = info
	} else {
		sm.suspiciousIPs[ip] = SuspiciousIPInfo{
			IP:                 ip,
			FirstSeen:          now,
			LastSeen:           now,
			FailureCount:       1,
			SuspiciousPatterns: []string{reason},
			ThreatLevel:        ThreatLevelLow,
		}
	}
	
	sm.observability.RecordSecurityEvent(ctx, "suspicious_ip",
		String("ip", ip),
		String("reason", reason),
	)
	
	sm.logger.Warn("suspicious IP detected", log.Fields{
		"ip":     ip,
		"reason": reason,
	})
}

// banIP bans an IP address
func (sm *SecurityManager) banIP(ctx context.Context, ip string, duration time.Duration, reason string) {
	sm.ipMutex.Lock()
	defer sm.ipMutex.Unlock()
	
	now := time.Now()
	banInfo := BannedIPInfo{
		IP:           ip,
		BannedAt:     now,
		ExpiresAt:    now.Add(duration),
		Reason:       reason,
		LastActivity: now,
		AutoBanned:   true,
	}
	
	// Update failure count if IP was suspicious
	if suspInfo, exists := sm.suspiciousIPs[ip]; exists {
		banInfo.FailureCount = suspInfo.FailureCount
	}
	
	sm.bannedIPs[ip] = banInfo
	
	sm.observability.RecordSecurityEvent(ctx, "ban_ip",
		String("ip", ip),
		String("reason", reason),
		String("duration", duration.String()),
	)
	
	sm.logger.Warn("IP banned", log.Fields{
		"ip":       ip,
		"reason":   reason,
		"duration": duration.String(),
		"expires":  banInfo.ExpiresAt,
	})
}

// detectAttackPatterns detects various attack patterns
func (id *IntrusionDetector) detectAttackPatterns(ctx context.Context, ip, username, failureReason string) {
	id.mutex.Lock()
	defer id.mutex.Unlock()
	
	// Brute force detection
	if id.config.PatternDetection.BruteForceDetection {
		id.detectBruteForce(ctx, ip, username)
	}
	
	// Dictionary attack detection
	if id.config.PatternDetection.DictionaryAttackDetection {
		id.detectDictionaryAttack(ctx, ip, username)
	}
	
	// Scanning detection
	if id.config.PatternDetection.ScanningDetection {
		id.detectScanning(ctx, ip)
	}
}

// detectBruteForce detects brute force attacks
func (id *IntrusionDetector) detectBruteForce(ctx context.Context, ip, username string) {
	patternKey := fmt.Sprintf("brute_force_%s_%s", ip, username)
	now := time.Now()
	
	if pattern, exists := id.attackPatterns[patternKey]; exists {
		if now.Sub(pattern.LastDetected) < id.config.PatternDetection.BruteForceWindow {
			pattern.EventCount++
			pattern.LastDetected = now
			
			if pattern.EventCount >= id.config.PatternDetection.BruteForceThreshold {
				pattern.Severity = ThreatLevelHigh
				id.logger.Warn("brute force attack detected", log.Fields{
					"ip":       ip,
					"username": username,
					"events":   pattern.EventCount,
				})
				
				id.observability.RecordSecurityEvent(ctx, "brute_force_detected",
					String("ip", ip),
					String("username", username),
					Int("event_count", pattern.EventCount),
				)
			}
		}
	} else {
		id.attackPatterns[patternKey] = &AttackPattern{
			PatternType:   "brute_force",
			IP:            ip,
			FirstDetected: now,
			LastDetected:  now,
			EventCount:    1,
			Severity:      ThreatLevelLow,
		}
	}
}

// detectDictionaryAttack detects dictionary attacks
func (id *IntrusionDetector) detectDictionaryAttack(ctx context.Context, ip, username string) {
	patternKey := fmt.Sprintf("dictionary_%s", ip)
	now := time.Now()
	
	if pattern, exists := id.attackPatterns[patternKey]; exists {
		if now.Sub(pattern.LastDetected) < id.config.PatternDetection.DictionaryWindow {
			pattern.EventCount++
			pattern.LastDetected = now
			
			if pattern.EventCount >= id.config.PatternDetection.DictionaryThreshold {
				pattern.Severity = ThreatLevelHigh
				id.logger.Warn("dictionary attack detected", log.Fields{
					"ip":     ip,
					"events": pattern.EventCount,
				})
				
				id.observability.RecordSecurityEvent(ctx, "dictionary_attack_detected",
					String("ip", ip),
					Int("event_count", pattern.EventCount),
				)
			}
		}
	} else {
		id.attackPatterns[patternKey] = &AttackPattern{
			PatternType:   "dictionary",
			IP:            ip,
			FirstDetected: now,
			LastDetected:  now,
			EventCount:    1,
			Severity:      ThreatLevelLow,
		}
	}
}

// detectScanning detects scanning activities
func (id *IntrusionDetector) detectScanning(ctx context.Context, ip string) {
	patternKey := fmt.Sprintf("scanning_%s", ip)
	now := time.Now()
	
	if pattern, exists := id.attackPatterns[patternKey]; exists {
		if now.Sub(pattern.LastDetected) < id.config.PatternDetection.ScanningWindow {
			pattern.EventCount++
			pattern.LastDetected = now
			
			if pattern.EventCount >= id.config.PatternDetection.ScanningThreshold {
				pattern.Severity = ThreatLevelMedium
				id.logger.Warn("scanning activity detected", log.Fields{
					"ip":     ip,
					"events": pattern.EventCount,
				})
				
				id.observability.RecordSecurityEvent(ctx, "scanning_detected",
					String("ip", ip),
					Int("event_count", pattern.EventCount),
				)
			}
		}
	} else {
		id.attackPatterns[patternKey] = &AttackPattern{
			PatternType:   "scanning",
			IP:            ip,
			FirstDetected: now,
			LastDetected:  now,
			EventCount:    1,
			Severity:      ThreatLevelLow,
		}
	}
}

// matchIPPattern checks if an IP matches a pattern (supports CIDR)
func (sm *SecurityManager) matchIPPattern(ip, pattern string) bool {
	// Direct match
	if ip == pattern {
		return true
	}
	
	// CIDR match
	if strings.Contains(pattern, "/") {
		_, cidr, err := net.ParseCIDR(pattern)
		if err != nil {
			return false
		}
		
		ipAddr := net.ParseIP(ip)
		if ipAddr == nil {
			return false
		}
		
		return cidr.Contains(ipAddr)
	}
	
	return false
}

// cleanupRateLimiters removes inactive rate limiters
func (sm *SecurityManager) cleanupRateLimiters() {
	ticker := time.NewTicker(sm.config.RateLimit.CleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sm.rateMutex.Lock()
			// In a real implementation, we'd track last access time
			// For now, we'll clean up periodically based on configuration
			sm.rateMutex.Unlock()
		case <-sm.ctx.Done():
			return
		}
	}
}

// monitorIntrusionPatterns monitors and cleans up intrusion patterns
func (sm *SecurityManager) monitorIntrusionPatterns() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sm.intrusionDetector.cleanupExpiredPatterns()
		case <-sm.ctx.Done():
			return
		}
	}
}

// cleanupExpiredPatterns removes expired attack patterns
func (id *IntrusionDetector) cleanupExpiredPatterns() {
	id.mutex.Lock()
	defer id.mutex.Unlock()
	
	now := time.Now()
	for key, pattern := range id.attackPatterns {
		var window time.Duration
		
		switch pattern.PatternType {
		case "brute_force":
			window = id.config.PatternDetection.BruteForceWindow
		case "dictionary":
			window = id.config.PatternDetection.DictionaryWindow
		case "scanning":
			window = id.config.PatternDetection.ScanningWindow
		default:
			window = 1 * time.Hour
		}
		
		if now.Sub(pattern.LastDetected) > window {
			delete(id.attackPatterns, key)
		}
	}
}

// cleanupExpiredBans removes expired IP bans
func (sm *SecurityManager) cleanupExpiredBans() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sm.ipMutex.Lock()
			now := time.Now()
			for ip, banInfo := range sm.bannedIPs {
				if now.After(banInfo.ExpiresAt) {
					delete(sm.bannedIPs, ip)
					sm.observability.RecordSecurityEvent(context.Background(), "unban_ip",
						String("ip", ip),
						String("reason", "expired"),
					)
					sm.logger.Info("IP ban expired", log.Fields{"ip": ip})
				}
			}
			sm.ipMutex.Unlock()
		case <-sm.ctx.Done():
			return
		}
	}
}

// GetSecurityStatus returns current security status
func (sm *SecurityManager) GetSecurityStatus() map[string]interface{} {
	if !sm.enabled {
		return map[string]interface{}{
			"enabled": false,
		}
	}
	
	sm.ipMutex.RLock()
	bannedCount := len(sm.bannedIPs)
	suspiciousCount := len(sm.suspiciousIPs)
	sm.ipMutex.RUnlock()
	
	sm.rateMutex.RLock()
	rateLimiterCount := len(sm.rateLimiters)
	sm.rateMutex.RUnlock()
	
	sm.intrusionDetector.mutex.RLock()
	attackPatternCount := len(sm.intrusionDetector.attackPatterns)
	sm.intrusionDetector.mutex.RUnlock()
	
	return map[string]interface{}{
		"enabled":              true,
		"banned_ips":           bannedCount,
		"suspicious_ips":       suspiciousCount,
		"active_rate_limiters": rateLimiterCount,
		"attack_patterns":      attackPatternCount,
		"features": map[string]bool{
			"rate_limiting":       sm.config.RateLimit.Enabled,
			"intrusion_detection": sm.config.IntrusionDetection.Enabled,
			"ip_filtering":        sm.config.IPFiltering.Enabled,
			"auth_security":       sm.config.AuthSecurity.Enabled,
		},
	}
}