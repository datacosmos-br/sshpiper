// Package libplugin provides HTTP and JWT utility functions for plugins.
//
// This file contains:
//   - DoJSONRequest: Helper for making HTTP requests with JSON bodies and parsing JSON responses
//   - DecodeJWTClaims: Helper for parsing JWT tokens and extracting claims
//
// These helpers are used by plugins that need to interact with HTTP APIs or parse JWT tokens for authentication/authorization.
//
// Example usage:
//
//	err := DoJSONRequest(ctx, client, "POST", url, req, &resp, headers)
//	claims, err := DecodeJWTClaims(token)
package libplugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"net/netip"

	gocache "github.com/patrickmn/go-cache"
	"go4.org/netipx"
)

// DoJSONRequest performs an HTTP request with a JSON body and decodes the JSON response into respBody.
//
// Example usage:
//
//	err := DoJSONRequest(ctx, client, "POST", url, req, &resp, headers)
//
// If reqBody is nil, no body is sent. If respBody is nil, the response is ignored.
// Returns an error if the request fails, the response is not 2xx, or JSON decoding fails.
// Security: Does not verify TLS certificates if client is misconfigured. Use with care for sensitive data.
func DoJSONRequest(ctx context.Context, client *http.Client, method, url string, reqBody, respBody interface{}, headers map[string]string) error {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		body = bytes.NewReader(b)
	}
	if method == "" {
		return fmt.Errorf("method must not be empty")
	}
	if url == "" {
		return fmt.Errorf("url must not be empty")
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http error: %s", resp.Status)
	}
	if respBody != nil {
		return json.NewDecoder(resp.Body).Decode(respBody)
	}
	return nil
}

// DecodeJWTClaims parses a JWT and returns its claims as a map[string]interface{}.
//
// Example usage:
//
//	claims, err := DecodeJWTClaims(token)
//
// Returns an error if the token is not a valid JWT or claims cannot be decoded.
// Security: Does not verify JWT signature or issuer. Use only for non-security-critical inspection.
func DecodeJWTClaims(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal JWT claims: %w", err)
	}
	return claims, nil
}

// BuildIPSet constructs a netipx.IPSet from a slice of CIDR or IP strings.
// Returns a pointer to the set, or nil if input is empty or all parse errors.
// Example:
//
//	ipset := libplugin.BuildIPSet([]string{"192.168.1.0/24", "10.0.0.1"})
func BuildIPSet(cidrs []string) *netipx.IPSet {
	var ipsetBuilder netipx.IPSetBuilder
	for _, cidr := range cidrs {
		if strings.Contains(cidr, "/") {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			ipsetBuilder.AddPrefix(prefix)
		} else {
			ip, err := netip.ParseAddr(cidr)
			if err != nil {
				continue
			}
			ipsetBuilder.Add(ip)
		}
	}
	ipset, err := ipsetBuilder.IPSet()
	if err != nil {
		return nil
	}
	return ipset
}

// BanCache provides a concurrency-safe, in-memory ban tracker for IP addresses.
// It wraps github.com/patrickmn/go-cache and supports ban duration, increment, check, and flush.
type BanCache struct {
	cache       *gocache.Cache
	banDuration time.Duration
	maxFailures int
}

// NewBanCache creates a new BanCache with the given ban duration and max failures.
// Example:
//
//	bc := libplugin.NewBanCache(5, time.Hour)
func NewBanCache(maxFailures int, banDuration time.Duration) *BanCache {
	return &BanCache{
		cache:       gocache.New(banDuration, banDuration/2*3),
		banDuration: banDuration,
		maxFailures: maxFailures,
	}
}

// CheckAndAdd checks if the IP is banned; if not present, initializes its counter.
// Returns true if banned, false otherwise.
func (b *BanCache) CheckAndAdd(ip string) (banned bool, err error) {
	failed, found := b.cache.Get(ip)
	if !found {
		// init
		if err := b.cache.Add(ip, 0, b.banDuration); err != nil {
			return false, err
		}
		return false, nil
	}
	if failed.(int) >= b.maxFailures {
		return true, nil
	}
	return false, nil
}

// Increment increments the failure count for the IP and returns the new count.
func (b *BanCache) Increment(ip string) int {
	failed, _ := b.cache.IncrementInt(ip, 1)
	return failed
}

// Flush clears all ban entries (e.g., on SIGHUP).
func (b *BanCache) Flush() {
	b.cache.Flush()
}
