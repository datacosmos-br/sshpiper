// Package sshpiperd provides professional health check and metrics capabilities
// for the SSH proxy daemon with comprehensive observability features.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

// HealthStatus represents the health status of the daemon
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// Metrics holds runtime metrics for the SSH proxy
type Metrics struct {
	ActiveConnections int64  `json:"active_connections"`
	TotalConnections  int64  `json:"total_connections"`
	FailedConnections int64  `json:"failed_connections"`
	BytesTransferred  int64  `json:"bytes_transferred"`
	GoRoutines        int    `json:"goroutines"`
	MemoryUsageBytes  uint64 `json:"memory_usage_bytes"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
	ActivePlugins     int    `json:"active_plugins"`
	PluginErrors      int64  `json:"plugin_errors"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    HealthStatus  `json:"status"`
	Timestamp time.Time     `json:"timestamp"`
	Version   string        `json:"version"`
	Uptime    time.Duration `json:"uptime"`
	Metrics   Metrics       `json:"metrics"`
}

// HealthManager manages health checks and metrics collection
type HealthManager struct {
	startTime         time.Time
	logger            *slog.Logger
	activeConnections int64
	totalConnections  int64
	failedConnections int64
	bytesTransferred  int64
	pluginErrors      int64
	activePlugins     int
}

// NewHealthManager creates a new health manager instance
func NewHealthManager(logger *slog.Logger) *HealthManager {
	return &HealthManager{
		startTime: time.Now(),
		logger:    logger,
	}
}

// GetHealth returns the current health status
func (hm *HealthManager) GetHealth(ctx context.Context) HealthResponse {
	metrics := hm.collectMetrics()

	status := HealthStatusHealthy
	if hm.activePlugins == 0 {
		status = HealthStatusUnhealthy
	} else if atomic.LoadInt64(&hm.pluginErrors) > 0 {
		status = HealthStatusDegraded
	}

	return HealthResponse{
		Status:    status,
		Timestamp: time.Now(),
		Version:   version(),
		Uptime:    time.Since(hm.startTime),
		Metrics:   metrics,
	}
}

// collectMetrics gathers runtime metrics
func (hm *HealthManager) collectMetrics() Metrics {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return Metrics{
		ActiveConnections: atomic.LoadInt64(&hm.activeConnections),
		TotalConnections:  atomic.LoadInt64(&hm.totalConnections),
		FailedConnections: atomic.LoadInt64(&hm.failedConnections),
		BytesTransferred:  atomic.LoadInt64(&hm.bytesTransferred),
		GoRoutines:        runtime.NumGoroutine(),
		MemoryUsageBytes:  memStats.Alloc,
		UptimeSeconds:     int64(time.Since(hm.startTime).Seconds()),
		ActivePlugins:     hm.activePlugins,
		PluginErrors:      atomic.LoadInt64(&hm.pluginErrors),
	}
}

// Connection tracking methods
func (hm *HealthManager) IncrementActiveConnections() {
	atomic.AddInt64(&hm.activeConnections, 1)
	atomic.AddInt64(&hm.totalConnections, 1)
}

func (hm *HealthManager) DecrementActiveConnections() {
	atomic.AddInt64(&hm.activeConnections, -1)
}

func (hm *HealthManager) SetActivePlugins(count int) {
	hm.activePlugins = count
}

// HealthHandler returns health status as JSON
func (hm *HealthManager) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		health := hm.GetHealth(r.Context())

		statusCode := http.StatusOK
		if health.Status == HealthStatusUnhealthy {
			statusCode = http.StatusServiceUnavailable
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(health)
	}
}

// MetricsHandler returns Prometheus-style metrics
func (hm *HealthManager) MetricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metrics := hm.collectMetrics()

		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "sshpiper_active_connections %d\n", metrics.ActiveConnections)
		fmt.Fprintf(w, "sshpiper_total_connections %d\n", metrics.TotalConnections)
		fmt.Fprintf(w, "sshpiper_failed_connections %d\n", metrics.FailedConnections)
		fmt.Fprintf(w, "sshpiper_goroutines %d\n", metrics.GoRoutines)
		fmt.Fprintf(w, "sshpiper_memory_usage_bytes %d\n", metrics.MemoryUsageBytes)
		fmt.Fprintf(w, "sshpiper_uptime_seconds %d\n", metrics.UptimeSeconds)
		fmt.Fprintf(w, "sshpiper_active_plugins %d\n", metrics.ActivePlugins)
	}
}
