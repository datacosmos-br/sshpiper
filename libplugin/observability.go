package libplugin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// ObservabilityManager manages comprehensive observability
type ObservabilityManager struct {
	// Configuration
	config           ObservabilityConfig
	serviceName      string
	serviceVersion   string
	environment      string
	
	// Metrics collection
	metrics          map[string]*MetricCollector
	metricsMutex     sync.RWMutex
	
	// HTTP server for metrics exposure
	metricsServer    *http.Server
	
	// Context and lifecycle
	ctx              context.Context
	cancel           context.CancelFunc
	mutex            sync.RWMutex
	
	// Observability state
	logger           *StandardLogger
	enabled          bool
	startTime        time.Time
	
	// Tracing state (simplified)
	traces           map[string]*TraceSpan
	tracesMutex      sync.RWMutex
}

// MetricCollector collects and stores metrics
type MetricCollector struct {
	Name        string                 `json:"name"`
	Type        MetricType             `json:"type"`
	Value       float64                `json:"value"`
	Labels      map[string]string      `json:"labels"`
	LastUpdated time.Time              `json:"last_updated"`
	Count       int64                  `json:"count"`
	Sum         float64                `json:"sum"`
	Histogram   map[string]int64       `json:"histogram,omitempty"`
}

// MetricType represents the type of metric
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
)

// TraceSpan represents a simplified trace span
type TraceSpan struct {
	TraceID     string                 `json:"trace_id"`
	SpanID      string                 `json:"span_id"`
	ParentID    string                 `json:"parent_id,omitempty"`
	Operation   string                 `json:"operation"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     *time.Time             `json:"end_time,omitempty"`
	Duration    *time.Duration         `json:"duration,omitempty"`
	Tags        map[string]string      `json:"tags"`
	Logs        []TraceLog             `json:"logs"`
	Status      TraceStatus            `json:"status"`
}

// TraceLog represents a log entry within a trace
type TraceLog struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields"`
}

// TraceStatus represents the status of a trace span
type TraceStatus string

const (
	TraceStatusOK    TraceStatus = "ok"
	TraceStatusError TraceStatus = "error"
)

// Attribute represents a key-value attribute for metrics and traces
type Attribute struct {
	Key   string
	Value interface{}
}

// String creates a string attribute
func String(key, value string) Attribute {
	return Attribute{Key: key, Value: value}
}

// Int creates an integer attribute  
func Int(key string, value int) Attribute {
	return Attribute{Key: key, Value: value}
}

// Float64 creates a float64 attribute
func Float64(key string, value float64) Attribute {
	return Attribute{Key: key, Value: value}
}

// Bool creates a boolean attribute
func Bool(key string, value bool) Attribute {
	return Attribute{Key: key, Value: value}
}

// TraceContext provides context for distributed tracing
type TraceContext struct {
	TraceID         string `json:"trace_id"`
	SpanID          string `json:"span_id"`
	ParentSpanID    string `json:"parent_span_id,omitempty"`
	Baggage         map[string]string `json:"baggage,omitempty"`
}

// NewObservabilityManager creates a new observability manager
func NewObservabilityManager(config ObservabilityConfig) (*ObservabilityManager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	logger := NewStandardLogger("observability")
	
	om := &ObservabilityManager{
		config:         config,
		serviceName:    config.ServiceName,
		serviceVersion: config.ServiceVersion,
		environment:    config.Environment,
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
		enabled:        config.Enabled,
		startTime:      time.Now(),
		metrics:        make(map[string]*MetricCollector),
		traces:         make(map[string]*TraceSpan),
	}
	
	if !config.Enabled {
		logger.Info("observability disabled by configuration")
		return om, nil
	}
	
	// Initialize logging
	if err := om.initializeLogging(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize logging: %w", err)
	}
	
	// Create custom metrics
	if err := om.createCustomMetrics(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create custom metrics: %w", err)
	}
	
	// Start metrics server if enabled
	if config.Metrics.Enabled {
		if err := om.startMetricsServer(); err != nil {
			cancel()
			return nil, fmt.Errorf("failed to start metrics server: %w", err)
		}
	}
	
	logger.Info("observability manager initialized successfully", log.Fields{
		"service_name":    config.ServiceName,
		"service_version": config.ServiceVersion,
		"environment":     config.Environment,
		"tracing_enabled": config.Tracing.Enabled,
		"metrics_enabled": config.Metrics.Enabled,
	})
	
	return om, nil
}

// initializeLogging sets up structured logging
func (om *ObservabilityManager) initializeLogging() error {
	// Configure logrus with observability settings
	if om.config.Logging.Format == "json" {
		log.SetFormatter(&log.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	} else {
		log.SetFormatter(&log.TextFormatter{
			TimestampFormat: time.RFC3339,
			FullTimestamp:   true,
		})
	}
	
	// Set log level
	level, err := log.ParseLevel(om.config.Logging.Level)
	if err != nil {
		level = log.InfoLevel
	}
	log.SetLevel(level)
	
	om.logger.Info("logging configured", log.Fields{
		"level":           om.config.Logging.Level,
		"format":          om.config.Logging.Format,
		"trace_id":        om.config.Logging.TraceID,
		"context_fields":  om.config.Logging.ContextFields,
	})
	
	return nil
}

// createCustomMetrics creates application-specific metrics
func (om *ObservabilityManager) createCustomMetrics() error {
	om.metricsMutex.Lock()
	defer om.metricsMutex.Unlock()
	
	// Connection metrics
	om.metrics["sshpiper_connections_active"] = &MetricCollector{
		Name:        "sshpiper_connections_active",
		Type:        MetricTypeGauge,
		Labels:      make(map[string]string),
		LastUpdated: time.Now(),
	}
	
	// Request metrics
	om.metrics["sshpiper_request_duration_seconds"] = &MetricCollector{
		Name:        "sshpiper_request_duration_seconds",
		Type:        MetricTypeHistogram,
		Labels:      make(map[string]string),
		LastUpdated: time.Now(),
		Histogram:   make(map[string]int64),
	}
	
	// Error metrics
	om.metrics["sshpiper_errors_total"] = &MetricCollector{
		Name:        "sshpiper_errors_total",
		Type:        MetricTypeCounter,
		Labels:      make(map[string]string),
		LastUpdated: time.Now(),
	}
	
	// Plugin metrics
	if om.config.Metrics.PluginMetrics {
		om.metrics["sshpiper_plugins_active"] = &MetricCollector{
			Name:        "sshpiper_plugins_active",
			Type:        MetricTypeGauge,
			Labels:      make(map[string]string),
			LastUpdated: time.Now(),
		}
		
		om.metrics["sshpiper_plugin_duration_seconds"] = &MetricCollector{
			Name:        "sshpiper_plugin_duration_seconds",
			Type:        MetricTypeHistogram,
			Labels:      make(map[string]string),
			LastUpdated: time.Now(),
			Histogram:   make(map[string]int64),
		}
		
		om.metrics["sshpiper_plugin_errors_total"] = &MetricCollector{
			Name:        "sshpiper_plugin_errors_total",
			Type:        MetricTypeCounter,
			Labels:      make(map[string]string),
			LastUpdated: time.Now(),
		}
		
		om.metrics["sshpiper_plugin_reloads_total"] = &MetricCollector{
			Name:        "sshpiper_plugin_reloads_total",
			Type:        MetricTypeCounter,
			Labels:      make(map[string]string),
			LastUpdated: time.Now(),
		}
	}
	
	// System metrics
	if om.config.Metrics.SystemMetrics {
		om.metrics["sshpiper_cpu_usage_percent"] = &MetricCollector{
			Name:        "sshpiper_cpu_usage_percent",
			Type:        MetricTypeGauge,
			Labels:      make(map[string]string),
			LastUpdated: time.Now(),
		}
		
		om.metrics["sshpiper_memory_usage_bytes"] = &MetricCollector{
			Name:        "sshpiper_memory_usage_bytes",
			Type:        MetricTypeGauge,
			Labels:      make(map[string]string),
			LastUpdated: time.Now(),
		}
		
		om.metrics["sshpiper_goroutines_total"] = &MetricCollector{
			Name:        "sshpiper_goroutines_total",
			Type:        MetricTypeGauge,
			Labels:      make(map[string]string),
			LastUpdated: time.Now(),
		}
	}
	
	// Security metrics
	if om.config.Metrics.SecurityMetrics {
		om.metrics["sshpiper_auth_attempts_total"] = &MetricCollector{
			Name:        "sshpiper_auth_attempts_total",
			Type:        MetricTypeCounter,
			Labels:      make(map[string]string),
			LastUpdated: time.Now(),
		}
		
		om.metrics["sshpiper_auth_failures_total"] = &MetricCollector{
			Name:        "sshpiper_auth_failures_total",
			Type:        MetricTypeCounter,
			Labels:      make(map[string]string),
			LastUpdated: time.Now(),
		}
		
		om.metrics["sshpiper_suspicious_ips_total"] = &MetricCollector{
			Name:        "sshpiper_suspicious_ips_total",
			Type:        MetricTypeCounter,
			Labels:      make(map[string]string),
			LastUpdated: time.Now(),
		}
		
		om.metrics["sshpiper_banned_ips_active"] = &MetricCollector{
			Name:        "sshpiper_banned_ips_active",
			Type:        MetricTypeGauge,
			Labels:      make(map[string]string),
			LastUpdated: time.Now(),
		}
	}
	
	om.logger.Info("custom metrics created successfully", log.Fields{
		"system_metrics":   om.config.Metrics.SystemMetrics,
		"plugin_metrics":   om.config.Metrics.PluginMetrics,
		"security_metrics": om.config.Metrics.SecurityMetrics,
		"total_metrics":    len(om.metrics),
	})
	
	return nil
}

// startMetricsServer starts the metrics HTTP server
func (om *ObservabilityManager) startMetricsServer() error {
	config := om.config.Exporters.Prometheus
	
	mux := http.NewServeMux()
	
	// Metrics endpoint (Prometheus-compatible format)
	mux.HandleFunc(config.Path, om.handleMetrics)
	
	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	// Metrics info endpoint
	mux.HandleFunc("/info", om.handleInfo)
	
	// Traces endpoint
	mux.HandleFunc("/traces", om.handleTraces)
	
	om.metricsServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: mux,
	}
	
	go func() {
		om.logger.Info("starting metrics server", log.Fields{
			"port": config.Port,
			"path": config.Path,
		})
		
		if err := om.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			om.logger.Error("metrics server error", err)
		}
	}()
	
	return nil
}

// handleMetrics serves metrics in Prometheus format
func (om *ObservabilityManager) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	
	om.metricsMutex.RLock()
	defer om.metricsMutex.RUnlock()
	
	var output strings.Builder
	
	// Sort metrics by name for consistent output
	names := make([]string, 0, len(om.metrics))
	for name := range om.metrics {
		names = append(names, name)
	}
	sort.Strings(names)
	
	for _, name := range names {
		metric := om.metrics[name]
		
		// Write metric help
		output.WriteString(fmt.Sprintf("# HELP %s %s\n", metric.Name, getMetricHelp(metric.Name)))
		output.WriteString(fmt.Sprintf("# TYPE %s %s\n", metric.Name, strings.ToLower(string(metric.Type))))
		
		// Write metric value
		switch metric.Type {
		case MetricTypeCounter:
			output.WriteString(fmt.Sprintf("%s %d\n", metric.Name, metric.Count))
		case MetricTypeGauge:
			output.WriteString(fmt.Sprintf("%s %.2f\n", metric.Name, metric.Value))
		case MetricTypeHistogram:
			// Write histogram buckets
			for bucket, count := range metric.Histogram {
				output.WriteString(fmt.Sprintf("%s_bucket{le=\"%s\"} %d\n", metric.Name, bucket, count))
			}
			output.WriteString(fmt.Sprintf("%s_count %d\n", metric.Name, metric.Count))
			output.WriteString(fmt.Sprintf("%s_sum %.2f\n", metric.Name, metric.Sum))
		}
		
		output.WriteString("\n")
	}
	
	w.Write([]byte(output.String()))
}

// handleInfo serves information about the observability system
func (om *ObservabilityManager) handleInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"service_name":    om.serviceName,
		"service_version": om.serviceVersion,
		"environment":     om.environment,
		"uptime_seconds":  time.Since(om.startTime).Seconds(),
		"enabled_features": map[string]bool{
			"tracing":          om.config.Tracing.Enabled,
			"metrics":          om.config.Metrics.Enabled,
			"system_metrics":   om.config.Metrics.SystemMetrics,
			"plugin_metrics":   om.config.Metrics.PluginMetrics,
			"security_metrics": om.config.Metrics.SecurityMetrics,
		},
		"metrics_count": len(om.metrics),
		"traces_count":  len(om.traces),
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// handleTraces serves trace information
func (om *ObservabilityManager) handleTraces(w http.ResponseWriter, r *http.Request) {
	om.tracesMutex.RLock()
	defer om.tracesMutex.RUnlock()
	
	// Return recent traces (last 100)
	traces := make([]*TraceSpan, 0, len(om.traces))
	for _, trace := range om.traces {
		traces = append(traces, trace)
	}
	
	// Sort by start time (most recent first)
	sort.Slice(traces, func(i, j int) bool {
		return traces[i].StartTime.After(traces[j].StartTime)
	})
	
	// Limit to last 100 traces
	if len(traces) > 100 {
		traces = traces[:100]
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"traces": traces,
		"count":  len(traces),
	})
}

// getMetricHelp returns help text for a metric
func getMetricHelp(name string) string {
	helpTexts := map[string]string{
		"sshpiper_connections_active":        "Number of active SSH connections",
		"sshpiper_request_duration_seconds":  "Duration of SSH requests in seconds",
		"sshpiper_errors_total":              "Total number of errors",
		"sshpiper_plugins_active":            "Number of active plugins",
		"sshpiper_plugin_duration_seconds":   "Duration of plugin operations in seconds",
		"sshpiper_plugin_errors_total":       "Total number of plugin errors",
		"sshpiper_plugin_reloads_total":      "Total number of plugin reloads",
		"sshpiper_cpu_usage_percent":         "CPU usage percentage",
		"sshpiper_memory_usage_bytes":        "Memory usage in bytes",
		"sshpiper_goroutines_total":          "Number of goroutines",
		"sshpiper_auth_attempts_total":       "Total number of authentication attempts",
		"sshpiper_auth_failures_total":       "Total number of authentication failures",
		"sshpiper_suspicious_ips_total":      "Total number of suspicious IP addresses detected",
		"sshpiper_banned_ips_active":         "Number of currently banned IP addresses",
	}
	
	if help, exists := helpTexts[name]; exists {
		return help
	}
	return "No description available"
}

// Start begins observability collection and monitoring
func (om *ObservabilityManager) Start() error {
	if !om.enabled {
		return nil
	}
	
	om.logger.Info("starting observability manager")
	
	// Start system metrics collection if enabled
	if om.config.Metrics.SystemMetrics {
		go om.collectSystemMetrics()
	}
	
	// Start trace cleanup
	if om.config.Tracing.Enabled {
		go om.cleanupExpiredTraces()
	}
	
	om.logger.Info("observability manager started successfully")
	return nil
}

// Stop gracefully shuts down the observability manager
func (om *ObservabilityManager) Stop() error {
	if !om.enabled {
		return nil
	}
	
	om.logger.Info("stopping observability manager")
	
	// Cancel context
	om.cancel()
	
	// Shutdown metrics server
	if om.metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := om.metricsServer.Shutdown(ctx); err != nil {
			om.logger.Error("failed to shutdown metrics server", err)
		}
	}
	
	om.logger.Info("observability manager stopped")
	return nil
}

// collectSystemMetrics collects system-level metrics
func (om *ObservabilityManager) collectSystemMetrics() {
	ticker := time.NewTicker(om.config.Metrics.Interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			om.recordSystemMetrics()
		case <-om.ctx.Done():
			return
		}
	}
}

// recordSystemMetrics records current system metrics
func (om *ObservabilityManager) recordSystemMetrics() {
	om.metricsMutex.Lock()
	defer om.metricsMutex.Unlock()
	
	now := time.Now()
	
	// Record goroutine count
	if metric, exists := om.metrics["sshpiper_goroutines_total"]; exists {
		metric.Value = float64(runtime.NumGoroutine())
		metric.LastUpdated = now
	}
	
	// Record memory stats
	if metric, exists := om.metrics["sshpiper_memory_usage_bytes"]; exists {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		metric.Value = float64(m.Alloc)
		metric.LastUpdated = now
	}
}

// cleanupExpiredTraces removes old traces to prevent memory leaks
func (om *ObservabilityManager) cleanupExpiredTraces() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			om.tracesMutex.Lock()
			
			cutoff := time.Now().Add(-1 * time.Hour) // Keep traces for 1 hour
			for id, trace := range om.traces {
				if trace.StartTime.Before(cutoff) {
					delete(om.traces, id)
				}
			}
			
			om.tracesMutex.Unlock()
		case <-om.ctx.Done():
			return
		}
	}
}

// StartSpan creates a new tracing span
func (om *ObservabilityManager) StartSpan(ctx context.Context, name string, attrs ...Attribute) (context.Context, string) {
	if !om.enabled || !om.config.Tracing.Enabled {
		return ctx, ""
	}
	
	traceID := generateID()
	spanID := generateID()
	
	tags := make(map[string]string)
	for _, attr := range attrs {
		tags[attr.Key] = fmt.Sprintf("%v", attr.Value)
	}
	
	span := &TraceSpan{
		TraceID:   traceID,
		SpanID:    spanID,
		Operation: name,
		StartTime: time.Now(),
		Tags:      tags,
		Logs:      make([]TraceLog, 0),
		Status:    TraceStatusOK,
	}
	
	om.tracesMutex.Lock()
	om.traces[spanID] = span
	om.tracesMutex.Unlock()
	
	// Add span to context
	newCtx := context.WithValue(ctx, "span_id", spanID)
	newCtx = context.WithValue(newCtx, "trace_id", traceID)
	
	return newCtx, spanID
}

// FinishSpan completes a tracing span
func (om *ObservabilityManager) FinishSpan(ctx context.Context, spanID string, status TraceStatus) {
	if !om.enabled || !om.config.Tracing.Enabled || spanID == "" {
		return
	}
	
	om.tracesMutex.Lock()
	defer om.tracesMutex.Unlock()
	
	if span, exists := om.traces[spanID]; exists {
		now := time.Now()
		span.EndTime = &now
		duration := now.Sub(span.StartTime)
		span.Duration = &duration
		span.Status = status
	}
}

// RecordConnectionEvent records a connection-related metric event
func (om *ObservabilityManager) RecordConnectionEvent(ctx context.Context, event string, attrs ...Attribute) {
	if !om.enabled || !om.config.Metrics.Enabled {
		return
	}
	
	om.metricsMutex.Lock()
	defer om.metricsMutex.Unlock()
	
	switch event {
	case "connect":
		if metric, exists := om.metrics["sshpiper_connections_active"]; exists {
			metric.Value++
			metric.LastUpdated = time.Now()
		}
	case "disconnect":
		if metric, exists := om.metrics["sshpiper_connections_active"]; exists {
			if metric.Value > 0 {
				metric.Value--
			}
			metric.LastUpdated = time.Now()
		}
	}
}

// RecordRequestDuration records the duration of a request
func (om *ObservabilityManager) RecordRequestDuration(ctx context.Context, duration time.Duration, attrs ...Attribute) {
	if !om.enabled || !om.config.Metrics.Enabled {
		return
	}
	
	om.metricsMutex.Lock()
	defer om.metricsMutex.Unlock()
	
	if metric, exists := om.metrics["sshpiper_request_duration_seconds"]; exists {
		seconds := duration.Seconds()
		metric.Sum += seconds
		metric.Count++
		metric.LastUpdated = time.Now()
		
		// Add to histogram bucket
		bucket := getHistogramBucket(seconds)
		if metric.Histogram == nil {
			metric.Histogram = make(map[string]int64)
		}
		metric.Histogram[bucket]++
	}
}

// RecordError records an error event
func (om *ObservabilityManager) RecordError(ctx context.Context, errorType string, attrs ...Attribute) {
	if !om.enabled || !om.config.Metrics.Enabled {
		return
	}
	
	om.metricsMutex.Lock()
	defer om.metricsMutex.Unlock()
	
	if metric, exists := om.metrics["sshpiper_errors_total"]; exists {
		metric.Count++
		metric.LastUpdated = time.Now()
	}
}

// RecordPluginEvent records a plugin-related metric event
func (om *ObservabilityManager) RecordPluginEvent(ctx context.Context, event string, pluginName string, attrs ...Attribute) {
	if !om.enabled || !om.config.Metrics.Enabled || !om.config.Metrics.PluginMetrics {
		return
	}
	
	om.metricsMutex.Lock()
	defer om.metricsMutex.Unlock()
	
	switch event {
	case "load":
		if metric, exists := om.metrics["sshpiper_plugins_active"]; exists {
			metric.Value++
			metric.LastUpdated = time.Now()
		}
	case "unload":
		if metric, exists := om.metrics["sshpiper_plugins_active"]; exists {
			if metric.Value > 0 {
				metric.Value--
			}
			metric.LastUpdated = time.Now()
		}
	case "reload":
		if metric, exists := om.metrics["sshpiper_plugin_reloads_total"]; exists {
			metric.Count++
			metric.LastUpdated = time.Now()
		}
	case "error":
		if metric, exists := om.metrics["sshpiper_plugin_errors_total"]; exists {
			metric.Count++
			metric.LastUpdated = time.Now()
		}
	}
}

// RecordPluginDuration records the duration of a plugin operation
func (om *ObservabilityManager) RecordPluginDuration(ctx context.Context, pluginName string, operation string, duration time.Duration) {
	if !om.enabled || !om.config.Metrics.Enabled || !om.config.Metrics.PluginMetrics {
		return
	}
	
	om.metricsMutex.Lock()
	defer om.metricsMutex.Unlock()
	
	if metric, exists := om.metrics["sshpiper_plugin_duration_seconds"]; exists {
		seconds := duration.Seconds()
		metric.Sum += seconds
		metric.Count++
		metric.LastUpdated = time.Now()
		
		// Add to histogram bucket
		bucket := getHistogramBucket(seconds)
		if metric.Histogram == nil {
			metric.Histogram = make(map[string]int64)
		}
		metric.Histogram[bucket]++
	}
}

// RecordSecurityEvent records a security-related metric event
func (om *ObservabilityManager) RecordSecurityEvent(ctx context.Context, event string, attrs ...Attribute) {
	if !om.enabled || !om.config.Metrics.Enabled || !om.config.Metrics.SecurityMetrics {
		return
	}
	
	om.metricsMutex.Lock()
	defer om.metricsMutex.Unlock()
	
	switch event {
	case "auth_attempt":
		if metric, exists := om.metrics["sshpiper_auth_attempts_total"]; exists {
			metric.Count++
			metric.LastUpdated = time.Now()
		}
	case "auth_failure":
		if metric, exists := om.metrics["sshpiper_auth_failures_total"]; exists {
			metric.Count++
			metric.LastUpdated = time.Now()
		}
	case "suspicious_ip":
		if metric, exists := om.metrics["sshpiper_suspicious_ips_total"]; exists {
			metric.Count++
			metric.LastUpdated = time.Now()
		}
	case "ban_ip":
		if metric, exists := om.metrics["sshpiper_banned_ips_active"]; exists {
			metric.Value++
			metric.LastUpdated = time.Now()
		}
	case "unban_ip":
		if metric, exists := om.metrics["sshpiper_banned_ips_active"]; exists {
			if metric.Value > 0 {
				metric.Value--
			}
			metric.LastUpdated = time.Now()
		}
	}
}

// GetTraceContext extracts trace context information
func (om *ObservabilityManager) GetTraceContext(ctx context.Context) TraceContext {
	traceID := ""
	spanID := ""
	
	if tid := ctx.Value("trace_id"); tid != nil {
		traceID = tid.(string)
	}
	if sid := ctx.Value("span_id"); sid != nil {
		spanID = sid.(string)
	}
	
	return TraceContext{
		TraceID: traceID,
		SpanID:  spanID,
	}
}

// LogWithTrace logs a message with trace context
func (om *ObservabilityManager) LogWithTrace(ctx context.Context, level log.Level, message string, fields log.Fields) {
	if om.config.Logging.TraceID {
		traceCtx := om.GetTraceContext(ctx)
		if fields == nil {
			fields = log.Fields{}
		}
		if traceCtx.TraceID != "" {
			fields["trace_id"] = traceCtx.TraceID
		}
		if traceCtx.SpanID != "" {
			fields["span_id"] = traceCtx.SpanID
		}
	}
	
	entry := om.logger.WithFields(fields)
	switch level {
	case log.DebugLevel:
		entry.Debug(message)
	case log.InfoLevel:
		entry.Info(message)
	case log.WarnLevel:
		entry.Warn(message)
	case log.ErrorLevel:
		entry.Error(message)
	case log.FatalLevel:
		entry.Fatal(message)
	case log.PanicLevel:
		entry.Panic(message)
	}
}

// GetMetrics returns current metrics snapshot
func (om *ObservabilityManager) GetMetrics(ctx context.Context) map[string]interface{} {
	if !om.enabled {
		return nil
	}
	
	om.metricsMutex.RLock()
	defer om.metricsMutex.RUnlock()
	
	metrics := map[string]interface{}{
		"service_name":    om.serviceName,
		"service_version": om.serviceVersion,
		"environment":     om.environment,
		"uptime_seconds":  time.Since(om.startTime).Seconds(),
		"enabled_features": map[string]bool{
			"tracing":          om.config.Tracing.Enabled,
			"metrics":          om.config.Metrics.Enabled,
			"system_metrics":   om.config.Metrics.SystemMetrics,
			"plugin_metrics":   om.config.Metrics.PluginMetrics,
			"security_metrics": om.config.Metrics.SecurityMetrics,
		},
		"metrics_count": len(om.metrics),
	}
	
	// Add current metric values
	currentMetrics := make(map[string]interface{})
	for name, metric := range om.metrics {
		switch metric.Type {
		case MetricTypeCounter:
			currentMetrics[name] = metric.Count
		case MetricTypeGauge:
			currentMetrics[name] = metric.Value
		case MetricTypeHistogram:
			currentMetrics[name] = map[string]interface{}{
				"count": metric.Count,
				"sum":   metric.Sum,
			}
		}
	}
	metrics["current_metrics"] = currentMetrics
	
	// Add runtime metrics
	if om.config.Metrics.SystemMetrics {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		
		metrics["runtime"] = map[string]interface{}{
			"goroutines":     runtime.NumGoroutine(),
			"memory_alloc":   m.Alloc,
			"memory_sys":     m.Sys,
			"gc_runs":        m.NumGC,
		}
	}
	
	return metrics
}

// generateID generates a random ID for traces and spans
func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// getHistogramBucket determines the appropriate histogram bucket for a value
func getHistogramBucket(value float64) string {
	buckets := []float64{0.001, 0.01, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0}
	
	for _, bucket := range buckets {
		if value <= bucket {
			return fmt.Sprintf("%.3f", bucket)
		}
	}
	
	return "+Inf"
}