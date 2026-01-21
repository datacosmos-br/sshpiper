package libplugin

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"plugin"
	"strings"
	"sync"
	"time"

	"github.com/urfave/cli/v2"
	log "github.com/sirupsen/logrus"
)

// PluginDiscoveryManager manages plugin discovery and hot-reload capabilities
type PluginDiscoveryManager struct {
	// Configuration
	pluginDir      string
	configDir      string
	hotReload      bool
	scanInterval   time.Duration
	
	// State management
	loadedPlugins  map[string]*ManagedPlugin
	pluginConfigs  map[string]*PluginConfiguration
	ctx            context.Context
	cancel         context.CancelFunc
	mutex          sync.RWMutex
	
	// Observability
	logger         *StandardLogger
	metrics        *StandardMetrics
	
	// Event handlers
	onPluginLoad   func(plugin *ManagedPlugin) error
	onPluginUnload func(plugin *ManagedPlugin) error
	onPluginReload func(old, new *ManagedPlugin) error
}

// ManagedPlugin represents a plugin with lifecycle management
type ManagedPlugin struct {
	// Metadata
	Name         string                    `json:"name"`
	Version      string                   `json:"version"`
	FilePath     string                   `json:"file_path"`
	ConfigPath   string                   `json:"config_path"`
	LoadTime     time.Time                `json:"load_time"`
	LastReload   time.Time                `json:"last_reload"`
	Status       PluginStatus             `json:"status"`
	
	// Plugin instance
	Interface    StandardPluginInterface  `json:"-"`
	NativePlugin *plugin.Plugin          `json:"-"`
	Config       *PluginConfiguration    `json:"-"`
	
	// Health and metrics
	LoadCount    int64                    `json:"load_count"`
	ErrorCount   int64                    `json:"error_count"`
	LastError    string                   `json:"last_error,omitempty"`
	Health       PluginHealth             `json:"health"`
	
	// Dependencies
	Dependencies []string                 `json:"dependencies"`
	Dependents   []string                 `json:"dependents"`
}

// PluginStatus represents the current status of a plugin
type PluginStatus string

const (
	PluginStatusLoading   PluginStatus = "loading"
	PluginStatusActive    PluginStatus = "active"
	PluginStatusFailed    PluginStatus = "failed"
	PluginStatusUnloading PluginStatus = "unloading"
	PluginStatusDisabled  PluginStatus = "disabled"
)

// PluginHealth represents the health status of a plugin
type PluginHealth struct {
	Healthy       bool      `json:"healthy"`
	LastCheck     time.Time `json:"last_check"`
	ErrorRate     float64   `json:"error_rate"`
	ResponseTime  time.Duration `json:"response_time"`
	CheckInterval time.Duration `json:"check_interval"`
}

// PluginConfiguration represents declarative plugin configuration
type PluginConfiguration struct {
	// Plugin metadata
	Name        string            `yaml:"name" json:"name"`
	Version     string            `yaml:"version" json:"version"`
	Description string            `yaml:"description" json:"description"`
	Type        PluginType        `yaml:"type" json:"type"`
	Enabled     bool              `yaml:"enabled" json:"enabled"`
	
	// Loading configuration
	AutoLoad    bool              `yaml:"auto_load" json:"auto_load"`
	LoadOrder   int               `yaml:"load_order" json:"load_order"`
	HotReload   bool              `yaml:"hot_reload" json:"hot_reload"`
	
	// Dependencies
	Dependencies []string         `yaml:"dependencies" json:"dependencies"`
	Conflicts    []string         `yaml:"conflicts" json:"conflicts"`
	
	// Resource limits
	Resources   PluginResources   `yaml:"resources" json:"resources"`
	
	// Health check configuration
	HealthCheck HealthCheckConfig `yaml:"health_check" json:"health_check"`
	
	// Plugin-specific configuration
	Config      map[string]interface{} `yaml:"config" json:"config"`
	
	// Security settings
	Security    PluginSecurity    `yaml:"security" json:"security"`
}

// PluginResources defines resource limits for plugins
type PluginResources struct {
	MaxMemoryMB    int           `yaml:"max_memory_mb" json:"max_memory_mb"`
	MaxConnections int           `yaml:"max_connections" json:"max_connections"`
	Timeout        time.Duration `yaml:"timeout" json:"timeout"`
	RateLimit      RateLimit     `yaml:"rate_limit" json:"rate_limit"`
}

// RateLimit defines rate limiting configuration
type RateLimit struct {
	RequestsPerSecond int           `yaml:"requests_per_second" json:"requests_per_second"`
	BurstSize        int           `yaml:"burst_size" json:"burst_size"`
	WindowSize       time.Duration `yaml:"window_size" json:"window_size"`
}

// HealthCheckConfig defines health check settings
type HealthCheckConfig struct {
	Enabled       bool          `yaml:"enabled" json:"enabled"`
	Interval      time.Duration `yaml:"interval" json:"interval"`
	Timeout       time.Duration `yaml:"timeout" json:"timeout"`
	FailThreshold int           `yaml:"fail_threshold" json:"fail_threshold"`
	SuccessThreshold int        `yaml:"success_threshold" json:"success_threshold"`
}

// PluginSecurity defines security settings for plugins
type PluginSecurity struct {
	AllowedHosts    []string `yaml:"allowed_hosts" json:"allowed_hosts"`
	DeniedHosts     []string `yaml:"denied_hosts" json:"denied_hosts"`
	RequireAuth     bool     `yaml:"require_auth" json:"require_auth"`
	AllowedUsers    []string `yaml:"allowed_users" json:"allowed_users"`
	DeniedUsers     []string `yaml:"denied_users" json:"denied_users"`
	MaxFailAttempts int      `yaml:"max_fail_attempts" json:"max_fail_attempts"`
	LockoutDuration time.Duration `yaml:"lockout_duration" json:"lockout_duration"`
}

// DiscoveryManagerConfig configures the plugin discovery manager
type DiscoveryManagerConfig struct {
	PluginDir     string        `yaml:"plugin_dir" json:"plugin_dir"`
	ConfigDir     string        `yaml:"config_dir" json:"config_dir"`
	HotReload     bool          `yaml:"hot_reload" json:"hot_reload"`
	ScanInterval  time.Duration `yaml:"scan_interval" json:"scan_interval"`
	EnableMetrics bool          `yaml:"enable_metrics" json:"enable_metrics"`
}

// NewPluginDiscoveryManager creates a new plugin discovery manager
func NewPluginDiscoveryManager(config DiscoveryManagerConfig) (*PluginDiscoveryManager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	logger := NewStandardLogger("plugin_discovery")
	metrics := NewStandardMetrics("plugin_discovery")
	
	pdm := &PluginDiscoveryManager{
		pluginDir:     config.PluginDir,
		configDir:     config.ConfigDir,
		hotReload:     config.HotReload,
		scanInterval:  config.ScanInterval,
		loadedPlugins: make(map[string]*ManagedPlugin),
		pluginConfigs: make(map[string]*PluginConfiguration),
		ctx:           ctx,
		cancel:        cancel,
		logger:        logger,
		metrics:       metrics,
	}
	
	if config.ScanInterval == 0 {
		pdm.scanInterval = 30 * time.Second
	}
	
	logger.Info("plugin discovery manager created", log.Fields{
		"plugin_dir":    config.PluginDir,
		"config_dir":    config.ConfigDir,
		"hot_reload":    config.HotReload,
		"scan_interval": pdm.scanInterval,
	})
	
	return pdm, nil
}

// Start begins plugin discovery and monitoring
func (pdm *PluginDiscoveryManager) Start() error {
	pdm.logger.Info("starting plugin discovery manager")
	
	// Initial scan for plugins and configurations
	if err := pdm.scanPlugins(); err != nil {
		return fmt.Errorf("initial plugin scan failed: %w", err)
	}
	
	if err := pdm.loadConfigurations(); err != nil {
		return fmt.Errorf("failed to load configurations: %w", err)
	}
	
	// Load plugins according to configuration
	if err := pdm.loadConfiguredPlugins(); err != nil {
		return fmt.Errorf("failed to load configured plugins: %w", err)
	}
	
	// Start periodic file scanning if hot reload is enabled
	if pdm.hotReload {
		go pdm.hotReloadMonitor()
	}
	
	// Start periodic scanning
	go pdm.periodicScan()
	
	// Start health checking
	go pdm.healthChecker()
	
	pdm.logger.Info("plugin discovery manager started successfully", log.Fields{
		"loaded_plugins": len(pdm.loadedPlugins),
		"hot_reload":     pdm.hotReload,
	})
	
	return nil
}

// Stop gracefully shuts down the plugin discovery manager
func (pdm *PluginDiscoveryManager) Stop() error {
	pdm.logger.Info("stopping plugin discovery manager")
	
	// Cancel context to stop all goroutines
	pdm.cancel()
	
	// Unload all plugins
	pdm.mutex.Lock()
	for name, managedPlugin := range pdm.loadedPlugins {
		if err := pdm.unloadPluginUnsafe(name); err != nil {
			pdm.logger.Error("failed to unload plugin during shutdown", err, log.Fields{
				"plugin": name,
			})
		} else {
			pdm.logger.Debug("plugin unloaded during shutdown", log.Fields{
				"plugin": managedPlugin.Name,
			})
		}
	}
	pdm.mutex.Unlock()
	
	// File watcher cleanup not needed in simplified version
	
	pdm.logger.Info("plugin discovery manager stopped")
	return nil
}

// scanPlugins discovers available plugin files
func (pdm *PluginDiscoveryManager) scanPlugins() error {
	pdm.logger.Debug("scanning for plugins", log.Fields{
		"plugin_dir": pdm.pluginDir,
	})
	
	if _, err := os.Stat(pdm.pluginDir); os.IsNotExist(err) {
		pdm.logger.Info("plugin directory does not exist, creating it", log.Fields{
			"plugin_dir": pdm.pluginDir,
		})
		if err := os.MkdirAll(pdm.pluginDir, 0755); err != nil {
			return fmt.Errorf("failed to create plugin directory: %w", err)
		}
		return nil
	}
	
	pluginCount := 0
	err := filepath.WalkDir(pdm.pluginDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		if d.IsDir() {
			return nil
		}
		
		// Look for plugin files (.so files or executables)
		if strings.HasSuffix(path, ".so") || isExecutable(path) {
			pluginCount++
			pdm.logger.Debug("discovered plugin file", log.Fields{
				"path": path,
				"name": d.Name(),
			})
		}
		
		return nil
	})
	
	if err != nil {
		return fmt.Errorf("failed to scan plugin directory: %w", err)
	}
	
	pdm.logger.Info("plugin scan completed", log.Fields{
		"plugin_count": pluginCount,
	})
	
	pdm.metrics.IncrementCounter("plugin_scans")
	return nil
}

// loadConfigurations loads plugin configuration files
func (pdm *PluginDiscoveryManager) loadConfigurations() error {
	pdm.logger.Debug("loading plugin configurations", log.Fields{
		"config_dir": pdm.configDir,
	})
	
	if _, err := os.Stat(pdm.configDir); os.IsNotExist(err) {
		pdm.logger.Info("config directory does not exist, creating it", log.Fields{
			"config_dir": pdm.configDir,
		})
		if err := os.MkdirAll(pdm.configDir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
		return nil
	}
	
	configCount := 0
	err := filepath.WalkDir(pdm.configDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		if d.IsDir() {
			return nil
		}
		
		// Look for YAML configuration files
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			config, err := pdm.loadConfigurationFile(path)
			if err != nil {
				pdm.logger.Error("failed to load configuration file", err, log.Fields{
					"path": path,
				})
				return nil // Continue with other files
			}
			
			pdm.pluginConfigs[config.Name] = config
			configCount++
			
			pdm.logger.Debug("loaded plugin configuration", log.Fields{
				"plugin": config.Name,
				"path":   path,
				"enabled": config.Enabled,
			})
		}
		
		return nil
	})
	
	if err != nil {
		return fmt.Errorf("failed to scan config directory: %w", err)
	}
	
	pdm.logger.Info("configuration loading completed", log.Fields{
		"config_count": configCount,
	})
	
	return nil
}

// loadConfigurationFile loads a single configuration file
func (pdm *PluginDiscoveryManager) loadConfigurationFile(path string) (*PluginConfiguration, error) {
	// This would use a YAML parser to load the configuration
	// For now, return a basic configuration structure
	filename := filepath.Base(path)
	name := strings.TrimSuffix(filename, filepath.Ext(filename))
	
	config := &PluginConfiguration{
		Name:        name,
		Version:     "1.0.0",
		Description: fmt.Sprintf("Plugin %s loaded from %s", name, path),
		Type:        PluginTypeSimpleAuth,
		Enabled:     true,
		AutoLoad:    true,
		HotReload:   true,
		Resources: PluginResources{
			MaxMemoryMB:    256,
			MaxConnections: 100,
			Timeout:        30 * time.Second,
		},
		HealthCheck: HealthCheckConfig{
			Enabled:          true,
			Interval:         30 * time.Second,
			Timeout:          5 * time.Second,
			FailThreshold:    3,
			SuccessThreshold: 2,
		},
		Config: make(map[string]interface{}),
	}
	
	return config, nil
}

// loadConfiguredPlugins loads plugins according to their configuration
func (pdm *PluginDiscoveryManager) loadConfiguredPlugins() error {
	pdm.logger.Info("loading configured plugins", log.Fields{
		"config_count": len(pdm.pluginConfigs),
	})
	
	loadedCount := 0
	for name, config := range pdm.pluginConfigs {
		if !config.Enabled || !config.AutoLoad {
			pdm.logger.Debug("skipping plugin (disabled or not auto-load)", log.Fields{
				"plugin":    name,
				"enabled":   config.Enabled,
				"auto_load": config.AutoLoad,
			})
			continue
		}
		
		if err := pdm.loadPlugin(name); err != nil {
			pdm.logger.Error("failed to load plugin", err, log.Fields{
				"plugin": name,
			})
			continue
		}
		
		loadedCount++
	}
	
	pdm.logger.Info("configured plugins loaded", log.Fields{
		"loaded_count": loadedCount,
		"total_configs": len(pdm.pluginConfigs),
	})
	
	return nil
}

// loadPlugin loads a specific plugin
func (pdm *PluginDiscoveryManager) loadPlugin(name string) error {
	start := time.Now()
	pdm.logger.Info("loading plugin", log.Fields{
		"plugin": name,
	})
	
	pdm.mutex.Lock()
	defer pdm.mutex.Unlock()
	
	// Check if already loaded
	if existing, exists := pdm.loadedPlugins[name]; exists {
		if existing.Status == PluginStatusActive {
			return fmt.Errorf("plugin %s is already loaded", name)
		}
	}
	
	// Get configuration
	config, exists := pdm.pluginConfigs[name]
	if !exists {
		return fmt.Errorf("no configuration found for plugin %s", name)
	}
	
	// Create managed plugin instance
	managedPlugin := &ManagedPlugin{
		Name:       name,
		Version:    config.Version,
		ConfigPath: "", // Would be set from actual config file path
		LoadTime:   time.Now(),
		Status:     PluginStatusLoading,
		Config:     config,
		Health: PluginHealth{
			Healthy:       false,
			CheckInterval: config.HealthCheck.Interval,
		},
		Dependencies: config.Dependencies,
	}
	
	// For demonstration, create a mock plugin interface
	// In real implementation, this would load the actual plugin binary
	managedPlugin.Interface = pdm.createMockPlugin(name, config)
	managedPlugin.Status = PluginStatusActive
	managedPlugin.Health.Healthy = true
	managedPlugin.Health.LastCheck = time.Now()
	managedPlugin.LoadCount++
	
	pdm.loadedPlugins[name] = managedPlugin
	
	// Call load handler if configured
	if pdm.onPluginLoad != nil {
		if err := pdm.onPluginLoad(managedPlugin); err != nil {
			delete(pdm.loadedPlugins, name)
			return fmt.Errorf("plugin load handler failed: %w", err)
		}
	}
	
	duration := time.Since(start)
	pdm.metrics.RecordDuration("plugin_load", duration)
	pdm.metrics.IncrementCounter("plugins_loaded")
	
	pdm.logger.Info("plugin loaded successfully", log.Fields{
		"plugin":   name,
		"duration": duration,
		"status":   managedPlugin.Status,
	})
	
	return nil
}

// unloadPluginUnsafe unloads a plugin without locking (internal use)
func (pdm *PluginDiscoveryManager) unloadPluginUnsafe(name string) error {
	managedPlugin, exists := pdm.loadedPlugins[name]
	if !exists {
		return fmt.Errorf("plugin %s is not loaded", name)
	}
	
	managedPlugin.Status = PluginStatusUnloading
	
	// Call unload handler if configured
	if pdm.onPluginUnload != nil {
		if err := pdm.onPluginUnload(managedPlugin); err != nil {
			pdm.logger.Error("plugin unload handler failed", err, log.Fields{
				"plugin": name,
			})
		}
	}
	
	delete(pdm.loadedPlugins, name)
	pdm.metrics.IncrementCounter("plugins_unloaded")
	
	return nil
}

// createMockPlugin creates a mock plugin for demonstration
func (pdm *PluginDiscoveryManager) createMockPlugin(name string, config *PluginConfiguration) StandardPluginInterface {
	// This would be replaced with actual plugin loading logic
	return &MockPlugin{
		name:        name,
		version:     config.Version,
		description: config.Description,
		pluginType:  config.Type,
	}
}

// MockPlugin is a demonstration plugin implementation
type MockPlugin struct {
	name        string
	version     string
	description string
	pluginType  PluginType
}

func (mp *MockPlugin) GetName() string                                                                           { return mp.name }
func (mp *MockPlugin) GetVersion() string                                                                        { return mp.version }
func (mp *MockPlugin) GetDescription() string                                                                    { return mp.description }
func (mp *MockPlugin) GetType() PluginType                                                                      { return mp.pluginType }
func (mp *MockPlugin) GetFlags() []cli.Flag                                                                 { return nil }
func (mp *MockPlugin) ParseConfig(c *cli.Context) (interface{}, error)                                         { return nil, nil }
func (mp *MockPlugin) ValidateConfig(config interface{}) error                                                  { return nil }
func (mp *MockPlugin) TestPassword(config interface{}, conn ConnMetadata, password []byte) (*Upstream, error) { return nil, fmt.Errorf("not implemented") }
func (mp *MockPlugin) AuthorizedKeys(config interface{}, conn ConnMetadata, key []byte) (*Upstream, error)    { return nil, fmt.Errorf("not implemented") }

// hotReloadMonitor monitors for changes and triggers hot reloads
func (pdm *PluginDiscoveryManager) hotReloadMonitor() {
	ticker := time.NewTicker(5 * time.Second) // Check every 5 seconds
	defer ticker.Stop()
	
	// Track file modification times
	pluginFiles := make(map[string]time.Time)
	configFiles := make(map[string]time.Time)
	
	// Initial scan
	pdm.scanFileModTimes(pluginFiles, configFiles)
	
	for {
		select {
		case <-ticker.C:
			pdm.checkForChanges(pluginFiles, configFiles)
		case <-pdm.ctx.Done():
			return
		}
	}
}

// scanFileModTimes scans and records file modification times
func (pdm *PluginDiscoveryManager) scanFileModTimes(pluginFiles, configFiles map[string]time.Time) {
	// Scan plugin directory
	if _, err := os.Stat(pdm.pluginDir); err == nil {
		filepath.WalkDir(pdm.pluginDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			
			if strings.HasSuffix(path, ".so") || isExecutable(path) {
				if info, err := d.Info(); err == nil {
					pluginFiles[path] = info.ModTime()
				}
			}
			return nil
		})
	}
	
	// Scan config directory
	if _, err := os.Stat(pdm.configDir); err == nil {
		filepath.WalkDir(pdm.configDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			
			if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
				if info, err := d.Info(); err == nil {
					configFiles[path] = info.ModTime()
				}
			}
			return nil
		})
	}
}

// checkForChanges checks for file changes and triggers reloads
func (pdm *PluginDiscoveryManager) checkForChanges(pluginFiles, configFiles map[string]time.Time) {
	newPluginFiles := make(map[string]time.Time)
	newConfigFiles := make(map[string]time.Time)
	
	pdm.scanFileModTimes(newPluginFiles, newConfigFiles)
	
	// Check for plugin file changes
	for path, newTime := range newPluginFiles {
		if oldTime, exists := pluginFiles[path]; exists {
			if newTime.After(oldTime) {
				pdm.handlePluginFileChange(path)
			}
		} else {
			// New file
			pdm.handlePluginFileChange(path)
		}
		pluginFiles[path] = newTime
	}
	
	// Check for config file changes
	for path, newTime := range newConfigFiles {
		if oldTime, exists := configFiles[path]; exists {
			if newTime.After(oldTime) {
				pdm.handleConfigFileChange(path)
			}
		} else {
			// New file
			pdm.handleConfigFileChange(path)
		}
		configFiles[path] = newTime
	}
}

// handleConfigFileChange processes configuration file changes
func (pdm *PluginDiscoveryManager) handleConfigFileChange(path string) {
	filename := filepath.Base(path)
	pluginName := strings.TrimSuffix(filename, filepath.Ext(filename))
	
	pdm.logger.Info("configuration file changed, reloading", log.Fields{
		"plugin": pluginName,
		"path":   path,
	})
	
	// Reload configuration and plugin if needed
	if err := pdm.reloadPluginConfig(pluginName, path); err != nil {
		pdm.logger.Error("failed to reload plugin configuration", err, log.Fields{
			"plugin": pluginName,
		})
	}
}

// handlePluginFileChange processes plugin file changes
func (pdm *PluginDiscoveryManager) handlePluginFileChange(path string) {
	filename := filepath.Base(path)
	pluginName := strings.TrimSuffix(filename, filepath.Ext(filename))
	
	pdm.logger.Info("plugin file changed, reloading", log.Fields{
		"plugin": pluginName,
		"path":   path,
	})
	
	// Reload plugin
	if err := pdm.reloadPlugin(pluginName); err != nil {
		pdm.logger.Error("failed to reload plugin", err, log.Fields{
			"plugin": pluginName,
		})
	}
}

// reloadPluginConfig reloads configuration for a plugin
func (pdm *PluginDiscoveryManager) reloadPluginConfig(pluginName, configPath string) error {
	// Load new configuration
	newConfig, err := pdm.loadConfigurationFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to load new configuration: %w", err)
	}
	
	pdm.mutex.Lock()
	defer pdm.mutex.Unlock()
	
	// Update configuration
	pdm.pluginConfigs[pluginName] = newConfig
	
	// If plugin is loaded and hot reload is enabled, reload it
	if managedPlugin, exists := pdm.loadedPlugins[pluginName]; exists {
		if newConfig.HotReload {
			return pdm.reloadPluginWithNewConfig(managedPlugin, newConfig)
		}
	}
	
	return nil
}

// reloadPlugin reloads a specific plugin
func (pdm *PluginDiscoveryManager) reloadPlugin(pluginName string) error {
	pdm.mutex.Lock()
	defer pdm.mutex.Unlock()
	
	managedPlugin, exists := pdm.loadedPlugins[pluginName]
	if !exists {
		return fmt.Errorf("plugin %s is not loaded", pluginName)
	}
	
	config := managedPlugin.Config
	if !config.HotReload {
		return fmt.Errorf("plugin %s does not support hot reload", pluginName)
	}
	
	// Create new plugin instance
	newManagedPlugin := &ManagedPlugin{
		Name:         pluginName,
		Version:      config.Version,
		ConfigPath:   managedPlugin.ConfigPath,
		LoadTime:     time.Now(),
		LastReload:   time.Now(),
		Status:       PluginStatusLoading,
		Config:       config,
		LoadCount:    managedPlugin.LoadCount + 1,
		Dependencies: config.Dependencies,
		Health: PluginHealth{
			Healthy:       false,
			CheckInterval: config.HealthCheck.Interval,
		},
	}
	
	// Load new plugin instance
	newManagedPlugin.Interface = pdm.createMockPlugin(pluginName, config)
	newManagedPlugin.Status = PluginStatusActive
	newManagedPlugin.Health.Healthy = true
	newManagedPlugin.Health.LastCheck = time.Now()
	
	// Call reload handler if configured
	if pdm.onPluginReload != nil {
		if err := pdm.onPluginReload(managedPlugin, newManagedPlugin); err != nil {
			return fmt.Errorf("plugin reload handler failed: %w", err)
		}
	}
	
	// Replace old plugin with new one
	pdm.loadedPlugins[pluginName] = newManagedPlugin
	pdm.metrics.IncrementCounter("plugins_reloaded")
	
	pdm.logger.Info("plugin reloaded successfully", log.Fields{
		"plugin":      pluginName,
		"load_count":  newManagedPlugin.LoadCount,
		"last_reload": newManagedPlugin.LastReload,
	})
	
	return nil
}

// reloadPluginWithNewConfig reloads a plugin with new configuration
func (pdm *PluginDiscoveryManager) reloadPluginWithNewConfig(oldPlugin *ManagedPlugin, newConfig *PluginConfiguration) error {
	// Implementation for reloading with new configuration
	oldPlugin.Config = newConfig
	oldPlugin.LastReload = time.Now()
	oldPlugin.LoadCount++
	
	pdm.logger.Info("plugin configuration reloaded", log.Fields{
		"plugin": oldPlugin.Name,
		"version": newConfig.Version,
	})
	
	return nil
}

// periodicScan performs periodic plugin discovery
func (pdm *PluginDiscoveryManager) periodicScan() {
	ticker := time.NewTicker(pdm.scanInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			pdm.logger.Debug("performing periodic plugin scan")
			
			if err := pdm.scanPlugins(); err != nil {
				pdm.logger.Error("periodic plugin scan failed", err)
			}
			
			if err := pdm.loadConfigurations(); err != nil {
				pdm.logger.Error("periodic configuration load failed", err)
			}
			
		case <-pdm.ctx.Done():
			return
		}
	}
}

// healthChecker performs periodic health checks on loaded plugins
func (pdm *PluginDiscoveryManager) healthChecker() {
	ticker := time.NewTicker(30 * time.Second) // Base health check interval
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			pdm.checkPluginHealth()
			
		case <-pdm.ctx.Done():
			return
		}
	}
}

// checkPluginHealth checks the health of all loaded plugins
func (pdm *PluginDiscoveryManager) checkPluginHealth() {
	pdm.mutex.RLock()
	plugins := make([]*ManagedPlugin, 0, len(pdm.loadedPlugins))
	for _, plugin := range pdm.loadedPlugins {
		plugins = append(plugins, plugin)
	}
	pdm.mutex.RUnlock()
	
	for _, plugin := range plugins {
		if plugin.Config.HealthCheck.Enabled {
			pdm.performHealthCheck(plugin)
		}
	}
}

// performHealthCheck performs a health check on a specific plugin
func (pdm *PluginDiscoveryManager) performHealthCheck(plugin *ManagedPlugin) {
	start := time.Now()
	
	// Simple health check - in real implementation this would test plugin functionality
	healthy := plugin.Status == PluginStatusActive && plugin.Interface != nil
	duration := time.Since(start)
	
	plugin.Health.Healthy = healthy
	plugin.Health.LastCheck = time.Now()
	plugin.Health.ResponseTime = duration
	
	if healthy {
		pdm.metrics.IncrementCounter("health_checks_success")
	} else {
		pdm.metrics.IncrementCounter("health_checks_failed")
	}
	
	pdm.logger.Debug("health check completed", log.Fields{
		"plugin":   plugin.Name,
		"healthy":  healthy,
		"duration": duration,
	})
}

// GetLoadedPlugins returns information about all loaded plugins
func (pdm *PluginDiscoveryManager) GetLoadedPlugins() map[string]*ManagedPlugin {
	pdm.mutex.RLock()
	defer pdm.mutex.RUnlock()
	
	result := make(map[string]*ManagedPlugin)
	for name, plugin := range pdm.loadedPlugins {
		// Create a copy to avoid race conditions
		pluginCopy := *plugin
		result[name] = &pluginCopy
	}
	
	return result
}

// GetPluginStatus returns the status of a specific plugin
func (pdm *PluginDiscoveryManager) GetPluginStatus(name string) (*ManagedPlugin, error) {
	pdm.mutex.RLock()
	defer pdm.mutex.RUnlock()
	
	plugin, exists := pdm.loadedPlugins[name]
	if !exists {
		return nil, fmt.Errorf("plugin %s not found", name)
	}
	
	// Return a copy
	pluginCopy := *plugin
	return &pluginCopy, nil
}

// SetPluginLoadHandler sets the callback for plugin load events
func (pdm *PluginDiscoveryManager) SetPluginLoadHandler(handler func(plugin *ManagedPlugin) error) {
	pdm.onPluginLoad = handler
}

// SetPluginUnloadHandler sets the callback for plugin unload events
func (pdm *PluginDiscoveryManager) SetPluginUnloadHandler(handler func(plugin *ManagedPlugin) error) {
	pdm.onPluginUnload = handler
}

// SetPluginReloadHandler sets the callback for plugin reload events
func (pdm *PluginDiscoveryManager) SetPluginReloadHandler(handler func(old, new *ManagedPlugin) error) {
	pdm.onPluginReload = handler
}

// Helper function to check if a file is executable
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	
	mode := info.Mode()
	return mode&0111 != 0
}