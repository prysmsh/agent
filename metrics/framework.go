package metrics

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// MetricsFramework orchestrates plugin-based metrics collection
type MetricsFramework struct {
	config    *Config
	plugins   map[string]Plugin
	registry  *prometheus.Registry
	buffer    *MetricsBuffer
	collector *PrometheusCollector
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	handlerMu sync.RWMutex
	handlers  []BatchHandler
}

// Config holds framework configuration
type Config struct {
	// Collection settings
	CollectionInterval time.Duration `json:"collection_interval" yaml:"collection_interval"`
	BatchSize          int           `json:"batch_size" yaml:"batch_size"`
	BufferSize         int           `json:"buffer_size" yaml:"buffer_size"`

	// Performance settings
	EnableSampling bool    `json:"enable_sampling" yaml:"enable_sampling"`
	SampleRate     float64 `json:"sample_rate" yaml:"sample_rate"`
	MaxConcurrency int     `json:"max_concurrency" yaml:"max_concurrency"`

	// Retention settings
	RetentionPeriod    time.Duration `json:"retention_period" yaml:"retention_period"`
	CompactionInterval time.Duration `json:"compaction_interval" yaml:"compaction_interval"`

	// Security settings
	EnableSecurity   bool    `json:"enable_security" yaml:"enable_security"`
	ThreatDetection  bool    `json:"threat_detection" yaml:"threat_detection"`
	AnomalyThreshold float64 `json:"anomaly_threshold" yaml:"anomaly_threshold"`

	// Ray integration
	EnableRay         bool   `json:"enable_ray" yaml:"enable_ray"`
	RayClusterAddress string `json:"ray_cluster_address" yaml:"ray_cluster_address"`

	// Plugin configurations
	PluginConfigs map[string]interface{} `json:"plugin_configs" yaml:"plugin_configs"`
}

// DefaultConfig returns sensible defaults for production
func DefaultConfig() *Config {
	return &Config{
		CollectionInterval: 10 * time.Second,
		BatchSize:          1000,
		BufferSize:         10000,
		EnableSampling:     true,
		SampleRate:         1.0, // 100% by default, adjust for high traffic
		MaxConcurrency:     10,
		RetentionPeriod:    24 * time.Hour,
		CompactionInterval: 1 * time.Hour,
		EnableSecurity:     true,
		ThreatDetection:    true,
		AnomalyThreshold:   2.0, // 2 standard deviations
		EnableRay:          false,
		PluginConfigs:      make(map[string]interface{}),
	}
}

// NewFramework creates a new metrics framework instance
func NewFramework(config *Config) *MetricsFramework {
	if config == nil {
		config = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())
	registry := prometheus.NewRegistry()

	// Create custom collector for framework metrics
	collector := NewPrometheusCollector()
	registry.MustRegister(collector)

	return &MetricsFramework{
		config:    config,
		plugins:   make(map[string]Plugin),
		registry:  registry,
		buffer:    NewMetricsBuffer(config.BufferSize),
		collector: collector,
		ctx:       ctx,
		cancel:    cancel,
	}
}

// BatchHandler processes metric batches exported by the framework.
type BatchHandler func(context.Context, []Metric) error

// RegisterBatchHandler attaches a handler that will be invoked for every processed batch.
func (f *MetricsFramework) RegisterBatchHandler(handler BatchHandler) {
	if handler == nil {
		return
	}

	f.handlerMu.Lock()
	defer f.handlerMu.Unlock()
	f.handlers = append(f.handlers, handler)
	log.Printf("Registered metrics batch handler (total: %d)", len(f.handlers))
}

// RegisterPlugin adds a new metrics plugin
func (f *MetricsFramework) RegisterPlugin(plugin Plugin) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	name := plugin.Name()
	if _, exists := f.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}

	// Initialize plugin with framework context
	if err := plugin.Initialize(f.ctx, f.config.PluginConfigs[name]); err != nil {
		return fmt.Errorf("failed to initialize plugin %s: %w", name, err)
	}

	f.plugins[name] = plugin
	log.Printf("Registered metrics plugin: %s", name)

	// Register plugin's Prometheus metrics
	if err := f.registry.Register(plugin.PrometheusCollector()); err != nil {
		log.Printf("Warning: failed to register Prometheus collector for plugin %s: %v", name, err)
	}

	return nil
}

// Start begins metrics collection
func (f *MetricsFramework) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	log.Printf("Starting metrics framework with %d plugins", len(f.plugins))

	// Start buffer processing
	f.wg.Add(1)
	go f.processMetricsBuffer()

	// Start collection for each plugin
	for name, plugin := range f.plugins {
		f.wg.Add(1)
		go f.runPluginCollection(name, plugin)
	}

	// Start compaction if enabled
	if f.config.CompactionInterval > 0 {
		f.wg.Add(1)
		go f.runCompaction()
	}

	// Start security monitoring if enabled
	if f.config.EnableSecurity {
		f.wg.Add(1)
		go f.runSecurityMonitoring()
	}

	return nil
}

// Stop gracefully shuts down the framework
func (f *MetricsFramework) Stop() error {
	log.Println("Stopping metrics framework...")
	f.cancel()
	f.wg.Wait()

	// Shutdown plugins
	f.mu.Lock()
	for name, plugin := range f.plugins {
		if err := plugin.Shutdown(); err != nil {
			log.Printf("Error shutting down plugin %s: %v", name, err)
		}
	}
	f.mu.Unlock()

	log.Println("Metrics framework stopped")
	return nil
}

// GetRegistry returns the Prometheus registry
func (f *MetricsFramework) GetRegistry() *prometheus.Registry {
	return f.registry
}

// runPluginCollection handles collection for a specific plugin
func (f *MetricsFramework) runPluginCollection(name string, plugin Plugin) {
	defer f.wg.Done()

	ticker := time.NewTicker(f.config.CollectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			// Collect metrics with timeout
			collectCtx, cancel := context.WithTimeout(f.ctx, 30*time.Second)

			metrics, err := plugin.Collect(collectCtx)
			cancel()

			if err != nil {
				log.Printf("Error collecting metrics from plugin %s: %v", name, err)
				continue
			}

			// Apply sampling if enabled and configured
			if f.config.EnableSampling && f.shouldSample() {
				f.buffer.Add(metrics...)
			}
		}
	}
}

// processMetricsBuffer handles buffered metrics
func (f *MetricsFramework) processMetricsBuffer() {
	defer f.wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			batch := f.buffer.GetBatch(f.config.BatchSize)
			if len(batch) > 0 {
				f.processBatch(batch)
			}
		}
	}
}

// processBatch processes a batch of metrics
func (f *MetricsFramework) processBatch(batch []Metric) {
	// Update Prometheus metrics
	for _, metric := range batch {
		f.collector.UpdateMetric(metric)
	}

	// Future: Send to Ray for distributed processing
	if f.config.EnableRay {
		f.sendToRay(batch)
	}

	// Deliver batch to registered handlers
	f.handlerMu.RLock()
	handlers := make([]BatchHandler, len(f.handlers))
	copy(handlers, f.handlers)
	f.handlerMu.RUnlock()

	for _, handler := range handlers {
		if handler == nil {
			continue
		}

		batchCopy := make([]Metric, len(batch))
		copy(batchCopy, batch)

		go func(h BatchHandler, metrics []Metric) {
			ctx, cancel := context.WithTimeout(f.ctx, 15*time.Second)
			defer cancel()

			if err := h(ctx, metrics); err != nil {
				log.Printf("Metrics batch handler error: %v", err)
			}
		}(handler, batchCopy)
	}
}

// runCompaction performs periodic data compaction
func (f *MetricsFramework) runCompaction() {
	defer f.wg.Done()

	ticker := time.NewTicker(f.config.CompactionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			log.Println("Running metrics compaction...")
			// Implement compaction logic
			f.compactMetrics()
		}
	}
}

// runSecurityMonitoring monitors for security events
func (f *MetricsFramework) runSecurityMonitoring() {
	defer f.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			f.detectAnomalies()
		}
	}
}

// shouldSample determines if current metric should be sampled
func (f *MetricsFramework) shouldSample() bool {
	// Simple random sampling - can be enhanced with more sophisticated algorithms
	return f.config.SampleRate >= 1.0 ||
		(f.config.SampleRate > 0 && time.Now().UnixNano()%100 < int64(f.config.SampleRate*100))
}

// sendToRay sends metrics to Ray cluster for distributed processing
func (f *MetricsFramework) sendToRay(batch []Metric) {
	// TODO: Implement Ray integration
	log.Printf("Would send %d metrics to Ray cluster at %s", len(batch), f.config.RayClusterAddress)
}

// compactMetrics performs data compaction
func (f *MetricsFramework) compactMetrics() {
	// TODO: Implement metric compaction for storage efficiency
	log.Println("Compacting metrics data...")
}

// detectAnomalies performs anomaly detection on collected metrics
func (f *MetricsFramework) detectAnomalies() {
	// TODO: Implement anomaly detection algorithms
	// This will analyze patterns in metrics to detect security threats,
	// performance anomalies, and operational issues
}

// GetPluginMetrics returns metrics from a specific plugin
func (f *MetricsFramework) GetPluginMetrics(pluginName string) ([]Metric, error) {
	f.mu.RLock()
	plugin, exists := f.plugins[pluginName]
	f.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("plugin %s not found", pluginName)
	}

	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()

	return plugin.Collect(ctx)
}

// GetFrameworkStats returns framework operational statistics
func (f *MetricsFramework) GetFrameworkStats() FrameworkStats {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return FrameworkStats{
		RegisteredPlugins: len(f.plugins),
		BufferSize:        f.buffer.Size(),
		BufferCapacity:    f.config.BufferSize,
		IsRunning:         f.ctx.Err() == nil,
		ConfiguredPlugins: f.getPluginNames(),
	}
}

func (f *MetricsFramework) getPluginNames() []string {
	names := make([]string, 0, len(f.plugins))
	for name := range f.plugins {
		names = append(names, name)
	}
	return names
}

// FrameworkStats contains operational statistics
type FrameworkStats struct {
	RegisteredPlugins int      `json:"registered_plugins"`
	BufferSize        int      `json:"buffer_size"`
	BufferCapacity    int      `json:"buffer_capacity"`
	IsRunning         bool     `json:"is_running"`
	ConfiguredPlugins []string `json:"configured_plugins"`
}
