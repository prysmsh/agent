package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// PrometheusCollector implements prometheus.Collector for custom metrics
type PrometheusCollector struct {
	// Framework metrics
	frameworkMetrics *FrameworkMetrics
	
	// Dynamic metrics storage
	counters   map[string]*prometheus.CounterVec
	gauges     map[string]*prometheus.GaugeVec
	histograms map[string]*prometheus.HistogramVec
	summaries  map[string]*prometheus.SummaryVec
	
	// Mutex for thread-safe operations
	mu sync.RWMutex
	
	// Registry reference
	registry prometheus.Registerer
}

// FrameworkMetrics contains core framework metrics
type FrameworkMetrics struct {
	// Collection metrics
	MetricsCollected    *prometheus.CounterVec
	CollectionDuration  *prometheus.HistogramVec
	CollectionErrors    *prometheus.CounterVec
	BufferSize          *prometheus.GaugeVec
	BufferOverflows     *prometheus.CounterVec
	
	// Plugin metrics
	PluginHealth        *prometheus.GaugeVec
	PluginMetrics       *prometheus.CounterVec
	PluginErrors        *prometheus.CounterVec
	PluginDuration      *prometheus.HistogramVec
	
	// Security metrics
	SecurityEvents      *prometheus.CounterVec
	ThreatLevel         *prometheus.GaugeVec
	AnomaliesDetected   *prometheus.CounterVec
	
	// Performance metrics
	SystemCPU           *prometheus.GaugeVec
	SystemMemory        *prometheus.GaugeVec
	SystemDisk          *prometheus.GaugeVec
	NetworkTraffic      *prometheus.CounterVec
	
	// Business metrics
	SLACompliance       *prometheus.GaugeVec
	UserSessions        *prometheus.GaugeVec
	APIRequests         *prometheus.CounterVec
	ResponseTime        *prometheus.HistogramVec
}

// NewPrometheusCollector creates a new Prometheus collector
func NewPrometheusCollector() *PrometheusCollector {
	collector := &PrometheusCollector{
		counters:   make(map[string]*prometheus.CounterVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
		histograms: make(map[string]*prometheus.HistogramVec),
		summaries:  make(map[string]*prometheus.SummaryVec),
	}
	
	collector.initFrameworkMetrics()
	return collector
}

// initFrameworkMetrics initializes core framework metrics
func (c *PrometheusCollector) initFrameworkMetrics() {
	c.frameworkMetrics = &FrameworkMetrics{
		// Collection metrics
		MetricsCollected: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_metrics_collected_total",
				Help: "Total number of metrics collected",
			},
			[]string{"plugin", "category", "severity"},
		),
		
		CollectionDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "kubeaccess_collection_duration_seconds",
				Help:    "Time spent collecting metrics",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"plugin"},
		),
		
		CollectionErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_collection_errors_total",
				Help: "Total number of collection errors",
			},
			[]string{"plugin", "error_type"},
		),
		
		BufferSize: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_buffer_size",
				Help: "Current size of metrics buffer",
			},
			[]string{"buffer_type"},
		),
		
		BufferOverflows: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_buffer_overflows_total",
				Help: "Total number of buffer overflows",
			},
			[]string{"buffer_type"},
		),
		
		// Plugin metrics
		PluginHealth: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_plugin_health",
				Help: "Plugin health status (1=healthy, 0=unhealthy)",
			},
			[]string{"plugin"},
		),
		
		PluginMetrics: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_plugin_metrics_total",
				Help: "Total metrics produced by plugin",
			},
			[]string{"plugin"},
		),
		
		PluginErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_plugin_errors_total",
				Help: "Total errors from plugin",
			},
			[]string{"plugin", "error_type"},
		),
		
		PluginDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "kubeaccess_plugin_duration_seconds",
				Help:    "Plugin execution duration",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"plugin"},
		),
		
		// Security metrics
		SecurityEvents: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_security_events_total",
				Help: "Total number of security events",
			},
			[]string{"event_type", "severity", "source"},
		),
		
		ThreatLevel: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_threat_level",
				Help: "Current threat level",
			},
			[]string{"component", "threat_type"},
		),
		
		AnomaliesDetected: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_anomalies_detected_total",
				Help: "Total number of anomalies detected",
			},
			[]string{"component", "anomaly_type"},
		),
		
		// Performance metrics
		SystemCPU: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_system_cpu_usage_percent",
				Help: "System CPU usage percentage",
			},
			[]string{"component", "cpu_type"},
		),
		
		SystemMemory: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_system_memory_usage_bytes",
				Help: "System memory usage in bytes",
			},
			[]string{"component", "memory_type"},
		),
		
		SystemDisk: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_system_disk_usage_bytes",
				Help: "System disk usage in bytes",
			},
			[]string{"component", "disk_type"},
		),
		
		NetworkTraffic: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_network_traffic_bytes_total",
				Help: "Total network traffic in bytes",
			},
			[]string{"component", "direction", "protocol"},
		),
		
		// Business metrics
		SLACompliance: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_sla_compliance_percent",
				Help: "SLA compliance percentage",
			},
			[]string{"service", "sla_type"},
		),
		
		UserSessions: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_user_sessions_active",
				Help: "Number of active user sessions",
			},
			[]string{"cluster", "user_type"},
		),
		
		APIRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_api_requests_total",
				Help: "Total number of API requests",
			},
			[]string{"endpoint", "method", "status_code"},
		),
		
		ResponseTime: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "kubeaccess_api_response_time_seconds",
				Help:    "API response time in seconds",
				Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10},
			},
			[]string{"endpoint", "method"},
		),
	}
}

// UpdateMetric updates a metric in Prometheus
func (c *PrometheusCollector) UpdateMetric(metric Metric) {
	// Update framework metrics
	c.frameworkMetrics.MetricsCollected.WithLabelValues(
		metric.Plugin,
		string(metric.Category),
		string(metric.Severity),
	).Inc()
	
	// Create/update specific metric based on type
	switch metric.Type {
	case MetricTypeCounter:
		c.updateCounter(metric)
	case MetricTypeGauge:
		c.updateGauge(metric)
	case MetricTypeHistogram:
		c.updateHistogram(metric)
	case MetricTypeSummary:
		c.updateSummary(metric)
	}
	
	// Handle security events
	if metric.Security != nil {
		c.updateSecurityMetrics(metric)
	}
}

// updateCounter updates or creates a counter metric
func (c *PrometheusCollector) updateCounter(metric Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	metricName := c.buildMetricName(metric)
	labels := c.extractLabelNames(metric.Labels)
	
	counter, exists := c.counters[metricName]
	if !exists {
		counter = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: metricName,
				Help: c.buildHelpText(metric),
			},
			labels,
		)
		c.counters[metricName] = counter
	}
	
	if value, ok := metric.Value.(float64); ok {
		counter.WithLabelValues(c.extractLabelValues(metric.Labels, labels)...).Add(value)
	}
}

// updateGauge updates or creates a gauge metric
func (c *PrometheusCollector) updateGauge(metric Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	metricName := c.buildMetricName(metric)
	labels := c.extractLabelNames(metric.Labels)
	
	gauge, exists := c.gauges[metricName]
	if !exists {
		gauge = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: metricName,
				Help: c.buildHelpText(metric),
			},
			labels,
		)
		c.gauges[metricName] = gauge
	}
	
	if value, ok := metric.Value.(float64); ok {
		gauge.WithLabelValues(c.extractLabelValues(metric.Labels, labels)...).Set(value)
	}
}

// updateHistogram updates or creates a histogram metric
func (c *PrometheusCollector) updateHistogram(metric Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	metricName := c.buildMetricName(metric)
	labels := c.extractLabelNames(metric.Labels)
	
	histogram, exists := c.histograms[metricName]
	if !exists {
		histogram = prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    metricName,
				Help:    c.buildHelpText(metric),
				Buckets: prometheus.DefBuckets,
			},
			labels,
		)
		c.histograms[metricName] = histogram
	}
	
	if value, ok := metric.Value.(float64); ok {
		histogram.WithLabelValues(c.extractLabelValues(metric.Labels, labels)...).Observe(value)
	}
}

// updateSummary updates or creates a summary metric
func (c *PrometheusCollector) updateSummary(metric Metric) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	metricName := c.buildMetricName(metric)
	labels := c.extractLabelNames(metric.Labels)
	
	summary, exists := c.summaries[metricName]
	if !exists {
		summary = prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Name:       metricName,
				Help:       c.buildHelpText(metric),
				Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
			},
			labels,
		)
		c.summaries[metricName] = summary
	}
	
	if value, ok := metric.Value.(float64); ok {
		summary.WithLabelValues(c.extractLabelValues(metric.Labels, labels)...).Observe(value)
	}
}

// updateSecurityMetrics updates security-specific metrics
func (c *PrometheusCollector) updateSecurityMetrics(metric Metric) {
	if metric.Security.Anomaly {
		c.frameworkMetrics.AnomaliesDetected.WithLabelValues(
			metric.Component,
			"security_anomaly",
		).Inc()
	}
	
	if metric.Security.ThreatLevel != ThreatLevelNone {
		threatValue := c.threatLevelToValue(metric.Security.ThreatLevel)
		c.frameworkMetrics.ThreatLevel.WithLabelValues(
			metric.Component,
			string(metric.Security.ThreatLevel),
		).Set(threatValue)
	}
}

// buildMetricName creates a Prometheus-compatible metric name
func (c *PrometheusCollector) buildMetricName(metric Metric) string {
	return "kubeaccess_" + metric.Plugin + "_" + metric.Name
}

// buildHelpText creates help text for the metric
func (c *PrometheusCollector) buildHelpText(metric Metric) string {
	return metric.Component + " " + metric.Name + " metric from " + metric.Plugin + " plugin"
}

// extractLabelNames extracts label names from metric labels
func (c *PrometheusCollector) extractLabelNames(labels map[string]string) []string {
	names := make([]string, 0, len(labels))
	for name := range labels {
		names = append(names, name)
	}
	return names
}

// extractLabelValues extracts label values in correct order
func (c *PrometheusCollector) extractLabelValues(labels map[string]string, names []string) []string {
	values := make([]string, len(names))
	for i, name := range names {
		values[i] = labels[name]
	}
	return values
}

// threatLevelToValue converts threat level to numeric value
func (c *PrometheusCollector) threatLevelToValue(level ThreatLevel) float64 {
	switch level {
	case ThreatLevelNone:
		return 0
	case ThreatLevelLow:
		return 1
	case ThreatLevelMedium:
		return 2
	case ThreatLevelHigh:
		return 3
	case ThreatLevelCritical:
		return 4
	default:
		return 0
	}
}

// RecordCollectionDuration records how long a plugin took to collect metrics
func (c *PrometheusCollector) RecordCollectionDuration(pluginName string, duration time.Duration) {
	c.frameworkMetrics.CollectionDuration.WithLabelValues(pluginName).Observe(duration.Seconds())
}

// RecordCollectionError records a collection error
func (c *PrometheusCollector) RecordCollectionError(pluginName, errorType string) {
	c.frameworkMetrics.CollectionErrors.WithLabelValues(pluginName, errorType).Inc()
}

// UpdateBufferSize updates buffer size metric
func (c *PrometheusCollector) UpdateBufferSize(bufferType string, size float64) {
	c.frameworkMetrics.BufferSize.WithLabelValues(bufferType).Set(size)
}

// RecordBufferOverflow records a buffer overflow
func (c *PrometheusCollector) RecordBufferOverflow(bufferType string) {
	c.frameworkMetrics.BufferOverflows.WithLabelValues(bufferType).Inc()
}

// UpdatePluginHealth updates plugin health metric
func (c *PrometheusCollector) UpdatePluginHealth(pluginName string, healthy bool) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	c.frameworkMetrics.PluginHealth.WithLabelValues(pluginName).Set(value)
}

// Describe implements prometheus.Collector
func (c *PrometheusCollector) Describe(ch chan<- *prometheus.Desc) {
	// Framework metrics
	c.frameworkMetrics.MetricsCollected.Describe(ch)
	c.frameworkMetrics.CollectionDuration.Describe(ch)
	c.frameworkMetrics.CollectionErrors.Describe(ch)
	// ... describe all other framework metrics
	
	// Dynamic metrics
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	for _, counter := range c.counters {
		counter.Describe(ch)
	}
	for _, gauge := range c.gauges {
		gauge.Describe(ch)
	}
	for _, histogram := range c.histograms {
		histogram.Describe(ch)
	}
	for _, summary := range c.summaries {
		summary.Describe(ch)
	}
}

// Collect implements prometheus.Collector
func (c *PrometheusCollector) Collect(ch chan<- prometheus.Metric) {
	// Framework metrics
	c.frameworkMetrics.MetricsCollected.Collect(ch)
	c.frameworkMetrics.CollectionDuration.Collect(ch)
	c.frameworkMetrics.CollectionErrors.Collect(ch)
	// ... collect all other framework metrics
	
	// Dynamic metrics
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	for _, counter := range c.counters {
		counter.Collect(ch)
	}
	for _, gauge := range c.gauges {
		gauge.Collect(ch)
	}
	for _, histogram := range c.histograms {
		histogram.Collect(ch)
	}
	for _, summary := range c.summaries {
		summary.Collect(ch)
	}
}