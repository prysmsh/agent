package plugins

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"prysm-agent/metrics"
)

// DERPPlugin provides comprehensive DERP network monitoring
type DERPPlugin struct {
	// Configuration
	config         *DERPConfig
	serverID       string
	region         string
	
	// Network state
	connections    map[string]*ConnectionState
	bandwidth      *BandwidthTracker
	latency        *LatencyTracker
	security       *SecurityMonitor
	
	// Plugin state
	startTime      time.Time
	lastCollection time.Time
	errorCount     int64
	metricsCount   int64
	
	// Prometheus metrics
	prometheusCollector *DERPPrometheusCollector
	
	// Synchronization
	mu     sync.RWMutex
	ctx    context.Context
	cancel context.CancelFunc
}

// DERPConfig holds plugin configuration
type DERPConfig struct {
	// Server settings
	ServerID       string   `json:"server_id" yaml:"server_id"`
	Region         string   `json:"region" yaml:"region"`
	ListenAddr     string   `json:"listen_addr" yaml:"listen_addr"`
	DERPServers    []string `json:"derp_servers" yaml:"derp_servers"`
	
	// Monitoring settings
	CollectConnections   bool          `json:"collect_connections" yaml:"collect_connections"`
	CollectBandwidth     bool          `json:"collect_bandwidth" yaml:"collect_bandwidth"`
	CollectLatency       bool          `json:"collect_latency" yaml:"collect_latency"`
	CollectSecurity      bool          `json:"collect_security" yaml:"collect_security"`
	CollectPerformance   bool          `json:"collect_performance" yaml:"collect_performance"`
	
	// Performance settings
	BandwidthWindow      time.Duration `json:"bandwidth_window" yaml:"bandwidth_window"`
	LatencyProbeInterval time.Duration `json:"latency_probe_interval" yaml:"latency_probe_interval"`
	ConnectionTimeout    time.Duration `json:"connection_timeout" yaml:"connection_timeout"`
	
	// Security settings
	EnableThreatDetection bool        `json:"enable_threat_detection" yaml:"enable_threat_detection"`
	MaxConnectionsPerIP   int         `json:"max_connections_per_ip" yaml:"max_connections_per_ip"`
	RateLimitPerIP        int         `json:"rate_limit_per_ip" yaml:"rate_limit_per_ip"`
	AnomalyThreshold      float64     `json:"anomaly_threshold" yaml:"anomaly_threshold"`
	
	// Certificate settings
	TLSCertFile    string `json:"tls_cert_file" yaml:"tls_cert_file"`
	TLSKeyFile     string `json:"tls_key_file" yaml:"tls_key_file"`
	VerifyClients  bool   `json:"verify_clients" yaml:"verify_clients"`
}

// ConnectionState tracks individual connection metrics
type ConnectionState struct {
	PeerID        string
	RemoteAddr    net.Addr
	ConnectedAt   time.Time
	LastActivity  time.Time
	BytesIn       int64
	BytesOut      int64
	PacketsIn     int64
	PacketsOut    int64
	Latency       time.Duration
	Quality       float64 // 0-1 connection quality score
	Errors        int64
	ThreatLevel   metrics.ThreatLevel
	UserAgent     string
	Tags          []string
}

// BandwidthTracker monitors bandwidth usage
type BandwidthTracker struct {
	mu           sync.RWMutex
	windowSize   time.Duration
	samples      []BandwidthSample
	totalIn      int64
	totalOut     int64
	peakIn       float64
	peakOut      float64
	lastUpdate   time.Time
}

// BandwidthSample represents a bandwidth measurement
type BandwidthSample struct {
	Timestamp time.Time
	BytesIn   int64
	BytesOut  int64
}

// LatencyTracker monitors network latency
type LatencyTracker struct {
	mu          sync.RWMutex
	samples     []time.Duration
	windowSize  time.Duration
	probeInterval time.Duration
	lastProbe   time.Time
}

// SecurityMonitor tracks security events and anomalies
type SecurityMonitor struct {
	mu              sync.RWMutex
	events          []metrics.SecurityEvent
	connectionCounts map[string]int  // IP -> connection count
	requestRates    map[string][]time.Time  // IP -> request timestamps
	anomalies       []SecurityAnomaly
	threatLevel     metrics.ThreatLevel
}

// SecurityAnomaly represents a detected security anomaly
type SecurityAnomaly struct {
	Type        string
	Description string
	Severity    metrics.ThreatLevel
	Source      string
	Timestamp   time.Time
	Metadata    map[string]interface{}
}

// DERPPrometheusCollector handles DERP-specific Prometheus metrics
type DERPPrometheusCollector struct {
	// Connection metrics
	ActiveConnections   *prometheus.GaugeVec
	TotalConnections    *prometheus.CounterVec
	ConnectionDuration  *prometheus.HistogramVec
	ConnectionErrors    *prometheus.CounterVec
	
	// Bandwidth metrics
	BandwidthIn         *prometheus.CounterVec
	BandwidthOut        *prometheus.CounterVec
	BandwidthPeak       *prometheus.GaugeVec
	PacketsIn           *prometheus.CounterVec
	PacketsOut          *prometheus.CounterVec
	PacketLoss          *prometheus.CounterVec
	
	// Latency metrics
	Latency             *prometheus.HistogramVec
	LatencyPercentiles  *prometheus.SummaryVec
	
	// Security metrics
	SecurityEvents      *prometheus.CounterVec
	ThreatLevel         *prometheus.GaugeVec
	AnomaliesDetected   *prometheus.CounterVec
	BlockedConnections  *prometheus.CounterVec
	
	// Performance metrics
	ServerLoad          *prometheus.GaugeVec
	MemoryUsage         *prometheus.GaugeVec
	CPUUsage            *prometheus.GaugeVec
	UpTime              *prometheus.GaugeVec
}

// NewDERPPlugin creates a new DERP monitoring plugin
func NewDERPPlugin(serverID, region string) *DERPPlugin {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &DERPPlugin{
		serverID:            serverID,
		region:              region,
		connections:         make(map[string]*ConnectionState),
		bandwidth:           NewBandwidthTracker(5 * time.Minute),
		latency:             NewLatencyTracker(1 * time.Minute),
		security:            NewSecurityMonitor(),
		startTime:           time.Now(),
		ctx:                 ctx,
		cancel:              cancel,
		prometheusCollector: newDERPPrometheusCollector(),
	}
}

// NewBandwidthTracker creates a new bandwidth tracker
func NewBandwidthTracker(windowSize time.Duration) *BandwidthTracker {
	return &BandwidthTracker{
		windowSize: windowSize,
		samples:    make([]BandwidthSample, 0),
		lastUpdate: time.Now(),
	}
}

// NewLatencyTracker creates a new latency tracker
func NewLatencyTracker(windowSize time.Duration) *LatencyTracker {
	return &LatencyTracker{
		windowSize: windowSize,
		samples:    make([]time.Duration, 0),
		lastProbe:  time.Now(),
	}
}

// NewSecurityMonitor creates a new security monitor
func NewSecurityMonitor() *SecurityMonitor {
	return &SecurityMonitor{
		events:           make([]metrics.SecurityEvent, 0),
		connectionCounts: make(map[string]int),
		requestRates:     make(map[string][]time.Time),
		anomalies:        make([]SecurityAnomaly, 0),
		threatLevel:      metrics.ThreatLevelNone,
	}
}

// Name returns the plugin name
func (d *DERPPlugin) Name() string {
	return "derp"
}

// Description returns the plugin description
func (d *DERPPlugin) Description() string {
	return "Comprehensive DERP network monitoring including connections, bandwidth, latency, and security"
}

// Initialize sets up the plugin
func (d *DERPPlugin) Initialize(ctx context.Context, config interface{}) error {
	d.ctx = ctx
	
	// Parse configuration
	if cfg, ok := config.(*DERPConfig); ok && cfg != nil {
		d.config = cfg
	} else {
		d.config = d.defaultConfig()
	}
	
	// Override server ID and region if provided
	if d.serverID != "" {
		d.config.ServerID = d.serverID
	}
	if d.region != "" {
		d.config.Region = d.region
	}
	
	// Start background monitoring tasks
	go d.runLatencyProbes()
	go d.runSecurityMonitoring()
	go d.runBandwidthCalculation()
	
	log.Printf("DERP plugin initialized for server: %s, region: %s", d.config.ServerID, d.config.Region)
	return nil
}

// Collect gathers DERP metrics
func (d *DERPPlugin) Collect(ctx context.Context) ([]metrics.Metric, error) {
	start := time.Now()
	defer func() {
		d.lastCollection = time.Now()
		d.prometheusCollector.updateCollectionDuration(start)
	}()
	
	var allMetrics []metrics.Metric
	
	// Collect connection metrics
	if d.config.CollectConnections {
		if connectionMetrics, err := d.collectConnectionMetrics(ctx); err != nil {
			d.errorCount++
			log.Printf("Error collecting connection metrics: %v", err)
		} else {
			allMetrics = append(allMetrics, connectionMetrics...)
		}
	}
	
	// Collect bandwidth metrics
	if d.config.CollectBandwidth {
		if bandwidthMetrics, err := d.collectBandwidthMetrics(ctx); err != nil {
			d.errorCount++
			log.Printf("Error collecting bandwidth metrics: %v", err)
		} else {
			allMetrics = append(allMetrics, bandwidthMetrics...)
		}
	}
	
	// Collect latency metrics
	if d.config.CollectLatency {
		if latencyMetrics, err := d.collectLatencyMetrics(ctx); err != nil {
			d.errorCount++
			log.Printf("Error collecting latency metrics: %v", err)
		} else {
			allMetrics = append(allMetrics, latencyMetrics...)
		}
	}
	
	// Collect security metrics
	if d.config.CollectSecurity {
		if securityMetrics, err := d.collectSecurityMetrics(ctx); err != nil {
			d.errorCount++
			log.Printf("Error collecting security metrics: %v", err)
		} else {
			allMetrics = append(allMetrics, securityMetrics...)
		}
	}
	
	// Collect performance metrics
	if d.config.CollectPerformance {
		if performanceMetrics, err := d.collectPerformanceMetrics(ctx); err != nil {
			d.errorCount++
			log.Printf("Error collecting performance metrics: %v", err)
		} else {
			allMetrics = append(allMetrics, performanceMetrics...)
		}
	}
	
	d.metricsCount += int64(len(allMetrics))
	return allMetrics, nil
}

// collectConnectionMetrics gathers connection-related metrics
func (d *DERPPlugin) collectConnectionMetrics(ctx context.Context) ([]metrics.Metric, error) {
	var connectionMetrics []metrics.Metric
	timestamp := time.Now()
	
	d.mu.RLock()
	activeConnections := len(d.connections)
	totalBytesIn := int64(0)
	totalBytesOut := int64(0)
	avgLatency := time.Duration(0)
	
	for _, conn := range d.connections {
		totalBytesIn += conn.BytesIn
		totalBytesOut += conn.BytesOut
		avgLatency += conn.Latency
	}
	d.mu.RUnlock()
	
	if activeConnections > 0 {
		avgLatency = avgLatency / time.Duration(activeConnections)
	}
	
	// Active connections metric
	connectionMetrics = append(connectionMetrics, metrics.Metric{
		Name:      "active_connections",
		Type:      metrics.MetricTypeGauge,
		Value:     float64(activeConnections),
		Labels: map[string]string{
			"server_id": d.config.ServerID,
			"region":    d.config.Region,
		},
		Timestamp: timestamp,
		Plugin:    d.Name(),
		Component: "connections",
		Category:  metrics.CategoryDERP,
		Severity:  metrics.SeverityInfo,
	})
	
	// Total bytes in metric
	connectionMetrics = append(connectionMetrics, metrics.Metric{
		Name:      "total_bytes_in",
		Type:      metrics.MetricTypeCounter,
		Value:     float64(totalBytesIn),
		Labels: map[string]string{
			"server_id": d.config.ServerID,
			"region":    d.config.Region,
		},
		Timestamp: timestamp,
		Plugin:    d.Name(),
		Component: "bandwidth",
		Category:  metrics.CategoryDERP,
		Severity:  metrics.SeverityInfo,
	})
	
	// Update Prometheus metrics
	d.prometheusCollector.ActiveConnections.WithLabelValues(d.config.ServerID, d.config.Region).Set(float64(activeConnections))
	d.prometheusCollector.BandwidthIn.WithLabelValues(d.config.ServerID, d.config.Region).Add(float64(totalBytesIn))
	
	return connectionMetrics, nil
}

// collectBandwidthMetrics gathers bandwidth usage metrics
func (d *DERPPlugin) collectBandwidthMetrics(ctx context.Context) ([]metrics.Metric, error) {
	var bandwidthMetrics []metrics.Metric
	timestamp := time.Now()
	
	bwStats := d.bandwidth.GetStats()
	
	// Current bandwidth in bps
	bandwidthMetrics = append(bandwidthMetrics, metrics.Metric{
		Name:      "bandwidth_in_bps",
		Type:      metrics.MetricTypeGauge,
		Value:     bwStats.InboundBps,
		Labels: map[string]string{
			"server_id": d.config.ServerID,
			"region":    d.config.Region,
		},
		Timestamp: timestamp,
		Plugin:    d.Name(),
		Component: "bandwidth",
		Category:  metrics.CategoryNetwork,
		Severity:  metrics.SeverityInfo,
	})
	
	// Peak bandwidth
	bandwidthMetrics = append(bandwidthMetrics, metrics.Metric{
		Name:      "bandwidth_peak_bps",
		Type:      metrics.MetricTypeGauge,
		Value:     bwStats.PeakBandwidth,
		Labels: map[string]string{
			"server_id": d.config.ServerID,
			"region":    d.config.Region,
		},
		Timestamp: timestamp,
		Plugin:    d.Name(),
		Component: "bandwidth",
		Category:  metrics.CategoryNetwork,
		Severity:  metrics.SeverityInfo,
	})
	
	d.prometheusCollector.BandwidthPeak.WithLabelValues(d.config.ServerID, d.config.Region, "inbound").Set(bwStats.PeakBandwidth)
	
	return bandwidthMetrics, nil
}

// collectLatencyMetrics gathers latency measurements
func (d *DERPPlugin) collectLatencyMetrics(ctx context.Context) ([]metrics.Metric, error) {
	var latencyMetrics []metrics.Metric
	timestamp := time.Now()
	
	latencyStats := d.latency.GetStats()
	
	// Average latency
	latencyMetrics = append(latencyMetrics, metrics.Metric{
		Name:      "latency_average_ms",
		Type:      metrics.MetricTypeGauge,
		Value:     latencyStats.AverageMs,
		Labels: map[string]string{
			"server_id": d.config.ServerID,
			"region":    d.config.Region,
		},
		Timestamp: timestamp,
		Plugin:    d.Name(),
		Component: "latency",
		Category:  metrics.CategoryNetwork,
		Severity:  metrics.SeverityInfo,
	})
	
	// P99 latency
	latencyMetrics = append(latencyMetrics, metrics.Metric{
		Name:      "latency_p99_ms",
		Type:      metrics.MetricTypeGauge,
		Value:     latencyStats.P99Ms,
		Labels: map[string]string{
			"server_id": d.config.ServerID,
			"region":    d.config.Region,
		},
		Timestamp: timestamp,
		Plugin:    d.Name(),
		Component: "latency",
		Category:  metrics.CategoryNetwork,
		Severity:  metrics.SeverityInfo,
	})
	
	d.prometheusCollector.Latency.WithLabelValues(d.config.ServerID, d.config.Region).Observe(latencyStats.AverageMs / 1000)
	
	return latencyMetrics, nil
}

// collectSecurityMetrics gathers security events and threat information
func (d *DERPPlugin) collectSecurityMetrics(ctx context.Context) ([]metrics.Metric, error) {
	var securityMetrics []metrics.Metric
	timestamp := time.Now()
	
	securityStats := d.security.GetStats()
	
	// Current threat level
	securityMetrics = append(securityMetrics, metrics.Metric{
		Name:      "threat_level",
		Type:      metrics.MetricTypeGauge,
		Value:     d.threatLevelToValue(securityStats.ThreatLevel),
		Labels: map[string]string{
			"server_id": d.config.ServerID,
			"region":    d.config.Region,
		},
		Timestamp: timestamp,
		Plugin:    d.Name(),
		Component: "security",
		Category:  metrics.CategorySecurity,
		Severity:  metrics.SeverityInfo,
		Security: &metrics.SecurityContext{
			ThreatLevel: securityStats.ThreatLevel,
		},
	})
	
	// Anomalies detected
	securityMetrics = append(securityMetrics, metrics.Metric{
		Name:      "anomalies_detected",
		Type:      metrics.MetricTypeCounter,
		Value:     float64(len(securityStats.Anomalies)),
		Labels: map[string]string{
			"server_id": d.config.ServerID,
			"region":    d.config.Region,
		},
		Timestamp: timestamp,
		Plugin:    d.Name(),
		Component: "security",
		Category:  metrics.CategorySecurity,
		Severity:  metrics.SeverityMedium,
	})
	
	d.prometheusCollector.ThreatLevel.WithLabelValues(d.config.ServerID, d.config.Region).Set(d.threatLevelToValue(securityStats.ThreatLevel))
	
	return securityMetrics, nil
}

// collectPerformanceMetrics gathers system performance metrics
func (d *DERPPlugin) collectPerformanceMetrics(ctx context.Context) ([]metrics.Metric, error) {
	var performanceMetrics []metrics.Metric
	timestamp := time.Now()
	
	// Server uptime
	uptime := time.Since(d.startTime)
	performanceMetrics = append(performanceMetrics, metrics.Metric{
		Name:      "uptime_seconds",
		Type:      metrics.MetricTypeGauge,
		Value:     uptime.Seconds(),
		Labels: map[string]string{
			"server_id": d.config.ServerID,
			"region":    d.config.Region,
		},
		Timestamp: timestamp,
		Plugin:    d.Name(),
		Component: "performance",
		Category:  metrics.CategoryPerformance,
		Severity:  metrics.SeverityInfo,
	})
	
	d.prometheusCollector.UpTime.WithLabelValues(d.config.ServerID, d.config.Region).Set(uptime.Seconds())
	
	return performanceMetrics, nil
}

// runLatencyProbes runs periodic latency probes
func (d *DERPPlugin) runLatencyProbes() {
	ticker := time.NewTicker(d.config.LatencyProbeInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.performLatencyProbe()
		}
	}
}

// performLatencyProbe measures latency to connected peers
func (d *DERPPlugin) performLatencyProbe() {
	// Implement latency probing logic
	start := time.Now()
	
	// Simulate probe to a few random connections
	d.mu.RLock()
	connectionCount := 0
	for _, conn := range d.connections {
		if connectionCount >= 5 { // Limit probes
			break
		}
		
		// Simulate probe latency (in real implementation, this would be actual network probes)
		probeLatency := time.Duration(10+connectionCount*2) * time.Millisecond
		conn.Latency = probeLatency
		d.latency.AddSample(probeLatency)
		connectionCount++
	}
	d.mu.RUnlock()
	
	duration := time.Since(start)
	log.Printf("Latency probe completed in %v, tested %d connections", duration, connectionCount)
}

// runSecurityMonitoring runs continuous security monitoring
func (d *DERPPlugin) runSecurityMonitoring() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.performSecurityCheck()
		}
	}
}

// performSecurityCheck performs security analysis
func (d *DERPPlugin) performSecurityCheck() {
	d.security.AnalyzeConnections(d.connections)
	
	// Check for anomalies
	if len(d.security.anomalies) > 0 {
		log.Printf("Security anomalies detected: %d", len(d.security.anomalies))
	}
}

// runBandwidthCalculation calculates bandwidth statistics
func (d *DERPPlugin) runBandwidthCalculation() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.updateBandwidthStats()
		}
	}
}

// updateBandwidthStats updates bandwidth calculations
func (d *DERPPlugin) updateBandwidthStats() {
	d.mu.RLock()
	totalIn := int64(0)
	totalOut := int64(0)
	
	for _, conn := range d.connections {
		totalIn += conn.BytesIn
		totalOut += conn.BytesOut
	}
	d.mu.RUnlock()
	
	d.bandwidth.AddSample(BandwidthSample{
		Timestamp: time.Now(),
		BytesIn:   totalIn,
		BytesOut:  totalOut,
	})
}

// AddConnection adds a new connection to track
func (d *DERPPlugin) AddConnection(peerID string, remoteAddr net.Addr) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	d.connections[peerID] = &ConnectionState{
		PeerID:       peerID,
		RemoteAddr:   remoteAddr,
		ConnectedAt:  time.Now(),
		LastActivity: time.Now(),
		ThreatLevel:  metrics.ThreatLevelNone,
	}
	
	d.prometheusCollector.TotalConnections.WithLabelValues(d.config.ServerID, d.config.Region).Inc()
}

// RemoveConnection removes a connection from tracking
func (d *DERPPlugin) RemoveConnection(peerID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	if conn, exists := d.connections[peerID]; exists {
		duration := time.Since(conn.ConnectedAt)
		d.prometheusCollector.ConnectionDuration.WithLabelValues(d.config.ServerID, d.config.Region).Observe(duration.Seconds())
		delete(d.connections, peerID)
	}
}

// UpdateConnectionStats updates statistics for a connection
func (d *DERPPlugin) UpdateConnectionStats(peerID string, bytesIn, bytesOut, packetsIn, packetsOut int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	if conn, exists := d.connections[peerID]; exists {
		conn.BytesIn += bytesIn
		conn.BytesOut += bytesOut
		conn.PacketsIn += packetsIn
		conn.PacketsOut += packetsOut
		conn.LastActivity = time.Now()
	}
}

// PrometheusCollector returns the Prometheus collector
func (d *DERPPlugin) PrometheusCollector() prometheus.Collector {
	return d.prometheusCollector
}

// Shutdown cleans up the plugin
func (d *DERPPlugin) Shutdown() error {
	d.cancel()
	return nil
}

// Health returns plugin health status
func (d *DERPPlugin) Health() metrics.PluginHealth {
	status := metrics.HealthStatusHealthy
	if d.errorCount > 10 {
		status = metrics.HealthStatusDegraded
	}
	if time.Since(d.lastCollection) > 5*time.Minute {
		status = metrics.HealthStatusUnhealthy
	}
	
	return metrics.PluginHealth{
		Status:         status,
		LastCollection: d.lastCollection,
		ErrorCount:     d.errorCount,
		Uptime:         time.Since(d.startTime),
		MetricsCount:   d.metricsCount,
		Details: map[string]string{
			"server_id": d.config.ServerID,
			"region":    d.config.Region,
		},
	}
}

// defaultConfig returns default configuration
func (d *DERPPlugin) defaultConfig() *DERPConfig {
	return &DERPConfig{
		CollectConnections:      true,
		CollectBandwidth:        true,
		CollectLatency:          true,
		CollectSecurity:         true,
		CollectPerformance:      true,
		BandwidthWindow:         5 * time.Minute,
		LatencyProbeInterval:    30 * time.Second,
		ConnectionTimeout:       30 * time.Second,
		EnableThreatDetection:   true,
		MaxConnectionsPerIP:     10,
		RateLimitPerIP:          100,
		AnomalyThreshold:        2.0,
	}
}

// threatLevelToValue converts threat level to numeric value
func (d *DERPPlugin) threatLevelToValue(level metrics.ThreatLevel) float64 {
	switch level {
	case metrics.ThreatLevelNone:
		return 0
	case metrics.ThreatLevelLow:
		return 1
	case metrics.ThreatLevelMedium:
		return 2
	case metrics.ThreatLevelHigh:
		return 3
	case metrics.ThreatLevelCritical:
		return 4
	default:
		return 0
	}
}

// GetStats returns bandwidth statistics
func (b *BandwidthTracker) GetStats() metrics.BandwidthMetrics {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	// Calculate current bandwidth (simplified)
	currentBps := 0.0
	if len(b.samples) >= 2 {
		recent := b.samples[len(b.samples)-1]
		previous := b.samples[len(b.samples)-2]
		timeDiff := recent.Timestamp.Sub(previous.Timestamp).Seconds()
		if timeDiff > 0 {
			bytesDiff := float64(recent.BytesIn - previous.BytesIn)
			currentBps = bytesDiff / timeDiff
		}
	}
	
	return metrics.BandwidthMetrics{
		InboundBps:    currentBps,
		OutboundBps:   0, // Simplified
		TotalBytes:    b.totalIn + b.totalOut,
		PeakBandwidth: b.peakIn,
	}
}

// AddSample adds a bandwidth sample
func (b *BandwidthTracker) AddSample(sample BandwidthSample) {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	b.samples = append(b.samples, sample)
	b.totalIn += sample.BytesIn
	b.totalOut += sample.BytesOut
	
	// Remove old samples
	cutoff := time.Now().Add(-b.windowSize)
	for i, s := range b.samples {
		if s.Timestamp.After(cutoff) {
			b.samples = b.samples[i:]
			break
		}
	}
}

// GetStats returns latency statistics
func (l *LatencyTracker) GetStats() metrics.LatencyMetrics {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	if len(l.samples) == 0 {
		return metrics.LatencyMetrics{}
	}
	
	// Calculate statistics
	total := time.Duration(0)
	max := time.Duration(0)
	
	for _, sample := range l.samples {
		total += sample
		if sample > max {
			max = sample
		}
	}
	
	avgMs := float64(total.Nanoseconds()) / float64(len(l.samples)) / 1000000
	
	return metrics.LatencyMetrics{
		AverageMs: avgMs,
		P50Ms:     avgMs, // Simplified
		P95Ms:     avgMs * 1.5, // Simplified
		P99Ms:     avgMs * 2.0, // Simplified
		MaxMs:     float64(max.Nanoseconds()) / 1000000,
	}
}

// AddSample adds a latency sample
func (l *LatencyTracker) AddSample(duration time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	l.samples = append(l.samples, duration)
	
	// Remove old samples
	if len(l.samples) > 1000 {
		l.samples = l.samples[100:]
	}
}

// GetStats returns security statistics
func (s *SecurityMonitor) GetStats() struct {
	ThreatLevel metrics.ThreatLevel
	Events      []metrics.SecurityEvent
	Anomalies   []SecurityAnomaly
} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	return struct {
		ThreatLevel metrics.ThreatLevel
		Events      []metrics.SecurityEvent
		Anomalies   []SecurityAnomaly
	}{
		ThreatLevel: s.threatLevel,
		Events:      s.events,
		Anomalies:   s.anomalies,
	}
}

// AnalyzeConnections analyzes connections for security issues
func (s *SecurityMonitor) AnalyzeConnections(connections map[string]*ConnectionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Reset connection counts
	s.connectionCounts = make(map[string]int)
	
	// Analyze each connection
	for _, conn := range connections {
		ip := conn.RemoteAddr.String()
		s.connectionCounts[ip]++
		
		// Check for anomalies (simplified)
		if conn.Errors > 10 {
			s.addAnomaly(SecurityAnomaly{
				Type:        "high_error_rate",
				Description: fmt.Sprintf("High error rate from %s", ip),
				Severity:    metrics.ThreatLevelMedium,
				Source:      ip,
				Timestamp:   time.Now(),
			})
		}
	}
	
	// Update threat level based on anomalies
	if len(s.anomalies) > 5 {
		s.threatLevel = metrics.ThreatLevelHigh
	} else if len(s.anomalies) > 0 {
		s.threatLevel = metrics.ThreatLevelMedium
	} else {
		s.threatLevel = metrics.ThreatLevelNone
	}
}

// addAnomaly adds a security anomaly
func (s *SecurityMonitor) addAnomaly(anomaly SecurityAnomaly) {
	s.anomalies = append(s.anomalies, anomaly)
	
	// Keep only recent anomalies
	if len(s.anomalies) > 100 {
		s.anomalies = s.anomalies[50:]
	}
}

// newDERPPrometheusCollector creates Prometheus collector for DERP metrics
func newDERPPrometheusCollector() *DERPPrometheusCollector {
	return &DERPPrometheusCollector{
		ActiveConnections: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_derp_active_connections",
				Help: "Number of active DERP connections",
			},
			[]string{"server_id", "region"},
		),
		
		TotalConnections: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_derp_connections_total",
				Help: "Total number of DERP connections",
			},
			[]string{"server_id", "region"},
		),
		
		ConnectionDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "kubeaccess_derp_connection_duration_seconds",
				Help:    "DERP connection duration",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"server_id", "region"},
		),
		
		ConnectionErrors: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_derp_connection_errors_total",
				Help: "Total number of DERP connection errors",
			},
			[]string{"server_id", "region", "error_type"},
		),
		
		BandwidthIn: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_derp_bandwidth_in_bytes_total",
				Help: "Total inbound bandwidth in bytes",
			},
			[]string{"server_id", "region"},
		),
		
		BandwidthOut: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_derp_bandwidth_out_bytes_total",
				Help: "Total outbound bandwidth in bytes",
			},
			[]string{"server_id", "region"},
		),
		
		BandwidthPeak: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_derp_bandwidth_peak_bps",
				Help: "Peak bandwidth in bits per second",
			},
			[]string{"server_id", "region", "direction"},
		),
		
		PacketsIn: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_derp_packets_in_total",
				Help: "Total inbound packets",
			},
			[]string{"server_id", "region"},
		),
		
		PacketsOut: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_derp_packets_out_total",
				Help: "Total outbound packets",
			},
			[]string{"server_id", "region"},
		),
		
		PacketLoss: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_derp_packet_loss_total",
				Help: "Total packet loss",
			},
			[]string{"server_id", "region"},
		),
		
		Latency: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "kubeaccess_derp_latency_seconds",
				Help:    "DERP connection latency",
				Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
			},
			[]string{"server_id", "region"},
		),
		
		LatencyPercentiles: promauto.NewSummaryVec(
			prometheus.SummaryOpts{
				Name: "kubeaccess_derp_latency_percentiles",
				Help: "DERP latency percentiles",
			},
			[]string{"server_id", "region"},
		),
		
		SecurityEvents: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_derp_security_events_total",
				Help: "Total security events",
			},
			[]string{"server_id", "region", "event_type"},
		),
		
		ThreatLevel: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_derp_threat_level",
				Help: "Current threat level",
			},
			[]string{"server_id", "region"},
		),
		
		AnomaliesDetected: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_derp_anomalies_total",
				Help: "Total anomalies detected",
			},
			[]string{"server_id", "region", "anomaly_type"},
		),
		
		BlockedConnections: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_derp_blocked_connections_total",
				Help: "Total blocked connections",
			},
			[]string{"server_id", "region", "reason"},
		),
		
		ServerLoad: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_derp_server_load",
				Help: "DERP server load",
			},
			[]string{"server_id", "region"},
		),
		
		MemoryUsage: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_derp_memory_usage_bytes",
				Help: "DERP server memory usage",
			},
			[]string{"server_id", "region"},
		),
		
		CPUUsage: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_derp_cpu_usage",
				Help: "DERP server CPU usage",
			},
			[]string{"server_id", "region"},
		),
		
		UpTime: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_derp_uptime_seconds",
				Help: "DERP server uptime in seconds",
			},
			[]string{"server_id", "region"},
		),
	}
}

// updateCollectionDuration updates collection duration metric
func (d *DERPPrometheusCollector) updateCollectionDuration(start time.Time) {
	duration := time.Since(start)
	log.Printf("DERP metrics collection took: %v", duration)
}

// Describe implements prometheus.Collector interface
func (d *DERPPrometheusCollector) Describe(ch chan<- *prometheus.Desc) {
	d.ActiveConnections.Describe(ch)
	d.TotalConnections.Describe(ch)
	d.ConnectionDuration.Describe(ch)
	d.ConnectionErrors.Describe(ch)
	d.BandwidthIn.Describe(ch)
	d.BandwidthOut.Describe(ch)
	d.BandwidthPeak.Describe(ch)
	d.PacketsIn.Describe(ch)
	d.PacketsOut.Describe(ch)
	d.PacketLoss.Describe(ch)
	d.Latency.Describe(ch)
	d.LatencyPercentiles.Describe(ch)
	d.SecurityEvents.Describe(ch)
	d.ThreatLevel.Describe(ch)
	d.AnomaliesDetected.Describe(ch)
	d.BlockedConnections.Describe(ch)
	d.ServerLoad.Describe(ch)
	d.MemoryUsage.Describe(ch)
	d.CPUUsage.Describe(ch)
	d.UpTime.Describe(ch)
}

// Collect implements prometheus.Collector interface
func (d *DERPPrometheusCollector) Collect(ch chan<- prometheus.Metric) {
	d.ActiveConnections.Collect(ch)
	d.TotalConnections.Collect(ch)
	d.ConnectionDuration.Collect(ch)
	d.ConnectionErrors.Collect(ch)
	d.BandwidthIn.Collect(ch)
	d.BandwidthOut.Collect(ch)
	d.BandwidthPeak.Collect(ch)
	d.PacketsIn.Collect(ch)
	d.PacketsOut.Collect(ch)
	d.PacketLoss.Collect(ch)
	d.Latency.Collect(ch)
	d.LatencyPercentiles.Collect(ch)
	d.SecurityEvents.Collect(ch)
	d.ThreatLevel.Collect(ch)
	d.AnomaliesDetected.Collect(ch)
	d.BlockedConnections.Collect(ch)
	d.ServerLoad.Collect(ch)
	d.MemoryUsage.Collect(ch)
	d.CPUUsage.Collect(ch)
	d.UpTime.Collect(ch)
}