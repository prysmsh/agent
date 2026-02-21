package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Plugin defines the interface for metrics collection plugins
type Plugin interface {
	// Name returns the plugin identifier
	Name() string
	
	// Description returns plugin description
	Description() string
	
	// Initialize sets up the plugin with configuration
	Initialize(ctx context.Context, config interface{}) error
	
	// Collect gathers metrics and returns them
	Collect(ctx context.Context) ([]Metric, error)
	
	// PrometheusCollector returns the Prometheus collector for this plugin
	PrometheusCollector() prometheus.Collector
	
	// Shutdown cleans up plugin resources
	Shutdown() error
	
	// Health returns plugin health status
	Health() PluginHealth
}

// Metric represents a collected metric with metadata
type Metric struct {
	// Core metric data
	Name        string                 `json:"name"`
	Type        MetricType             `json:"type"`
	Value       interface{}            `json:"value"`
	Labels      map[string]string      `json:"labels"`
	Timestamp   time.Time             `json:"timestamp"`
	
	// Metadata
	Plugin      string                 `json:"plugin"`
	Component   string                 `json:"component"`
	Severity    Severity              `json:"severity"`
	Category    Category              `json:"category"`
	
	// Context and tracing
	TraceID     string                 `json:"trace_id,omitempty"`
	SpanID      string                 `json:"span_id,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	
	// Security context
	Security    *SecurityContext       `json:"security,omitempty"`
	
	// Additional metadata
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// MetricType defines the type of metric
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeSummary   MetricType = "summary"
	MetricTypeEvent     MetricType = "event"
	MetricTypeLog       MetricType = "log"
)

// Severity indicates metric importance
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityDebug    Severity = "debug"
)

// Category groups related metrics
type Category string

const (
	CategoryKubernetes Category = "kubernetes"
	CategoryNetwork    Category = "network"
	CategorySecurity   Category = "security"
	CategoryPerformance Category = "performance"
	CategoryBusiness   Category = "business"
	CategorySystem     Category = "system"
	CategoryDERP       Category = "derp"
	CategoryCompliance Category = "compliance"
)

// SecurityContext provides security-related metadata
type SecurityContext struct {
	UserID        string            `json:"user_id,omitempty"`
	SessionID     string            `json:"session_id,omitempty"`
	SourceIP      string            `json:"source_ip,omitempty"`
	UserAgent     string            `json:"user_agent,omitempty"`
	ThreatLevel   ThreatLevel       `json:"threat_level,omitempty"`
	Anomaly       bool              `json:"anomaly,omitempty"`
	AnomalyScore  float64           `json:"anomaly_score,omitempty"`
	Tags          []string          `json:"tags,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

// ThreatLevel indicates security threat severity
type ThreatLevel string

const (
	ThreatLevelNone     ThreatLevel = "none"
	ThreatLevelLow      ThreatLevel = "low"
	ThreatLevelMedium   ThreatLevel = "medium"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelCritical ThreatLevel = "critical"
)

// PluginHealth represents plugin operational status
type PluginHealth struct {
	Status         HealthStatus      `json:"status"`
	LastCollection time.Time         `json:"last_collection"`
	ErrorCount     int64             `json:"error_count"`
	LastError      string            `json:"last_error,omitempty"`
	Uptime         time.Duration     `json:"uptime"`
	MemoryUsage    int64             `json:"memory_usage"`
	MetricsCount   int64             `json:"metrics_count"`
	Details        map[string]string `json:"details,omitempty"`
}

// HealthStatus indicates plugin health
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// KubernetesMetrics contains Kubernetes-specific metrics
type KubernetesMetrics struct {
	ClusterID       string            `json:"cluster_id"`
	Namespace       string            `json:"namespace"`
	NodeCount       int               `json:"node_count"`
	PodCount        int               `json:"pod_count"`
	ServiceCount    int               `json:"service_count"`
	ResourceUsage   ResourceUsage     `json:"resource_usage"`
	ServiceHealth   []ServiceHealth   `json:"service_health"`
	NetworkPolicies int               `json:"network_policies"`
	Events          []KubernetesEvent `json:"events"`
}

// ResourceUsage tracks resource consumption
type ResourceUsage struct {
	CPU          CPUUsage    `json:"cpu"`
	Memory       MemoryUsage `json:"memory"`
	Storage      StorageUsage `json:"storage"`
	Network      NetworkUsage `json:"network"`
	RequestedCPU float64     `json:"requested_cpu"`
	RequestedMemory int64    `json:"requested_memory"`
	LimitCPU     float64     `json:"limit_cpu"`
	LimitMemory  int64       `json:"limit_memory"`
}

// CPUUsage tracks CPU metrics
type CPUUsage struct {
	UsagePercent    float64 `json:"usage_percent"`
	UsageCores      float64 `json:"usage_cores"`
	ThrottledTime   int64   `json:"throttled_time"`
	ThrottledPeriods int64  `json:"throttled_periods"`
}

// MemoryUsage tracks memory metrics
type MemoryUsage struct {
	UsageBytes    int64   `json:"usage_bytes"`
	UsagePercent  float64 `json:"usage_percent"`
	CacheBytes    int64   `json:"cache_bytes"`
	WorkingSetBytes int64 `json:"working_set_bytes"`
	PageFaults    int64   `json:"page_faults"`
}

// StorageUsage tracks storage metrics
type StorageUsage struct {
	UsageBytes     int64   `json:"usage_bytes"`
	UsagePercent   float64 `json:"usage_percent"`
	AvailableBytes int64   `json:"available_bytes"`
	InodesUsed     int64   `json:"inodes_used"`
	InodesTotal    int64   `json:"inodes_total"`
}

// NetworkUsage tracks network metrics
type NetworkUsage struct {
	RxBytes    int64   `json:"rx_bytes"`
	TxBytes    int64   `json:"tx_bytes"`
	RxPackets  int64   `json:"rx_packets"`
	TxPackets  int64   `json:"tx_packets"`
	RxErrors   int64   `json:"rx_errors"`
	TxErrors   int64   `json:"tx_errors"`
	Bandwidth  float64 `json:"bandwidth_mbps"`
}

// ServiceHealth tracks service health status
type ServiceHealth struct {
	ServiceName string        `json:"service_name"`
	Namespace   string        `json:"namespace"`
	Status      string        `json:"status"`
	Replicas    int           `json:"replicas"`
	Ready       int           `json:"ready"`
	Restarts    int           `json:"restarts"`
	Age         time.Duration `json:"age"`
	LastRestart time.Time     `json:"last_restart"`
}

// KubernetesEvent represents a Kubernetes event
type KubernetesEvent struct {
	Type        string    `json:"type"`
	Reason      string    `json:"reason"`
	Message     string    `json:"message"`
	Object      string    `json:"object"`
	Count       int       `json:"count"`
	FirstTime   time.Time `json:"first_time"`
	LastTime    time.Time `json:"last_time"`
	Severity    Severity  `json:"severity"`
}

// DERPMetrics contains DERP network metrics
type DERPMetrics struct {
	ServerID        string                    `json:"server_id"`
	Region          string                    `json:"region"`
	Connections     int                       `json:"connections"`
	Bandwidth       BandwidthMetrics          `json:"bandwidth"`
	Latency         LatencyMetrics            `json:"latency"`
	PacketStats     PacketStats               `json:"packet_stats"`
	ConnectionStats map[string]ConnectionStat `json:"connection_stats"`
	SecurityEvents  []SecurityEvent           `json:"security_events"`
}

// BandwidthMetrics tracks bandwidth usage
type BandwidthMetrics struct {
	InboundBps   float64 `json:"inbound_bps"`
	OutboundBps  float64 `json:"outbound_bps"`
	TotalBytes   int64   `json:"total_bytes"`
	PeakBandwidth float64 `json:"peak_bandwidth"`
}

// LatencyMetrics tracks network latency
type LatencyMetrics struct {
	AverageMs float64 `json:"average_ms"`
	P50Ms     float64 `json:"p50_ms"`
	P95Ms     float64 `json:"p95_ms"`
	P99Ms     float64 `json:"p99_ms"`
	MaxMs     float64 `json:"max_ms"`
}

// PacketStats tracks packet-level statistics
type PacketStats struct {
	Sent      int64 `json:"sent"`
	Received  int64 `json:"received"`
	Dropped   int64 `json:"dropped"`
	Corrupted int64 `json:"corrupted"`
	Retries   int64 `json:"retries"`
}

// ConnectionStat tracks individual connection statistics
type ConnectionStat struct {
	PeerID       string        `json:"peer_id"`
	Duration     time.Duration `json:"duration"`
	BytesIn      int64         `json:"bytes_in"`
	BytesOut     int64         `json:"bytes_out"`
	PacketsIn    int64         `json:"packets_in"`
	PacketsOut   int64         `json:"packets_out"`
	LastActivity time.Time     `json:"last_activity"`
	Status       string        `json:"status"`
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	EventID     string                 `json:"event_id"`
	Type        SecurityEventType      `json:"type"`
	Severity    ThreatLevel            `json:"severity"`
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Mitigated   bool                   `json:"mitigated"`
}

// SecurityEventType categorizes security events
type SecurityEventType string

const (
	SecurityEventTypeAuthentication SecurityEventType = "authentication"
	SecurityEventTypeAuthorization  SecurityEventType = "authorization"
	SecurityEventTypeAnomaly        SecurityEventType = "anomaly"
	SecurityEventTypeIntrusion      SecurityEventType = "intrusion"
	SecurityEventTypeCompliance     SecurityEventType = "compliance"
	SecurityEventTypeThreat         SecurityEventType = "threat"
)

// ContainerVulnerability represents a single CVE/vulnerability finding for metrics.
type ContainerVulnerability struct {
	VulnerabilityID  string    `json:"vulnerability_id"`
	PackageName     string    `json:"package_name"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion    string    `json:"fixed_version"`
	Severity        string    `json:"severity"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	References      []string  `json:"references"`
	PublishedDate   time.Time `json:"published_date,omitempty"`
	LastModifiedDate time.Time `json:"last_modified_date,omitempty"`
}

// ImageScanResult holds the result of scanning a container image for metrics/reporting.
type ImageScanResult struct {
	ImageName        string                  `json:"image_name"`
	ImageDigest      string                  `json:"image_digest"`
	ScanTime         time.Time               `json:"scan_time"`
	TotalVulns       int                     `json:"total_vulns"`
	CriticalCount    int                     `json:"critical_count"`
	HighCount        int                     `json:"high_count"`
	MediumCount      int                     `json:"medium_count"`
	LowCount         int                     `json:"low_count"`
	Vulnerabilities  []ContainerVulnerability `json:"vulnerabilities"`
	ComplianceStatus string                  `json:"compliance_status"` // COMPLIANT, NON_COMPLIANT, WARNING, UNKNOWN
	ScanError        string                  `json:"scan_error,omitempty"`
}

// ContainerSecurityEvent represents a security scan result for a single container.
type ContainerSecurityEvent struct {
	ClusterID       string         `json:"cluster_id"`
	Namespace       string         `json:"namespace"`
	PodName         string         `json:"pod_name"`
	ContainerName   string         `json:"container_name"`
	ImageScanResult ImageScanResult `json:"image_scan_result"`
	Timestamp       time.Time      `json:"timestamp"`
}

// PerformanceMetrics contains system performance data
type PerformanceMetrics struct {
	Component     string            `json:"component"`
	ResponseTime  time.Duration     `json:"response_time"`
	Throughput    float64           `json:"throughput"`
	ErrorRate     float64           `json:"error_rate"`
	Availability  float64           `json:"availability"`
	SLACompliance float64           `json:"sla_compliance"`
	Bottlenecks   []Bottleneck      `json:"bottlenecks"`
	Trends        []PerformanceTrend `json:"trends"`
}

// Bottleneck identifies performance bottlenecks
type Bottleneck struct {
	Component   string    `json:"component"`
	Resource    string    `json:"resource"`
	Severity    Severity  `json:"severity"`
	Impact      float64   `json:"impact"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// PerformanceTrend tracks performance over time
type PerformanceTrend struct {
	Metric    string    `json:"metric"`
	Value     float64   `json:"value"`
	Change    float64   `json:"change"`
	Direction string    `json:"direction"` // "improving", "degrading", "stable"
	Timestamp time.Time `json:"timestamp"`
}