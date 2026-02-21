// Package main provides packet inspection for the tunnel daemon.
// The PacketInspector analyzes traffic in-flight as it passes through the proxy,
// detecting threats like SQL injection, XSS, command injection, and malware.
package main

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ThreatLevel represents severity of detected threat
type ThreatLevel int

const (
	ThreatNone ThreatLevel = iota
	ThreatLow
	ThreatMedium
	ThreatHigh
	ThreatCritical
)

func (t ThreatLevel) String() string {
	switch t {
	case ThreatLow:
		return "low"
	case ThreatMedium:
		return "medium"
	case ThreatHigh:
		return "high"
	case ThreatCritical:
		return "critical"
	default:
		return "none"
	}
}

// ThreatCategory classifies the type of threat
type ThreatCategory string

const (
	ThreatCategoryReverseShell       ThreatCategory = "reverse_shell"
	ThreatCategoryCryptominer        ThreatCategory = "cryptominer"
	ThreatCategoryRansomware         ThreatCategory = "ransomware"
	ThreatCategoryRootkit            ThreatCategory = "rootkit"
	ThreatCategoryDataExfiltration   ThreatCategory = "data_exfiltration"
	ThreatCategoryPrivilegeEscalation ThreatCategory = "privilege_escalation"
	ThreatCategoryLateralMovement    ThreatCategory = "lateral_movement"
	ThreatCategoryPersistence        ThreatCategory = "persistence"
	ThreatCategoryCredentialAccess   ThreatCategory = "credential_access"
	ThreatCategoryDefenseEvasion     ThreatCategory = "defense_evasion"
	ThreatCategorySuspiciousProcess  ThreatCategory = "suspicious_process"
	ThreatCategoryC2Communication    ThreatCategory = "c2_communication"
)

// InspectionMode controls how the inspector responds to detected threats
type InspectionMode string

const (
	// InspectionModeDetect logs threats but allows traffic to pass
	InspectionModeDetect InspectionMode = "detect"
	// InspectionModeBlock blocks traffic when critical/high threats detected
	InspectionModeBlock InspectionMode = "block"
)

// InspectionConfig configures the packet inspection behavior
type InspectionConfig struct {
	Enabled     bool           `json:"enabled"`
	Mode        InspectionMode `json:"mode"`
	MaxBodySize int64          `json:"maxBodySize"` // Max bytes to buffer for inspection

	// Protocol-specific settings
	HTTP struct {
		Enabled     bool  `json:"enabled"`
		ScanBody    bool  `json:"scanBody"`
		MaxBodySize int64 `json:"maxBodySize"`
	} `json:"http"`

	DNS struct {
		Enabled   bool `json:"enabled"`
		DetectDGA bool `json:"detectDGA"`
	} `json:"dns"`

	// Response actions per threat level
	OnCritical string `json:"onCritical"` // "block" or "alert"
	OnHigh     string `json:"onHigh"`
	OnMedium   string `json:"onMedium"`
}

// DefaultInspectionConfig returns a sensible default configuration
func DefaultInspectionConfig() *InspectionConfig {
	cfg := &InspectionConfig{
		Enabled:     true,
		Mode:        InspectionModeDetect,
		MaxBodySize: 16 * 1024 * 1024, // 16MB
		OnCritical:  "block",
		OnHigh:      "alert",
		OnMedium:    "log",
	}
	cfg.HTTP.Enabled = true
	cfg.HTTP.ScanBody = true
	cfg.HTTP.MaxBodySize = 16 * 1024 * 1024
	cfg.DNS.Enabled = true
	cfg.DNS.DetectDGA = true
	return cfg
}

// InspectionResult represents the outcome of inspecting a data chunk
type InspectionResult struct {
	Timestamp   time.Time      `json:"timestamp"`
	ThreatLevel ThreatLevel    `json:"threatLevel"`
	Category    ThreatCategory `json:"category"`
	Description string         `json:"description"`
	Indicators  []string       `json:"indicators"`
	MitreATTCK  string         `json:"mitreAttck,omitempty"`
	Score       int            `json:"score"`
	ShouldBlock bool           `json:"shouldBlock"`

	// Connection context
	SrcIP   net.IP `json:"srcIp,omitempty"`
	DstIP   net.IP `json:"dstIp,omitempty"`
	SrcPort int    `json:"srcPort,omitempty"`
	DstPort int    `json:"dstPort,omitempty"`

	// Additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// PacketInspector defines the interface for traffic inspection
type PacketInspector interface {
	// Inspect analyzes a chunk of data and returns any detected threats
	// The direction parameter indicates traffic flow: "inbound" or "outbound"
	Inspect(data []byte, direction string, ctx *InspectionContext) []InspectionResult

	// Name returns the inspector name for logging
	Name() string

	// Stats returns inspection statistics
	Stats() map[string]interface{}
}

// InspectionContext provides context about the connection being inspected
type InspectionContext struct {
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     int
	DstPort     int
	Protocol    string // "tcp" or "udp"
	PodName     string
	PodNS       string
	ContainerID string

	// Accumulated data for multi-packet inspection
	Buffer      []byte
	BytesSeen   int64
	PacketCount int64

	// Per-connection stream state for multi-chunk pattern detection
	Stream *StreamState
}

// InspectionStats tracks inspection metrics
type InspectionStats struct {
	PacketsInspected int64
	BytesInspected   int64
	ThreatsDetected  int64
	ThreatsByLevel   map[ThreatLevel]int64
	ThreatsByCategory map[ThreatCategory]int64
	ConnectionsBlocked int64
	InspectionLatencyNs int64 // Cumulative for averaging
}

// InspectingReader wraps an io.Reader to inspect data as it passes through
type InspectingReader struct {
	reader     io.Reader
	inspector  PacketInspector
	ctx        *InspectionContext
	config     *InspectionConfig
	direction  string
	onThreat   func(InspectionResult)

	// Stats
	bytesRead int64
	mu        sync.Mutex
	blocked   bool
	blockErr  error
}

// NewInspectingReader creates a reader that inspects data in-flight
func NewInspectingReader(
	reader io.Reader,
	inspector PacketInspector,
	ctx *InspectionContext,
	config *InspectionConfig,
	direction string,
	onThreat func(InspectionResult),
) *InspectingReader {
	return &InspectingReader{
		reader:    reader,
		inspector: inspector,
		ctx:       ctx,
		config:    config,
		direction: direction,
		onThreat:  onThreat,
	}
}

// Read implements io.Reader with inspection
func (ir *InspectingReader) Read(p []byte) (n int, err error) {
	ir.mu.Lock()
	if ir.blocked {
		ir.mu.Unlock()
		return 0, ir.blockErr
	}
	ir.mu.Unlock()

	n, err = ir.reader.Read(p)
	if n > 0 && ir.inspector != nil && ir.config.Enabled {
		start := time.Now()
		results := ir.inspector.Inspect(p[:n], ir.direction, ir.ctx)
		_ = time.Since(start) // latency tracking

		for _, result := range results {
			// Populate connection context
			result.SrcIP = ir.ctx.SrcIP
			result.DstIP = ir.ctx.DstIP
			result.SrcPort = ir.ctx.SrcPort
			result.DstPort = ir.ctx.DstPort

			// Check if we should block
			if ir.shouldBlock(result) {
				result.ShouldBlock = true
				ir.mu.Lock()
				ir.blocked = true
				ir.blockErr = &InspectionBlockedError{Result: result}
				ir.mu.Unlock()
			}

			// Notify callback
			if ir.onThreat != nil {
				ir.onThreat(result)
			}
		}

		atomic.AddInt64(&ir.bytesRead, int64(n))
		ir.ctx.BytesSeen += int64(n)
		ir.ctx.PacketCount++
	}

	return n, err
}

// shouldBlock determines if the result warrants blocking the connection
func (ir *InspectingReader) shouldBlock(result InspectionResult) bool {
	if ir.config.Mode != InspectionModeBlock {
		return false
	}

	switch result.ThreatLevel {
	case ThreatCritical:
		return ir.config.OnCritical == "block"
	case ThreatHigh:
		return ir.config.OnHigh == "block"
	case ThreatMedium:
		return ir.config.OnMedium == "block"
	default:
		return false
	}
}

// BytesRead returns the total bytes read through this reader
func (ir *InspectingReader) BytesRead() int64 {
	return atomic.LoadInt64(&ir.bytesRead)
}

// InspectionBlockedError is returned when inspection blocks a connection
type InspectionBlockedError struct {
	Result InspectionResult
}

func (e *InspectionBlockedError) Error() string {
	return "connection blocked by packet inspection: " + e.Result.Description
}

// MultiInspector combines multiple inspectors into one
type MultiInspector struct {
	inspectors []PacketInspector
	stats      InspectionStats
	statsMu    sync.RWMutex
}

// NewMultiInspector creates an inspector that runs multiple inspectors in sequence
func NewMultiInspector(inspectors ...PacketInspector) *MultiInspector {
	return &MultiInspector{
		inspectors: inspectors,
		stats: InspectionStats{
			ThreatsByLevel:    make(map[ThreatLevel]int64),
			ThreatsByCategory: make(map[ThreatCategory]int64),
		},
	}
}

// AddInspector adds a new inspector to the chain
func (mi *MultiInspector) AddInspector(inspector PacketInspector) {
	mi.inspectors = append(mi.inspectors, inspector)
}

// Inspect runs all inspectors and aggregates results
func (mi *MultiInspector) Inspect(data []byte, direction string, ctx *InspectionContext) []InspectionResult {
	var allResults []InspectionResult

	start := time.Now()
	for _, inspector := range mi.inspectors {
		results := inspector.Inspect(data, direction, ctx)
		allResults = append(allResults, results...)
	}
	latency := time.Since(start)

	// Update stats
	mi.statsMu.Lock()
	mi.stats.PacketsInspected++
	mi.stats.BytesInspected += int64(len(data))
	mi.stats.InspectionLatencyNs += latency.Nanoseconds()
	for _, r := range allResults {
		mi.stats.ThreatsDetected++
		mi.stats.ThreatsByLevel[r.ThreatLevel]++
		mi.stats.ThreatsByCategory[r.Category]++
	}
	mi.statsMu.Unlock()

	return allResults
}

// Name returns the multi-inspector name
func (mi *MultiInspector) Name() string {
	return "multi-inspector"
}

// Stats returns aggregated statistics
func (mi *MultiInspector) Stats() map[string]interface{} {
	mi.statsMu.RLock()
	defer mi.statsMu.RUnlock()

	avgLatency := int64(0)
	if mi.stats.PacketsInspected > 0 {
		avgLatency = mi.stats.InspectionLatencyNs / mi.stats.PacketsInspected
	}

	levelStats := make(map[string]int64)
	for level, count := range mi.stats.ThreatsByLevel {
		levelStats[level.String()] = count
	}

	categoryStats := make(map[string]int64)
	for cat, count := range mi.stats.ThreatsByCategory {
		categoryStats[string(cat)] = count
	}

	return map[string]interface{}{
		"packets_inspected":     mi.stats.PacketsInspected,
		"bytes_inspected":       mi.stats.BytesInspected,
		"threats_detected":      mi.stats.ThreatsDetected,
		"threats_by_level":      levelStats,
		"threats_by_category":   categoryStats,
		"connections_blocked":   mi.stats.ConnectionsBlocked,
		"avg_latency_ns":        avgLatency,
	}
}

// IncrementBlocked increments the blocked connections counter
func (mi *MultiInspector) IncrementBlocked() {
	mi.statsMu.Lock()
	mi.stats.ConnectionsBlocked++
	mi.statsMu.Unlock()
}
