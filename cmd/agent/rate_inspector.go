// Package main provides rate-based threat detection for the DPI engine.
// Detects connection floods, request floods, port scans, and slow loris attacks
// using per-source-IP sliding window counters.
package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Rate limiting thresholds
const (
	rateConnFloodThreshold = 100  // connections per minute per source
	rateReqFloodThreshold  = 500  // requests per minute per destination
	ratePortScanThreshold  = 20   // distinct ports per source in 60s
	rateSlowLorisTimeout   = 30 * time.Second
	rateSlowLorisMinBytes  = 100
	rateWindowDuration     = 60 * time.Second
	rateCleanupInterval    = 30 * time.Second
)

// RateInspector implements PacketInspector for rate-based anomaly detection.
type RateInspector struct {
	// Per-source IP connection counters
	connCounts   sync.Map // string(srcIP) → *rateBucket
	// Per-destination request counters
	reqCounts    sync.Map // string(dstIP:dstPort) → *rateBucket
	// Per-source port scan tracking
	portScan     sync.Map // string(srcIP) → *portScanBucket

	stats struct {
		connFloodDetected  int64
		reqFloodDetected   int64
		portScanDetected   int64
		slowLorisDetected  int64
	}

	stopCh chan struct{}
}

// rateBucket tracks event counts in a sliding window.
type rateBucket struct {
	mu       sync.Mutex
	count    int
	windowStart time.Time
	alerted  bool
}

// portScanBucket tracks distinct destination ports per source.
type portScanBucket struct {
	mu          sync.Mutex
	ports       map[int]bool
	windowStart time.Time
	alerted     bool
}

// NewRateInspector creates a rate inspector.
func NewRateInspector() *RateInspector {
	return &RateInspector{
		stopCh: make(chan struct{}),
	}
}

// StartCleanup begins periodic cleanup of expired rate buckets.
func (r *RateInspector) StartCleanup() {
	go func() {
		ticker := time.NewTicker(rateCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-r.stopCh:
				return
			case <-ticker.C:
				r.cleanup()
			}
		}
	}()
}

// Stop stops the rate inspector.
func (r *RateInspector) Stop() {
	close(r.stopCh)
}

// Inspect implements PacketInspector for rate-based detection.
func (r *RateInspector) Inspect(data []byte, direction string, ctx *InspectionContext) []InspectionResult {
	if ctx == nil {
		return nil
	}

	var results []InspectionResult
	now := time.Now()

	srcIP := ""
	if ctx.SrcIP != nil {
		srcIP = ctx.SrcIP.String()
	}
	dstKey := ""
	if ctx.DstIP != nil {
		dstKey = fmt.Sprintf("%s:%d", ctx.DstIP.String(), ctx.DstPort)
	}

	// Connection flood detection (per-source IP)
	if srcIP != "" {
		if result := r.checkConnFlood(srcIP, now); result != nil {
			results = append(results, *result)
		}
	}

	// Request flood detection (per-destination)
	if dstKey != "" {
		if result := r.checkReqFlood(dstKey, srcIP, now); result != nil {
			results = append(results, *result)
		}
	}

	// Port scan detection
	if srcIP != "" && ctx.DstPort > 0 {
		if result := r.checkPortScan(srcIP, ctx.DstPort, now); result != nil {
			results = append(results, *result)
		}
	}

	// Slow loris detection (connection open long with minimal data)
	if ctx.Stream != nil && srcIP != "" {
		if result := r.checkSlowLoris(ctx, now); result != nil {
			results = append(results, *result)
		}
	}

	return results
}

// checkConnFlood checks for connection floods from a single source.
func (r *RateInspector) checkConnFlood(srcIP string, now time.Time) *InspectionResult {
	val, _ := r.connCounts.LoadOrStore(srcIP, &rateBucket{windowStart: now})
	bucket := val.(*rateBucket)

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	// Reset window if expired
	if now.Sub(bucket.windowStart) > rateWindowDuration {
		bucket.count = 0
		bucket.windowStart = now
		bucket.alerted = false
	}

	bucket.count++

	if bucket.count > rateConnFloodThreshold && !bucket.alerted {
		bucket.alerted = true
		atomic.AddInt64(&r.stats.connFloodDetected, 1)
		return &InspectionResult{
			Timestamp:   now,
			ThreatLevel: ThreatHigh,
			Category:    ThreatCategoryDefenseEvasion,
			Description: fmt.Sprintf("Connection flood detected: %d connections/min from %s", bucket.count, srcIP),
			Indicators:  []string{"rate-conn-flood", srcIP},
			MitreATTCK:  "T1498",
			Score:       75,
			Metadata: map[string]interface{}{
				"source_ip":      srcIP,
				"connection_count": bucket.count,
				"window_sec":    60,
			},
		}
	}

	return nil
}

// checkReqFlood checks for request floods to a single destination.
func (r *RateInspector) checkReqFlood(dstKey, srcIP string, now time.Time) *InspectionResult {
	val, _ := r.reqCounts.LoadOrStore(dstKey, &rateBucket{windowStart: now})
	bucket := val.(*rateBucket)

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	if now.Sub(bucket.windowStart) > rateWindowDuration {
		bucket.count = 0
		bucket.windowStart = now
		bucket.alerted = false
	}

	bucket.count++

	if bucket.count > rateReqFloodThreshold && !bucket.alerted {
		bucket.alerted = true
		atomic.AddInt64(&r.stats.reqFloodDetected, 1)
		return &InspectionResult{
			Timestamp:   now,
			ThreatLevel: ThreatMedium,
			Category:    ThreatCategoryDefenseEvasion,
			Description: fmt.Sprintf("Request flood detected: %d requests/min to %s", bucket.count, dstKey),
			Indicators:  []string{"rate-req-flood", dstKey},
			MitreATTCK:  "T1498",
			Score:       65,
			Metadata: map[string]interface{}{
				"destination":    dstKey,
				"source_ip":     srcIP,
				"request_count": bucket.count,
				"window_sec":    60,
			},
		}
	}

	return nil
}

// checkPortScan detects port scanning patterns.
func (r *RateInspector) checkPortScan(srcIP string, dstPort int, now time.Time) *InspectionResult {
	val, _ := r.portScan.LoadOrStore(srcIP, &portScanBucket{
		ports:       make(map[int]bool),
		windowStart: now,
	})
	bucket := val.(*portScanBucket)

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	if now.Sub(bucket.windowStart) > rateWindowDuration {
		bucket.ports = make(map[int]bool)
		bucket.windowStart = now
		bucket.alerted = false
	}

	bucket.ports[dstPort] = true

	if len(bucket.ports) > ratePortScanThreshold && !bucket.alerted {
		bucket.alerted = true
		atomic.AddInt64(&r.stats.portScanDetected, 1)
		return &InspectionResult{
			Timestamp:   now,
			ThreatLevel: ThreatHigh,
			Category:    ThreatCategoryLateralMovement,
			Description: fmt.Sprintf("Port scan detected: %d distinct ports from %s", len(bucket.ports), srcIP),
			Indicators:  []string{"rate-port-scan", srcIP},
			MitreATTCK:  "T1046",
			Score:       80,
			Metadata: map[string]interface{}{
				"source_ip":    srcIP,
				"port_count":   len(bucket.ports),
				"window_sec":   60,
			},
		}
	}

	return nil
}

// checkSlowLoris detects slow loris attacks.
func (r *RateInspector) checkSlowLoris(ctx *InspectionContext, now time.Time) *InspectionResult {
	if ctx.Stream == nil {
		return nil
	}

	totalBytes := ctx.Stream.TotalBytes()
	// Only check after the connection has been open a while with minimal data
	if ctx.PacketCount > 5 && totalBytes < rateSlowLorisMinBytes {
		atomic.AddInt64(&r.stats.slowLorisDetected, 1)
		return &InspectionResult{
			Timestamp:   now,
			ThreatLevel: ThreatMedium,
			Category:    ThreatCategoryDefenseEvasion,
			Description: "Slow loris attack suspected: connection with minimal data transfer",
			Indicators:  []string{"rate-slow-loris"},
			MitreATTCK:  "T1498.001",
			Score:       60,
			Metadata: map[string]interface{}{
				"total_bytes":  totalBytes,
				"packet_count": ctx.PacketCount,
			},
		}
	}

	return nil
}

// cleanup removes expired rate buckets to prevent memory leaks.
func (r *RateInspector) cleanup() {
	now := time.Now()
	cutoff := 2 * rateWindowDuration

	r.connCounts.Range(func(key, val interface{}) bool {
		bucket := val.(*rateBucket)
		bucket.mu.Lock()
		expired := now.Sub(bucket.windowStart) > cutoff
		bucket.mu.Unlock()
		if expired {
			r.connCounts.Delete(key)
		}
		return true
	})

	r.reqCounts.Range(func(key, val interface{}) bool {
		bucket := val.(*rateBucket)
		bucket.mu.Lock()
		expired := now.Sub(bucket.windowStart) > cutoff
		bucket.mu.Unlock()
		if expired {
			r.reqCounts.Delete(key)
		}
		return true
	})

	r.portScan.Range(func(key, val interface{}) bool {
		bucket := val.(*portScanBucket)
		bucket.mu.Lock()
		expired := now.Sub(bucket.windowStart) > cutoff
		bucket.mu.Unlock()
		if expired {
			r.portScan.Delete(key)
		}
		return true
	})
}

// Name implements PacketInspector.
func (r *RateInspector) Name() string {
	return "rate-inspector"
}

// Stats implements PacketInspector.
func (r *RateInspector) Stats() map[string]interface{} {
	return map[string]interface{}{
		"conn_flood_detected":  atomic.LoadInt64(&r.stats.connFloodDetected),
		"req_flood_detected":   atomic.LoadInt64(&r.stats.reqFloodDetected),
		"port_scan_detected":   atomic.LoadInt64(&r.stats.portScanDetected),
		"slow_loris_detected":  atomic.LoadInt64(&r.stats.slowLorisDetected),
	}
}
