package metrics

import (
	"sync"
	"time"
)

// MetricsBuffer provides thread-safe buffering for high-traffic metrics
type MetricsBuffer struct {
	buffer   []Metric
	capacity int
	mu       sync.RWMutex
	stats    BufferStats
}

// BufferStats tracks buffer performance metrics
type BufferStats struct {
	TotalAdded    int64     `json:"total_added"`
	TotalDropped  int64     `json:"total_dropped"`
	CurrentSize   int       `json:"current_size"`
	MaxSize       int       `json:"max_size"`
	LastFlush     time.Time `json:"last_flush"`
	FlushCount    int64     `json:"flush_count"`
	OverflowCount int64     `json:"overflow_count"`
}

// NewMetricsBuffer creates a new metrics buffer
func NewMetricsBuffer(capacity int) *MetricsBuffer {
	return &MetricsBuffer{
		buffer:   make([]Metric, 0, capacity),
		capacity: capacity,
		stats: BufferStats{
			MaxSize: capacity,
		},
	}
}

// Add adds metrics to the buffer with overflow protection
func (b *MetricsBuffer) Add(metrics ...Metric) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	added := 0
	for _, metric := range metrics {
		if len(b.buffer) < b.capacity {
			// Add timestamp if not set
			if metric.Timestamp.IsZero() {
				metric.Timestamp = time.Now()
			}
			
			b.buffer = append(b.buffer, metric)
			b.stats.TotalAdded++
			added++
		} else {
			// Buffer full - implement overflow strategy
			b.handleOverflow(metric)
		}
	}
	
	b.stats.CurrentSize = len(b.buffer)
	return added
}

// GetBatch retrieves a batch of metrics from the buffer
func (b *MetricsBuffer) GetBatch(size int) []Metric {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	if len(b.buffer) == 0 {
		return nil
	}
	
	// Determine batch size
	batchSize := size
	if batchSize > len(b.buffer) {
		batchSize = len(b.buffer)
	}
	
	// Extract batch
	batch := make([]Metric, batchSize)
	copy(batch, b.buffer[:batchSize])
	
	// Remove from buffer
	b.buffer = b.buffer[batchSize:]
	b.stats.CurrentSize = len(b.buffer)
	b.stats.FlushCount++
	b.stats.LastFlush = time.Now()
	
	return batch
}

// handleOverflow implements overflow strategy (drop oldest)
func (b *MetricsBuffer) handleOverflow(metric Metric) {
	// Drop oldest metric and add new one (FIFO overflow)
	if len(b.buffer) > 0 {
		b.buffer = b.buffer[1:] // Remove oldest
	}
	
	b.buffer = append(b.buffer, metric)
	b.stats.TotalDropped++
	b.stats.OverflowCount++
}

// Size returns current buffer size
func (b *MetricsBuffer) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.buffer)
}

// Stats returns buffer statistics
func (b *MetricsBuffer) Stats() BufferStats {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	stats := b.stats
	stats.CurrentSize = len(b.buffer)
	return stats
}

// Clear empties the buffer
func (b *MetricsBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	b.buffer = b.buffer[:0]
	b.stats.CurrentSize = 0
}

// Capacity returns buffer capacity
func (b *MetricsBuffer) Capacity() int {
	return b.capacity
}

// IsEmpty checks if buffer is empty
func (b *MetricsBuffer) IsEmpty() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.buffer) == 0
}

// IsFull checks if buffer is at capacity
func (b *MetricsBuffer) IsFull() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.buffer) >= b.capacity
}

// GetOldestMetric returns the oldest metric without removing it
func (b *MetricsBuffer) GetOldestMetric() *Metric {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	if len(b.buffer) == 0 {
		return nil
	}
	
	return &b.buffer[0]
}

// GetNewestMetric returns the newest metric without removing it
func (b *MetricsBuffer) GetNewestMetric() *Metric {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	if len(b.buffer) == 0 {
		return nil
	}
	
	return &b.buffer[len(b.buffer)-1]
}

// FilterByCategory returns metrics matching specific categories
func (b *MetricsBuffer) FilterByCategory(categories ...Category) []Metric {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	categoryMap := make(map[Category]bool)
	for _, cat := range categories {
		categoryMap[cat] = true
	}
	
	var filtered []Metric
	for _, metric := range b.buffer {
		if categoryMap[metric.Category] {
			filtered = append(filtered, metric)
		}
	}
	
	return filtered
}

// FilterBySeverity returns metrics matching minimum severity
func (b *MetricsBuffer) FilterBySeverity(minSeverity Severity) []Metric {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	severityOrder := map[Severity]int{
		SeverityDebug:    0,
		SeverityInfo:     1,
		SeverityLow:      2,
		SeverityMedium:   3,
		SeverityHigh:     4,
		SeverityCritical: 5,
	}
	
	minLevel := severityOrder[minSeverity]
	var filtered []Metric
	
	for _, metric := range b.buffer {
		if severityOrder[metric.Severity] >= minLevel {
			filtered = append(filtered, metric)
		}
	}
	
	return filtered
}

// FilterByTimeRange returns metrics within time range
func (b *MetricsBuffer) FilterByTimeRange(start, end time.Time) []Metric {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	var filtered []Metric
	for _, metric := range b.buffer {
		if metric.Timestamp.After(start) && metric.Timestamp.Before(end) {
			filtered = append(filtered, metric)
		}
	}
	
	return filtered
}

// GetMetricsByPlugin returns metrics from specific plugin
func (b *MetricsBuffer) GetMetricsByPlugin(pluginName string) []Metric {
	b.mu.RLock()
	defer b.mu.RUnlock()
	
	var filtered []Metric
	for _, metric := range b.buffer {
		if metric.Plugin == pluginName {
			filtered = append(filtered, metric)
		}
	}
	
	return filtered
}

// Compact removes old metrics based on retention policy
func (b *MetricsBuffer) Compact(retentionPeriod time.Duration) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	cutoff := time.Now().Add(-retentionPeriod)
	originalSize := len(b.buffer)
	
	// Keep only metrics newer than cutoff
	kept := 0
	for i, metric := range b.buffer {
		if metric.Timestamp.After(cutoff) {
			if i != kept {
				b.buffer[kept] = metric
			}
			kept++
		}
	}
	
	// Truncate buffer
	b.buffer = b.buffer[:kept]
	b.stats.CurrentSize = len(b.buffer)
	
	return originalSize - kept // Return number of removed metrics
}