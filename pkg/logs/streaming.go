package logs

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prysmsh/pkg/tlsutil"
	"github.com/sirupsen/logrus"
)

// StreamingCollector provides real-time log streaming capabilities
type StreamingCollector struct {
	config         *StreamingConfig
	collector      *LogCollector
	derpConn       *websocket.Conn
	backendConn    *websocket.Conn
	connMutex      sync.RWMutex
	streamBuffer   chan LogEntry
	isStreaming    bool
	streamingMutex sync.RWMutex
}

// StreamingConfig extends the basic Config with streaming options
type StreamingConfig struct {
	*Config

	// Streaming settings
	EnableStreaming      bool          `json:"enable_streaming"`
	StreamBufferSize     int           `json:"stream_buffer_size"`
	StreamFlushInterval  time.Duration `json:"stream_flush_interval"`
	ReconnectInterval    time.Duration `json:"reconnect_interval"`
	MaxReconnectAttempts int           `json:"max_reconnect_attempts"`

	// DERP streaming settings
	EnableDERPStreaming bool   `json:"enable_derp_streaming"`
	DERPEndpoint        string `json:"derp_endpoint"`
	DERPClientID        string `json:"derp_client_id"`
	DERPPublicKey       string `json:"derp_public_key"`
	SkipDERPTLSVerify   bool   `json:"skip_derp_tls_verify"`

	// Backend WebSocket settings
	BackendWSEndpoint   string        `json:"backend_ws_endpoint"`
	WSHeartbeatInterval time.Duration `json:"ws_heartbeat_interval"`

	// Compression and optimization
	EnableCompression   bool `json:"enable_compression"`
	CompressionLevel    int  `json:"compression_level"`
	EnableDeduplication bool `json:"enable_deduplication"`
}

// StreamMessage represents a streaming log message
type StreamMessage struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      interface{}            `json:"data"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// NewStreamingCollector creates a new streaming log collector
func NewStreamingCollector(config *StreamingConfig) *StreamingCollector {
	baseCollector := NewLogCollector(config.Config)

	return &StreamingCollector{
		config:       config,
		collector:    baseCollector,
		streamBuffer: make(chan LogEntry, config.StreamBufferSize),
	}
}

// Start begins the streaming log collection
func (sc *StreamingCollector) Start(ctx context.Context) error {
	// Start the base collector
	if err := sc.collector.Start(ctx); err != nil {
		return fmt.Errorf("failed to start base collector: %w", err)
	}

	// Note: We'll intercept entries through a different approach since
	// addEntriesToBatch is a method, not a field that can be reassigned

	if sc.config.EnableStreaming {
		// Initialize streaming connections
		if err := sc.initializeConnections(ctx); err != nil {
			logrus.Warnf("Failed to initialize streaming connections: %v", err)
		}

		// Start streaming routines
		go sc.streamProcessor(ctx)
		go sc.connectionMonitor(ctx)
	}

	logrus.Info("Enhanced streaming log collector started")
	return nil
}

// Stop stops the streaming collector
func (sc *StreamingCollector) Stop() error {
	sc.streamingMutex.Lock()
	sc.isStreaming = false
	sc.streamingMutex.Unlock()

	// Close connections
	sc.closeConnections()

	// Stop base collector
	return sc.collector.Stop()
}

// handleLogEntry processes log entries for both batching and streaming
func (sc *StreamingCollector) handleLogEntry(entries []LogEntry) {
	// Send to base collector for batching (fallback)
	sc.collector.addEntriesToBatch(entries)

	// Stream entries if streaming is enabled
	if sc.config.EnableStreaming && sc.isStreaming {
		for _, entry := range entries {
			select {
			case sc.streamBuffer <- entry:
			default:
				logrus.Warn("Stream buffer full, dropping log entry")
			}
		}
	}
}

// AddEntriesToBatch wraps the base collector's method and adds streaming
func (sc *StreamingCollector) AddEntriesToBatch(entries []LogEntry) {
	// Send to base collector for batching
	sc.collector.addEntriesToBatch(entries)

	// Stream entries if streaming is enabled
	if sc.config.EnableStreaming && sc.isStreaming {
		for _, entry := range entries {
			select {
			case sc.streamBuffer <- entry:
			default:
				logrus.Warn("Stream buffer full, dropping log entry")
			}
		}
	}
}

// initializeConnections sets up WebSocket connections
func (sc *StreamingCollector) initializeConnections(ctx context.Context) error {
	if sc.config.EnableDERPStreaming {
		if err := sc.connectToDERP(ctx); err != nil {
			logrus.Errorf("Failed to connect to DERP: %v", err)
		}
	}

	if sc.config.BackendWSEndpoint != "" {
		if err := sc.connectToBackend(ctx); err != nil {
			logrus.Errorf("Failed to connect to backend WebSocket: %v", err)
		}
	}

	return nil
}

// connectToDERP establishes DERP WebSocket connection
func (sc *StreamingCollector) connectToDERP(ctx context.Context) error {
	if strings.TrimSpace(sc.config.DERPEndpoint) == "" {
		return fmt.Errorf("DERP endpoint not configured")
	}

	tlsConfig := &tls.Config{}
	if sc.config.SkipDERPTLSVerify {
		tlsConfig.InsecureSkipVerify = true
	} else if parsed, err := url.Parse(sc.config.DERPEndpoint); err == nil {
		tlsConfig.ServerName = parsed.Hostname()
	}
	tlsutil.ApplyPQCConfig(tlsConfig)

	dialer := &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		TLSClientConfig:  tlsConfig,
	}

	headers := http.Header{}
	headers.Set("X-Client-ID", sc.config.DERPClientID)
	headers.Set("X-Public-Key", sc.config.DERPPublicKey)
	headers.Set("X-Agent-Token", sc.config.AgentToken)

	conn, _, err := dialer.DialContext(ctx, sc.config.DERPEndpoint, headers)
	if err != nil {
		return fmt.Errorf("DERP connection failed: %w", err)
	}

	sc.connMutex.Lock()
	sc.derpConn = conn
	sc.connMutex.Unlock()

	// Send registration message
	regMsg := StreamMessage{
		Type:      "register",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"client_id":       sc.config.DERPClientID,
			"cluster_id":      sc.config.ClusterID,
			"organization_id": fmt.Sprintf("%d", sc.config.OrganizationID),
			"agent_type":      "log_streaming",
			"region":          sc.config.DERPRegion,
		},
	}

	if err := conn.WriteJSON(regMsg); err != nil {
		return fmt.Errorf("failed to send registration: %w", err)
	}

	logrus.Info("Connected to DERP for log streaming")
	return nil
}

// connectToBackend establishes backend WebSocket connection
func (sc *StreamingCollector) connectToBackend(ctx context.Context) error {
	dialer := &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+sc.config.AgentToken)
	headers.Set("X-Cluster-ID", sc.config.ClusterID)

	conn, _, err := dialer.DialContext(ctx, sc.config.BackendWSEndpoint, headers)
	if err != nil {
		return fmt.Errorf("backend WebSocket connection failed: %w", err)
	}

	sc.connMutex.Lock()
	sc.backendConn = conn
	sc.connMutex.Unlock()

	logrus.Info("Connected to backend WebSocket for log streaming")
	return nil
}

// streamProcessor handles the streaming of log entries
func (sc *StreamingCollector) streamProcessor(ctx context.Context) {
	sc.streamingMutex.Lock()
	sc.isStreaming = true
	sc.streamingMutex.Unlock()

	ticker := time.NewTicker(sc.config.StreamFlushInterval)
	defer ticker.Stop()

	var batch []LogEntry
	var lastFlush time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case entry := <-sc.streamBuffer:
			batch = append(batch, entry)

			// Stream immediately if batch is full or enough time has passed
			if len(batch) >= 10 || time.Since(lastFlush) > sc.config.StreamFlushInterval {
				sc.streamBatch(batch)
				batch = nil
				lastFlush = time.Now()
			}
		case <-ticker.C:
			if len(batch) > 0 {
				sc.streamBatch(batch)
				batch = nil
				lastFlush = time.Now()
			}
		}
	}
}

// streamBatch sends a batch of log entries via streaming
func (sc *StreamingCollector) streamBatch(entries []LogEntry) {
	if len(entries) == 0 {
		return
	}

	message := StreamMessage{
		Type:      "log_batch",
		Timestamp: time.Now(),
		Data:      entries,
		Metadata: map[string]interface{}{
			"batch_size":  len(entries),
			"cluster_id":  sc.config.ClusterID,
			"compression": sc.config.EnableCompression,
		},
	}

	// Try DERP first, then fallback to backend WebSocket
	if !sc.sendViaDERP(message) {
		sc.sendViaBackend(message)
	}
}

// sendViaDERP sends message via DERP connection
func (sc *StreamingCollector) sendViaDERP(message StreamMessage) bool {
	sc.connMutex.RLock()
	conn := sc.derpConn
	sc.connMutex.RUnlock()

	if conn == nil {
		return false
	}

	// Wrap in DERP message format
	derpMessage := map[string]interface{}{
		"type":    "relay",
		"target":  "backend",
		"payload": message,
	}

	if err := conn.WriteJSON(derpMessage); err != nil {
		logrus.Errorf("Failed to send via DERP: %v", err)
		return false
	}

	logrus.Debugf("Sent %d log entries via DERP", len(message.Data.([]LogEntry)))
	return true
}

// sendViaBackend sends message via backend WebSocket
func (sc *StreamingCollector) sendViaBackend(message StreamMessage) bool {
	sc.connMutex.RLock()
	conn := sc.backendConn
	sc.connMutex.RUnlock()

	if conn == nil {
		return false
	}

	if err := conn.WriteJSON(message); err != nil {
		logrus.Errorf("Failed to send via backend WebSocket: %v", err)
		return false
	}

	logrus.Debugf("Sent %d log entries via backend WebSocket", len(message.Data.([]LogEntry)))
	return true
}

// connectionMonitor monitors and maintains connections
func (sc *StreamingCollector) connectionMonitor(ctx context.Context) {
	ticker := time.NewTicker(sc.config.ReconnectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sc.checkAndReconnect(ctx)
		}
	}
}

// checkAndReconnect checks connection health and reconnects if needed
func (sc *StreamingCollector) checkAndReconnect(ctx context.Context) {
	sc.connMutex.RLock()
	derpConn := sc.derpConn
	backendConn := sc.backendConn
	sc.connMutex.RUnlock()

	// Check DERP connection
	if sc.config.EnableDERPStreaming && derpConn != nil {
		if err := derpConn.WriteMessage(websocket.PingMessage, nil); err != nil {
			logrus.Warn("DERP connection lost, attempting reconnect")
			sc.reconnectDERP(ctx)
		}
	}

	// Check backend connection
	if sc.config.BackendWSEndpoint != "" && backendConn != nil {
		if err := backendConn.WriteMessage(websocket.PingMessage, nil); err != nil {
			logrus.Warn("Backend WebSocket connection lost, attempting reconnect")
			sc.reconnectBackend(ctx)
		}
	}
}

// reconnectDERP attempts to reconnect to DERP
func (sc *StreamingCollector) reconnectDERP(ctx context.Context) {
	sc.connMutex.Lock()
	if sc.derpConn != nil {
		sc.derpConn.Close()
		sc.derpConn = nil
	}
	sc.connMutex.Unlock()

	for attempt := 0; attempt < sc.config.MaxReconnectAttempts; attempt++ {
		time.Sleep(time.Duration(attempt+1) * time.Second)

		if err := sc.connectToDERP(ctx); err == nil {
			logrus.Info("Successfully reconnected to DERP")
			return
		}
	}

	logrus.Error("Failed to reconnect to DERP after maximum attempts")
}

// reconnectBackend attempts to reconnect to backend WebSocket
func (sc *StreamingCollector) reconnectBackend(ctx context.Context) {
	sc.connMutex.Lock()
	if sc.backendConn != nil {
		sc.backendConn.Close()
		sc.backendConn = nil
	}
	sc.connMutex.Unlock()

	for attempt := 0; attempt < sc.config.MaxReconnectAttempts; attempt++ {
		time.Sleep(time.Duration(attempt+1) * time.Second)

		if err := sc.connectToBackend(ctx); err == nil {
			logrus.Info("Successfully reconnected to backend WebSocket")
			return
		}
	}

	logrus.Error("Failed to reconnect to backend WebSocket after maximum attempts")
}

// closeConnections closes all WebSocket connections
func (sc *StreamingCollector) closeConnections() {
	sc.connMutex.Lock()
	defer sc.connMutex.Unlock()

	if sc.derpConn != nil {
		sc.derpConn.Close()
		sc.derpConn = nil
	}

	if sc.backendConn != nil {
		sc.backendConn.Close()
		sc.backendConn = nil
	}
}

// GetStreamingStats returns statistics about streaming performance
func (sc *StreamingCollector) GetStreamingStats() map[string]interface{} {
	sc.streamingMutex.RLock()
	defer sc.streamingMutex.RUnlock()

	return map[string]interface{}{
		"is_streaming":       sc.isStreaming,
		"buffer_size":        len(sc.streamBuffer),
		"buffer_capacity":    cap(sc.streamBuffer),
		"derp_connected":     sc.derpConn != nil,
		"backend_connected":  sc.backendConn != nil,
		"enable_derp":        sc.config.EnableDERPStreaming,
		"enable_compression": sc.config.EnableCompression,
	}
}
