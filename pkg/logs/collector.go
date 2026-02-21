package logs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
)

// LogCollector collects logs from Kubernetes and sends them to the ingestion service
type LogCollector struct {
	config              *Config
	httpClient          *http.Client
	batch               *LogBatch
	batchMutex          sync.Mutex
	lastCollection      time.Time
	isRunning           bool
	bufferEnabled       bool
	bufferDir           string
	bufferMaxFiles      int
	bufferMaxBytes      int64
	bufferDrainInterval time.Duration
	bufferMutex         sync.Mutex
}

var (
	logBatchesProcessed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "prysm_agent_log_batches_total",
			Help: "Number of log batches processed by the agent",
		},
		[]string{"result"},
	)
	logBufferQueueSize = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "prysm_agent_log_buffer_queue_size",
			Help: "Pending buffered log batches awaiting resend",
		},
	)
	logBufferErrorsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "prysm_agent_log_buffer_errors_total",
			Help: "Errors while buffering or draining log batches",
		},
	)
)

// Config contains configuration for the log collector
type Config struct {
	// Agent identification
	AgentID        string `json:"agent_id"`
	AgentToken     string `json:"agent_token"`
	ClusterID      string `json:"cluster_id"`
	OrganizationID uint   `json:"organization_id"`

	// Ingestion service endpoints
	IngestionURL   string `json:"ingestion_url"`
	PrivateLinkURL string `json:"private_link_url,omitempty"`
	PrivateLinkKey string `json:"private_link_key,omitempty"`

	// Collection settings
	BatchSize          int           `json:"batch_size"`
	BatchTimeout       time.Duration `json:"batch_timeout"`
	CollectionInterval time.Duration `json:"collection_interval"`
	MaxRetries         int           `json:"max_retries"`

	// Log sources
	EnabledSources    []LogSource `json:"enabled_sources"`
	ExcludeNamespaces []string    `json:"exclude_namespaces"`
	IncludeLevels     []LogLevel  `json:"include_levels"`
	MaxMessageSize    int         `json:"max_message_size"`

	// DERP network settings
	DERPRegion     string `json:"derp_region,omitempty"`
	UsePrivateLink bool   `json:"use_private_link"`

	// Local buffering
	EnableFileBuffer    bool          `json:"enable_file_buffer"`
	BufferDirectory     string        `json:"buffer_directory"`
	BufferMaxFiles      int           `json:"buffer_max_files"`
	BufferMaxSizeMB     int           `json:"buffer_max_size_mb"`
	BufferDrainInterval time.Duration `json:"buffer_drain_interval"`
}

// LogLevel represents log severity levels
type LogLevel string

const (
	LogLevelTrace LogLevel = "trace"
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
)

// LogSource represents the source of log entries
type LogSource string

const (
	LogSourcePod       LogSource = "pod"
	LogSourceContainer LogSource = "container"
	LogSourceEvent     LogSource = "event"
	LogSourceAudit     LogSource = "audit"
	LogSourceSystem    LogSource = "system"
	LogSourceIngress   LogSource = "ingress"
	LogSourceNetwork   LogSource = "network"
)

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	Level       LogLevel               `json:"level"`
	Message     string                 `json:"message"`
	Source      LogSource              `json:"source"`
	ClusterID   string                 `json:"cluster_id"`
	Namespace   string                 `json:"namespace,omitempty"`
	Pod         string                 `json:"pod,omitempty"`
	Container   string                 `json:"container,omitempty"`
	Node        string                 `json:"node,omitempty"`
	Labels      map[string]string      `json:"labels,omitempty"`
	Annotations map[string]string      `json:"annotations,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// LogBatch represents a batch of log entries for efficient transmission
type LogBatch struct {
	ID        string     `json:"id"`
	AgentID   string     `json:"agent_id"`
	ClusterID string     `json:"cluster_id"`
	Entries   []LogEntry `json:"entries"`
	Timestamp time.Time  `json:"timestamp"`
	Checksum  string     `json:"checksum,omitempty"`
}

// IngestionRequest represents the request sent to the ingestion service
type IngestionRequest struct {
	AgentToken  string     `json:"agent_token"`
	BatchID     string     `json:"batch_id"`
	ClusterID   string     `json:"cluster_id"`
	Timestamp   time.Time  `json:"timestamp"`
	Compression string     `json:"compression,omitempty"`
	Logs        []LogEntry `json:"logs"`
	Checksum    string     `json:"checksum,omitempty"`
}

// ParseOrgIDFromToken extracts organization ID from agent token
// Token format: tkn_<base64(org_{orgID}_{randomHex})>
func ParseOrgIDFromToken(token string) (uint, error) {
	const prefix = "tkn_"
	if !strings.HasPrefix(token, prefix) {
		return 0, fmt.Errorf("invalid token format: missing tkn_ prefix")
	}

	encoded := token[len(prefix):]
	if pad := len(encoded) % 4; pad != 0 {
		encoded += strings.Repeat("=", 4-pad)
	}

	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return 0, fmt.Errorf("invalid token format: base64 decode failed: %w", err)
	}

	var orgID uint
	if _, err := fmt.Sscanf(string(decoded), "org_%d_", &orgID); err != nil {
		return 0, fmt.Errorf("invalid token format: org ID parse failed: %w", err)
	}

	return orgID, nil
}

// NewLogCollector creates a new log collector instance
func NewLogCollector(config *Config) *LogCollector {
	// If OrganizationID is not set but AgentToken is, try to extract from token
	if config.OrganizationID == 0 && config.AgentToken != "" {
		if orgID, err := ParseOrgIDFromToken(config.AgentToken); err == nil {
			config.OrganizationID = orgID
			logrus.Infof("Parsed organization ID %d from agent token", orgID)
		}
	}
	bufferDir := strings.TrimSpace(config.BufferDirectory)
	bufferMaxFiles := config.BufferMaxFiles
	bufferMaxBytes := int64(config.BufferMaxSizeMB) * 1024 * 1024
	bufferDrainInterval := config.BufferDrainInterval

	if bufferMaxFiles < 0 {
		bufferMaxFiles = 0
	}
	if bufferMaxBytes < 0 {
		bufferMaxBytes = 0
	}
	if bufferDrainInterval <= 0 {
		bufferDrainInterval = time.Minute
	}

	return &LogCollector{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		batch: &LogBatch{
			ID:        generateBatchID(),
			AgentID:   config.AgentID,
			ClusterID: config.ClusterID,
			Entries:   make([]LogEntry, 0, config.BatchSize),
			Timestamp: time.Now(),
		},
		bufferEnabled:       config.EnableFileBuffer,
		bufferDir:           bufferDir,
		bufferMaxFiles:      bufferMaxFiles,
		bufferMaxBytes:      bufferMaxBytes,
		bufferDrainInterval: bufferDrainInterval,
	}
}

// Start starts the log collection process
func (lc *LogCollector) Start(ctx context.Context) error {
	if lc.isRunning {
		return fmt.Errorf("log collector is already running")
	}

	logrus.Info("Starting log collector")
	lc.isRunning = true

	if lc.bufferEnabled {
		if lc.bufferDir == "" {
			lc.bufferDir = "/var/lib/prysm/log-buffer"
		}
		if err := os.MkdirAll(lc.bufferDir, 0o755); err != nil {
			logrus.Errorf("Failed to create buffer directory %s: %v", lc.bufferDir, err)
			lc.bufferEnabled = false
		} else {
			lc.updateBufferMetrics()
			go lc.bufferDrainLoop(ctx)
		}
	}

	// Start collection loops for each enabled source
	for _, source := range lc.config.EnabledSources {
		go lc.collectFromSource(ctx, source)
	}

	// Start batch flushing routine
	go lc.batchFlusher(ctx)

	logrus.Infof("Log collector started with sources: %v", lc.config.EnabledSources)
	return nil
}

// Stop stops the log collection process
func (lc *LogCollector) Stop() error {
	if !lc.isRunning {
		return nil
	}

	logrus.Info("Stopping log collector")
	lc.isRunning = false

	// Flush any remaining logs
	if err := lc.flushBatch(); err != nil {
		logrus.Errorf("Failed to flush final batch: %v", err)
	}

	return nil
}

// collectFromSource collects logs from a specific source
func (lc *LogCollector) collectFromSource(ctx context.Context, source LogSource) {
	ticker := time.NewTicker(lc.config.CollectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !lc.isRunning {
				return
			}

			entries, err := lc.collectLogs(source)
			if err != nil {
				logrus.Errorf("Failed to collect logs from %s: %v", source, err)
				continue
			}

			if len(entries) > 0 {
				lc.addEntriesToBatch(entries)
				logrus.Debugf("Collected %d log entries from %s", len(entries), source)
			}
		}
	}
}

// collectLogs collects logs from a specific source
func (lc *LogCollector) collectLogs(source LogSource) ([]LogEntry, error) {
	switch source {
	case LogSourcePod:
		return lc.collectPodLogs()
	case LogSourceEvent:
		return lc.collectEvents()
	case LogSourceAudit:
		return lc.collectAuditLogs()
	case LogSourceSystem:
		return lc.collectSystemLogs()
	default:
		return nil, fmt.Errorf("unsupported log source: %s", source)
	}
}

// collectPodLogs collects logs from pods
func (lc *LogCollector) collectPodLogs() ([]LogEntry, error) {
	var entries []LogEntry

	// Get pods from all non-excluded namespaces
	cmd := exec.Command("kubectl", "get", "pods", "--all-namespaces",
		"--no-headers", "-o", "custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,NODE:.spec.nodeName")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get pods: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		namespace := parts[0]
		podName := parts[1]
		nodeName := parts[2]

		// Skip excluded namespaces
		if lc.isNamespaceExcluded(namespace) {
			continue
		}

		// Get logs for this pod
		podEntries, err := lc.getPodLogs(namespace, podName, nodeName)
		if err != nil {
			logrus.Debugf("Failed to get logs for pod %s/%s: %v", namespace, podName, err)
			continue
		}

		entries = append(entries, podEntries...)
	}

	return entries, nil
}

// getPodLogs gets logs for a specific pod
func (lc *LogCollector) getPodLogs(namespace, podName, nodeName string) ([]LogEntry, error) {
	// Get logs since last collection
	since := lc.lastCollection.Format(time.RFC3339)
	if lc.lastCollection.IsZero() {
		since = time.Now().Add(-time.Minute).Format(time.RFC3339) // Last minute if first run
	}

	cmd := exec.Command("kubectl", "logs", podName, "-n", namespace,
		"--since-time="+since, "--timestamps=true", "--tail=100")

	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if strings.Contains(message, "no such file or directory") {
			logrus.Debugf("Pod logs unavailable for %s/%s: %s", namespace, podName, message)
			return nil, nil
		}
		return nil, fmt.Errorf("%v: %s", err, message)
	}

	return lc.parsePodLogs(string(output), namespace, podName, nodeName), nil
}

// parsePodLogs parses kubectl logs output into LogEntry structures
func (lc *LogCollector) parsePodLogs(output, namespace, podName, nodeName string) []LogEntry {
	var entries []LogEntry
	lines := strings.Split(strings.TrimSpace(output), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		entry := lc.parseLogLine(line, LogSourcePod, namespace, podName, nodeName)
		if entry != nil && lc.shouldIncludeEntry(entry) {
			entries = append(entries, *entry)
		}
	}

	return entries
}

// parseLogLine parses a single log line into a LogEntry
func (lc *LogCollector) parseLogLine(line string, source LogSource, namespace, podName, nodeName string) *LogEntry {
	// Parse timestamped log line format: "2023-01-01T12:00:00.000Z log message here"
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return nil
	}

	timestamp, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		timestamp = time.Now()
	}

	message := parts[1]
	if len(message) > lc.config.MaxMessageSize {
		message = message[:lc.config.MaxMessageSize] + "...[truncated]"
	}

	// Determine log level from message content
	level := lc.inferLogLevel(message)

	return &LogEntry{
		Timestamp: timestamp,
		Level:     level,
		Message:   message,
		Source:    source,
		ClusterID: lc.config.ClusterID,
		Namespace: namespace,
		Pod:       podName,
		Node:      nodeName,
		Metadata: map[string]interface{}{
			"collected_at": time.Now(),
			"agent_id":     lc.config.AgentID,
		},
	}
}

// collectEvents collects Kubernetes events
func (lc *LogCollector) collectEvents() ([]LogEntry, error) {
	cmd := exec.Command("kubectl", "get", "events", "--all-namespaces",
		"--sort-by=.metadata.creationTimestamp", "-o", "json")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %v", err)
	}

	return lc.parseEvents(output)
}

// parseEvents parses kubectl events JSON output
func (lc *LogCollector) parseEvents(jsonData []byte) ([]LogEntry, error) {
	var events struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			FirstTimestamp string `json:"firstTimestamp"`
			LastTimestamp  string `json:"lastTimestamp"`
			Type           string `json:"type"`
			Reason         string `json:"reason"`
			Message        string `json:"message"`
			Source         struct {
				Component string `json:"component"`
			} `json:"source"`
		} `json:"items"`
	}

	if err := json.Unmarshal(jsonData, &events); err != nil {
		return nil, err
	}

	var entries []LogEntry
	for _, event := range events.Items {
		timestamp, _ := time.Parse(time.RFC3339, event.LastTimestamp)

		// Only include recent events
		if time.Since(timestamp) > time.Hour {
			continue
		}

		level := LogLevelInfo
		if event.Type == "Warning" {
			level = LogLevelWarn
		}

		entry := LogEntry{
			Timestamp: timestamp,
			Level:     level,
			Message:   fmt.Sprintf("[%s] %s: %s", event.Reason, event.Source.Component, event.Message),
			Source:    LogSourceEvent,
			ClusterID: lc.config.ClusterID,
			Namespace: event.Metadata.Namespace,
			Metadata: map[string]interface{}{
				"event_type":   event.Type,
				"event_reason": event.Reason,
				"component":    event.Source.Component,
			},
		}

		if lc.shouldIncludeEntry(&entry) {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// collectAuditLogs collects audit logs (placeholder implementation)
func (lc *LogCollector) collectAuditLogs() ([]LogEntry, error) {
	// TODO: Implement audit log collection
	// This would require access to audit log files or API server audit webhook
	return []LogEntry{}, nil
}

// collectSystemLogs collects system-level logs
func (lc *LogCollector) collectSystemLogs() ([]LogEntry, error) {
	// Collect logs from system pods in kube-system namespace
	return lc.getSystemPodLogs()
}

// getSystemPodLogs gets logs from system pods
func (lc *LogCollector) getSystemPodLogs() ([]LogEntry, error) {
	cmd := exec.Command("kubectl", "get", "pods", "-n", "kube-system",
		"--no-headers", "-o", "custom-columns=NAME:.metadata.name")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get system pods: %v", err)
	}

	var entries []LogEntry
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, podName := range lines {
		if podName == "" {
			continue
		}

		podEntries, err := lc.getPodLogs("kube-system", podName, "")
		if err != nil {
			continue
		}

		entries = append(entries, podEntries...)
	}

	return entries, nil
}

// addEntriesToBatch adds log entries to the current batch
func (lc *LogCollector) addEntriesToBatch(entries []LogEntry) {
	lc.batchMutex.Lock()
	defer lc.batchMutex.Unlock()

	for _, entry := range entries {
		lc.batch.Entries = append(lc.batch.Entries, entry)

		// Flush batch if it's full
		if len(lc.batch.Entries) >= lc.config.BatchSize {
			go lc.flushBatch()
			break
		}
	}
}

// batchFlusher periodically flushes batches based on timeout
func (lc *LogCollector) batchFlusher(ctx context.Context) {
	ticker := time.NewTicker(lc.config.BatchTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !lc.isRunning {
				return
			}

			lc.batchMutex.Lock()
			if len(lc.batch.Entries) > 0 {
				go lc.flushBatch()
			}
			lc.batchMutex.Unlock()
		}
	}
}

// flushBatch sends the current batch to the ingestion service
func (lc *LogCollector) flushBatch() error {
	lc.batchMutex.Lock()
	defer lc.batchMutex.Unlock()

	if len(lc.batch.Entries) == 0 {
		return nil
	}

	// Calculate checksum
	lc.batch.Checksum = lc.calculateBatchChecksum()

	// Create ingestion request
	request := IngestionRequest{
		AgentToken: lc.config.AgentToken,
		BatchID:    lc.batch.ID,
		ClusterID:  lc.config.ClusterID,
		Timestamp:  lc.batch.Timestamp,
		Logs:       lc.batch.Entries,
		Checksum:   lc.batch.Checksum,
	}

	// Send to ingestion service
	if err := lc.sendToIngestionService(&request); err != nil {
		logrus.Errorf("Failed to send batch %s: %v", lc.batch.ID, err)
		logBatchesProcessed.WithLabelValues("failed").Inc()
		if lc.bufferEnabled {
			if persistErr := lc.persistBatch(&request); persistErr != nil {
				logBufferErrorsTotal.Inc()
				return fmt.Errorf("failed to send batch: %v (buffer persist error: %v)", err, persistErr)
			}
			logrus.Warnf("Buffered batch %s for later retry", lc.batch.ID)
			logBatchesProcessed.WithLabelValues("buffered").Inc()
		} else {
			return fmt.Errorf("failed to send batch: %v", err)
		}
	} else {
		logrus.Infof("Successfully sent batch %s with %d entries", lc.batch.ID, len(lc.batch.Entries))
		logBatchesProcessed.WithLabelValues("sent").Inc()
	}

	// Reset batch
	lc.batch = &LogBatch{
		ID:        generateBatchID(),
		AgentID:   lc.config.AgentID,
		ClusterID: lc.config.ClusterID,
		Entries:   make([]LogEntry, 0, lc.config.BatchSize),
		Timestamp: time.Now(),
	}

	lc.lastCollection = time.Now()
	return nil
}

// sendToIngestionService sends logs to the ingestion service
func (lc *LogCollector) sendToIngestionService(request *IngestionRequest) error {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	// Choose endpoint (private link vs regular)
	url := lc.config.IngestionURL + "/api/v1/logs/ingest"
	if lc.config.UsePrivateLink && lc.config.PrivateLinkURL != "" {
		url = lc.config.PrivateLinkURL + "/private/logs/ingest"
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "prysm-agent/1.0")

	// Set authentication headers
	if lc.config.UsePrivateLink && lc.config.PrivateLinkKey != "" {
		req.Header.Set("X-Private-Link-Key", lc.config.PrivateLinkKey)
	} else {
		req.Header.Set("Authorization", "Bearer "+lc.config.AgentToken)
	}

	// Add DERP region if specified
	if lc.config.DERPRegion != "" {
		req.Header.Set("X-DERP-Region", lc.config.DERPRegion)
	}

	// Send request with retries
	var lastErr error
	for attempt := 0; attempt <= lc.config.MaxRetries; attempt++ {
		resp, err := lc.httpClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return nil
		}

		body, _ := io.ReadAll(resp.Body)
		lastErr = fmt.Errorf("ingestion failed with status %d: %s", resp.StatusCode, string(body))

		if resp.StatusCode < 500 {
			break // Don't retry client errors
		}

		time.Sleep(time.Duration(attempt+1) * time.Second)
	}

	return lastErr
}

// Helper functions

func (lc *LogCollector) isNamespaceExcluded(namespace string) bool {
	for _, excluded := range lc.config.ExcludeNamespaces {
		if namespace == excluded {
			return true
		}
	}
	return false
}

func (lc *LogCollector) shouldIncludeEntry(entry *LogEntry) bool {
	// Check if log level is included
	for _, level := range lc.config.IncludeLevels {
		if entry.Level == level {
			return true
		}
	}
	return len(lc.config.IncludeLevels) == 0 // Include all if no filter specified
}

func (lc *LogCollector) inferLogLevel(message string) LogLevel {
	lowerMsg := strings.ToLower(message)

	if strings.Contains(lowerMsg, "error") || strings.Contains(lowerMsg, "err") {
		return LogLevelError
	}
	if strings.Contains(lowerMsg, "warn") || strings.Contains(lowerMsg, "warning") {
		return LogLevelWarn
	}
	if strings.Contains(lowerMsg, "debug") {
		return LogLevelDebug
	}
	if strings.Contains(lowerMsg, "fatal") || strings.Contains(lowerMsg, "panic") {
		return LogLevelFatal
	}

	return LogLevelInfo
}

func (lc *LogCollector) calculateBatchChecksum() string {
	data, _ := json.Marshal(lc.batch.Entries)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func generateBatchID() string {
	return fmt.Sprintf("batch_%d_%s", time.Now().Unix(),
		hex.EncodeToString([]byte(strconv.FormatInt(time.Now().UnixNano(), 36)))[0:8])
}

// Buffer helpers

func (lc *LogCollector) persistBatch(request *IngestionRequest) error {
	lc.bufferMutex.Lock()
	defer lc.bufferMutex.Unlock()

	if lc.bufferDir == "" {
		return fmt.Errorf("buffer directory not configured")
	}

	if err := lc.enforceBufferLimits(); err != nil {
		return err
	}

	filename := fmt.Sprintf("%d_%s.json", time.Now().UnixNano(), request.BatchID)
	path := filepath.Join(lc.bufferDir, filename)

	data, err := json.Marshal(request)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}

	lc.updateBufferMetrics()
	return nil
}

func (lc *LogCollector) enforceBufferLimits() error {
	if lc.bufferMaxFiles <= 0 && lc.bufferMaxBytes <= 0 {
		return nil
	}

	files, err := os.ReadDir(lc.bufferDir)
	if err != nil {
		return err
	}

	if lc.bufferMaxFiles > 0 && len(files) >= lc.bufferMaxFiles {
		return fmt.Errorf("buffer file limit reached (%d)", lc.bufferMaxFiles)
	}

	if lc.bufferMaxBytes > 0 {
		var size int64
		for _, file := range files {
			info, err := file.Info()
			if err != nil {
				continue
			}
			size += info.Size()
		}
		if size >= lc.bufferMaxBytes {
			return fmt.Errorf("buffer size limit reached (%d bytes)", lc.bufferMaxBytes)
		}
	}

	return nil
}

func (lc *LogCollector) bufferDrainLoop(ctx context.Context) {
	interval := lc.bufferDrainInterval
	if interval <= 0 {
		interval = time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lc.drainBufferedBatches()
		}
	}
}

func (lc *LogCollector) drainBufferedBatches() {
	if lc.bufferDir == "" {
		return
	}

	lc.bufferMutex.Lock()
	files, err := os.ReadDir(lc.bufferDir)
	lc.bufferMutex.Unlock()
	if err != nil {
		logrus.Errorf("Failed to read buffer directory: %v", err)
		logBufferErrorsTotal.Inc()
		return
	}

	if len(files) == 0 {
		lc.updateBufferMetrics()
		return
	}

	sort.Slice(files, func(i, j int) bool {
		infoI, _ := files[i].Info()
		infoJ, _ := files[j].Info()
		if infoI == nil || infoJ == nil {
			return files[i].Name() < files[j].Name()
		}
		return infoI.ModTime().Before(infoJ.ModTime())
	})

	for _, file := range files {
		path := filepath.Join(lc.bufferDir, file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			logrus.Errorf("Failed to read buffered batch %s: %v", file.Name(), err)
			logBufferErrorsTotal.Inc()
			continue
		}

		var request IngestionRequest
		if err := json.Unmarshal(data, &request); err != nil {
			logrus.Errorf("Invalid buffered batch %s: %v", file.Name(), err)
			logBufferErrorsTotal.Inc()
			_ = os.Remove(path)
			continue
		}

		if err := lc.sendToIngestionService(&request); err != nil {
			logrus.Warnf("Resend of buffered batch %s failed: %v", file.Name(), err)
			logBufferErrorsTotal.Inc()
			continue
		}

		logrus.Infof("Successfully drained buffered batch %s", file.Name())
		logBatchesProcessed.WithLabelValues("drained").Inc()
		_ = os.Remove(path)
	}

	lc.updateBufferMetrics()
}

func (lc *LogCollector) updateBufferMetrics() {
	if lc.bufferDir == "" {
		logBufferQueueSize.Set(0)
		return
	}
	files, err := os.ReadDir(lc.bufferDir)
	if err != nil {
		logBufferQueueSize.Set(0)
		return
	}
	logBufferQueueSize.Set(float64(len(files)))
}
