// Package main: log proxy handler for the agent.
// Fluent Bit sends logs to the agent, which proxies them to the remote prysm-ingestion-api.
// This allows Fluent Bit to use a local endpoint and the agent handles auth/batching/retries.

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// logProxyConfig holds configuration for the log proxy
type logProxyConfig struct {
	IngestionURL   string        // Full URL e.g. http://backend/api/v1/logs/ingest or .../ingest/fluent
	SendRawArray  bool          // If true, send body as raw JSON array (for /fluent); else wrapped object
	AgentToken    string
	ClusterID     string
	OrgID         uint
	BatchSize     int
	FlushInterval time.Duration
}

// logProxyHandler handles incoming logs from Fluent Bit and proxies to remote
type logProxyHandler struct {
	config     logProxyConfig
	httpClient *http.Client
	
	// Batching
	mu        sync.Mutex
	batch     []map[string]interface{}
	lastFlush time.Time
}

func newLogProxyHandler(cfg logProxyConfig) *logProxyHandler {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 5 * time.Second
	}
	
	h := &logProxyHandler{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		batch:     make([]map[string]interface{}, 0, cfg.BatchSize),
		lastFlush: time.Now(),
	}
	
	// Start background flusher
	go h.backgroundFlusher()
	
	return h
}

// ServeHTTP handles log ingestion requests from Fluent Bit
func (h *logProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse Fluent Bit JSON (can be array or object)
	var logs []map[string]interface{}
	if len(body) > 0 && body[0] == '[' {
		if err := json.Unmarshal(body, &logs); err != nil {
			log.Printf("log-proxy: failed to parse array: %v", err)
			http.Error(w, "invalid JSON array", http.StatusBadRequest)
			return
		}
	} else {
		var single map[string]interface{}
		if err := json.Unmarshal(body, &single); err != nil {
			log.Printf("log-proxy: failed to parse object: %v", err)
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		logs = []map[string]interface{}{single}
	}

	// Add to batch
	h.mu.Lock()
	h.batch = append(h.batch, logs...)
	shouldFlush := len(h.batch) >= h.config.BatchSize
	h.mu.Unlock()

	if shouldFlush {
		go h.flush()
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"accepted"}`))
}

// backgroundFlusher periodically flushes the batch
func (h *logProxyHandler) backgroundFlusher() {
	ticker := time.NewTicker(h.config.FlushInterval)
	defer ticker.Stop()

	for range ticker.C {
		h.mu.Lock()
		if len(h.batch) > 0 && time.Since(h.lastFlush) >= h.config.FlushInterval {
			h.mu.Unlock()
			h.flush()
		} else {
			h.mu.Unlock()
		}
	}
}

// flush sends the current batch to the remote prysm-ingestion-api
func (h *logProxyHandler) flush() {
	h.mu.Lock()
	if len(h.batch) == 0 {
		h.mu.Unlock()
		return
	}
	toSend := h.batch
	h.batch = make([]map[string]interface{}, 0, h.config.BatchSize)
	h.lastFlush = time.Now()
	h.mu.Unlock()

	// Split into chunks of max 500 logs to avoid 413 errors
	const maxChunkSize = 500
	for i := 0; i < len(toSend); i += maxChunkSize {
		end := i + maxChunkSize
		if end > len(toSend) {
			end = len(toSend)
		}
		chunk := toSend[i:end]
		h.sendChunk(chunk)
	}
}

// sendChunk sends a single chunk to the remote backend
func (h *logProxyHandler) sendChunk(logs []map[string]interface{}) {
	var jsonData []byte
	var err error
	if h.config.SendRawArray {
		// Backend /fluent expects raw JSON array
		jsonData, err = json.Marshal(logs)
	} else {
		payload := map[string]interface{}{
			"logs":       logs,
			"cluster_id": h.config.ClusterID,
			"source":     "fluent-bit-proxy",
		}
		jsonData, err = json.Marshal(payload)
	}
	if err != nil {
		log.Printf("log-proxy: failed to marshal chunk: %v", err)
		return
	}

	url := strings.TrimSuffix(h.config.IngestionURL, "/")
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonData))
	if err != nil {
		log.Printf("log-proxy: failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.config.AgentToken)
	req.Header.Set("X-Cluster-ID", h.config.ClusterID)
	req.Header.Set("User-Agent", "prysm-agent-log-proxy/1.0")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		log.Printf("log-proxy: failed to send chunk (%d logs): %v", len(logs), err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("log-proxy: forwarded %d logs to %s", len(logs), h.config.IngestionURL)
	} else {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		log.Printf("log-proxy: remote returned %d: %s", resp.StatusCode, string(body))
	}
}

// setupLogProxyRoutes adds log proxy endpoints to the HTTP mux
func (a *PrysmAgent) setupLogProxyRoutes(mux *http.ServeMux) {
	// Agent forwards logs to the backend API, which routes to prysm-ingestion-api
	// Fluent Bit sends to /fluent; backend's ingestFluentBitLogs expects raw JSON array
	backendURL := a.BackendURL
	if backendURL == "" {
		log.Println("log-proxy: no backend URL configured, log proxy disabled")
		return
	}

	// Fluent Bit handler: forwards to backend /api/v1/logs/ingest/fluent (raw JSON array)
	fluentCfg := logProxyConfig{
		IngestionURL:   backendURL + "/api/v1/logs/ingest/fluent",
		SendRawArray:   true,
		AgentToken:     a.AgentToken,
		ClusterID:      a.ClusterID,
		OrgID:          a.OrganizationID,
		BatchSize:      100,
		FlushInterval:  5 * time.Second,
	}
	fluentHandler := newLogProxyHandler(fluentCfg)

	// Generic handler: forwards to backend /api/v1/logs/ingest (wrapped format)
	cfg := logProxyConfig{
		IngestionURL:   backendURL + "/api/v1/logs/ingest",
		SendRawArray:   false,
		AgentToken:     a.AgentToken,
		ClusterID:      a.ClusterID,
		OrgID:          a.OrganizationID,
		BatchSize:      100,
		FlushInterval:  5 * time.Second,
	}
	handler := newLogProxyHandler(cfg)

	// Fluent Bit sends to /fluent; use fluent handler so backend receives correct format
	mux.Handle("/api/v1/logs/ingest", handler)
	mux.Handle("/api/v1/logs/ingest/fluent", fluentHandler)

	// Honeypot-specific endpoint with security event tagging
	honeypotCfg := logProxyConfig{
		IngestionURL:  backendURL + "/api/v1/honeypot/events/ingest",
		AgentToken:    a.AgentToken,
		ClusterID:     a.ClusterID,
		OrgID:         a.OrganizationID,
		BatchSize:     50, // Smaller batch for faster honeypot alerts
		FlushInterval: 2 * time.Second,
	}
	honeypotHandler := newHoneypotLogHandler(honeypotCfg)
	mux.Handle("/api/v1/logs/ingest/honeypot", honeypotHandler)

	// Mesh event proxy: eBPF collector sends mesh connection events here,
	// agent forwards to backend /api/v1/agent/ztunnel/events
	meshProxy := &meshEventProxy{
		backendURL: backendURL + "/api/v1/agent/ztunnel/events",
		agentToken: a.AgentToken,
		clusterID:  a.ClusterID,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
	mux.Handle("/api/v1/agent/ztunnel/events", meshProxy)

	log.Printf("log-proxy: enabled, forwarding to %s/api/v1/logs/ingest", backendURL)
	log.Printf("log-proxy: honeypot endpoint enabled at /api/v1/logs/ingest/honeypot")
	log.Printf("log-proxy: mesh event proxy enabled at /api/v1/agent/ztunnel/events")
}

// honeypotLogHandler handles honeypot events with special processing
type honeypotLogHandler struct {
	config     logProxyConfig
	httpClient *http.Client
	mu         sync.Mutex
	batch      []map[string]interface{}
	lastFlush  time.Time
}

func newHoneypotLogHandler(cfg logProxyConfig) *honeypotLogHandler {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 2 * time.Second
	}

	h := &honeypotLogHandler{
		config:     cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		batch:      make([]map[string]interface{}, 0, cfg.BatchSize),
		lastFlush:  time.Now(),
	}

	go h.backgroundFlusher()
	return h
}

func (h *honeypotLogHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get honeypot type from header
	honeypotType := r.Header.Get("X-Honeypot-Type")
	if honeypotType == "" {
		honeypotType = "unknown"
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 5*1024*1024)) // 5MB limit
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse logs
	var logs []map[string]interface{}
	if len(body) > 0 && body[0] == '[' {
		if err := json.Unmarshal(body, &logs); err != nil {
			http.Error(w, "invalid JSON array", http.StatusBadRequest)
			return
		}
	} else {
		var single map[string]interface{}
		if err := json.Unmarshal(body, &single); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		logs = []map[string]interface{}{single}
	}

	// Enrich each log with honeypot metadata
	for i := range logs {
		logs[i]["source"] = "honeypot"
		logs[i]["honeypot_type"] = honeypotType
		logs[i]["cluster_id"] = h.config.ClusterID
		
		// Add security tags
		if _, ok := logs[i]["tags"]; !ok {
			logs[i]["tags"] = []string{"honeypot", "security", "intrusion"}
		}
		
		// Set severity based on event type
		if eventType, ok := logs[i]["eventid"].(string); ok {
			logs[i]["severity"] = classifyHoneypotEvent(eventType)
		}
	}

	// Add to batch
	h.mu.Lock()
	h.batch = append(h.batch, logs...)
	shouldFlush := len(h.batch) >= h.config.BatchSize
	h.mu.Unlock()

	if shouldFlush {
		go h.flush()
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"accepted"}`))
}

func (h *honeypotLogHandler) backgroundFlusher() {
	ticker := time.NewTicker(h.config.FlushInterval)
	defer ticker.Stop()

	for range ticker.C {
		h.mu.Lock()
		if len(h.batch) > 0 && time.Since(h.lastFlush) >= h.config.FlushInterval {
			h.mu.Unlock()
			h.flush()
		} else {
			h.mu.Unlock()
		}
	}
}

func (h *honeypotLogHandler) flush() {
	h.mu.Lock()
	if len(h.batch) == 0 {
		h.mu.Unlock()
		return
	}
	toSend := h.batch
	h.batch = make([]map[string]interface{}, 0, h.config.BatchSize)
	h.lastFlush = time.Now()
	h.mu.Unlock()

	// Send to honeypot events endpoint
	payload := map[string]interface{}{
		"events":     toSend,
		"cluster_id": h.config.ClusterID,
		"source":     "honeypot-agent",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("honeypot-proxy: failed to marshal: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, h.config.IngestionURL, bytes.NewReader(jsonData))
	if err != nil {
		log.Printf("honeypot-proxy: failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.config.AgentToken)
	req.Header.Set("X-Cluster-ID", h.config.ClusterID)
	req.Header.Set("User-Agent", "prysm-agent-honeypot-proxy/1.0")

	resp, err := h.httpClient.Do(req)
	if err != nil {
		log.Printf("honeypot-proxy: failed to send %d events: %v", len(toSend), err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("honeypot-proxy: forwarded %d honeypot events", len(toSend))
	} else {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		log.Printf("honeypot-proxy: remote returned %d: %s", resp.StatusCode, string(body))
	}
}

// classifyHoneypotEvent returns severity based on event type
func classifyHoneypotEvent(eventType string) string {
	// Critical events
	criticalEvents := []string{
		"cowrie.login.success",
		"cowrie.session.file_download",
		"dionaea.download.complete",
		"cowrie.command.input",
	}
	for _, e := range criticalEvents {
		if strings.Contains(eventType, e) || eventType == e {
			return "critical"
		}
	}

	// High severity events
	highEvents := []string{
		"cowrie.login.failed",
		"dionaea.connection",
		"heralding.auth_attempt",
	}
	for _, e := range highEvents {
		if strings.Contains(eventType, e) || eventType == e {
			return "high"
		}
	}

	// Default to medium for other honeypot events
	return "medium"
}

// meshEventProxy proxies mesh connection events from the eBPF DaemonSet to the backend.
// No batching needed since the eBPF collector already buffers and flushes in batches.
type meshEventProxy struct {
	backendURL string
	agentToken string
	clusterID  string
	httpClient *http.Client
}

func (p *meshEventProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 5*1024*1024)) // 5MB limit
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	req, err := http.NewRequest(http.MethodPost, p.backendURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("mesh-proxy: failed to create request: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.agentToken)
	req.Header.Set("X-Cluster-ID", p.clusterID)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		log.Printf("mesh-proxy: backend request failed: %v", err)
		http.Error(w, "backend unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}
