package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestLogProxyUnwrapsIngestionRequest verifies that the log proxy correctly
// unwraps ingestionRequest format (sent by the eBPF collector) instead of
// treating the entire payload as a single log entry.
func TestLogProxyUnwrapsIngestionRequest(t *testing.T) {
	// Capture what gets forwarded to the "backend"
	var received []byte
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		received = buf.Bytes()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	handler := newLogProxyHandler(logProxyConfig{
		IngestionURL:  backend.URL,
		AgentToken:    "tkn_test",
		ClusterID:     "42",
		OrgID:         1,
		BatchSize:     1, // Flush immediately
		FlushInterval: 100 * time.Millisecond,
	})

	// Simulate eBPF collector's ingestionRequest format
	payload := map[string]interface{}{
		"agent_token": "tkn_test",
		"batch_id":    "batch-123",
		"cluster_id":  "42",
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"logs": []map[string]interface{}{
			{
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"level":     "warn",
				"message":   "Suspicious outbound connection to C2 server",
				"source":    "security",
				"namespace": "default",
				"pod":       "app-pod-1",
				"tags":      []string{"security", "ebpf"},
			},
			{
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"level":     "error",
				"message":   "Process executed from /tmp",
				"source":    "ebpf",
				"namespace": "kube-system",
				"pod":       "coredns-abc",
				"tags":      []string{"security", "threat"},
			},
		},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/logs/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}

	// Wait for async flush
	time.Sleep(500 * time.Millisecond)

	if len(received) == 0 {
		t.Fatal("backend received no data")
	}

	var forwarded struct {
		Logs      []map[string]interface{} `json:"logs"`
		ClusterID string                   `json:"cluster_id"`
	}
	if err := json.Unmarshal(received, &forwarded); err != nil {
		t.Fatalf("failed to parse forwarded payload: %v", err)
	}

	// Should have 2 individual log entries, NOT 1 wrapped payload
	if len(forwarded.Logs) != 2 {
		t.Fatalf("expected 2 log entries, got %d (ingestionRequest was not unwrapped)", len(forwarded.Logs))
	}

	// Verify the first entry preserved its Source field
	if src, ok := forwarded.Logs[0]["source"].(string); !ok || src != "security" {
		t.Errorf("expected source='security', got %v", forwarded.Logs[0]["source"])
	}
	if src, ok := forwarded.Logs[1]["source"].(string); !ok || src != "ebpf" {
		t.Errorf("expected source='ebpf', got %v", forwarded.Logs[1]["source"])
	}
}

// TestLogProxySingleLogEntry verifies that a regular single log entry (not
// ingestionRequest format) is still handled correctly.
func TestLogProxySingleLogEntry(t *testing.T) {
	var received []byte
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		received = buf.Bytes()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	handler := newLogProxyHandler(logProxyConfig{
		IngestionURL:  backend.URL,
		AgentToken:    "tkn_test",
		ClusterID:     "42",
		OrgID:         1,
		BatchSize:     1,
		FlushInterval: 100 * time.Millisecond,
	})

	// Single log entry (NOT ingestionRequest format)
	payload := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"level":     "info",
		"message":   "Application started",
		"source":    "app",
		"namespace": "default",
		"pod":       "my-app-1",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/logs/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}

	time.Sleep(500 * time.Millisecond)

	if len(received) == 0 {
		t.Fatal("backend received no data")
	}

	var forwarded struct {
		Logs []map[string]interface{} `json:"logs"`
	}
	if err := json.Unmarshal(received, &forwarded); err != nil {
		t.Fatalf("failed to parse forwarded payload: %v", err)
	}

	if len(forwarded.Logs) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(forwarded.Logs))
	}

	if msg, ok := forwarded.Logs[0]["message"].(string); !ok || msg != "Application started" {
		t.Errorf("expected message='Application started', got %v", forwarded.Logs[0]["message"])
	}
}

// TestLogProxyArrayFormat verifies that a JSON array of log entries is handled correctly.
func TestLogProxyArrayFormat(t *testing.T) {
	var mu sync.Mutex
	var received []byte
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		buf := new(bytes.Buffer)
		buf.ReadFrom(r.Body)
		received = buf.Bytes()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	handler := newLogProxyHandler(logProxyConfig{
		IngestionURL:  backend.URL,
		AgentToken:    "tkn_test",
		ClusterID:     "42",
		OrgID:         1,
		BatchSize:     5,
		FlushInterval: 100 * time.Millisecond,
	})

	entries := []map[string]interface{}{
		{"timestamp": time.Now().UTC().Format(time.RFC3339), "level": "info", "message": "msg1"},
		{"timestamp": time.Now().UTC().Format(time.RFC3339), "level": "warn", "message": "msg2"},
		{"timestamp": time.Now().UTC().Format(time.RFC3339), "level": "error", "message": "msg3"},
	}
	body, _ := json.Marshal(entries)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/logs/ingest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}

	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	data := received
	mu.Unlock()

	if len(data) == 0 {
		t.Fatal("backend received no data")
	}

	var forwarded struct {
		Logs []map[string]interface{} `json:"logs"`
	}
	if err := json.Unmarshal(data, &forwarded); err != nil {
		t.Fatalf("failed to parse forwarded payload: %v", err)
	}

	if len(forwarded.Logs) != 3 {
		t.Fatalf("expected 3 log entries, got %d", len(forwarded.Logs))
	}
}
