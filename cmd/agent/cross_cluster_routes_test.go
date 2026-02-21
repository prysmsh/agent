package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestNewCrossClusterRouteManager(t *testing.T) {
	agent := &PrysmAgent{
		BackendURL: "http://localhost:8080",
		AgentToken: "test-token",
		ClusterID:  "1",
	}
	m := newCrossClusterRouteManager(agent)
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if m.agent != agent {
		t.Error("agent reference mismatch")
	}
	if m.sources == nil || m.targets == nil || m.sourceConns == nil {
		t.Error("maps should be initialized")
	}
}

func TestReconcile_SourceAndTarget(t *testing.T) {
	// Mock backend that returns routes
	sourceRoute := crossClusterRouteAssignment{
		ID:               1,
		Name:             "test-source",
		SourceClusterID:  10,
		TargetClusterID:  20,
		TargetService:    "api-svc",
		TargetNamespace:  "default",
		TargetPort:       8080,
		LocalPort:        19090,
		Role:             "source",
		PeerClusterID:    20,
		PeerDERPClientID: "cluster_20",
		Enabled:          true,
	}
	targetRoute := crossClusterRouteAssignment{
		ID:               2,
		Name:             "test-target",
		SourceClusterID:  30,
		TargetClusterID:  10,
		TargetService:    "db-svc",
		TargetNamespace:  "prod",
		TargetPort:       5432,
		LocalPort:        15432,
		Role:             "target",
		PeerClusterID:    30,
		PeerDERPClientID: "cluster_30",
		Enabled:          true,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"routes": []crossClusterRouteAssignment{sourceRoute, targetRoute},
			"total":  2,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	agent := &PrysmAgent{
		BackendURL: srv.URL,
		AgentToken: "test-token",
		ClusterID:  "10",
		HTTPClient: srv.Client(),
	}
	m := newCrossClusterRouteManager(agent)

	ctx := context.Background()
	m.reconcile(ctx)

	m.mu.Lock()
	defer m.mu.Unlock()

	// Source route should have a listener
	if sr, ok := m.sources[1]; !ok {
		t.Error("expected source route 1 to be started")
	} else {
		// Verify listener is on the right port
		addr := sr.listener.Addr().String()
		if addr == "" {
			t.Error("listener should have an address")
		}
		// Cleanup
		sr.cancel()
		sr.listener.Close()
	}

	// Target route should be registered
	if _, ok := m.targets[2]; !ok {
		t.Error("expected target route 2 to be started")
	}
}

func TestReconcile_StopsRemovedRoutes(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var routes []crossClusterRouteAssignment
		if callCount == 1 {
			// First call: one source route
			routes = []crossClusterRouteAssignment{{
				ID:               1,
				Name:             "ephemeral",
				SourceClusterID:  10,
				TargetClusterID:  20,
				TargetService:    "svc",
				TargetPort:       80,
				LocalPort:        19091,
				Role:             "source",
				PeerDERPClientID: "cluster_20",
				Enabled:          true,
			}}
		}
		// Second call: empty (route removed)
		json.NewEncoder(w).Encode(map[string]interface{}{"routes": routes, "total": len(routes)})
	}))
	defer srv.Close()

	agent := &PrysmAgent{
		BackendURL: srv.URL,
		AgentToken: "test-token",
		ClusterID:  "10",
		HTTPClient: srv.Client(),
	}
	m := newCrossClusterRouteManager(agent)

	ctx := context.Background()

	// First reconcile: starts the route
	m.reconcile(ctx)
	m.mu.Lock()
	if _, ok := m.sources[1]; !ok {
		t.Fatal("expected source route to be started after first reconcile")
	}
	m.mu.Unlock()

	// Second reconcile: should stop it
	m.reconcile(ctx)
	m.mu.Lock()
	if _, ok := m.sources[1]; ok {
		t.Error("expected source route to be removed after second reconcile")
	}
	m.mu.Unlock()
}

func TestFetchRoutes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request path and headers
		expectedPath := "/api/v1/agent/cross-cluster-routes/clusters/42"
		if r.URL.Path != expectedPath {
			t.Errorf("path = %q, want %q", r.URL.Path, expectedPath)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing or wrong Authorization header")
		}
		if r.Header.Get("X-Cluster-ID") != "42" {
			t.Error("missing or wrong X-Cluster-ID header")
		}

		resp := map[string]interface{}{
			"routes": []crossClusterRouteAssignment{{
				ID:   1,
				Name: "r1",
				Role: "source",
			}},
			"total": 1,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	agent := &PrysmAgent{
		BackendURL: srv.URL,
		AgentToken: "test-token",
		ClusterID:  "42",
		HTTPClient: srv.Client(),
	}
	m := newCrossClusterRouteManager(agent)

	routes, err := m.fetchRoutes(context.Background())
	if err != nil {
		t.Fatalf("fetchRoutes error: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].Name != "r1" {
		t.Errorf("route name = %q, want r1", routes[0].Name)
	}
}

func TestFetchRoutes_BackendError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"server error"}`))
	}))
	defer srv.Close()

	agent := &PrysmAgent{
		BackendURL: srv.URL,
		AgentToken: "test-token",
		ClusterID:  "1",
		HTTPClient: srv.Client(),
	}
	m := newCrossClusterRouteManager(agent)

	_, err := m.fetchRoutes(context.Background())
	if err == nil {
		t.Fatal("expected error from backend 500")
	}
}

func TestReportStatus(t *testing.T) {
	var received struct {
		Status           string `json:"status"`
		ConnectionMethod string `json:"connection_method"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		expectedPath := "/api/v1/agent/cross-cluster-routes/42/status"
		if r.URL.Path != expectedPath {
			t.Errorf("path = %q, want %q", r.URL.Path, expectedPath)
		}
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	agent := &PrysmAgent{
		BackendURL: srv.URL,
		AgentToken: "test-token",
		ClusterID:  "1",
		HTTPClient: srv.Client(),
	}
	m := newCrossClusterRouteManager(agent)

	m.reportStatus(42, "active", "derp")

	if received.Status != "active" {
		t.Errorf("status = %q, want active", received.Status)
	}
	if received.ConnectionMethod != "derp" {
		t.Errorf("connection_method = %q, want derp", received.ConnectionMethod)
	}
}

func TestHandleCrossClusterData_TargetSide(t *testing.T) {
	agent := &PrysmAgent{}
	m := newCrossClusterRouteManager(agent)

	// Create a target route with a mock connection
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	tr := &targetRoute{
		assignment: crossClusterRouteAssignment{ID: 1},
		conns:      map[string]net.Conn{"stream_1": serverConn},
	}
	m.mu.Lock()
	m.targets[1] = tr
	m.mu.Unlock()

	// Simulate data arriving for the target
	testData := []byte("hello from source")
	payload, _ := json.Marshal(map[string]interface{}{
		"stream_id": "stream_1",
		"route_id":  1,
		"data":      testData,
	})
	msg := &derpMessage{
		Type: "cross_cluster_data",
		From: "cluster_99",
		Data: payload,
	}

	// Read in background
	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		n, _ := clientConn.Read(buf)
		done <- buf[:n]
	}()

	m.handleCrossClusterData(msg)

	select {
	case received := <-done:
		if string(received) != string(testData) {
			t.Errorf("received %q, want %q", string(received), string(testData))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for data on target connection")
	}
}

func TestHandleCrossClusterData_SourceSide(t *testing.T) {
	agent := &PrysmAgent{}
	m := newCrossClusterRouteManager(agent)

	// Create a source connection
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	m.sourceConnsMu.Lock()
	m.sourceConns["stream_2"] = serverConn
	m.sourceConnsMu.Unlock()

	testData := []byte("response from target")
	payload, _ := json.Marshal(map[string]interface{}{
		"stream_id": "stream_2",
		"route_id":  99, // no target for this route ID, falls through to source
		"data":      testData,
	})
	msg := &derpMessage{
		Type: "cross_cluster_data",
		From: "cluster_20",
		Data: payload,
	}

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1024)
		n, _ := clientConn.Read(buf)
		done <- buf[:n]
	}()

	m.handleCrossClusterData(msg)

	select {
	case received := <-done:
		if string(received) != string(testData) {
			t.Errorf("received %q, want %q", string(received), string(testData))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for return data on source connection")
	}
}

func TestHandleCrossClusterClose(t *testing.T) {
	agent := &PrysmAgent{}
	m := newCrossClusterRouteManager(agent)

	// Setup a target connection
	targetConn, _ := net.Pipe()
	tr := &targetRoute{
		assignment: crossClusterRouteAssignment{ID: 5},
		conns:      map[string]net.Conn{"stream_close": targetConn},
	}
	m.mu.Lock()
	m.targets[5] = tr
	m.mu.Unlock()

	// Setup a source connection
	sourceConn, _ := net.Pipe()
	m.sourceConnsMu.Lock()
	m.sourceConns["stream_close"] = sourceConn
	m.sourceConnsMu.Unlock()

	payload, _ := json.Marshal(map[string]interface{}{
		"stream_id": "stream_close",
		"route_id":  5,
	})
	msg := &derpMessage{Type: "cross_cluster_close", Data: payload}

	m.handleCrossClusterClose(msg)

	// Verify connections are removed
	tr.connsMu.Lock()
	if _, exists := tr.conns["stream_close"]; exists {
		t.Error("target connection should be removed after close")
	}
	tr.connsMu.Unlock()

	m.sourceConnsMu.RLock()
	if _, exists := m.sourceConns["stream_close"]; exists {
		t.Error("source connection should be removed after close")
	}
	m.sourceConnsMu.RUnlock()
}

func TestStopAll(t *testing.T) {
	agent := &PrysmAgent{
		BackendURL: "http://localhost",
		AgentToken: "tok",
		ClusterID:  "1",
		HTTPClient: &http.Client{Timeout: time.Second},
	}
	m := newCrossClusterRouteManager(agent)

	// Add a source route with a real listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, cancel := context.WithCancel(context.Background())
	m.sources[1] = &sourceRoute{
		assignment: crossClusterRouteAssignment{ID: 1, Name: "s1"},
		listener:   ln,
		cancel:     cancel,
	}

	// Add a target route
	targetConn, _ := net.Pipe()
	_, tCancel := context.WithCancel(context.Background())
	m.targets[2] = &targetRoute{
		assignment: crossClusterRouteAssignment{ID: 2, Name: "t1"},
		cancel:     tCancel,
		conns:      map[string]net.Conn{"s1": targetConn},
	}

	m.stopAll()

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sources) != 0 {
		t.Errorf("expected 0 sources, got %d", len(m.sources))
	}
	if len(m.targets) != 0 {
		t.Errorf("expected 0 targets, got %d", len(m.targets))
	}
}

func TestTargetRoute_CloseAllConns(t *testing.T) {
	c1, _ := net.Pipe()
	c2, _ := net.Pipe()
	tr := &targetRoute{
		conns: map[string]net.Conn{"a": c1, "b": c2},
	}

	tr.closeAllConns()

	if len(tr.conns) != 0 {
		t.Errorf("expected 0 conns, got %d", len(tr.conns))
	}
}

func TestStartDisabledWithoutConfig(t *testing.T) {
	tests := []struct {
		name  string
		agent *PrysmAgent
	}{
		{"no backend URL", &PrysmAgent{AgentToken: "t", ClusterID: "1"}},
		{"no token", &PrysmAgent{BackendURL: "http://x", ClusterID: "1"}},
		{"no cluster ID", &PrysmAgent{BackendURL: "http://x", AgentToken: "t"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newCrossClusterRouteManager(tt.agent)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.Start(ctx)
			}()

			// Start should return quickly when disabled
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("Start should return immediately when disabled")
				cancel()
			}
		})
	}
}

func TestHandleCrossClusterSetup_NoTargetRoute(t *testing.T) {
	agent := &PrysmAgent{}
	m := newCrossClusterRouteManager(agent)

	// No target routes registered
	payload, _ := json.Marshal(map[string]interface{}{
		"stream_id":        "stream_1",
		"route_id":         999,
		"target_service":   "svc",
		"target_namespace": "default",
		"target_port":      80,
	})
	msg := &derpMessage{
		Type: "cross_cluster_setup",
		From: "cluster_5",
		Data: payload,
	}

	// Should not panic
	m.handleCrossClusterSetup(msg)
}

func TestSourceRouteAcceptLoop(t *testing.T) {
	// Create a mock backend to handle status reports
	statusReported := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			statusReported <- body["status"]
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"routes": []interface{}{}, "total": 0})
	}))
	defer srv.Close()

	agent := &PrysmAgent{
		BackendURL: srv.URL,
		AgentToken: "test-token",
		ClusterID:  "10",
		HTTPClient: srv.Client(),
	}
	m := newCrossClusterRouteManager(agent)

	// Start source route on a random port
	r := crossClusterRouteAssignment{
		ID:               1,
		Name:             "accept-test",
		LocalPort:        0, // Will fail since we can't listen on port 0 directly
		Role:             "source",
		PeerDERPClientID: "cluster_20",
	}

	// Use a real port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // Free it so startSourceRoute can use it

	r.LocalPort = port
	m.mu.Lock()
	m.startSourceRoute(context.Background(), r)
	m.mu.Unlock()

	// Verify the route was started
	m.mu.Lock()
	sr, ok := m.sources[1]
	m.mu.Unlock()
	if !ok {
		t.Fatal("source route should have been started")
	}

	// Connect a TCP client to the listener
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to source listener: %v", err)
	}
	// Close immediately - proxySourceConnection will fail due to no DERP manager, which is fine
	conn.Close()

	// Cleanup
	sr.cancel()
	sr.listener.Close()
}
