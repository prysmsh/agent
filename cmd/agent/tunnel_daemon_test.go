package main

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewTunnelDaemon(t *testing.T) {
	agent := &PrysmAgent{
		BackendURL:     "https://api.prysm.sh",
		AgentToken:     "test-token",
		ClusterID:      "test-cluster",
		OrganizationID: 1,
	}

	daemon := newTunnelDaemon(agent)

	if daemon.outboundPort != DefaultOutboundPort {
		t.Errorf("expected outbound port %d, got %d", DefaultOutboundPort, daemon.outboundPort)
	}

	if daemon.inboundPort != DefaultInboundPort {
		t.Errorf("expected inbound port %d, got %d", DefaultInboundPort, daemon.inboundPort)
	}

	if daemon.bufferSize != DefaultBufferSize {
		t.Errorf("expected buffer size %d, got %d", DefaultBufferSize, daemon.bufferSize)
	}

	if daemon.certStore == nil {
		t.Error("expected cert store to be initialized")
	}
}

func TestTunnelDaemonStats(t *testing.T) {
	agent := &PrysmAgent{
		BackendURL:     "https://api.prysm.sh",
		AgentToken:     "test-token",
		ClusterID:      "test-cluster",
		OrganizationID: 1,
	}

	daemon := newTunnelDaemon(agent)

	// Simulate some stats
	atomic.AddInt64(&daemon.stats.outboundConns, 5)
	atomic.AddInt64(&daemon.stats.inboundConns, 3)
	atomic.AddInt64(&daemon.stats.bytesProxied, 1024)
	atomic.AddInt64(&daemon.stats.certsIssued, 2)
	atomic.AddInt64(&daemon.stats.connectionErrors, 1)

	stats := daemon.Stats()

	if stats["outbound_connections"].(int64) != 5 {
		t.Errorf("expected 5 outbound connections, got %v", stats["outbound_connections"])
	}

	if stats["inbound_connections"].(int64) != 3 {
		t.Errorf("expected 3 inbound connections, got %v", stats["inbound_connections"])
	}

	if stats["bytes_proxied"].(int64) != 1024 {
		t.Errorf("expected 1024 bytes proxied, got %v", stats["bytes_proxied"])
	}

	if stats["certs_issued"].(int64) != 2 {
		t.Errorf("expected 2 certs issued, got %v", stats["certs_issued"])
	}

	if stats["connection_errors"].(int64) != 1 {
		t.Errorf("expected 1 connection error, got %v", stats["connection_errors"])
	}
}

func TestTunnelDaemonProxy(t *testing.T) {
	agent := &PrysmAgent{}
	daemon := newTunnelDaemon(agent)

	// Create a pipe to simulate connections
	clientReader, clientWriter := net.Pipe()
	serverReader, serverWriter := net.Pipe()

	done := make(chan struct{})

	go func() {
		daemon.proxy(clientReader, serverWriter)
		close(done)
	}()

	// Write from client side
	testData := []byte("hello from client")
	go func() {
		clientWriter.Write(testData)
		clientWriter.Close()
	}()

	// Read from server side
	buf := make([]byte, len(testData))
	n, err := serverReader.Read(buf)
	if err != nil {
		t.Errorf("unexpected error reading: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("expected %q, got %q", testData, buf[:n])
	}

	serverReader.Close()
	serverWriter.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("proxy did not complete in time")
	}
}

func TestTunnelDaemonShutdown(t *testing.T) {
	agent := &PrysmAgent{}
	daemon := newTunnelDaemon(agent)

	// Create listeners manually for testing shutdown
	outboundLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create outbound listener: %v", err)
	}
	daemon.outboundLn = outboundLn

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = daemon.Shutdown(ctx)
	if err != nil {
		t.Errorf("unexpected shutdown error: %v", err)
	}
}

func TestIsLocalIP(t *testing.T) {
	// Loopback should be local
	if !isLocalIP(net.ParseIP("127.0.0.1")) {
		t.Error("expected 127.0.0.1 to be local")
	}

	// A random external IP should not be local
	if isLocalIP(net.ParseIP("8.8.8.8")) {
		t.Error("expected 8.8.8.8 to not be local")
	}
}

func TestPQCCurvePreferences(t *testing.T) {
	curves := getPQCCurvePreferences()

	if !PQCEnabled {
		t.Skip("PQC not enabled")
	}

	// First curve should be the PQC hybrid
	if len(curves) == 0 {
		t.Fatal("expected at least one curve preference")
	}

	// X25519MLKEM768 should be first when PQC is enabled
	// This is the hybrid post-quantum key exchange (X25519 + ML-KEM-768)
	if curves[0] != tls.X25519MLKEM768 {
		t.Errorf("expected X25519MLKEM768 as first curve, got %v", curves[0])
	}

	// Should have fallback curves
	if len(curves) < 2 {
		t.Error("expected fallback curves for non-PQC peers")
	}
}

func TestTunnelDaemonStatsPQC(t *testing.T) {
	agent := &PrysmAgent{
		BackendURL:     "https://api.prysm.sh",
		AgentToken:     "test-token",
		ClusterID:      "test-cluster",
		OrganizationID: 1,
	}

	daemon := newTunnelDaemon(agent)
	stats := daemon.Stats()

	// Check PQC fields exist
	if _, ok := stats["pqc_enabled"]; !ok {
		t.Error("expected pqc_enabled in stats")
	}

	if _, ok := stats["pqc_algorithm"]; !ok {
		t.Error("expected pqc_algorithm in stats")
	}

	if _, ok := stats["pqc_connections"]; !ok {
		t.Error("expected pqc_connections in stats")
	}

	// Verify PQC is enabled
	if stats["pqc_enabled"].(bool) != PQCEnabled {
		t.Errorf("expected pqc_enabled=%v, got %v", PQCEnabled, stats["pqc_enabled"])
	}

	// Verify algorithm name
	if PQCEnabled {
		alg := stats["pqc_algorithm"].(string)
		if alg != "ML-KEM-768 (X25519 hybrid)" {
			t.Errorf("expected ML-KEM-768 algorithm, got %s", alg)
		}
	}
}
