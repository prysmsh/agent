package main

import (
	"net"
	"testing"
)

func TestRateInspector_ConnFlood(t *testing.T) {
	r := NewRateInspector()
	ctx := &InspectionContext{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		DstPort: 80,
	}

	var detected bool
	for i := 0; i < 110; i++ {
		results := r.Inspect(nil, "inbound", ctx)
		for _, res := range results {
			if res.Indicators[0] == "rate-conn-flood" {
				detected = true
			}
		}
	}

	if !detected {
		t.Error("expected connection flood detection after 100+ connections")
	}
}

func TestRateInspector_ConnFloodAlertOnce(t *testing.T) {
	r := NewRateInspector()
	ctx := &InspectionContext{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		DstPort: 80,
	}

	alertCount := 0
	for i := 0; i < 200; i++ {
		results := r.Inspect(nil, "inbound", ctx)
		for _, res := range results {
			if res.Indicators[0] == "rate-conn-flood" {
				alertCount++
			}
		}
	}

	if alertCount != 1 {
		t.Errorf("expected exactly 1 conn flood alert, got %d", alertCount)
	}
}

func TestRateInspector_ReqFlood(t *testing.T) {
	r := NewRateInspector()
	ctx := &InspectionContext{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		DstPort: 8080,
	}

	var detected bool
	for i := 0; i < 510; i++ {
		results := r.Inspect(nil, "inbound", ctx)
		for _, res := range results {
			if res.Indicators[0] == "rate-req-flood" {
				detected = true
			}
		}
	}

	if !detected {
		t.Error("expected request flood detection after 500+ requests")
	}
}

func TestRateInspector_PortScan(t *testing.T) {
	r := NewRateInspector()

	var detected bool
	for port := 1; port <= 25; port++ {
		ctx := &InspectionContext{
			SrcIP:   net.ParseIP("10.0.0.1"),
			DstIP:   net.ParseIP("10.0.0.2"),
			DstPort: port,
		}
		results := r.Inspect(nil, "inbound", ctx)
		for _, res := range results {
			if res.Indicators[0] == "rate-port-scan" {
				detected = true
			}
		}
	}

	if !detected {
		t.Error("expected port scan detection after 20+ distinct ports")
	}
}

func TestRateInspector_SlowLoris(t *testing.T) {
	r := NewRateInspector()

	stream := NewStreamState()
	// Simulate minimal data
	stream.Append([]byte("G"))

	ctx := &InspectionContext{
		SrcIP:       net.ParseIP("10.0.0.1"),
		DstIP:       net.ParseIP("10.0.0.2"),
		DstPort:     80,
		PacketCount: 10, // Many packets but little data
		Stream:      stream,
	}

	results := r.Inspect(nil, "inbound", ctx)

	found := false
	for _, res := range results {
		if res.Indicators[0] == "rate-slow-loris" {
			found = true
		}
	}
	if !found {
		t.Error("expected slow loris detection")
	}
}

func TestRateInspector_NormalTraffic(t *testing.T) {
	r := NewRateInspector()
	ctx := &InspectionContext{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		DstPort: 80,
	}

	// Well under thresholds
	for i := 0; i < 10; i++ {
		results := r.Inspect(nil, "inbound", ctx)
		if len(results) != 0 {
			t.Errorf("expected no alerts for normal traffic, got %d", len(results))
		}
	}
}

func TestRateInspector_NilContext(t *testing.T) {
	r := NewRateInspector()
	results := r.Inspect(nil, "inbound", nil)
	if len(results) != 0 {
		t.Error("expected no results for nil context")
	}
}

func TestRateInspector_Cleanup(t *testing.T) {
	r := NewRateInspector()
	ctx := &InspectionContext{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		DstPort: 80,
	}

	// Add some entries
	r.Inspect(nil, "inbound", ctx)

	// Cleanup should not panic
	r.cleanup()
}

func TestRateInspector_Stats(t *testing.T) {
	r := NewRateInspector()
	stats := r.Stats()

	if stats["conn_flood_detected"] != int64(0) {
		t.Error("expected 0 conn floods initially")
	}
	if stats["port_scan_detected"] != int64(0) {
		t.Error("expected 0 port scans initially")
	}
}
