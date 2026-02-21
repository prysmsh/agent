package main

import (
	"net"
	"strings"
	"testing"
)

func TestReputationInspector_ExactIP(t *testing.T) {
	r := NewReputationInspector()
	r.loadFromReader(strings.NewReader("1.2.3.4\n5.6.7.8\n"))

	if !r.IsBlocked(net.ParseIP("1.2.3.4")) {
		t.Error("expected 1.2.3.4 to be blocked")
	}
	if !r.IsBlocked(net.ParseIP("5.6.7.8")) {
		t.Error("expected 5.6.7.8 to be blocked")
	}
	if r.IsBlocked(net.ParseIP("9.9.9.9")) {
		t.Error("expected 9.9.9.9 to not be blocked")
	}
}

func TestReputationInspector_CIDR(t *testing.T) {
	r := NewReputationInspector()
	r.loadFromReader(strings.NewReader("10.0.0.0/8\n192.168.1.0/24\n"))

	if !r.IsBlocked(net.ParseIP("10.1.2.3")) {
		t.Error("expected 10.1.2.3 to be blocked (10.0.0.0/8)")
	}
	if !r.IsBlocked(net.ParseIP("192.168.1.100")) {
		t.Error("expected 192.168.1.100 to be blocked (192.168.1.0/24)")
	}
	if r.IsBlocked(net.ParseIP("192.168.2.1")) {
		t.Error("expected 192.168.2.1 to not be blocked")
	}
}

func TestReputationInspector_Comments(t *testing.T) {
	r := NewReputationInspector()
	data := `# This is a comment
1.2.3.4

# Another comment
5.6.7.8
`
	r.loadFromReader(strings.NewReader(data))

	if !r.IsBlocked(net.ParseIP("1.2.3.4")) {
		t.Error("expected 1.2.3.4 to be blocked")
	}
	if !r.IsBlocked(net.ParseIP("5.6.7.8")) {
		t.Error("expected 5.6.7.8 to be blocked")
	}
}

func TestReputationInspector_Mixed(t *testing.T) {
	r := NewReputationInspector()
	data := `# Blocklist
1.2.3.4
10.0.0.0/8
2001:db8::1
`
	r.loadFromReader(strings.NewReader(data))

	if !r.IsBlocked(net.ParseIP("1.2.3.4")) {
		t.Error("expected 1.2.3.4 to be blocked")
	}
	if !r.IsBlocked(net.ParseIP("10.255.0.1")) {
		t.Error("expected 10.255.0.1 to be blocked (10.0.0.0/8)")
	}
	if !r.IsBlocked(net.ParseIP("2001:db8::1")) {
		t.Error("expected 2001:db8::1 to be blocked")
	}
}

func TestReputationInspector_Inspect_BlockedSrc(t *testing.T) {
	r := NewReputationInspector()
	r.loadFromReader(strings.NewReader("10.0.0.1\n"))

	ctx := &InspectionContext{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("172.16.0.1"),
		DstPort: 80,
	}

	results := r.Inspect(nil, "inbound", ctx)

	found := false
	for _, res := range results {
		if res.Indicators[0] == "reputation-blocked-src" {
			found = true
		}
	}
	if !found {
		t.Error("expected blocked source IP detection")
	}
}

func TestReputationInspector_Inspect_BlockedDst(t *testing.T) {
	r := NewReputationInspector()
	r.loadFromReader(strings.NewReader("172.16.0.1\n"))

	ctx := &InspectionContext{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("172.16.0.1"),
		DstPort: 443,
	}

	results := r.Inspect(nil, "outbound", ctx)

	found := false
	for _, res := range results {
		if res.Indicators[0] == "reputation-blocked-dst" {
			found = true
		}
	}
	if !found {
		t.Error("expected blocked destination IP detection")
	}
}

func TestReputationInspector_Inspect_Clean(t *testing.T) {
	r := NewReputationInspector()
	r.loadFromReader(strings.NewReader("1.2.3.4\n"))

	ctx := &InspectionContext{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		DstPort: 80,
	}

	results := r.Inspect(nil, "inbound", ctx)
	if len(results) != 0 {
		t.Errorf("expected no results for clean IPs, got %d", len(results))
	}
}

func TestReputationInspector_Inspect_NilContext(t *testing.T) {
	r := NewReputationInspector()
	results := r.Inspect(nil, "inbound", nil)
	if len(results) != 0 {
		t.Error("expected no results for nil context")
	}
}

func TestReputationInspector_IsBlocked_NilIP(t *testing.T) {
	r := NewReputationInspector()
	if r.IsBlocked(nil) {
		t.Error("expected nil IP to not be blocked")
	}
}

func TestReputationInspector_LoadNonexistentFile(t *testing.T) {
	r := NewReputationInspector()
	err := r.LoadFromFile("/nonexistent/file.txt")
	if err != nil {
		t.Errorf("expected nil error for nonexistent file, got %v", err)
	}
}

func TestReputationInspector_Stats(t *testing.T) {
	r := NewReputationInspector()
	stats := r.Stats()

	if stats["ips_checked"] != int64(0) {
		t.Error("expected 0 IPs checked initially")
	}
	if stats["blocked_hits"] != int64(0) {
		t.Error("expected 0 blocked hits initially")
	}
	if stats["list_size"] != int64(0) {
		t.Error("expected 0 list size initially")
	}
}

func TestReputationInspector_EmptyList(t *testing.T) {
	r := NewReputationInspector()
	r.loadFromReader(strings.NewReader(""))

	if r.IsBlocked(net.ParseIP("1.2.3.4")) {
		t.Error("expected nothing blocked on empty list")
	}
}
