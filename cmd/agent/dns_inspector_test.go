package main

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestDNSInspector_KnownBadDomain(t *testing.T) {
	d := NewDNSInspector()
	d.SetBadDomains([]string{"evil.com", "malware.example.org"})

	ctx := &InspectionContext{SrcIP: net.ParseIP("10.0.0.1")}

	// Build a DNS query for evil.com
	data := buildDNSQuery("evil.com", 1) // A record
	results := d.Inspect(data, "outbound", ctx)

	found := false
	for _, r := range results {
		if r.Category == ThreatCategoryC2Communication {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected known-bad domain detection for evil.com")
	}
}

func TestDNSInspector_KnownBadSubdomain(t *testing.T) {
	d := NewDNSInspector()
	d.SetBadDomains([]string{"evil.com"})

	ctx := &InspectionContext{SrcIP: net.ParseIP("10.0.0.1")}

	// Subdomain of known-bad domain should also match
	data := buildDNSQuery("foo.bar.evil.com", 1)
	results := d.Inspect(data, "outbound", ctx)

	found := false
	for _, r := range results {
		if r.Category == ThreatCategoryC2Communication {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected known-bad domain detection for subdomain of evil.com")
	}
}

func TestDNSInspector_TunnelingLongSubdomain(t *testing.T) {
	d := NewDNSInspector()
	ctx := &InspectionContext{SrcIP: net.ParseIP("10.0.0.1")}

	// Long encoded subdomain typical of DNS tunneling
	longSub := "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHZlcnkgbG9uZyBzdWJkb21haW4gdGhhdCBpcyB1c2VkIGZvcg.tunnel.example.com"
	data := buildDNSQuery(longSub, 1)
	results := d.Inspect(data, "outbound", ctx)

	found := false
	for _, r := range results {
		if r.Category == ThreatCategoryDNSTunneling {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DNS tunneling detection for long subdomain")
	}
}

func TestDNSInspector_DGADetection(t *testing.T) {
	d := NewDNSInspector()
	ctx := &InspectionContext{SrcIP: net.ParseIP("10.0.0.1")}

	// Typical DGA domain: random consonants, no vowels, mixed digits
	dgaDomain := "xkqjrm7tf9p2.com"
	data := buildDNSQuery(dgaDomain, 1)
	results := d.Inspect(data, "outbound", ctx)

	found := false
	for _, r := range results {
		if r.Category == ThreatCategoryDGA {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DGA detection for random-looking domain")
	}
}

func TestDNSInspector_NormalDomain(t *testing.T) {
	d := NewDNSInspector()
	ctx := &InspectionContext{SrcIP: net.ParseIP("10.0.0.1")}

	data := buildDNSQuery("google.com", 1)
	results := d.Inspect(data, "outbound", ctx)

	// Should not flag normal domains
	for _, r := range results {
		if r.Category == ThreatCategoryDGA || r.Category == ThreatCategoryDNSTunneling {
			t.Errorf("false positive on google.com: %s", r.Description)
		}
	}
}

func TestDNSInspector_Exfiltration(t *testing.T) {
	d := NewDNSInspector()
	ctx := &InspectionContext{SrcIP: net.ParseIP("10.0.0.1")}

	// Simulate >50 queries to same domain
	for i := 0; i < 51; i++ {
		data := buildDNSQuery("data.exfil.com", 1)
		results := d.Inspect(data, "outbound", ctx)

		if i == 50 {
			found := false
			for _, r := range results {
				if r.Category == ThreatCategoryDataExfiltration {
					found = true
					break
				}
			}
			if !found {
				t.Error("expected exfiltration detection after 50+ queries")
			}
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input   string
		minEnt  float64
		maxEnt  float64
	}{
		{"aaaaaaa", 0, 0.1},     // Low entropy (all same)
		{"abcdefg", 2.5, 3.0},   // Medium entropy
		{"", 0, 0},               // Empty
	}

	for _, tt := range tests {
		e := shannonEntropy(tt.input)
		if e < tt.minEnt || e > tt.maxEnt {
			t.Errorf("shannonEntropy(%q) = %f, expected between %f and %f", tt.input, e, tt.minEnt, tt.maxEnt)
		}
	}
}

func TestDGAScore(t *testing.T) {
	tests := []struct {
		label    string
		minScore float64
	}{
		{"google", 0},       // Normal: should score low
		{"xkqjrmtf9p2", 0.5}, // DGA-like: should score high
	}

	for _, tt := range tests {
		score := dgaScore(tt.label)
		if score < tt.minScore {
			t.Errorf("dgaScore(%q) = %f, expected >= %f", tt.label, score, tt.minScore)
		}
	}
}

func TestParseDNSQuery(t *testing.T) {
	data := buildDNSQuery("example.com", 1)
	// Strip TCP length prefix if present
	q, err := parseDNSQuery(data)
	if err != nil {
		t.Fatalf("parseDNSQuery failed: %v", err)
	}
	if q == nil {
		t.Fatal("parseDNSQuery returned nil")
	}
	if len(q.names) == 0 {
		t.Fatal("parseDNSQuery returned no names")
	}
	if q.names[0] != "example.com" {
		t.Errorf("parseDNSQuery name = %q, want %q", q.names[0], "example.com")
	}
}

func TestDNSInspector_NonDNSData(t *testing.T) {
	d := NewDNSInspector()
	ctx := &InspectionContext{}

	// Random non-DNS data should not panic or produce results
	results := d.Inspect([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n"), "inbound", ctx)
	if len(results) != 0 {
		t.Errorf("expected no results for non-DNS data, got %d", len(results))
	}
}

// buildDNSQuery creates a minimal DNS query message for testing.
func buildDNSQuery(name string, qtype uint16) []byte {
	var buf []byte

	// DNS Header (12 bytes)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x1234) // Transaction ID
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // Flags: standard query
	binary.BigEndian.PutUint16(header[4:6], 1)       // QDCount = 1
	buf = append(buf, header...)

	// Question section: encode domain name
	labels := splitDomainLabels(name)
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0) // root label

	// QTYPE and QCLASS
	qtypeClass := make([]byte, 4)
	binary.BigEndian.PutUint16(qtypeClass[0:2], qtype)
	binary.BigEndian.PutUint16(qtypeClass[2:4], 1) // IN class
	buf = append(buf, qtypeClass...)

	return buf
}

func splitDomainLabels(domain string) []string {
	parts := []string{}
	for _, p := range splitDot(domain) {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func splitDot(s string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}
