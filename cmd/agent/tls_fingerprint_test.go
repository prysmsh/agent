package main

import (
	"crypto/tls"
	"testing"
)

func TestComputeJA3(t *testing.T) {
	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		SupportedPoints:   []uint8{0}, // uncompressed
	}

	hash, raw := ComputeJA3(hello)
	if hash == "" {
		t.Error("expected non-empty JA3 hash")
	}
	if raw == "" {
		t.Error("expected non-empty JA3 string")
	}
	t.Logf("JA3 hash: %s, raw: %s", hash, raw)
}

func TestComputeJA3_Nil(t *testing.T) {
	hash, raw := ComputeJA3(nil)
	if hash != "" || raw != "" {
		t.Error("expected empty result for nil ClientHelloInfo")
	}
}

func TestTLSFingerprintInspector_KnownBad(t *testing.T) {
	insp := NewTLSFingerprintInspector()

	// Create a hello that produces a known-bad hash
	// We'll set the hash directly by adding it
	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12},
		CipherSuites:      []uint16{0x0035, 0x0084},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedPoints:   []uint8{0},
	}

	// Compute the hash for this hello
	hash, _ := ComputeJA3(hello)

	// Add it as known-bad
	insp.SetKnownBad(map[string]string{hash: "test-malware"})

	result := insp.CheckJA3(hello)
	if result == nil {
		t.Error("expected known-bad detection")
		return
	}

	if result.ThreatLevel != ThreatCritical {
		t.Errorf("expected Critical threat, got %v", result.ThreatLevel)
	}

	if result.Category != ThreatCategoryC2Communication {
		t.Errorf("expected C2 category, got %v", result.Category)
	}
}

func TestTLSFingerprintInspector_Clean(t *testing.T) {
	insp := NewTLSFingerprintInspector()

	hello := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13},
		CipherSuites:      []uint16{tls.TLS_AES_128_GCM_SHA256},
		SupportedCurves:   []tls.CurveID{tls.X25519},
		SupportedPoints:   []uint8{0},
	}

	result := insp.CheckJA3(hello)
	if result != nil {
		t.Error("expected no detection for clean hello")
	}
}

func TestTLSFingerprintInspector_Inspect_NonTLS(t *testing.T) {
	insp := NewTLSFingerprintInspector()

	// Non-TLS data should produce no results
	results := insp.Inspect([]byte("GET / HTTP/1.1\r\n"), "inbound", nil)
	if len(results) != 0 {
		t.Error("expected no results for non-TLS data")
	}
}

func TestIsGREASE(t *testing.T) {
	tests := []struct {
		val  uint16
		want bool
	}{
		{0x0a0a, true},
		{0x1a1a, true},
		{0x2a2a, true},
		{0xfafa, true},
		{0x0001, false},
		{0x0035, false},
		{0x1301, false},
	}

	for _, tt := range tests {
		got := isGREASE(tt.val)
		if got != tt.want {
			t.Errorf("isGREASE(0x%04x) = %v, want %v", tt.val, got, tt.want)
		}
	}
}

func TestTLSFingerprintInspector_Stats(t *testing.T) {
	insp := NewTLSFingerprintInspector()
	stats := insp.Stats()

	if stats["fingerprints_computed"] != int64(0) {
		t.Error("expected 0 fingerprints initially")
	}
	if stats["known_bad_matches"] != int64(0) {
		t.Error("expected 0 matches initially")
	}
	if stats["known_bad_count"].(int) < 5 {
		t.Errorf("expected at least 5 default known-bad hashes, got %d", stats["known_bad_count"].(int))
	}
}

func TestComputeJA3FromRaw_TooShort(t *testing.T) {
	hash, _ := computeJA3FromRaw([]byte{0x16, 0x03, 0x01})
	if hash != "" {
		t.Error("expected empty hash for too-short data")
	}
}

func TestComputeJA3FromRaw_NotTLS(t *testing.T) {
	data := make([]byte, 100)
	data[0] = 0x17 // Not handshake
	hash, _ := computeJA3FromRaw(data)
	if hash != "" {
		t.Error("expected empty hash for non-TLS data")
	}
}
