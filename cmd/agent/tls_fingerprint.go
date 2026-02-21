// Package main provides JA3/JA4 TLS fingerprinting for the DPI engine.
// Computes JA3 hashes from TLS ClientHello messages to detect known-bad
// TLS implementations (Cobalt Strike, Metasploit, etc.) and anomalous clients.
package main

import (
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// TLSFingerprintInspector detects malicious TLS clients via JA3 fingerprints.
type TLSFingerprintInspector struct {
	// Known-bad JA3 hashes (hash → description)
	knownBad   map[string]string
	knownBadMu sync.RWMutex

	stats struct {
		fingerprintsComputed int64
		knownBadMatches      int64
	}
	statsMu sync.RWMutex
}

// NewTLSFingerprintInspector creates a TLS fingerprint inspector with default known-bad hashes.
func NewTLSFingerprintInspector() *TLSFingerprintInspector {
	t := &TLSFingerprintInspector{
		knownBad: make(map[string]string),
	}
	t.loadDefaultKnownBad()
	return t
}

// loadDefaultKnownBad initializes known-bad JA3 fingerprints.
func (t *TLSFingerprintInspector) loadDefaultKnownBad() {
	// Well-known malicious JA3 hashes
	t.knownBad = map[string]string{
		"72a589da586844d7f0818ce684948eea": "Cobalt Strike (default)",
		"a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike (variant)",
		"6734f37431670b3ab4292b8f60f29984": "Trickbot",
		"e7d705a3286e19ea42f587b344ee6865": "AsyncRAT",
		"4d7a28d6f2263ed61de88ca66eb011e3": "Metasploit Meterpreter",
		"3b5074b1b5d032e5620f69f9f700ff0e": "Emotet",
		"51c64c77e60f3980eea90869b68c58a8": "Dridex",
		"2d1eb5817ece335c24904f516ad5da12": "IcedID",
	}
}

// SetKnownBad replaces the known-bad JA3 hash set.
func (t *TLSFingerprintInspector) SetKnownBad(hashes map[string]string) {
	t.knownBadMu.Lock()
	defer t.knownBadMu.Unlock()
	// Merge with defaults
	for k, v := range hashes {
		t.knownBad[k] = v
	}
}

// Inspect implements PacketInspector. This inspector doesn't scan byte streams directly;
// it relies on TLS ClientHello data stored in the InspectionContext metadata.
// The actual fingerprint extraction happens in the TLS handshake callback.
func (t *TLSFingerprintInspector) Inspect(data []byte, direction string, ctx *InspectionContext) []InspectionResult {
	// TLS fingerprint checking is done via CheckJA3 called from the TLS handshake
	// This Inspect method handles raw ClientHello bytes if present in the data stream
	if len(data) < 5 || direction != "inbound" {
		return nil
	}

	// Check for TLS ClientHello: ContentType=22 (handshake), HandshakeType=1 (ClientHello)
	if data[0] != 0x16 { // Not a TLS handshake record
		return nil
	}

	// Try to parse ClientHello and compute JA3
	ja3Hash, ja3Str := computeJA3FromRaw(data)
	if ja3Hash == "" {
		return nil
	}

	t.statsMu.Lock()
	t.stats.fingerprintsComputed++
	t.statsMu.Unlock()

	// Check against known-bad
	t.knownBadMu.RLock()
	desc, isBad := t.knownBad[ja3Hash]
	t.knownBadMu.RUnlock()

	if isBad {
		t.statsMu.Lock()
		t.stats.knownBadMatches++
		t.statsMu.Unlock()

		return []InspectionResult{{
			Timestamp:   time.Now(),
			ThreatLevel: ThreatCritical,
			Category:    ThreatCategoryC2Communication,
			Description: fmt.Sprintf("Known malicious TLS client detected: %s (JA3: %s)", desc, ja3Hash),
			Indicators:  []string{"ja3-known-bad", ja3Hash, desc},
			MitreATTCK:  "T1071.001",
			Score:       90,
			Metadata: map[string]interface{}{
				"ja3_hash":   ja3Hash,
				"ja3_string": ja3Str,
				"malware":    desc,
			},
		}}
	}

	return nil
}

// CheckJA3 checks a JA3 hash computed from a tls.ClientHelloInfo.
// Called from the TLS GetConfigForClient callback during handshake.
func (t *TLSFingerprintInspector) CheckJA3(hello *tls.ClientHelloInfo) *InspectionResult {
	if hello == nil {
		return nil
	}

	ja3Hash, ja3Str := ComputeJA3(hello)
	if ja3Hash == "" {
		return nil
	}

	t.statsMu.Lock()
	t.stats.fingerprintsComputed++
	t.statsMu.Unlock()

	t.knownBadMu.RLock()
	desc, isBad := t.knownBad[ja3Hash]
	t.knownBadMu.RUnlock()

	if isBad {
		t.statsMu.Lock()
		t.stats.knownBadMatches++
		t.statsMu.Unlock()

		return &InspectionResult{
			Timestamp:   time.Now(),
			ThreatLevel: ThreatCritical,
			Category:    ThreatCategoryC2Communication,
			Description: fmt.Sprintf("Known malicious TLS client detected: %s (JA3: %s)", desc, ja3Hash),
			Indicators:  []string{"ja3-known-bad", ja3Hash, desc},
			MitreATTCK:  "T1071.001",
			Score:       90,
			Metadata: map[string]interface{}{
				"ja3_hash":   ja3Hash,
				"ja3_string": ja3Str,
				"malware":    desc,
			},
		}
	}

	return nil
}

// ComputeJA3 computes a JA3 fingerprint from a tls.ClientHelloInfo.
// JA3 format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
func ComputeJA3(hello *tls.ClientHelloInfo) (hash string, raw string) {
	if hello == nil {
		return "", ""
	}

	// TLS version: use the max supported version
	version := hello.SupportedVersions
	var tlsVer uint16
	if len(version) > 0 {
		tlsVer = version[0]
		for _, v := range version {
			if v > tlsVer {
				tlsVer = v
			}
		}
	}

	// Cipher suites
	ciphers := make([]string, 0, len(hello.CipherSuites))
	for _, c := range hello.CipherSuites {
		// Skip GREASE values (0x?a?a pattern)
		if isGREASE(uint16(c)) {
			continue
		}
		ciphers = append(ciphers, fmt.Sprintf("%d", c))
	}

	// Supported curves (elliptic curves / named groups)
	curves := make([]string, 0, len(hello.SupportedCurves))
	for _, c := range hello.SupportedCurves {
		if isGREASE(uint16(c)) {
			continue
		}
		curves = append(curves, fmt.Sprintf("%d", c))
	}

	// Supported point formats
	points := make([]string, 0, len(hello.SupportedPoints))
	for _, p := range hello.SupportedPoints {
		points = append(points, fmt.Sprintf("%d", p))
	}

	// Build JA3 string (extensions field is not available from ClientHelloInfo,
	// so we omit it — this gives us a JA3-like hash)
	ja3Str := fmt.Sprintf("%d,%s,,%s,%s",
		tlsVer,
		strings.Join(ciphers, "-"),
		strings.Join(curves, "-"),
		strings.Join(points, "-"),
	)

	ja3Hash := fmt.Sprintf("%x", md5.Sum([]byte(ja3Str)))
	return ja3Hash, ja3Str
}

// computeJA3FromRaw attempts to compute a JA3 from raw TLS ClientHello bytes.
func computeJA3FromRaw(data []byte) (string, string) {
	if len(data) < 43 {
		return "", ""
	}

	// TLS record header: ContentType(1) + Version(2) + Length(2)
	if data[0] != 0x16 {
		return "", ""
	}

	// Handshake header: HandshakeType(1) + Length(3)
	offset := 5
	if offset >= len(data) || data[offset] != 0x01 { // ClientHello
		return "", ""
	}
	offset += 4 // skip handshake header

	if offset+2 > len(data) {
		return "", ""
	}

	// ClientHello: Version(2) + Random(32) + SessionID(var) + CipherSuites(var) + ...
	tlsVersion := uint16(data[offset])<<8 | uint16(data[offset+1])
	offset += 2 + 32 // skip version + random

	if offset >= len(data) {
		return "", ""
	}

	// Session ID
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	if offset+2 > len(data) {
		return "", ""
	}

	// Cipher suites
	cipherLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2
	if offset+cipherLen > len(data) {
		return "", ""
	}

	var ciphers []string
	for i := 0; i < cipherLen; i += 2 {
		c := uint16(data[offset+i])<<8 | uint16(data[offset+i+1])
		if !isGREASE(c) {
			ciphers = append(ciphers, fmt.Sprintf("%d", c))
		}
	}
	offset += cipherLen

	if offset >= len(data) {
		return "", ""
	}

	// Compression methods
	compLen := int(data[offset])
	offset += 1 + compLen

	// Extensions (parse for curves and point formats)
	var extensions, curves, points []string
	if offset+2 <= len(data) {
		extTotalLen := int(data[offset])<<8 | int(data[offset+1])
		offset += 2
		extEnd := offset + extTotalLen
		if extEnd > len(data) {
			extEnd = len(data)
		}

		for offset+4 <= extEnd {
			extType := uint16(data[offset])<<8 | uint16(data[offset+1])
			extLen := int(data[offset+2])<<8 | int(data[offset+3])
			offset += 4

			if !isGREASE(extType) {
				extensions = append(extensions, fmt.Sprintf("%d", extType))
			}

			if offset+extLen > extEnd {
				break
			}

			extData := data[offset : offset+extLen]

			// Supported groups (extension 0x000a)
			if extType == 0x000a && len(extData) >= 2 {
				groupLen := int(extData[0])<<8 | int(extData[1])
				for i := 2; i+1 < 2+groupLen && i+1 < len(extData); i += 2 {
					g := uint16(extData[i])<<8 | uint16(extData[i+1])
					if !isGREASE(g) {
						curves = append(curves, fmt.Sprintf("%d", g))
					}
				}
			}

			// EC point formats (extension 0x000b)
			if extType == 0x000b && len(extData) >= 1 {
				pfLen := int(extData[0])
				for i := 1; i < 1+pfLen && i < len(extData); i++ {
					points = append(points, fmt.Sprintf("%d", extData[i]))
				}
			}

			offset += extLen
		}
	}

	ja3Str := fmt.Sprintf("%d,%s,%s,%s,%s",
		tlsVersion,
		strings.Join(ciphers, "-"),
		strings.Join(extensions, "-"),
		strings.Join(curves, "-"),
		strings.Join(points, "-"),
	)

	ja3Hash := fmt.Sprintf("%x", md5.Sum([]byte(ja3Str)))
	return ja3Hash, ja3Str
}

// isGREASE checks if a value is a GREASE (Generate Random Extensions And Sustain Extensibility) value.
// GREASE values follow the pattern 0x?a?a.
func isGREASE(val uint16) bool {
	if val&0x0f0f != 0x0a0a {
		return false
	}
	hi := (val >> 8) & 0x0f
	lo := val & 0x0f
	return hi == 0x0a && lo == 0x0a
}

// Name implements PacketInspector.
func (t *TLSFingerprintInspector) Name() string {
	return "tls-fingerprint-inspector"
}

// Stats implements PacketInspector.
func (t *TLSFingerprintInspector) Stats() map[string]interface{} {
	t.statsMu.RLock()
	defer t.statsMu.RUnlock()

	t.knownBadMu.RLock()
	knownBadCount := len(t.knownBad)
	t.knownBadMu.RUnlock()

	return map[string]interface{}{
		"fingerprints_computed": t.stats.fingerprintsComputed,
		"known_bad_matches":    t.stats.knownBadMatches,
		"known_bad_count":      knownBadCount,
	}
}

// SortedUint16 sorts a uint16 slice (for deterministic JA3 computation).
func SortedUint16(vals []uint16) []uint16 {
	sorted := make([]uint16, len(vals))
	copy(sorted, vals)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted
}
