// Package main provides DNS traffic inspection for the DPI engine.
// Detects DNS tunneling, DGA (Domain Generation Algorithm) domains,
// DNS exfiltration, and known-bad domain lookups.
package main

import (
	"encoding/binary"
	"math"
	"strings"
	"sync"
	"time"
	"unicode"
)

// DNS record types relevant for tunneling detection
const (
	dnsTypeTXT   = 16
	dnsTypeNULL  = 10
	dnsTypeCNAME = 5
	dnsTypeMX    = 15
)

// DNSInspector implements PacketInspector for DNS traffic analysis.
type DNSInspector struct {
	// Known-bad domains (IOC list)
	badDomains   map[string]bool
	badDomainsMu sync.RWMutex

	// Per-source query tracking for exfil detection
	queryTracker   map[string]*dnsQueryBucket
	queryTrackerMu sync.Mutex

	stats struct {
		queriesInspected int64
		tunnelDetected   int64
		dgaDetected      int64
		badDomainHits    int64
		exfilDetected    int64
	}
	statsMu sync.RWMutex
}

// dnsQueryBucket tracks DNS query volume per source IP per domain.
type dnsQueryBucket struct {
	domainCounts map[string]int
	windowStart  time.Time
}

// NewDNSInspector creates a DNS inspector with default settings.
func NewDNSInspector() *DNSInspector {
	return &DNSInspector{
		badDomains:   make(map[string]bool),
		queryTracker: make(map[string]*dnsQueryBucket),
	}
}

// SetBadDomains replaces the known-bad domain set.
func (d *DNSInspector) SetBadDomains(domains []string) {
	d.badDomainsMu.Lock()
	defer d.badDomainsMu.Unlock()
	d.badDomains = make(map[string]bool, len(domains))
	for _, domain := range domains {
		d.badDomains[strings.ToLower(strings.TrimSuffix(domain, "."))] = true
	}
}

// Inspect implements PacketInspector for DNS traffic.
func (d *DNSInspector) Inspect(data []byte, direction string, ctx *InspectionContext) []InspectionResult {
	var results []InspectionResult

	// Try to parse as DNS message (TCP: 2-byte length prefix; UDP: raw)
	dnsData := data
	if len(data) > 2 {
		// Check for TCP DNS length prefix
		msgLen := binary.BigEndian.Uint16(data[:2])
		if int(msgLen) == len(data)-2 {
			dnsData = data[2:]
		}
	}

	query, err := parseDNSQuery(dnsData)
	if err != nil || query == nil {
		return nil
	}

	d.statsMu.Lock()
	d.stats.queriesInspected++
	d.statsMu.Unlock()

	srcIP := ""
	if ctx != nil && ctx.SrcIP != nil {
		srcIP = ctx.SrcIP.String()
	}

	for _, name := range query.names {
		domain := strings.ToLower(strings.TrimSuffix(name, "."))

		// 1. Check known-bad domains
		if d.isKnownBad(domain) {
			d.statsMu.Lock()
			d.stats.badDomainHits++
			d.statsMu.Unlock()
			results = append(results, InspectionResult{
				Timestamp:   time.Now(),
				ThreatLevel: ThreatCritical,
				Category:    ThreatCategoryC2Communication,
				Description: "DNS query to known malicious domain: " + domain,
				Indicators:  []string{"dns-ioc", domain},
				MitreATTCK:  "T1071.004",
				Score:       95,
				Metadata: map[string]interface{}{
					"domain":     domain,
					"query_type": query.qtype,
				},
			})
		}

		// 2. Check for DNS tunneling indicators
		if result := d.checkTunneling(domain, query.qtype); result != nil {
			d.statsMu.Lock()
			d.stats.tunnelDetected++
			d.statsMu.Unlock()
			results = append(results, *result)
		}

		// 3. DGA detection
		if result := d.checkDGA(domain); result != nil {
			d.statsMu.Lock()
			d.stats.dgaDetected++
			d.statsMu.Unlock()
			results = append(results, *result)
		}

		// 4. Exfiltration detection (high query volume to single domain)
		if srcIP != "" {
			if result := d.checkExfiltration(srcIP, domain); result != nil {
				d.statsMu.Lock()
				d.stats.exfilDetected++
				d.statsMu.Unlock()
				results = append(results, *result)
			}
		}
	}

	return results
}

// isKnownBad checks if a domain or any parent domain is in the IOC list.
func (d *DNSInspector) isKnownBad(domain string) bool {
	d.badDomainsMu.RLock()
	defer d.badDomainsMu.RUnlock()

	// Check exact match and parent domains
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		check := strings.Join(parts[i:], ".")
		if d.badDomains[check] {
			return true
		}
	}
	return false
}

// checkTunneling detects DNS tunneling patterns.
func (d *DNSInspector) checkTunneling(domain string, qtype uint16) *InspectionResult {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil
	}

	// Get the subdomain portion (everything except last 2 labels = registered domain)
	subdomainParts := parts
	if len(parts) > 2 {
		subdomainParts = parts[:len(parts)-2]
	}
	subdomain := strings.Join(subdomainParts, ".")

	// Indicator 1: Long subdomain (tunneled data is typically base32/base64 encoded)
	if len(subdomain) > 50 {
		return &InspectionResult{
			Timestamp:   time.Now(),
			ThreatLevel: ThreatHigh,
			Category:    ThreatCategoryDNSTunneling,
			Description: "DNS tunneling detected: abnormally long subdomain (" + itoa(len(subdomain)) + " chars)",
			Indicators:  []string{"dns-tunnel-length", domain},
			MitreATTCK:  "T1071.004",
			Score:       80,
			Metadata: map[string]interface{}{
				"subdomain_length": len(subdomain),
				"domain":           domain,
			},
		}
	}

	// Indicator 2: High entropy in subdomain labels
	if len(subdomain) > 10 {
		entropy := shannonEntropy(subdomain)
		if entropy > 3.5 {
			return &InspectionResult{
				Timestamp:   time.Now(),
				ThreatLevel: ThreatHigh,
				Category:    ThreatCategoryDNSTunneling,
				Description: "DNS tunneling detected: high entropy subdomain",
				Indicators:  []string{"dns-tunnel-entropy", domain},
				MitreATTCK:  "T1071.004",
				Score:       75,
				Metadata: map[string]interface{}{
					"entropy": entropy,
					"domain":  domain,
				},
			}
		}
	}

	// Indicator 3: Many subdomain labels (>4 labels before registered domain)
	if len(subdomainParts) > 4 {
		return &InspectionResult{
			Timestamp:   time.Now(),
			ThreatLevel: ThreatMedium,
			Category:    ThreatCategoryDNSTunneling,
			Description: "DNS tunneling suspected: excessive subdomain depth",
			Indicators:  []string{"dns-tunnel-depth", domain},
			MitreATTCK:  "T1071.004",
			Score:       60,
			Metadata: map[string]interface{}{
				"label_count": len(parts),
				"domain":      domain,
			},
		}
	}

	// Indicator 4: Unusual record types commonly used for tunneling
	if qtype == dnsTypeTXT || qtype == dnsTypeNULL {
		if len(subdomain) > 20 && shannonEntropy(subdomain) > 3.0 {
			return &InspectionResult{
				Timestamp:   time.Now(),
				ThreatLevel: ThreatHigh,
				Category:    ThreatCategoryDNSTunneling,
				Description: "DNS tunneling detected: encoded data in TXT/NULL query",
				Indicators:  []string{"dns-tunnel-qtype", domain},
				MitreATTCK:  "T1071.004",
				Score:       85,
				Metadata: map[string]interface{}{
					"query_type": qtype,
					"domain":     domain,
				},
			}
		}
	}

	return nil
}

// checkDGA detects algorithmically generated domains.
func (d *DNSInspector) checkDGA(domain string) *InspectionResult {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil
	}

	// Analyze the registered domain (second-level label)
	sld := parts[len(parts)-2] // e.g., "qxkjrmtf" in "qxkjrmtf.com"

	// Skip short domains and common ones
	if len(sld) < 6 {
		return nil
	}

	score := dgaScore(sld)
	if score > 0.75 {
		return &InspectionResult{
			Timestamp:   time.Now(),
			ThreatLevel: ThreatHigh,
			Category:    ThreatCategoryDGA,
			Description: "Possible DGA domain detected: " + domain,
			Indicators:  []string{"dga-domain", domain},
			MitreATTCK:  "T1568.002",
			Score:       int(score * 100),
			Metadata: map[string]interface{}{
				"dga_score": score,
				"domain":    domain,
			},
		}
	}

	return nil
}

// dgaScore computes a 0-1 score indicating how likely a label is DGA-generated.
func dgaScore(label string) float64 {
	if len(label) == 0 {
		return 0
	}

	var score float64

	// Feature 1: Consonant/vowel ratio
	vowels, consonants, digits := 0, 0, 0
	for _, r := range label {
		r = unicode.ToLower(r)
		switch {
		case strings.ContainsRune("aeiou", r):
			vowels++
		case r >= 'a' && r <= 'z':
			consonants++
		case r >= '0' && r <= '9':
			digits++
		}
	}
	total := vowels + consonants + digits
	if total == 0 {
		return 0
	}

	vowelRatio := float64(vowels) / float64(total)
	// Normal English: ~40% vowels. DGA tends to have very low or erratic ratios.
	if vowelRatio < 0.2 || vowelRatio > 0.6 {
		score += 0.3
	}

	// Feature 2: Length anomaly
	if len(label) > 8 {
		score += 0.1
	}
	if len(label) > 12 {
		score += 0.1
	}
	if len(label) > 20 {
		score += 0.1
	}

	// Feature 3: Digit mixing (DGA often mixes letters and digits)
	if digits > 0 && consonants > 0 {
		score += 0.2
	}

	// Feature 4: Shannon entropy
	entropy := shannonEntropy(label)
	if entropy > 3.0 {
		score += 0.2
	}
	if entropy > 3.5 {
		score += 0.1
	}

	if score > 1.0 {
		score = 1.0
	}
	return score
}

// checkExfiltration detects high DNS query volume to a single domain from one source.
func (d *DNSInspector) checkExfiltration(srcIP, domain string) *InspectionResult {
	// Extract registered domain (last 2 labels)
	parts := strings.Split(domain, ".")
	regDomain := domain
	if len(parts) >= 2 {
		regDomain = strings.Join(parts[len(parts)-2:], ".")
	}

	d.queryTrackerMu.Lock()
	defer d.queryTrackerMu.Unlock()

	bucket, ok := d.queryTracker[srcIP]
	now := time.Now()

	// Reset bucket if window expired (60s window)
	if !ok || now.Sub(bucket.windowStart) > 60*time.Second {
		bucket = &dnsQueryBucket{
			domainCounts: make(map[string]int),
			windowStart:  now,
		}
		d.queryTracker[srcIP] = bucket
	}

	bucket.domainCounts[regDomain]++

	// Threshold: >50 queries to same domain in 60s
	if bucket.domainCounts[regDomain] > 50 {
		return &InspectionResult{
			Timestamp:   time.Now(),
			ThreatLevel: ThreatHigh,
			Category:    ThreatCategoryDataExfiltration,
			Description: "DNS exfiltration suspected: high query volume to " + regDomain,
			Indicators:  []string{"dns-exfil", regDomain},
			MitreATTCK:  "T1048.003",
			Score:       80,
			Metadata: map[string]interface{}{
				"domain":      regDomain,
				"query_count": bucket.domainCounts[regDomain],
				"window_sec":  60,
			},
		}
	}

	return nil
}

// Name implements PacketInspector.
func (d *DNSInspector) Name() string {
	return "dns-inspector"
}

// Stats implements PacketInspector.
func (d *DNSInspector) Stats() map[string]interface{} {
	d.statsMu.RLock()
	defer d.statsMu.RUnlock()

	d.badDomainsMu.RLock()
	iocCount := len(d.badDomains)
	d.badDomainsMu.RUnlock()

	return map[string]interface{}{
		"queries_inspected": d.stats.queriesInspected,
		"tunnel_detected":   d.stats.tunnelDetected,
		"dga_detected":      d.stats.dgaDetected,
		"bad_domain_hits":   d.stats.badDomainHits,
		"exfil_detected":    d.stats.exfilDetected,
		"ioc_domain_count":  iocCount,
	}
}

// CleanupExpiredTrackers removes expired query tracking buckets.
func (d *DNSInspector) CleanupExpiredTrackers() {
	d.queryTrackerMu.Lock()
	defer d.queryTrackerMu.Unlock()

	now := time.Now()
	for ip, bucket := range d.queryTracker {
		if now.Sub(bucket.windowStart) > 2*time.Minute {
			delete(d.queryTracker, ip)
		}
	}
}

// --- DNS parsing helpers ---

// dnsQuery holds minimal parsed DNS query information.
type dnsQuery struct {
	names []string
	qtype uint16
}

// parseDNSQuery extracts query names from a DNS message.
// Minimal parser for the question section (RFC 1035).
func parseDNSQuery(data []byte) (*dnsQuery, error) {
	if len(data) < 12 {
		return nil, nil // Too short for DNS header
	}

	// DNS header: ID(2) + Flags(2) + QDCount(2) + ANCount(2) + NSCount(2) + ARCount(2)
	qdcount := binary.BigEndian.Uint16(data[4:6])
	if qdcount == 0 || qdcount > 10 {
		return nil, nil
	}

	query := &dnsQuery{}
	offset := 12

	for i := 0; i < int(qdcount) && offset < len(data); i++ {
		name, newOffset := decodeDNSName(data, offset)
		if newOffset <= offset || newOffset+4 > len(data) {
			break
		}

		query.names = append(query.names, name)
		query.qtype = binary.BigEndian.Uint16(data[newOffset : newOffset+2])
		offset = newOffset + 4 // skip QTYPE(2) + QCLASS(2)
	}

	if len(query.names) == 0 {
		return nil, nil
	}

	return query, nil
}

// decodeDNSName decodes a DNS name from wire format.
func decodeDNSName(data []byte, offset int) (string, int) {
	var parts []string
	visited := make(map[int]bool)

	for offset < len(data) {
		if visited[offset] {
			break // pointer loop
		}
		visited[offset] = true

		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}

		// Compression pointer
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				break
			}
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2])) & 0x3FFF
			name, _ := decodeDNSName(data, ptr)
			if name != "" {
				parts = append(parts, name)
			}
			offset += 2
			break
		}

		// Regular label
		offset++
		if offset+length > len(data) {
			break
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}

	return strings.Join(parts, "."), offset
}

// shannonEntropy computes Shannon entropy of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	var entropy float64
	n := float64(len(s))
	for _, count := range freq {
		p := float64(count) / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// itoa is a simple int to string helper to avoid importing strconv just for this.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}
