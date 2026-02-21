// Package main provides Data Loss Prevention (DLP) inspection for the DPI engine.
// Detects credit card numbers, SSNs, API keys, private keys, and credentials
// flowing through tunnels to prevent data exfiltration.
package main

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// DLP threat categories
const (
	ThreatCategoryDLP ThreatCategory = "data_loss_prevention" // T1048
)

// dlpPattern defines a DLP detection pattern.
type dlpPattern struct {
	id          string
	name        string
	description string
	pattern     *regexp.Regexp
	level       ThreatLevel
	score       int
	mitre       string
	// validator is an optional function for post-regex validation (e.g., Luhn check)
	validator func(match string) bool
}

// DLPInspector implements PacketInspector for data loss prevention.
type DLPInspector struct {
	patterns []*dlpPattern
	stats    struct {
		scansPerformed  int64
		sensitiveFound  int64
		creditCards     int64
		ssns            int64
		apiKeys         int64
		privateKeys     int64
		credentialsURLs int64
	}
	statsMu sync.RWMutex
}

// NewDLPInspector creates a DLP inspector with default patterns.
func NewDLPInspector() *DLPInspector {
	d := &DLPInspector{}
	d.loadDefaultPatterns()
	return d
}

func (d *DLPInspector) loadDefaultPatterns() {
	d.patterns = []*dlpPattern{
		// Credit card numbers (Luhn-validated)
		{
			id:          "dlp-cc-001",
			name:        "Credit card number (Visa)",
			description: "Detected Visa credit card number in transit",
			pattern:     regexp.MustCompile(`\b4[0-9]{12}(?:[0-9]{3})?\b`),
			level:       ThreatHigh,
			score:       85,
			mitre:       "T1048",
			validator:   luhnCheck,
		},
		{
			id:          "dlp-cc-002",
			name:        "Credit card number (Mastercard)",
			description: "Detected Mastercard credit card number in transit",
			pattern:     regexp.MustCompile(`\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b`),
			level:       ThreatHigh,
			score:       85,
			mitre:       "T1048",
			validator:   luhnCheck,
		},
		{
			id:          "dlp-cc-003",
			name:        "Credit card number (Amex)",
			description: "Detected American Express card number in transit",
			pattern:     regexp.MustCompile(`\b3[47][0-9]{13}\b`),
			level:       ThreatHigh,
			score:       85,
			mitre:       "T1048",
			validator:   luhnCheck,
		},
		{
			id:          "dlp-cc-004",
			name:        "Credit card number (Discover)",
			description: "Detected Discover card number in transit",
			pattern:     regexp.MustCompile(`\b6(?:011|5[0-9]{2})[0-9]{12}\b`),
			level:       ThreatHigh,
			score:       85,
			mitre:       "T1048",
			validator:   luhnCheck,
		},

		// SSN (Go regexp doesn't support lookaheads, so we validate in post-processing)
		{
			id:          "dlp-ssn-001",
			name:        "US Social Security Number",
			description: "Detected US SSN in transit",
			pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			level:       ThreatHigh,
			score:       90,
			mitre:       "T1048",
			validator:   validateSSN,
		},

		// AWS credentials
		{
			id:          "dlp-aws-001",
			name:        "AWS Access Key ID",
			description: "Detected AWS access key in transit",
			pattern:     regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
			level:       ThreatCritical,
			score:       95,
			mitre:       "T1552.001",
		},
		{
			id:          "dlp-aws-002",
			name:        "AWS Secret Access Key",
			description: "Detected AWS secret key in transit",
			pattern:     regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`),
			level:       ThreatCritical,
			score:       95,
			mitre:       "T1552.001",
		},

		// GitHub tokens
		{
			id:          "dlp-gh-001",
			name:        "GitHub personal access token",
			description: "Detected GitHub token in transit",
			pattern:     regexp.MustCompile(`\bgh[ps]_[A-Za-z0-9_]{36,}\b`),
			level:       ThreatCritical,
			score:       95,
			mitre:       "T1552.001",
		},
		{
			id:          "dlp-gh-002",
			name:        "GitHub OAuth token",
			description: "Detected GitHub OAuth token in transit",
			pattern:     regexp.MustCompile(`\bgho_[A-Za-z0-9_]{36,}\b`),
			level:       ThreatCritical,
			score:       90,
			mitre:       "T1552.001",
		},

		// Stripe keys
		{
			id:          "dlp-stripe-001",
			name:        "Stripe live secret key",
			description: "Detected Stripe live secret key in transit",
			pattern:     regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`),
			level:       ThreatCritical,
			score:       95,
			mitre:       "T1552.001",
		},
		{
			id:          "dlp-stripe-002",
			name:        "Stripe live publishable key",
			description: "Detected Stripe live publishable key in transit",
			pattern:     regexp.MustCompile(`\bpk_live_[A-Za-z0-9]{24,}\b`),
			level:       ThreatHigh,
			score:       70,
			mitre:       "T1552.001",
		},

		// GCP service account
		{
			id:          "dlp-gcp-001",
			name:        "GCP service account key",
			description: "Detected GCP service account JSON key in transit",
			pattern:     regexp.MustCompile(`"type"\s*:\s*"service_account"[\s\S]*?"private_key"`),
			level:       ThreatCritical,
			score:       95,
			mitre:       "T1552.001",
		},

		// Private keys
		{
			id:          "dlp-pkey-001",
			name:        "RSA private key",
			description: "Detected RSA private key in transit",
			pattern:     regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
			level:       ThreatCritical,
			score:       95,
			mitre:       "T1552.004",
		},
		{
			id:          "dlp-pkey-002",
			name:        "EC private key",
			description: "Detected EC private key in transit",
			pattern:     regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			level:       ThreatCritical,
			score:       95,
			mitre:       "T1552.004",
		},
		{
			id:          "dlp-pkey-003",
			name:        "OpenSSH private key",
			description: "Detected OpenSSH private key in transit",
			pattern:     regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
			level:       ThreatCritical,
			score:       95,
			mitre:       "T1552.004",
		},
		{
			id:          "dlp-pkey-004",
			name:        "Generic private key",
			description: "Detected private key in transit",
			pattern:     regexp.MustCompile(`-----BEGIN PRIVATE KEY-----`),
			level:       ThreatCritical,
			score:       95,
			mitre:       "T1552.004",
		},

		// Passwords in URLs
		{
			id:          "dlp-cred-001",
			name:        "Credentials in URL",
			description: "Detected credentials embedded in URL",
			pattern:     regexp.MustCompile(`(?i)(?:https?|ftp)://[^:@/\s]+:[^:@/\s]+@[^/\s]+`),
			level:       ThreatHigh,
			score:       80,
			mitre:       "T1552.001",
		},

		// Generic API key patterns
		{
			id:          "dlp-apikey-001",
			name:        "Generic API key assignment",
			description: "Detected API key or secret in transit",
			pattern:     regexp.MustCompile(`(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[=:]\s*['"][A-Za-z0-9\-_.]{20,}['"]`),
			level:       ThreatHigh,
			score:       75,
			mitre:       "T1552.001",
		},

		// Slack tokens
		{
			id:          "dlp-slack-001",
			name:        "Slack bot/user token",
			description: "Detected Slack token in transit",
			pattern:     regexp.MustCompile(`\bxox[bpors]-[0-9]+-[0-9]+-[A-Za-z0-9]+\b`),
			level:       ThreatHigh,
			score:       85,
			mitre:       "T1552.001",
		},
	}
}

// Inspect implements PacketInspector. Scans outbound traffic only (exfiltration direction).
func (d *DLPInspector) Inspect(data []byte, direction string, ctx *InspectionContext) []InspectionResult {
	// DLP primarily scans outbound traffic (data leaving the mesh)
	if direction != "outbound" && direction != "any" {
		return nil
	}

	d.statsMu.Lock()
	d.stats.scansPerformed++
	d.statsMu.Unlock()

	dataStr := string(data)
	var results []InspectionResult

	for _, p := range d.patterns {
		matches := p.pattern.FindAllString(dataStr, 5) // cap at 5 matches per pattern
		for _, match := range matches {
			// Run validator if present (e.g., Luhn for credit cards)
			if p.validator != nil && !p.validator(match) {
				continue
			}

			d.statsMu.Lock()
			d.stats.sensitiveFound++
			d.updateCategoryStats(p.id)
			d.statsMu.Unlock()

			// Redact the match for the indicator (show first/last 4 chars)
			redacted := redactMatch(match)

			results = append(results, InspectionResult{
				Timestamp:   time.Now(),
				ThreatLevel: p.level,
				Category:    ThreatCategoryDLP,
				Description: p.description,
				Indicators:  []string{p.id, redacted},
				MitreATTCK:  p.mitre,
				Score:       p.score,
				Metadata: map[string]interface{}{
					"pattern_id":   p.id,
					"pattern_name": p.name,
					"direction":    direction,
				},
			})

			break // One match per pattern is enough
		}
	}

	return results
}

// updateCategoryStats increments per-category counters. Caller must hold statsMu.
func (d *DLPInspector) updateCategoryStats(patternID string) {
	switch {
	case strings.HasPrefix(patternID, "dlp-cc-"):
		d.stats.creditCards++
	case strings.HasPrefix(patternID, "dlp-ssn-"):
		d.stats.ssns++
	case strings.HasPrefix(patternID, "dlp-aws-") || strings.HasPrefix(patternID, "dlp-gh-") ||
		strings.HasPrefix(patternID, "dlp-stripe-") || strings.HasPrefix(patternID, "dlp-gcp-") ||
		strings.HasPrefix(patternID, "dlp-apikey-") || strings.HasPrefix(patternID, "dlp-slack-"):
		d.stats.apiKeys++
	case strings.HasPrefix(patternID, "dlp-pkey-"):
		d.stats.privateKeys++
	case strings.HasPrefix(patternID, "dlp-cred-"):
		d.stats.credentialsURLs++
	}
}

// Name implements PacketInspector.
func (d *DLPInspector) Name() string {
	return "dlp-inspector"
}

// Stats implements PacketInspector.
func (d *DLPInspector) Stats() map[string]interface{} {
	d.statsMu.RLock()
	defer d.statsMu.RUnlock()

	return map[string]interface{}{
		"scans_performed":  d.stats.scansPerformed,
		"sensitive_found":  d.stats.sensitiveFound,
		"credit_cards":     d.stats.creditCards,
		"ssns":             d.stats.ssns,
		"api_keys":         d.stats.apiKeys,
		"private_keys":     d.stats.privateKeys,
		"credentials_urls": d.stats.credentialsURLs,
		"pattern_count":    len(d.patterns),
	}
}

// validateSSN checks if a matched SSN pattern is valid (not 000, 666, or 9xx prefix).
func validateSSN(s string) bool {
	if len(s) != 11 { // NNN-NN-NNNN
		return false
	}
	// Area number (first 3 digits) cannot be 000, 666, or 900-999
	area := s[:3]
	if area == "000" || area == "666" {
		return false
	}
	if area[0] == '9' {
		return false
	}
	// Group number (middle 2 digits) cannot be 00
	if s[4:6] == "00" {
		return false
	}
	// Serial number (last 4 digits) cannot be 0000
	if s[7:] == "0000" {
		return false
	}
	return true
}

// luhnCheck validates a number string using the Luhn algorithm.
func luhnCheck(s string) bool {
	// Strip non-digit characters
	var digits []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}

	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}

	return sum%10 == 0
}

// redactMatch redacts the middle of a sensitive match for logging.
func redactMatch(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}
