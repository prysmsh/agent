// Package main provides network threat signatures for packet inspection.
// This implements pattern-based detection for common web attacks including
// SQL injection, XSS, command injection, path traversal, and web shells.
package main

import (
	"bytes"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Extended ThreatCategory constants for network-based threats
const (
	ThreatCategorySQLInjection     ThreatCategory = "sql_injection"      // T1190
	ThreatCategoryXSS              ThreatCategory = "xss"                // T1189
	ThreatCategoryPathTraversal    ThreatCategory = "path_traversal"     // T1083
	ThreatCategoryWebShell         ThreatCategory = "web_shell"          // T1505.003
	ThreatCategoryMaliciousUpload  ThreatCategory = "malicious_upload"   // T1608.001
	ThreatCategoryDNSTunneling     ThreatCategory = "dns_tunneling"      // T1071.004
	ThreatCategoryDGA              ThreatCategory = "dga"                // T1568.002
	ThreatCategoryCommandInjection ThreatCategory = "command_injection"  // T1059
	ThreatCategoryLDAPInjection    ThreatCategory = "ldap_injection"     // T1190
	ThreatCategoryXXE              ThreatCategory = "xxe"                // T1190
	ThreatCategorySSRF             ThreatCategory = "ssrf"               // T1190
	ThreatCategoryFileInclusion    ThreatCategory = "file_inclusion"     // T1190
	ThreatCategoryTemplateInjection ThreatCategory = "template_injection" // T1190
)

// NetworkSignature defines a pattern-based threat signature
type NetworkSignature struct {
	ID          string
	Name        string
	Description string
	Pattern     *regexp.Regexp
	Category    ThreatCategory
	Level       ThreatLevel
	Score       int
	MitreATTCK  string
	// Direction: "any", "inbound", "outbound"
	Direction string
}

// NetworkSignatureScanner implements PacketInspector using regex patterns
type NetworkSignatureScanner struct {
	signatures []*NetworkSignature
	stats      struct {
		scansPerformed int64
		matchesFound   int64
		bytesScanned   int64
	}
	statsMu sync.RWMutex

	// externalSigs holds signatures loaded from YAML files (hot-reloadable)
	externalMu   sync.RWMutex
	externalSigs []*NetworkSignature
}

// NewNetworkSignatureScanner creates a scanner with default signatures
func NewNetworkSignatureScanner() *NetworkSignatureScanner {
	scanner := &NetworkSignatureScanner{}
	scanner.loadDefaultSignatures()
	return scanner
}

// loadDefaultSignatures initializes the default signature set
func (s *NetworkSignatureScanner) loadDefaultSignatures() {
	s.signatures = []*NetworkSignature{
		// SQL Injection signatures
		{
			ID:          "sqli-001",
			Name:        "SQL UNION injection",
			Description: "Detected SQL UNION-based injection attempt",
			Pattern:     regexp.MustCompile(`(?i)(?:union\s+(?:all\s+)?select|select\s+.*\s+from\s+.*\s+where)`),
			Category:    ThreatCategorySQLInjection,
			Level:       ThreatHigh,
			Score:       80,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},
		{
			ID:          "sqli-002",
			Name:        "SQL comment injection",
			Description: "Detected SQL comment-based injection attempt",
			Pattern:     regexp.MustCompile(`(?i)(?:--|#|/\*|\*/|;)\s*(?:select|insert|update|delete|drop|create|alter|exec|execute)`),
			Category:    ThreatCategorySQLInjection,
			Level:       ThreatHigh,
			Score:       75,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},
		{
			ID:          "sqli-003",
			Name:        "SQL OR/AND injection",
			Description: "Detected SQL boolean injection attempt",
			Pattern:     regexp.MustCompile(`(?i)(?:'\s*(?:or|and)\s*'?\d|"\s*(?:or|and)\s*"?\d|'\s*(?:or|and)\s*'[^']*'|"\s*(?:or|and)\s*"[^"]*")`),
			Category:    ThreatCategorySQLInjection,
			Level:       ThreatHigh,
			Score:       80,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},
		{
			ID:          "sqli-004",
			Name:        "SQL time-based injection",
			Description: "Detected SQL time-based blind injection attempt",
			Pattern:     regexp.MustCompile(`(?i)(?:sleep\s*\(\s*\d|benchmark\s*\(\s*\d|waitfor\s+delay|pg_sleep)`),
			Category:    ThreatCategorySQLInjection,
			Level:       ThreatHigh,
			Score:       85,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},
		{
			ID:          "sqli-005",
			Name:        "SQL stacked queries",
			Description: "Detected SQL stacked queries injection",
			Pattern:     regexp.MustCompile(`(?i);\s*(?:select|insert|update|delete|drop|create|alter|truncate)\s+`),
			Category:    ThreatCategorySQLInjection,
			Level:       ThreatHigh,
			Score:       85,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},

		// XSS signatures
		{
			ID:          "xss-001",
			Name:        "Script tag injection",
			Description: "Detected JavaScript script tag injection",
			Pattern:     regexp.MustCompile(`(?i)<\s*script[^>]*>.*?<\s*/\s*script\s*>`),
			Category:    ThreatCategoryXSS,
			Level:       ThreatHigh,
			Score:       80,
			MitreATTCK:  "T1189",
			Direction:   "any",
		},
		{
			ID:          "xss-002",
			Name:        "Event handler injection",
			Description: "Detected HTML event handler injection",
			Pattern:     regexp.MustCompile(`(?i)(?:on(?:load|error|click|mouse|focus|blur|submit|change|key|abort|drag|drop|touch|play|ended|pause|scroll|resize|hashchange|popstate|storage|message|online|offline|beforeunload)\s*=)`),
			Category:    ThreatCategoryXSS,
			Level:       ThreatHigh,
			Score:       75,
			MitreATTCK:  "T1189",
			Direction:   "any",
		},
		{
			ID:          "xss-003",
			Name:        "JavaScript URI injection",
			Description: "Detected javascript: URI scheme injection",
			Pattern:     regexp.MustCompile(`(?i)(?:javascript|vbscript|livescript|data)\s*:`),
			Category:    ThreatCategoryXSS,
			Level:       ThreatHigh,
			Score:       80,
			MitreATTCK:  "T1189",
			Direction:   "any",
		},
		{
			ID:          "xss-004",
			Name:        "DOM manipulation",
			Description: "Detected DOM manipulation attempt",
			Pattern:     regexp.MustCompile(`(?i)(?:document\.(?:cookie|write|location|domain)|window\.(?:location|open|eval)|\.innerHTML\s*=|\.outerHTML\s*=)`),
			Category:    ThreatCategoryXSS,
			Level:       ThreatMedium,
			Score:       60,
			MitreATTCK:  "T1189",
			Direction:   "any",
		},
		{
			ID:          "xss-005",
			Name:        "SVG/IMG tag injection",
			Description: "Detected SVG/IMG based XSS",
			Pattern:     regexp.MustCompile(`(?i)<\s*(?:svg|img|iframe|object|embed|video|audio)[^>]*(?:on\w+\s*=|src\s*=\s*["']?(?:javascript|data):)`),
			Category:    ThreatCategoryXSS,
			Level:       ThreatHigh,
			Score:       75,
			MitreATTCK:  "T1189",
			Direction:   "any",
		},

		// Command Injection signatures
		{
			ID:          "cmdi-001",
			Name:        "Command chaining",
			Description: "Detected command chaining/injection attempt",
			Pattern:     regexp.MustCompile(`(?:;|\||&&|\$\(|\x60).*?(?:cat|ls|pwd|whoami|id|uname|wget|curl|nc|bash|sh|python|perl|ruby|php)`),
			Category:    ThreatCategoryCommandInjection,
			Level:       ThreatCritical,
			Score:       90,
			MitreATTCK:  "T1059",
			Direction:   "any",
		},
		{
			ID:          "cmdi-002",
			Name:        "Reverse shell command",
			Description: "Detected reverse shell command pattern",
			Pattern:     regexp.MustCompile(`(?i)(?:bash\s+-i\s+>&|nc\s+-e|/dev/tcp/|mkfifo|python.*socket.*connect|perl.*socket.*open)`),
			Category:    ThreatCategoryCommandInjection,
			Level:       ThreatCritical,
			Score:       95,
			MitreATTCK:  "T1059.004",
			Direction:   "any",
		},
		{
			ID:          "cmdi-003",
			Name:        "Download and execute",
			Description: "Detected download and execute pattern",
			Pattern:     regexp.MustCompile(`(?i)(?:curl|wget|fetch)\s+.*\|\s*(?:bash|sh|python|perl|ruby)`),
			Category:    ThreatCategoryCommandInjection,
			Level:       ThreatCritical,
			Score:       95,
			MitreATTCK:  "T1059",
			Direction:   "any",
		},
		{
			ID:          "cmdi-004",
			Name:        "Base64 decode execute",
			Description: "Detected base64 decode and execute pattern",
			Pattern:     regexp.MustCompile(`(?i)(?:base64\s+-d|echo.*\|\s*base64|atob\s*\().*(?:\||exec|eval|system)`),
			Category:    ThreatCategoryCommandInjection,
			Level:       ThreatHigh,
			Score:       85,
			MitreATTCK:  "T1059",
			Direction:   "any",
		},

		// Path Traversal signatures
		{
			ID:          "path-001",
			Name:        "Directory traversal",
			Description: "Detected directory traversal attempt",
			Pattern:     regexp.MustCompile(`(?:\.\.[\\/]){2,}|(?:\.\.[\\/]).*(?:etc/passwd|etc/shadow|windows/system32)`),
			Category:    ThreatCategoryPathTraversal,
			Level:       ThreatHigh,
			Score:       80,
			MitreATTCK:  "T1083",
			Direction:   "any",
		},
		{
			ID:          "path-002",
			Name:        "Encoded traversal",
			Description: "Detected URL-encoded directory traversal",
			Pattern:     regexp.MustCompile(`(?i)(?:%2e%2e[/\\%]|%252e%252e[/\\%]|%c0%ae%c0%ae[/\\%]|\.\.%2f|\.\.%5c|%2e%2e%2f)`),
			Category:    ThreatCategoryPathTraversal,
			Level:       ThreatHigh,
			Score:       85,
			MitreATTCK:  "T1083",
			Direction:   "any",
		},
		{
			ID:          "path-003",
			Name:        "Sensitive file access",
			Description: "Detected access attempt to sensitive files",
			Pattern:     regexp.MustCompile(`(?i)(?:/etc/(?:passwd|shadow|hosts|sudoers)|/proc/self/|/var/log/|\.ssh/|\.aws/credentials|\.kube/config)`),
			Category:    ThreatCategoryPathTraversal,
			Level:       ThreatHigh,
			Score:       80,
			MitreATTCK:  "T1083",
			Direction:   "any",
		},

		// Web Shell signatures
		{
			ID:          "webshell-001",
			Name:        "PHP web shell",
			Description: "Detected PHP web shell pattern",
			Pattern:     regexp.MustCompile(`(?i)<\?php.*(?:eval\s*\(|base64_decode|system\s*\(|exec\s*\(|shell_exec|passthru|proc_open)`),
			Category:    ThreatCategoryWebShell,
			Level:       ThreatCritical,
			Score:       95,
			MitreATTCK:  "T1505.003",
			Direction:   "any",
		},
		{
			ID:          "webshell-002",
			Name:        "JSP web shell",
			Description: "Detected JSP web shell pattern",
			Pattern:     regexp.MustCompile(`(?i)<%.*(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder|\.exec\s*\()`),
			Category:    ThreatCategoryWebShell,
			Level:       ThreatCritical,
			Score:       95,
			MitreATTCK:  "T1505.003",
			Direction:   "any",
		},
		{
			ID:          "webshell-003",
			Name:        "ASP web shell",
			Description: "Detected ASP web shell pattern",
			Pattern:     regexp.MustCompile(`(?i)<%.*(?:CreateObject\s*\(\s*["']WScript\.Shell|Server\.CreateObject)`),
			Category:    ThreatCategoryWebShell,
			Level:       ThreatCritical,
			Score:       95,
			MitreATTCK:  "T1505.003",
			Direction:   "any",
		},

		// LDAP Injection
		{
			ID:          "ldapi-001",
			Name:        "LDAP injection",
			Description: "Detected LDAP injection attempt",
			Pattern:     regexp.MustCompile(`(?i)(?:\*\)\(|\)\(\||\)\(!\(|(?:uid|cn|mail|objectClass)\s*=\s*\*)`),
			Category:    ThreatCategoryLDAPInjection,
			Level:       ThreatHigh,
			Score:       75,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},

		// XXE (XML External Entity)
		{
			ID:          "xxe-001",
			Name:        "XXE attack",
			Description: "Detected XML External Entity injection",
			Pattern:     regexp.MustCompile(`(?i)<!(?:DOCTYPE|ENTITY)[^>]*(?:SYSTEM|PUBLIC)\s*["'][^"']*["']`),
			Category:    ThreatCategoryXXE,
			Level:       ThreatHigh,
			Score:       85,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},
		{
			ID:          "xxe-002",
			Name:        "XXE file disclosure",
			Description: "Detected XXE file disclosure attempt",
			Pattern:     regexp.MustCompile(`(?i)<!ENTITY[^>]*(?:file://|php://|expect://|data://)`),
			Category:    ThreatCategoryXXE,
			Level:       ThreatCritical,
			Score:       90,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},

		// SSRF (Server-Side Request Forgery)
		{
			ID:          "ssrf-001",
			Name:        "SSRF localhost",
			Description: "Detected SSRF attempt to localhost",
			Pattern:     regexp.MustCompile(`(?i)(?:url|uri|path|src|href|dest|redirect|next|goto|return)\s*=\s*["']?(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])`),
			Category:    ThreatCategorySSRF,
			Level:       ThreatHigh,
			Score:       80,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},
		{
			ID:          "ssrf-002",
			Name:        "SSRF internal IP",
			Description: "Detected SSRF attempt to internal network",
			Pattern:     regexp.MustCompile(`(?i)(?:url|uri|path|src|href|dest|redirect)\s*=\s*["']?https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)`),
			Category:    ThreatCategorySSRF,
			Level:       ThreatHigh,
			Score:       75,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},
		{
			ID:          "ssrf-003",
			Name:        "SSRF cloud metadata",
			Description: "Detected SSRF attempt to cloud metadata",
			Pattern:     regexp.MustCompile(`(?i)(?:169\.254\.169\.254|metadata\.google|metadata\.azure)`),
			Category:    ThreatCategorySSRF,
			Level:       ThreatCritical,
			Score:       90,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},

		// File Inclusion
		{
			ID:          "lfi-001",
			Name:        "Local file inclusion",
			Description: "Detected local file inclusion attempt",
			Pattern:     regexp.MustCompile(`(?i)(?:file|page|include|path|doc|document|folder|root|pg)\s*=\s*["']?(?:\.\.[\\/]|/etc/|/proc/|/var/|C:\\)`),
			Category:    ThreatCategoryFileInclusion,
			Level:       ThreatHigh,
			Score:       80,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},
		{
			ID:          "rfi-001",
			Name:        "Remote file inclusion",
			Description: "Detected remote file inclusion attempt",
			Pattern:     regexp.MustCompile(`(?i)(?:file|page|include|path|doc)\s*=\s*["']?https?://`),
			Category:    ThreatCategoryFileInclusion,
			Level:       ThreatHigh,
			Score:       85,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},

		// Template Injection
		{
			ID:          "ssti-001",
			Name:        "Server-side template injection",
			Description: "Detected template injection attempt",
			Pattern:     regexp.MustCompile(`(?i)\{\{\s*(?:config|request|self|cycler|joiner|namespace|lipsum|range|dict|get_flashed_messages|url_for|\[\]|__class__|__mro__|__subclasses__|__globals__|__builtins__)`),
			Category:    ThreatCategoryTemplateInjection,
			Level:       ThreatHigh,
			Score:       85,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},
		{
			ID:          "ssti-002",
			Name:        "Jinja2 template injection",
			Description: "Detected Jinja2 template injection",
			Pattern:     regexp.MustCompile(`\{\{.*(?:__|\x27|\x22|\[|\]|\(\)).*\}\}`),
			Category:    ThreatCategoryTemplateInjection,
			Level:       ThreatHigh,
			Score:       80,
			MitreATTCK:  "T1190",
			Direction:   "any",
		},

		// Malicious file uploads / EICAR test
		{
			ID:          "malware-001",
			Name:        "EICAR test file",
			Description: "Detected EICAR anti-malware test file",
			Pattern:     regexp.MustCompile(`X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*`),
			Category:    ThreatCategoryMaliciousUpload,
			Level:       ThreatMedium,
			Score:       50,
			MitreATTCK:  "T1608.001",
			Direction:   "any",
		},
		{
			ID:          "malware-002",
			Name:        "PE executable upload",
			Description: "Detected Windows executable upload",
			Pattern:     regexp.MustCompile(`MZ[\x00-\xff]{0,500}This program`),
			Category:    ThreatCategoryMaliciousUpload,
			Level:       ThreatMedium,
			Score:       60,
			MitreATTCK:  "T1608.001",
			Direction:   "inbound",
		},
		{
			ID:          "malware-003",
			Name:        "ELF executable upload",
			Description: "Detected Linux executable upload",
			Pattern:     regexp.MustCompile(`\x7fELF[\x01\x02][\x01\x02]`),
			Category:    ThreatCategoryMaliciousUpload,
			Level:       ThreatMedium,
			Score:       60,
			MitreATTCK:  "T1608.001",
			Direction:   "inbound",
		},
	}
}

// Inspect implements PacketInspector.
// It normalizes the payload (URL decode, HTML entities, unicode, etc.) before
// matching signatures. If the InspectionContext has a StreamState, the full
// sliding window is inspected instead of just the current chunk, enabling
// detection of patterns split across TCP segments.
func (s *NetworkSignatureScanner) Inspect(data []byte, direction string, ctx *InspectionContext) []InspectionResult {
	var results []InspectionResult

	s.statsMu.Lock()
	s.stats.scansPerformed++
	s.stats.bytesScanned += int64(len(data))
	s.statsMu.Unlock()

	// Determine the data to scan: use stream window if available
	scanData := data
	if ctx != nil && ctx.Stream != nil {
		scanData = ctx.Stream.Append(data)
	}

	// Normalize payload to defeat encoding-based evasion
	normalized := NormalizePayload(scanData)
	normalizedStr := bytesToSafeString(normalized)

	// Also scan raw data (some signatures match binary patterns)
	rawStr := bytesToSafeString(scanData)

	// Merge built-in and external signatures
	allSigs := s.allSignatures()

	for _, sig := range allSigs {
		// Check direction filter
		if sig.Direction != "any" && sig.Direction != direction {
			continue
		}

		// Deduplicate: skip if already alerted for this sig on this connection
		if ctx != nil && ctx.Stream != nil {
			if ctx.Stream.HasAlerted(sig.ID) {
				continue
			}
		}

		// Match against normalized data first, then raw
		matched := sig.Pattern.MatchString(normalizedStr)
		matchStr := normalizedStr
		if !matched {
			matched = sig.Pattern.MatchString(rawStr)
			matchStr = rawStr
		}

		if matched {
			s.statsMu.Lock()
			s.stats.matchesFound++
			s.statsMu.Unlock()

			// Mark as alerted for dedup
			if ctx != nil && ctx.Stream != nil {
				ctx.Stream.MarkAlerted(sig.ID)
			}

			// Extract matched content for indicators
			match := sig.Pattern.FindString(matchStr)
			indicators := []string{sig.ID}
			if len(match) > 0 && len(match) < 200 {
				indicators = append(indicators, truncateString(match, 100))
			}

			results = append(results, InspectionResult{
				Timestamp:   time.Now(),
				ThreatLevel: sig.Level,
				Category:    sig.Category,
				Description: sig.Description,
				Indicators:  indicators,
				MitreATTCK:  sig.MitreATTCK,
				Score:       sig.Score,
				Metadata: map[string]interface{}{
					"signature_id":   sig.ID,
					"signature_name": sig.Name,
					"direction":      direction,
				},
			})
		}
	}

	return results
}

// allSignatures returns the merged list of built-in and external signatures.
func (s *NetworkSignatureScanner) allSignatures() []*NetworkSignature {
	s.externalMu.RLock()
	ext := s.externalSigs
	s.externalMu.RUnlock()

	if len(ext) == 0 {
		return s.signatures
	}

	// Build override map by ID
	overrides := make(map[string]*NetworkSignature, len(ext))
	for _, sig := range ext {
		overrides[sig.ID] = sig
	}

	// Merge: external overrides built-in by ID
	merged := make([]*NetworkSignature, 0, len(s.signatures)+len(ext))
	seen := make(map[string]bool)
	for _, sig := range s.signatures {
		if override, ok := overrides[sig.ID]; ok {
			merged = append(merged, override)
			seen[sig.ID] = true
		} else {
			merged = append(merged, sig)
		}
	}
	// Append external sigs that don't override built-in
	for _, sig := range ext {
		if !seen[sig.ID] {
			merged = append(merged, sig)
		}
	}
	return merged
}

// SetExternalSignatures replaces the external signature set (thread-safe).
// Called by the signature loader on hot-reload.
func (s *NetworkSignatureScanner) SetExternalSignatures(sigs []*NetworkSignature) {
	s.externalMu.Lock()
	s.externalSigs = sigs
	s.externalMu.Unlock()
}

// Name implements PacketInspector
func (s *NetworkSignatureScanner) Name() string {
	return "network-signature-scanner"
}

// Stats implements PacketInspector
func (s *NetworkSignatureScanner) Stats() map[string]interface{} {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()

	s.externalMu.RLock()
	extCount := len(s.externalSigs)
	s.externalMu.RUnlock()

	return map[string]interface{}{
		"scans_performed":          s.stats.scansPerformed,
		"matches_found":            s.stats.matchesFound,
		"bytes_scanned":            s.stats.bytesScanned,
		"builtin_signature_count":  len(s.signatures),
		"external_signature_count": extCount,
		"signature_count":          len(s.signatures) + extCount,
	}
}

// AddSignature adds a custom signature
func (s *NetworkSignatureScanner) AddSignature(sig *NetworkSignature) {
	s.signatures = append(s.signatures, sig)
}

// Helper functions

// bytesToSafeString converts bytes to a string safe for regex matching
// Handles binary data by replacing non-printable chars (except common ones)
func bytesToSafeString(data []byte) string {
	// Fast path: if data is small enough, just convert directly
	if len(data) < 8192 {
		return string(data)
	}

	// For larger data, only scan first and last portions
	// (attacks are typically at boundaries)
	if len(data) > 32768 {
		combined := make([]byte, 0, 65536)
		combined = append(combined, data[:32768]...)
		combined = append(combined, data[len(data)-32768:]...)
		return string(combined)
	}

	return string(data)
}

// truncateString safely truncates a string to maxLen
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// HTTPRequestInspector specializes in HTTP request inspection
type HTTPRequestInspector struct {
	scanner *NetworkSignatureScanner
}

// NewHTTPRequestInspector creates an HTTP-specialized inspector
func NewHTTPRequestInspector() *HTTPRequestInspector {
	return &HTTPRequestInspector{
		scanner: NewNetworkSignatureScanner(),
	}
}

// Inspect implements PacketInspector with HTTP awareness
func (h *HTTPRequestInspector) Inspect(data []byte, direction string, ctx *InspectionContext) []InspectionResult {
	results := h.scanner.Inspect(data, direction, ctx)

	// Additional HTTP-specific checks
	if isHTTPRequest(data) {
		// Check for suspicious HTTP methods
		if bytes.HasPrefix(data, []byte("TRACE ")) || bytes.HasPrefix(data, []byte("TRACK ")) {
			results = append(results, InspectionResult{
				Timestamp:   time.Now(),
				ThreatLevel: ThreatMedium,
				Category:    ThreatCategoryXSS,
				Description: "HTTP TRACE/TRACK method enabled - potential XST vulnerability",
				Indicators:  []string{"http-trace-method"},
				MitreATTCK:  "T1189",
				Score:       50,
			})
		}

		// Check for HTTP request smuggling patterns
		if bytes.Contains(data, []byte("Transfer-Encoding:")) && bytes.Contains(data, []byte("Content-Length:")) {
			results = append(results, InspectionResult{
				Timestamp:   time.Now(),
				ThreatLevel: ThreatHigh,
				Category:    ThreatCategoryCommandInjection,
				Description: "Potential HTTP request smuggling - both Transfer-Encoding and Content-Length present",
				Indicators:  []string{"http-smuggling"},
				MitreATTCK:  "T1190",
				Score:       75,
			})
		}

		// Check for suspicious User-Agent patterns
		if idx := bytes.Index(data, []byte("User-Agent:")); idx >= 0 {
			uaEnd := bytes.IndexByte(data[idx:], '\n')
			if uaEnd > 0 {
				ua := string(data[idx : idx+uaEnd])
				suspiciousUA := []string{"sqlmap", "nikto", "nmap", "burp", "zap", "acunetix", "nessus", "openvas", "w3af", "skipfish", "wfuzz", "gobuster", "dirbuster", "masscan"}
				uaLower := strings.ToLower(ua)
				for _, tool := range suspiciousUA {
					if strings.Contains(uaLower, tool) {
						results = append(results, InspectionResult{
							Timestamp:   time.Now(),
							ThreatLevel: ThreatMedium,
							Category:    ThreatCategorySuspiciousProcess,
							Description: "Suspicious security scanner User-Agent detected: " + tool,
							Indicators:  []string{"scanner-ua", tool},
							MitreATTCK:  "T1595",
							Score:       55,
						})
						break
					}
				}
			}
		}
	}

	return results
}

// Name implements PacketInspector
func (h *HTTPRequestInspector) Name() string {
	return "http-request-inspector"
}

// Stats implements PacketInspector
func (h *HTTPRequestInspector) Stats() map[string]interface{} {
	return h.scanner.Stats()
}

// isHTTPRequest checks if data looks like an HTTP request
func isHTTPRequest(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	methods := [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("HEAD "),
		[]byte("OPTIONS "),
		[]byte("PATCH "),
		[]byte("CONNECT "),
		[]byte("TRACE "),
		[]byte("TRACK "),
	}
	for _, method := range methods {
		if bytes.HasPrefix(data, method) {
			return true
		}
	}
	return false
}
