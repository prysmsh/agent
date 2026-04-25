package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestFingerprint_BasicGET(t *testing.T) {
	r := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/api/users", RawQuery: "page=1&limit=10"},
		Header: http.Header{"User-Agent": []string{"Mozilla/5.0 Chrome/120"}},
	}
	fp := fingerprint(r)
	if !strings.HasPrefix(fp, "GET /api/users") {
		t.Errorf("expected GET /api/users prefix, got %q", fp)
	}
	if !strings.Contains(fp, "ua:chrome") {
		t.Errorf("expected ua:chrome, got %q", fp)
	}
	if !strings.Contains(fp, "q:limit,page") {
		t.Errorf("expected sorted query keys, got %q", fp)
	}
}

func TestFingerprint_POSTWithBody(t *testing.T) {
	r := &http.Request{
		Method:        "POST",
		URL:           &url.URL{Path: "/api/login"},
		Header:        http.Header{"Content-Type": []string{"application/json"}, "User-Agent": []string{"python-requests/2.31"}},
		ContentLength: 256,
	}
	fp := fingerprint(r)
	if !strings.Contains(fp, "ct:application/json") {
		t.Errorf("expected content type, got %q", fp)
	}
	if !strings.Contains(fp, "ua:python-requests") {
		t.Errorf("expected python-requests, got %q", fp)
	}
	if !strings.Contains(fp, "len:small") {
		t.Errorf("expected small, got %q", fp)
	}
}

func TestFingerprint_AttackTool(t *testing.T) {
	r := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/admin"},
		Header: http.Header{"User-Agent": []string{"sqlmap/1.7"}},
	}
	fp := fingerprint(r)
	if !strings.Contains(fp, "ua:sqlmap") {
		t.Errorf("expected sqlmap, got %q", fp)
	}
}

func TestUAFamily(t *testing.T) {
	tests := []struct{ ua, expect string }{
		{"Mozilla/5.0 Chrome/120", "chrome"},
		{"sqlmap/1.7#stable", "sqlmap"},
		{"python-requests/2.31.0", "python-requests"},
		{"curl/8.4.0", "curl"},
		{"Go-http-client/2.0", "go-http-client"},
		{"CustomBot", "custombot"},
	}
	for _, tt := range tests {
		if got := uaFamily(tt.ua); got != tt.expect {
			t.Errorf("uaFamily(%q) = %q, want %q", tt.ua, got, tt.expect)
		}
	}
}

func TestBodySizeBucket(t *testing.T) {
	tests := []struct {
		size   int64
		expect string
	}{
		{0, "empty"}, {-1, "empty"}, {100, "small"}, {5000, "medium"}, {50000, "large"}, {200000, "huge"},
	}
	for _, tt := range tests {
		if got := bodySizeBucket(tt.size); got != tt.expect {
			t.Errorf("bodySizeBucket(%d) = %q, want %q", tt.size, got, tt.expect)
		}
	}
}
