package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEdgeProxy_FindDomain(t *testing.T) {
	syncer := testSyncer([]edgeDomainConfig{
		{Domain: "example.com", UpstreamTarget: "localhost:3000", Proxied: true, Status: "active"},
		{Domain: "other.com", UpstreamTarget: "localhost:4000", Proxied: false, Status: "active"},
	})
	p := &edgeProxy{syncer: syncer}

	tests := []struct {
		host   string
		expect string
	}{
		{"example.com", "example.com"},
		{"www.example.com", "example.com"},
		{"api.example.com", "example.com"},
		{"other.com", "other.com"},
		{"unknown.com", ""},
	}

	for _, tt := range tests {
		domain := p.findDomain(tt.host)
		if tt.expect == "" {
			if domain != nil {
				t.Errorf("findDomain(%q) = %s, want nil", tt.host, domain.Domain)
			}
		} else {
			if domain == nil || domain.Domain != tt.expect {
				got := ""
				if domain != nil {
					got = domain.Domain
				}
				t.Errorf("findDomain(%q) = %q, want %q", tt.host, got, tt.expect)
			}
		}
	}
}

func TestEdgeProxy_ActiveProxiedDomains(t *testing.T) {
	syncer := testSyncer([]edgeDomainConfig{
		{Domain: "active-proxied.com", Proxied: true, Status: "active"},
		{Domain: "active-dnsonly.com", Proxied: false, Status: "active"},
		{Domain: "pending.com", Proxied: true, Status: "pending_verification"},
	})
	p := &edgeProxy{syncer: syncer}

	domains := p.activeProxiedDomains()
	if len(domains) != 1 {
		t.Fatalf("expected 1 active proxied domain, got %d", len(domains))
	}
	if domains[0] != "active-proxied.com" {
		t.Errorf("expected active-proxied.com, got %s", domains[0])
	}
}

func TestEdgeProxy_HandleHTTPS_UnknownDomain(t *testing.T) {
	syncer := testSyncer([]edgeDomainConfig{})
	p := &edgeProxy{syncer: syncer}

	req := httptest.NewRequest("GET", "https://unknown.com/path", nil)
	req.Host = "unknown.com"
	w := httptest.NewRecorder()

	p.handleHTTPS(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestEdgeProxy_HandleHTTPS_DNSOnly(t *testing.T) {
	syncer := testSyncer([]edgeDomainConfig{
		{Domain: "dnsonly.com", UpstreamTarget: "localhost:3000", Proxied: false, Status: "active"},
	})
	p := &edgeProxy{syncer: syncer}

	req := httptest.NewRequest("GET", "https://dnsonly.com/", nil)
	req.Host = "dnsonly.com"
	w := httptest.NewRecorder()

	p.handleHTTPS(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected 502, got %d", w.Code)
	}
}

func TestEdgeProxy_HandleHTTPS_ProxiedUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Proto") != "https" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-Prysm-Domain") != "test.com" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-Prysm-Request-ID") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from upstream"))
	}))
	defer upstream.Close()

	upstreamAddr := upstream.Listener.Addr().String()

	syncer := testSyncer([]edgeDomainConfig{
		{Domain: "test.com", UpstreamTarget: upstreamAddr, Proxied: true, Status: "active"},
	})
	p := &edgeProxy{syncer: syncer}

	req := httptest.NewRequest("GET", "https://test.com/api/hello", nil)
	req.Host = "test.com"
	req.RemoteAddr = "192.168.1.100:54321"
	w := httptest.NewRecorder()

	p.handleHTTPS(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	if w.Body.String() != "hello from upstream" {
		t.Errorf("expected 'hello from upstream', got %q", w.Body.String())
	}
}

func TestEdgeProxy_HandleHTTPRedirect(t *testing.T) {
	p := &edgeProxy{}

	req := httptest.NewRequest("GET", "http://example.com/path?q=1", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	p.handleHTTPRedirect(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Errorf("expected 301, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "https://example.com/path?q=1" {
		t.Errorf("expected redirect to https, got %q", loc)
	}
}
