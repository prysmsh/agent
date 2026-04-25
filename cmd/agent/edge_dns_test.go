package main

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/miekg/dns"
)

type testResponseWriter struct {
	msg *dns.Msg
}

func (w *testResponseWriter) LocalAddr() net.Addr            { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (w *testResponseWriter) RemoteAddr() net.Addr           { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }
func (w *testResponseWriter) WriteMsg(msg *dns.Msg) error    { w.msg = msg; return nil }
func (w *testResponseWriter) Write([]byte) (int, error)      { return 0, nil }
func (w *testResponseWriter) Close() error                   { return nil }
func (w *testResponseWriter) TsigStatus() error              { return nil }
func (w *testResponseWriter) TsigTimersOnly(bool)            {}
func (w *testResponseWriter) Hijack()                        {}

func testSyncer(domains []edgeDomainConfig) *edgeSyncer {
	return &edgeSyncer{domains: domains}
}

func TestEdgeDNS_ResolveA_Proxied(t *testing.T) {
	syncer := testSyncer([]edgeDomainConfig{
		{Domain: "example.com", Proxied: true, UpstreamTarget: "1.2.3.4:8080"},
	})
	d := newEdgeDNS(syncer, "10.0.0.1", 5353)

	domain := d.findDomain("example.com")
	if domain == nil {
		t.Fatal("expected domain to be found")
	}

	ip := d.resolveA(domain)
	if ip != "10.0.0.1" {
		t.Errorf("expected edge IP 10.0.0.1, got %s", ip)
	}
}

func TestEdgeDNS_ResolveA_DNSOnly(t *testing.T) {
	syncer := testSyncer([]edgeDomainConfig{
		{Domain: "example.com", Proxied: false, UpstreamTarget: "192.168.1.50:9000"},
	})
	d := newEdgeDNS(syncer, "10.0.0.1", 5353)

	domain := d.findDomain("example.com")
	if domain == nil {
		t.Fatal("expected domain to be found")
	}

	ip := d.resolveA(domain)
	if ip != "192.168.1.50" {
		t.Errorf("expected origin IP 192.168.1.50, got %s", ip)
	}
}

func TestEdgeDNS_ResolveA_DNSOnly_Hostname(t *testing.T) {
	syncer := testSyncer([]edgeDomainConfig{
		{Domain: "example.com", Proxied: false, UpstreamTarget: "backend.internal:8080"},
	})
	d := newEdgeDNS(syncer, "10.0.0.1", 5353)

	domain := d.findDomain("example.com")
	if domain == nil {
		t.Fatal("expected domain to be found")
	}

	ip := d.resolveA(domain)
	if ip != "" {
		t.Errorf("expected empty IP for hostname origin, got %s", ip)
	}
}

func TestEdgeDNS_SubdomainMatch(t *testing.T) {
	syncer := testSyncer([]edgeDomainConfig{
		{Domain: "example.com", Proxied: true, UpstreamTarget: "1.2.3.4:80"},
	})
	d := newEdgeDNS(syncer, "10.0.0.1", 5353)

	domain := d.findDomain("www.example.com")
	if domain == nil {
		t.Fatal("expected www.example.com to match zone example.com")
	}
	if domain.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", domain.Domain)
	}
}

func TestEdgeDNS_NoMatch(t *testing.T) {
	syncer := testSyncer([]edgeDomainConfig{
		{Domain: "example.com", Proxied: true},
	})
	d := newEdgeDNS(syncer, "10.0.0.1", 5353)

	domain := d.findDomain("unknown.org")
	if domain != nil {
		t.Errorf("expected nil for unknown domain, got %+v", domain)
	}
}

func TestEdgeDNS_CustomRecords(t *testing.T) {
	records := []map[string]string{
		{"type": "MX", "value": "10 mail.example.com"},
		{"type": "TXT", "value": "v=spf1 include:example.com ~all"},
	}
	raw, _ := json.Marshal(records)

	syncer := testSyncer([]edgeDomainConfig{
		{Domain: "example.com", Proxied: false, DNSRecords: json.RawMessage(raw)},
	})
	d := newEdgeDNS(syncer, "10.0.0.1", 5353)

	domain := d.findDomain("example.com")
	if domain == nil {
		t.Fatal("expected domain to be found")
	}

	mx := d.resolveCustomRecord(domain, "example.com.", dns.TypeMX)
	if mx == nil {
		t.Fatal("expected MX record, got nil")
	}
	if _, ok := mx.(*dns.MX); !ok {
		t.Errorf("expected *dns.MX type, got %T", mx)
	}

	txt := d.resolveCustomRecord(domain, "example.com.", dns.TypeTXT)
	if txt == nil {
		t.Fatal("expected TXT record, got nil")
	}
	if _, ok := txt.(*dns.TXT); !ok {
		t.Errorf("expected *dns.TXT type, got %T", txt)
	}
}

func TestEdgeDNS_ServeDNS_Integration(t *testing.T) {
	syncer := testSyncer([]edgeDomainConfig{
		{Domain: "example.com", Proxied: true, UpstreamTarget: "1.2.3.4:80"},
	})
	d := newEdgeDNS(syncer, "10.0.0.1", 5353)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	w := &testResponseWriter{}
	d.serveDNS(w, req)

	if w.msg == nil {
		t.Fatal("expected a response message")
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(w.msg.Answer))
	}
	a, ok := w.msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected *dns.A answer, got %T", w.msg.Answer[0])
	}
	if a.A.String() != "10.0.0.1" {
		t.Errorf("expected IP 10.0.0.1, got %s", a.A.String())
	}
	if !w.msg.Authoritative {
		t.Error("expected authoritative response")
	}
}

func TestEdgeDNS_ServeDNS_NXDOMAIN(t *testing.T) {
	syncer := testSyncer([]edgeDomainConfig{
		{Domain: "example.com", Proxied: true},
	})
	d := newEdgeDNS(syncer, "10.0.0.1", 5353)

	req := new(dns.Msg)
	req.SetQuestion("notfound.org.", dns.TypeA)

	w := &testResponseWriter{}
	d.serveDNS(w, req)

	if w.msg == nil {
		t.Fatal("expected a response message")
	}
	if w.msg.Rcode != dns.RcodeNameError {
		t.Errorf("expected NXDOMAIN rcode %d, got %d", dns.RcodeNameError, w.msg.Rcode)
	}
}
