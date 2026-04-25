package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type edgeDNS struct {
	syncer    *edgeSyncer
	edgeIP    string
	port      int
	stopCh    chan struct{}
	limiterMu sync.Mutex
	limiters  map[string]*queryLimiter
}

type queryLimiter struct {
	count    int
	windowStart time.Time
}

const (
	dnsRateLimitQPS    = 50  // queries per second per client IP
	dnsRateLimitWindow = time.Second
)

func newEdgeDNS(syncer *edgeSyncer, edgeIP string, port int) *edgeDNS {
	return &edgeDNS{
		syncer:   syncer,
		edgeIP:   edgeIP,
		port:     port,
		stopCh:   make(chan struct{}),
		limiters: make(map[string]*queryLimiter),
	}
}

func (d *edgeDNS) start() error {
	addr := fmt.Sprintf(":%d", d.port)
	handler := dns.HandlerFunc(d.serveDNS)

	udpServer := &dns.Server{Addr: addr, Net: "udp", Handler: handler}
	tcpServer := &dns.Server{Addr: addr, Net: "tcp", Handler: handler}

	go func() {
		log.Printf("edge-dns: starting UDP on %s", addr)
		if err := udpServer.ListenAndServe(); err != nil {
			select {
			case <-d.stopCh:
			default:
				log.Printf("edge-dns: UDP error: %v", err)
			}
		}
	}()

	go func() {
		log.Printf("edge-dns: starting TCP on %s", addr)
		if err := tcpServer.ListenAndServe(); err != nil {
			select {
			case <-d.stopCh:
			default:
				log.Printf("edge-dns: TCP error: %v", err)
			}
		}
	}()

	// Periodic limiter cleanup — evict stale entries every 60s
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-d.stopCh:
				return
			case <-ticker.C:
				d.cleanupLimiters()
			}
		}
	}()

	return nil
}

func (d *edgeDNS) cleanupLimiters() {
	d.limiterMu.Lock()
	defer d.limiterMu.Unlock()
	now := time.Now()
	for ip, lim := range d.limiters {
		if now.Sub(lim.windowStart) > 10*time.Second {
			delete(d.limiters, ip)
		}
	}
}

var allowedQTypes = map[uint16]bool{
	dns.TypeA: true, dns.TypeAAAA: true, dns.TypeCNAME: true,
	dns.TypeMX: true, dns.TypeTXT: true, dns.TypeNS: true, dns.TypeSOA: true,
}

func (d *edgeDNS) serveDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 || len(r.Question) > 1 {
		dns.HandleFailed(w, r)
		return
	}

	// Rate limit by client IP
	clientIP := extractDNSClientIP(w.RemoteAddr())
	if clientIP != "" && !d.allowQuery(clientIP) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]

	// Reject unsupported query types
	if !allowedQTypes[q.Qtype] {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return
	}

	// Reject non-INET class
	if q.Qclass != dns.ClassINET {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return
	}

	qname := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if len(qname) > 253 {
		dns.HandleFailed(w, r)
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = false

	domain := d.findDomain(qname)
	if domain == nil {
		m.Rcode = dns.RcodeNameError
		w.WriteMsg(m)
		return
	}

	rr := d.resolve(domain, qname, q.Qtype)
	if rr != nil {
		m.Answer = append(m.Answer, rr)
	}

	w.WriteMsg(m)
}

func (d *edgeDNS) allowQuery(clientIP string) bool {
	d.limiterMu.Lock()
	defer d.limiterMu.Unlock()

	now := time.Now()
	lim, ok := d.limiters[clientIP]
	if !ok || now.Sub(lim.windowStart) > dnsRateLimitWindow {
		d.limiters[clientIP] = &queryLimiter{count: 1, windowStart: now}
		return true
	}
	lim.count++
	return lim.count <= dnsRateLimitQPS
}

func extractDNSClientIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *net.TCPAddr:
		return a.IP.String()
	}
	host, _, _ := net.SplitHostPort(addr.String())
	return host
}

func (d *edgeDNS) findDomain(qname string) *edgeDomainConfig {
	domains := d.syncer.getDomains()
	for i := range domains {
		domainName := strings.ToLower(domains[i].Domain)
		if qname == domainName || strings.HasSuffix(qname, "."+domainName) {
			return &domains[i]
		}
	}
	return nil
}

func (d *edgeDNS) resolve(domain *edgeDomainConfig, qname string, qtype uint16) dns.RR {
	fqdn := dns.Fqdn(qname)

	switch qtype {
	case dns.TypeA:
		ip := d.resolveA(domain)
		if ip == "" {
			return nil
		}
		rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", fqdn, ip))
		if err != nil {
			return nil
		}
		return rr

	case dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeTXT:
		return d.resolveCustomRecord(domain, fqdn, qtype)
	}

	return nil
}

func (d *edgeDNS) resolveA(domain *edgeDomainConfig) string {
	if domain.Proxied {
		return d.edgeIP
	}
	host := domain.UpstreamTarget
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		host = host[:idx]
	}
	if net.ParseIP(host) != nil {
		return host
	}
	return ""
}

func (d *edgeDNS) resolveCustomRecord(domain *edgeDomainConfig, fqdn string, qtype uint16) dns.RR {
	if len(domain.DNSRecords) == 0 {
		return nil
	}

	type dnsRec struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	var records []dnsRec
	if err := json.Unmarshal(domain.DNSRecords, &records); err != nil {
		return nil
	}

	qtypeStr := dns.TypeToString[qtype]
	for _, rec := range records {
		if !strings.EqualFold(rec.Type, qtypeStr) {
			continue
		}
		var rrStr string
		switch qtype {
		case dns.TypeMX:
			rrStr = fmt.Sprintf("%s 300 IN MX %s", fqdn, rec.Value)
		case dns.TypeTXT:
			rrStr = fmt.Sprintf("%s 300 IN TXT \"%s\"", fqdn, rec.Value)
		case dns.TypeCNAME:
			rrStr = fmt.Sprintf("%s 300 IN CNAME %s", fqdn, dns.Fqdn(rec.Value))
		case dns.TypeAAAA:
			rrStr = fmt.Sprintf("%s 60 IN AAAA %s", fqdn, rec.Value)
		}
		if rrStr != "" {
			rr, err := dns.NewRR(rrStr)
			if err == nil {
				return rr
			}
		}
	}
	return nil
}
