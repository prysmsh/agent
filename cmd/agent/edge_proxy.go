package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"
)

type edgeProxy struct {
	syncer    *edgeSyncer
	httpPort  int
	httpsPort int
	acmeEmail string
	staging   bool
	certMagic   *certmagic.Config
	wafClient   *warpVectorClient
	embedFn     func(string) []float32
}

func newEdgeProxy(syncer *edgeSyncer, httpPort, httpsPort int, acmeEmail string, staging bool) *edgeProxy {
	return &edgeProxy{
		syncer:    syncer,
		httpPort:  httpPort,
		httpsPort: httpsPort,
		acmeEmail: acmeEmail,
		staging:   staging,
	}
}

func (p *edgeProxy) start(ctx context.Context) error {
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = p.acmeEmail
	if p.staging {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	}

	magic := certmagic.NewDefault()
	p.certMagic = magic

	domains := p.activeProxiedDomains()
	if len(domains) > 0 {
		if err := magic.ManageAsync(ctx, domains); err != nil {
			log.Printf("edge-proxy: initial cert provisioning: %v", err)
		}
	}

	p.syncer.onChange = chainOnChange(p.syncer.onChange, func() {
		updated := p.activeProxiedDomains()
		if len(updated) > 0 {
			if err := magic.ManageAsync(ctx, updated); err != nil {
				log.Printf("edge-proxy: cert re-sync: %v", err)
			}
		}
		log.Printf("edge-proxy: config updated, %d proxied domain(s)", len(updated))
	})

	tlsConfig := &tls.Config{
		GetCertificate: magic.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h2", "http/1.1"},
	}

	httpsServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", p.httpsPort),
		Handler:      http.HandlerFunc(p.handleHTTPS),
		TLSConfig:    tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	acmeIssuer := certmagic.DefaultACME
	httpHandler := acmeIssuer.HTTPChallengeHandler(http.HandlerFunc(p.handleHTTPRedirect))
	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", p.httpPort),
		Handler:      httpHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("edge-proxy: HTTPS listening on :%d", p.httpsPort)
		ln, err := tls.Listen("tcp", httpsServer.Addr, tlsConfig)
		if err != nil {
			log.Printf("edge-proxy: HTTPS listen error: %v", err)
			return
		}
		if err := httpsServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("edge-proxy: HTTPS serve error: %v", err)
		}
	}()

	go func() {
		log.Printf("edge-proxy: HTTP listening on :%d (ACME + redirect)", p.httpPort)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("edge-proxy: HTTP serve error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpsServer.Shutdown(shutCtx)
		httpServer.Shutdown(shutCtx)
	}()

	return nil
}

func (p *edgeProxy) handleHTTPRedirect(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.RequestURI()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func (p *edgeProxy) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	domain := p.findDomain(host)
	if domain == nil {
		http.Error(w, "unknown domain", http.StatusNotFound)
		return
	}

	if !domain.Proxied {
		http.Error(w, "domain is DNS-only", http.StatusBadGateway)
		return
	}

	// AI WAF inline check
	if p.wafClient != nil && p.embedFn != nil {
		result := checkRequest(r, p.embedFn, p.wafClient)
		if result.Blocked {
			log.Printf("ai-waf: blocked %s %s from %s (threat=%s score=%.2f latency=%s)",
				r.Method, r.URL.Path, r.RemoteAddr, result.ThreatType, result.Score, result.Latency)
			w.Header().Set("X-Prysm-WAF", "blocked")
			w.Header().Set("X-Prysm-Threat", result.ThreatType)
			http.Error(w, "Request blocked by AI WAF", http.StatusForbidden)
			return
		}
	}

	upstream, err := url.Parse("http://" + domain.UpstreamTarget)
	if err != nil {
		http.Error(w, "invalid upstream", http.StatusBadGateway)
		return
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host
			req.Host = upstream.Host

			clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
			if clientIP == "" {
				clientIP = r.RemoteAddr
			}
			req.Header.Set("X-Forwarded-For", clientIP)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Real-IP", clientIP)
			req.Header.Set("X-Forwarded-Host", r.Host)
			req.Header.Set("X-Prysm-Domain", domain.Domain)
			req.Header.Set("X-Prysm-Request-ID", generateRequestID())
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("edge-proxy: upstream error for %s: %v", domain.Domain, err)
			http.Error(w, "upstream unreachable", http.StatusBadGateway)
		},
		Transport: &http.Transport{
			DialContext: ssrfSafeDialer().DialContext,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	proxy.ServeHTTP(w, r)
}

func (p *edgeProxy) findDomain(host string) *edgeDomainConfig {
	domains := p.syncer.getDomains()
	for i := range domains {
		d := strings.ToLower(domains[i].Domain)
		if host == d || strings.HasSuffix(host, "."+d) {
			return &domains[i]
		}
	}
	return nil
}

func (p *edgeProxy) activeProxiedDomains() []string {
	var result []string
	for _, d := range p.syncer.getDomains() {
		if d.Proxied && d.Status == "active" {
			result = append(result, d.Domain)
		}
	}
	return result
}

func generateRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// ssrfSafeDialer returns a net.Dialer wrapped with IP validation that blocks
// connections to private, loopback, link-local, and multicast addresses.
// This prevents SSRF attacks where an attacker sets upstream_target to an
// internal IP (e.g. 169.254.169.254 for cloud metadata).
func ssrfSafeDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("ssrf: invalid address %q", address)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("ssrf: cannot parse IP %q", host)
			}
			if isPrivateIP(ip) {
				return fmt.Errorf("ssrf: blocked connection to private IP %s", ip)
			}
			return nil
		},
	}
}

func isPrivateIP(ip net.IP) bool {
	privateRanges := []struct {
		network *net.IPNet
	}{
		{parseCIDR("10.0.0.0/8")},
		{parseCIDR("172.16.0.0/12")},
		{parseCIDR("192.168.0.0/16")},
		{parseCIDR("127.0.0.0/8")},
		{parseCIDR("169.254.0.0/16")},
		{parseCIDR("224.0.0.0/4")},
		{parseCIDR("::1/128")},
		{parseCIDR("fe80::/10")},
		{parseCIDR("fc00::/7")},
	}
	for _, r := range privateRanges {
		if r.network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIDR(s string) *net.IPNet {
	_, network, _ := net.ParseCIDR(s)
	return network
}

func chainOnChange(existing func(), additional func()) func() {
	if existing == nil {
		return additional
	}
	return func() {
		existing()
		additional()
	}
}
