// Package main provides IP/domain reputation checking for the DPI engine.
// Maintains an in-memory blocklist of known-bad IPs and CIDR ranges loaded
// from local files and periodically refreshed from the backend API.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultReputationFile is the default path for reputation data.
	DefaultReputationFile = "/etc/prysm/dpi/reputation.txt"

	// reputationRefreshInterval is how often to refresh from backend.
	reputationRefreshInterval = 5 * time.Minute
)

// ReputationInspector checks source/destination IPs against a blocklist.
type ReputationInspector struct {
	// IP blocklist
	blockedIPs   map[string]bool // exact IP matches
	blockedCIDRs []*net.IPNet    // CIDR range matches
	blockMu      sync.RWMutex

	// Backend API config
	backendURL string
	clusterID  string
	httpClient *http.Client

	stats struct {
		ipsChecked   int64
		blockedHits  int64
		listSize     int64
	}

	stopCh chan struct{}
}

// NewReputationInspector creates a reputation inspector.
func NewReputationInspector() *ReputationInspector {
	return &ReputationInspector{
		blockedIPs: make(map[string]bool),
		httpClient: &http.Client{Timeout: 10 * time.Second},
		stopCh:     make(chan struct{}),
	}
}

// LoadFromFile loads IPs and CIDRs from a text file (one per line).
// Lines starting with # are comments. Empty lines are skipped.
func (r *ReputationInspector) LoadFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist yet — not an error
		}
		return err
	}
	defer f.Close()

	return r.loadFromReader(f)
}

// loadFromReader parses IPs/CIDRs from a reader.
func (r *ReputationInspector) loadFromReader(reader io.Reader) error {
	var ips []string
	var cidrs []*net.IPNet

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Try CIDR first
		if strings.Contains(line, "/") {
			_, cidr, err := net.ParseCIDR(line)
			if err == nil {
				cidrs = append(cidrs, cidr)
				continue
			}
		}

		// Try as plain IP
		if ip := net.ParseIP(line); ip != nil {
			ips = append(ips, ip.String())
		}
	}

	r.blockMu.Lock()
	r.blockedIPs = make(map[string]bool, len(ips))
	for _, ip := range ips {
		r.blockedIPs[ip] = true
	}
	r.blockedCIDRs = cidrs
	atomic.StoreInt64(&r.stats.listSize, int64(len(ips)+len(cidrs)))
	r.blockMu.Unlock()

	return scanner.Err()
}

// SetBackendConfig configures backend API refresh.
func (r *ReputationInspector) SetBackendConfig(backendURL, clusterID string, httpClient *http.Client) {
	r.backendURL = backendURL
	r.clusterID = clusterID
	if httpClient != nil {
		r.httpClient = httpClient
	}
}

// Start loads the initial reputation list and begins periodic refresh.
func (r *ReputationInspector) Start() {
	// Load from local file
	if err := r.LoadFromFile(DefaultReputationFile); err != nil {
		log.Printf("dpi: reputation: failed to load %s: %v", DefaultReputationFile, err)
	} else {
		r.blockMu.RLock()
		count := len(r.blockedIPs) + len(r.blockedCIDRs)
		r.blockMu.RUnlock()
		if count > 0 {
			log.Printf("dpi: reputation: loaded %d entries from %s", count, DefaultReputationFile)
		}
	}

	// Start backend refresh loop if configured
	if r.backendURL != "" {
		go r.refreshLoop()
	}
}

// Stop stops the reputation inspector.
func (r *ReputationInspector) Stop() {
	close(r.stopCh)
}

// refreshLoop periodically fetches the blocklist from the backend API.
func (r *ReputationInspector) refreshLoop() {
	ticker := time.NewTicker(reputationRefreshInterval)
	defer ticker.Stop()

	// Initial fetch
	r.fetchFromBackend()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.fetchFromBackend()
		}
	}
}

// fetchFromBackend fetches the reputation list from the backend API.
func (r *ReputationInspector) fetchFromBackend() {
	if r.backendURL == "" {
		return
	}

	url := fmt.Sprintf("%s/api/v1/agent/dpi/reputation", strings.TrimRight(r.backendURL, "/"))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	if r.clusterID != "" {
		req.Header.Set("X-Cluster-ID", r.clusterID)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return
	}

	// Backend returns JSON array of IPs/CIDRs
	var entries []string
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		// Try plain text format as fallback
		return
	}

	var ips []string
	var cidrs []*net.IPNet
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if strings.Contains(entry, "/") {
			if _, cidr, err := net.ParseCIDR(entry); err == nil {
				cidrs = append(cidrs, cidr)
				continue
			}
		}
		if ip := net.ParseIP(entry); ip != nil {
			ips = append(ips, ip.String())
		}
	}

	r.blockMu.Lock()
	// Merge with file-based entries (backend additions)
	for _, ip := range ips {
		r.blockedIPs[ip] = true
	}
	r.blockedCIDRs = append(r.blockedCIDRs, cidrs...)
	atomic.StoreInt64(&r.stats.listSize, int64(len(r.blockedIPs)+len(r.blockedCIDRs)))
	r.blockMu.Unlock()

	total := len(ips) + len(cidrs)
	if total > 0 {
		log.Printf("dpi: reputation: refreshed %d entries from backend", total)
	}
}

// IsBlocked checks if an IP is in the blocklist.
func (r *ReputationInspector) IsBlocked(ip net.IP) bool {
	if ip == nil {
		return false
	}

	r.blockMu.RLock()
	defer r.blockMu.RUnlock()

	// Check exact IP match
	if r.blockedIPs[ip.String()] {
		return true
	}

	// Check CIDR ranges
	for _, cidr := range r.blockedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// Inspect implements PacketInspector for reputation checking.
func (r *ReputationInspector) Inspect(data []byte, direction string, ctx *InspectionContext) []InspectionResult {
	if ctx == nil {
		return nil
	}

	var results []InspectionResult

	// Check source IP
	if ctx.SrcIP != nil {
		atomic.AddInt64(&r.stats.ipsChecked, 1)
		if r.IsBlocked(ctx.SrcIP) {
			atomic.AddInt64(&r.stats.blockedHits, 1)
			results = append(results, InspectionResult{
				Timestamp:   time.Now(),
				ThreatLevel: ThreatHigh,
				Category:    ThreatCategoryC2Communication,
				Description: fmt.Sprintf("Connection from blocklisted IP: %s", ctx.SrcIP),
				Indicators:  []string{"reputation-blocked-src", ctx.SrcIP.String()},
				MitreATTCK:  "T1071",
				Score:       85,
				Metadata: map[string]interface{}{
					"blocked_ip": ctx.SrcIP.String(),
					"direction":  "source",
				},
			})
		}
	}

	// Check destination IP
	if ctx.DstIP != nil {
		atomic.AddInt64(&r.stats.ipsChecked, 1)
		if r.IsBlocked(ctx.DstIP) {
			atomic.AddInt64(&r.stats.blockedHits, 1)
			results = append(results, InspectionResult{
				Timestamp:   time.Now(),
				ThreatLevel: ThreatHigh,
				Category:    ThreatCategoryC2Communication,
				Description: fmt.Sprintf("Connection to blocklisted IP: %s", ctx.DstIP),
				Indicators:  []string{"reputation-blocked-dst", ctx.DstIP.String()},
				MitreATTCK:  "T1071",
				Score:       85,
				Metadata: map[string]interface{}{
					"blocked_ip": ctx.DstIP.String(),
					"direction":  "destination",
				},
			})
		}
	}

	return results
}

// Name implements PacketInspector.
func (r *ReputationInspector) Name() string {
	return "reputation-inspector"
}

// Stats implements PacketInspector.
func (r *ReputationInspector) Stats() map[string]interface{} {
	return map[string]interface{}{
		"ips_checked":  atomic.LoadInt64(&r.stats.ipsChecked),
		"blocked_hits": atomic.LoadInt64(&r.stats.blockedHits),
		"list_size":    atomic.LoadInt64(&r.stats.listSize),
	}
}
