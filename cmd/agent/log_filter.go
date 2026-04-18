// Package main: rule-based log filter for the agent log proxy.
// Filters logs before shipping to reduce volume; security-relevant logs are always kept.
// See: spec/AGENT_LOG_AI_FILTER_DESIGN.md

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// LogShipPolicy controls whether filtering is applied.
// - "all": ship every log (no filtering).
// - "rules_only": apply drop/ship rules (levels, namespaces).
// - "ai_filter": rules_only + content-based ship/drop (ShipIfContains, DropIfContains); optional ONNX later.
const (
	ShipPolicyAll       = "all"
	ShipPolicyRulesOnly = "rules_only"
	ShipPolicyAIFilter  = "ai_filter"
)

// LogFilterConfig holds rule-based and content-based filter settings (from env or backend).
type LogFilterConfig struct {
	Policy string // ShipPolicyAll, ShipPolicyRulesOnly, or ShipPolicyAIFilter

	// Drop rules: logs matching these are never shipped.
	DropLevels     []string // e.g. ["debug"] — drop debug level
	DropNamespaces []string // e.g. ["kube-system"] — drop these namespaces

	// Allowlist: when non-empty, only ship logs from these namespaces (overrides drop for namespaces not in list).
	// Empty = no allowlist (only drop rules apply).
	ShipOnlyNamespaces []string

	// Always-ship levels: always ship these regardless of namespace (security/errors).
	// Default: error, critical, alert, emergency + security-tagged.
	AlwaysShipLevels []string

	// Phase 2 – content-based: substring match on log message (case-insensitive).
	// When policy is ai_filter: ship if message contains any of ShipIfContains; drop if message contains any of DropIfContains.
	ShipIfContains []string // e.g. ["error", "exception", "unauthorized"]
	DropIfContains []string // e.g. ["/health", "ping", "liveness probe"]

	// Phase 3 – backend-provided "interesting" templates (merged with ShipIfContains when applying).
	InterestingTemplates []string

	// ModelScoringURL: when set (from backend), agent sends log message batches here for ship/drop decisions.
	// The org deployment provides this (e.g. backend /api/v1/agent/log-filter/score or prysm-ai).
	// Empty = use local keyword matching only.
	ModelScoringURL string
}

// defaultAlwaysShipLevels are levels we never drop (prefer recall for security).
var defaultAlwaysShipLevels = []string{"error", "critical", "alert", "emergency", "err", "fatal"}

// Default drop rules when LOG_SHIP_POLICY=rules_only and env vars are unset (reduces volume out of the box).
var (
	defaultDropLevels     = []string{"debug"}
	defaultDropNamespaces = []string{"kube-system", "kube-public"}
)

func defaultLogFilterConfig() LogFilterConfig {
	c := LogFilterConfig{
		Policy:           ShipPolicyAIFilter,  // default: rules + content-based filter
		AlwaysShipLevels: defaultAlwaysShipLevels,
	}
	policy := strings.TrimSpace(strings.ToLower(os.Getenv("LOG_SHIP_POLICY")))
	if policy == ShipPolicyAll {
		c.Policy = ShipPolicyAll
	} else if policy == ShipPolicyAIFilter {
		c.Policy = ShipPolicyAIFilter
	}
	if s := os.Getenv("LOG_DROP_LEVELS"); s != "" {
		for _, v := range strings.Split(s, ",") {
			v = strings.TrimSpace(strings.ToLower(v))
			if v != "" {
				c.DropLevels = append(c.DropLevels, v)
			}
		}
	} else if c.Policy == ShipPolicyRulesOnly || c.Policy == ShipPolicyAIFilter {
		c.DropLevels = append([]string{}, defaultDropLevels...)
	}
	if s := os.Getenv("LOG_DROP_NAMESPACES"); s != "" {
		for _, v := range strings.Split(s, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				c.DropNamespaces = append(c.DropNamespaces, v)
			}
		}
	} else if c.Policy == ShipPolicyRulesOnly || c.Policy == ShipPolicyAIFilter {
		c.DropNamespaces = append([]string{}, defaultDropNamespaces...)
	}
	if s := os.Getenv("LOG_SHIP_ONLY_NAMESPACES"); s != "" {
		for _, v := range strings.Split(s, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				c.ShipOnlyNamespaces = append(c.ShipOnlyNamespaces, v)
			}
		}
	}
	// Phase 2: content-based ship/drop (used when policy is ai_filter)
	if s := os.Getenv("LOG_SHIP_IF_CONTAINS"); s != "" {
		for _, v := range strings.Split(s, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				c.ShipIfContains = append(c.ShipIfContains, v)
			}
		}
	}
	if s := os.Getenv("LOG_DROP_IF_CONTAINS"); s != "" {
		for _, v := range strings.Split(s, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				c.DropIfContains = append(c.DropIfContains, v)
			}
		}
	}
	return c
}

// FilterLogs applies the rule-based (and optionally content-based or remote-model) filter. Returns logs to ship and the number dropped.
// When cfg.ModelScoringURL is set and scoringToken is non-empty, message batches are sent to that URL for ship/drop decisions.
// record shape: Fluent Bit style — "log" or "message", "stream", "level", "kubernetes": {"namespace_name": "..."}.
func FilterLogs(records []map[string]interface{}, cfg LogFilterConfig, scoringToken string) (toShip []map[string]interface{}, dropped int) {
	if cfg.Policy == ShipPolicyAll {
		return records, 0
	}
	if cfg.Policy != ShipPolicyRulesOnly && cfg.Policy != ShipPolicyAIFilter {
		return records, 0
	}
	if len(cfg.DropLevels) == 0 && len(cfg.DropNamespaces) == 0 && len(cfg.ShipOnlyNamespaces) == 0 &&
		len(cfg.ShipIfContains) == 0 && len(cfg.DropIfContains) == 0 && len(cfg.InterestingTemplates) == 0 &&
		cfg.ModelScoringURL == "" {
		return records, 0
	}

	dropLevelSet := make(map[string]struct{}, len(cfg.DropLevels))
	for _, l := range cfg.DropLevels {
		dropLevelSet[l] = struct{}{}
	}
	dropNSSet := make(map[string]struct{}, len(cfg.DropNamespaces))
	for _, ns := range cfg.DropNamespaces {
		dropNSSet[ns] = struct{}{}
	}
	shipOnlyNSSet := make(map[string]struct{}, len(cfg.ShipOnlyNamespaces))
	for _, ns := range cfg.ShipOnlyNamespaces {
		shipOnlyNSSet[ns] = struct{}{}
	}
	alwaysShipLevelSet := make(map[string]struct{}, len(cfg.AlwaysShipLevels))
	for _, l := range cfg.AlwaysShipLevels {
		alwaysShipLevelSet[strings.ToLower(l)] = struct{}{}
	}

	toShip = make([]map[string]interface{}, 0, len(records))
	if cfg.Policy == ShipPolicyAIFilter && cfg.ModelScoringURL != "" && scoringToken != "" {
		// Remote model scoring: first apply level/namespace, then score remaining messages in batch.
		var candidates []map[string]interface{}
		for _, rec := range records {
			if shouldShip(rec, dropLevelSet, dropNSSet, shipOnlyNSSet, alwaysShipLevelSet) {
				candidates = append(candidates, rec)
			} else {
				dropped++
			}
		}
		shipMask, err := scoreBatchRemote(candidates, cfg.ModelScoringURL, scoringToken)
		if err != nil {
			// Fallback to local keyword filter
			for _, rec := range candidates {
				if contentFilter(rec, &cfg) {
					toShip = append(toShip, rec)
				} else {
					dropped++
				}
			}
		} else {
			for i, rec := range candidates {
				if i < len(shipMask) && shipMask[i] {
					toShip = append(toShip, rec)
				} else {
					dropped++
				}
			}
		}
		return toShip, dropped
	}

	for _, rec := range records {
		ship := shouldShip(rec, dropLevelSet, dropNSSet, shipOnlyNSSet, alwaysShipLevelSet)
		if ship && cfg.Policy == ShipPolicyAIFilter {
			ship = contentFilter(rec, &cfg)
		}
		if ship {
			ship = applyWasmLogFilters(rec)
		}
		if ship {
			toShip = append(toShip, rec)
		} else {
			dropped++
		}
	}
	return toShip, dropped
}

func shouldShip(rec map[string]interface{}, dropLevel, dropNS, shipOnlyNS, alwaysShipLevel map[string]struct{}) bool {
	level := extractLevel(rec)
	namespace := extractNamespace(rec)

	// Always ship high-severity levels (security/errors)
	if level != "" {
		if _, ok := alwaysShipLevel[strings.ToLower(level)]; ok {
			return true
		}
	}

	// If we have an allowlist of namespaces, only ship from those
	if len(shipOnlyNS) > 0 {
		if namespace == "" {
			return false // no namespace = drop when allowlist is set
		}
		if _, ok := shipOnlyNS[namespace]; !ok {
			return false
		}
		// namespace is in allowlist; still apply drop level if present
	}

	// Drop by namespace
	if namespace != "" {
		if _, ok := dropNS[namespace]; ok {
			return false
		}
	}

	// Drop by level
	if level != "" {
		if _, ok := dropLevel[strings.ToLower(level)]; ok {
			return false
		}
	}

	return true
}

func extractLevel(rec map[string]interface{}) string {
	if l, ok := rec["level"].(string); ok && l != "" {
		return l
	}
	if s, ok := rec["stream"].(string); ok && strings.ToLower(s) == "stderr" {
		return "error"
	}
	if l, ok := rec["severity"].(string); ok && l != "" {
		return l
	}
	return ""
}

func extractNamespace(rec map[string]interface{}) string {
	if ns, ok := rec["namespace"].(string); ok && ns != "" {
		return ns
	}
	if k8s, ok := rec["kubernetes"].(map[string]interface{}); ok {
		if ns, ok := k8s["namespace_name"].(string); ok && ns != "" {
			return ns
		}
	}
	return ""
}

// scoreBatchRemote sends messages in batches to the org-provided scoring URL; returns ship[] or error.
const scoreBatchSize = 100

func scoreBatchRemote(candidates []map[string]interface{}, url, authToken string) ([]bool, error) {
	messages := make([]string, 0, len(candidates))
	for _, rec := range candidates {
		messages = append(messages, extractMessage(rec))
	}
	allShip := make([]bool, 0, len(messages))
	client := &http.Client{Timeout: 15 * time.Second}
	for i := 0; i < len(messages); i += scoreBatchSize {
		end := i + scoreBatchSize
		if end > len(messages) {
			end = len(messages)
		}
		batch := messages[i:end]
		body, _ := json.Marshal(map[string]interface{}{"messages": batch})
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+authToken)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("log-filter: remote score request failed: %v", err)
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			log.Printf("log-filter: remote score returned %d", resp.StatusCode)
			return nil, fmt.Errorf("remote score returned %d", resp.StatusCode)
		}
		var out struct {
			Ship []bool `json:"ship"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()
		if len(out.Ship) != len(batch) {
			return nil, fmt.Errorf("ship length mismatch")
		}
		allShip = append(allShip, out.Ship...)
	}
	return allShip, nil
}

// extractMessage returns the log message text from a record (Fluent Bit: "log", "message", "msg").
func extractMessage(rec map[string]interface{}) string {
	for _, key := range []string{"log", "message", "msg"} {
		if s, ok := rec[key].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// contentFilter applies Phase 2/3 content-based rules: drop if message matches DropIfContains;
// ship if message matches ShipIfContains or InterestingTemplates; else keep (don't drop by content).
// Called only when policy is ai_filter, after level/namespace rules.
func contentFilter(rec map[string]interface{}, cfg *LogFilterConfig) bool {
	msg := extractMessage(rec)
	if msg == "" {
		return true
	}
	lower := strings.ToLower(msg)
	// Drop if any drop pattern matches
	for _, p := range cfg.DropIfContains {
		if p != "" && strings.Contains(lower, strings.ToLower(p)) {
			return false
		}
	}
	// Ship if any ship pattern or interesting template matches (optional; if no lists, we don't drop)
	shipPatterns := append([]string{}, cfg.ShipIfContains...)
	shipPatterns = append(shipPatterns, cfg.InterestingTemplates...)
	for _, p := range shipPatterns {
		if p != "" && strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return true // no content rule matched → keep (prefer recall for security)
}

// LogFilterStats is optional: track received/shipped/dropped for observability.
type LogFilterStats struct {
	Received int
	Shipped  int
	Dropped  int
}

func (s *LogFilterStats) RecordBatch(received, shipped int) {
	s.Received += received
	s.Shipped += shipped
	s.Dropped += (received - shipped)
}

func (s *LogFilterStats) LogIfDropped(interval int) {
	if s.Dropped > 0 && s.Shipped > 0 && (s.Shipped+s.Dropped)%interval == 0 {
		log.Printf("log-filter: rules_only policy — shipped %d, dropped %d (total received %d)", s.Shipped, s.Dropped, s.Received)
	}
}

// Phase 3: dynamic config from backend (merged with env at startup)
var (
	cachedLogFilter struct {
		mu          sync.RWMutex
		cfg         LogFilterConfig
		initialized bool
	}
)

// initLogFilterConfig sets the cached config from env (defaultLogFilterConfig). Call once at startup.
func initLogFilterConfig() {
	cachedLogFilter.mu.Lock()
	defer cachedLogFilter.mu.Unlock()
	cachedLogFilter.cfg = defaultLogFilterConfig()
	cachedLogFilter.initialized = true
}

// getLogFilterConfig returns the current filter config (env-based or merged from backend).
func getLogFilterConfig() LogFilterConfig {
	cachedLogFilter.mu.RLock()
	defer cachedLogFilter.mu.RUnlock()
	if !cachedLogFilter.initialized {
		return defaultLogFilterConfig()
	}
	return cachedLogFilter.cfg
}

// updateLogFilterConfig merges backend response into the cached config. Only non-empty fields from backend override.
func updateLogFilterConfig(backend map[string]interface{}) {
	cachedLogFilter.mu.Lock()
	defer cachedLogFilter.mu.Unlock()
	if !cachedLogFilter.initialized {
		cachedLogFilter.cfg = defaultLogFilterConfig()
		cachedLogFilter.initialized = true
	}
	c := &cachedLogFilter.cfg
	if v, ok := backend["policy"].(string); ok && v != "" {
		v = strings.TrimSpace(strings.ToLower(v))
		if v == ShipPolicyAll || v == ShipPolicyRulesOnly || v == ShipPolicyAIFilter {
			c.Policy = v
		}
	}
	if v, ok := backend["drop_levels"].([]interface{}); ok {
		c.DropLevels = nil
		for _, x := range v {
			if s, ok := x.(string); ok {
				c.DropLevels = append(c.DropLevels, strings.TrimSpace(strings.ToLower(s)))
			}
		}
	}
	if v, ok := backend["drop_namespaces"].([]interface{}); ok {
		c.DropNamespaces = nil
		for _, x := range v {
			if s, ok := x.(string); ok {
				c.DropNamespaces = append(c.DropNamespaces, strings.TrimSpace(s))
			}
		}
	}
	if v, ok := backend["ship_only_namespaces"].([]interface{}); ok {
		c.ShipOnlyNamespaces = nil
		for _, x := range v {
			if s, ok := x.(string); ok {
				c.ShipOnlyNamespaces = append(c.ShipOnlyNamespaces, strings.TrimSpace(s))
			}
		}
	}
	if v, ok := backend["ship_if_contains"].([]interface{}); ok {
		c.ShipIfContains = nil
		for _, x := range v {
			if s, ok := x.(string); ok {
				c.ShipIfContains = append(c.ShipIfContains, strings.TrimSpace(s))
			}
		}
	}
	if v, ok := backend["drop_if_contains"].([]interface{}); ok {
		c.DropIfContains = nil
		for _, x := range v {
			if s, ok := x.(string); ok {
				c.DropIfContains = append(c.DropIfContains, strings.TrimSpace(s))
			}
		}
	}
	if v, ok := backend["interesting_templates"].([]interface{}); ok {
		c.InterestingTemplates = nil
		for _, x := range v {
			if s, ok := x.(string); ok {
				c.InterestingTemplates = append(c.InterestingTemplates, strings.TrimSpace(s))
			}
		}
	}
	if v, ok := backend["model_scoring_url"].(string); ok {
		c.ModelScoringURL = strings.TrimSpace(v)
	}
}

// StartLogFilterConfigRefresh starts a goroutine that fetches log filter config from the backend periodically.
// GET /api/v1/agent/log-filter/config with Authorization and X-Cluster-ID.
func StartLogFilterConfigRefresh(backendURL, agentToken, clusterID string, interval time.Duration) {
	url := strings.TrimSuffix(backendURL, "/") + "/api/v1/agent/log-filter/config"
	client := &http.Client{Timeout: 15 * time.Second}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				continue
			}
			req.Header.Set("Authorization", "Bearer "+agentToken)
			req.Header.Set("X-Cluster-ID", clusterID)
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("log-filter: failed to fetch config from backend: %v", err)
				continue
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				continue
			}
			var out map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				resp.Body.Close()
				continue
			}
			resp.Body.Close()
			updateLogFilterConfig(out)
		}
	}()
	log.Printf("log-filter: refreshing config from backend every %v", interval)
}
