package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type edgeDomainConfig struct {
	ID             uint             `json:"id"`
	Domain         string           `json:"domain"`
	UpstreamTarget string           `json:"upstream_target"`
	UpstreamMode   string           `json:"upstream_mode"`
	Proxied        bool             `json:"proxied"`
	Status         string           `json:"status"`
	DNSRecords     json.RawMessage  `json:"dns_records"`
	Rules          []edgeRuleConfig `json:"rules"`
}

type edgeRuleConfig struct {
	ID              uint            `json:"id"`
	Name            string          `json:"name"`
	Priority        int             `json:"priority"`
	MatchExpression string          `json:"match_expression"`
	Action          string          `json:"action"`
	ActionConfig    json.RawMessage `json:"action_config"`
}

type edgeConfigResponse struct {
	Domains []edgeDomainConfig `json:"domains"`
}

type edgeSyncer struct {
	agent      *PrysmAgent
	mu         sync.RWMutex
	domains    []edgeDomainConfig
	configHash string
	interval   time.Duration
	onChange   func()
}

func newEdgeSyncer(agent *PrysmAgent) *edgeSyncer {
	return &edgeSyncer{
		agent:    agent,
		interval: 30 * time.Second,
	}
}

func (s *edgeSyncer) run(ctx context.Context) {
	if s.agent.BackendURL == "" || s.agent.AgentToken == "" {
		log.Printf("edge-sync: backend URL or agent token not set, skipping")
		return
	}

	s.fetch(ctx)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.fetch(ctx)
		}
	}
}

func (s *edgeSyncer) fetch(ctx context.Context) {
	url := s.agent.BackendURL + "/api/v1/agent/edge/config"

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		log.Printf("edge-sync: create request: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.agent.AgentToken)
	req.Header.Set("X-Cluster-ID", s.agent.ClusterID)

	resp, err := s.agent.HTTPClient.Do(req)
	if err != nil {
		log.Printf("edge-sync: fetch failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("edge-sync: backend returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		return
	}

	var cfg edgeConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		log.Printf("edge-sync: decode: %v", err)
		return
	}

	raw, _ := json.Marshal(cfg.Domains)
	newHash := fmt.Sprintf("%x", sha256.Sum256(raw))

	s.mu.Lock()
	changed := s.configHash != newHash
	s.domains = cfg.Domains
	s.configHash = newHash
	s.mu.Unlock()

	if changed && s.onChange != nil {
		s.onChange()
	}

	if len(cfg.Domains) > 0 {
		names := make([]string, len(cfg.Domains))
		for i, d := range cfg.Domains {
			names[i] = fmt.Sprintf("%s(%d rules)", d.Domain, len(d.Rules))
		}
		log.Printf("edge-sync: %d domain(s): %s", len(cfg.Domains), strings.Join(names, ", "))
	}
}

func (s *edgeSyncer) getDomains() []edgeDomainConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.domains
}
