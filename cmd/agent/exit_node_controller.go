package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	exitNodeReconcileInterval = 2 * time.Minute
	exitNodeConfigPath        = "/api/v1/agent/network/config"
)

type agentNetworkConfig struct {
	ClusterID    uint   `json:"cluster_id"`
	OverlayCIDR  string `json:"overlay_cidr"`
	IsExitRouter bool   `json:"is_exit_router"`
}

type exitNodeController struct {
	agent       *PrysmAgent
	lastEnabled *bool
	mu          sync.Mutex
}

func (a *PrysmAgent) startExitNodeController(ctx context.Context) {
	if a.BackendURL == "" || a.AgentToken == "" {
		log.Printf("Exit node controller: backend URL or agent token not configured, skipping")
		return
	}

	c := &exitNodeController{agent: a}
	go c.reconcileLoop(ctx)
	log.Printf("Exit node controller started")
}

func (c *exitNodeController) reconcileLoop(ctx context.Context) {
	ticker := time.NewTicker(exitNodeReconcileInterval)
	defer ticker.Stop()

	// Initial reconcile
	c.reconcile(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.reconcile(ctx)
		}
	}
}

func (c *exitNodeController) reconcile(ctx context.Context) {
	config, err := c.fetchConfig(ctx)
	if err != nil {
		log.Printf("Exit node controller: failed to fetch config: %v", err)
		return
	}

	c.mu.Lock()
	wasEnabled := c.lastEnabled
	c.mu.Unlock()

	enable := config != nil && config.IsExitRouter

	if wasEnabled != nil && *wasEnabled == enable {
		return
	}

	c.mu.Lock()
	c.lastEnabled = &enable
	c.mu.Unlock()

	if enable {
		if err := c.enableExitNode(config.OverlayCIDR); err != nil {
			log.Printf("Exit node controller: failed to enable exit node: %v", err)
			c.mu.Lock()
			c.lastEnabled = wasEnabled
			c.mu.Unlock()
			return
		}
		log.Printf("Exit node controller: exit node enabled (overlay %s)", config.OverlayCIDR)
	} else {
		if err := c.disableExitNode(); err != nil {
			log.Printf("Exit node controller: failed to disable exit node: %v", err)
		} else {
			log.Printf("Exit node controller: exit node disabled")
		}
	}
}

func (c *exitNodeController) fetchConfig(ctx context.Context) (*agentNetworkConfig, error) {
	url := strings.TrimSuffix(c.agent.BackendURL, "/") + exitNodeConfigPath + "?cluster_id=" + c.agent.ClusterID
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.agent.AgentToken)
	req.Header.Set("X-Agent-Token", c.agent.AgentToken)

	resp, err := c.agent.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("config fetch returned %d: %s", resp.StatusCode, string(body))
	}

	var config agentNetworkConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func (c *exitNodeController) enableExitNode(overlayCIDR string) error {
	if overlayCIDR == "" {
		overlayCIDR = getEnvOrDefault("EXIT_NODE_OVERLAY_CIDR", "100.96.0.0/11")
	}

	if err := c.setIPForwarding(true); err != nil {
		return fmt.Errorf("set IP forwarding: %w", err)
	}
	if err := c.ensureNATRule(overlayCIDR); err != nil {
		return fmt.Errorf("ensure NAT rule: %w", err)
	}
	return nil
}

func (c *exitNodeController) disableExitNode() error {
	c.removeNATRule()
	c.setIPForwarding(false)
	return nil
}

func (c *exitNodeController) setIPForwarding(enable bool) error {
	val := "0"
	if enable {
		val = "1"
	}
	paths := []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv6/conf/all/forwarding",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			continue
		}
		if err := os.WriteFile(p, []byte(val), 0o644); err != nil {
			log.Printf("Exit node: failed to write %s: %v", p, err)
		}
	}
	return nil
}

func (c *exitNodeController) ensureNATRule(overlayCIDR string) error {
	// iptables -t nat -C POSTROUTING -s <cidr> ! -o <wg_iface> -j MASQUERADE
	// If rule exists, -C succeeds; else we add it.
	wgIface := getEnvOrDefault("WIREGUARD_INTERFACE", "wg-prysm")

	checkCmd := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", overlayCIDR, "!", "-o", wgIface, "-j", "MASQUERADE")
	if err := checkCmd.Run(); err == nil {
		return nil
	}

	addCmd := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", overlayCIDR, "!", "-o", wgIface, "-j", "MASQUERADE")
	if out, err := addCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables add: %v: %s", err, string(out))
	}
	return nil
}

func (c *exitNodeController) removeNATRule() {
	overlayCIDR := getEnvOrDefault("EXIT_NODE_OVERLAY_CIDR", "100.96.0.0/11")
	wgIface := getEnvOrDefault("WIREGUARD_INTERFACE", "wg-prysm")

	cmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", overlayCIDR, "!", "-o", wgIface, "-j", "MASQUERADE")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Exit node: iptables delete (may be harmless): %v: %s", err, string(out))
	}
}
