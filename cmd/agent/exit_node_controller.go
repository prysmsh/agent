package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	exitNodeReconcileInterval = 2 * time.Minute
	exitNodeConfigPath        = "/api/v1/agent/network/config"
	exitNodeUpdatePath        = "/api/v1/mesh/nodes/by-device/%s/exit"
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
		if err := c.enableExitNode(ctx, config.OverlayCIDR); err != nil {
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

func (c *exitNodeController) enableExitNode(ctx context.Context, overlayCIDR string) error {
	if overlayCIDR == "" {
		overlayCIDR = getEnvOrDefault("EXIT_NODE_OVERLAY_CIDR", "100.96.0.0/11")
	}

	if err := c.setIPForwarding(true); err != nil {
		return fmt.Errorf("set IP forwarding: %w", err)
	}
	if err := c.ensureNATRule(overlayCIDR); err != nil {
		return fmt.Errorf("ensure NAT rule: %w", err)
	}

	// Discover and report cluster CIDRs to the backend so the CLI subnet
	// router can route them transparently without any manual configuration.
	go c.discoverAndReportCIDRs(ctx)

	return nil
}

// discoverAndReportCIDRs discovers the cluster's service and pod CIDRs from
// the k8s API and reports them to the backend as exit_cidrs for this node.
func (c *exitNodeController) discoverAndReportCIDRs(ctx context.Context) {
	cidrs, err := c.discoverClusterCIDRs(ctx)
	if err != nil {
		log.Printf("Exit node controller: CIDR discovery failed: %v", err)
		return
	}
	if len(cidrs) == 0 {
		log.Printf("Exit node controller: no cluster CIDRs discovered")
		return
	}
	log.Printf("Exit node controller: discovered cluster CIDRs: %v", cidrs)

	if err := c.reportExitCIDRs(ctx, cidrs); err != nil {
		log.Printf("Exit node controller: failed to report exit CIDRs: %v", err)
		return
	}
	log.Printf("Exit node controller: reported exit CIDRs to backend: %v", cidrs)
}

// discoverClusterCIDRs returns the service CIDR and pod CIDRs for this cluster.
// It tries multiple sources in order of reliability.
func (c *exitNodeController) discoverClusterCIDRs(ctx context.Context) ([]string, error) {
	var cidrs []string

	// 1. Service CIDR — try kube-proxy ConfigMap, fall back to kubernetes svc IP.
	if svcCIDR := c.discoverServiceCIDR(ctx); svcCIDR != "" {
		cidrs = append(cidrs, svcCIDR)
	}

	// 2. Pod CIDRs — from node specs.
	podCIDRs := c.discoverPodCIDRs(ctx)
	cidrs = append(cidrs, podCIDRs...)

	return cidrs, nil
}

// discoverServiceCIDR returns the cluster service IP range.
// It checks (in order):
//  1. CLUSTER_SERVICE_CIDR environment variable
//  2. kube-proxy ConfigMap (works on kubeadm/k3s/most distros)
//  3. Deriving a /16 from the kubernetes.default service ClusterIP
func (c *exitNodeController) discoverServiceCIDR(ctx context.Context) string {
	// Env override.
	if cidr := getEnvOrDefault("CLUSTER_SERVICE_CIDR", ""); cidr != "" {
		return cidr
	}

	if c.agent.clientset == nil {
		return ""
	}

	// Try kube-proxy ConfigMap — present on kubeadm, k3s, kind, etc.
	if cidr := c.serviceRangeFromKubeProxy(ctx); cidr != "" {
		return cidr
	}

	// Fall back: infer from the kubernetes.default ClusterIP (always first IP of range).
	return c.serviceRangeFromKubernetesSvc(ctx)
}

func (c *exitNodeController) serviceRangeFromKubeProxy(ctx context.Context) string {
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cm, err := c.agent.clientset.CoreV1().ConfigMaps("kube-system").Get(tctx, "kube-proxy", metav1.GetOptions{})
	if err != nil {
		return ""
	}

	// The ConfigMap may use "config.conf" (kubeadm) or "kube-proxy.conf" (older clusters).
	for _, key := range []string{"config.conf", "kube-proxy.conf"} {
		data, ok := cm.Data[key]
		if !ok {
			continue
		}
		// Look for clusterCIDR: <cidr> in the YAML/JSON config.
		for _, line := range strings.Split(data, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "clusterCIDR:") {
				cidr := strings.TrimSpace(strings.TrimPrefix(line, "clusterCIDR:"))
				cidr = strings.Trim(cidr, "\"'")
				if _, _, err := net.ParseCIDR(cidr); err == nil {
					return cidr
				}
			}
		}
	}
	return ""
}

func (c *exitNodeController) serviceRangeFromKubernetesSvc(ctx context.Context) string {
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	svc, err := c.agent.clientset.CoreV1().Services("default").Get(tctx, "kubernetes", metav1.GetOptions{})
	if err != nil || svc.Spec.ClusterIP == "" {
		return ""
	}

	ip := net.ParseIP(svc.Spec.ClusterIP)
	if ip == nil {
		return ""
	}

	// Assume a /16 covering the first two octets (standard for most distros).
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.0.0/16", ip[0], ip[1])
}

// discoverPodCIDRs returns the pod CIDRs by inspecting node specs.
// It collects all unique pod CIDRs across nodes.
func (c *exitNodeController) discoverPodCIDRs(ctx context.Context) []string {
	if c.agent.clientset == nil {
		return nil
	}

	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	nodes, err := c.agent.clientset.CoreV1().Nodes().List(tctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var cidrs []string
	for _, node := range nodes.Items {
		for _, cidr := range node.Spec.PodCIDRs {
			if cidr != "" && !seen[cidr] {
				seen[cidr] = true
				cidrs = append(cidrs, cidr)
			}
		}
		if node.Spec.PodCIDR != "" && !seen[node.Spec.PodCIDR] {
			seen[node.Spec.PodCIDR] = true
			cidrs = append(cidrs, node.Spec.PodCIDR)
		}
	}
	return cidrs
}

// reportExitCIDRs calls PUT /api/v1/mesh/nodes/by-device/<deviceID>/exit with
// the discovered CIDRs so the backend stores them as advertised_cidrs.
func (c *exitNodeController) reportExitCIDRs(ctx context.Context, cidrs []string) error {
	deviceID := fmt.Sprintf("cluster_%s", c.agent.ClusterID)

	payload := map[string]interface{}{
		"enable":     true,
		"exit_cidrs": cidrs,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := strings.TrimSuffix(c.agent.BackendURL, "/") + fmt.Sprintf(exitNodeUpdatePath, deviceID)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.agent.AgentToken)
	req.Header.Set("X-Agent-Token", c.agent.AgentToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.agent.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("backend returned %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

func (c *exitNodeController) disableExitNode() error {
	c.removeNATRule()
	// NOTE: Do NOT disable ip_forward here. It is a system-wide kernel
	// setting shared with Docker, flannel, and k8s networking. Turning it
	// off breaks all container-to-internet traffic on the node.
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
	wgIface := getEnvOrDefault("WIREGUARD_INTERFACE", "prysm0")

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
	wgIface := getEnvOrDefault("WIREGUARD_INTERFACE", "prysm0")

	cmd := exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", overlayCIDR, "!", "-o", wgIface, "-j", "MASQUERADE")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Exit node: iptables delete (may be harmless): %v: %s", err, string(out))
	}
}
