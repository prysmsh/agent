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
	"time"
)

const (
	wgKeyPath  = "/var/lib/prysm-agent/wg-prysm.key"
	wgPubPath  = "/var/lib/prysm-agent/wg-prysm.pub"
	wgIfacName = "wg-prysm"
)

func shortKey(k string) string {
	if len(k) < 16 {
		return k
	}
	return k[:16]
}

type wgManager struct {
	agent      *PrysmAgent
	nh         *nethelperClient
	privateKey string
	publicKey  string
	overlayIP  string
	listenPort int
	iface      string
	running    bool
}

type wgNetworkConfig struct {
	OverlayCIDR string   `json:"overlay_cidr"`
	ListenPort  int      `json:"listen_port"`
	Peers       []wgPeer `json:"peers"`
}

type wgPeer struct {
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
}

func (a *PrysmAgent) startWireGuard(ctx context.Context) {
	// Always create the nethelper client; we detect availability on
	// the first real call (iface.create) to avoid a TOCTOU race.
	nhc := newNethelperClient()

	// Read existing key pair
	privKeyBytes, err := os.ReadFile(wgKeyPath)
	if err != nil {
		log.Printf("wireguard: failed to read private key %s: %v", wgKeyPath, err)
		return
	}
	pubKeyBytes, err := os.ReadFile(wgPubPath)
	if err != nil {
		log.Printf("wireguard: failed to read public key %s: %v", wgPubPath, err)
		return
	}

	w := &wgManager{
		agent:      a,
		nh:         nhc,
		privateKey: strings.TrimSpace(string(privKeyBytes)),
		publicKey:  strings.TrimSpace(string(pubKeyBytes)),
		iface:      wgIfacName,
	}
	a.wgManager = w

	// Push public key to backend
	if err := w.pushPublicKey(ctx); err != nil {
		log.Printf("wireguard: failed to push public key: %v", err)
		return
	}

	// Fetch network config and bring up interface
	cfg, err := w.fetchNetworkConfig(ctx)
	if err != nil {
		log.Printf("wireguard: failed to fetch network config: %v", err)
		return
	}

	if err := w.createInterface(cfg); err != nil {
		log.Printf("wireguard: failed to create interface: %v", err)
		return
	}

	w.running = true
	log.Printf("wireguard: interface %s up with overlay %s (port %d, %d peers)",
		w.iface, w.overlayIP, w.listenPort, len(cfg.Peers))

	// Start WG-over-DERP bridge for CLI peers
	if a.derpManager != nil && w.listenPort > 0 {
		bridge, err := newWGDERPBridge(a.derpManager, w.listenPort)
		if err != nil {
			log.Printf("wireguard: failed to start DERP bridge: %v", err)
		} else {
			a.derpManager.wgBridge = bridge
			log.Printf("wireguard: DERP bridge active on port %d (bridging to WG port %d)", bridge.BridgePort(), w.listenPort)
			// Add CLI device peers with bridge endpoint
			w.addDERPPeers(cfg, bridge.BridgePort())
		}
	}

	// Reconciliation loop
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("wireguard: context cancelled, tearing down")
			if err := w.stop(); err != nil {
				log.Printf("wireguard: teardown error: %v", err)
			}
			return
		case <-ticker.C:
			updated, err := w.fetchNetworkConfig(ctx)
			if err != nil {
				log.Printf("wireguard: reconcile fetch failed: %v", err)
				continue
			}
			if err := w.reconcilePeers(updated.Peers); err != nil {
				log.Printf("wireguard: reconcile peers failed: %v", err)
			}
		}
	}
}

func (w *wgManager) pushPublicKey(ctx context.Context) error {
	url := w.agent.BackendURL + "/api/v1/agent/network/key"
	payload, _ := json.Marshal(map[string]string{"public_key": w.publicKey})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+w.agent.AgentToken)
	req.Header.Set("X-Cluster-ID", w.agent.ClusterID)

	resp, err := w.agent.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("backend returned %d", resp.StatusCode)
	}
	log.Printf("wireguard: pushed public key to backend")
	return nil
}

func (w *wgManager) fetchNetworkConfig(ctx context.Context) (*wgNetworkConfig, error) {
	url := w.agent.BackendURL + "/api/v1/agent/network/config"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+w.agent.AgentToken)
	req.Header.Set("X-Cluster-ID", w.agent.ClusterID)

	resp, err := w.agent.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("backend returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var cfg wgNetworkConfig
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return &cfg, nil
}

func (w *wgManager) createInterface(cfg *wgNetworkConfig) error {
	w.overlayIP = cfg.OverlayCIDR
	w.listenPort = cfg.ListenPort

	// Try nethelper first; fall back to direct execution on connection error.
	if w.nh != nil {
		err := w.nh.ifaceCreate(w.listenPort, wgKeyPath)
		if err != nil && strings.Contains(err.Error(), "connect to nethelper") {
			log.Printf("wireguard: nethelper not reachable, falling back to direct execution")
			w.nh = nil
		} else if err != nil {
			return fmt.Errorf("nethelper iface.create: %w", err)
		}
	}

	if w.nh != nil {
		log.Printf("wireguard: using nethelper daemon for privileged operations")
		if err := w.nh.ifaceAddAddr(w.overlayIP); err != nil {
			_ = w.nh.ifaceDelete()
			return fmt.Errorf("nethelper iface.addAddr: %w", err)
		}
		if err := w.nh.ifaceSetUp(); err != nil {
			_ = w.nh.ifaceDelete()
			return fmt.Errorf("nethelper iface.setUp: %w", err)
		}
	} else {
		// Direct execution fallback
		if _, err := exec.LookPath("wg"); err != nil {
			return fmt.Errorf("wg command not found: %w", err)
		}
		if _, err := exec.LookPath("ip"); err != nil {
			return fmt.Errorf("ip command not found: %w", err)
		}

		_ = runCmd("ip", "link", "del", w.iface)

		if err := runCmd("ip", "link", "add", w.iface, "type", "wireguard"); err != nil {
			if strings.Contains(err.Error(), "RTNETLINK") || strings.Contains(err.Error(), "not supported") ||
				strings.Contains(err.Error(), "No such file") || strings.Contains(err.Error(), "Operation not permitted") {
				return fmt.Errorf("wireguard kernel module not available: %w", err)
			}
			return fmt.Errorf("ip link add: %w", err)
		}

		if err := runCmd("wg", "set", w.iface,
			"private-key", wgKeyPath,
			"listen-port", fmt.Sprintf("%d", w.listenPort),
		); err != nil {
			_ = runCmd("ip", "link", "del", w.iface)
			return fmt.Errorf("wg set: %w", err)
		}

		if err := runCmd("ip", "addr", "add", w.overlayIP, "dev", w.iface); err != nil {
			_ = runCmd("ip", "link", "del", w.iface)
			return fmt.Errorf("ip addr add: %w", err)
		}

		if err := runCmd("ip", "link", "set", w.iface, "up"); err != nil {
			_ = runCmd("ip", "link", "del", w.iface)
			return fmt.Errorf("ip link set up: %w", err)
		}
	}

	// Add initial peers
	for _, p := range cfg.Peers {
		if err := w.addPeer(p.PublicKey, p.Endpoint, p.AllowedIPs); err != nil {
			log.Printf("wireguard: failed to add peer %s: %v", shortKey(p.PublicKey), err)
		}
	}

	return nil
}

func (w *wgManager) addPeer(pubKey, endpoint string, allowedIPs []string) error {
	if w.nh != nil {
		if err := w.nh.peerSet(pubKey, endpoint, allowedIPs); err != nil {
			return fmt.Errorf("nethelper peer.set: %w", err)
		}
	} else {
		args := []string{"set", w.iface, "peer", pubKey,
			"allowed-ips", strings.Join(allowedIPs, ","),
		}
		if endpoint != "" {
			args = append(args, "endpoint", endpoint)
		}
		if err := runCmd("wg", args...); err != nil {
			return fmt.Errorf("wg set peer: %w", err)
		}
	}

	log.Printf("wireguard: added peer %s endpoint=%s allowed=%s",
		shortKey(pubKey), endpoint, strings.Join(allowedIPs, ","))
	return nil
}

func (w *wgManager) reconcilePeers(peers []wgPeer) error {
	for _, p := range peers {
		if err := w.addPeer(p.PublicKey, p.Endpoint, p.AllowedIPs); err != nil {
			log.Printf("wireguard: reconcile peer %s failed: %v", shortKey(p.PublicKey), err)
		}
	}
	return nil
}

// addDERPPeers adds CLI device peers that use the DERP bridge as their endpoint.
// These peers have an "endpoint" field in the config that is a device ID (not host:port).
func (w *wgManager) addDERPPeers(cfg *wgNetworkConfig, bridgePort int) {
	for _, p := range cfg.Peers {
		// CLI device peers have an "endpoint" that looks like a device ID (no colon = not host:port)
		if p.Endpoint == "" || strings.Contains(p.Endpoint, ":") {
			continue // skip cluster peers with host:port endpoints
		}
		// This is a DERP-transported peer — use the bridge as its endpoint
		bridgeEndpoint := fmt.Sprintf("127.0.0.1:%d", bridgePort)
		if err := w.addPeer(p.PublicKey, bridgeEndpoint, p.AllowedIPs); err != nil {
			log.Printf("wireguard: add DERP peer %s failed: %v", shortKey(p.PublicKey), err)
		} else {
			log.Printf("wireguard: added DERP peer %s via bridge port %d", shortKey(p.PublicKey), bridgePort)
		}
	}
}

func (w *wgManager) stop() error {
	if !w.running {
		return nil
	}
	w.running = false
	log.Printf("wireguard: removing interface %s", w.iface)

	if w.nh != nil {
		return w.nh.ifaceDelete()
	}
	return runCmd("ip", "link", "del", w.iface)
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
