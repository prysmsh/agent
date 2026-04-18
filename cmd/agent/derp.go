package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prysmsh/pkg/channel"
	"github.com/prysmsh/pkg/keystore"
	"github.com/prysmsh/pkg/pqc"
	"github.com/prysmsh/pkg/pqc/sign"
	"github.com/prysmsh/pkg/tlsutil"
	"golang.org/x/crypto/curve25519"
)

// K8s API port for DERP tunnel (cluster proxy uses this to identify K8s API routes)
const derpK8sAPIPort = 6443

// Agent HTTP server port for tool execution via DERP
const agentHTTPPort = 8080

// In-cluster K8s API host (agent runs in cluster)
const k8sAPIHost = "kubernetes.default.svc.cluster.local"
const k8sAPIPort = "443"

// inClusterCAPath is the mounted service account CA used to verify the in-cluster API server.
const inClusterCAPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

// loadInClusterCAPool reads the in-cluster CA and returns a CertPool for TLS verification.
// Returns nil if the file is missing or invalid (e.g. not running in-cluster).
func loadInClusterCAPool(path string) *x509.CertPool {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil
	}
	return pool
}

// isInClusterK8sAddr returns true if addr is the in-cluster API server (host:port).
// Matches both DNS names and the KUBERNETES_SERVICE_HOST IP injected by kubelet.
func isInClusterK8sAddr(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if port != "443" && port != k8sAPIPort {
		return false
	}
	if host == k8sAPIHost || host == "kubernetes.default.svc" || host == "kubernetes" {
		return true
	}
	// When KUBERNETES_SERVICE_HOST is set, the addr was overridden to the service IP.
	if kubeHost := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST")); kubeHost != "" && host == kubeHost {
		return true
	}
	return false
}

type derpManager struct {
	agent           *PrysmAgent
	servers         []string
	region          string
	clientID        string
	publicKey       string
	hybridPublicKey string // base64 X25519+Kyber768 for quantum-resistant relay
	hybridKeyPair   *pqc.HybridKeyPair
	signingKeyPair  *sign.HybridSigningKeyPair
	keyStore        *keystore.Store
	skipVerify      bool
	stateDir        string
	ifaceName       string
	k8sAPIAddr      string // host:port for K8s API (from KUBECONFIG_APISERVER when outside cluster)
	k8sCACertPool   *x509.CertPool // CA pool for verifying the K8s API server certificate
	connMu          sync.RWMutex
	conn            *websocket.Conn
	currentServer   string
	writeMu         sync.Mutex
	nextIndex       int
	// Route state for K8s API tunneling (routeID -> k8sConn)
	routeConns      map[string]net.Conn
	routeSources    map[string]string              // routeID -> source client ID for traffic_data replies
	routeCiphers    map[string][32]byte            // routeID -> shared secret for E2E encryption (legacy X25519)
	routeHandshakes map[string]*channel.Handshake  // routeID -> pending channel handshake
	routeSessions   map[string]*channel.Session    // routeID -> established channel session
	routeMu         sync.RWMutex

	// Mesh routes cache: external_port -> local service; slug -> local service (for exit target_address <route-name>:port or derp.<cluster>:port)
	meshRoutesMu       sync.RWMutex
	meshRoutesCache    map[int]struct{ ServiceName string; ServicePort int }
	meshRouteSlugCache map[string]struct{ ServiceName string; ServicePort int }
	meshRoutesAt       time.Time
}

type derpMessage struct {
	Type      string          `json:"type"`
	From      string          `json:"from,omitempty"`
	To        string          `json:"to,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Encrypted bool            `json:"encrypted,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

func (a *PrysmAgent) startDERP(ctx context.Context) error {
	manager, err := newDERPManager(a)
	if err != nil {
		return err
	}

	a.derpManager = manager
	go manager.run(ctx)
	log.Printf("DERP connectivity enabled with %d relay candidate(s)", len(manager.servers))
	return nil
}

func newDERPManager(agent *PrysmAgent) (*derpManager, error) {
	if len(agent.derpServers) == 0 {
		return nil, fmt.Errorf("no DERP servers configured")
	}

	stateDir := strings.TrimSpace(getEnvOrDefault("WIREGUARD_STATE_DIR", "/var/lib/prysm-agent"))
	if stateDir == "" {
		stateDir = "/var/lib/prysm-agent"
	}

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("ensure state directory: %w", err)
	}

	iface := strings.TrimSpace(getEnvOrDefault("WIREGUARD_INTERFACE", "wg-prysm"))
	privPath := filepath.Join(stateDir, iface+".key")
	pubPath := filepath.Join(stateDir, iface+".pub")
	_, pubKey, err := ensureKeyPair(privPath, pubPath)
	if err != nil {
		return nil, fmt.Errorf("ensure WireGuard keys: %w", err)
	}

	clientID, err := ensureDERPClientID(stateDir, agent.ClusterID)
	if err != nil {
		return nil, fmt.Errorf("ensure DERP client id: %w", err)
	}

	ks, err := ensureKeyStore(stateDir, agent.AgentToken)
	if err != nil {
		return nil, fmt.Errorf("ensure keystore: %w", err)
	}

	hybridKP, err := ks.KEMKey("derp-kem")
	if err != nil {
		return nil, fmt.Errorf("load KEM key from keystore: %w", err)
	}
	pubBytes, err := hybridKP.PublicKey().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal hybrid public key: %w", err)
	}
	hybridPubB64 := base64.StdEncoding.EncodeToString(pubBytes)

	signingKP, err := ks.SigningKey("derp-sign")
	if err != nil {
		return nil, fmt.Errorf("load signing key from keystore: %w", err)
	}

	servers := make([]string, 0, len(agent.derpServers))
	for _, s := range agent.derpServers {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			servers = append(servers, trimmed)
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no valid DERP servers found after trimming")
	}

	k8sAPIAddr := net.JoinHostPort(k8sAPIHost, k8sAPIPort)
	if apiURL := strings.TrimSpace(getEnvOrDefault("KUBECONFIG_APISERVER", "")); apiURL != "" {
		if u, err := url.Parse(apiURL); err == nil && u.Hostname() != "" {
			if u.Port() != "" {
				k8sAPIAddr = u.Host
			} else {
				k8sAPIAddr = net.JoinHostPort(u.Hostname(), strconv.Itoa(derpK8sAPIPort))
			}
		}
	}
	// In-cluster: use KUBERNETES_SERVICE_HOST:PORT so we don't need DNS (hostNetwork pods often can't resolve kubernetes.default.svc)
	if kubeHost := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST")); kubeHost != "" {
		kubePort := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
		if kubePort == "" {
			kubePort = k8sAPIPort
		}
		k8sAPIAddr = net.JoinHostPort(kubeHost, kubePort)
	}

	// Load K8s CA from kubeconfig for TLS verification of the API server.
	var k8sCACertPool *x509.CertPool
	if kubeConfig, err := agent.loadKubeConfig(); err == nil {
		if len(kubeConfig.TLSClientConfig.CAData) > 0 {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(kubeConfig.TLSClientConfig.CAData) {
				k8sCACertPool = pool
			}
		} else if kubeConfig.TLSClientConfig.CAFile != "" {
			if data, err := os.ReadFile(kubeConfig.TLSClientConfig.CAFile); err == nil {
				pool := x509.NewCertPool()
				if pool.AppendCertsFromPEM(data) {
					k8sCACertPool = pool
				}
			}
		}
	}

	return &derpManager{
		agent:           agent,
		servers:         servers,
		region:          agent.derpRegion,
		clientID:        clientID,
		publicKey:       pubKey,
		hybridPublicKey: hybridPubB64,
		hybridKeyPair:   hybridKP,
		signingKeyPair:  signingKP,
		keyStore:        ks,
		skipVerify:      agent.derpSkipVerify,
		stateDir:        stateDir,
		ifaceName:       iface,
		k8sAPIAddr:      k8sAPIAddr,
		k8sCACertPool:   k8sCACertPool,
		routeConns:      make(map[string]net.Conn),
		routeSources:    make(map[string]string),
		routeCiphers:    make(map[string][32]byte),
		routeHandshakes: make(map[string]*channel.Handshake),
		routeSessions:   make(map[string]*channel.Session),
	}, nil
}

func (m *derpManager) run(ctx context.Context) {
	backoff := 5 * time.Second

	for {
		if ctx.Err() != nil {
			m.closeConnection()
			return
		}

		if err := m.connectAndServe(ctx); err != nil && ctx.Err() == nil {
			log.Printf("DERP connection error: %v", err)
		}

		select {
		case <-ctx.Done():
			m.closeConnection()
			return
		case <-time.After(backoff):
		}

		if backoff < 60*time.Second {
			backoff += 5 * time.Second
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
		}
	}
}

func (m *derpManager) connectAndServe(ctx context.Context) error {
	var lastErr error

	for i := 0; i < len(m.servers); i++ {
		endpoint := m.nextEndpoint()
		if endpoint == "" {
			continue
		}

		if err := m.dialAndRun(ctx, endpoint); err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("DERP dial attempt failed for %s: %v", endpoint, err)
			continue
		}

		// Successful run; reset backoff and continue loop to allow reconnection if needed
		return nil
	}

	if lastErr == nil {
		return fmt.Errorf("no DERP endpoints available")
	}
	return lastErr
}

func (m *derpManager) dialAndRun(ctx context.Context, endpoint string) error {
	dialer := websocket.Dialer{
		Proxy:             http.ProxyFromEnvironment,
		HandshakeTimeout:  10 * time.Second,
		EnableCompression: false, // Disable to avoid compatibility issues with relay
	}

	if strings.HasPrefix(strings.ToLower(endpoint), "wss://") {
		dialer.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		tlsutil.ApplyPQCConfig(dialer.TLSClientConfig)
		if m.skipVerify {
			// #nosec G402
			dialer.TLSClientConfig.InsecureSkipVerify = true
		}
	}

	headers := http.Header{}
	headers.Set("User-Agent", "prysm-agent/derp")
	if m.agent.ClusterID != "" {
		headers.Set("X-Cluster-ID", m.agent.ClusterID)
	}
	if m.agent.AgentToken != "" {
		headers.Set("X-Agent-Token", m.agent.AgentToken)
	}

	conn, _, err := dialer.DialContext(ctx, endpoint, headers)
	if err != nil {
		return err
	}
	defer conn.Close()

	m.setConnection(conn, endpoint)
	defer m.clearConnection()

	defer func() {
		m.writeMu.Lock()
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(2*time.Second))
		m.writeMu.Unlock()
	}()

	// Set up WebSocket-level keepalive so the relay's read-deadline is
	// always extended. The relay expects a pong within 60 s; we use 90 s
	// on the client side to be more tolerant.
	const pongWait = 90 * time.Second
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	if err := m.sendRegister(conn); err != nil {
		return fmt.Errorf("send register: %w", err)
	}

	return m.serveConnection(ctx, conn)
}

func (m *derpManager) serveConnection(ctx context.Context, conn *websocket.Conn) error {
	log.Printf("DERP connected to %s as %s", m.currentServer, m.clientID)

	errCh := make(chan error, 1)
	registeredCh := make(chan struct{}, 1)

	go m.readLoop(conn, errCh, registeredCh)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	case <-registeredCh:
	case <-time.After(15 * time.Second):
		return fmt.Errorf("timeout waiting for DERP registration acknowledgement")
	}

	// Pre-warm mesh routes cache so first exit route doesn't wait on backend fetch.
	go func() {
		_ = m.resolveMeshRoutePort(0)
	}()

	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	discoveryTicker := time.NewTicker(5 * time.Minute)
	defer discoveryTicker.Stop()

	if err := m.sendDiscovery(conn); err != nil {
		log.Printf("DERP discovery request failed: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		case <-heartbeatTicker.C:
			// Send WebSocket-level ping so the relay resets its
			// read-deadline via the pong we'll receive back.
			m.writeMu.Lock()
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			pingErr := conn.WriteMessage(websocket.PingMessage, nil)
			m.writeMu.Unlock()
			if pingErr != nil {
				return fmt.Errorf("websocket ping: %w", pingErr)
			}
			if err := m.sendHeartbeat(conn); err != nil {
				return err
			}
		case <-discoveryTicker.C:
			if err := m.sendDiscovery(conn); err != nil {
				log.Printf("DERP discovery refresh failed: %v", err)
			}
		}
	}
}

func (m *derpManager) readLoop(conn *websocket.Conn, errCh chan<- error, registeredCh chan<- struct{}) {
	for {
		var msg derpMessage
		if err := conn.ReadJSON(&msg); err != nil {
			errCh <- err
			return
		}

		if msg.Type == "registered" {
			select {
			case registeredCh <- struct{}{}:
			default:
			}
		}

		m.handleMessage(&msg)
	}
}

func (m *derpManager) handleMessage(msg *derpMessage) {
	switch msg.Type {
	case "welcome":
		log.Printf("DERP welcome: %s", strings.TrimSpace(string(msg.Data)))
	case "registered":
		log.Printf("DERP registration confirmed by %s", m.currentServer)
	case "heartbeat_ack":
		// No-op; successful heartbeat
	case "discovery_response":
		var payload struct {
			Peers []map[string]interface{} `json:"peers"`
		}
		if err := json.Unmarshal(msg.Data, &payload); err != nil {
			log.Printf("DERP discovery response decode error: %v", err)
			return
		}
		log.Printf("DERP discovery: %d peer(s) available in cluster %s", len(payload.Peers), m.agent.ClusterID)
	case "error":
		log.Printf("DERP error from server: %s", strings.TrimSpace(string(msg.Data)))
		// If a route was closed, tear down the K8s connection to stop forwarding
		var errPayload struct {
			Error   string `json:"error"`
			RouteID string `json:"route_id"`
		}
		if json.Unmarshal(msg.Data, &errPayload) == nil && errPayload.RouteID != "" && errPayload.Error == "route_not_found" {
			m.routeMu.Lock()
			if conn := m.routeConns[errPayload.RouteID]; conn != nil {
				conn.Close()
				delete(m.routeConns, errPayload.RouteID)
				delete(m.routeSources, errPayload.RouteID)
				delete(m.routeCiphers, errPayload.RouteID)
				delete(m.routeHandshakes, errPayload.RouteID)
				delete(m.routeSessions, errPayload.RouteID)
			}
			m.routeMu.Unlock()
		}
	case "route_setup":
		m.handleRouteSetup(msg)
	case "traffic_data":
		m.handleTrafficData(msg)
	case "ping":
		m.handlePing(msg)
	case "cross_cluster_setup":
		if m.agent.ccRouteManager != nil {
			m.agent.ccRouteManager.handleCrossClusterSetup(msg)
		}
	case "cross_cluster_data":
		if m.agent.ccRouteManager != nil {
			m.agent.ccRouteManager.handleCrossClusterData(msg)
		}
	case "cross_cluster_close":
		if m.agent.ccRouteManager != nil {
			m.agent.ccRouteManager.handleCrossClusterClose(msg)
		}
	default:
		log.Printf("DERP message type=%s size=%d bytes", msg.Type, len(msg.Data))
	}
}

func (m *derpManager) handleRouteSetup(msg *derpMessage) {
	var payload struct {
		RouteID                string `json:"route_id"`
		TargetPort             int    `json:"target_port"`
		ExternalPort           int    `json:"external_port"`
		OrganizationID         string `json:"organization_id"`
		BackendEphemeralPubkey string `json:"backend_ephemeral_pubkey,omitempty"`
		HandshakeMsg           string `json:"handshake_msg,omitempty"` // channel handshake msg1 (base64)
		RouteType              string `json:"route_type,omitempty"`
		TargetAddress          string `json:"target_address,omitempty"`
	}
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		log.Printf("DERP route_setup parse error: %v", err)
		m.sendRouteResponse(msg.From, "", "failed", "invalid payload", "")
		return
	}

	var conn net.Conn
	var dialErr error

	if payload.RouteType == "exit" {
		// Exit route: target_address is "<route-slug>.<cluster-slug>.mesh:<port>" or a literal host:port.
		if payload.TargetAddress == "" {
			log.Printf("DERP route_setup: exit route missing target_address")
			m.sendRouteResponse(msg.From, payload.RouteID, "failed", "target_address required for exit route", "")
			return
		}
		dialAddr := payload.TargetAddress
		isMeshRoute := false
		if host, _, err := net.SplitHostPort(payload.TargetAddress); err == nil {
			if strings.HasSuffix(host, ".mesh") {
				isMeshRoute = true
				// <route-slug>.<cluster-slug>.mesh:<port> — resolve by route slug (first segment)
				parts := strings.Split(strings.TrimSuffix(host, ".mesh"), ".")
				if len(parts) >= 1 && parts[0] != "" {
					if svcAddr := m.resolveMeshRouteBySlug(parts[0]); svcAddr != "" {
						dialAddr = svcAddr
						log.Printf("DERP route_setup: exit route %s -> mesh route slug %s -> %s", payload.TargetAddress, parts[0], dialAddr)
					}
				}
			}
		}
		// If this is a .mesh route but we didn't resolve to a service, don't dial the literal hostname (DNS will fail).
		// Fail fast with a clear error so the client gets "mesh route not found" instead of "no such host".
		if isMeshRoute && dialAddr == payload.TargetAddress {
			log.Printf("DERP route_setup: mesh route %s not found (backend unreachable or slug not configured)", payload.TargetAddress)
			m.sendRouteResponse(msg.From, payload.RouteID, "failed", "mesh route not found; check backend connectivity and route config", "")
			return
		}
		log.Printf("DERP route_setup: exit route to %s", dialAddr)
		conn, dialErr = net.DialTimeout("tcp", dialAddr, 10*time.Second)
		if dialErr != nil {
			log.Printf("DERP route_setup: failed to dial exit target %s: %v", dialAddr, dialErr)
			m.sendRouteResponse(msg.From, payload.RouteID, "failed", dialErr.Error(), "")
			return
		}
	} else if payload.TargetPort == agentHTTPPort {
		// Agent HTTP route: route to the agent's own HTTP server for tool execution.
		log.Printf("DERP route_setup: routing to agent HTTP server (port %d)", agentHTTPPort)
		conn, dialErr = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", agentHTTPPort), 10*time.Second)
		if dialErr != nil {
			log.Printf("DERP route_setup: failed to dial agent HTTP %v: %v", agentHTTPPort, dialErr)
			m.sendRouteResponse(msg.From, payload.RouteID, "failed", dialErr.Error(), "")
			return
		}
	} else {
		// K8s API route: only handle port 6443.
		if payload.TargetPort != derpK8sAPIPort {
			log.Printf("DERP route_setup: ignoring non-K8s port %d", payload.TargetPort)
			m.sendRouteResponse(msg.From, payload.RouteID, "failed", "unsupported target port", "")
			return
		}
		addr := m.k8sAPIAddr
		host, _, _ := net.SplitHostPort(addr)
		tlsCfg := &tls.Config{}
		// Allow skipping TLS verification for K8s API (e.g. local k3s/minikube with self-signed certs).
		skipK8sVerify := os.Getenv("K8S_API_SKIP_TLS_VERIFY") == "true" || os.Getenv("K8S_API_SKIP_TLS_VERIFY") == "1"
		if skipK8sVerify {
			tlsCfg.InsecureSkipVerify = true
		} else if isInClusterK8sAddr(addr) {
			tlsCfg.ServerName = "kubernetes"
			if pool := loadInClusterCAPool(inClusterCAPath); pool != nil {
				tlsCfg.RootCAs = pool
			} else if m.k8sCACertPool != nil {
				tlsCfg.RootCAs = m.k8sCACertPool
			} else {
				tlsCfg.InsecureSkipVerify = true
			}
		} else {
			// External K8s API: use actual hostname and cluster CA from kubeconfig.
			tlsCfg.ServerName = host
			if m.k8sCACertPool != nil {
				tlsCfg.RootCAs = m.k8sCACertPool
			} else {
				tlsCfg.InsecureSkipVerify = true
			}
		}
		tlsutil.ApplyPQCConfig(tlsCfg)
		conn, dialErr = tls.Dial("tcp", addr, tlsCfg)
		if dialErr != nil {
			log.Printf("DERP route_setup: failed to dial K8s API %s: %v", addr, dialErr)
			m.sendRouteResponse(msg.From, payload.RouteID, "failed", dialErr.Error(), "")
			return
		}
	}

	// E2E encryption: prefer channel handshake (authenticated hybrid KEM),
	// fall back to legacy X25519 ECDH for backwards compat with old backends.
	var agentPubKeyB64 string
	var handshakeRespB64 string

	if payload.HandshakeMsg != "" && m.signingKeyPair != nil {
		// New path: authenticated channel handshake.
		msg1Bytes, err := base64.StdEncoding.DecodeString(payload.HandshakeMsg)
		if err != nil {
			log.Printf("DERP E2E: invalid handshake_msg base64: %v", err)
			m.sendRouteResponse(msg.From, payload.RouteID, "failed", "invalid handshake_msg", "")
			conn.Close()
			return
		}
		hs, err := channel.NewResponder(m.signingKeyPair)
		if err != nil {
			log.Printf("DERP E2E: failed to create responder: %v", err)
			m.sendRouteResponse(msg.From, payload.RouteID, "failed", "handshake init failed", "")
			conn.Close()
			return
		}
		if _, err := hs.ReadMessage(msg1Bytes); err != nil {
			log.Printf("DERP E2E: failed to read handshake msg1: %v", err)
			m.sendRouteResponse(msg.From, payload.RouteID, "failed", "handshake msg1 failed", "")
			conn.Close()
			return
		}
		msg2Bytes, err := hs.WriteMessage(nil)
		if err != nil {
			log.Printf("DERP E2E: failed to write handshake msg2: %v", err)
			m.sendRouteResponse(msg.From, payload.RouteID, "failed", "handshake msg2 failed", "")
			conn.Close()
			return
		}
		handshakeRespB64 = base64.StdEncoding.EncodeToString(msg2Bytes)

		// Store pending handshake (waiting for msg3 via traffic_data).
		m.routeMu.Lock()
		m.routeHandshakes[payload.RouteID] = hs
		m.routeMu.Unlock()
		log.Printf("DERP E2E: channel handshake started for route %s (awaiting msg3)", payload.RouteID)
	} else if payload.BackendEphemeralPubkey != "" {
		// Legacy path: X25519 ECDH (unauthenticated).
		backendPubBytes, err := base64.StdEncoding.DecodeString(payload.BackendEphemeralPubkey)
		if err == nil && len(backendPubBytes) == 32 {
			var agentPriv, agentPub [32]byte
			if _, err := rand.Read(agentPriv[:]); err == nil {
				curve25519.ScalarBaseMult(&agentPub, &agentPriv)
				agentPubKeyB64 = base64.StdEncoding.EncodeToString(agentPub[:])
				var backendPub [32]byte
				copy(backendPub[:], backendPubBytes)
				var sharedSecret [32]byte
				curve25519.ScalarMult(&sharedSecret, &agentPriv, &backendPub)
				m.routeMu.Lock()
				m.routeCiphers[payload.RouteID] = sharedSecret
				m.routeMu.Unlock()
			} else {
				log.Printf("DERP E2E WARNING: failed to generate ephemeral key: %v", err)
			}
		} else {
			log.Printf("DERP E2E WARNING: invalid backend ephemeral pubkey")
		}
	} else {
		log.Printf("DERP E2E WARNING: backend did not provide handshake or ephemeral pubkey (old backend?)")
	}

	m.routeMu.Lock()
	m.routeConns[payload.RouteID] = conn
	m.routeSources[payload.RouteID] = msg.From
	m.routeMu.Unlock()
	m.sendRouteResponseFull(msg.From, payload.RouteID, "ok", "", agentPubKeyB64, handshakeRespB64)
	go m.forwardFromK8s(payload.RouteID, conn)
}

func (m *derpManager) forwardFromK8s(routeID string, conn net.Conn) {
	defer func() {
		conn.Close()
		m.routeMu.Lock()
		delete(m.routeConns, routeID)
		delete(m.routeSources, routeID)
		delete(m.routeCiphers, routeID)
		delete(m.routeHandshakes, routeID)
		delete(m.routeSessions, routeID)
		m.routeMu.Unlock()
	}()
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if err := m.sendTrafficData(routeID, buf[:n]); err != nil {
				log.Printf("DERP forwardFromK8s: send error: %v", err)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("DERP forwardFromK8s: read error: %v", err)
			}
			return
		}
	}
}

func (m *derpManager) handleTrafficData(msg *derpMessage) {
	var payload struct {
		RouteID   string `json:"route_id"`
		Data      []byte `json:"data"`
		Handshake bool   `json:"handshake,omitempty"` // true if this is handshake msg3
	}
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		log.Printf("DERP traffic_data parse error: %v", err)
		return
	}

	// Check if this is a channel handshake msg3 (completes the handshake).
	m.routeMu.RLock()
	hs := m.routeHandshakes[payload.RouteID]
	m.routeMu.RUnlock()

	if hs != nil && payload.Handshake {
		if _, err := hs.ReadMessage(payload.Data); err != nil {
			log.Printf("DERP E2E: handshake msg3 failed for route %s: %v", payload.RouteID, err)
			return
		}
		session := hs.Session()
		if session == nil {
			log.Printf("DERP E2E: handshake complete but no session for route %s", payload.RouteID)
			return
		}
		m.routeMu.Lock()
		m.routeSessions[payload.RouteID] = session
		delete(m.routeHandshakes, payload.RouteID)
		m.routeMu.Unlock()
		log.Printf("DERP E2E: channel session established for route %s", payload.RouteID)
		return
	}

	m.routeMu.RLock()
	conn := m.routeConns[payload.RouteID]
	session := m.routeSessions[payload.RouteID]
	key := m.routeCiphers[payload.RouteID]
	m.routeMu.RUnlock()
	if conn == nil {
		return
	}

	data := payload.Data

	// Decrypt: prefer channel session, fall back to legacy X25519.
	if session != nil {
		decrypted, err := session.Decrypt(data)
		if err != nil {
			log.Printf("DERP traffic_data session decrypt error for route %s: %v", payload.RouteID, err)
			return
		}
		data = decrypted
	} else if key != [32]byte{} && len(data) > pqc.NonceSize {
		decrypted, err := pqc.DecryptPayload(key, data)
		if err != nil {
			log.Printf("DERP traffic_data decrypt error for route %s: %v", payload.RouteID, err)
			return
		}
		data = decrypted
	}

	if _, err := conn.Write(data); err != nil {
		log.Printf("DERP traffic_data: write to K8s conn error: %v", err)
		conn.Close()
		m.routeMu.Lock()
		delete(m.routeConns, payload.RouteID)
		delete(m.routeSources, payload.RouteID)
		delete(m.routeCiphers, payload.RouteID)
		delete(m.routeHandshakes, payload.RouteID)
		delete(m.routeSessions, payload.RouteID)
		m.routeMu.Unlock()
	}
}

func (m *derpManager) handlePing(msg *derpMessage) {
	var payload struct {
		RequestID    string `json:"request_id"`
		SourceClient string `json:"source_client"`
	}
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		log.Printf("DERP ping parse error: %v", err)
		return
	}
	to := strings.TrimSpace(payload.SourceClient)
	if to == "" {
		to = msg.From
	}
	clusterName := m.agent.ClusterName
	if clusterName == "" {
		clusterName = fmt.Sprintf("Cluster %s", m.agent.ClusterID)
	}
	data := map[string]interface{}{
		"request_id":   payload.RequestID,
		"status":       "ok",
		"cluster_id":   m.agent.ClusterID,
		"cluster_name": clusterName,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
	}
	payloadBytes, _ := json.Marshal(data)
	resp := derpMessage{Type: "ping_response", From: m.clientID, To: to, Data: payloadBytes}
	m.connMu.RLock()
	conn := m.conn
	m.connMu.RUnlock()
	if conn != nil {
		_ = m.writeMessage(conn, resp)
	}
}

func (m *derpManager) sendRouteResponse(to, routeID, status, errDetail, agentEphemeralPubkey string) {
	m.sendRouteResponseFull(to, routeID, status, errDetail, agentEphemeralPubkey, "")
}

func (m *derpManager) sendRouteResponseFull(to, routeID, status, errDetail, agentEphemeralPubkey, handshakeMsg string) {
	data := map[string]string{"route_id": routeID, "status": status}
	if errDetail != "" {
		data["error"] = errDetail
	}
	if agentEphemeralPubkey != "" {
		data["agent_ephemeral_pubkey"] = agentEphemeralPubkey
	}
	if handshakeMsg != "" {
		data["handshake_msg"] = handshakeMsg
	}
	payload, _ := json.Marshal(data)
	msg := derpMessage{Type: "route_response", From: m.clientID, To: to, Data: payload}
	m.connMu.RLock()
	conn := m.conn
	m.connMu.RUnlock()
	if conn != nil {
		_ = m.writeMessage(conn, msg)
	}
}

// resolveMeshRoutePort returns the local dial address (service.namespace.svc.cluster.local:port)
// for the given external port, by fetching mesh routes from the backend. Empty string if not found.
// Uses a longer timeout and retries to cope with slow or flaky backend connectivity from the cluster.
func (m *derpManager) resolveMeshRoutePort(externalPort int) string {
	const cacheExpiry = 2 * time.Minute
	m.meshRoutesMu.RLock()
	if time.Since(m.meshRoutesAt) < cacheExpiry && len(m.meshRoutesCache) > 0 {
		e, ok := m.meshRoutesCache[externalPort]
		m.meshRoutesMu.RUnlock()
		if ok {
			return fmt.Sprintf("%s.default.svc.cluster.local:%d", e.ServiceName, e.ServicePort)
		}
		// Cache miss can happen right after a new route is created; refresh before failing.
	} else {
		m.meshRoutesMu.RUnlock()
	}

	base := strings.TrimSuffix(m.agent.BackendURL, "/")
	if base == "" || m.agent.ClusterID == "" || m.agent.AgentToken == "" {
		return ""
	}
	url := fmt.Sprintf("%s/api/v1/agent/mesh-routes/clusters/%s", base, m.agent.ClusterID)
	// Dedicated client with longer timeout (60s) for mesh-routes; cluster egress can be slow.
	meshRoutesClient := &http.Client{Timeout: 60 * time.Second}
	const maxAttempts = 3
	const backoff = 2 * time.Second
	var resp *http.Response
	for attempt := 0; attempt < maxAttempts; attempt++ {
			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				return ""
			}
			req.Header.Set("X-Agent-Token", m.agent.AgentToken)
			req.Header.Set("X-Cluster-ID", m.agent.ClusterID)
			resp, err = meshRoutesClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		if resp != nil {
			resp.Body.Close()
			resp = nil
		}
		if attempt < maxAttempts-1 {
			if err != nil {
				log.Printf("DERP mesh-routes: fetch attempt %d failed: %v; retrying in %v", attempt+1, err, backoff)
			} else {
				log.Printf("DERP mesh-routes: fetch attempt %d returned non-200; retrying in %v", attempt+1, backoff)
			}
			time.Sleep(backoff)
		} else if err != nil {
			log.Printf("DERP mesh-routes: fetch failed after %d attempts: %v", maxAttempts, err)
			return ""
		}
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			log.Printf("DERP mesh-routes: fetch failed with status=%d body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return ""
	}
	defer resp.Body.Close()

	var out struct {
		Routes []struct {
			ExternalPort int    `json:"external_port"`
			ServiceName  string `json:"service_name"`
			ServicePort  int    `json:"service_port"`
			Slug         string `json:"slug"`
		} `json:"routes"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return ""
	}

	m.meshRoutesMu.Lock()
	m.meshRoutesCache = make(map[int]struct{ ServiceName string; ServicePort int })
	m.meshRouteSlugCache = make(map[string]struct{ ServiceName string; ServicePort int })
	for _, r := range out.Routes {
		m.meshRoutesCache[r.ExternalPort] = struct{ ServiceName string; ServicePort int }{r.ServiceName, r.ServicePort}
		if r.Slug != "" {
			m.meshRouteSlugCache[r.Slug] = struct{ ServiceName string; ServicePort int }{r.ServiceName, r.ServicePort}
		}
	}
	m.meshRoutesAt = time.Now()
	e, ok := m.meshRoutesCache[externalPort]
	m.meshRoutesMu.Unlock()
	if !ok {
		return ""
	}
	return fmt.Sprintf("%s.default.svc.cluster.local:%d", e.ServiceName, e.ServicePort)
}

// resolveMeshRouteBySlug returns the local dial address for the given route name slug (e.g. "my-api").
// Empty string if not found. Uses the same cache as resolveMeshRoutePort.
func (m *derpManager) resolveMeshRouteBySlug(slug string) string {
	const cacheExpiry = 2 * time.Minute
	m.meshRoutesMu.RLock()
	if time.Since(m.meshRoutesAt) < cacheExpiry && m.meshRouteSlugCache != nil {
		if e, ok := m.meshRouteSlugCache[slug]; ok {
			m.meshRoutesMu.RUnlock()
			return fmt.Sprintf("%s.default.svc.cluster.local:%d", e.ServiceName, e.ServicePort)
		}
		m.meshRoutesMu.RUnlock()
		// Cache miss can happen right after route creation; refresh before failing.
	} else {
		m.meshRoutesMu.RUnlock()
	}
	// Trigger fetch so slug cache is populated
	_ = m.resolveMeshRoutePort(0)
	m.meshRoutesMu.RLock()
	defer m.meshRoutesMu.RUnlock()
	if e, ok := m.meshRouteSlugCache[slug]; ok {
		return fmt.Sprintf("%s.default.svc.cluster.local:%d", e.ServiceName, e.ServicePort)
	}
	return ""
}

func (m *derpManager) sendTrafficData(routeID string, data []byte) error {
	m.routeMu.RLock()
	to := m.routeSources[routeID]
	session := m.routeSessions[routeID]
	key := m.routeCiphers[routeID]
	m.routeMu.RUnlock()
	if to == "" {
		return fmt.Errorf("route %s has no source", routeID)
	}

	// Encrypt: prefer channel session, fall back to legacy X25519.
	dataToSend := data
	if session != nil {
		encrypted, err := session.Encrypt(data)
		if err != nil {
			return fmt.Errorf("session encrypt traffic: %w", err)
		}
		dataToSend = encrypted
	} else if key != [32]byte{} {
		encrypted, err := pqc.EncryptPayload(key, data)
		if err != nil {
			return fmt.Errorf("encrypt traffic: %w", err)
		}
		dataToSend = encrypted
	}

	payload, _ := json.Marshal(map[string]interface{}{"route_id": routeID, "data": dataToSend})
	msg := derpMessage{Type: "traffic_data", From: m.clientID, To: to, Data: payload}
	m.connMu.RLock()
	conn := m.conn
	m.connMu.RUnlock()
	if conn == nil {
		return fmt.Errorf("DERP not connected")
	}
	return m.writeMessage(conn, msg)
}

func (m *derpManager) sendRegister(conn *websocket.Conn) error {
	payload := map[string]string{
		"public_key":      m.publicKey,
		"cluster_id":      m.agent.ClusterID,
		"region":          m.region,
		"organization_id": fmt.Sprintf("%d", m.agent.OrganizationID),
		"agent_token":     m.agent.AgentToken,
	}
	if m.hybridPublicKey != "" {
		payload["hybrid_public_key"] = m.hybridPublicKey
	}
	if m.signingKeyPair != nil {
		sigPubBytes, err := m.signingKeyPair.PublicKey().MarshalBinary()
		if err == nil {
			payload["signing_public_key"] = base64.StdEncoding.EncodeToString(sigPubBytes)
		}
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	msg := derpMessage{
		Type: "register",
		From: m.clientID,
		To:   "server",
		Data: data,
	}
	return m.writeMessage(conn, msg)
}

func (m *derpManager) sendHeartbeat(conn *websocket.Conn) error {
	payload := map[string]string{
		"client_id": m.clientID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"region":    m.region,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	msg := derpMessage{
		Type: "heartbeat",
		From: m.clientID,
		To:   "server",
		Data: data,
	}
	return m.writeMessage(conn, msg)
}

func (m *derpManager) sendDiscovery(conn *websocket.Conn) error {
	clusterID := strings.TrimSpace(m.agent.ClusterID)
	if clusterID == "" {
		return nil
	}

	payload := map[string]string{
		"cluster_id": clusterID,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	msg := derpMessage{
		Type: "discovery",
		From: m.clientID,
		To:   "server",
		Data: data,
	}
	return m.writeMessage(conn, msg)
}

func (m *derpManager) writeMessage(conn *websocket.Conn, msg derpMessage) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	if conn == nil {
		return fmt.Errorf("DERP connection not established")
	}

	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}

	if err := conn.WriteJSON(msg); err != nil {
		return err
	}

	return nil
}

func (m *derpManager) nextEndpoint() string {
	if len(m.servers) == 0 {
		return ""
	}

	idx := m.nextIndex % len(m.servers)
	m.nextIndex = (idx + 1) % len(m.servers)
	return m.servers[idx]
}

func (m *derpManager) setConnection(conn *websocket.Conn, endpoint string) {
	m.connMu.Lock()
	m.conn = conn
	m.currentServer = endpoint
	m.connMu.Unlock()
}

func (m *derpManager) clearConnection() {
	m.connMu.Lock()
	m.conn = nil
	m.currentServer = ""
	m.connMu.Unlock()
}

func (m *derpManager) closeConnection() {
	m.connMu.Lock()
	defer m.connMu.Unlock()

	if m.conn != nil {
		m.writeMu.Lock()
		_ = m.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(2*time.Second))
		m.writeMu.Unlock()
		_ = m.conn.Close()
		m.conn = nil
		m.currentServer = ""
	}
}

// ensureKeyPair reads or generates a WireGuard-style X25519 key pair at privPath and pubPath.
func ensureKeyPair(privPath, pubPath string) (priv, pub string, err error) {
	if data, err := os.ReadFile(privPath); err == nil {
		priv = strings.TrimSpace(string(data))
		if pubData, err := os.ReadFile(pubPath); err == nil {
			pub = strings.TrimSpace(string(pubData))
			if priv != "" && pub != "" {
				return priv, pub, nil
			}
		}
	}
	var privBytes [32]byte
	if _, err := rand.Read(privBytes[:]); err != nil {
		return "", "", err
	}
	privBytes[0] &= 248
	privBytes[31] &= 127
	privBytes[31] |= 64
	var pubBytes [32]byte
	curve25519.ScalarBaseMult(&pubBytes, &privBytes)
	priv = base64.StdEncoding.EncodeToString(privBytes[:])
	pub = base64.StdEncoding.EncodeToString(pubBytes[:])
	dir := filepath.Dir(privPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(privPath, []byte(priv+"\n"), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(pubPath, []byte(pub+"\n"), 0o600); err != nil {
		return "", "", err
	}
	return priv, pub, nil
}

// ensureKeyStore loads or creates an encrypted keystore containing the DERP
// KEM and signing key pairs. The keystore is password-protected using either
// the PRYSM_KEYSTORE_PASSWORD env var or a key derived from the agent token.
func ensureKeyStore(stateDir, agentToken string) (*keystore.Store, error) {
	path := filepath.Join(stateDir, "prysm.keystore")
	password := []byte(os.Getenv("PRYSM_KEYSTORE_PASSWORD"))
	if len(password) == 0 && agentToken != "" {
		password = deriveKeystorePassword(agentToken)
	}
	if len(password) == 0 {
		return nil, fmt.Errorf("PRYSM_KEYSTORE_PASSWORD or agent token required for keystore")
	}

	// Try to open existing keystore.
	if data, err := os.ReadFile(path); err == nil {
		store, err := keystore.Open(data, password)
		if err == nil {
			return store, nil
		}
		log.Printf("DERP keystore: failed to open existing keystore, recreating: %v", err)
	}

	// Create new keystore with KEM and signing keys.
	store := keystore.New()
	if _, err := store.GenerateKEMKey("derp-kem"); err != nil {
		return nil, fmt.Errorf("generate KEM key: %w", err)
	}
	if _, err := store.GenerateSigningKey("derp-sign"); err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}

	sealed, err := store.Seal(password)
	if err != nil {
		return nil, fmt.Errorf("seal keystore: %w", err)
	}
	if err := os.WriteFile(path, sealed, 0o600); err != nil {
		return nil, fmt.Errorf("write keystore: %w", err)
	}
	log.Printf("DERP keystore: created new keystore at %s", path)
	return store, nil
}

// deriveKeystorePassword deterministically derives a keystore password from the
// agent token using SHA-256, used as a fallback when no explicit password is set.
func deriveKeystorePassword(token string) []byte {
	h := sha256.Sum256([]byte("prysm-keystore:" + token))
	return h[:]
}

func ensureDERPClientID(stateDir, clusterID string) (string, error) {
	// Use predictable format: cluster_{clusterID}
	// This format matches the backend's PeerDERPClientID (cross-cluster routes)
	// and MeshPeer.DeviceID so the CLI SOCKS5 proxy can address agents via DERP.
	sanitized := sanitizeIdentifier(clusterID)
	if sanitized == "" {
		sanitized = "0"
	}
	id := fmt.Sprintf("cluster_%s", sanitized)

	// Persist for logging/debugging purposes
	path := filepath.Join(stateDir, "derp-client.id")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return id, nil // Continue even if we can't persist
	}
	_ = os.WriteFile(path, []byte(id+"\n"), 0o600)

	return id, nil
}

func sanitizeIdentifier(input string) string {
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" {
		return ""
	}

	var b strings.Builder
	lastDash := false
	for _, r := range input {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '-' || r == '_' || r == ' ':
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}

	out := strings.Trim(b.String(), "-")
	return out
}
