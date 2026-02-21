package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
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
	"github.com/prysmsh/pkg/pqc"
	"github.com/prysmsh/pkg/tlsutil"
	"golang.org/x/crypto/curve25519"
)

// K8s API port for DERP tunnel (cluster proxy uses this to identify K8s API routes)
const derpK8sAPIPort = 6443

// In-cluster K8s API host (agent runs in cluster)
const k8sAPIHost = "kubernetes.default.svc.cluster.local"
const k8sAPIPort = "443"

type derpManager struct {
	agent           *PrysmAgent
	servers         []string
	region          string
	clientID        string
	publicKey       string
	hybridPublicKey string // base64 X25519+Kyber768 for quantum-resistant relay
	hybridKeyPair   *pqc.HybridKeyPair
	skipVerify      bool
	stateDir        string
	ifaceName       string
	k8sAPIAddr      string // host:port for K8s API (from KUBECONFIG_APISERVER when outside cluster)
	connMu          sync.RWMutex
	conn            *websocket.Conn
	currentServer   string
	writeMu         sync.Mutex
	nextIndex       int
	// Route state for K8s API tunneling (routeID -> k8sConn)
	routeConns   map[string]net.Conn
	routeSources map[string]string    // routeID -> source client ID for traffic_data replies
	routeCiphers map[string][32]byte  // routeID -> shared secret for E2E encryption
	routeMu      sync.RWMutex
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

	hybridKP, hybridPubB64, err := ensureHybridKeyPair(stateDir)
	if err != nil {
		return nil, fmt.Errorf("ensure hybrid PQC key (required for DERP): %w", err)
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

	return &derpManager{
		agent:           agent,
		servers:         servers,
		region:          agent.derpRegion,
		clientID:        clientID,
		publicKey:       pubKey,
		hybridPublicKey: hybridPubB64,
		hybridKeyPair:   hybridKP,
		skipVerify:      agent.derpSkipVerify,
		stateDir:        stateDir,
		ifaceName:       iface,
		k8sAPIAddr:      k8sAPIAddr,
		routeConns:      make(map[string]net.Conn),
		routeSources:    make(map[string]string),
		routeCiphers:    make(map[string][32]byte),
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
		// Exit route: dial target address directly (plain TCP).
		if payload.TargetAddress == "" {
			log.Printf("DERP route_setup: exit route missing target_address")
			m.sendRouteResponse(msg.From, payload.RouteID, "failed", "target_address required for exit route", "")
			return
		}
		log.Printf("DERP route_setup: exit route to %s", payload.TargetAddress)
		conn, dialErr = net.DialTimeout("tcp", payload.TargetAddress, 10*time.Second)
		if dialErr != nil {
			log.Printf("DERP route_setup: failed to dial exit target %s: %v", payload.TargetAddress, dialErr)
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
		tlsCfg := &tls.Config{
			InsecureSkipVerify: m.skipVerify,
			ServerName:         "kubernetes",
		}
		tlsutil.ApplyPQCConfig(tlsCfg)
		conn, dialErr = tls.Dial("tcp", addr, tlsCfg)
		if dialErr != nil {
			log.Printf("DERP route_setup: failed to dial K8s API %s: %v", addr, dialErr)
			m.sendRouteResponse(msg.From, payload.RouteID, "failed", dialErr.Error(), "")
			return
		}
	}

	// Handle E2E encryption key exchange if backend provided its ephemeral public key
	var agentPubKeyB64 string
	if payload.BackendEphemeralPubkey != "" {
		backendPubBytes, err := base64.StdEncoding.DecodeString(payload.BackendEphemeralPubkey)
		if err == nil && len(backendPubBytes) == 32 {
			// Generate ephemeral X25519 key pair for this route
			var agentPriv, agentPub [32]byte
			if _, err := rand.Read(agentPriv[:]); err == nil {
				curve25519.ScalarBaseMult(&agentPub, &agentPriv)
				agentPubKeyB64 = base64.StdEncoding.EncodeToString(agentPub[:])

				// Compute shared secret
				var backendPub [32]byte
				copy(backendPub[:], backendPubBytes)
				var sharedSecret [32]byte
				curve25519.ScalarMult(&sharedSecret, &agentPriv, &backendPub)

				// Store cipher key for this route
				m.routeMu.Lock()
				m.routeCiphers[payload.RouteID] = sharedSecret
				m.routeMu.Unlock()
			} else {
				log.Printf("DERP E2E WARNING: failed to generate ephemeral key, falling back to plaintext: %v", err)
			}
		} else {
			log.Printf("DERP E2E WARNING: invalid backend ephemeral pubkey, falling back to plaintext")
		}
	} else {
		log.Printf("DERP E2E WARNING: backend did not provide ephemeral pubkey (old backend?), falling back to plaintext")
	}

	m.routeMu.Lock()
	m.routeConns[payload.RouteID] = conn
	m.routeSources[payload.RouteID] = msg.From
	m.routeMu.Unlock()
	m.sendRouteResponse(msg.From, payload.RouteID, "ok", "", agentPubKeyB64)
	go m.forwardFromK8s(payload.RouteID, conn)
}

func (m *derpManager) forwardFromK8s(routeID string, conn net.Conn) {
	defer func() {
		conn.Close()
		m.routeMu.Lock()
		delete(m.routeConns, routeID)
		delete(m.routeSources, routeID)
		delete(m.routeCiphers, routeID)
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
		RouteID string `json:"route_id"`
		Data    []byte `json:"data"`
	}
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		log.Printf("DERP traffic_data parse error: %v", err)
		return
	}
	m.routeMu.RLock()
	conn := m.routeConns[payload.RouteID]
	key := m.routeCiphers[payload.RouteID]
	m.routeMu.RUnlock()
	if conn == nil {
		return
	}

	// Decrypt if E2E encryption is active for this route
	data := payload.Data
	if key != [32]byte{} && len(data) > pqc.NonceSize {
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
	data := map[string]string{"route_id": routeID, "status": status}
	if errDetail != "" {
		data["error"] = errDetail
	}
	if agentEphemeralPubkey != "" {
		data["agent_ephemeral_pubkey"] = agentEphemeralPubkey
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

func (m *derpManager) sendTrafficData(routeID string, data []byte) error {
	m.routeMu.RLock()
	to := m.routeSources[routeID]
	key := m.routeCiphers[routeID]
	m.routeMu.RUnlock()
	if to == "" {
		return fmt.Errorf("route %s has no source", routeID)
	}

	// Encrypt if E2E encryption is active for this route
	dataToSend := data
	if key != [32]byte{} {
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

// ensureHybridKeyPair loads or generates a hybrid X25519+Kyber768 key pair for quantum-resistant DERP relay encryption.
func ensureHybridKeyPair(stateDir string) (*pqc.HybridKeyPair, string, error) {
	path := filepath.Join(stateDir, "derp-hybrid.key")
	if data, err := os.ReadFile(path); err == nil && len(data) >= pqc.HybridSecretKeySize {
		kp, err := pqc.UnmarshalKeyPair(data)
		if err == nil {
			pubBytes, _ := kp.PublicKey().MarshalBinary()
			return kp, base64.StdEncoding.EncodeToString(pubBytes), nil
		}
	}
	kp, err := pqc.GenerateKeyPair()
	if err != nil {
		return nil, "", err
	}
	pubBytes, err := kp.PublicKey().MarshalBinary()
	if err != nil {
		return nil, "", err
	}
	ser, err := kp.MarshalKeyPair()
	if err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(path, ser, 0o600); err != nil {
		return nil, "", err
	}
	return kp, base64.StdEncoding.EncodeToString(pubBytes), nil
}

func ensureDERPClientID(stateDir, clusterID string) (string, error) {
	// Use predictable format: cluster_{clusterID}
	// This format is expected by the backend for cross-cluster routing.
	// The backend uses fmt.Sprintf("cluster_%d", targetClusterID) to address peers.
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
