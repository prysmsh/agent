package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prysmsh/pkg/tlsutil"

	"prysm-agent/metrics"
	"prysm-agent/metrics/plugins"
)

// P2P DERP Server - Distributed relay network
// Each server can connect to other servers forming a mesh

type P2PDERPServer struct {
	// Basic server info
	ID       string
	Region   string
	Port     string
	Domain   string
	
	// Client management
	clients   map[string]*DERPClient
	clientsMu sync.RWMutex
	upgrader  websocket.Upgrader
	
	// P2P server federation
	peers     map[string]*PeerServer
	peersMu   sync.RWMutex
	
	// Bootstrap peers for initial discovery
	bootstrapPeers []string
	
	// Metrics framework
	metricsFramework *metrics.MetricsFramework
	metricsConfig    *metrics.Config
	derpPlugin       *plugins.DERPPlugin
	ebpfPlugin       *plugins.EBPFPlugin
	
	// Server start time for uptime tracking
	startTime        time.Time
}

type DERPClient struct {
	ID        string
	Conn      *websocket.Conn
	PublicKey [32]byte
	LastSeen  time.Time
	ClusterID string
	Region    string
	ServerID  string  // Which server this client is connected to
	
	// Metrics tracking
	ConnectedAt   time.Time
	BytesIn       int64
	BytesOut      int64
	PacketsIn     int64
	PacketsOut    int64
	RemoteAddr    net.Addr
	UserAgent     string
}

type PeerServer struct {
	ID       string
	Address  string
	Region   string
	Conn     *websocket.Conn
	LastSeen time.Time
	Clients  []string  // Client IDs hosted by this peer
}

type DERPMessage struct {
	Type      string          `json:"type"`
	From      string          `json:"from"`
	To        string          `json:"to"`
	Data      []byte          `json:"data"`
	Encrypted bool            `json:"encrypted"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	ServerRoute []string      `json:"server_route,omitempty"`  // For inter-server routing
}

type ServerMessage struct {
	Type     string      `json:"type"`
	From     string      `json:"from"`
	Data     interface{} `json:"data"`
	Timestamp time.Time  `json:"timestamp"`
}

func NewP2PDERPServer(region, port string, bootstrapPeers []string) *P2PDERPServer {
	serverID := generateServerID()
	domain := os.Getenv("DERP_DOMAIN")
	if domain == "" {
		domain = "localhost"
	}

	// Create metrics configuration
	metricsConfig := &metrics.Config{
		CollectionInterval: parseTimeEnv("METRICS_COLLECTION_INTERVAL", 15*time.Second),
		BatchSize:          parseIntEnv("METRICS_BATCH_SIZE", 1000),
		BufferSize:         parseIntEnv("METRICS_BUFFER_SIZE", 50000), // Larger for network traffic
		EnableSampling:     parseBoolEnv("METRICS_ENABLE_SAMPLING", true),
		SampleRate:         parseFloatEnv("METRICS_SAMPLE_RATE", 0.1), // 10% sampling for high-traffic
		MaxConcurrency:     parseIntEnv("METRICS_MAX_CONCURRENCY", 10),
		RetentionPeriod:    parseTimeEnv("METRICS_RETENTION_PERIOD", 24*time.Hour),
		CompactionInterval: parseTimeEnv("METRICS_COMPACTION_INTERVAL", 1*time.Hour),
		EnableSecurity:     parseBoolEnv("METRICS_ENABLE_SECURITY", true),
		ThreatDetection:    parseBoolEnv("METRICS_THREAT_DETECTION", true),
		AnomalyThreshold:   parseFloatEnv("METRICS_ANOMALY_THRESHOLD", 2.0),
		EnableRay:          parseBoolEnv("METRICS_ENABLE_RAY", false),
		RayClusterAddress:  getEnvOrDefault("RAY_CLUSTER_ADDRESS", "ray://localhost:10001"),
		PluginConfigs:      make(map[string]interface{}),
	}

	// Initialize metrics framework
	metricsFramework := metrics.NewFramework(metricsConfig)

	// Create DERP plugin for this server
	derpPlugin := plugins.NewDERPPlugin(serverID, region)

	// Create eBPF plugin for this server
	ebpfPlugin := plugins.NewEBPFPlugin(serverID, region)

	return &P2PDERPServer{
		ID:             serverID,
		Region:         region,
		Port:           port,
		Domain:         domain,
		clients:        make(map[string]*DERPClient),
		peers:          make(map[string]*PeerServer),
		bootstrapPeers: bootstrapPeers,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for P2P network
			},
		},
		metricsFramework: metricsFramework,
		metricsConfig:    metricsConfig,
		derpPlugin:       derpPlugin,
		ebpfPlugin:       ebpfPlugin,
		startTime:        time.Now(),
	}
}

func (s *P2PDERPServer) Start() error {
	ctx := context.Background()
	
	// Initialize and start metrics framework
	if err := s.initializeMetricsFramework(ctx); err != nil {
		log.Printf("Warning: Failed to initialize metrics framework: %v", err)
	} else {
		log.Printf("Metrics framework initialized successfully")
	}
	
	// Start server discovery and federation
	go s.federationLoop(ctx)
	
	// Start cleanup routine
	go s.cleanupLoop(ctx)
	
	// Start metrics server on separate port
	go s.startMetricsServer(ctx)
	
	// Setup HTTP routes
	http.HandleFunc("/derp", s.handleClientWebSocket)
	http.HandleFunc("/server", s.handleServerWebSocket)  // Inter-server communication
	http.HandleFunc("/health", s.handleHealth)
	http.HandleFunc("/stats", s.handleLegacyMetrics)  // Legacy metrics for compatibility
	http.HandleFunc("/peers", s.handlePeers)  // Peer discovery endpoint
	
	log.Printf("[%s] P2P DERP server starting on port %s", s.ID, s.Port)
	log.Printf("[%s] Region: %s, Bootstrap peers: %v", s.ID, s.Region, s.bootstrapPeers)
	
	return http.ListenAndServeTLS(":"+s.Port, "cert.pem", "key.pem", nil)
}

// Client WebSocket handler (existing functionality)
func (s *P2PDERPServer) handleClientWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[%s] Client WebSocket upgrade failed: %v", s.ID, err)
		return
	}
	defer conn.Close()

	clientID := generateClientID()
	now := time.Now()
	
	client := &DERPClient{
		ID:          clientID,
		Conn:        conn,
		LastSeen:    now,
		ConnectedAt: now,
		ServerID:    s.ID,
		RemoteAddr:  conn.RemoteAddr(),
		UserAgent:   r.Header.Get("User-Agent"),
	}

	s.clientsMu.Lock()
	s.clients[clientID] = client
	s.clientsMu.Unlock()

	// Track client connection in metrics
	if s.derpPlugin != nil {
		s.derpPlugin.AddConnection(clientID, client.RemoteAddr)
	}

	// Notify peers about new client
	s.notifyPeersAboutClient(client, "client_joined")

	// Send welcome message
	welcome := DERPMessage{
		Type: "welcome",
		From: s.ID,
		To:   clientID,
		Data: []byte(fmt.Sprintf(`{"client_id":"%s","server_id":"%s","server_time":"%s"}`, 
			clientID, s.ID, time.Now().Format(time.RFC3339))),
	}
	conn.WriteJSON(welcome)

	// Handle client messages
	for {
		var msg DERPMessage
		if err := conn.ReadJSON(&msg); err != nil {
			log.Printf("[%s] Client %s disconnected: %v", s.ID, clientID, err)
			break
		}

		client.LastSeen = time.Now()
		s.handleClientMessage(client, &msg)
	}

	// Cleanup
	s.clientsMu.Lock()
	delete(s.clients, clientID)
	s.clientsMu.Unlock()
	
	// Remove from metrics tracking
	if s.derpPlugin != nil {
		s.derpPlugin.RemoveConnection(clientID)
	}
	
	// Notify peers about client departure
	s.notifyPeersAboutClient(client, "client_left")
}

// Server WebSocket handler (for inter-server communication)
func (s *P2PDERPServer) handleServerWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[%s] Server WebSocket upgrade failed: %v", s.ID, err)
		return
	}
	defer conn.Close()

	// Wait for peer identification
	var handshake ServerMessage
	if err := conn.ReadJSON(&handshake); err != nil {
		log.Printf("[%s] Failed to read peer handshake: %v", s.ID, err)
		return
	}

	if handshake.Type != "peer_handshake" {
		log.Printf("[%s] Invalid handshake type: %s", s.ID, handshake.Type)
		return
	}

	peerData := handshake.Data.(map[string]interface{})
	peerID := peerData["server_id"].(string)
	peerRegion := peerData["region"].(string)
	peerAddress := peerData["address"].(string)

	peer := &PeerServer{
		ID:       peerID,
		Address:  peerAddress,
		Region:   peerRegion,
		Conn:     conn,
		LastSeen: time.Now(),
	}

	s.peersMu.Lock()
	s.peers[peerID] = peer
	s.peersMu.Unlock()

	log.Printf("[%s] Peer server connected: %s (%s)", s.ID, peerID, peerRegion)

	// Send handshake response
	response := ServerMessage{
		Type: "peer_handshake_ack",
		From: s.ID,
		Data: map[string]interface{}{
			"server_id": s.ID,
			"region":    s.Region,
			"address":   fmt.Sprintf("%s:%s", s.Domain, s.Port),
		},
		Timestamp: time.Now(),
	}
	conn.WriteJSON(response)

	// Exchange current client lists
	s.exchangeClientLists(peer)

	// Handle server messages
	for {
		var msg ServerMessage
		if err := conn.ReadJSON(&msg); err != nil {
			log.Printf("[%s] Peer %s disconnected: %v", s.ID, peerID, err)
			break
		}

		peer.LastSeen = time.Now()
		s.handleServerMessage(peer, &msg)
	}

	// Cleanup
	s.peersMu.Lock()
	delete(s.peers, peerID)
	s.peersMu.Unlock()
}

func (s *P2PDERPServer) handleClientMessage(sender *DERPClient, msg *DERPMessage) {
	switch msg.Type {
	case "register":
		s.handleClientRegistration(sender, msg)
	case "relay":
		s.handleClientRelay(sender, msg)
	case "heartbeat":
		s.handleClientHeartbeat(sender, msg)
	case "discovery":
		s.handleClientDiscovery(sender, msg)
	default:
		log.Printf("[%s] Unknown client message type: %s", s.ID, msg.Type)
	}
}

func (s *P2PDERPServer) handleClientRelay(sender *DERPClient, msg *DERPMessage) {
	// First try local clients
	s.clientsMu.RLock()
	target, exists := s.clients[msg.To]
	s.clientsMu.RUnlock()

	if exists {
		// Local delivery
		relayMsg := DERPMessage{
			Type:      "message",
			From:      sender.ID,
			To:        target.ID,
			Data:      msg.Data,
			Encrypted: msg.Encrypted,
			Metadata:  msg.Metadata,
		}
		
		if err := target.Conn.WriteJSON(relayMsg); err != nil {
			log.Printf("[%s] Failed to relay message locally to %s: %v", s.ID, target.ID, err)
		} else {
			log.Printf("[%s] Relayed message locally: %s -> %s", s.ID, sender.ID, target.ID)
			
			// Update metrics for both sender and receiver
			dataSize := int64(len(msg.Data))
			s.updateClientMetrics(sender.ID, 0, dataSize, 0, 1) // Outbound for sender
			s.updateClientMetrics(target.ID, dataSize, 0, 1, 0) // Inbound for target
		}
		return
	}

	// Try remote servers
	s.relayToRemoteServer(sender, msg)
}

func (s *P2PDERPServer) relayToRemoteServer(sender *DERPClient, msg *DERPMessage) {
	// Find which peer server has this client
	var targetPeer *PeerServer
	s.peersMu.RLock()
	for _, peer := range s.peers {
		for _, clientID := range peer.Clients {
			if clientID == msg.To {
				targetPeer = peer
				break
			}
		}
		if targetPeer != nil {
			break
		}
	}
	s.peersMu.RUnlock()

	if targetPeer == nil {
		// Send error back to sender
		errorMsg := DERPMessage{
			Type: "error",
			From: s.ID,
			To:   sender.ID,
			Data: []byte(fmt.Sprintf(`{"error":"target_not_found","target":"%s"}`, msg.To)),
		}
		sender.Conn.WriteJSON(errorMsg)
		return
	}

	// Forward to peer server
	serverMsg := ServerMessage{
		Type: "relay_message",
		From: s.ID,
		Data: map[string]interface{}{
			"original_message": msg,
			"route": []string{s.ID, targetPeer.ID},
		},
		Timestamp: time.Now(),
	}

	if err := targetPeer.Conn.WriteJSON(serverMsg); err != nil {
		log.Printf("[%s] Failed to relay to peer %s: %v", s.ID, targetPeer.ID, err)
	} else {
		log.Printf("[%s] Relayed message to peer %s: %s -> %s", s.ID, targetPeer.ID, sender.ID, msg.To)
	}
}

func (s *P2PDERPServer) handleClientDiscovery(client *DERPClient, msg *DERPMessage) {
	var discoveryReq struct {
		ClusterID string `json:"cluster_id"`
	}
	
	if err := json.Unmarshal(msg.Data, &discoveryReq); err != nil {
		return
	}

	var peers []map[string]interface{}

	// Find local clients in the same cluster
	s.clientsMu.RLock()
	for _, c := range s.clients {
		if c.ClusterID == discoveryReq.ClusterID && c.ID != client.ID {
			peers = append(peers, map[string]interface{}{
				"client_id":  c.ID,
				"public_key": c.PublicKey,
				"region":     c.Region,
				"last_seen":  c.LastSeen,
				"server_id":  s.ID,
			})
		}
	}
	s.clientsMu.RUnlock()

	// Query peer servers for remote clients
	s.queryPeersForClients(discoveryReq.ClusterID, &peers)

	response := DERPMessage{
		Type: "discovery_response",
		From: s.ID,
		To:   client.ID,
		Data: marshalJSON(map[string]interface{}{
			"peers": peers,
			"total_servers": len(s.peers) + 1,
		}),
	}
	client.Conn.WriteJSON(response)
}

func (s *P2PDERPServer) queryPeersForClients(clusterID string, peers *[]map[string]interface{}) {
	// Send discovery query to all connected peers
	query := ServerMessage{
		Type: "cluster_query",
		From: s.ID,
		Data: map[string]interface{}{
			"cluster_id": clusterID,
		},
		Timestamp: time.Now(),
	}

	s.peersMu.RLock()
	for _, peer := range s.peers {
		if peer.Conn != nil {
			peer.Conn.WriteJSON(query)
		}
	}
	s.peersMu.RUnlock()
	
	// Note: In a real implementation, this would be async with a response collector
	// For simplicity, we're just showing the structure
}

func (s *P2PDERPServer) handleServerMessage(peer *PeerServer, msg *ServerMessage) {
	switch msg.Type {
	case "relay_message":
		s.handleServerRelay(peer, msg)
	case "client_update":
		s.handlePeerClientUpdate(peer, msg)
	case "cluster_query":
		s.handleClusterQuery(peer, msg)
	case "peer_heartbeat":
		// Already handled by updating LastSeen
		log.Printf("[%s] Heartbeat from peer %s", s.ID, peer.ID)
	default:
		log.Printf("[%s] Unknown server message type: %s", s.ID, msg.Type)
	}
}

func (s *P2PDERPServer) handleClusterQuery(peer *PeerServer, msg *ServerMessage) {
	data := msg.Data.(map[string]interface{})
	clusterID := data["cluster_id"].(string)
	
	var clients []map[string]interface{}
	
	// Find local clients in the requested cluster
	s.clientsMu.RLock()
	for _, client := range s.clients {
		if client.ClusterID == clusterID {
			clients = append(clients, map[string]interface{}{
				"client_id":  client.ID,
				"public_key": client.PublicKey,
				"region":     client.Region,
				"last_seen":  client.LastSeen,
				"server_id":  s.ID,
			})
		}
	}
	s.clientsMu.RUnlock()
	
	// Send response back to querying peer
	response := ServerMessage{
		Type: "cluster_query_response",
		From: s.ID,
		Data: map[string]interface{}{
			"cluster_id": clusterID,
			"clients":    clients,
		},
		Timestamp: time.Now(),
	}
	
	if peer.Conn != nil {
		peer.Conn.WriteJSON(response)
	}
}

func (s *P2PDERPServer) handleServerRelay(peer *PeerServer, msg *ServerMessage) {
	data := msg.Data.(map[string]interface{})
	originalMsg := data["original_message"].(map[string]interface{})
	
	targetID := originalMsg["to"].(string)
	
	// Find local client
	s.clientsMu.RLock()
	target, exists := s.clients[targetID]
	s.clientsMu.RUnlock()
	
	if exists {
		// Deliver to local client
		relayMsg := DERPMessage{
			Type:      "message",
			From:      originalMsg["from"].(string),
			To:        target.ID,
			Data:      []byte(originalMsg["data"].(string)),
			Encrypted: originalMsg["encrypted"].(bool),
		}
		
		if err := target.Conn.WriteJSON(relayMsg); err != nil {
			log.Printf("[%s] Failed to deliver relayed message to %s: %v", s.ID, target.ID, err)
		} else {
			log.Printf("[%s] Delivered relayed message to %s", s.ID, target.ID)
		}
	}
}

// Federation and discovery methods
func (s *P2PDERPServer) federationLoop(ctx context.Context) {
	// Initial connection to bootstrap peers
	go s.connectToBootstrapPeers()
	
	// Periodic peer discovery and health checks
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.maintainPeerConnections()
		}
	}
}

func (s *P2PDERPServer) connectToBootstrapPeers() {
	for _, peerAddr := range s.bootstrapPeers {
		go s.connectToPeer(peerAddr)
	}
}

func (s *P2PDERPServer) connectToPeer(address string) {
	if strings.Contains(address, s.Port) && strings.Contains(address, s.Domain) {
		// Don't connect to ourselves
		return
	}

	wsURL := fmt.Sprintf("wss://%s/server", address)

	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	tlsutil.ApplyPQCConfig(tlsConfig)
	dialer := websocket.Dialer{
		TLSClientConfig: tlsConfig,
	}

	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		log.Printf("[%s] Failed to connect to peer %s: %v", s.ID, address, err)
		return
	}
	
	// Send handshake
	handshake := ServerMessage{
		Type: "peer_handshake",
		From: s.ID,
		Data: map[string]interface{}{
			"server_id": s.ID,
			"region":    s.Region,
			"address":   fmt.Sprintf("%s:%s", s.Domain, s.Port),
		},
		Timestamp: time.Now(),
	}
	
	if err := conn.WriteJSON(handshake); err != nil {
		log.Printf("[%s] Failed to send handshake to %s: %v", s.ID, address, err)
		conn.Close()
		return
	}
	
	log.Printf("[%s] Connected to peer server: %s", s.ID, address)
}

// Utility methods
func (s *P2PDERPServer) handleClientRegistration(client *DERPClient, msg *DERPMessage) {
	var regData struct {
		PublicKey string `json:"public_key"`
		ClusterID string `json:"cluster_id"`
		Region    string `json:"region"`
	}
	
	if err := json.Unmarshal(msg.Data, &regData); err != nil {
		log.Printf("[%s] Invalid registration data: %v", s.ID, err)
		return
	}

	copy(client.PublicKey[:], regData.PublicKey)
	client.ClusterID = regData.ClusterID
	client.Region = regData.Region

	response := DERPMessage{
		Type: "registered",
		From: s.ID,
		To:   client.ID,
		Data: []byte(fmt.Sprintf(`{"status":"success","client_id":"%s","server_id":"%s"}`, client.ID, s.ID)),
	}
	client.Conn.WriteJSON(response)

	log.Printf("[%s] Client registered: %s (cluster: %s, region: %s)", 
		s.ID, client.ID, client.ClusterID, client.Region)
}

func (s *P2PDERPServer) handleClientHeartbeat(client *DERPClient, msg *DERPMessage) {
	client.LastSeen = time.Now()
	
	response := DERPMessage{
		Type: "heartbeat_ack",
		From: s.ID,
		To:   client.ID,
		Data: []byte(fmt.Sprintf(`{"timestamp":"%s"}`, time.Now().Format(time.RFC3339))),
	}
	client.Conn.WriteJSON(response)
}

func (s *P2PDERPServer) notifyPeersAboutClient(client *DERPClient, action string) {
	notification := ServerMessage{
		Type: "client_update",
		From: s.ID,
		Data: map[string]interface{}{
			"action":     action,
			"client_id":  client.ID,
			"cluster_id": client.ClusterID,
			"region":     client.Region,
		},
		Timestamp: time.Now(),
	}

	s.peersMu.RLock()
	for _, peer := range s.peers {
		if peer.Conn != nil {
			peer.Conn.WriteJSON(notification)
		}
	}
	s.peersMu.RUnlock()
}

func (s *P2PDERPServer) exchangeClientLists(peer *PeerServer) {
	// Send our client list to the peer
	var clients []map[string]interface{}
	s.clientsMu.RLock()
	for _, client := range s.clients {
		clients = append(clients, map[string]interface{}{
			"client_id":  client.ID,
			"cluster_id": client.ClusterID,
			"region":     client.Region,
		})
	}
	s.clientsMu.RUnlock()

	exchange := ServerMessage{
		Type: "client_list_exchange",
		From: s.ID,
		Data: map[string]interface{}{
			"clients": clients,
		},
		Timestamp: time.Now(),
	}

	if peer.Conn != nil {
		peer.Conn.WriteJSON(exchange)
	}
}

func (s *P2PDERPServer) handlePeerClientUpdate(peer *PeerServer, msg *ServerMessage) {
	data := msg.Data.(map[string]interface{})
	action := data["action"].(string)
	clientID := data["client_id"].(string)

	switch action {
	case "client_joined":
		// Add client to peer's client list
		peer.Clients = append(peer.Clients, clientID)
		log.Printf("[%s] Peer %s added client: %s", s.ID, peer.ID, clientID)
	case "client_left":
		// Remove client from peer's client list
		for i, id := range peer.Clients {
			if id == clientID {
				peer.Clients = append(peer.Clients[:i], peer.Clients[i+1:]...)
				break
			}
		}
		log.Printf("[%s] Peer %s removed client: %s", s.ID, peer.ID, clientID)
	}
}

func (s *P2PDERPServer) maintainPeerConnections() {
	// Health check and reconnection logic would go here
	s.peersMu.RLock()
	peerCount := len(s.peers)
	s.peersMu.RUnlock()
	
	log.Printf("[%s] Maintaining %d peer connections", s.ID, peerCount)
}

func (s *P2PDERPServer) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.clientsMu.Lock()
			now := time.Now()
			for id, client := range s.clients {
				if now.Sub(client.LastSeen) > 5*time.Minute {
					client.Conn.Close()
					delete(s.clients, id)
					log.Printf("[%s] Cleaned up stale client: %s", s.ID, id)
				}
			}
			s.clientsMu.Unlock()
		}
	}
}

// HTTP handlers
func (s *P2PDERPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.clientsMu.RLock()
	clientCount := len(s.clients)
	s.clientsMu.RUnlock()
	
	s.peersMu.RLock()
	peerCount := len(s.peers)
	s.peersMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "healthy",
		"server_id":     s.ID,
		"region":        s.Region,
		"client_count":  clientCount,
		"peer_count":    peerCount,
		"server_time":   time.Now().Format(time.RFC3339),
		"service":       "p2p-derp-relay",
	})
}

// initializeMetricsFramework sets up and starts the metrics collection framework
func (s *P2PDERPServer) initializeMetricsFramework(ctx context.Context) error {
	log.Printf("[%s] Initializing metrics framework...", s.ID)

	// Register DERP plugin
	if err := s.metricsFramework.RegisterPlugin(s.derpPlugin); err != nil {
		return fmt.Errorf("failed to register DERP plugin: %w", err)
	}

	// Register eBPF plugin
	if err := s.metricsFramework.RegisterPlugin(s.ebpfPlugin); err != nil {
		return fmt.Errorf("failed to register eBPF plugin: %w", err)
	}

	// Start the metrics framework
	if err := s.metricsFramework.Start(); err != nil {
		return fmt.Errorf("failed to start metrics framework: %w", err)
	}

	log.Printf("[%s] Metrics framework initialized with DERP and eBPF plugins", s.ID)
	return nil
}

// startMetricsServer starts the Prometheus metrics HTTP server on a separate port
func (s *P2PDERPServer) startMetricsServer(ctx context.Context) {
	metricsPort := getEnvOrDefault("METRICS_PORT", "9092")
	
	mux := http.NewServeMux()
	
	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.HandlerFor(
		s.metricsFramework.GetRegistry(),
		promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		},
	))
	
	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		stats := s.metricsFramework.GetFrameworkStats()
		clientCount := len(s.clients)
		peerCount := len(s.peers)
		
		healthStatus := "healthy"
		if !stats.IsRunning {
			healthStatus = "degraded"
		}
		
		fmt.Fprintf(w, `{
			"status":"%s",
			"server_id":"%s",
			"region":"%s",
			"uptime_seconds":%.0f,
			"client_count":%d,
			"peer_count":%d,
			"metrics_framework":{
				"running":%t,
				"plugins":%d,
				"buffer_usage":%.2f
			}
		}`, 
			healthStatus,
			s.ID,
			s.Region,
			time.Since(s.startTime).Seconds(),
			clientCount,
			peerCount,
			stats.IsRunning,
			stats.RegisteredPlugins,
			float64(stats.BufferSize)/float64(stats.BufferCapacity)*100,
		)
	})
	
	// Detailed server stats
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		s.clientsMu.RLock()
		s.peersMu.RLock()
		defer s.clientsMu.RUnlock()
		defer s.peersMu.RUnlock()
		
		stats := s.metricsFramework.GetFrameworkStats()
		
		clientsByRegion := make(map[string]int)
		clientsByCluster := make(map[string]int)
		totalBytesIn := int64(0)
		totalBytesOut := int64(0)
		
		for _, client := range s.clients {
			if client.Region != "" {
				clientsByRegion[client.Region]++
			}
			if client.ClusterID != "" {
				clientsByCluster[client.ClusterID]++
			}
			totalBytesIn += client.BytesIn
			totalBytesOut += client.BytesOut
		}
		
		peersByRegion := make(map[string]int)
		for _, peer := range s.peers {
			if peer.Region != "" {
				peersByRegion[peer.Region]++
			}
		}
		
		response := map[string]interface{}{
			"server_info": map[string]interface{}{
				"server_id": s.ID,
				"region":    s.Region,
				"uptime":    time.Since(s.startTime).String(),
				"port":      s.Port,
			},
			"connections": map[string]interface{}{
				"total_clients":      len(s.clients),
				"total_peers":        len(s.peers),
				"clients_by_region":  clientsByRegion,
				"clients_by_cluster": clientsByCluster,
				"peers_by_region":    peersByRegion,
			},
			"traffic": map[string]interface{}{
				"total_bytes_in":  totalBytesIn,
				"total_bytes_out": totalBytesOut,
			},
			"metrics_framework": map[string]interface{}{
				"running":         stats.IsRunning,
				"plugins":         stats.RegisteredPlugins,
				"buffer_size":     stats.BufferSize,
				"buffer_capacity": stats.BufferCapacity,
				"buffer_usage_pct": float64(stats.BufferSize)/float64(stats.BufferCapacity)*100,
			},
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
	
	// Connection management endpoint
	mux.HandleFunc("/connections", func(w http.ResponseWriter, r *http.Request) {
		s.clientsMu.RLock()
		defer s.clientsMu.RUnlock()
		
		var connections []map[string]interface{}
		for _, client := range s.clients {
			connections = append(connections, map[string]interface{}{
				"client_id":    client.ID,
				"cluster_id":   client.ClusterID,
				"region":       client.Region,
				"connected_at": client.ConnectedAt,
				"last_seen":    client.LastSeen,
				"bytes_in":     client.BytesIn,
				"bytes_out":    client.BytesOut,
				"packets_in":   client.PacketsIn,
				"packets_out":  client.PacketsOut,
				"remote_addr":  client.RemoteAddr.String(),
				"user_agent":   client.UserAgent,
			})
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"server_id":   s.ID,
			"connections": connections,
		})
	})
	
	server := &http.Server{
		Addr:    ":" + metricsPort,
		Handler: mux,
	}
	
	log.Printf("[%s] Starting metrics server on port %s", s.ID, metricsPort)
	
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[%s] Metrics server error: %v", s.ID, err)
		}
	}()
	
	// Wait for shutdown
	<-ctx.Done()
	
	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[%s] Metrics server shutdown error: %v", s.ID, err)
	}
}

// updateClientMetrics updates bandwidth and packet metrics for a client
func (s *P2PDERPServer) updateClientMetrics(clientID string, bytesIn, bytesOut, packetsIn, packetsOut int64) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	
	if client, exists := s.clients[clientID]; exists {
		client.BytesIn += bytesIn
		client.BytesOut += bytesOut
		client.PacketsIn += packetsIn
		client.PacketsOut += packetsOut
		client.LastSeen = time.Now()
		
		// Update DERP plugin metrics
		if s.derpPlugin != nil {
			s.derpPlugin.UpdateConnectionStats(clientID, bytesIn, bytesOut, packetsIn, packetsOut)
		}
	}
}

func (s *P2PDERPServer) handleLegacyMetrics(w http.ResponseWriter, r *http.Request) {
	s.clientsMu.RLock()
	s.peersMu.RLock()
	defer s.clientsMu.RUnlock()
	defer s.peersMu.RUnlock()

	metrics := map[string]interface{}{
		"server_id":      s.ID,
		"region":         s.Region,
		"total_clients":  len(s.clients),
		"total_peers":    len(s.peers),
		"clients_by_region": make(map[string]int),
		"clients_by_cluster": make(map[string]int),
		"peers_by_region": make(map[string]int),
	}

	for _, client := range s.clients {
		if region := client.Region; region != "" {
			metrics["clients_by_region"].(map[string]int)[region]++
		}
		if cluster := client.ClusterID; cluster != "" {
			metrics["clients_by_cluster"].(map[string]int)[cluster]++
		}
	}
	
	for _, peer := range s.peers {
		if region := peer.Region; region != "" {
			metrics["peers_by_region"].(map[string]int)[region]++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

func (s *P2PDERPServer) handlePeers(w http.ResponseWriter, r *http.Request) {
	s.peersMu.RLock()
	defer s.peersMu.RUnlock()

	var peers []map[string]interface{}
	for _, peer := range s.peers {
		peers = append(peers, map[string]interface{}{
			"server_id":    peer.ID,
			"address":      peer.Address,
			"region":       peer.Region,
			"last_seen":    peer.LastSeen,
			"client_count": len(peer.Clients),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"server_id": s.ID,
		"peers":     peers,
	})
}

func generateServerID() string {
	var bytes [8]byte
	rand.Read(bytes[:])
	return fmt.Sprintf("derp-server-%x", bytes)
}

func generateClientID() string {
	var bytes [16]byte
	rand.Read(bytes[:])
	return fmt.Sprintf("%x", bytes)
}

func marshalJSON(v interface{}) []byte {
	data, _ := json.Marshal(v)
	return data
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// parseTimeEnv parses a time duration from environment variable
func parseTimeEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// parseIntEnv parses an integer from environment variable
func parseIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// parseFloatEnv parses a float64 from environment variable
func parseFloatEnv(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
		}
	}
	return defaultValue
}

// parseBoolEnv parses a boolean from environment variable
func parseBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func main() {
	if len(os.Args) < 3 {
		log.Fatal("Usage: p2p-derp-server <region> <port> [bootstrap-peer1] [bootstrap-peer2] ...")
	}

	region := os.Args[1]
	port := os.Args[2]
	var bootstrapPeers []string
	
	if len(os.Args) > 3 {
		bootstrapPeers = os.Args[3:]
	}

	server := NewP2PDERPServer(region, port, bootstrapPeers)
	log.Fatal(server.Start())
}