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
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// crossClusterRouteAssignment is returned by the backend for a specific cluster.
type crossClusterRouteAssignment struct {
	ID               uint   `json:"id"`
	OrganizationID   uint   `json:"organization_id"`
	Name             string `json:"name"`
	SourceClusterID  uint   `json:"source_cluster_id"`
	TargetClusterID  uint   `json:"target_cluster_id"`
	TargetService    string `json:"target_service"`
	TargetNamespace  string `json:"target_namespace"`
	TargetPort       int    `json:"target_port"`
	LocalPort        int    `json:"local_port"`
	Protocol         string `json:"protocol"`
	Status           string `json:"status"`
	Enabled          bool   `json:"enabled"`
	Role             string `json:"role"`                // "source" or "target"
	PeerClusterID    uint   `json:"peer_cluster_id"`
	PeerDERPClientID string `json:"peer_derp_client_id"` // e.g. "cluster_5"
}

// crossClusterRouteManager reconciles running cross-cluster routes with the desired state.
type crossClusterRouteManager struct {
	agent   *PrysmAgent
	mu      sync.Mutex
	sources map[uint]*sourceRoute
	targets map[uint]*targetRoute

	// Source-side: track TCP client connections so we can write return data
	sourceConnsMu sync.RWMutex
	sourceConns   map[string]net.Conn // streamID -> TCP client conn

	// proxyMode: when true, this is running as the CC proxy pod (creates TCP listeners)
	// when false, this is the main agent (manages proxy pod lifecycle, no TCP listeners)
	proxyMode bool

	// proxyPodRunning: tracks if we've created the proxy pod (main agent mode only)
	proxyPodRunning bool
}

type sourceRoute struct {
	assignment   crossClusterRouteAssignment
	serviceIP    string       // ClusterIP of the K8s Service for this route
	listener     net.Listener // TCP listener on target_port (proxy mode only)
	cancel       context.CancelFunc
}

type targetRoute struct {
	assignment crossClusterRouteAssignment
	cancel     context.CancelFunc
	connsMu    sync.Mutex
	conns      map[string]net.Conn // streamID -> K8s service conn
}

func newCrossClusterRouteManager(agent *PrysmAgent) *crossClusterRouteManager {
	return &crossClusterRouteManager{
		agent:       agent,
		sources:     make(map[uint]*sourceRoute),
		targets:     make(map[uint]*targetRoute),
		sourceConns: make(map[string]net.Conn),
	}
}

// SetProxyMode enables proxy mode (creates TCP listeners instead of managing proxy pod)
func (m *crossClusterRouteManager) SetProxyMode(enabled bool) {
	m.proxyMode = enabled
}

func (m *crossClusterRouteManager) Start(ctx context.Context) {
	if m.agent.BackendURL == "" || m.agent.AgentToken == "" || m.agent.ClusterID == "" {
		log.Println("cross-cluster-routes: disabled (missing backend URL, token, or cluster ID)")
		return
	}

	interval := 30 * time.Second
	if d := getEnvOrDefault("CC_ROUTE_POLL_INTERVAL", ""); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
			interval = parsed
		}
	}

	log.Printf("cross-cluster-routes: poller started (interval=%v)", interval)
	m.reconcile(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.stopAll()
			return
		case <-ticker.C:
			m.reconcile(ctx)
		}
	}
}

func (m *crossClusterRouteManager) reconcile(ctx context.Context) {
	routes, err := m.fetchRoutes(ctx)
	if err != nil {
		log.Printf("cross-cluster-routes: poll failed: %v", err)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	desiredSources := make(map[uint]crossClusterRouteAssignment)
	desiredTargets := make(map[uint]crossClusterRouteAssignment)
	for _, r := range routes {
		switch r.Role {
		case "source":
			desiredSources[r.ID] = r
		case "target":
			desiredTargets[r.ID] = r
		}
	}

	// Stop removed source routes
	for id, sr := range m.sources {
		if _, ok := desiredSources[id]; !ok {
			log.Printf("cross-cluster-routes: stopping source route %d (%s)", id, sr.assignment.Name)
			sr.cancel()
			if sr.listener != nil {
				sr.listener.Close()
			}
			if !m.proxyMode {
				m.cleanupRouteService(ctx, sr.assignment)
			}
			delete(m.sources, id)
			m.reportStatus(id, "disabled", "")
		}
	}

	// Delete proxy pod if no source routes remain (main agent mode only)
	if !m.proxyMode && len(m.sources) == 0 && len(desiredSources) == 0 {
		m.deleteProxyPod(ctx)
	}

	// Stop removed target routes
	for id, tr := range m.targets {
		if _, ok := desiredTargets[id]; !ok {
			log.Printf("cross-cluster-routes: stopping target route %d (%s)", id, tr.assignment.Name)
			tr.cancel()
			tr.closeAllConns()
			delete(m.targets, id)
		}
	}

	// Start new source routes
	for id, r := range desiredSources {
		if _, exists := m.sources[id]; !exists {
			m.startSourceRoute(ctx, r)
		}
	}

	// Start new target routes
	for id, r := range desiredTargets {
		if _, exists := m.targets[id]; !exists {
			m.startTargetRoute(ctx, r)
		}
	}
}

func (m *crossClusterRouteManager) startSourceRoute(ctx context.Context, r crossClusterRouteAssignment) {
	routeCtx, cancel := context.WithCancel(ctx)
	sr := &sourceRoute{assignment: r, cancel: cancel}

	if m.proxyMode {
		// Proxy mode: create TCP listener on target_port (same port as the target service)
		// This way the K8s Service can route directly: service:8080 → proxy:8080 → target:8080
		ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", r.TargetPort))
		if err != nil {
			log.Printf("cross-cluster-routes: source route %d listen on port %d failed: %v", r.ID, r.TargetPort, err)
			m.reportStatus(r.ID, "error", "")
			cancel()
			return
		}
		sr.listener = ln
		log.Printf("cross-cluster-routes: source route %d listening on :%d", r.ID, r.TargetPort)
		go m.acceptLoop(routeCtx, sr)
		m.sources[r.ID] = sr
		log.Printf("cross-cluster-routes: source route %d (%s) → %s.%s:%d via %s",
			r.ID, r.Name, r.TargetService, r.TargetNamespace, r.TargetPort, r.PeerDERPClientID)
		m.reportStatus(r.ID, "active", "derp")
		return
	}

	// Main agent mode: ensure proxy pod exists and create K8s Service + Endpoints
	if err := m.ensureProxyPod(ctx); err != nil {
		log.Printf("cross-cluster-routes: failed to ensure proxy pod: %v", err)
		m.reportStatus(r.ID, "error", "")
		cancel()
		return
	}

	serviceIP := m.ensureRouteService(ctx, r)
	if serviceIP == "" {
		log.Printf("cross-cluster-routes: source route %d failed to create service", r.ID)
		m.reportStatus(r.ID, "error", "")
		cancel()
		return
	}
	sr.serviceIP = serviceIP
	m.sources[r.ID] = sr

	log.Printf("cross-cluster-routes: source route %d (%s) service %s:%d → %s.%s:%d via proxy pod",
		r.ID, r.Name, serviceIP, r.TargetPort, r.TargetService, r.TargetNamespace, r.TargetPort)
	m.reportStatus(r.ID, "active", "derp")
}

// acceptLoop accepts incoming TCP connections on the source route listener
// and proxies them to the target cluster via DERP.
func (m *crossClusterRouteManager) acceptLoop(ctx context.Context, sr *sourceRoute) {
	for {
		conn, err := sr.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if !strings.Contains(err.Error(), "use of closed") {
					log.Printf("cross-cluster-routes: source route %d accept error: %v", sr.assignment.ID, err)
				}
				return
			}
		}
		r := sr.assignment // copy
		go m.ProxyConnection(ctx, &r, conn)
	}
}

// LookupByServiceIP checks if the given ClusterIP:port matches a cross-cluster route.
// Called by tunnel daemon to intercept traffic destined for CC routes.
// Returns the route assignment and true if found, nil and false otherwise.
func (m *crossClusterRouteManager) LookupByServiceIP(ip string, port int) (*crossClusterRouteAssignment, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, sr := range m.sources {
		if sr.serviceIP == ip && sr.assignment.TargetPort == port {
			r := sr.assignment // copy
			return &r, true
		}
	}
	return nil, false
}

// ProxyConnection proxies a TCP connection through DERP to the target cluster.
// Called by tunnel daemon when traffic matches a cross-cluster route.
func (m *crossClusterRouteManager) ProxyConnection(ctx context.Context, r *crossClusterRouteAssignment, conn net.Conn) {
	defer conn.Close()

	dm := m.agent.derpManager
	if dm == nil {
		log.Printf("cross-cluster-routes: no DERP manager for route %d", r.ID)
		return
	}

	streamID := fmt.Sprintf("ccr_%d_%d", r.ID, time.Now().UnixNano())

	// Track this source connection for return traffic
	m.sourceConnsMu.Lock()
	m.sourceConns[streamID] = conn
	m.sourceConnsMu.Unlock()
	defer func() {
		m.sourceConnsMu.Lock()
		delete(m.sourceConns, streamID)
		m.sourceConnsMu.Unlock()
	}()

	// Send setup to target
	setupData, _ := json.Marshal(map[string]interface{}{
		"stream_id":        streamID,
		"route_id":         r.ID,
		"target_service":   r.TargetService,
		"target_namespace": r.TargetNamespace,
		"target_port":      r.TargetPort,
	})
	setupMsg := derpMessage{
		Type: "cross_cluster_setup",
		From: dm.clientID,
		To:   r.PeerDERPClientID,
		Data: setupData,
	}

	dm.connMu.RLock()
	derpConn := dm.conn
	dm.connMu.RUnlock()
	if derpConn == nil {
		log.Printf("cross-cluster-routes: DERP not connected for route %d", r.ID)
		return
	}
	if err := dm.writeMessage(derpConn, setupMsg); err != nil {
		log.Printf("cross-cluster-routes: setup send failed for route %d: %v", r.ID, err)
		return
	}

	log.Printf("cross-cluster-routes: proxying connection for route %d (%s) via DERP to %s",
		r.ID, r.Name, r.PeerDERPClientID)

	// Forward TCP → DERP
	buf := make([]byte, 32*1024)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			payload, _ := json.Marshal(map[string]interface{}{
				"stream_id": streamID,
				"route_id":  r.ID,
				"data":      buf[:n],
			})
			msg := derpMessage{
				Type: "cross_cluster_data",
				From: dm.clientID,
				To:   r.PeerDERPClientID,
				Data: payload,
			}
			dm.connMu.RLock()
			c := dm.conn
			dm.connMu.RUnlock()
			if c == nil {
				return
			}
			if writeErr := dm.writeMessage(c, msg); writeErr != nil {
				log.Printf("cross-cluster-routes: source→DERP write error route %d: %v", r.ID, writeErr)
				return
			}
		}
		if err != nil {
			// Send close to peer
			m.sendClose(dm, streamID, r.ID, r.PeerDERPClientID)
			return
		}
	}
}

func (m *crossClusterRouteManager) startTargetRoute(_ context.Context, r crossClusterRouteAssignment) {
	_, cancel := context.WithCancel(context.Background())
	tr := &targetRoute{assignment: r, cancel: cancel, conns: make(map[string]net.Conn)}
	m.targets[r.ID] = tr

	log.Printf("cross-cluster-routes: target route %d (%s) → %s.%s:%d",
		r.ID, r.Name, r.TargetService, r.TargetNamespace, r.TargetPort)
}

// handleCrossClusterSetup handles incoming setup from a source agent.
func (m *crossClusterRouteManager) handleCrossClusterSetup(msg *derpMessage) {
	var payload struct {
		StreamID        string `json:"stream_id"`
		RouteID         uint   `json:"route_id"`
		TargetService   string `json:"target_service"`
		TargetNamespace string `json:"target_namespace"`
		TargetPort      int    `json:"target_port"`
	}
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		log.Printf("cross-cluster-routes: invalid setup: %v", err)
		return
	}

	m.mu.Lock()
	tr, ok := m.targets[payload.RouteID]
	m.mu.Unlock()
	if !ok {
		log.Printf("cross-cluster-routes: no target handler for route %d", payload.RouteID)
		return
	}

	svcAddr := fmt.Sprintf("%s.%s.svc.cluster.local:%d",
		payload.TargetService, payload.TargetNamespace, payload.TargetPort)
	conn, err := net.DialTimeout("tcp", svcAddr, 10*time.Second)
	if err != nil {
		log.Printf("cross-cluster-routes: target dial %s failed: %v", svcAddr, err)
		return
	}

	tr.connsMu.Lock()
	tr.conns[payload.StreamID] = conn
	tr.connsMu.Unlock()

	log.Printf("cross-cluster-routes: target route %d stream %s → %s", payload.RouteID, payload.StreamID, svcAddr)

	go m.forwardTargetToSource(tr, payload.StreamID, payload.RouteID, msg.From, conn)
}

func (m *crossClusterRouteManager) forwardTargetToSource(tr *targetRoute, streamID string, routeID uint, sourceClient string, conn net.Conn) {
	defer func() {
		conn.Close()
		tr.connsMu.Lock()
		delete(tr.conns, streamID)
		tr.connsMu.Unlock()
	}()

	dm := m.agent.derpManager
	if dm == nil {
		return
	}

	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			payload, _ := json.Marshal(map[string]interface{}{
				"stream_id": streamID,
				"route_id":  routeID,
				"data":      buf[:n],
			})
			msg := derpMessage{
				Type: "cross_cluster_data",
				From: dm.clientID,
				To:   sourceClient,
				Data: payload,
			}
			dm.connMu.RLock()
			c := dm.conn
			dm.connMu.RUnlock()
			if c == nil {
				return
			}
			if writeErr := dm.writeMessage(c, msg); writeErr != nil {
				return
			}
		}
		if err != nil {
			dm := m.agent.derpManager
			if dm != nil {
				m.sendClose(dm, streamID, routeID, sourceClient)
			}
			return
		}
	}
}

// handleCrossClusterData handles incoming data from a peer.
func (m *crossClusterRouteManager) handleCrossClusterData(msg *derpMessage) {
	var payload struct {
		StreamID string `json:"stream_id"`
		RouteID  uint   `json:"route_id"`
		Data     []byte `json:"data"`
	}
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		return
	}

	// Try target side first
	m.mu.Lock()
	tr, isTarget := m.targets[payload.RouteID]
	m.mu.Unlock()

	if isTarget {
		tr.connsMu.Lock()
		conn := tr.conns[payload.StreamID]
		tr.connsMu.Unlock()
		if conn != nil {
			if _, err := conn.Write(payload.Data); err != nil {
				conn.Close()
				tr.connsMu.Lock()
				delete(tr.conns, payload.StreamID)
				tr.connsMu.Unlock()
			}
			return
		}
	}

	// Source side: write return data to TCP client
	m.sourceConnsMu.RLock()
	conn := m.sourceConns[payload.StreamID]
	m.sourceConnsMu.RUnlock()
	if conn != nil {
		if _, err := conn.Write(payload.Data); err != nil {
			conn.Close()
			m.sourceConnsMu.Lock()
			delete(m.sourceConns, payload.StreamID)
			m.sourceConnsMu.Unlock()
		}
	}
}

// handleCrossClusterClose handles stream close from a peer.
func (m *crossClusterRouteManager) handleCrossClusterClose(msg *derpMessage) {
	var payload struct {
		StreamID string `json:"stream_id"`
		RouteID  uint   `json:"route_id"`
	}
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		return
	}

	// Close target-side connection
	m.mu.Lock()
	tr, isTarget := m.targets[payload.RouteID]
	m.mu.Unlock()
	if isTarget {
		tr.connsMu.Lock()
		if c := tr.conns[payload.StreamID]; c != nil {
			c.Close()
			delete(tr.conns, payload.StreamID)
		}
		tr.connsMu.Unlock()
	}

	// Close source-side connection
	m.sourceConnsMu.Lock()
	if c := m.sourceConns[payload.StreamID]; c != nil {
		c.Close()
		delete(m.sourceConns, payload.StreamID)
	}
	m.sourceConnsMu.Unlock()
}

func (m *crossClusterRouteManager) sendClose(dm *derpManager, streamID string, routeID uint, to string) {
	closePayload, _ := json.Marshal(map[string]interface{}{
		"stream_id": streamID,
		"route_id":  routeID,
	})
	closeMsg := derpMessage{
		Type: "cross_cluster_close",
		From: dm.clientID,
		To:   to,
		Data: closePayload,
	}
	dm.connMu.RLock()
	c := dm.conn
	dm.connMu.RUnlock()
	if c != nil {
		_ = dm.writeMessage(c, closeMsg)
	}
}

func (tr *targetRoute) closeAllConns() {
	tr.connsMu.Lock()
	defer tr.connsMu.Unlock()
	for id, c := range tr.conns {
		c.Close()
		delete(tr.conns, id)
	}
}

func (m *crossClusterRouteManager) stopAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx := context.Background()
	for id, sr := range m.sources {
		sr.cancel()
		if sr.listener != nil {
			sr.listener.Close()
		}
		if !m.proxyMode {
			m.cleanupRouteService(ctx, sr.assignment)
		}
		delete(m.sources, id)
	}
	for id, tr := range m.targets {
		tr.cancel()
		tr.closeAllConns()
		delete(m.targets, id)
	}
	// Delete proxy pod when shutting down (main agent mode only)
	if !m.proxyMode {
		m.deleteProxyPod(ctx)
	}
}

// ccRouteServiceName returns the K8s Service name for a cross-cluster route.
func ccRouteServiceName(r crossClusterRouteAssignment) string {
	return fmt.Sprintf("cc-%s--%s", r.TargetService, r.TargetNamespace)
}

// ccRouteAgentNamespace returns the namespace the agent pod is running in.
func ccRouteAgentNamespace() string {
	// Try downward-API env var first, then service-account file, then default.
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if s := strings.TrimSpace(string(data)); s != "" {
			return s
		}
	}
	return "prysm-system"
}

// ccRouteAgentSelector returns the label selector used to match the agent pod.
func ccRouteAgentSelector() map[string]string {
	return map[string]string{"app.kubernetes.io/name": "agent"}
}

// ccRouteAgentPodIP returns the agent pod's IP address.
// With hostNetwork, this is the node IP. Falls back to discovering local IPs.
func ccRouteAgentPodIP() string {
	// Try downward-API env var first
	if ip := os.Getenv("POD_IP"); ip != "" {
		return ip
	}
	// Fallback: get first non-loopback IPv4 address
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return ""
}

// ensureRouteService creates or updates a K8s Service and Endpoints in the agent's namespace.
// The service has no selector - we manually create Endpoints pointing to the proxy pod's
// TCP listener on target_port. This allows any pod to reach the cross-cluster route via DNS.
// Traffic flow: pod → service:target_port → proxy:target_port → DERP → remote cluster:target_port
// Returns the ClusterIP of the service.
func (m *crossClusterRouteManager) ensureRouteService(ctx context.Context, r crossClusterRouteAssignment) string {
	cs := m.agent.clientset
	if cs == nil {
		return ""
	}

	ns := ccRouteAgentNamespace()
	svcName := ccRouteServiceName(r)

	// Get proxy pod IP for Endpoints
	proxyIP := m.getProxyPodIP(ctx)
	if proxyIP == "" {
		log.Printf("cross-cluster-routes: cannot determine proxy pod IP for route %d", r.ID)
		return ""
	}

	labels := map[string]string{
		"prysm.sh/managed-by": "prysm-agent",
		"prysm.sh/component":  "cc-route",
		"prysm.sh/route-id":   strconv.FormatUint(uint64(r.ID), 10),
	}

	// Service with NO selector - we manually manage Endpoints
	// Port and TargetPort are both target_port (e.g., 8080)
	// Traffic flows: service:8080 → proxy pod:8080 → DERP → target cluster:8080
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: ns,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			// No selector - Endpoints are manually managed
			Ports: []corev1.ServicePort{
				{
					Name:       "cc",
					Port:       int32(r.TargetPort),
					TargetPort: intstr.FromInt32(int32(r.TargetPort)), // Same port - proxy listens on target_port
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	// Endpoints pointing to proxy pod IP + target_port
	endpoints := &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName, // Must match service name
			Namespace: ns,
			Labels:    labels,
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{
					{IP: proxyIP},
				},
				Ports: []corev1.EndpointPort{
					{
						Name:     "cc",
						Port:     int32(r.TargetPort),
						Protocol: corev1.ProtocolTCP,
					},
				},
			},
		},
	}

	tCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Create or update Service
	var clusterIP string
	created, err := cs.CoreV1().Services(ns).Create(tCtx, svc, metav1.CreateOptions{})
	if err != nil {
		if isAlreadyExists(err) {
			existing, getErr := cs.CoreV1().Services(ns).Get(tCtx, svcName, metav1.GetOptions{})
			if getErr != nil {
				log.Printf("cross-cluster-routes: get service %s/%s failed: %v", ns, svcName, getErr)
				return ""
			}
			existing.Spec.Ports = svc.Spec.Ports
			existing.Labels = labels
			existing.Spec.Selector = nil
			updated, updateErr := cs.CoreV1().Services(ns).Update(tCtx, existing, metav1.UpdateOptions{})
			if updateErr != nil {
				log.Printf("cross-cluster-routes: update service %s/%s failed: %v", ns, svcName, updateErr)
				clusterIP = existing.Spec.ClusterIP
			} else {
				clusterIP = updated.Spec.ClusterIP
			}
		} else {
			log.Printf("cross-cluster-routes: create service %s/%s failed: %v", ns, svcName, err)
			return ""
		}
	} else {
		clusterIP = created.Spec.ClusterIP
		log.Printf("cross-cluster-routes: created service %s/%s ClusterIP=%s (route %d)", ns, svcName, clusterIP, r.ID)
	}

	// Create or update Endpoints
	_, err = cs.CoreV1().Endpoints(ns).Create(tCtx, endpoints, metav1.CreateOptions{})
	if err != nil {
		if isAlreadyExists(err) {
			_, updateErr := cs.CoreV1().Endpoints(ns).Update(tCtx, endpoints, metav1.UpdateOptions{})
			if updateErr != nil {
				log.Printf("cross-cluster-routes: update endpoints %s/%s failed: %v", ns, svcName, updateErr)
			}
		} else {
			log.Printf("cross-cluster-routes: create endpoints %s/%s failed: %v", ns, svcName, err)
		}
	} else {
		log.Printf("cross-cluster-routes: created endpoints %s/%s → %s:%d (route %d)", ns, svcName, proxyIP, r.TargetPort, r.ID)
	}

	return clusterIP
}

// cleanupRouteService deletes the K8s Service and Endpoints for a removed route.
func (m *crossClusterRouteManager) cleanupRouteService(ctx context.Context, r crossClusterRouteAssignment) {
	cs := m.agent.clientset
	if cs == nil {
		return
	}

	ns := ccRouteAgentNamespace()
	svcName := ccRouteServiceName(r)

	tCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Delete Endpoints first
	err := cs.CoreV1().Endpoints(ns).Delete(tCtx, svcName, metav1.DeleteOptions{})
	if err != nil && !strings.Contains(err.Error(), "not found") {
		log.Printf("cross-cluster-routes: delete endpoints %s/%s failed: %v", ns, svcName, err)
	}

	// Delete Service
	err = cs.CoreV1().Services(ns).Delete(tCtx, svcName, metav1.DeleteOptions{})
	if err != nil {
		if !strings.Contains(err.Error(), "not found") {
			log.Printf("cross-cluster-routes: delete service %s/%s failed: %v", ns, svcName, err)
		}
		return
	}
	log.Printf("cross-cluster-routes: deleted service %s/%s (route %d)", ns, svcName, r.ID)
}

func (m *crossClusterRouteManager) fetchRoutes(ctx context.Context) ([]crossClusterRouteAssignment, error) {
	url := fmt.Sprintf("%s/api/v1/agent/cross-cluster-routes/clusters/%s", m.agent.BackendURL, m.agent.ClusterID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+m.agent.AgentToken)
	req.Header.Set("X-Cluster-ID", m.agent.ClusterID)

	resp, err := m.agent.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("backend returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Routes []crossClusterRouteAssignment `json:"routes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Routes, nil
}

func (m *crossClusterRouteManager) reportStatus(routeID uint, status, connectionMethod string) {
	url := fmt.Sprintf("%s/api/v1/agent/cross-cluster-routes/%d/status", m.agent.BackendURL, routeID)
	body, _ := json.Marshal(map[string]string{
		"status":            status,
		"connection_method": connectionMethod,
	})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.agent.AgentToken)
	req.Header.Set("X-Cluster-ID", m.agent.ClusterID)

	resp, err := m.agent.HTTPClient.Do(req)
	if err != nil {
		log.Printf("cross-cluster-routes: status report failed: %v", err)
		return
	}
	resp.Body.Close()
}

// ============================================================================
// Proxy Pod Management (main agent mode only)
// ============================================================================

const ccProxyPodName = "prysm-cc-proxy"

// ensureProxyPod creates the cross-cluster proxy pod if it doesn't exist.
// The proxy pod runs without hostNetwork, getting a Pod IP for Endpoints.
func (m *crossClusterRouteManager) ensureProxyPod(ctx context.Context) error {
	if m.proxyPodRunning {
		return nil
	}

	cs := m.agent.clientset
	if cs == nil {
		return fmt.Errorf("no kubernetes client")
	}

	ns := ccRouteAgentNamespace()
	tCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Check if pod already exists
	existing, err := cs.CoreV1().Pods(ns).Get(tCtx, ccProxyPodName, metav1.GetOptions{})
	if err == nil && existing.Status.Phase == corev1.PodRunning {
		m.proxyPodRunning = true
		log.Printf("cross-cluster-routes: proxy pod already running (IP: %s)", existing.Status.PodIP)
		return nil
	}

	// Get agent image from current pod (via downward API or default)
	agentImage := os.Getenv("AGENT_IMAGE")
	if agentImage == "" {
		agentImage = "172.21.0.17:5000/prysm/agent:latest" // Default for local dev
	}

	// Build environment variables for proxy pod
	envVars := []corev1.EnvVar{
		{Name: "BACKEND_URL", Value: m.agent.BackendURL},
		{Name: "AGENT_TOKEN", Value: m.agent.AgentToken},
		{Name: "CLUSTER_ID", Value: m.agent.ClusterID},
		{Name: "ORGANIZATION_ID", Value: fmt.Sprintf("%d", m.agent.OrganizationID)},
		{Name: "DERP_SERVERS", Value: strings.Join(m.agent.derpServers, ",")},
		{Name: "DERP_SKIP_TLS_VERIFY", Value: fmt.Sprintf("%v", m.agent.derpSkipVerify)},
		{Name: "POD_IP", ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{FieldPath: "status.podIP"},
		}},
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ccProxyPodName,
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "cc-proxy",
				"app.kubernetes.io/component": "cross-cluster",
				"prysm.sh/managed-by":         "prysm-agent",
			},
			Annotations: map[string]string{
				"prysm.sh/mesh-exclude": "true", // Exclude from mesh CNI to avoid circular dependency
			},
		},
		Spec: corev1.PodSpec{
			// NO hostNetwork - this is the key difference from main agent
			HostNetwork:        false,
			ServiceAccountName: "prysm-agent", // Reuse agent's SA
			Containers: []corev1.Container{
				{
					Name:    "cc-proxy",
					Image:   agentImage,
					Command: []string{"./prysm-agent", "--cc-proxy"},
					Env:     envVars,
					Ports: []corev1.ContainerPort{
						{Name: "health", ContainerPort: 8081, Protocol: corev1.ProtocolTCP},
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{Path: "/health", Port: intstr.FromInt32(8081)},
						},
						InitialDelaySeconds: 5,
						PeriodSeconds:       10,
					},
				},
			},
			RestartPolicy: corev1.RestartPolicyAlways,
		},
	}

	// Delete existing pod if not running (e.g., failed/pending)
	if existing != nil {
		_ = cs.CoreV1().Pods(ns).Delete(tCtx, ccProxyPodName, metav1.DeleteOptions{})
		time.Sleep(2 * time.Second) // Brief wait for deletion
	}

	_, err = cs.CoreV1().Pods(ns).Create(tCtx, pod, metav1.CreateOptions{})
	if err != nil && !isAlreadyExists(err) {
		return fmt.Errorf("create proxy pod: %w", err)
	}

	// Wait for pod to be running (use parent context, not the short tCtx)
	log.Printf("cross-cluster-routes: waiting for proxy pod to start...")
	for i := 0; i < 30; i++ {
		time.Sleep(2 * time.Second)
		waitCtx, waitCancel := context.WithTimeout(ctx, 5*time.Second)
		p, err := cs.CoreV1().Pods(ns).Get(waitCtx, ccProxyPodName, metav1.GetOptions{})
		waitCancel()
		if err != nil {
			continue
		}
		if p.Status.Phase == corev1.PodRunning && p.Status.PodIP != "" {
			m.proxyPodRunning = true
			log.Printf("cross-cluster-routes: proxy pod running (IP: %s)", p.Status.PodIP)
			return nil
		}
	}

	return fmt.Errorf("proxy pod not ready after 60s")
}

// getProxyPodIP returns the proxy pod's IP address.
func (m *crossClusterRouteManager) getProxyPodIP(ctx context.Context) string {
	cs := m.agent.clientset
	if cs == nil {
		return ""
	}

	ns := ccRouteAgentNamespace()
	tCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	pod, err := cs.CoreV1().Pods(ns).Get(tCtx, ccProxyPodName, metav1.GetOptions{})
	if err != nil {
		return ""
	}
	return pod.Status.PodIP
}

// deleteProxyPod removes the proxy pod when no routes exist.
func (m *crossClusterRouteManager) deleteProxyPod(ctx context.Context) {
	if !m.proxyPodRunning {
		return
	}

	cs := m.agent.clientset
	if cs == nil {
		return
	}

	ns := ccRouteAgentNamespace()
	tCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	err := cs.CoreV1().Pods(ns).Delete(tCtx, ccProxyPodName, metav1.DeleteOptions{})
	if err != nil && !strings.Contains(err.Error(), "not found") {
		log.Printf("cross-cluster-routes: delete proxy pod failed: %v", err)
		return
	}
	m.proxyPodRunning = false
	log.Printf("cross-cluster-routes: deleted proxy pod")
}
