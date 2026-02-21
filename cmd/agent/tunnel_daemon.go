// Package main provides the tunnel daemon for transparent mTLS encryption.
// The tunnel daemon acts as both client (outbound) and server (inbound) for
// traffic intercepted by prysm-cni iptables rules, wrapping it in mTLS using
// per-pod workload identity certificates.
//
// Architecture (NAT REDIRECT mode):
//
//	Pod A → iptables NAT REDIRECT:15001 → Tunnel Daemon (client) → mTLS → Tunnel Daemon (server) → Pod B
//	                                              ↑                                    ↑
//	                                    Pod A's cert                        Verify Pod A cert
//	                                    from cert store                     against Org CA
//
// The original destination is retrieved via SO_ORIGINAL_DST socket option.
// This approach is used by Istio/Envoy and is more reliable than TPROXY in containerized environments.

package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
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
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// DefaultOutboundPort is the port for iptables REDIRECT traffic
	DefaultOutboundPort = 15001

	// DefaultInboundPort is the mTLS server port for incoming tunnel connections
	DefaultInboundPort = 15002

	// DefaultBufferSize is the IO buffer size for proxying
	DefaultBufferSize = 32768

	// ConnectionTimeout is the timeout for establishing connections
	ConnectionTimeout = 10 * time.Second

	// IdleTimeout is the timeout for idle connections
	IdleTimeout = 5 * time.Minute

	// PQCEnabled controls whether Post-Quantum Cryptography is used
	// When enabled, uses ML-KEM-768 hybrid key exchange (X25519 + ML-KEM)
	PQCEnabled = true
)

// tunnelStats tracks statistics for the tunnel daemon
type tunnelStats struct {
	outboundConns      int64
	inboundConns       int64
	bytesProxied       int64
	certsIssued        int64
	connectionErrors   int64
	certErrors         int64
	pqcConnections     int64 // Connections using PQC key exchange
	packetsInspected   int64 // Packets that went through DPI
	threatsDetected    int64 // Threats detected by DPI
	connectionsBlocked int64 // Connections blocked due to threats
}

// getPQCCurvePreferences returns the curve preferences for PQC-enabled TLS.
// Uses hybrid X25519+ML-KEM-768 for post-quantum security with classical fallback.
// ML-KEM-768 provides NIST Level 3 security (equivalent to AES-192).
func getPQCCurvePreferences() []tls.CurveID {
	if PQCEnabled {
		return []tls.CurveID{
			tls.X25519MLKEM768, // Hybrid PQ: X25519 + ML-KEM-768
			tls.X25519,         // Fallback for non-PQC peers
			tls.CurveP256,      // Additional fallback
		}
	}
	return []tls.CurveID{tls.X25519, tls.CurveP256}
}

// isPQCConnection checks if the TLS connection likely used PQC key exchange.
// Since we configure both endpoints with X25519MLKEM768 as the preferred curve
// and require TLS 1.3, connections will use PQC when both sides support it.
// Note: Go's ConnectionState doesn't expose the negotiated curve directly,
// so we infer PQC usage from our configuration and TLS version.
func isPQCConnection(conn *tls.Conn) bool {
	state := conn.ConnectionState()
	// TLS 1.3 is required for PQC key exchange
	// If we're using TLS 1.3 and PQC is enabled in config, assume PQC was used
	return PQCEnabled && state.Version == tls.VersionTLS13
}

// tunnelDaemon implements a transparent proxy that wraps traffic in mTLS
type tunnelDaemon struct {
	agent            *PrysmAgent
	outboundLn       net.Listener // legacy host listener (unused when netns manager active)
	netnsMgr         *netnsListenerManager
	inboundLn        net.Listener // :15002 for mTLS server
	certStore        *podCertStore
	meshReporter     *MeshTopologyReporter
	bufferSize       int
	outboundPort     int
	inboundPort      int
	stats            tunnelStats
	activeConns      sync.WaitGroup
	shutdownCh       chan struct{}

	// Packet inspection (DPI)
	inspector          *MultiInspector
	inspectionConfig   *InspectionConfig
	inspectionConfigMu sync.RWMutex

	// DPI subsystems
	sigScanner    *NetworkSignatureScanner
	sigLoader     *SignatureLoader
	rateInspector *RateInspector
	dnsInspector  *DNSInspector
	tlsInspector  *TLSFingerprintInspector
	repInspector  *ReputationInspector
}

// newTunnelDaemon creates a new tunnel daemon
func newTunnelDaemon(agent *PrysmAgent) *tunnelDaemon {
	outboundPort := DefaultOutboundPort
	if p := os.Getenv("TUNNEL_DAEMON_OUTBOUND_PORT"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			outboundPort = parsed
		}
	}

	inboundPort := DefaultInboundPort
	if p := os.Getenv("TUNNEL_DAEMON_INBOUND_PORT"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			inboundPort = parsed
		}
	}

	bufferSize := DefaultBufferSize
	if s := os.Getenv("TUNNEL_DAEMON_BUFFER_SIZE"); s != "" {
		if parsed, err := strconv.Atoi(s); err == nil && parsed > 0 {
			bufferSize = parsed
		}
	}

	ttl := DefaultWorkloadCertTTL
	if t := os.Getenv("TUNNEL_DAEMON_CERT_TTL"); t != "" {
		if parsed, err := time.ParseDuration(t); err == nil && parsed > 0 {
			ttl = parsed
		}
	}

	// Initialize packet inspection configuration
	inspectionConfig := DefaultInspectionConfig()
	if e := os.Getenv("TUNNEL_DAEMON_DPI_ENABLED"); e != "" {
		inspectionConfig.Enabled = e == "true" || e == "1"
	}
	if m := os.Getenv("TUNNEL_DAEMON_DPI_MODE"); m != "" {
		if m == "block" {
			inspectionConfig.Mode = InspectionModeBlock
		} else {
			inspectionConfig.Mode = InspectionModeDetect
		}
	}

	// Initialize DPI subsystems
	sigScanner := NewNetworkSignatureScanner()
	httpInspector := NewHTTPRequestInspector()
	dnsInsp := NewDNSInspector()
	dlpInsp := NewDLPInspector()
	rateInsp := NewRateInspector()
	tlsInsp := NewTLSFingerprintInspector()
	repInsp := NewReputationInspector()

	// Build multi-inspector chain: signatures → HTTP → DNS → DLP → rate → TLS → reputation
	inspector := NewMultiInspector(
		sigScanner,
		httpInspector,
		dnsInsp,
		dlpInsp,
		rateInsp,
		tlsInsp,
		repInsp,
	)

	// Signature loader for hot-reloadable YAML signatures
	sigDir := DefaultSignatureDir
	if d := os.Getenv("PRYSM_DPI_SIGNATURES_DIR"); d != "" {
		sigDir = d
	}
	sigLoader := NewSignatureLoader(sigDir, sigScanner)

	td := &tunnelDaemon{
		agent:            agent,
		certStore:        newPodCertStore(agent, ttl),
		meshReporter:     NewMeshTopologyReporter(agent),
		bufferSize:       bufferSize,
		outboundPort:     outboundPort,
		inboundPort:      inboundPort,
		shutdownCh:       make(chan struct{}),
		inspector:        inspector,
		inspectionConfig: inspectionConfig,
		sigScanner:       sigScanner,
		sigLoader:        sigLoader,
		rateInspector:    rateInsp,
		dnsInspector:     dnsInsp,
		tlsInspector:     tlsInsp,
		repInspector:     repInsp,
	}
	td.netnsMgr = newNetnsListenerManager(td)

	if inspectionConfig.Enabled {
		log.Printf("tunnel: DPI enabled in %s mode with %d inspectors", inspectionConfig.Mode, len(inspector.inspectors))
	}

	return td
}

// Start initializes and starts the tunnel daemon
func (t *tunnelDaemon) Start(ctx context.Context) error {
	// Initialize certificate store
	if err := t.certStore.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize cert store: %w", err)
	}

	// Start certificate cleanup loop
	t.certStore.StartCleanupLoop(ctx)

	// Start netns listener manager: TPROXY rules are in each pod's netns, so we must
	// listen inside each pod's netns. The CNI writes netns paths to /var/run/prysm/tunnel-pods.
	if err := t.netnsMgr.Start(ctx); err != nil {
		return fmt.Errorf("failed to start netns listener manager: %w", err)
	}

	// Start host-level outbound listener for DNAT-redirected traffic.
	// The CNI iptables rules DNAT pod traffic to nodeIP:15001, so we need
	// a listener on the host network in addition to the per-pod netns listeners.
	outboundAddr := fmt.Sprintf(":%d", t.outboundPort)
	outboundLn, err := net.Listen("tcp", outboundAddr)
	if err != nil {
		log.Printf("tunnel: warning: failed to listen on outbound port %s: %v (DNAT mode unavailable)", outboundAddr, err)
	} else {
		t.outboundLn = outboundLn
		log.Printf("tunnel: listening for outbound DNAT traffic on %s", outboundAddr)
		go t.runOutbound(ctx)
	}

	// Start inbound listener with TLS
	inboundAddr := fmt.Sprintf(":%d", t.inboundPort)
	tlsConfig := t.buildServerTLSConfig()
	inboundLn, err := tls.Listen("tcp", inboundAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on inbound port %s: %w", inboundAddr, err)
	}
	t.inboundLn = inboundLn
	log.Printf("tunnel: listening for inbound mTLS connections on %s", inboundAddr)

	// Start mesh topology reporter (sends pod-to-pod connections to backend)
	if t.meshReporter != nil {
		t.meshReporter.Start(ctx)
	}

	// Start DPI subsystems
	if t.sigLoader != nil {
		t.sigLoader.Start()
	}
	if t.rateInspector != nil {
		t.rateInspector.StartCleanup()
	}
	if t.repInspector != nil {
		if t.agent.BackendURL != "" {
			t.repInspector.SetBackendConfig(t.agent.BackendURL, t.agent.ClusterID, t.agent.HTTPClient)
		}
		t.repInspector.Start()
	}

	// Start inbound and outbound handlers
	go t.runInbound(ctx)

	// Wait for shutdown
	go func() {
		<-ctx.Done()
		close(t.shutdownCh)
		if t.outboundLn != nil {
			t.outboundLn.Close()
		}
		t.inboundLn.Close()
	}()

	return nil
}

// buildServerTLSConfig creates the TLS config for the inbound mTLS server.
// Uses TLS 1.3 with ML-KEM-768 hybrid key exchange for post-quantum security.
func (t *tunnelDaemon) buildServerTLSConfig() *tls.Config {
	return &tls.Config{
		ClientCAs:        t.certStore.GetCACertPool(),
		ClientAuth:       tls.RequireAndVerifyClientCert,
		MinVersion:       tls.VersionTLS13, // TLS 1.3 required for PQC key exchange
		CurvePreferences: getPQCCurvePreferences(),
		// Dynamic certificate selection based on SNI (not used here, but could be)
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// For server mode, we use the agent's mTLS certificate
			// This identifies us as a valid tunnel daemon
			if t.agent.mtlsClient != nil && t.agent.mtlsClient.IsEnabled() {
				tlsConfig := t.agent.mtlsClient.GetTLSConfig()
				if tlsConfig != nil && len(tlsConfig.Certificates) > 0 {
					return &tlsConfig.Certificates[0], nil
				}
			}
			return nil, fmt.Errorf("no server certificate available")
		},
	}
}

// runInbound handles inbound connections (server mode)
func (t *tunnelDaemon) runInbound(ctx context.Context) {
	for {
		conn, err := t.inboundLn.Accept()
		if err != nil {
			select {
			case <-t.shutdownCh:
				return
			default:
				log.Printf("tunnel: inbound accept error: %v", err)
				continue
			}
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			conn.Close()
			continue
		}

		t.activeConns.Add(1)
		atomic.AddInt64(&t.stats.inboundConns, 1)
		go func() {
			defer t.activeConns.Done()
			t.handleInbound(ctx, tlsConn)
		}()
	}
}

// runOutbound accepts connections on the host-level outbound listener (:15001).
// Traffic arrives here via DNAT iptables rules set up by the CNI.
func (t *tunnelDaemon) runOutbound(ctx context.Context) {
	for {
		conn, err := t.outboundLn.Accept()
		if err != nil {
			select {
			case <-t.shutdownCh:
				return
			default:
				log.Printf("tunnel: outbound accept error: %v", err)
				continue
			}
		}

		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			conn.Close()
			continue
		}

		t.activeConns.Add(1)
		atomic.AddInt64(&t.stats.outboundConns, 1)
		go func() {
			defer t.activeConns.Done()
			t.handleOutboundInNetns(ctx, tcpConn, "host")
		}()
	}
}

// handleOutboundInNetns processes an outbound connection from a local pod.
// Connection is accepted in pod's netns (via NAT REDIRECT), but dial goes to host netns
// where kube-proxy rules can route to service IPs.
func (t *tunnelDaemon) handleOutboundInNetns(ctx context.Context, conn *net.TCPConn, podUID string) {
	defer conn.Close()

	// For NAT REDIRECT mode: use SO_ORIGINAL_DST to get the original destination
	// This is how Istio/Envoy handle transparent proxying
	origIP, origPort, err := getOriginalDst(conn)
	if err != nil {
		log.Printf("tunnel: SO_ORIGINAL_DST failed for pod %s: %v", podUID, err)
		return
	}

	// Validate we got a real destination (not localhost or our proxy port)
	if origIP.IsLoopback() || origPort == t.outboundPort {
		log.Printf("tunnel: invalid original dest for pod %s: %s:%d (loopback or proxy port)", podUID, origIP, origPort)
		return
	}

	// Skip if destination is our own tunnel daemon ports (avoid loop)
	if origPort == t.outboundPort || origPort == t.inboundPort {
		return
	}

	// Skip if destination is still localhost (shouldn't happen after fallback)
	if origIP.IsLoopback() || (origIP.IsUnspecified() && origPort == t.outboundPort) {
		return
	}

	srcIP := conn.RemoteAddr().(*net.TCPAddr).IP
	log.Printf("tunnel: outbound from %s -> %s:%d (pod %s)", srcIP, origIP, origPort, podUID)

	// Check if destination is a cross-cluster route
	if t.agent.ccRouteManager != nil {
		if route, ok := t.agent.ccRouteManager.LookupByServiceIP(origIP.String(), origPort); ok {
			log.Printf("tunnel: routing to cross-cluster route %d (%s) via DERP", route.ID, route.Name)
			t.agent.ccRouteManager.ProxyConnection(ctx, route, conn)
			return
		}
	}

	// Lookup source pod for topology
	srcPod, _ := t.lookupPodByIP(ctx, srcIP)

	// Lookup destination pod - first try direct pod IP, then try service IP resolution
	dstPod, _ := t.lookupPodByIP(ctx, origIP)
	if dstPod == nil {
		// origIP might be a ClusterIP service - try to resolve via endpoints
		dstPod, _ = t.lookupPodByServiceIP(ctx, origIP, origPort)
	}

	// Dial destination from HOST network namespace (not pod netns)
	// This is required because kube-proxy iptables rules that route service IPs
	// to pod IPs are only present in the host netns, not inside each pod's netns.
	destAddr := net.JoinHostPort(origIP.String(), strconv.Itoa(origPort))
	dialer := &net.Dialer{Timeout: ConnectionTimeout}
	destConn, err := dialer.DialContext(ctx, "tcp", destAddr)
	if err != nil {
		log.Printf("tunnel: failed to dial %s: %v", destAddr, err)
		atomic.AddInt64(&t.stats.connectionErrors, 1)
		return
	}
	defer destConn.Close()

	// Record topology before proxy (for real-time visibility)
	if t.meshReporter != nil {
		srcNs, srcName := "unknown", "pod-"+srcIP.String()
		dstNs, dstName := "unknown", "pod-"+origIP.String()
		if srcPod != nil {
			srcNs, srcName = srcPod.Namespace, srcPod.Name
		}
		if dstPod != nil {
			dstNs, dstName = dstPod.Namespace, dstPod.Name
		}
		t.meshReporter.RecordConnection(srcNs, srcName, dstNs, dstName, origPort, 0, 0)
	}

	// Bidirectional proxy with DPI inspection
	t.proxyWithContext(conn, destConn, srcPod, dstPod)
}

// handleOutbound processes an outbound connection from a local pod
func (t *tunnelDaemon) handleOutbound(ctx context.Context, conn *net.TCPConn) {
	defer conn.Close()

	// For TPROXY mode: the local address of the accepted connection IS the original destination
	// This is because TPROXY preserves the original destination in the socket
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	origIP := localAddr.IP
	origPort := localAddr.Port

	// Skip if destination is our own tunnel daemon ports (avoid loop)
	if origPort == t.outboundPort || origPort == t.inboundPort {
		return // Silently skip self-connections
	}

	// Skip if destination is localhost or our listener address
	if origIP.IsLoopback() || (origIP.IsUnspecified() && origPort == t.outboundPort) {
		return
	}

	srcIP := conn.RemoteAddr().(*net.TCPAddr).IP
	log.Printf("tunnel: outbound from %s -> %s:%d", srcIP, origIP, origPort)

	// Check if destination is local (same node) - skip tunnel for local traffic
	if isLocalIP(origIP) {
		// Lookup pods for topology recording
		localSrcPod, srcErr := t.lookupPodByIP(ctx, srcIP)
		localDstPod, dstErr := t.lookupPodByIP(ctx, origIP)
		// Direct connection to local destination
		localAddr := net.JoinHostPort(origIP.String(), strconv.Itoa(origPort))
		localConn, err := net.DialTimeout("tcp", localAddr, ConnectionTimeout)
		if err != nil {
			log.Printf("tunnel: failed to connect to local %s: %v", localAddr, err)
			atomic.AddInt64(&t.stats.connectionErrors, 1)
			return
		}
		defer localConn.Close()
		result := t.proxy(conn, localConn)
		// Record topology after proxy with actual byte counts
		if srcErr == nil && dstErr == nil && t.meshReporter != nil {
			t.meshReporter.RecordConnection(localSrcPod.Namespace, localSrcPod.Name, localDstPod.Namespace, localDstPod.Name, origPort, result.bytesSent, result.bytesRecv)
		}
		return
	}

	// 2. Lookup source and destination pods
	srcPod, err := t.lookupPodByIP(ctx, srcIP)
	if err != nil {
		log.Printf("tunnel: failed to lookup pod for IP %s: %v", srcIP, err)
		atomic.AddInt64(&t.stats.connectionErrors, 1)
		return
	}
	dstPod, dstErr := t.lookupPodByIP(ctx, origIP)

	// Destination is not a pod (e.g. Service ClusterIP, external host): use direct connection.
	// No mTLS needed; pass through to origIP:origPort.
	if dstErr != nil {
		localAddr := net.JoinHostPort(origIP.String(), strconv.Itoa(origPort))
		localConn, dialErr := net.DialTimeout("tcp", localAddr, ConnectionTimeout)
		if dialErr == nil {
			defer localConn.Close()
			t.proxy(conn, localConn)
			return
		}
		log.Printf("tunnel: failed to connect to non-pod %s: %v", localAddr, dialErr)
		atomic.AddInt64(&t.stats.connectionErrors, 1)
		return
	}

	// Same-node pod-to-pod: bypass mTLS (avoids cert issuance), record topology, direct proxy.
	// Pod IPs are not in node InterfaceAddrs, so isLocalIP is false; check NodeName instead.
	if srcPod.Spec.NodeName != "" && srcPod.Spec.NodeName == dstPod.Spec.NodeName {
		localAddr := net.JoinHostPort(origIP.String(), strconv.Itoa(origPort))
		localConn, err := net.DialTimeout("tcp", localAddr, ConnectionTimeout)
		if err != nil {
			log.Printf("tunnel: failed to connect to same-node pod %s: %v", localAddr, err)
			atomic.AddInt64(&t.stats.connectionErrors, 1)
			return
		}
		defer localConn.Close()
		result := t.proxy(conn, localConn)
		if t.meshReporter != nil {
			t.meshReporter.RecordConnection(srcPod.Namespace, srcPod.Name, dstPod.Namespace, dstPod.Name, origPort, result.bytesSent, result.bytesRecv)
		}
		return
	}

	// 3. Remote pod: require mTLS
	pod := srcPod

	// 4. Get or issue certificate for this pod (required for cross-node mTLS)
	cert, err := t.certStore.GetOrIssue(ctx, pod.Namespace, pod.Name)
	if err != nil {
		log.Printf("tunnel: failed to get cert for %s/%s: %v", pod.Namespace, pod.Name, err)
		atomic.AddInt64(&t.stats.certErrors, 1)
		return
	}
	atomic.AddInt64(&t.stats.certsIssued, 1)

	// 5. Create TLS config with pod's certificate and PQC key exchange
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{*cert.cert},
		RootCAs:            t.certStore.GetCACertPool(),
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13, // TLS 1.3 required for PQC
		CurvePreferences:   getPQCCurvePreferences(),
		// Use original IP as server name for certificate verification
		ServerName: origIP.String(),
	}

	// 6. Connect to destination's tunnel daemon on inbound port
	destAddr := net.JoinHostPort(origIP.String(), strconv.Itoa(t.inboundPort))
	dialer := &net.Dialer{Timeout: ConnectionTimeout}
	destConn, err := tls.DialWithDialer(dialer, "tcp", destAddr, tlsConfig)
	if err != nil {
		// Fallback: tunnel daemon unreachable (e.g. agent as Deployment, hostNetwork pod dest).
		// Use direct connection to origIP:origPort.
		fallbackDstPod, lookupErr := t.lookupPodByIP(ctx, origIP)
		localAddr := net.JoinHostPort(origIP.String(), strconv.Itoa(origPort))
		if localConn, dialErr := net.DialTimeout("tcp", localAddr, ConnectionTimeout); dialErr == nil {
			defer localConn.Close()
			result := t.proxy(conn, localConn)
			if lookupErr == nil && t.meshReporter != nil {
				t.meshReporter.RecordConnection(pod.Namespace, pod.Name, fallbackDstPod.Namespace, fallbackDstPod.Name, origPort, result.bytesSent, result.bytesRecv)
			}
			return
		}
		log.Printf("tunnel: failed to dial %s: %v", destAddr, err)
		atomic.AddInt64(&t.stats.connectionErrors, 1)
		return
	}
	defer destConn.Close()

	// Track PQC usage
	if isPQCConnection(destConn) {
		atomic.AddInt64(&t.stats.pqcConnections, 1)
	}

	// 7. Send original port as first message (simple protocol)
	if err := binary.Write(destConn, binary.BigEndian, uint16(origPort)); err != nil {
		log.Printf("tunnel: failed to write target port: %v", err)
		atomic.AddInt64(&t.stats.connectionErrors, 1)
		return
	}

	// 7b. Bidirectional proxy, then record topology with actual byte counts
	result := t.proxy(conn, destConn)
	if remoteDstPod, lookupErr := t.lookupPodByIP(ctx, origIP); lookupErr == nil && t.meshReporter != nil {
		t.meshReporter.RecordConnection(pod.Namespace, pod.Name, remoteDstPod.Namespace, remoteDstPod.Name, origPort, result.bytesSent, result.bytesRecv)
	}
}

// handleInbound processes an inbound mTLS connection from another tunnel daemon
func (t *tunnelDaemon) handleInbound(ctx context.Context, conn *tls.Conn) {
	defer conn.Close()

	// Set deadline for handshake
	conn.SetDeadline(time.Now().Add(ConnectionTimeout))

	// Complete TLS handshake
	if err := conn.Handshake(); err != nil {
		log.Printf("tunnel: TLS handshake failed: %v", err)
		atomic.AddInt64(&t.stats.connectionErrors, 1)
		return
	}

	// Reset deadline
	conn.SetDeadline(time.Time{})

	// 1. Verify peer certificate (already done by TLS handshake)
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		log.Println("tunnel: no peer certificate")
		atomic.AddInt64(&t.stats.connectionErrors, 1)
		return
	}
	peerCert := state.PeerCertificates[0]

	// Track PQC usage on inbound (inferred from TLS 1.3 + PQC config)
	if PQCEnabled && state.Version == tls.VersionTLS13 {
		atomic.AddInt64(&t.stats.pqcConnections, 1)
	}

	// Extract identity from SAN
	identity := GetIdentityFromCert(peerCert)
	if identity == "" {
		log.Println("tunnel: peer certificate has no SPIFFE identity")
		atomic.AddInt64(&t.stats.certErrors, 1)
		return
	}

	// 2. Read target port from first message
	var targetPort uint16
	if err := binary.Read(conn, binary.BigEndian, &targetPort); err != nil {
		log.Printf("tunnel: failed to read target port: %v", err)
		atomic.AddInt64(&t.stats.connectionErrors, 1)
		return
	}

	// 3. Connect to local destination pod
	// The destination is localhost since this is the target node
	localAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(targetPort)))
	localConn, err := net.DialTimeout("tcp", localAddr, ConnectionTimeout)
	if err != nil {
		log.Printf("tunnel: failed to connect to local %s: %v", localAddr, err)
		atomic.AddInt64(&t.stats.connectionErrors, 1)
		return
	}
	defer localConn.Close()

	log.Printf("tunnel: inbound connection from %s to port %d", identity, targetPort)

	// 4. Bidirectional proxy
	t.proxy(conn, localConn)
}

// proxyResult holds the byte counts from a completed proxy session
type proxyResult struct {
	bytesSent int64 // client → server
	bytesRecv int64 // server → client
}

// proxy performs bidirectional data copy between two connections
func (t *tunnelDaemon) proxy(client, server net.Conn) proxyResult {
	return t.proxyWithContext(client, server, nil, nil)
}

// proxyWithContext performs bidirectional data copy with optional inspection context
func (t *tunnelDaemon) proxyWithContext(client, server net.Conn, srcPod, dstPod *corev1.Pod) proxyResult {
	var wg sync.WaitGroup
	wg.Add(2)

	var bytesSent, bytesRecv int64

	// Build inspection context if DPI is enabled
	// Get current inspection config (thread-safe)
	t.inspectionConfigMu.RLock()
	inspCfg := t.inspectionConfig
	t.inspectionConfigMu.RUnlock()

	var inspCtx *InspectionContext
	if inspCfg != nil && inspCfg.Enabled && t.inspector != nil {
		clientAddr := client.RemoteAddr()
		serverAddr := server.RemoteAddr()

		var srcIP, dstIP net.IP
		var srcPort, dstPort int
		if tcpAddr, ok := clientAddr.(*net.TCPAddr); ok {
			srcIP = tcpAddr.IP
			srcPort = tcpAddr.Port
		}
		if tcpAddr, ok := serverAddr.(*net.TCPAddr); ok {
			dstIP = tcpAddr.IP
			dstPort = tcpAddr.Port
		}

		inspCtx = &InspectionContext{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Protocol: "tcp",
			Stream:   NewStreamState(),
		}

		// Add pod context if available
		if srcPod != nil {
			inspCtx.PodName = srcPod.Name
			inspCtx.PodNS = srcPod.Namespace
		}
	}

	// Threat callback for logging and metrics
	onThreat := func(result InspectionResult) {
		atomic.AddInt64(&t.stats.threatsDetected, 1)
		log.Printf("tunnel: DPI threat detected: %s (level=%s, category=%s, score=%d)",
			result.Description, result.ThreatLevel.String(), result.Category, result.Score)

		// Report to mesh reporter for analytics
		if t.meshReporter != nil && srcPod != nil {
			t.meshReporter.RecordThreat(srcPod.Namespace, srcPod.Name, result)
		}

		if result.ShouldBlock {
			atomic.AddInt64(&t.stats.connectionsBlocked, 1)
			if t.inspector != nil {
				t.inspector.IncrementBlocked()
			}
		}
	}

	copyWithInspection := func(dst, src net.Conn, direction string, counter *int64) {
		defer wg.Done()

		var reader io.Reader = src
		if inspCfg != nil && inspCfg.Enabled && t.inspector != nil && inspCtx != nil {
			// Wrap reader with inspecting reader (uses config captured at connection start)
			reader = NewInspectingReader(
				src,
				t.inspector,
				inspCtx,
				inspCfg,
				direction,
				onThreat,
			)
			atomic.AddInt64(&t.stats.packetsInspected, 1)
		}

		buf := make([]byte, t.bufferSize)
		n, err := io.CopyBuffer(dst, reader, buf)
		atomic.AddInt64(&t.stats.bytesProxied, n)
		atomic.AddInt64(counter, n)

		// Log if connection was blocked by DPI
		if err != nil {
			if _, ok := err.(*InspectionBlockedError); ok {
				log.Printf("tunnel: connection blocked by DPI: %v", err)
			}
		}

		// Close write side to signal EOF
		if tcpConn, ok := dst.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}

	go copyWithInspection(server, client, "outbound", &bytesSent)
	go copyWithInspection(client, server, "inbound", &bytesRecv)

	wg.Wait()

	return proxyResult{bytesSent: bytesSent, bytesRecv: bytesRecv}
}

// lookupPodByIP finds a pod by its IP address using the Kubernetes API
func (t *tunnelDaemon) lookupPodByIP(ctx context.Context, ip net.IP) (*corev1.Pod, error) {
	if t.agent.clientset == nil {
		return nil, fmt.Errorf("kubernetes client not available")
	}

	ipStr := ip.String()

	// List all pods and find by IP
	// In production, consider caching this or using a watch
	pods, err := t.agent.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("status.podIP=%s", ipStr),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no pod found with IP %s", ipStr)
	}

	return &pods.Items[0], nil
}

// lookupPodByServiceIP finds a pod behind a Kubernetes Service ClusterIP.
// When the original destination is a service IP (not a pod IP), this resolves
// the service to one of its endpoint pods for topology recording.
func (t *tunnelDaemon) lookupPodByServiceIP(ctx context.Context, serviceIP net.IP, port int) (*corev1.Pod, error) {
	if t.agent.clientset == nil {
		return nil, fmt.Errorf("kubernetes client not available")
	}

	ipStr := serviceIP.String()

	// Find the service with this ClusterIP
	services, err := t.agent.clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	for _, svc := range services.Items {
		if svc.Spec.ClusterIP == ipStr {
			// Found the service - now get its endpoints
			endpoints, err := t.agent.clientset.CoreV1().Endpoints(svc.Namespace).Get(ctx, svc.Name, metav1.GetOptions{})
			if err != nil {
				continue
			}
			// Return the first endpoint pod
			for _, subset := range endpoints.Subsets {
				for _, addr := range subset.Addresses {
					if addr.TargetRef != nil && addr.TargetRef.Kind == "Pod" {
						pod, err := t.agent.clientset.CoreV1().Pods(svc.Namespace).Get(ctx, addr.TargetRef.Name, metav1.GetOptions{})
						if err == nil {
							return pod, nil
						}
					}
					// Fallback: lookup by endpoint IP
					if addr.IP != "" {
						epIP := net.ParseIP(addr.IP)
						if epIP != nil {
							return t.lookupPodByIP(ctx, epIP)
						}
					}
				}
			}
			return nil, fmt.Errorf("service %s/%s has no ready endpoints", svc.Namespace, svc.Name)
		}
	}

	return nil, fmt.Errorf("no service found with ClusterIP %s", ipStr)
}

// Stats returns current tunnel statistics
func (t *tunnelDaemon) Stats() map[string]interface{} {
	certStats := t.certStore.Stats()

	stats := map[string]interface{}{
		"outbound_connections": atomic.LoadInt64(&t.stats.outboundConns),
		"inbound_connections":  atomic.LoadInt64(&t.stats.inboundConns),
		"bytes_proxied":        atomic.LoadInt64(&t.stats.bytesProxied),
		"certs_issued":         atomic.LoadInt64(&t.stats.certsIssued),
		"connection_errors":    atomic.LoadInt64(&t.stats.connectionErrors),
		"cert_errors":          atomic.LoadInt64(&t.stats.certErrors),
		"pqc_connections":      atomic.LoadInt64(&t.stats.pqcConnections),
		"pqc_enabled":          PQCEnabled,
		"pqc_algorithm":        "ML-KEM-768 (X25519 hybrid)",
		"outbound_port":        t.outboundPort,
		"inbound_port":         t.inboundPort,
		"cert_store":           certStats,
	}

	// Add DPI stats (thread-safe read)
	t.inspectionConfigMu.RLock()
	cfg := t.inspectionConfig
	t.inspectionConfigMu.RUnlock()

	if cfg != nil {
		stats["dpi_enabled"] = cfg.Enabled
		stats["dpi_mode"] = string(cfg.Mode)
		stats["packets_inspected"] = atomic.LoadInt64(&t.stats.packetsInspected)
		stats["threats_detected"] = atomic.LoadInt64(&t.stats.threatsDetected)
		stats["connections_blocked"] = atomic.LoadInt64(&t.stats.connectionsBlocked)

		if t.inspector != nil {
			stats["dpi_details"] = t.inspector.Stats()
		}
	}

	return stats
}

// GetInspectionConfig returns a copy of the current inspection configuration
func (t *tunnelDaemon) GetInspectionConfig() *InspectionConfig {
	t.inspectionConfigMu.RLock()
	defer t.inspectionConfigMu.RUnlock()

	if t.inspectionConfig == nil {
		return nil
	}

	// Return a copy to avoid race conditions
	cfg := *t.inspectionConfig
	return &cfg
}

// SetInspectionConfig updates the inspection configuration at runtime
func (t *tunnelDaemon) SetInspectionConfig(cfg *InspectionConfig) {
	t.inspectionConfigMu.Lock()
	defer t.inspectionConfigMu.Unlock()

	oldEnabled := t.inspectionConfig != nil && t.inspectionConfig.Enabled
	oldMode := InspectionModeDetect
	if t.inspectionConfig != nil {
		oldMode = t.inspectionConfig.Mode
	}

	t.inspectionConfig = cfg

	// Log the change
	if cfg == nil {
		log.Println("tunnel: DPI configuration cleared")
	} else if oldEnabled != cfg.Enabled {
		if cfg.Enabled {
			log.Printf("tunnel: DPI enabled in %s mode", cfg.Mode)
		} else {
			log.Println("tunnel: DPI disabled")
		}
	} else if oldMode != cfg.Mode {
		log.Printf("tunnel: DPI mode changed from %s to %s", oldMode, cfg.Mode)
	}
}

// UpdateInspectionMode updates just the inspection mode (detect/block) at runtime
func (t *tunnelDaemon) UpdateInspectionMode(mode InspectionMode) {
	t.inspectionConfigMu.Lock()
	defer t.inspectionConfigMu.Unlock()

	if t.inspectionConfig == nil {
		t.inspectionConfig = DefaultInspectionConfig()
	}

	oldMode := t.inspectionConfig.Mode
	t.inspectionConfig.Mode = mode

	if oldMode != mode {
		log.Printf("tunnel: DPI mode changed from %s to %s", oldMode, mode)
	}
}

// SetInspectionEnabled enables or disables inspection at runtime
func (t *tunnelDaemon) SetInspectionEnabled(enabled bool) {
	t.inspectionConfigMu.Lock()
	defer t.inspectionConfigMu.Unlock()

	if t.inspectionConfig == nil {
		t.inspectionConfig = DefaultInspectionConfig()
	}

	oldEnabled := t.inspectionConfig.Enabled
	t.inspectionConfig.Enabled = enabled

	if oldEnabled != enabled {
		if enabled {
			log.Printf("tunnel: DPI enabled in %s mode", t.inspectionConfig.Mode)
		} else {
			log.Println("tunnel: DPI disabled")
		}
	}
}

// Shutdown gracefully shuts down the tunnel daemon
func (t *tunnelDaemon) Shutdown(ctx context.Context) error {
	close(t.shutdownCh)

	// Stop DPI subsystems
	if t.sigLoader != nil {
		t.sigLoader.Stop()
	}
	if t.rateInspector != nil {
		t.rateInspector.Stop()
	}
	if t.repInspector != nil {
		t.repInspector.Stop()
	}

	// Close listeners (netns manager stops via context)
	if t.outboundLn != nil {
		t.outboundLn.Close()
	}
	if t.inboundLn != nil {
		t.inboundLn.Close()
	}

	// Wait for active connections with timeout
	done := make(chan struct{})
	go func() {
		t.activeConns.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("tunnel: all connections closed")
	case <-ctx.Done():
		log.Println("tunnel: shutdown timeout, some connections may be orphaned")
	}

	return nil
}

// startTunnelDaemon is called from main.go to start the tunnel daemon
func (a *PrysmAgent) startTunnelDaemon(ctx context.Context) {
	daemon := newTunnelDaemon(a)

	if err := daemon.Start(ctx); err != nil {
		log.Printf("tunnel: failed to start: %v", err)
		return
	}

	// Store reference for status endpoint
	a.tunnelDaemon = daemon

	if PQCEnabled {
		log.Printf("tunnel: daemon started with PQC (ML-KEM-768 hybrid) (outbound:%d, inbound:%d)",
			daemon.outboundPort, daemon.inboundPort)
	} else {
		log.Printf("tunnel: daemon started (outbound:%d, inbound:%d)",
			daemon.outboundPort, daemon.inboundPort)
	}

	// Wait for shutdown
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := daemon.Shutdown(shutdownCtx); err != nil {
		log.Printf("tunnel: shutdown error: %v", err)
	}
}

// dpiConfigPollLoop periodically fetches DPI configuration from the backend
// and applies it to the tunnel daemon. This allows the UI to control DPI
// settings without requiring agent restarts or env var changes.
func (a *PrysmAgent) dpiConfigPollLoop(ctx context.Context) {
	// Wait for the tunnel daemon to start
	for a.tunnelDaemon == nil {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}

	// Initial fetch
	a.fetchAndApplyDPIConfig(ctx)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.fetchAndApplyDPIConfig(ctx)
		}
	}
}

func (a *PrysmAgent) fetchAndApplyDPIConfig(parent context.Context) {
	if a.BackendURL == "" || a.ClusterID == "" {
		return
	}

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s/api/v1/agent/dpi/config", strings.TrimRight(a.BackendURL, "/"))
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Cluster-ID", a.ClusterID)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return
	}

	var cfg struct {
		Enabled    bool   `json:"enabled"`
		Mode       string `json:"mode"`
		OnCritical string `json:"onCritical"`
		OnHigh     string `json:"onHigh"`
		OnMedium   string `json:"onMedium"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return
	}

	// Apply to tunnel daemon
	current := a.tunnelDaemon.GetInspectionConfig()
	if current == nil {
		current = DefaultInspectionConfig()
	}

	changed := current.Enabled != cfg.Enabled ||
		string(current.Mode) != cfg.Mode ||
		current.OnCritical != cfg.OnCritical ||
		current.OnHigh != cfg.OnHigh ||
		current.OnMedium != cfg.OnMedium

	if !changed {
		return
	}

	current.Enabled = cfg.Enabled
	if cfg.Mode == "block" {
		current.Mode = InspectionModeBlock
	} else {
		current.Mode = InspectionModeDetect
	}
	current.OnCritical = cfg.OnCritical
	current.OnHigh = cfg.OnHigh
	current.OnMedium = cfg.OnMedium

	a.tunnelDaemon.SetInspectionConfig(current)
}
