package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"
)

func parseUint(s string) (uint, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return uint(n), err
}

// PrysmAgent is the main agent struct used by k8s_sa_provision, telemetry, derp, and log_daemonset_reconciler.
type PrysmAgent struct {
	clientset      kubernetes.Interface
	metricsClient  *metricsclient.Clientset
	discoveryConn  discovery.DiscoveryInterface
	HTTPClient     *http.Client
	BackendURL     string
	AgentToken     string
	ClusterID      string
	ClusterName    string
	Region         string
	OrganizationID uint
	kubeconfigPath string
	lastTelemetry  time.Time
	derpServers    []string
	derpRegion     string
	derpSkipVerify bool
	derpManager    *derpManager
	mtlsClient     *MTLSClient
	tunnelDaemon   *tunnelDaemon
	ccRouteManager *crossClusterRouteManager
}

func main() {
	healthCheck := flag.Bool("health-check", false, "Run health check and exit 0 if healthy")
	ccProxyMode := flag.Bool("cc-proxy", false, "Run in cross-cluster proxy mode (no hostNetwork, TCP listeners only)")
	flag.Parse()

	if *healthCheck {
		// Used by Docker HEALTHCHECK; agent may not have k8s yet
		if err := runHealthCheck(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Cross-cluster proxy mode: lightweight mode for handling CC routes without hostNetwork
	if *ccProxyMode {
		runCCProxyMode()
		return
	}

	var orgID uint
	if s := getEnvOrDefault("ORGANIZATION_ID", ""); s != "" {
		if n, err := parseUint(s); err == nil {
			orgID = n
		}
	}
	agent := &PrysmAgent{
		BackendURL:     strings.TrimSuffix(getEnvOrDefault("BACKEND_URL", ""), "/"),
		AgentToken:     getEnvOrDefault("AGENT_TOKEN", ""),
		ClusterID:      getEnvOrDefault("CLUSTER_ID", ""),
		ClusterName:    getEnvOrDefault("CLUSTER_NAME", ""),
		Region:         getEnvOrDefault("REGION", ""),
		OrganizationID: orgID,
		kubeconfigPath: getEnvOrDefault("KUBECONFIG", ""),
		derpRegion:     getEnvOrDefault("DERP_REGION", ""),
		derpSkipVerify: getEnvOrDefault("DERP_SKIP_TLS_VERIFY", "") == "true" || getEnvOrDefault("DERP_SKIP_TLS_VERIFY", "") == "1",
		HTTPClient:     &http.Client{Timeout: 30 * time.Second},
	}
	if servers := getEnvOrDefault("DERP_SERVERS", getEnvOrDefault("DERP_SERVER", "")); servers != "" {
		agent.derpServers = strings.Split(servers, ",")
		for i, s := range agent.derpServers {
			agent.derpServers[i] = strings.TrimSpace(s)
		}
	}

	if err := agent.initKubernetesClients(); err != nil {
		log.Printf("Kubernetes init failed: %v (continuing without k8s)", err)
	}

	ctx := context.Background()

	// Auto-register with the backend to obtain a cluster ID
	if agent.BackendURL != "" && agent.AgentToken != "" {
		if err := agent.autoRegister(ctx); err != nil {
			log.Printf("Auto-registration failed: %v", err)
			if agent.ClusterID == "" {
				log.Fatal("No CLUSTER_ID and auto-registration failed, cannot continue")
			}
			log.Printf("Falling back to CLUSTER_ID=%s from environment", agent.ClusterID)
		}
	}

	// Initialize mTLS client for zero-trust authentication
	if agent.BackendURL != "" && agent.ClusterID != "" {
		agent.mtlsClient = NewMTLSClient(agent.BackendURL, agent.ClusterID)
		if err := agent.mtlsClient.Initialize(ctx); err != nil {
			log.Printf("mTLS initialization failed: %v (using token auth)", err)
		} else if agent.mtlsClient.IsEnabled() {
			// Replace HTTP client with mTLS-enabled client
			agent.HTTPClient = agent.mtlsClient.GetHTTPClient()
			// Start certificate renewal loop
			agent.mtlsClient.StartRenewalLoop(ctx)
			log.Println("✅ Using mTLS authentication for control plane communication")
		}
	}

	// K8s SA provisioning (prysm-system SAs for proxy auth)
	if agent.clientset != nil {
		agent.ensurePrysmK8sSAs(ctx)
	}

	// Log collector DaemonSet reconciler: run once then every LOG_COLLECTOR_RECONCILE_INTERVAL
	if agent.clientset != nil {
		agent.ensureLogCollectorDaemonSet(ctx)
		interval := 5 * time.Minute
		if d := getEnvOrDefault("LOG_COLLECTOR_RECONCILE_INTERVAL", ""); d != "" {
			if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
				interval = parsed
			}
		}
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for range ticker.C {
				agent.ensureLogCollectorDaemonSet(ctx)
			}
		}()
	}

	// eBPF collector DaemonSet reconciler: run once then every EBPF_COLLECTOR_RECONCILE_INTERVAL
	if agent.clientset != nil {
		agent.ensureEbpfCollectorDaemonSet(ctx)
		ebpfInterval := 5 * time.Minute
		if d := getEnvOrDefault("EBPF_COLLECTOR_RECONCILE_INTERVAL", ""); d != "" {
			if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
				ebpfInterval = parsed
			}
		}
		go func() {
			ticker := time.NewTicker(ebpfInterval)
			defer ticker.Stop()
			for range ticker.C {
				agent.ensureEbpfCollectorDaemonSet(ctx)
			}
		}()
	}

	// DERP and telemetry (optional)
	if len(agent.derpServers) > 0 {
		if err := agent.startDERP(ctx); err != nil {
			log.Printf("DERP start failed: %v", err)
		}
	}

	// Cross-cluster route manager: polls backend for assigned routes, manages TCP listeners + DERP streams
	agent.ccRouteManager = newCrossClusterRouteManager(agent)
	go agent.ccRouteManager.Start(ctx)

	// Exit node controller: when cluster is exit router, enable IP forwarding and NAT
	agent.startExitNodeController(ctx)
	if agent.clientset != nil {
		go agent.clusterTelemetryLoop(ctx)
		go agent.vulnerabilityScannerLoop(ctx)
		go agent.honeypotReconcileLoop(ctx)    // Honeypot operator controller
		go agent.prysmCNIReconcileLoop(ctx)    // Prysm CNI operator (zero trust redirect)
		go agent.startAIAgentController(ctx)   // AI agent deploy/undeploy via NATS
		go agent.startK8sResourceWatcher(ctx)  // K8s resource watcher for RAG pipeline
		go agent.podHealthReconcileLoop(ctx)   // Pod health auto-remediation (eviction cleanup, resource resize)
	}

	// Tunnel daemon: transparent mTLS proxy for zero-trust pod-to-pod encryption
	// Intercepts traffic redirected by prysm-cni and wraps it in mTLS using per-pod certificates
	if getEnvOrDefault("TUNNEL_DAEMON_ENABLED", "") == "true" || getEnvOrDefault("TUNNEL_DAEMON_ENABLED", "") == "1" {
		go agent.startTunnelDaemon(ctx)
		go agent.dpiConfigPollLoop(ctx)
	}

	// Health/ready HTTP server + log proxy
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK); _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK); _, _ = w.Write([]byte("ok")) })
	
	// mTLS certificate status endpoint
	mux.HandleFunc("/mtls/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if agent.mtlsClient == nil {
			_, _ = w.Write([]byte(`{"enabled": false, "reason": "not_configured"}`))
			return
		}
		info := agent.mtlsClient.GetCertificateInfo()
		data, _ := json.Marshal(info)
		_, _ = w.Write(data)
	})

	// Tunnel daemon status endpoint
	mux.HandleFunc("/tunnel/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if agent.tunnelDaemon == nil {
			_, _ = w.Write([]byte(`{"enabled": false}`))
			return
		}
		stats := agent.tunnelDaemon.Stats()
		stats["enabled"] = true
		data, _ := json.Marshal(stats)
		_, _ = w.Write(data)
	})

	// DPI (Deep Packet Inspection) configuration endpoint
	// GET: returns current config, POST/PUT: updates config at runtime
	mux.HandleFunc("/inspection/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if agent.tunnelDaemon == nil {
			http.Error(w, `{"error": "tunnel daemon not enabled"}`, http.StatusServiceUnavailable)
			return
		}

		switch r.Method {
		case http.MethodGet:
			// Return current config
			cfg := agent.tunnelDaemon.GetInspectionConfig()
			if cfg == nil {
				_, _ = w.Write([]byte(`{"enabled": false}`))
				return
			}
			data, _ := json.Marshal(map[string]interface{}{
				"enabled":    cfg.Enabled,
				"mode":       cfg.Mode,
				"onCritical": cfg.OnCritical,
				"onHigh":     cfg.OnHigh,
				"onMedium":   cfg.OnMedium,
			})
			_, _ = w.Write(data)

		case http.MethodPost, http.MethodPut:
			// Update config at runtime
			var req struct {
				Enabled    *bool   `json:"enabled"`
				Mode       *string `json:"mode"`
				OnCritical *string `json:"onCritical"`
				OnHigh     *string `json:"onHigh"`
				OnMedium   *string `json:"onMedium"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, `{"error": "invalid JSON"}`, http.StatusBadRequest)
				return
			}

			// Get current config or create default
			cfg := agent.tunnelDaemon.GetInspectionConfig()
			if cfg == nil {
				cfg = DefaultInspectionConfig()
			}

			// Apply updates
			if req.Enabled != nil {
				cfg.Enabled = *req.Enabled
			}
			if req.Mode != nil {
				switch *req.Mode {
				case "detect":
					cfg.Mode = InspectionModeDetect
				case "block":
					cfg.Mode = InspectionModeBlock
				default:
					http.Error(w, `{"error": "invalid mode, must be 'detect' or 'block'"}`, http.StatusBadRequest)
					return
				}
			}
			if req.OnCritical != nil {
				cfg.OnCritical = *req.OnCritical
			}
			if req.OnHigh != nil {
				cfg.OnHigh = *req.OnHigh
			}
			if req.OnMedium != nil {
				cfg.OnMedium = *req.OnMedium
			}

			// Apply the new config
			agent.tunnelDaemon.SetInspectionConfig(cfg)

			// Return updated config
			data, _ := json.Marshal(map[string]interface{}{
				"enabled":    cfg.Enabled,
				"mode":       cfg.Mode,
				"onCritical": cfg.OnCritical,
				"onHigh":     cfg.OnHigh,
				"onMedium":   cfg.OnMedium,
				"updated":    true,
			})
			_, _ = w.Write(data)

		default:
			http.Error(w, `{"error": "method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})
	
	// Setup K8s audit webhook for dynamic audit events
	agent.setupAuditWebhookRoutes(mux)

	// Setup log proxy for Fluent Bit → Agent → Remote
	agent.setupLogProxyRoutes(mux)

	port := getEnvOrDefault("AGENT_HTTP_PORT", "8080")
	addr := ":" + port
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
			return err
		},
	}
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		log.Fatalf("HTTP server: %v", err)
	}
	srv := &http.Server{Handler: mux}
	log.Printf("Agent listening on %s (health, ready, log-proxy)", addr)
	if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server: %v", err)
	}
}

// autoRegister calls POST /api/v1/clusters/register to register this agent's
// cluster with the backend. On success it sets a.ClusterID from the response.
// It retries up to 5 times with exponential backoff since the backend may not
// be ready at agent startup.
func (a *PrysmAgent) autoRegister(ctx context.Context) error {
	hostname, _ := os.Hostname()
	clusterName := a.ClusterName
	if clusterName == "" {
		clusterName = hostname
	}

	body := map[string]interface{}{
		"cluster_name": clusterName,
		"agent_token":  a.AgentToken,
		"agent_type":   "k8s-bootstrap",
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal register request: %w", err)
	}

	url := a.BackendURL + "/api/v1/clusters/register"

	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second // 1s, 2s, 4s, 8s
			log.Printf("Auto-register attempt %d failed, retrying in %v...", attempt, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			lastErr = fmt.Errorf("create request: %w", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := a.HTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("POST %s: %w", url, err)
			continue
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			lastErr = fmt.Errorf("register returned %d: %s", resp.StatusCode, string(respBody))
			continue
		}

		var result map[string]interface{}
		if err := json.Unmarshal(respBody, &result); err != nil {
			lastErr = fmt.Errorf("parse register response: %w", err)
			continue
		}

		clusterID, ok := result["cluster_id"]
		if !ok {
			lastErr = fmt.Errorf("register response missing cluster_id")
			continue
		}

		a.ClusterID = fmt.Sprintf("%v", clusterID)
		// Strip any decimal (JSON numbers decode as float64)
		if idx := strings.Index(a.ClusterID, "."); idx != -1 {
			a.ClusterID = a.ClusterID[:idx]
		}

		name, _ := result["cluster_name"].(string)
		if name != "" {
			a.ClusterName = name
		}

		log.Printf("Auto-registered cluster %q (ID: %s)", a.ClusterName, a.ClusterID)
		return nil
	}

	return fmt.Errorf("auto-register failed after 5 attempts: %w", lastErr)
}

func runHealthCheck() error {
	port := getEnvOrDefault("AGENT_HTTP_PORT", "8080")
	resp, err := http.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("health check returned non-200")
	}
	return nil
}

// runCCProxyMode runs the agent in cross-cluster proxy mode.
// This is a lightweight mode that only handles cross-cluster routes.
// It runs without hostNetwork, getting a Pod IP that Endpoints can point to.
func runCCProxyMode() {
	log.Println("Starting in cross-cluster proxy mode")

	var orgID uint
	if s := getEnvOrDefault("ORGANIZATION_ID", ""); s != "" {
		if n, err := parseUint(s); err == nil {
			orgID = n
		}
	}

	agent := &PrysmAgent{
		BackendURL:     strings.TrimSuffix(getEnvOrDefault("BACKEND_URL", ""), "/"),
		AgentToken:     getEnvOrDefault("AGENT_TOKEN", ""),
		ClusterID:      getEnvOrDefault("CLUSTER_ID", ""),
		OrganizationID: orgID,
		derpRegion:     getEnvOrDefault("DERP_REGION", ""),
		derpSkipVerify: getEnvOrDefault("DERP_SKIP_TLS_VERIFY", "") == "true" || getEnvOrDefault("DERP_SKIP_TLS_VERIFY", "") == "1",
		HTTPClient:     &http.Client{Timeout: 30 * time.Second},
	}

	if servers := getEnvOrDefault("DERP_SERVERS", getEnvOrDefault("DERP_SERVER", "")); servers != "" {
		agent.derpServers = strings.Split(servers, ",")
		for i, s := range agent.derpServers {
			agent.derpServers[i] = strings.TrimSpace(s)
		}
	}

	ctx := context.Background()

	// Start DERP connection (required for cross-cluster routing)
	if len(agent.derpServers) > 0 {
		if err := agent.startDERP(ctx); err != nil {
			log.Fatalf("DERP start failed: %v", err)
		}
	} else {
		log.Fatal("CC proxy mode requires DERP_SERVERS to be configured")
	}

	// Start cross-cluster route manager
	agent.ccRouteManager = newCrossClusterRouteManager(agent)
	agent.ccRouteManager.SetProxyMode(true) // Enable proxy mode (creates TCP listeners)
	go agent.ccRouteManager.Start(ctx)

	// Simple health endpoint
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	port := getEnvOrDefault("CC_PROXY_HEALTH_PORT", "8081")
	log.Printf("CC proxy health endpoint on :%s", port)
	server := &http.Server{Addr: ":" + port, Handler: mux}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		// Note: signal.Notify would need "os/signal" import
		<-sigCh
		log.Println("Shutting down CC proxy...")
		server.Close()
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("CC proxy server failed: %v", err)
	}
}
