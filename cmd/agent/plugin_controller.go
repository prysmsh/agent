package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// pluginSpec is the plugin data returned by GET /agent/plugins/config.
type pluginSpec struct {
	ID              uint            `json:"id"`
	Name            string          `json:"name"`
	Type            string          `json:"type"`
	Config          json.RawMessage `json:"config"`
	WasmURL         string          `json:"wasm_url"`
	WasmSHA256      string          `json:"wasm_sha256"`
	WasmSignature   string          `json:"wasm_signature"`   // base64 Ed25519 signature of SHA256
	SigningPublicKey string          `json:"signing_public_key"` // hex Ed25519 public key
	Enabled         bool            `json:"enabled"`
}

// pluginEvent is a security event buffered for POST to /agent/plugins/events.
type pluginEvent struct {
	PluginID uint            `json:"plugin_id"`
	NodeName string          `json:"node_name"`
	Payload  json.RawMessage `json:"payload"`
}

// pluginStatusReport is POSTed to /agent/plugins/status.
type pluginStatusReport struct {
	PluginID      uint   `json:"plugin_id"`
	Status        string `json:"status"`
	StatusMessage string `json:"status_message"`
}

// pluginController manages the desired-state plugin lifecycle on each node.
type pluginController struct {
	agent         *PrysmAgent
	mu            sync.Mutex
	activePlugins map[uint]pluginSpec          // plugin_id -> spec (for change detection)
	instances     map[uint]*WasmPluginInstance // plugin_id -> live wazero instance (nil if no wasm_url)
	eventMu       sync.Mutex
	eventQueue    []pluginEvent // buffered events pending flush
}

// startPluginController polls the backend for plugin config, reconciles the active
// plugin set, and reports status back. Follows the ai_agent_controller pattern.
func (a *PrysmAgent) startPluginController(ctx context.Context) {
	if a.BackendURL == "" || a.AgentToken == "" || a.ClusterID == "" {
		log.Println("plugin-controller: disabled (missing backend URL, token, or cluster ID)")
		return
	}

	ctrl := &pluginController{
		agent:         a,
		activePlugins: make(map[uint]pluginSpec),
		instances:     make(map[uint]*WasmPluginInstance),
	}
	globalPluginController = ctrl

	interval := 30 * time.Second
	if d := os.Getenv("PLUGIN_RECONCILE_INTERVAL"); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
			interval = parsed
		}
	}

	// Start tick loop for custom/honeypot plugins.
	go runWasmTickLoop(ctx, 5*time.Second)

	// Initial reconcile
	ctrl.reconcile(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ctrl.reconcile(ctx)
		}
	}
}

// reconcile fetches desired plugin state from the backend and converges the active set.
func (ctrl *pluginController) reconcile(ctx context.Context) {
	rCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	desired, err := ctrl.fetchConfig(rCtx)
	if err != nil {
		log.Printf("plugin-controller: fetch config: %v", err)
		return
	}

	log.Printf("plugin-controller: fetched %d plugin(s) for cluster %s", len(desired), ctrl.agent.ClusterID)

	ctrl.mu.Lock()
	defer ctrl.mu.Unlock()

	// Build desired map
	desiredMap := make(map[uint]pluginSpec, len(desired))
	for _, p := range desired {
		desiredMap[p.ID] = p
	}

	var statuses []pluginStatusReport

	// Activate new or changed plugins
	for id, spec := range desiredMap {
		existing, active := ctrl.activePlugins[id]
		needsLoad := !active || existing.WasmURL != spec.WasmURL || existing.WasmSHA256 != spec.WasmSHA256
		if needsLoad {
			if active {
				ctrl.deactivatePlugin(existing)
			}
			status, msg := ctrl.activatePlugin(rCtx, spec)
			ctrl.activePlugins[id] = spec
			statuses = append(statuses, pluginStatusReport{
				PluginID:      id,
				Status:        status,
				StatusMessage: msg,
			})
		} else {
			statuses = append(statuses, pluginStatusReport{
				PluginID:      id,
				Status:        "active",
				StatusMessage: fmt.Sprintf("plugin %q active on cluster %s", spec.Name, ctrl.agent.ClusterID),
			})
		}
	}

	// Deactivate plugins that are no longer in desired state
	for id, spec := range ctrl.activePlugins {
		if _, stillDesired := desiredMap[id]; !stillDesired {
			ctrl.deactivatePlugin(spec)
			delete(ctrl.activePlugins, id)
		}
	}

	if len(statuses) > 0 {
		if err := ctrl.postStatus(rCtx, statuses); err != nil {
			log.Printf("plugin-controller: post status: %v", err)
		}
	}

	// Flush buffered plugin events
	ctrl.flushEvents(rCtx)
}

// EnqueueEvent adds an event to the buffer for the next reconcile flush.
// Safe to call from any goroutine (e.g. hostEmitEvent).
func (ctrl *pluginController) EnqueueEvent(ev pluginEvent) {
	ctrl.eventMu.Lock()
	ctrl.eventQueue = append(ctrl.eventQueue, ev)
	ctrl.eventMu.Unlock()
}

// flushEvents POSTs buffered events to the backend and clears the queue.
func (ctrl *pluginController) flushEvents(ctx context.Context) {
	ctrl.eventMu.Lock()
	if len(ctrl.eventQueue) == 0 {
		ctrl.eventMu.Unlock()
		return
	}
	events := ctrl.eventQueue
	ctrl.eventQueue = nil
	ctrl.eventMu.Unlock()

	if err := ctrl.postEvents(ctx, events); err != nil {
		log.Printf("plugin-controller: post events: %v", err)
		// Re-queue on failure
		ctrl.eventMu.Lock()
		ctrl.eventQueue = append(events, ctrl.eventQueue...)
		ctrl.eventMu.Unlock()
	}
}

// postEvents sends plugin events to POST /api/v1/agent/plugins/events.
func (ctrl *pluginController) postEvents(ctx context.Context, events []pluginEvent) error {
	a := ctrl.agent
	payload, err := json.Marshal(map[string]interface{}{
		"events": events,
	})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/v1/agent/plugins/events", a.BackendURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.AgentToken)
	req.Header.Set("X-Cluster-ID", a.ClusterID)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("events endpoint returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

// activatePlugin loads and registers a plugin. Returns (status, message).
func (ctrl *pluginController) activatePlugin(ctx context.Context, p pluginSpec) (status, msg string) {
	log.Printf("plugin-controller: activating plugin %d %q (type=%s)", p.ID, p.Name, p.Type)

	inst, err := loadWasmPlugin(ctx, p, ctrl.agent)
	if err != nil {
		log.Printf("plugin-controller: load error for plugin %d %q: %v", p.ID, p.Name, err)
		return "error", err.Error()
	}

	if inst != nil {
		registerWasmPlugin(inst)
		ctrl.instances[p.ID] = inst
	}

	return "active", fmt.Sprintf("plugin %q active on cluster %s", p.Name, ctrl.agent.ClusterID)
}

// deactivatePlugin tears down a plugin and removes it from the global registries.
func (ctrl *pluginController) deactivatePlugin(p pluginSpec) {
	log.Printf("plugin-controller: deactivating plugin %d %q", p.ID, p.Name)
	unregisterWasmPlugin(p.ID)
	delete(ctrl.instances, p.ID)
}

// fetchConfig calls GET /api/v1/agent/plugins/config to get plugin specs for this cluster.
func (ctrl *pluginController) fetchConfig(ctx context.Context) ([]pluginSpec, error) {
	a := ctrl.agent
	url := fmt.Sprintf("%s/api/v1/agent/plugins/config?cluster_id=%s", a.BackendURL, a.ClusterID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.AgentToken)
	req.Header.Set("X-Cluster-ID", a.ClusterID)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("backend returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Plugins []pluginSpec `json:"plugins"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Plugins, nil
}

// postStatus sends plugin status updates to POST /api/v1/agent/plugins/status.
func (ctrl *pluginController) postStatus(ctx context.Context, statuses []pluginStatusReport) error {
	a := ctrl.agent
	payload, err := json.Marshal(map[string]interface{}{"statuses": statuses})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/v1/agent/plugins/status", a.BackendURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.AgentToken)
	req.Header.Set("X-Cluster-ID", a.ClusterID)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status report returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}
