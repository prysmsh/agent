package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// wasmCallTimeout is the maximum time a single WASM function call may take.
const wasmCallTimeout = 5 * time.Second

// WasmPluginInstance holds a running wazero instance for one plugin.
type WasmPluginInstance struct {
	spec  pluginSpec
	agent *PrysmAgent
	rt    wazero.Runtime
	mod   api.Module
	mu    sync.Mutex

	// Cached function handles (nil = not exported by plugin)
	fnOnInit    api.Function
	fnOnPacket  api.Function
	fnOnLogLine api.Function
	fnOnTick    api.Function
	fnMalloc    api.Function
	fnFree      api.Function
}

// globalWasmMu protects globalWasmLogFilters, globalWasmPacketInspectors, and globalWasmTickPlugins.
var globalWasmMu sync.RWMutex

// globalPluginController is set by startPluginController so wasm_runtime.go can enqueue events.
var globalPluginController *pluginController

// globalWasmLogFilters holds active log-filter plugin instances.
var globalWasmLogFilters []*WasmPluginInstance

// globalWasmPacketInspectors holds active network-filter plugin instances.
var globalWasmPacketInspectors []*WasmPluginInstance

// globalWasmTickPlugins holds custom/honeypot plugins driven by on_tick.
var globalWasmTickPlugins []*WasmPluginInstance

// loadWasmPlugin downloads, verifies, and instantiates a WASM plugin.
// Returns nil, nil if no WasmURL is set (plugin is registered but no binary yet).
func loadWasmPlugin(ctx context.Context, spec pluginSpec, agent *PrysmAgent) (*WasmPluginInstance, error) {
	if spec.WasmURL == "" {
		return nil, nil
	}

	wasmBytes, err := downloadWasm(ctx, spec.WasmURL, agent.HTTPClient)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}

	sum := sha256.Sum256(wasmBytes)
	if spec.WasmSHA256 != "" {
		got := hex.EncodeToString(sum[:])
		if got != spec.WasmSHA256 {
			return nil, fmt.Errorf("SHA256 mismatch: expected %s got %s", spec.WasmSHA256, got)
		}
	}

	// Ed25519 signature verification (if backend provided both signature and public key)
	if spec.WasmSignature != "" && spec.SigningPublicKey != "" {
		pubBytes, err := hex.DecodeString(spec.SigningPublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid signing public key: %w", err)
		}
		sig, err := base64.StdEncoding.DecodeString(spec.WasmSignature)
		if err != nil {
			return nil, fmt.Errorf("invalid signature encoding: %w", err)
		}
		if !ed25519.Verify(ed25519.PublicKey(pubBytes), sum[:], sig) {
			return nil, fmt.Errorf("Ed25519 signature verification failed for plugin %d %q — refusing to load", spec.ID, spec.Name)
		}
		log.Printf("wasm-plugin %d %q: Ed25519 signature verified", spec.ID, spec.Name)
	}

	inst := &WasmPluginInstance{spec: spec, agent: agent}

	// Compile-time cache: share compiled modules across cold-starts (same process).
	rtCfg := wazero.NewRuntimeConfig().WithMemoryLimitPages(256) // 16 MiB cap
	inst.rt = wazero.NewRuntimeWithConfig(ctx, rtCfg)

	// Register host imports before instantiation.
	if err := inst.registerHostModule(ctx); err != nil {
		inst.rt.Close(ctx)
		return nil, fmt.Errorf("host module: %w", err)
	}

	compiled, err := inst.rt.CompileModule(ctx, wasmBytes)
	if err != nil {
		inst.rt.Close(ctx)
		return nil, fmt.Errorf("compile: %w", err)
	}

	mod, err := inst.rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName(
		fmt.Sprintf("prysm-plugin-%d", spec.ID),
	))
	if err != nil {
		inst.rt.Close(ctx)
		return nil, fmt.Errorf("instantiate: %w", err)
	}
	inst.mod = mod

	// Grab exported functions (all optional).
	inst.fnMalloc = mod.ExportedFunction("malloc")
	inst.fnFree = mod.ExportedFunction("free")
	inst.fnOnInit = mod.ExportedFunction("on_init")
	inst.fnOnPacket = mod.ExportedFunction("on_packet")
	inst.fnOnLogLine = mod.ExportedFunction("on_log_line")
	inst.fnOnTick = mod.ExportedFunction("on_tick")

	// Call on_init with the plugin config JSON.
	if inst.fnOnInit != nil {
		configBytes, _ := json.Marshal(spec.Config)
		if err := inst.callOnInit(ctx, configBytes); err != nil {
			log.Printf("wasm-plugin %d %q: on_init error: %v (continuing)", spec.ID, spec.Name, err)
		}
	}

	return inst, nil
}

// Close tears down the wazero runtime and frees all resources.
func (inst *WasmPluginInstance) Close(ctx context.Context) {
	inst.mu.Lock()
	defer inst.mu.Unlock()
	if inst.mod != nil {
		inst.mod.Close(ctx)
	}
	if inst.rt != nil {
		inst.rt.Close(ctx)
	}
}

// ---- memory helpers --------------------------------------------------------

// writeToPlugin copies b into plugin memory via malloc, returning (ptr, len).
// Caller must free ptr when done.
func (inst *WasmPluginInstance) writeToPlugin(ctx context.Context, b []byte) (uint32, uint32, error) {
	if inst.fnMalloc == nil {
		return 0, 0, fmt.Errorf("plugin does not export malloc")
	}
	res, err := inst.fnMalloc.Call(ctx, uint64(len(b)))
	if err != nil {
		return 0, 0, err
	}
	ptr := uint32(res[0])
	if !inst.mod.Memory().Write(ptr, b) {
		return 0, 0, fmt.Errorf("memory write out of bounds at ptr=%d len=%d", ptr, len(b))
	}
	return ptr, uint32(len(b)), nil
}

// freeInPlugin calls the plugin's free function if available.
func (inst *WasmPluginInstance) freeInPlugin(ctx context.Context, ptr uint32) {
	if inst.fnFree == nil || ptr == 0 {
		return
	}
	_, _ = inst.fnFree.Call(ctx, uint64(ptr))
}

// readString reads a null-terminated or length-prefixed string written by the
// plugin into linear memory starting at ptr with length n.
func (inst *WasmPluginInstance) readString(ptr, n uint32) (string, bool) {
	b, ok := inst.mod.Memory().Read(ptr, n)
	return string(b), ok
}

// ---- host import module ----------------------------------------------------

func (inst *WasmPluginInstance) registerHostModule(ctx context.Context) error {
	_, err := inst.rt.NewHostModuleBuilder("host").
		NewFunctionBuilder().
		WithFunc(inst.hostLog).
		Export("log").
		NewFunctionBuilder().
		WithFunc(inst.hostEmitEvent).
		Export("emit_event").
		NewFunctionBuilder().
		WithFunc(inst.hostGetConfig).
		Export("get_config").
		NewFunctionBuilder().
		WithFunc(inst.hostClockNs).
		Export("clock_ns").
		NewFunctionBuilder().
		WithFunc(inst.hostGetClusterID).
		Export("get_cluster_id").
		NewFunctionBuilder().
		WithFunc(inst.hostRequestReconcile).
		Export("request_reconcile").
		Instantiate(ctx)
	return err
}

// hostLog: void log(i32 level, i32 msg_ptr, i32 msg_len)
// level: 0=debug, 1=info, 2=warn, 3=error
func (inst *WasmPluginInstance) hostLog(_ context.Context, m api.Module, level, ptr, length uint32) {
	msg, _ := m.Memory().Read(ptr, length)
	prefix := "wasm-plugin[" + inst.spec.Name + "]"
	switch level {
	case 3:
		log.Printf("ERROR %s: %s", prefix, msg)
	case 2:
		log.Printf("WARN  %s: %s", prefix, msg)
	default:
		log.Printf("INFO  %s: %s", prefix, msg)
	}
}

// hostEmitEvent: void emit_event(i32 json_ptr, i32 json_len)
// Plugin calls this to surface a security event to the backend.
func (inst *WasmPluginInstance) hostEmitEvent(_ context.Context, m api.Module, ptr, length uint32) {
	raw, ok := m.Memory().Read(ptr, length)
	if !ok {
		return
	}
	log.Printf("wasm-plugin[%s] event: %s", inst.spec.Name, raw)

	// Enqueue for batch POST to backend on next reconcile.
	nodeName := ""
	if inst.agent != nil {
		nodeName = inst.agent.ClusterName
	}
	ev := pluginEvent{
		PluginID: inst.spec.ID,
		NodeName: nodeName,
		Payload:  json.RawMessage(raw),
	}
	if globalPluginController != nil {
		globalPluginController.EnqueueEvent(ev)
	}
}

// hostGetConfig: i32 get_config(i32 out_ptr)
// Writes the plugin's Config JSON into linear memory at out_ptr.
// Returns number of bytes written, or negative on error.
func (inst *WasmPluginInstance) hostGetConfig(_ context.Context, m api.Module, outPtr uint32) int32 {
	configBytes, _ := json.Marshal(inst.spec.Config)
	if !m.Memory().Write(outPtr, configBytes) {
		return -1
	}
	return int32(len(configBytes))
}

// hostClockNs: i64 clock_ns()
// Returns current Unix time in nanoseconds.
func (inst *WasmPluginInstance) hostClockNs(_ context.Context, _ api.Module) int64 {
	return time.Now().UnixNano()
}

// hostRequestReconcile: i32 request_reconcile(i32 json_ptr, i32 json_len)
// Supported payload:
// {"action":"set_log_collector_image","image":"ghcr.io/prysmsh/fluent-bit:4.2.2-1"}
// Returns 0 on success, negative on error.
func (inst *WasmPluginInstance) hostRequestReconcile(_ context.Context, m api.Module, ptr, length uint32) int32 {
	raw, ok := m.Memory().Read(ptr, length)
	if !ok {
		return -1
	}
	var req struct {
		Action string `json:"action"`
		Image  string `json:"image"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return -2
	}
	if strings.TrimSpace(req.Action) != "set_log_collector_image" {
		return -3
	}
	image := strings.TrimSpace(req.Image)
	if image == "" {
		return -4
	}
	if inst.agent == nil {
		return -5
	}

	// Keep runtime override in env so the existing reconciler path consumes it.
	if err := os.Setenv(logCollectorImageEnv, image); err != nil {
		return -6
	}
	log.Printf("wasm-plugin[%s] requested reconcile: %s=%q", inst.spec.Name, logCollectorImageEnv, image)

	// Best-effort immediate reconcile (periodic loop remains the source of eventual consistency).
	if inst.agent.clientset != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			inst.agent.ensureLogCollectorDaemonSet(ctx)
		}()
	}
	return 0
}

// hostGetClusterID: i32 get_cluster_id(i32 out_ptr)
// Writes the cluster ID string into linear memory at out_ptr.
// Returns bytes written, or negative on error.
func (inst *WasmPluginInstance) hostGetClusterID(_ context.Context, m api.Module, outPtr uint32) int32 {
	b := []byte(inst.agent.ClusterID)
	if !m.Memory().Write(outPtr, b) {
		return -1
	}
	return int32(len(b))
}

// ---- plugin call wrappers --------------------------------------------------

func (inst *WasmPluginInstance) callOnInit(ctx context.Context, configJSON []byte) error {
	tCtx, cancel := context.WithTimeout(ctx, wasmCallTimeout)
	defer cancel()

	inst.mu.Lock()
	defer inst.mu.Unlock()

	ptr, length, err := inst.writeToPlugin(tCtx, configJSON)
	if err != nil {
		return err
	}
	defer inst.freeInPlugin(tCtx, ptr)

	_, err = inst.fnOnInit.Call(tCtx, uint64(ptr), uint64(length))
	return err
}

// callOnPacket calls on_packet(data_ptr, data_len, ctx_ptr, ctx_len, dir_ptr, dir_len) -> i32
// Returns: 0 = allow, 1 = drop, 2 = alert.
// Returns (0, nil) if the plugin doesn't export on_packet.
func (inst *WasmPluginInstance) callOnPacket(ctx context.Context, data []byte, direction string, pktCtx *InspectionContext) (int32, error) {
	if inst.fnOnPacket == nil {
		return 0, nil
	}

	tCtx, cancel := context.WithTimeout(ctx, wasmCallTimeout)
	defer cancel()

	inst.mu.Lock()
	defer inst.mu.Unlock()

	dataPtr, dataLen, err := inst.writeToPlugin(tCtx, data)
	if err != nil {
		return 0, err
	}
	defer inst.freeInPlugin(tCtx, dataPtr)

	// Minimal context JSON: {src_ip, dst_ip, src_port, dst_port, protocol}
	ctxJSON, _ := json.Marshal(map[string]interface{}{
		"src_ip":   pktCtx.SrcIP.String(),
		"dst_ip":   pktCtx.DstIP.String(),
		"src_port": pktCtx.SrcPort,
		"dst_port": pktCtx.DstPort,
		"protocol": pktCtx.Protocol,
	})
	ctxPtr, ctxLen, err := inst.writeToPlugin(tCtx, ctxJSON)
	if err != nil {
		return 0, err
	}
	defer inst.freeInPlugin(tCtx, ctxPtr)

	dirBytes := []byte(direction)
	dirPtr, dirLen, err := inst.writeToPlugin(tCtx, dirBytes)
	if err != nil {
		return 0, err
	}
	defer inst.freeInPlugin(tCtx, dirPtr)

	res, err := inst.fnOnPacket.Call(tCtx,
		uint64(dataPtr), uint64(dataLen),
		uint64(ctxPtr), uint64(ctxLen),
		uint64(dirPtr), uint64(dirLen),
	)
	if err != nil {
		return 0, err
	}
	return int32(res[0]), nil
}

// callOnLogLine calls on_log_line(record_ptr, record_len) -> i32
// Returns: 0 = drop, 1 = ship.
// Returns (1, nil) if the plugin doesn't export on_log_line.
func (inst *WasmPluginInstance) callOnLogLine(ctx context.Context, record map[string]interface{}) (int32, error) {
	if inst.fnOnLogLine == nil {
		return 1, nil
	}

	tCtx, cancel := context.WithTimeout(ctx, wasmCallTimeout)
	defer cancel()

	inst.mu.Lock()
	defer inst.mu.Unlock()

	recBytes, err := json.Marshal(record)
	if err != nil {
		return 1, err
	}
	ptr, length, err := inst.writeToPlugin(tCtx, recBytes)
	if err != nil {
		return 1, err
	}
	defer inst.freeInPlugin(tCtx, ptr)

	res, err := inst.fnOnLogLine.Call(tCtx, uint64(ptr), uint64(length))
	if err != nil {
		return 1, err
	}
	return int32(res[0]), nil
}

// callOnTick calls on_tick() -> i32.
func (inst *WasmPluginInstance) callOnTick(ctx context.Context) error {
	if inst.fnOnTick == nil {
		return nil
	}

	tCtx, cancel := context.WithTimeout(ctx, wasmCallTimeout)
	defer cancel()

	inst.mu.Lock()
	defer inst.mu.Unlock()

	_, err := inst.fnOnTick.Call(tCtx)
	return err
}

// ---- WasmPacketInspector ---------------------------------------------------

// WasmPacketInspector implements PacketInspector by running all active
// network-filter WASM plugins against each packet.
type WasmPacketInspector struct{}

func (w *WasmPacketInspector) Name() string { return "wasm-network-filter" }

func (w *WasmPacketInspector) Stats() map[string]interface{} {
	globalWasmMu.RLock()
	n := len(globalWasmPacketInspectors)
	globalWasmMu.RUnlock()
	return map[string]interface{}{"active_plugins": n}
}

// Inspect calls on_packet for each active network-filter plugin.
// A "drop" decision from any plugin results in a ThreatHigh result.
// An "alert" decision results in a ThreatMedium result.
func (w *WasmPacketInspector) Inspect(data []byte, direction string, ctx *InspectionContext) []InspectionResult {
	globalWasmMu.RLock()
	instances := make([]*WasmPluginInstance, len(globalWasmPacketInspectors))
	copy(instances, globalWasmPacketInspectors)
	globalWasmMu.RUnlock()

	if len(instances) == 0 {
		return nil
	}

	bgCtx := context.Background()
	var results []InspectionResult

	for _, inst := range instances {
		decision, err := inst.callOnPacket(bgCtx, data, direction, ctx)
		if err != nil {
			log.Printf("wasm-plugin[%s] on_packet error: %v", inst.spec.Name, err)
			continue
		}
		switch decision {
		case 1: // drop
			results = append(results, InspectionResult{
				Timestamp:   time.Now(),
				ThreatLevel: ThreatHigh,
				Category:    ThreatCategoryDefenseEvasion,
				Description: fmt.Sprintf("wasm-plugin %q: packet drop decision", inst.spec.Name),
				ShouldBlock: true,
			})
		case 2: // alert
			results = append(results, InspectionResult{
				Timestamp:   time.Now(),
				ThreatLevel: ThreatMedium,
				Category:    ThreatCategoryDefenseEvasion,
				Description: fmt.Sprintf("wasm-plugin %q: packet alert decision", inst.spec.Name),
			})
		}
	}
	return results
}

// ---- WASM log filter -------------------------------------------------------

// applyWasmLogFilters runs all active log-filter WASM plugins against a record.
// Returns true if the record should be shipped (all plugins agree to ship),
// false if any plugin says to drop it.
func applyWasmLogFilters(record map[string]interface{}) bool {
	globalWasmMu.RLock()
	instances := make([]*WasmPluginInstance, len(globalWasmLogFilters))
	copy(instances, globalWasmLogFilters)
	globalWasmMu.RUnlock()

	if len(instances) == 0 {
		return true
	}

	bgCtx := context.Background()
	for _, inst := range instances {
		keep, err := inst.callOnLogLine(bgCtx, record)
		if err != nil {
			log.Printf("wasm-plugin[%s] on_log_line error: %v", inst.spec.Name, err)
			continue
		}
		if keep == 0 {
			return false
		}
	}
	return true
}

// ---- registry helpers ------------------------------------------------------

// registerWasmPlugin adds an instance to the appropriate global registry.
func registerWasmPlugin(inst *WasmPluginInstance) {
	globalWasmMu.Lock()
	defer globalWasmMu.Unlock()
	switch inst.spec.Type {
	case "network-filter":
		globalWasmPacketInspectors = append(globalWasmPacketInspectors, inst)
	case "log-filter":
		globalWasmLogFilters = append(globalWasmLogFilters, inst)
	default:
		// custom / honeypot: driven by on_tick goroutine
		globalWasmTickPlugins = append(globalWasmTickPlugins, inst)
	}
}

// unregisterWasmPlugin removes an instance by plugin ID from all registries and closes it.
func unregisterWasmPlugin(id uint) {
	globalWasmMu.Lock()
	defer globalWasmMu.Unlock()

	ctx := context.Background()

	globalWasmPacketInspectors = removeByID(globalWasmPacketInspectors, id, ctx)
	globalWasmLogFilters = removeByID(globalWasmLogFilters, id, ctx)
	globalWasmTickPlugins = removeByID(globalWasmTickPlugins, id, ctx)
}

// runWasmTickLoop calls on_tick for all custom/honeypot plugins every tickInterval.
// Should be called in a goroutine; returns when ctx is cancelled.
func runWasmTickLoop(ctx context.Context, tickInterval time.Duration) {
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			globalWasmMu.RLock()
			instances := make([]*WasmPluginInstance, len(globalWasmTickPlugins))
			copy(instances, globalWasmTickPlugins)
			globalWasmMu.RUnlock()

			for _, inst := range instances {
				if err := inst.callOnTick(ctx); err != nil {
					log.Printf("wasm-plugin[%s] on_tick error: %v", inst.spec.Name, err)
				}
			}
		}
	}
}

func removeByID(list []*WasmPluginInstance, id uint, ctx context.Context) []*WasmPluginInstance {
	out := list[:0]
	for _, inst := range list {
		if inst.spec.ID == id {
			inst.Close(ctx)
		} else {
			out = append(out, inst)
		}
	}
	return out
}

// ---- download helper -------------------------------------------------------

func downloadWasm(ctx context.Context, url string, client *http.Client) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, url)
	}
	// Limit to 32 MiB for safety.
	return io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
}
