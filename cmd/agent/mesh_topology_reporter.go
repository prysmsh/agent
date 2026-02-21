package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// meshConnectionEvent matches the backend's expected payload
type meshConnectionEvent struct {
	ClusterID       string `json:"cluster_id"`
	Timestamp       string `json:"timestamp"`
	SourceNamespace string `json:"source_namespace"`
	SourcePod       string `json:"source_pod"`
	DestNamespace   string `json:"dest_namespace"`
	DestPod         string `json:"dest_pod"`
	DestPort        int    `json:"dest_port"`
	Protocol        string `json:"protocol"`
	BytesSent       int64  `json:"bytes_sent"`
	BytesReceived   int64  `json:"bytes_received"`
	Status          string `json:"connection_status"`
}

// meshThreatEvent represents a DPI-detected threat for backend reporting
type meshThreatEvent struct {
	ClusterID   string                 `json:"cluster_id"`
	Timestamp   string                 `json:"timestamp"`
	Namespace   string                 `json:"namespace"`
	Pod         string                 `json:"pod"`
	ThreatLevel string                 `json:"threat_level"`
	Category    string                 `json:"category"`
	Description string                 `json:"description"`
	Score       int                    `json:"score"`
	MitreATTCK  string                 `json:"mitre_attck,omitempty"`
	Indicators  []string               `json:"indicators,omitempty"`
	SrcIP       string                 `json:"src_ip,omitempty"`
	DstIP       string                 `json:"dst_ip,omitempty"`
	SrcPort     int                    `json:"src_port,omitempty"`
	DstPort     int                    `json:"dst_port,omitempty"`
	Blocked     bool                   `json:"blocked"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// MeshTopologyReporter buffers and sends pod-to-pod connection events to the backend
type MeshTopologyReporter struct {
	agent         *PrysmAgent
	client        *http.Client
	buffer        []meshConnectionEvent
	threatBuffer  []meshThreatEvent
	bufferMu      sync.Mutex
	flushTicker   *time.Ticker
	flushInterval time.Duration
	natsConn      *nats.Conn
	natsSubject   string
}

// NewMeshTopologyReporter creates a reporter that sends to the backend
func NewMeshTopologyReporter(agent *PrysmAgent) *MeshTopologyReporter {
	interval := 10 * time.Second
	if d := getEnvOrDefault("MESH_TOPOLOGY_FLUSH_INTERVAL", ""); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
			interval = parsed
		}
	}
	r := &MeshTopologyReporter{
		agent:         agent,
		client:        &http.Client{Timeout: 10 * time.Second},
		buffer:        make([]meshConnectionEvent, 0, 50),
		threatBuffer:  make([]meshThreatEvent, 0, 20),
		flushInterval: interval,
	}
	// Connect to NATS if NATS_URL is set (for real-time mesh.connections stream)
	if url := strings.TrimSpace(os.Getenv("NATS_URL")); url != "" {
		nc, err := nats.Connect(url, nats.Name("prysm-agent-mesh-topology"))
		if err != nil {
			log.Printf("mesh-topology: NATS connect failed: %v", err)
		} else {
			r.natsConn = nc
			r.natsSubject = getEnvOrDefault("NATS_MESH_SUBJECT", "mesh.connections")
			log.Printf("mesh-topology: NATS publisher connected (subject=%s)", r.natsSubject)
		}
	}
	return r
}

// Start begins the background flush loop
func (r *MeshTopologyReporter) Start(ctx context.Context) {
	if r.agent.BackendURL == "" || r.agent.AgentToken == "" || r.agent.ClusterID == "" {
		log.Println("mesh-topology: disabled (missing backend URL, token, or cluster ID)")
		return
	}

	r.flushTicker = time.NewTicker(r.flushInterval)
	go func() {
		for {
			select {
			case <-ctx.Done():
				r.flush()
				return
			case <-r.flushTicker.C:
				r.flush()
			}
		}
	}()
	log.Printf("mesh-topology: reporter started (flush every %v)", r.flushInterval)
}

// RecordConnection records a pod-to-pod connection for topology
func (r *MeshTopologyReporter) RecordConnection(srcNs, srcPod, dstNs, dstPod string, destPort int, bytesSent, bytesRecv int64) {
	if r.agent.BackendURL == "" {
		return
	}

	// Skip self-connections (same pod talking to itself)
	if srcNs == dstNs && srcPod == dstPod {
		return
	}

	// Skip if source or destination is empty
	if srcNs == "" || srcPod == "" || dstNs == "" || dstPod == "" {
		return
	}

	log.Printf("mesh-topology: recording %s/%s -> %s/%s:%d", srcNs, srcPod, dstNs, dstPod, destPort)

	r.bufferMu.Lock()
	r.buffer = append(r.buffer, meshConnectionEvent{
		ClusterID:       r.agent.ClusterID,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		SourceNamespace: srcNs,
		SourcePod:       srcPod,
		DestNamespace:   dstNs,
		DestPod:         dstPod,
		DestPort:        destPort,
		Protocol:        "TCP",
		BytesSent:       bytesSent,
		BytesReceived:   bytesRecv,
		Status:          "success",
	})

	// Flush if buffer is large
	if len(r.buffer) >= 50 {
		buf := r.buffer
		r.buffer = make([]meshConnectionEvent, 0, 50)
		r.bufferMu.Unlock()
		go r.sendEvents(buf)
	} else {
		r.bufferMu.Unlock()
	}
}

// RecordThreat records a DPI-detected threat for reporting to the backend
func (r *MeshTopologyReporter) RecordThreat(ns, pod string, result InspectionResult) {
	if r.agent.BackendURL == "" {
		return
	}

	srcIP := ""
	dstIP := ""
	if result.SrcIP != nil {
		srcIP = result.SrcIP.String()
	}
	if result.DstIP != nil {
		dstIP = result.DstIP.String()
	}

	event := meshThreatEvent{
		ClusterID:   r.agent.ClusterID,
		Timestamp:   result.Timestamp.UTC().Format(time.RFC3339),
		Namespace:   ns,
		Pod:         pod,
		ThreatLevel: result.ThreatLevel.String(),
		Category:    string(result.Category),
		Description: result.Description,
		Score:       result.Score,
		MitreATTCK:  result.MitreATTCK,
		Indicators:  result.Indicators,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		SrcPort:     result.SrcPort,
		DstPort:     result.DstPort,
		Blocked:     result.ShouldBlock,
		Metadata:    result.Metadata,
	}

	log.Printf("mesh-topology: recording threat from %s/%s: %s (level=%s)", ns, pod, result.Description, result.ThreatLevel.String())

	r.bufferMu.Lock()
	r.threatBuffer = append(r.threatBuffer, event)

	// Flush immediately for critical threats, or when buffer is full
	if result.ThreatLevel == ThreatCritical || len(r.threatBuffer) >= 20 {
		buf := r.threatBuffer
		r.threatBuffer = make([]meshThreatEvent, 0, 20)
		r.bufferMu.Unlock()
		go r.sendThreatEvents(buf)
	} else {
		r.bufferMu.Unlock()
	}
}

func (r *MeshTopologyReporter) flush() {
	r.bufferMu.Lock()
	connBuf := r.buffer
	threatBuf := r.threatBuffer
	r.buffer = make([]meshConnectionEvent, 0, 50)
	r.threatBuffer = make([]meshThreatEvent, 0, 20)
	r.bufferMu.Unlock()

	if len(connBuf) > 0 {
		r.sendEvents(connBuf)
	}
	if len(threatBuf) > 0 {
		r.sendThreatEvents(threatBuf)
	}
}

func (r *MeshTopologyReporter) sendEvents(events []meshConnectionEvent) error {
	if len(events) == 0 {
		return nil
	}

	payload := map[string]interface{}{
		"organization_id": r.agent.OrganizationID,
		"cluster_id":      r.agent.ClusterID,
		"events":          events,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("mesh-topology: marshal error: %v", err)
		return err
	}

	url := fmt.Sprintf("%s/api/v1/agent/ztunnel/events", r.agent.BackendURL)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.agent.AgentToken)
	req.Header.Set("X-Cluster-ID", r.agent.ClusterID)

	resp, err := r.agent.HTTPClient.Do(req)
	if err != nil {
		log.Printf("mesh-topology: send failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("mesh-topology: backend returned %d", resp.StatusCode)
		return fmt.Errorf("backend returned %d", resp.StatusCode)
	}

	// Also publish to NATS for real-time backend subscription (mesh.connections)
	if r.natsConn != nil && r.natsSubject != "" && r.agent.OrganizationID != 0 {
		if err := r.natsConn.Publish(r.natsSubject, body); err != nil {
			log.Printf("mesh-topology: NATS publish failed: %v", err)
		}
	}

	log.Printf("mesh-topology: sent %d connection events", len(events))
	return nil
}

// sendThreatEvents sends DPI threat events to the backend
func (r *MeshTopologyReporter) sendThreatEvents(events []meshThreatEvent) error {
	if len(events) == 0 {
		return nil
	}

	payload := map[string]interface{}{
		"cluster_id": r.agent.ClusterID,
		"threats":    events,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("mesh-topology: threat marshal error: %v", err)
		return err
	}

	url := fmt.Sprintf("%s/api/v1/agent/threats", r.agent.BackendURL)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.agent.AgentToken)
	req.Header.Set("X-Cluster-ID", r.agent.ClusterID)

	resp, err := r.agent.HTTPClient.Do(req)
	if err != nil {
		log.Printf("mesh-topology: threat send failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("mesh-topology: backend returned %d for threats", resp.StatusCode)
		return fmt.Errorf("backend returned %d", resp.StatusCode)
	}

	log.Printf("mesh-topology: sent %d threat events", len(events))
	return nil
}
