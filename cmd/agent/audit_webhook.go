package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// auditConfig configures the K8s audit log webhook handler.
type auditConfig struct {
	BackendURL     string
	AgentToken     string
	ClusterID      string
	OrganizationID uint
	BatchSize      int
	FlushInterval  time.Duration
}

// auditWebhookHandler receives Kubernetes audit webhook events and forwards
// them to the Prysm backend as security events.
type auditWebhookHandler struct {
	config     auditConfig
	httpClient *http.Client
	mu         sync.Mutex
	batch      []auditEvent
	lastFlush  time.Time
}

// auditEvent is a simplified Kubernetes audit event for forwarding.
type auditEvent struct {
	Level             string                 `json:"level"`
	AuditID           string                 `json:"auditID"`
	Stage             string                 `json:"stage"`
	RequestURI        string                 `json:"requestURI"`
	Verb              string                 `json:"verb"`
	UserName          string                 `json:"userName"`
	UserGroups        []string               `json:"userGroups,omitempty"`
	SourceIPs         []string               `json:"sourceIPs,omitempty"`
	UserAgent         string                 `json:"userAgent,omitempty"`
	ObjectRef         *auditObjectRef        `json:"objectRef,omitempty"`
	ResponseCode      int                    `json:"responseCode,omitempty"`
	RequestTimestamp  string                 `json:"requestTimestamp,omitempty"`
	StageTimestamp    string                 `json:"stageTimestamp,omitempty"`
	Annotations       map[string]string      `json:"annotations,omitempty"`
	RequestObject     map[string]interface{} `json:"requestObject,omitempty"`
	SecurityRelevance string                 `json:"securityRelevance,omitempty"`
}

type auditObjectRef struct {
	Resource    string `json:"resource"`
	Namespace   string `json:"namespace,omitempty"`
	Name        string `json:"name,omitempty"`
	APIGroup    string `json:"apiGroup,omitempty"`
	APIVersion  string `json:"apiVersion,omitempty"`
	Subresource string `json:"subresource,omitempty"`
}

func newAuditWebhookHandler(cfg auditConfig) *auditWebhookHandler {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 3 * time.Second
	}

	h := &auditWebhookHandler{
		config:     cfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		batch:      make([]auditEvent, 0, cfg.BatchSize),
		lastFlush:  time.Now(),
	}
	go h.backgroundFlusher()
	return h
}

func (h *auditWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// K8s audit webhook sends an EventList.
	var eventList struct {
		APIVersion string                   `json:"apiVersion"`
		Kind       string                   `json:"kind"`
		Items      []map[string]interface{} `json:"items"`
	}
	if err := json.Unmarshal(body, &eventList); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	var events []auditEvent
	for _, item := range eventList.Items {
		evt := h.parseAuditEvent(item)
		if evt == nil {
			continue
		}
		// Classify security relevance.
		evt.SecurityRelevance = h.classifyEvent(evt)
		events = append(events, *evt)
	}

	if len(events) > 0 {
		h.mu.Lock()
		h.batch = append(h.batch, events...)
		shouldFlush := len(h.batch) >= h.config.BatchSize
		h.mu.Unlock()

		if shouldFlush {
			h.flush()
		}
	}

	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte(`{"status":"accepted"}`))
}

func (h *auditWebhookHandler) parseAuditEvent(raw map[string]interface{}) *auditEvent {
	evt := &auditEvent{}
	evt.Level, _ = raw["level"].(string)
	evt.AuditID, _ = raw["auditID"].(string)
	evt.Stage, _ = raw["stage"].(string)
	evt.RequestURI, _ = raw["requestURI"].(string)
	evt.Verb, _ = raw["verb"].(string)
	evt.UserAgent, _ = raw["userAgent"].(string)
	evt.RequestTimestamp, _ = raw["requestReceivedTimestamp"].(string)
	evt.StageTimestamp, _ = raw["stageTimestamp"].(string)

	if user, ok := raw["user"].(map[string]interface{}); ok {
		evt.UserName, _ = user["username"].(string)
		if groups, ok := user["groups"].([]interface{}); ok {
			for _, g := range groups {
				if s, ok := g.(string); ok {
					evt.UserGroups = append(evt.UserGroups, s)
				}
			}
		}
	}

	if ips, ok := raw["sourceIPs"].([]interface{}); ok {
		for _, ip := range ips {
			if s, ok := ip.(string); ok {
				evt.SourceIPs = append(evt.SourceIPs, s)
			}
		}
	}

	if objRef, ok := raw["objectRef"].(map[string]interface{}); ok {
		evt.ObjectRef = &auditObjectRef{}
		evt.ObjectRef.Resource, _ = objRef["resource"].(string)
		evt.ObjectRef.Namespace, _ = objRef["namespace"].(string)
		evt.ObjectRef.Name, _ = objRef["name"].(string)
		evt.ObjectRef.APIGroup, _ = objRef["apiGroup"].(string)
		evt.ObjectRef.APIVersion, _ = objRef["apiVersion"].(string)
		evt.ObjectRef.Subresource, _ = objRef["subresource"].(string)
	}

	if code, ok := raw["responseStatus"].(map[string]interface{}); ok {
		if c, ok := code["code"].(float64); ok {
			evt.ResponseCode = int(c)
		}
	}

	if annotations, ok := raw["annotations"].(map[string]interface{}); ok {
		evt.Annotations = make(map[string]string)
		for k, v := range annotations {
			evt.Annotations[k] = fmt.Sprintf("%v", v)
		}
	}

	// Only forward ResponseRequest stage events to avoid duplicates.
	if evt.Stage != "" && evt.Stage != "ResponseComplete" && evt.Stage != "ResponseStarted" {
		return nil
	}

	return evt
}

// classifyEvent determines if a K8s audit event is security-relevant.
func (h *auditWebhookHandler) classifyEvent(evt *auditEvent) string {
	if evt.ObjectRef == nil {
		return ""
	}

	// Privileged pod creation
	if evt.ObjectRef.Resource == "pods" && evt.Verb == "create" {
		return "pod_creation"
	}

	// Secret access
	if evt.ObjectRef.Resource == "secrets" && (evt.Verb == "get" || evt.Verb == "list" || evt.Verb == "watch") {
		return "secret_access"
	}

	// RBAC changes
	if evt.ObjectRef.Resource == "clusterrolebindings" || evt.ObjectRef.Resource == "rolebindings" ||
		evt.ObjectRef.Resource == "clusterroles" || evt.ObjectRef.Resource == "roles" {
		if evt.Verb == "create" || evt.Verb == "update" || evt.Verb == "patch" || evt.Verb == "delete" {
			return "rbac_change"
		}
	}

	// Exec into pod
	if evt.ObjectRef.Resource == "pods" && evt.ObjectRef.Subresource == "exec" {
		return "pod_exec"
	}

	// Port-forward
	if evt.ObjectRef.Resource == "pods" && evt.ObjectRef.Subresource == "portforward" {
		return "pod_portforward"
	}

	// Service account token creation
	if evt.ObjectRef.Resource == "serviceaccounts" && evt.ObjectRef.Subresource == "token" {
		return "sa_token_request"
	}

	// ConfigMap/Secret modification
	if (evt.ObjectRef.Resource == "configmaps" || evt.ObjectRef.Resource == "secrets") &&
		(evt.Verb == "create" || evt.Verb == "update" || evt.Verb == "patch" || evt.Verb == "delete") {
		return "config_modification"
	}

	// Namespace operations
	if evt.ObjectRef.Resource == "namespaces" && (evt.Verb == "create" || evt.Verb == "delete") {
		return "namespace_operation"
	}

	// Suspicious system user patterns
	if strings.HasPrefix(evt.UserName, "system:anonymous") {
		return "anonymous_access"
	}

	return ""
}

func (h *auditWebhookHandler) backgroundFlusher() {
	ticker := time.NewTicker(h.config.FlushInterval)
	defer ticker.Stop()
	for range ticker.C {
		h.flush()
	}
}

func (h *auditWebhookHandler) flush() {
	h.mu.Lock()
	batch := h.batch
	h.batch = make([]auditEvent, 0, h.config.BatchSize)
	h.lastFlush = time.Now()
	h.mu.Unlock()

	if len(batch) == 0 {
		return
	}

	// Convert to security events for the backend.
	var logEntries []map[string]interface{}
	for _, evt := range batch {
		entry := map[string]interface{}{
			"timestamp":  evt.RequestTimestamp,
			"level":      h.auditLevelToLogLevel(evt.Level),
			"message":    h.formatMessage(evt),
			"source":     "k8s_audit",
			"cluster_id": h.config.ClusterID,
			"tags":       []string{"k8s", "audit", evt.Verb},
			"metadata": map[string]interface{}{
				"org_id":              h.config.OrganizationID,
				"audit_id":           evt.AuditID,
				"verb":               evt.Verb,
				"user":               evt.UserName,
				"user_groups":        evt.UserGroups,
				"source_ips":         evt.SourceIPs,
				"request_uri":        evt.RequestURI,
				"response_code":      evt.ResponseCode,
				"security_relevance": evt.SecurityRelevance,
			},
		}

		if evt.ObjectRef != nil {
			entry["namespace"] = evt.ObjectRef.Namespace
			entry["metadata"].(map[string]interface{})["resource"] = evt.ObjectRef.Resource
			entry["metadata"].(map[string]interface{})["resource_name"] = evt.ObjectRef.Name
			entry["metadata"].(map[string]interface{})["subresource"] = evt.ObjectRef.Subresource
		}

		if evt.SecurityRelevance != "" {
			tags := entry["tags"].([]string)
			entry["tags"] = append(tags, "security", evt.SecurityRelevance)
		}

		logEntries = append(logEntries, entry)
	}

	payload, err := json.Marshal(map[string]interface{}{
		"agent_token": h.config.AgentToken,
		"batch_id":    fmt.Sprintf("audit-%d", time.Now().UnixNano()),
		"cluster_id":  h.config.ClusterID,
		"timestamp":   time.Now().UTC(),
		"logs":        logEntries,
	})
	if err != nil {
		log.Printf("audit webhook: marshal error: %v", err)
		return
	}

	endpoint := h.config.BackendURL
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}
	endpoint = strings.TrimSuffix(endpoint, "/api/v1/") + "/api/v1/logs/ingest"

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		log.Printf("audit webhook: request build error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.config.AgentToken)

	resp, err := h.httpClient.Do(req)
	if err != nil {
		log.Printf("audit webhook: flush failed (%d events): %v", len(batch), err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("audit webhook: backend rejected batch (%d events): status=%d", len(batch), resp.StatusCode)
	}
}

func (h *auditWebhookHandler) formatMessage(evt auditEvent) string {
	resource := ""
	if evt.ObjectRef != nil {
		resource = evt.ObjectRef.Resource
		if evt.ObjectRef.Namespace != "" {
			resource = evt.ObjectRef.Namespace + "/" + resource
		}
		if evt.ObjectRef.Name != "" {
			resource += "/" + evt.ObjectRef.Name
		}
		if evt.ObjectRef.Subresource != "" {
			resource += "/" + evt.ObjectRef.Subresource
		}
	}
	return fmt.Sprintf("K8s audit: %s %s by %s", evt.Verb, resource, evt.UserName)
}

func (h *auditWebhookHandler) auditLevelToLogLevel(level string) string {
	switch level {
	case "Panic", "RequestResponse":
		return "warn"
	case "Metadata":
		return "info"
	case "Request":
		return "info"
	default:
		return "debug"
	}
}

// setupAuditWebhookRoutes registers the K8s audit webhook endpoint.
func (a *PrysmAgent) setupAuditWebhookRoutes(mux *http.ServeMux) {
	if a.BackendURL == "" {
		log.Println("audit webhook: no backend URL, webhook disabled")
		return
	}

	cfg := auditConfig{
		BackendURL:     a.BackendURL,
		AgentToken:     a.AgentToken,
		ClusterID:      a.ClusterID,
		OrganizationID: a.OrganizationID,
		BatchSize:      50,
		FlushInterval:  3 * time.Second,
	}
	handler := newAuditWebhookHandler(cfg)
	mux.Handle("/api/v1/webhooks/audit", handler)
	log.Println("audit webhook: enabled at /api/v1/webhooks/audit")
}
