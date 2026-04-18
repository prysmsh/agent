package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
)

const (
	ctFinalizer     = "prysm.sh/tunnel-cleanup"
	ctAnnotOrigin   = "prysm.sh/origin"    // "cr" or "backend"
	ctAnnotTunnelID = "prysm.sh/tunnel-id" // backend tunnel ID string
)

// agentClusterTunnelRecord is the JSON shape returned by GET /api/v1/agent/cluster-tunnels.
type agentClusterTunnelRecord struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Service   string `json:"target_service"`
	Namespace string `json:"target_namespace"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Enabled   bool   `json:"enabled"`
}

// clusterTunnelController watches ClusterTunnel CRs and syncs them bidirectionally with the backend.
type clusterTunnelController struct {
	agent     *PrysmAgent
	dynClient dynamic.Interface
	namespace string
}

// startClusterTunnelController starts the CRD controller in a background goroutine.
func (a *PrysmAgent) startClusterTunnelController(ctx context.Context) {
	if a.dynamicClient == nil {
		log.Println("ct-controller: no dynamic client, skipping")
		return
	}
	if getEnvOrDefault("CCT_CRD_DISABLED", "") == "true" {
		log.Println("ct-controller: disabled via CCT_CRD_DISABLED=true")
		return
	}

	ctrl := &clusterTunnelController{
		agent:     a,
		dynClient: a.dynamicClient,
		namespace: ccRouteAgentNamespace(),
	}

	go ctrl.run(ctx)
}

func (c *clusterTunnelController) run(ctx context.Context) {
	log.Printf("ct-controller: starting (namespace=%s)", c.namespace)

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(
		c.dynClient, 30*time.Second, c.namespace, nil,
	)
	informer := factory.ForResource(ctGVR).Informer()

	reconcileCh := make(chan struct{}, 1)
	triggerReconcile := func() {
		select {
		case reconcileCh <- struct{}{}:
		default:
		}
	}

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(_ interface{}) { triggerReconcile() },
		UpdateFunc: func(_, _ interface{}) { triggerReconcile() },
		DeleteFunc: func(_ interface{}) { triggerReconcile() },
	})

	go informer.Run(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		log.Println("ct-controller: cache sync failed")
		return
	}
	log.Println("ct-controller: cache synced, starting reconcile loop")

	c.reconcile(ctx)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.reconcile(ctx)
		case <-reconcileCh:
			c.reconcile(ctx)
		}
	}
}

// reconcile performs a full bidirectional sync between ClusterTunnel CRs and the backend.
func (c *clusterTunnelController) reconcile(ctx context.Context) {
	backendTunnels, err := c.fetchBackendTunnels(ctx)
	if err != nil {
		log.Printf("ct-controller: fetch backend tunnels failed: %v", err)
		return
	}

	crList, err := c.dynClient.Resource(ctGVR).Namespace(c.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("ct-controller: list CRs failed: %v", err)
		return
	}

	// Index CRs by tunnel-id annotation
	crsByTunnelID := map[string]unstructured.Unstructured{}
	var crs []unstructured.Unstructured
	for _, item := range crList.Items {
		crs = append(crs, item)
		if ann := item.GetAnnotations(); ann != nil {
			if id := ann[ctAnnotTunnelID]; id != "" {
				crsByTunnelID[id] = item
			}
		}
	}

	// Index backend tunnels by ID
	backendByID := map[int64]agentClusterTunnelRecord{}
	for _, t := range backendTunnels {
		backendByID[t.ID] = t
	}

	// --- Upstream sync: CRs with origin=cr → create in backend ---
	for i := range crs {
		cr := &crs[i]
		c.handleCRUpstream(ctx, cr, backendByID)
	}

	// --- Handle deletions (finalizer) ---
	for i := range crs {
		cr := &crs[i]
		if cr.GetDeletionTimestamp() != nil {
			c.handleCRDeletion(ctx, cr)
		}
	}

	// --- Downstream sync: backend tunnels with no matching CR → create CR ---
	for _, t := range backendTunnels {
		idStr := strconv.FormatInt(t.ID, 10)
		if _, exists := crsByTunnelID[idStr]; !exists {
			c.createCRFromBackend(ctx, t)
		}
	}

	// --- Remove CRs whose backend tunnel no longer exists (origin=backend only) ---
	for i := range crs {
		cr := &crs[i]
		if cr.GetDeletionTimestamp() != nil {
			continue
		}
		ann := cr.GetAnnotations()
		if ann == nil || ann[ctAnnotOrigin] != "backend" {
			continue
		}
		idStr := ann[ctAnnotTunnelID]
		if idStr == "" {
			continue
		}
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			continue
		}
		if _, exists := backendByID[id]; !exists {
			log.Printf("ct-controller: backend tunnel %s removed, deleting CR %s", idStr, cr.GetName())
			_ = c.dynClient.Resource(ctGVR).Namespace(c.namespace).Delete(ctx, cr.GetName(), metav1.DeleteOptions{})
		}
	}
}

// handleCRUpstream syncs a CR-originated tunnel to the backend.
func (c *clusterTunnelController) handleCRUpstream(ctx context.Context, cr *unstructured.Unstructured, backendByID map[int64]agentClusterTunnelRecord) {
	if cr.GetDeletionTimestamp() != nil {
		return
	}

	ann := cr.GetAnnotations()
	if ann == nil {
		ann = map[string]string{}
	}

	origin := ann[ctAnnotOrigin]
	if origin == "" {
		ann[ctAnnotOrigin] = "cr"
		origin = "cr"
		cr.SetAnnotations(ann)
		c.patchAnnotations(ctx, cr)
	}
	if origin != "cr" {
		return
	}

	// Already synced?
	if ann[ctAnnotTunnelID] != "" {
		return
	}

	c.ensureFinalizer(ctx, cr)
	c.updateCRStatus(ctx, cr, "Pending", "Creating tunnel in backend")

	spec, err := extractCTSpec(cr)
	if err != nil {
		log.Printf("ct-controller: invalid spec on CR %s: %v", cr.GetName(), err)
		c.updateCRStatus(ctx, cr, "Error", err.Error())
		return
	}

	tunnelID, err := c.createTunnelInBackend(ctx, spec, cr.GetName())
	if err != nil {
		log.Printf("ct-controller: backend create failed for CR %s: %v", cr.GetName(), err)
		c.updateCRStatus(ctx, cr, "Error", err.Error())
		return
	}

	ann[ctAnnotTunnelID] = strconv.FormatInt(tunnelID, 10)
	cr.SetAnnotations(ann)
	c.patchAnnotations(ctx, cr)
	c.patchSpecBackendTunnelID(ctx, cr, tunnelID)
	c.updateCRStatus(ctx, cr, "Active", fmt.Sprintf("Synced to backend tunnel %d", tunnelID))
	log.Printf("ct-controller: CR %s → backend tunnel %d", cr.GetName(), tunnelID)
}

// handleCRDeletion processes CRs being deleted (finalizer cleanup).
func (c *clusterTunnelController) handleCRDeletion(ctx context.Context, cr *unstructured.Unstructured) {
	finalizers := cr.GetFinalizers()
	hasFinalizer := false
	for _, f := range finalizers {
		if f == ctFinalizer {
			hasFinalizer = true
			break
		}
	}
	if !hasFinalizer {
		return
	}

	ann := cr.GetAnnotations()
	if ann != nil {
		if idStr := ann[ctAnnotTunnelID]; idStr != "" {
			if err := c.deleteTunnelInBackend(ctx, idStr); err != nil {
				log.Printf("ct-controller: backend delete failed for tunnel %s: %v", idStr, err)
				return
			}
			log.Printf("ct-controller: deleted backend tunnel %s for CR %s", idStr, cr.GetName())
		}
	}

	var newFinalizers []string
	for _, f := range finalizers {
		if f != ctFinalizer {
			newFinalizers = append(newFinalizers, f)
		}
	}
	cr.SetFinalizers(newFinalizers)

	patch, _ := json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"finalizers": newFinalizers,
		},
	})
	_, err := c.dynClient.Resource(ctGVR).Namespace(c.namespace).Patch(
		ctx, cr.GetName(), types.MergePatchType, patch, metav1.PatchOptions{},
	)
	if err != nil {
		log.Printf("ct-controller: remove finalizer failed for CR %s: %v", cr.GetName(), err)
	}
}

// createCRFromBackend creates a ClusterTunnel CR from a backend tunnel record.
func (c *clusterTunnelController) createCRFromBackend(ctx context.Context, t agentClusterTunnelRecord) {
	name := fmt.Sprintf("backend-%d", t.ID)

	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": ctGroup + "/" + ctVersion,
			"kind":       ctKind,
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": c.namespace,
				"annotations": map[string]interface{}{
					ctAnnotOrigin:   "backend",
					ctAnnotTunnelID: strconv.FormatInt(t.ID, 10),
				},
			},
			"spec": map[string]interface{}{
				"service":         t.Service,
				"namespace":       t.Namespace,
				"port":            int64(t.Port),
				"protocol":        t.Protocol,
				"enabled":         t.Enabled,
				"backendTunnelID": t.ID,
			},
		},
	}

	_, err := c.dynClient.Resource(ctGVR).Namespace(c.namespace).Create(ctx, cr, metav1.CreateOptions{})
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			log.Printf("ct-controller: create CR for backend tunnel %d failed: %v", t.ID, err)
		}
		return
	}
	log.Printf("ct-controller: created CR %s from backend tunnel %d", name, t.ID)
}

// createTunnelInBackend POSTs a new ClusterTunnel to the backend.
func (c *clusterTunnelController) createTunnelInBackend(ctx context.Context, spec ClusterTunnelSpec, crName string) (int64, error) {
	if spec.Namespace == "" {
		spec.Namespace = "default"
	}
	if spec.Protocol == "" {
		spec.Protocol = "tcp"
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":             crName,
		"target_service":   spec.Service,
		"target_namespace": spec.Namespace,
		"port":             spec.Port,
		"protocol":         spec.Protocol,
		"enabled":          ctSpecEnabled(spec),
	})

	url := fmt.Sprintf("%s/api/v1/agent/cluster-tunnels", c.agent.BackendURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.agent.AgentToken)
	req.Header.Set("X-Cluster-ID", c.agent.ClusterID)

	resp, err := c.agent.HTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return 0, fmt.Errorf("backend returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Tunnel struct {
			ID int64 `json:"id"`
		} `json:"tunnel"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return 0, fmt.Errorf("parse response: %w", err)
	}
	return result.Tunnel.ID, nil
}

// deleteTunnelInBackend DELETEs a ClusterTunnel from the backend.
func (c *clusterTunnelController) deleteTunnelInBackend(ctx context.Context, tunnelID string) error {
	url := fmt.Sprintf("%s/api/v1/agent/cluster-tunnels/%s", c.agent.BackendURL, tunnelID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.agent.AgentToken)
	req.Header.Set("X-Cluster-ID", c.agent.ClusterID)

	resp, err := c.agent.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil // already deleted
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("backend returned %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// fetchBackendTunnels retrieves ClusterTunnel records from the backend for this cluster.
func (c *clusterTunnelController) fetchBackendTunnels(ctx context.Context) ([]agentClusterTunnelRecord, error) {
	url := fmt.Sprintf("%s/api/v1/agent/cluster-tunnels", c.agent.BackendURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.agent.AgentToken)
	req.Header.Set("X-Cluster-ID", c.agent.ClusterID)

	resp, err := c.agent.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("backend returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Tunnels []agentClusterTunnelRecord `json:"tunnels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return result.Tunnels, nil
}

// --- Helper methods ---

func extractCTSpec(cr *unstructured.Unstructured) (ClusterTunnelSpec, error) {
	specRaw, ok := cr.Object["spec"]
	if !ok {
		return ClusterTunnelSpec{}, fmt.Errorf("missing spec")
	}
	data, err := json.Marshal(specRaw)
	if err != nil {
		return ClusterTunnelSpec{}, err
	}
	var spec ClusterTunnelSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return ClusterTunnelSpec{}, err
	}
	return spec, nil
}

func (c *clusterTunnelController) ensureFinalizer(ctx context.Context, cr *unstructured.Unstructured) {
	for _, f := range cr.GetFinalizers() {
		if f == ctFinalizer {
			return
		}
	}
	finalizers := append(cr.GetFinalizers(), ctFinalizer)
	patch, _ := json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"finalizers": finalizers,
		},
	})
	_, err := c.dynClient.Resource(ctGVR).Namespace(c.namespace).Patch(
		ctx, cr.GetName(), types.MergePatchType, patch, metav1.PatchOptions{},
	)
	if err != nil {
		log.Printf("ct-controller: add finalizer failed for CR %s: %v", cr.GetName(), err)
	}
}

func (c *clusterTunnelController) patchAnnotations(ctx context.Context, cr *unstructured.Unstructured) {
	patch, _ := json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": cr.GetAnnotations(),
		},
	})
	_, err := c.dynClient.Resource(ctGVR).Namespace(c.namespace).Patch(
		ctx, cr.GetName(), types.MergePatchType, patch, metav1.PatchOptions{},
	)
	if err != nil {
		log.Printf("ct-controller: patch annotations failed for CR %s: %v", cr.GetName(), err)
	}
}

func (c *clusterTunnelController) patchSpecBackendTunnelID(ctx context.Context, cr *unstructured.Unstructured, tunnelID int64) {
	patch, _ := json.Marshal(map[string]interface{}{
		"spec": map[string]interface{}{
			"backendTunnelID": tunnelID,
		},
	})
	_, err := c.dynClient.Resource(ctGVR).Namespace(c.namespace).Patch(
		ctx, cr.GetName(), types.MergePatchType, patch, metav1.PatchOptions{},
	)
	if err != nil {
		log.Printf("ct-controller: patch spec.backendTunnelID failed for CR %s: %v", cr.GetName(), err)
	}
}

func (c *clusterTunnelController) updateCRStatus(ctx context.Context, cr *unstructured.Unstructured, phase, message string) {
	now := time.Now().UTC().Format(time.RFC3339)
	gen := cr.GetGeneration()

	patch, _ := json.Marshal(map[string]interface{}{
		"status": map[string]interface{}{
			"phase":              phase,
			"message":            message,
			"lastSyncedAt":       now,
			"observedGeneration": gen,
		},
	})
	_, err := c.dynClient.Resource(ctGVR).Namespace(c.namespace).Patch(
		ctx, cr.GetName(), types.MergePatchType, patch, metav1.PatchOptions{}, "status",
	)
	if err != nil {
		log.Printf("ct-controller: status update failed for CR %s: %v", cr.GetName(), err)
	}
}
