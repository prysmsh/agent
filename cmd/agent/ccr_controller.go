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
	ccrFinalizer    = "prysm.sh/route-cleanup"
	ccrAnnotOrigin  = "prysm.sh/origin"   // "cr" or "backend"
	ccrAnnotRouteID = "prysm.sh/route-id" // backend route ID (string)
)

// ccrController watches CrossClusterRoute CRs and syncs them bidirectionally with the backend.
type ccrController struct {
	agent     *PrysmAgent
	dynClient dynamic.Interface
	namespace string
}

// startCCRController starts the CRD controller in a background goroutine.
// It watches for CR changes and runs a periodic reconcile loop.
func (a *PrysmAgent) startCCRController(ctx context.Context) {
	if a.dynamicClient == nil {
		log.Println("ccr-controller: no dynamic client, skipping")
		return
	}
	if getEnvOrDefault("CCR_CRD_DISABLED", "") == "true" {
		log.Println("ccr-controller: disabled via CCR_CRD_DISABLED=true")
		return
	}

	ctrl := &ccrController{
		agent:     a,
		dynClient: a.dynamicClient,
		namespace: ccRouteAgentNamespace(),
	}

	go ctrl.run(ctx)
}

func (c *ccrController) run(ctx context.Context) {
	log.Printf("ccr-controller: starting (namespace=%s)", c.namespace)

	// Set up dynamic informer for CrossClusterRoute CRs
	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(
		c.dynClient, 30*time.Second, c.namespace, nil,
	)
	informer := factory.ForResource(ccrGVR).Informer()

	// Event handlers trigger immediate reconcile
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

	// Wait for cache sync
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		log.Println("ccr-controller: cache sync failed")
		return
	}
	log.Println("ccr-controller: cache synced, starting reconcile loop")

	// Initial reconcile
	c.reconcile(ctx)

	// Periodic + event-driven reconcile
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

// reconcile performs a full bidirectional sync between CRs and the backend.
func (c *ccrController) reconcile(ctx context.Context) {
	// Fetch backend routes
	backendRoutes, err := c.agent.ccRouteManager.fetchRoutes(ctx)
	if err != nil {
		log.Printf("ccr-controller: fetch backend routes failed: %v", err)
		return
	}

	// List CRs
	crList, err := c.dynClient.Resource(ccrGVR).Namespace(c.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("ccr-controller: list CRs failed: %v", err)
		return
	}

	// Index CRs by backendRouteID annotation
	crsByRouteID := map[string]unstructured.Unstructured{}
	var crs []unstructured.Unstructured
	for _, item := range crList.Items {
		crs = append(crs, item)
		if ann := item.GetAnnotations(); ann != nil {
			if id := ann[ccrAnnotRouteID]; id != "" {
				crsByRouteID[id] = item
			}
		}
	}

	// Index backend routes by ID
	backendByID := map[uint]crossClusterRouteAssignment{}
	for _, r := range backendRoutes {
		backendByID[r.ID] = r
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

	// --- Downstream sync: backend routes with no matching CR → create CR ---
	for _, r := range backendRoutes {
		idStr := strconv.FormatUint(uint64(r.ID), 10)
		if _, exists := crsByRouteID[idStr]; !exists {
			c.createCRFromBackend(ctx, r)
		}
	}

	// --- Remove CRs whose backend route no longer exists (origin=backend only) ---
	for i := range crs {
		cr := &crs[i]
		if cr.GetDeletionTimestamp() != nil {
			continue
		}
		ann := cr.GetAnnotations()
		if ann == nil || ann[ccrAnnotOrigin] != "backend" {
			continue
		}
		idStr := ann[ccrAnnotRouteID]
		if idStr == "" {
			continue
		}
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			continue
		}
		if _, exists := backendByID[uint(id)]; !exists {
			log.Printf("ccr-controller: backend route %s removed, deleting CR %s", idStr, cr.GetName())
			_ = c.dynClient.Resource(ccrGVR).Namespace(c.namespace).Delete(ctx, cr.GetName(), metav1.DeleteOptions{})
		}
	}

	// --- Feed merged routes to the route manager ---
	c.agent.ccRouteManager.reconcileFromAssignments(ctx, backendRoutes)

	// --- Publish runtime status (route + proxy health) back to CRDs ---
	proxyStatus := c.agent.ccRouteManager.getProxyHealthStatus(ctx)
	for i := range crs {
		cr := &crs[i]
		c.syncCRRuntimeStatus(ctx, cr, backendByID, proxyStatus)
	}
}

// handleCRUpstream syncs a CR-originated route to the backend.
func (c *ccrController) handleCRUpstream(ctx context.Context, cr *unstructured.Unstructured, backendByID map[uint]crossClusterRouteAssignment) {
	if cr.GetDeletionTimestamp() != nil {
		return
	}

	ann := cr.GetAnnotations()
	if ann == nil {
		ann = map[string]string{}
	}

	// Only process CR-originated routes that haven't been synced yet
	origin := ann[ccrAnnotOrigin]
	if origin == "" {
		// No origin set — treat as CR-originated, set annotation
		ann[ccrAnnotOrigin] = "cr"
		origin = "cr"
		cr.SetAnnotations(ann)
		c.patchAnnotations(ctx, cr)
	}
	if origin != "cr" {
		return
	}

	// Already synced?
	if ann[ccrAnnotRouteID] != "" {
		return
	}

	// Ensure finalizer
	c.ensureFinalizer(ctx, cr)

	// Update status to Syncing
	c.updateCRStatus(ctx, cr, "Syncing", "Creating route in backend")

	// Extract spec and POST to backend
	spec, err := extractSpec(cr)
	if err != nil {
		log.Printf("ccr-controller: invalid spec on CR %s: %v", cr.GetName(), err)
		c.updateCRStatus(ctx, cr, "Error", err.Error())
		return
	}

	routeID, err := c.createRouteInBackend(ctx, spec, cr.GetName())
	if err != nil {
		log.Printf("ccr-controller: backend create failed for CR %s: %v", cr.GetName(), err)
		c.updateCRStatus(ctx, cr, "Error", err.Error())
		return
	}

	// Patch CR with backend route ID
	ann[ccrAnnotRouteID] = strconv.FormatUint(uint64(routeID), 10)
	cr.SetAnnotations(ann)
	c.patchAnnotations(ctx, cr)

	// Update spec.backendRouteID
	c.patchSpecBackendRouteID(ctx, cr, routeID)

	c.updateCRStatus(ctx, cr, "Active", fmt.Sprintf("Synced to backend route %d", routeID))
	log.Printf("ccr-controller: CR %s → backend route %d", cr.GetName(), routeID)
}

// handleCRDeletion processes CRs being deleted (finalizer cleanup).
func (c *ccrController) handleCRDeletion(ctx context.Context, cr *unstructured.Unstructured) {
	finalizers := cr.GetFinalizers()
	hasFinalizer := false
	for _, f := range finalizers {
		if f == ccrFinalizer {
			hasFinalizer = true
			break
		}
	}
	if !hasFinalizer {
		return
	}

	// Delete backend route if this was a CR-originated route
	ann := cr.GetAnnotations()
	if ann != nil {
		if idStr := ann[ccrAnnotRouteID]; idStr != "" {
			if err := c.deleteRouteInBackend(ctx, idStr); err != nil {
				log.Printf("ccr-controller: backend delete failed for route %s: %v", idStr, err)
				// Don't remove finalizer — retry next reconcile
				return
			}
			log.Printf("ccr-controller: deleted backend route %s for CR %s", idStr, cr.GetName())
		}
	}

	// Remove finalizer
	var newFinalizers []string
	for _, f := range finalizers {
		if f != ccrFinalizer {
			newFinalizers = append(newFinalizers, f)
		}
	}
	cr.SetFinalizers(newFinalizers)

	patch, _ := json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"finalizers": newFinalizers,
		},
	})
	_, err := c.dynClient.Resource(ccrGVR).Namespace(c.namespace).Patch(
		ctx, cr.GetName(), types.MergePatchType, patch, metav1.PatchOptions{},
	)
	if err != nil {
		log.Printf("ccr-controller: remove finalizer failed for CR %s: %v", cr.GetName(), err)
	}
}

// createCRFromBackend creates a CR from a backend route (downstream sync).
func (c *ccrController) createCRFromBackend(ctx context.Context, r crossClusterRouteAssignment) {
	name := fmt.Sprintf("backend-%d", r.ID)

	enabled := r.Enabled
	cr := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": ccrGroup + "/" + ccrVersion,
			"kind":       ccrKind,
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": c.namespace,
				"annotations": map[string]interface{}{
					ccrAnnotOrigin:  "backend",
					ccrAnnotRouteID: strconv.FormatUint(uint64(r.ID), 10),
				},
			},
			"spec": map[string]interface{}{
				"sourceClusterID": int64(r.SourceClusterID),
				"targetClusterID": int64(r.TargetClusterID),
				"targetService":   r.TargetService,
				"targetNamespace": r.TargetNamespace,
				"targetPort":      int64(r.TargetPort),
				"localPort":       int64(r.LocalPort),
				"protocol":        r.Protocol,
				"enabled":         enabled,
				"backendRouteID":  int64(r.ID),
			},
		},
	}

	_, err := c.dynClient.Resource(ccrGVR).Namespace(c.namespace).Create(ctx, cr, metav1.CreateOptions{})
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			log.Printf("ccr-controller: create CR for backend route %d failed: %v", r.ID, err)
		}
		return
	}
	log.Printf("ccr-controller: created CR %s from backend route %d", name, r.ID)
}

// createRouteInBackend POSTs a new route to the backend.
func (c *ccrController) createRouteInBackend(ctx context.Context, spec CrossClusterRouteSpec, crName string) (uint, error) {
	name := crName
	if spec.TargetNamespace == "" {
		spec.TargetNamespace = "default"
	}
	if spec.Protocol == "" {
		spec.Protocol = "tcp"
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":              name,
		"source_cluster_id": spec.SourceClusterID,
		"target_cluster_id": spec.TargetClusterID,
		"target_service":    spec.TargetService,
		"target_namespace":  spec.TargetNamespace,
		"target_port":       spec.TargetPort,
		"local_port":        spec.LocalPort,
		"protocol":          spec.Protocol,
		"enabled":           ccrSpecEnabled(spec),
	})

	url := fmt.Sprintf("%s/api/v1/agent/cross-cluster-routes", c.agent.BackendURL)
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
		Route struct {
			ID uint `json:"id"`
		} `json:"route"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return 0, fmt.Errorf("parse response: %w", err)
	}
	return result.Route.ID, nil
}

// deleteRouteInBackend DELETEs a route from the backend.
func (c *ccrController) deleteRouteInBackend(ctx context.Context, routeID string) error {
	url := fmt.Sprintf("%s/api/v1/agent/cross-cluster-routes/%s", c.agent.BackendURL, routeID)
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

// --- Helper methods ---

func extractSpec(cr *unstructured.Unstructured) (CrossClusterRouteSpec, error) {
	specRaw, ok := cr.Object["spec"]
	if !ok {
		return CrossClusterRouteSpec{}, fmt.Errorf("missing spec")
	}
	data, err := json.Marshal(specRaw)
	if err != nil {
		return CrossClusterRouteSpec{}, err
	}
	var spec CrossClusterRouteSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return CrossClusterRouteSpec{}, err
	}
	return spec, nil
}

func (c *ccrController) ensureFinalizer(ctx context.Context, cr *unstructured.Unstructured) {
	for _, f := range cr.GetFinalizers() {
		if f == ccrFinalizer {
			return
		}
	}
	finalizers := append(cr.GetFinalizers(), ccrFinalizer)
	patch, _ := json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"finalizers": finalizers,
		},
	})
	_, err := c.dynClient.Resource(ccrGVR).Namespace(c.namespace).Patch(
		ctx, cr.GetName(), types.MergePatchType, patch, metav1.PatchOptions{},
	)
	if err != nil {
		log.Printf("ccr-controller: add finalizer failed for CR %s: %v", cr.GetName(), err)
	}
}

func (c *ccrController) patchAnnotations(ctx context.Context, cr *unstructured.Unstructured) {
	patch, _ := json.Marshal(map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": cr.GetAnnotations(),
		},
	})
	_, err := c.dynClient.Resource(ccrGVR).Namespace(c.namespace).Patch(
		ctx, cr.GetName(), types.MergePatchType, patch, metav1.PatchOptions{},
	)
	if err != nil {
		log.Printf("ccr-controller: patch annotations failed for CR %s: %v", cr.GetName(), err)
	}
}

func (c *ccrController) patchSpecBackendRouteID(ctx context.Context, cr *unstructured.Unstructured, routeID uint) {
	patch, _ := json.Marshal(map[string]interface{}{
		"spec": map[string]interface{}{
			"backendRouteID": routeID,
		},
	})
	_, err := c.dynClient.Resource(ccrGVR).Namespace(c.namespace).Patch(
		ctx, cr.GetName(), types.MergePatchType, patch, metav1.PatchOptions{},
	)
	if err != nil {
		log.Printf("ccr-controller: patch spec.backendRouteID failed for CR %s: %v", cr.GetName(), err)
	}
}

func (c *ccrController) updateCRStatus(ctx context.Context, cr *unstructured.Unstructured, phase, message string) {
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
	_, err := c.dynClient.Resource(ccrGVR).Namespace(c.namespace).Patch(
		ctx, cr.GetName(), types.MergePatchType, patch, metav1.PatchOptions{}, "status",
	)
	if err != nil {
		log.Printf("ccr-controller: status update failed for CR %s: %v", cr.GetName(), err)
	}
}

func statusPhaseFromBackend(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "active":
		return "Active"
	case "pending":
		return "Pending"
	case "error":
		return "Error"
	case "disabled":
		return "Disabled"
	case "disconnected":
		return "Disconnected"
	default:
		if s == "" {
			return "Pending"
		}
		return s
	}
}

func (c *ccrController) syncCRRuntimeStatus(
	ctx context.Context,
	cr *unstructured.Unstructured,
	backendByID map[uint]crossClusterRouteAssignment,
	proxyStatus ccProxyHealthStatus,
) {
	ann := cr.GetAnnotations()
	if ann == nil {
		return
	}

	idStr := strings.TrimSpace(ann[ccrAnnotRouteID])
	if idStr == "" {
		return
	}

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return
	}

	route, ok := backendByID[uint(id)]
	if !ok {
		return
	}

	serviceName := ccRouteServiceName(route)
	serviceIP := c.agent.ccRouteManager.getSourceRouteServiceIP(route.ID)
	phase := statusPhaseFromBackend(route.Status)
	message := fmt.Sprintf(
		"%s -> %s.%s:%d (local:%d)",
		route.Name, route.TargetService, route.TargetNamespace, route.TargetPort, route.LocalPort,
	)

	now := time.Now().UTC().Format(time.RFC3339)
	gen := cr.GetGeneration()

	patch := map[string]interface{}{
		"status": map[string]interface{}{
			"phase":              phase,
			"message":            message,
			"connectionMethod":   route.ConnectionMethod,
			"serviceName":        serviceName,
			"serviceIP":          serviceIP,
			"proxyPodName":       proxyStatus.Name,
			"proxyPodPhase":      proxyStatus.Phase,
			"proxyPodIP":         proxyStatus.IP,
			"proxyPodReady":      proxyStatus.Ready,
			"proxyMessage":       proxyStatus.Message,
			"lastSyncedAt":       now,
			"observedGeneration": gen,
		},
	}

	body, _ := json.Marshal(patch)
	if _, err := c.dynClient.Resource(ccrGVR).Namespace(c.namespace).Patch(
		ctx, cr.GetName(), types.MergePatchType, body, metav1.PatchOptions{}, "status",
	); err != nil {
		log.Printf("ccr-controller: runtime status update failed for CR %s: %v", cr.GetName(), err)
	}
}
