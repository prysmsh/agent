package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
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
	meshRouteAnnotOrigin = "prysm.sh/origin"    // "backend"
	meshRouteAnnotKey    = "prysm.sh/route-key" // stable backend key
)

var meshRouteNameSanitizer = regexp.MustCompile(`[^a-z0-9-]+`)

type meshRouteAssignment struct {
	ID               uint   `json:"id"`
	Name             string `json:"name"`
	Slug             string `json:"slug"`
	ExternalPort     int    `json:"external_port"`
	ServiceName      string `json:"service_name"`
	ServiceNamespace string `json:"service_namespace"`
	ServicePort      int    `json:"service_port"`
	Protocol         string `json:"protocol"`
	Enabled          *bool  `json:"enabled"`
	Status           string `json:"status"`
	Message          string `json:"message"`
}

type meshRouteController struct {
	agent     *PrysmAgent
	dynClient dynamic.Interface
	namespace string
}

func (a *PrysmAgent) startMeshRouteController(ctx context.Context) {
	if a.dynamicClient == nil {
		log.Println("mesh-route-controller: no dynamic client, skipping")
		return
	}
	if getEnvOrDefault("MESH_ROUTE_CRD_DISABLED", "") == "true" {
		log.Println("mesh-route-controller: disabled via MESH_ROUTE_CRD_DISABLED=true")
		return
	}

	ctrl := &meshRouteController{
		agent:     a,
		dynClient: a.dynamicClient,
		namespace: ccRouteAgentNamespace(),
	}
	go ctrl.run(ctx)
}

func (c *meshRouteController) run(ctx context.Context) {
	log.Printf("mesh-route-controller: starting (namespace=%s)", c.namespace)

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(
		c.dynClient, 30*time.Second, c.namespace, nil,
	)
	informer := factory.ForResource(mrGVR).Informer()

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
		log.Println("mesh-route-controller: cache sync failed")
		return
	}
	log.Println("mesh-route-controller: cache synced, starting reconcile loop")

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

func (c *meshRouteController) reconcile(ctx context.Context) {
	backendRoutes, err := c.fetchBackendMeshRoutes(ctx)
	if err != nil {
		log.Printf("mesh-route-controller: fetch backend mesh routes failed: %v", err)
		return
	}

	crList, err := c.dynClient.Resource(mrGVR).Namespace(c.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("mesh-route-controller: list CRs failed: %v", err)
		return
	}

	crByKey := map[string]unstructured.Unstructured{}
	for _, item := range crList.Items {
		ann := item.GetAnnotations()
		if ann == nil || ann[meshRouteAnnotOrigin] != "backend" {
			continue
		}
		if key := strings.TrimSpace(ann[meshRouteAnnotKey]); key != "" {
			crByKey[key] = item
		}
	}

	seen := map[string]struct{}{}
	for _, route := range backendRoutes {
		key := meshRouteKey(route)
		seen[key] = struct{}{}
		if existing, ok := crByKey[key]; ok {
			c.patchMeshRouteCR(ctx, existing.GetName(), route)
			continue
		}
		c.createMeshRouteCR(ctx, route, key)
	}

	for _, item := range crList.Items {
		ann := item.GetAnnotations()
		if ann == nil || ann[meshRouteAnnotOrigin] != "backend" {
			continue
		}
		key := strings.TrimSpace(ann[meshRouteAnnotKey])
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		if err := c.dynClient.Resource(mrGVR).Namespace(c.namespace).Delete(ctx, item.GetName(), metav1.DeleteOptions{}); err != nil {
			log.Printf("mesh-route-controller: delete stale CR %s failed: %v", item.GetName(), err)
		}
	}
}

func (c *meshRouteController) fetchBackendMeshRoutes(ctx context.Context) ([]meshRouteAssignment, error) {
	base := strings.TrimSuffix(c.agent.BackendURL, "/")
	if base == "" || c.agent.ClusterID == "" || c.agent.AgentToken == "" {
		return nil, fmt.Errorf("backend URL/cluster ID/agent token missing")
	}

	url := fmt.Sprintf("%s/api/v1/agent/mesh-routes/clusters/%s", base, c.agent.ClusterID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Agent-Token", c.agent.AgentToken)
	req.Header.Set("X-Cluster-ID", c.agent.ClusterID)

	resp, err := c.agent.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("backend returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out struct {
		Routes []meshRouteAssignment `json:"routes"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out.Routes, nil
}

func (c *meshRouteController) createMeshRouteCR(ctx context.Context, r meshRouteAssignment, routeKey string) {
	name := meshRouteCRName(r, routeKey)
	namespace := strings.TrimSpace(r.ServiceNamespace)
	if namespace == "" {
		namespace = "default"
	}
	protocol := meshRouteProtocol(r.Protocol)
	phase := meshRouteStatusPhase(r)
	message := meshRouteStatusMessage(r)
	now := time.Now().UTC().Format(time.RFC3339)

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": ccrGroup + "/" + ccrVersion,
			"kind":       mrKind,
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": c.namespace,
				"annotations": map[string]interface{}{
					meshRouteAnnotOrigin: "backend",
					meshRouteAnnotKey:    routeKey,
				},
			},
			"spec": map[string]interface{}{
				"routeID":          int64(r.ID),
				"name":             r.Name,
				"slug":             r.Slug,
				"externalPort":     int64(r.ExternalPort),
				"serviceName":      r.ServiceName,
				"serviceNamespace": namespace,
				"servicePort":      int64(r.ServicePort),
				"protocol":         protocol,
				"enabled":          meshRouteEnabled(r),
			},
			"status": map[string]interface{}{
				"phase":              phase,
				"message":            message,
				"lastSyncedAt":       now,
				"observedGeneration": int64(1),
			},
		},
	}

	if _, err := c.dynClient.Resource(mrGVR).Namespace(c.namespace).Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			log.Printf("mesh-route-controller: create CR for route %q failed: %v", routeKey, err)
		}
	}
}

func (c *meshRouteController) patchMeshRouteCR(ctx context.Context, crName string, r meshRouteAssignment) {
	current, err := c.dynClient.Resource(mrGVR).Namespace(c.namespace).Get(ctx, crName, metav1.GetOptions{})
	if err != nil {
		log.Printf("mesh-route-controller: get CR %s failed: %v", crName, err)
		return
	}

	namespace := strings.TrimSpace(r.ServiceNamespace)
	if namespace == "" {
		namespace = "default"
	}
	protocol := meshRouteProtocol(r.Protocol)
	now := time.Now().UTC().Format(time.RFC3339)

	specPatch := map[string]interface{}{
		"spec": map[string]interface{}{
			"routeID":          int64(r.ID),
			"name":             r.Name,
			"slug":             r.Slug,
			"externalPort":     int64(r.ExternalPort),
			"serviceName":      r.ServiceName,
			"serviceNamespace": namespace,
			"servicePort":      int64(r.ServicePort),
			"protocol":         protocol,
			"enabled":          meshRouteEnabled(r),
		},
	}
	specBody, _ := json.Marshal(specPatch)
	if _, err := c.dynClient.Resource(mrGVR).Namespace(c.namespace).Patch(
		ctx, crName, types.MergePatchType, specBody, metav1.PatchOptions{},
	); err != nil {
		log.Printf("mesh-route-controller: spec patch failed for CR %s: %v", crName, err)
		return
	}

	statusPatch := map[string]interface{}{
		"status": map[string]interface{}{
			"phase":              meshRouteStatusPhase(r),
			"message":            meshRouteStatusMessage(r),
			"lastSyncedAt":       now,
			"observedGeneration": current.GetGeneration(),
		},
	}
	statusBody, _ := json.Marshal(statusPatch)
	if _, err := c.dynClient.Resource(mrGVR).Namespace(c.namespace).Patch(
		ctx, crName, types.MergePatchType, statusBody, metav1.PatchOptions{}, "status",
	); err != nil {
		log.Printf("mesh-route-controller: status patch failed for CR %s: %v", crName, err)
	}
}

func meshRouteStatusPhase(r meshRouteAssignment) string {
	status := strings.TrimSpace(r.Status)
	if status == "" {
		if meshRouteEnabled(r) {
			return "Active"
		}
		return "Disabled"
	}
	switch strings.ToLower(status) {
	case "active":
		return "Active"
	case "pending":
		return "Pending"
	case "error":
		return "Error"
	case "disabled":
		return "Disabled"
	default:
		return status
	}
}

func meshRouteStatusMessage(r meshRouteAssignment) string {
	if msg := strings.TrimSpace(r.Message); msg != "" {
		return msg
	}
	namespace := strings.TrimSpace(r.ServiceNamespace)
	if namespace == "" {
		namespace = "default"
	}
	return fmt.Sprintf("%s.%s:%d <- external:%d", r.ServiceName, namespace, r.ServicePort, r.ExternalPort)
}

func meshRouteEnabled(r meshRouteAssignment) bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

func meshRouteProtocol(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "tcp", "udp":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return "tcp"
	}
}

func meshRouteKey(r meshRouteAssignment) string {
	if r.ID > 0 {
		return "id:" + strconv.FormatUint(uint64(r.ID), 10)
	}
	if s := strings.TrimSpace(r.Slug); s != "" {
		return "slug:" + strings.ToLower(s)
	}
	namespace := strings.TrimSpace(r.ServiceNamespace)
	if namespace == "" {
		namespace = "default"
	}
	return fmt.Sprintf("route:%s/%s:%d:%d", namespace, r.ServiceName, r.ServicePort, r.ExternalPort)
}

func meshRouteCRName(r meshRouteAssignment, routeKey string) string {
	base := strings.ToLower(strings.TrimSpace(r.Slug))
	if base == "" && r.ID > 0 {
		base = "id-" + strconv.FormatUint(uint64(r.ID), 10)
	}
	if base == "" {
		base = routeKey
	}
	base = strings.ReplaceAll(base, "_", "-")
	base = meshRouteNameSanitizer.ReplaceAllString(base, "-")
	base = strings.Trim(base, "-")
	if len(base) == 0 {
		base = "route"
	}
	if len(base) > 42 {
		base = base[:42]
		base = strings.Trim(base, "-")
	}
	return "backend-" + base
}
