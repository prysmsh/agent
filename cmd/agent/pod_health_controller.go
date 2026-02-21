package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	podHealthAnnotationOptOut = "prysm.sh/pod-health-opt-out"
	prysmLabelPrefix          = "prysm.sh/"
)

// podHealthConfig holds configuration for the pod health controller.
type podHealthConfig struct {
	Enabled             bool
	ScanInterval        time.Duration
	EvictionThreshold   int
	EvictionWindow      time.Duration
	ResizePercent       float64
	MinMemoryMi         int64
	MinCPUMilli         int64
	MinReplicas         int32
	ProtectedNamespaces map[string]bool
}

// evictionRecord tracks eviction history for a single Deployment.
type evictionRecord struct {
	Timestamps  []time.Time
	ResizeCount int
	LastResize  time.Time
	ScaledDown  bool
}

// podHealthController manages evicted pod cleanup, resource resizing, and node pressure checks.
type podHealthController struct {
	agent   *PrysmAgent
	config  podHealthConfig
	mu      sync.Mutex
	tracker map[string]*evictionRecord // key: "namespace/deployment-name"
}

func loadPodHealthConfig() podHealthConfig {
	cfg := podHealthConfig{
		Enabled:           true,
		ScanInterval:      60 * time.Second,
		EvictionThreshold: 3,
		EvictionWindow:    10 * time.Minute,
		ResizePercent:     0.20,
		MinMemoryMi:       32,
		MinCPUMilli:       10,
		MinReplicas:       1,
		ProtectedNamespaces: map[string]bool{
			"kube-system":      true,
			"kube-public":      true,
			"kube-node-lease":  true,
			"prysm-system":    true,
		},
	}

	if strings.EqualFold(os.Getenv("POD_HEALTH_ENABLED"), "false") {
		cfg.Enabled = false
	}
	if d, err := time.ParseDuration(os.Getenv("POD_HEALTH_SCAN_INTERVAL")); err == nil && d > 0 {
		cfg.ScanInterval = d
	}
	if n, err := strconv.Atoi(os.Getenv("POD_HEALTH_EVICTION_THRESHOLD")); err == nil && n > 0 {
		cfg.EvictionThreshold = n
	}
	if d, err := time.ParseDuration(os.Getenv("POD_HEALTH_EVICTION_WINDOW")); err == nil && d > 0 {
		cfg.EvictionWindow = d
	}
	if f, err := strconv.ParseFloat(os.Getenv("POD_HEALTH_RESIZE_PERCENT"), 64); err == nil && f > 0 && f < 1 {
		cfg.ResizePercent = f
	}
	if n, err := strconv.ParseInt(os.Getenv("POD_HEALTH_MIN_MEMORY_MI"), 10, 64); err == nil && n > 0 {
		cfg.MinMemoryMi = n
	}
	if n, err := strconv.ParseInt(os.Getenv("POD_HEALTH_MIN_CPU_MILLI"), 10, 64); err == nil && n > 0 {
		cfg.MinCPUMilli = n
	}
	if n, err := strconv.ParseInt(os.Getenv("POD_HEALTH_MIN_REPLICAS"), 10, 32); err == nil && n > 0 {
		cfg.MinReplicas = int32(n)
	}
	if extra := os.Getenv("POD_HEALTH_PROTECTED_NAMESPACES"); extra != "" {
		for _, ns := range strings.Split(extra, ",") {
			if ns = strings.TrimSpace(ns); ns != "" {
				cfg.ProtectedNamespaces[ns] = true
			}
		}
	}

	return cfg
}

// podHealthReconcileLoop runs the pod health controller on a ticker.
func (a *PrysmAgent) podHealthReconcileLoop(ctx context.Context) {
	cfg := loadPodHealthConfig()
	if !cfg.Enabled {
		log.Println("pod-health-controller: disabled via POD_HEALTH_ENABLED=false")
		return
	}

	ctrl := &podHealthController{
		agent:   a,
		config:  cfg,
		tracker: make(map[string]*evictionRecord),
	}

	log.Printf("pod-health-controller: started (interval=%s, threshold=%d/%s)",
		cfg.ScanInterval, cfg.EvictionThreshold, cfg.EvictionWindow)

	// Initial reconcile after short delay to let informers settle
	time.Sleep(10 * time.Second)
	ctrl.reconcile(ctx)

	ticker := time.NewTicker(cfg.ScanInterval)
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

func (c *podHealthController) reconcile(ctx context.Context) {
	c.scanEvictedPods(ctx)
	c.checkEvictionThresholds(ctx)
	c.checkNodePressure(ctx)
}

// scanEvictedPods finds and deletes Failed/Evicted pods, tracking eviction rates per deployment.
func (c *podHealthController) scanEvictedPods(ctx context.Context) {
	pods, err := c.agent.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Failed",
	})
	if err != nil {
		log.Printf("pod-health-controller: failed to list failed pods: %v", err)
		return
	}

	deleted := 0
	for i := range pods.Items {
		pod := &pods.Items[i]

		if pod.Status.Reason != "Evicted" {
			continue
		}
		if c.config.ProtectedNamespaces[pod.Namespace] {
			continue
		}
		if !isPrysmPod(pod) {
			continue
		}
		if hasOptOut(pod.Annotations) {
			continue
		}

		// Track eviction for the owning deployment
		if deployKey := c.resolveDeploymentOwner(ctx, pod); deployKey != "" {
			c.recordEviction(deployKey)
		}

		// Delete the evicted pod
		err := c.agent.clientset.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
		if err != nil {
			log.Printf("pod-health-controller: failed to delete evicted pod %s/%s: %v", pod.Namespace, pod.Name, err)
			continue
		}
		deleted++
	}

	if deleted > 0 {
		log.Printf("pod-health-controller: cleaned up %d evicted pods", deleted)
		c.reportEvent(ctx, "eviction_cleanup", "info",
			fmt.Sprintf("Cleaned up %d evicted pods", deleted), nil)
	}
}

// checkEvictionThresholds resizes or scales down deployments that are being evicted repeatedly.
func (c *podHealthController) checkEvictionThresholds(ctx context.Context) {
	c.mu.Lock()
	now := time.Now()
	// Copy keys to avoid holding the lock during API calls
	type candidate struct {
		key    string
		record *evictionRecord
	}
	var candidates []candidate
	for key, rec := range c.tracker {
		// Prune old timestamps outside the window
		cutoff := now.Add(-c.config.EvictionWindow)
		pruned := rec.Timestamps[:0]
		for _, ts := range rec.Timestamps {
			if ts.After(cutoff) {
				pruned = append(pruned, ts)
			}
		}
		rec.Timestamps = pruned

		if len(rec.Timestamps) >= c.config.EvictionThreshold {
			candidates = append(candidates, candidate{key: key, record: rec})
		}
	}
	c.mu.Unlock()

	for _, cand := range candidates {
		parts := strings.SplitN(cand.key, "/", 2)
		if len(parts) != 2 {
			continue
		}
		ns, name := parts[0], parts[1]

		// Check opt-out on deployment; only remediate Prysm-managed deployments
		deploy, err := c.agent.clientset.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			continue
		}
		if !isPrysmLabeled(deploy.Labels) {
			continue
		}
		if hasOptOut(deploy.Annotations) {
			continue
		}

		// Cooldown: don't resize more frequently than the eviction window
		if !cand.record.LastResize.IsZero() && time.Since(cand.record.LastResize) < c.config.EvictionWindow {
			// If we already resized and still evicting, scale down
			if !cand.record.ScaledDown && deploy.Spec.Replicas != nil && *deploy.Spec.Replicas > c.config.MinReplicas {
				newReplicas := *deploy.Spec.Replicas - 1
				deploy.Spec.Replicas = &newReplicas
				if _, err := c.agent.clientset.AppsV1().Deployments(ns).Update(ctx, deploy, metav1.UpdateOptions{}); err != nil {
					log.Printf("pod-health-controller: failed to scale down %s/%s: %v", ns, name, err)
					continue
				}
				cand.record.ScaledDown = true
				log.Printf("pod-health-controller: scaled down %s/%s to %d replicas", ns, name, newReplicas)
				c.reportEvent(ctx, "replica_scale", "warn",
					fmt.Sprintf("Scaled down %s/%s to %d replicas due to repeated evictions", ns, name, newReplicas),
					map[string]interface{}{"namespace": ns, "deployment": name, "replicas": newReplicas})
			}
			continue
		}

		// Reduce resource requests
		resized := false
		for i := range deploy.Spec.Template.Spec.Containers {
			container := &deploy.Spec.Template.Spec.Containers[i]
			if container.Resources.Requests == nil {
				continue
			}
			resized = c.reduceResources(container) || resized
		}

		if resized {
			if _, err := c.agent.clientset.AppsV1().Deployments(ns).Update(ctx, deploy, metav1.UpdateOptions{}); err != nil {
				log.Printf("pod-health-controller: failed to resize %s/%s: %v", ns, name, err)
				continue
			}
			cand.record.ResizeCount++
			cand.record.LastResize = time.Now()
			cand.record.ScaledDown = false // reset scale-down flag after a fresh resize
			// Clear eviction timestamps so threshold is evaluated fresh
			c.mu.Lock()
			cand.record.Timestamps = nil
			c.mu.Unlock()

			log.Printf("pod-health-controller: reduced resource requests for %s/%s (resize #%d)", ns, name, cand.record.ResizeCount)
			c.reportEvent(ctx, "resource_resize", "warn",
				fmt.Sprintf("Reduced resource requests for %s/%s (resize #%d) due to evictions", ns, name, cand.record.ResizeCount),
				map[string]interface{}{"namespace": ns, "deployment": name, "resize_count": cand.record.ResizeCount})
		}
	}
}

// checkNodePressure inspects node conditions and cleans up terminated pods on pressured nodes.
func (c *podHealthController) checkNodePressure(ctx context.Context) {
	nodes, err := c.agent.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("pod-health-controller: failed to list nodes: %v", err)
		return
	}

	pressureConditions := []corev1.NodeConditionType{
		corev1.NodeDiskPressure,
		corev1.NodeMemoryPressure,
		corev1.NodePIDPressure,
	}

	for i := range nodes.Items {
		node := &nodes.Items[i]
		for _, condType := range pressureConditions {
			if !hasNodeCondition(node, condType) {
				continue
			}

			log.Printf("pod-health-controller: node %s has %s", node.Name, condType)
			c.reportEvent(ctx, "node_pressure", "warn",
				fmt.Sprintf("Node %s has %s condition", node.Name, condType),
				map[string]interface{}{"node": node.Name, "condition": string(condType)})

			// On DiskPressure, clean up Succeeded and Failed pods on the node
			if condType == corev1.NodeDiskPressure {
				c.cleanTerminatedPodsOnNode(ctx, node.Name)
			}
		}
	}
}

// cleanTerminatedPodsOnNode deletes Succeeded and Failed pods scheduled on the given node.
func (c *podHealthController) cleanTerminatedPodsOnNode(ctx context.Context, nodeName string) {
	for _, phase := range []string{"Succeeded", "Failed"} {
		pods, err := c.agent.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
			FieldSelector: fmt.Sprintf("spec.nodeName=%s,status.phase=%s", nodeName, phase),
		})
		if err != nil {
			log.Printf("pod-health-controller: failed to list %s pods on node %s: %v", phase, nodeName, err)
			continue
		}
		cleaned := 0
		for j := range pods.Items {
			pod := &pods.Items[j]
			if c.config.ProtectedNamespaces[pod.Namespace] {
				continue
			}
			if !isPrysmPod(pod) {
				continue
			}
			_ = c.agent.clientset.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
			cleaned++
		}
		if cleaned > 0 {
			log.Printf("pod-health-controller: cleaned %d %s prysm pods on pressured node %s", cleaned, phase, nodeName)
		}
	}
}

// resolveDeploymentOwner walks the ownerRef chain Pod → ReplicaSet → Deployment
// and returns "namespace/deployment-name", or "" if not deployment-owned.
func (c *podHealthController) resolveDeploymentOwner(ctx context.Context, pod *corev1.Pod) string {
	// Find ReplicaSet owner
	var rsName string
	for _, ref := range pod.OwnerReferences {
		if ref.Kind == "ReplicaSet" {
			rsName = ref.Name
			break
		}
	}
	if rsName == "" {
		return ""
	}

	// Find Deployment owner of the ReplicaSet
	rs, err := c.agent.clientset.AppsV1().ReplicaSets(pod.Namespace).Get(ctx, rsName, metav1.GetOptions{})
	if err != nil {
		return ""
	}
	for _, ref := range rs.OwnerReferences {
		if ref.Kind == "Deployment" {
			return pod.Namespace + "/" + ref.Name
		}
	}
	return ""
}

func (c *podHealthController) recordEviction(deployKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec, ok := c.tracker[deployKey]
	if !ok {
		rec = &evictionRecord{}
		c.tracker[deployKey] = rec
	}
	rec.Timestamps = append(rec.Timestamps, time.Now())
}

// reduceResources reduces memory and CPU requests by the configured percentage,
// clamped to the configured floors. Returns true if anything changed.
func (c *podHealthController) reduceResources(container *corev1.Container) bool {
	changed := false
	minMem := resource.MustParse(fmt.Sprintf("%dMi", c.config.MinMemoryMi))
	minCPU := resource.MustParse(fmt.Sprintf("%dm", c.config.MinCPUMilli))

	if mem, ok := container.Resources.Requests[corev1.ResourceMemory]; ok {
		newVal := int64(float64(mem.Value()) * (1 - c.config.ResizePercent))
		newMem := *resource.NewQuantity(newVal, resource.BinarySI)
		if newMem.Cmp(minMem) < 0 {
			newMem = minMem.DeepCopy()
		}
		if newMem.Cmp(mem) < 0 {
			container.Resources.Requests[corev1.ResourceMemory] = newMem
			changed = true
		}
	}

	if cpu, ok := container.Resources.Requests[corev1.ResourceCPU]; ok {
		newMillis := int64(float64(cpu.MilliValue()) * (1 - c.config.ResizePercent))
		newCPU := *resource.NewMilliQuantity(newMillis, resource.DecimalSI)
		if newCPU.Cmp(minCPU) < 0 {
			newCPU = minCPU.DeepCopy()
		}
		if newCPU.Cmp(cpu) < 0 {
			container.Resources.Requests[corev1.ResourceCPU] = newCPU
			changed = true
		}
	}

	return changed
}

// reportEvent sends a log entry to the backend using the same format as audit_webhook.go.
func (c *podHealthController) reportEvent(ctx context.Context, category, level, message string, metadata map[string]interface{}) {
	if c.agent.BackendURL == "" {
		return
	}

	entry := map[string]interface{}{
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"level":      level,
		"message":    message,
		"source":     "pod_health_controller",
		"cluster_id": c.agent.ClusterID,
		"tags":       []string{"k8s", "pod_health", category},
	}
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	metadata["org_id"] = c.agent.OrganizationID
	metadata["category"] = category
	entry["metadata"] = metadata

	payload, err := json.Marshal(map[string]interface{}{
		"agent_token": c.agent.AgentToken,
		"batch_id":    fmt.Sprintf("pod-health-%d", time.Now().UnixNano()),
		"cluster_id":  c.agent.ClusterID,
		"timestamp":   time.Now().UTC(),
		"logs":        []map[string]interface{}{entry},
	})
	if err != nil {
		return
	}

	endpoint := strings.TrimSuffix(c.agent.BackendURL, "/") + "/api/v1/logs/ingest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.agent.AgentToken)

	resp, err := c.agent.HTTPClient.Do(req)
	if err != nil {
		log.Printf("pod-health-controller: failed to report event: %v", err)
		return
	}
	resp.Body.Close()
}

func hasOptOut(annotations map[string]string) bool {
	return strings.EqualFold(annotations[podHealthAnnotationOptOut], "true")
}

// isPrysmPod returns true if the pod has any label with the prysm.sh/ prefix.
func isPrysmPod(pod *corev1.Pod) bool {
	return isPrysmLabeled(pod.Labels)
}

// isPrysmLabeled returns true if the label map contains any key with the prysm.sh/ prefix.
func isPrysmLabeled(labels map[string]string) bool {
	for k := range labels {
		if strings.HasPrefix(k, prysmLabelPrefix) {
			return true
		}
	}
	return false
}

func hasNodeCondition(node *corev1.Node, condType corev1.NodeConditionType) bool {
	for _, c := range node.Status.Conditions {
		if c.Type == condType && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}
