package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

// k8sResourcePayload is the batch sent to POST /api/v1/agent/k8s-resources.
type k8sResourcePayload struct {
	ClusterID string            `json:"cluster_id"`
	Resources []k8sResourceItem `json:"resources"`
}

type k8sResourceItem struct {
	Kind      string                 `json:"kind"`
	Namespace string                 `json:"namespace"`
	Name      string                 `json:"name"`
	YAML      string                 `json:"yaml"`
	Action    string                 `json:"action"` // "upsert" or "delete"
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ownerRef is a simplified owner reference.
type ownerRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// k8sResourceWatcher watches K8s resources and sends them to the backend for RAG ingestion.
type k8sResourceWatcher struct {
	agent         *PrysmAgent
	client        *http.Client
	buffer        []k8sResourceItem
	bufferMu      sync.Mutex
	flushInterval time.Duration
	ignoredNS     map[string]bool
	serializer    *k8sjson.Serializer
}

func newK8sResourceWatcher(agent *PrysmAgent) *k8sResourceWatcher {
	interval := 30 * time.Second
	if d := getEnvOrDefault("K8S_RESOURCE_FLUSH_INTERVAL", ""); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
			interval = parsed
		}
	}

	ignored := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}
	if extra := getEnvOrDefault("K8S_RESOURCE_IGNORED_NAMESPACES", ""); extra != "" {
		for _, ns := range strings.Split(extra, ",") {
			ns = strings.TrimSpace(ns)
			if ns != "" {
				ignored[ns] = true
			}
		}
	}

	scheme := runtime.NewScheme()
	_ = appsv1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = networkingv1.AddToScheme(scheme)
	_ = rbacv1.AddToScheme(scheme)
	_ = autoscalingv2.AddToScheme(scheme)

	return &k8sResourceWatcher{
		agent:         agent,
		client:        &http.Client{Timeout: 30 * time.Second},
		buffer:        make([]k8sResourceItem, 0, 100),
		flushInterval: interval,
		ignoredNS:     ignored,
		serializer:    k8sjson.NewYAMLSerializer(k8sjson.DefaultMetaFactory, scheme, scheme),
	}
}

func (w *k8sResourceWatcher) start(ctx context.Context) {
	if w.agent.clientset == nil {
		log.Println("[k8s-watcher] no kubernetes client, skipping resource watcher")
		return
	}

	resyncInterval := 10 * time.Minute
	if d := getEnvOrDefault("K8S_RESOURCE_SYNC_INTERVAL", ""); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
			resyncInterval = parsed
		}
	}

	factory := informers.NewSharedInformerFactory(w.agent.clientset, resyncInterval)

	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { w.handleResource(obj, "upsert") },
		UpdateFunc: func(_, obj interface{}) { w.handleResource(obj, "upsert") },
		DeleteFunc: func(obj interface{}) { w.handleResource(obj, "delete") },
	}

	// Original resource types
	factory.Apps().V1().Deployments().Informer().AddEventHandler(handler)
	factory.Core().V1().Services().Informer().AddEventHandler(handler)
	factory.Core().V1().ConfigMaps().Informer().AddEventHandler(handler)
	factory.Networking().V1().NetworkPolicies().Informer().AddEventHandler(handler)
	factory.Rbac().V1().ClusterRoles().Informer().AddEventHandler(handler)
	factory.Rbac().V1().ClusterRoleBindings().Informer().AddEventHandler(handler)
	factory.Core().V1().Events().Informer().AddEventHandler(handler)

	// New resource types
	factory.Core().V1().Nodes().Informer().AddEventHandler(handler)
	factory.Core().V1().Pods().Informer().AddEventHandler(handler)
	factory.Apps().V1().ReplicaSets().Informer().AddEventHandler(handler)
	factory.Apps().V1().StatefulSets().Informer().AddEventHandler(handler)
	factory.Apps().V1().DaemonSets().Informer().AddEventHandler(handler)
	factory.Networking().V1().Ingresses().Informer().AddEventHandler(handler)
	factory.Autoscaling().V2().HorizontalPodAutoscalers().Informer().AddEventHandler(handler)

	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())

	log.Printf("[k8s-watcher] watching resources (resync=%v, flush=%v)", resyncInterval, w.flushInterval)

	// Flush loop
	ticker := time.NewTicker(w.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			w.flush()
			return
		case <-ticker.C:
			w.flush()
		}
	}
}

func (w *k8sResourceWatcher) handleResource(obj interface{}, action string) {
	metaObj, ok := obj.(metav1.ObjectMetaAccessor)
	if !ok {
		return
	}
	meta := metaObj.GetObjectMeta()

	// Skip ignored namespaces
	if meta.GetNamespace() != "" && w.ignoredNS[meta.GetNamespace()] {
		return
	}

	kind := objectKind(obj)
	if kind == "" {
		return
	}

	// Filter completed/failed pods on upsert
	if action == "upsert" {
		if pod, ok := obj.(*corev1.Pod); ok {
			if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
				return
			}
		}
	}

	item := k8sResourceItem{
		Kind:      kind,
		Namespace: meta.GetNamespace(),
		Name:      meta.GetName(),
		Action:    action,
	}

	if action == "upsert" {
		yaml := w.serializeYAML(obj)
		if yaml == "" {
			return
		}
		item.YAML = yaml
		item.Metadata = extractMetadata(obj)
		// Add content hash for change detection
		item.Metadata["content_hash"] = contentHash(yaml)
	}

	w.bufferMu.Lock()
	w.buffer = append(w.buffer, item)
	// Auto-flush at 50 items
	if len(w.buffer) >= 50 {
		items := w.buffer
		w.buffer = make([]k8sResourceItem, 0, 100)
		w.bufferMu.Unlock()
		w.send(items)
		return
	}
	w.bufferMu.Unlock()
}

func (w *k8sResourceWatcher) flush() {
	w.bufferMu.Lock()
	if len(w.buffer) == 0 {
		w.bufferMu.Unlock()
		return
	}
	items := w.buffer
	w.buffer = make([]k8sResourceItem, 0, 100)
	w.bufferMu.Unlock()
	w.send(items)
}

func (w *k8sResourceWatcher) send(items []k8sResourceItem) {
	if len(items) == 0 || w.agent.BackendURL == "" {
		return
	}

	payload := k8sResourcePayload{
		ClusterID: w.agent.ClusterID,
		Resources: items,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[k8s-watcher] marshal error: %v", err)
		return
	}

	url := w.agent.BackendURL + "/api/v1/agent/k8s-resources"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[k8s-watcher] build request error: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+w.agent.AgentToken)

	resp, err := w.client.Do(req)
	if err != nil {
		log.Printf("[k8s-watcher] POST error: %v", err)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("[k8s-watcher] sent %d resources to backend", len(items))
	} else {
		log.Printf("[k8s-watcher] backend returned %d for %d resources", resp.StatusCode, len(items))
	}
}

func (w *k8sResourceWatcher) serializeYAML(obj interface{}) string {
	runtimeObj, ok := obj.(runtime.Object)
	if !ok {
		return ""
	}
	var buf bytes.Buffer
	if err := w.serializer.Encode(runtimeObj, &buf); err != nil {
		return ""
	}
	s := buf.String()
	// Truncate to 8000 chars to keep embeddings manageable
	if len(s) > 8000 {
		s = s[:8000]
	}
	return s
}

func objectKind(obj interface{}) string {
	switch obj.(type) {
	case *appsv1.Deployment:
		return "Deployment"
	case *corev1.Service:
		return "Service"
	case *corev1.ConfigMap:
		return "ConfigMap"
	case *networkingv1.NetworkPolicy:
		return "NetworkPolicy"
	case *rbacv1.ClusterRole:
		return "ClusterRole"
	case *rbacv1.ClusterRoleBinding:
		return "ClusterRoleBinding"
	case *corev1.Event:
		return "Event"
	case *corev1.Node:
		return "Node"
	case *corev1.Pod:
		return "Pod"
	case *appsv1.ReplicaSet:
		return "ReplicaSet"
	case *appsv1.StatefulSet:
		return "StatefulSet"
	case *appsv1.DaemonSet:
		return "DaemonSet"
	case *networkingv1.Ingress:
		return "Ingress"
	case *autoscalingv2.HorizontalPodAutoscaler:
		return "HorizontalPodAutoscaler"
	default:
		return fmt.Sprintf("%T", obj)
	}
}

// extractMetadata extracts structured metadata from a K8s object for RAG enrichment.
func extractMetadata(obj interface{}) map[string]interface{} {
	meta := map[string]interface{}{}

	// Extract owner references from any object with ObjectMeta
	if accessor, ok := obj.(metav1.ObjectMetaAccessor); ok {
		objMeta := accessor.GetObjectMeta()
		if refs := objMeta.GetOwnerReferences(); len(refs) > 0 {
			owners := make([]ownerRef, 0, len(refs))
			for _, r := range refs {
				owners = append(owners, ownerRef{Kind: r.Kind, Name: r.Name})
			}
			meta["owner_refs"] = owners
		}
		if labels := objMeta.GetLabels(); len(labels) > 0 {
			meta["labels"] = labels
		}
	}

	switch o := obj.(type) {
	case *appsv1.Deployment:
		meta["replicas"] = ptrInt32(o.Spec.Replicas)
		meta["ready_replicas"] = o.Status.ReadyReplicas
		if o.Spec.Selector != nil && len(o.Spec.Selector.MatchLabels) > 0 {
			meta["label_selectors"] = o.Spec.Selector.MatchLabels
		}

	case *appsv1.ReplicaSet:
		meta["replicas"] = ptrInt32(o.Spec.Replicas)
		meta["ready_replicas"] = o.Status.ReadyReplicas
		if o.Spec.Selector != nil && len(o.Spec.Selector.MatchLabels) > 0 {
			meta["label_selectors"] = o.Spec.Selector.MatchLabels
		}

	case *appsv1.StatefulSet:
		meta["replicas"] = ptrInt32(o.Spec.Replicas)
		meta["ready_replicas"] = o.Status.ReadyReplicas
		if o.Spec.Selector != nil && len(o.Spec.Selector.MatchLabels) > 0 {
			meta["label_selectors"] = o.Spec.Selector.MatchLabels
		}

	case *appsv1.DaemonSet:
		meta["desired_number_scheduled"] = o.Status.DesiredNumberScheduled
		meta["ready_replicas"] = o.Status.NumberReady
		if o.Spec.Selector != nil && len(o.Spec.Selector.MatchLabels) > 0 {
			meta["label_selectors"] = o.Spec.Selector.MatchLabels
		}

	case *corev1.Service:
		if len(o.Spec.Selector) > 0 {
			meta["service_selector"] = o.Spec.Selector
		}

	case *corev1.Pod:
		meta["pod_phase"] = string(o.Status.Phase)
		meta["node_name"] = o.Spec.NodeName
		meta["container_count"] = len(o.Spec.Containers)
		containers := make([]string, 0, len(o.Spec.Containers))
		for _, c := range o.Spec.Containers {
			containers = append(containers, c.Name)
		}
		meta["containers"] = containers
		var totalRestarts int32
		for _, cs := range o.Status.ContainerStatuses {
			totalRestarts += cs.RestartCount
		}
		meta["restart_count"] = totalRestarts

	case *corev1.Node:
		capacity := map[string]string{}
		for k, v := range o.Status.Capacity {
			capacity[string(k)] = v.String()
		}
		meta["node_capacity"] = capacity
		allocatable := map[string]string{}
		for k, v := range o.Status.Allocatable {
			allocatable[string(k)] = v.String()
		}
		meta["node_allocatable"] = allocatable
		meta["unschedulable"] = o.Spec.Unschedulable

		conditions := make([]map[string]string, 0, len(o.Status.Conditions))
		for _, c := range o.Status.Conditions {
			conditions = append(conditions, map[string]string{
				"type":   string(c.Type),
				"status": string(c.Status),
			})
		}
		meta["node_conditions"] = conditions

		if len(o.Spec.Taints) > 0 {
			taints := make([]map[string]string, 0, len(o.Spec.Taints))
			for _, t := range o.Spec.Taints {
				taints = append(taints, map[string]string{
					"key":    t.Key,
					"value":  t.Value,
					"effect": string(t.Effect),
				})
			}
			meta["node_taints"] = taints
		}

	case *autoscalingv2.HorizontalPodAutoscaler:
		meta["scale_target_ref"] = map[string]string{
			"kind": o.Spec.ScaleTargetRef.Kind,
			"name": o.Spec.ScaleTargetRef.Name,
		}
		meta["scale_target_name"] = o.Spec.ScaleTargetRef.Name
		if o.Spec.MinReplicas != nil {
			meta["min_replicas"] = *o.Spec.MinReplicas
		}
		meta["max_replicas"] = o.Spec.MaxReplicas
		meta["current_replicas"] = o.Status.CurrentReplicas

		if len(o.Spec.Metrics) > 0 {
			metrics := make([]string, 0, len(o.Spec.Metrics))
			for _, m := range o.Spec.Metrics {
				switch m.Type {
				case autoscalingv2.ResourceMetricSourceType:
					if m.Resource != nil {
						metrics = append(metrics, string(m.Resource.Name))
					}
				case autoscalingv2.ObjectMetricSourceType:
					if m.Object != nil {
						metrics = append(metrics, m.Object.Metric.Name)
					}
				case autoscalingv2.PodsMetricSourceType:
					if m.Pods != nil {
						metrics = append(metrics, m.Pods.Metric.Name)
					}
				case autoscalingv2.ExternalMetricSourceType:
					if m.External != nil {
						metrics = append(metrics, m.External.Metric.Name)
					}
				}
			}
			meta["hpa_metrics"] = metrics
		}

	case *networkingv1.Ingress:
		if len(o.Spec.Rules) > 0 {
			hosts := make([]string, 0, len(o.Spec.Rules))
			for _, r := range o.Spec.Rules {
				if r.Host != "" {
					hosts = append(hosts, r.Host)
				}
			}
			if len(hosts) > 0 {
				meta["ingress_hosts"] = hosts
			}
		}
	}

	return meta
}

// contentHash returns a hex-encoded SHA-256 of the YAML content.
func contentHash(yaml string) string {
	h := sha256.Sum256([]byte(yaml))
	return fmt.Sprintf("%x", h)
}

func ptrInt32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

// startK8sResourceWatcher starts the K8s resource watcher goroutine.
func (a *PrysmAgent) startK8sResourceWatcher(ctx context.Context) {
	if a.BackendURL == "" || a.AgentToken == "" {
		log.Println("[k8s-watcher] no backend URL or token, skipping")
		return
	}
	watcher := newK8sResourceWatcher(a)
	watcher.start(ctx)
}
