package main

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestObjectKind(t *testing.T) {
	tests := []struct {
		obj  interface{}
		want string
	}{
		{&appsv1.Deployment{}, "Deployment"},
		{&corev1.Service{}, "Service"},
		{&corev1.ConfigMap{}, "ConfigMap"},
		{&networkingv1.NetworkPolicy{}, "NetworkPolicy"},
		{&rbacv1.ClusterRole{}, "ClusterRole"},
		{&rbacv1.ClusterRoleBinding{}, "ClusterRoleBinding"},
		{&corev1.Event{}, "Event"},
		{&corev1.Node{}, "Node"},
		{&corev1.Pod{}, "Pod"},
		{&appsv1.ReplicaSet{}, "ReplicaSet"},
		{&appsv1.StatefulSet{}, "StatefulSet"},
		{&appsv1.DaemonSet{}, "DaemonSet"},
		{&networkingv1.Ingress{}, "Ingress"},
		{&autoscalingv2.HorizontalPodAutoscaler{}, "HorizontalPodAutoscaler"},
	}

	for _, tt := range tests {
		got := objectKind(tt.obj)
		if got != tt.want {
			t.Errorf("objectKind(%T) = %q, want %q", tt.obj, got, tt.want)
		}
	}
}

func TestExtractMetadataNode(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "worker-1",
			Labels: map[string]string{"node.kubernetes.io/instance-type": "m5.xlarge"},
		},
		Spec: corev1.NodeSpec{
			Unschedulable: false,
			Taints: []corev1.Taint{
				{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule},
			},
		},
		Status: corev1.NodeStatus{
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("16Gi"),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("3800m"),
				corev1.ResourceMemory: resource.MustParse("15Gi"),
			},
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse},
			},
		},
	}

	meta := extractMetadata(node)

	// Check capacity
	cap, ok := meta["node_capacity"].(map[string]string)
	if !ok {
		t.Fatal("node_capacity not found or wrong type")
	}
	if cap["cpu"] != "4" {
		t.Errorf("capacity cpu = %q, want \"4\"", cap["cpu"])
	}

	// Check allocatable
	alloc, ok := meta["node_allocatable"].(map[string]string)
	if !ok {
		t.Fatal("node_allocatable not found")
	}
	if alloc["cpu"] != "3800m" {
		t.Errorf("allocatable cpu = %q, want \"3800m\"", alloc["cpu"])
	}

	// Check conditions
	conditions, ok := meta["node_conditions"].([]map[string]string)
	if !ok || len(conditions) != 2 {
		t.Fatalf("expected 2 conditions, got %v", meta["node_conditions"])
	}
	if conditions[0]["type"] != "Ready" || conditions[0]["status"] != "True" {
		t.Errorf("unexpected condition[0]: %v", conditions[0])
	}

	// Check taints
	taints, ok := meta["node_taints"].([]map[string]string)
	if !ok || len(taints) != 1 {
		t.Fatalf("expected 1 taint, got %v", meta["node_taints"])
	}
	if taints[0]["key"] != "dedicated" {
		t.Errorf("taint key = %q, want \"dedicated\"", taints[0]["key"])
	}

	// Check labels
	labels, ok := meta["labels"].(map[string]string)
	if !ok || labels["node.kubernetes.io/instance-type"] != "m5.xlarge" {
		t.Error("labels not extracted correctly")
	}
}

func TestExtractMetadataHPA(t *testing.T) {
	minReplicas := int32(2)
	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api-hpa",
			Namespace: "default",
		},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
				Kind: "Deployment",
				Name: "api-server",
			},
			MinReplicas: &minReplicas,
			MaxReplicas: 10,
			Metrics: []autoscalingv2.MetricSpec{
				{
					Type: autoscalingv2.ResourceMetricSourceType,
					Resource: &autoscalingv2.ResourceMetricSource{
						Name: corev1.ResourceCPU,
					},
				},
			},
		},
		Status: autoscalingv2.HorizontalPodAutoscalerStatus{
			CurrentReplicas: 4,
		},
	}

	meta := extractMetadata(hpa)

	// Check scale target ref
	ref, ok := meta["scale_target_ref"].(map[string]string)
	if !ok {
		t.Fatal("scale_target_ref not found")
	}
	if ref["kind"] != "Deployment" || ref["name"] != "api-server" {
		t.Errorf("scale_target_ref = %v, want Deployment/api-server", ref)
	}

	if meta["scale_target_name"] != "api-server" {
		t.Errorf("scale_target_name = %v, want api-server", meta["scale_target_name"])
	}

	if meta["max_replicas"] != int32(10) {
		t.Errorf("max_replicas = %v, want 10", meta["max_replicas"])
	}

	if meta["current_replicas"] != int32(4) {
		t.Errorf("current_replicas = %v, want 4", meta["current_replicas"])
	}

	// Check metrics
	metrics, ok := meta["hpa_metrics"].([]string)
	if !ok || len(metrics) != 1 || metrics[0] != "cpu" {
		t.Errorf("hpa_metrics = %v, want [cpu]", meta["hpa_metrics"])
	}
}

func TestExtractMetadataPod(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx-abc-123",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "ReplicaSet", Name: "nginx-abc"},
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "worker-1",
			Containers: []corev1.Container{
				{Name: "nginx"},
				{Name: "sidecar"},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{
				{RestartCount: 2},
				{RestartCount: 1},
			},
		},
	}

	meta := extractMetadata(pod)

	if meta["pod_phase"] != "Running" {
		t.Errorf("pod_phase = %v, want Running", meta["pod_phase"])
	}
	if meta["node_name"] != "worker-1" {
		t.Errorf("node_name = %v, want worker-1", meta["node_name"])
	}
	if meta["container_count"] != 2 {
		t.Errorf("container_count = %v, want 2", meta["container_count"])
	}
	if meta["restart_count"] != int32(3) {
		t.Errorf("restart_count = %v, want 3", meta["restart_count"])
	}

	containers, ok := meta["containers"].([]string)
	if !ok || len(containers) != 2 {
		t.Fatalf("containers = %v, want [nginx, sidecar]", meta["containers"])
	}

	owners, ok := meta["owner_refs"].([]ownerRef)
	if !ok || len(owners) != 1 || owners[0].Kind != "ReplicaSet" {
		t.Errorf("owner_refs = %v, want ReplicaSet/nginx-abc", meta["owner_refs"])
	}
}

func TestContentHash(t *testing.T) {
	yaml1 := "apiVersion: v1\nkind: Service\nmetadata:\n  name: web"
	yaml2 := "apiVersion: v1\nkind: Service\nmetadata:\n  name: api"

	h1 := contentHash(yaml1)
	h2 := contentHash(yaml1) // same input
	h3 := contentHash(yaml2) // different input

	if h1 != h2 {
		t.Error("contentHash not deterministic")
	}
	if h1 == h3 {
		t.Error("different content should produce different hash")
	}
	if len(h1) != 64 {
		t.Errorf("hash length = %d, want 64 (sha256 hex)", len(h1))
	}
}
