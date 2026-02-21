package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"
)

type clusterSnapshot struct {
	Info     map[string]interface{}
	Services map[string]interface{}
	Metrics  []map[string]interface{}
}

func (a *PrysmAgent) initKubernetesClients() error {
	if a.clientset != nil {
		return nil
	}

	config, err := a.loadKubeConfig()
	if err != nil {
		return err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("create kubernetes client: %w", err)
	}

	metricsClient, err := metricsclient.NewForConfig(config)
	if err != nil {
		log.Printf("Warning: metrics client initialization failed: %v", err)
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		log.Printf("Warning: discovery client initialization failed: %v", err)
	}

	a.clientset = clientset
	a.metricsClient = metricsClient
	a.discoveryConn = discoveryClient

	if a.ClusterName == "" {
		a.ClusterName = fmt.Sprintf("Cluster %s", a.ClusterID)
	}

	log.Printf("Kubernetes telemetry initialized (%s)", a.ClusterID)
	return nil
}

func (a *PrysmAgent) loadKubeConfig() (*rest.Config, error) {
	var config *rest.Config
	var err error

	if path := strings.TrimSpace(a.kubeconfigPath); path != "" {
		config, err = clientcmd.BuildConfigFromFlags("", path)
		if err != nil {
			log.Printf("Warning: failed to load kubeconfig from %s: %v", path, err)
		}
	}

	if config == nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("unable to build in-cluster config: %w", err)
		}
	}

	// Allow KUBECONFIG_APISERVER to override the server URL (useful when running
	// outside the cluster, e.g. in a Docker Compose sidecar container where
	// localhost in the kubeconfig resolves to the container itself).
	if override := strings.TrimSpace(getEnvOrDefault("KUBECONFIG_APISERVER", "")); override != "" {
		log.Printf("Overriding kubeconfig server with KUBECONFIG_APISERVER=%s", override)
		config.Host = override
	}

	return config, nil
}

func (a *PrysmAgent) clusterTelemetryLoop(parent context.Context) {
	if a.clientset == nil {
		return
	}

	log.Printf("Starting cluster telemetry loop for cluster %s", a.ClusterID)
	a.publishClusterTelemetry(parent)

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-parent.Done():
			return
		case <-ticker.C:
			a.publishClusterTelemetry(parent)
		}
	}
}

func (a *PrysmAgent) publishClusterTelemetry(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()

	snapshot, err := a.collectClusterSnapshot(ctx)
	if err != nil {
		log.Printf("Cluster telemetry collection failed: %v", err)
		return
	}

	if err := a.sendClusterSnapshot(ctx, snapshot); err != nil {
		log.Printf("Failed to publish cluster telemetry: %v", err)
		return
	}

	a.lastTelemetry = time.Now()
	log.Printf("Cluster telemetry published successfully (next update in 60s)")
}

func (a *PrysmAgent) collectClusterSnapshot(ctx context.Context) (*clusterSnapshot, error) {
	if a.clientset == nil {
		return nil, fmt.Errorf("kubernetes client not initialized")
	}

	info := map[string]interface{}{
		"id":         a.ClusterID,
		"name":       a.ClusterName,
		"region":     a.Region,
		"last_seen":  time.Now().UTC().Format(time.RFC3339),
		"health":     "healthy",
		"connected":  true,
		"agent_type": "k3s-bootstrap",
	}
	// When DERP is enabled, cluster proxy should use DERP tunnel (SaaS / private clusters)
	if len(a.derpServers) > 0 {
		info["use_derp"] = true
	}

	nodes, err := a.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}

	info["node_count"] = len(nodes.Items)

	var readyNodes int
	var totalCPUCapacityMilli int64
	var totalMemoryCapacityBytes int64
	for _, node := range nodes.Items {
		if nodeReady(&node) {
			readyNodes++
		}

		if qty, ok := node.Status.Capacity[corev1.ResourceCPU]; ok {
			totalCPUCapacityMilli += qty.MilliValue()
		}
		if qty, ok := node.Status.Capacity[corev1.ResourceMemory]; ok {
			totalMemoryCapacityBytes += qty.Value()
		}
	}

	info["ready_node_count"] = readyNodes
	info["node_cpu_capacity_milli"] = totalCPUCapacityMilli
	info["node_memory_capacity_bytes"] = totalMemoryCapacityBytes
	if readyNodes < len(nodes.Items) {
		info["health"] = "degraded"
	}

	pods, err := a.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	runningPods := 0
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning {
			runningPods++
		}
	}

	info["pod_count"] = len(pods.Items)
	info["running_pod_count"] = runningPods

	namespaces, err := a.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	info["namespace_count"] = len(namespaces.Items)

	services, err := a.clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list services: %w", err)
	}
	info["service_count"] = len(services.Items)

	serviceSummary := map[string]interface{}{
		"total": len(services.Items),
	}
	if len(services.Items) > 0 {
		byNamespace := map[string]int{}
		byType := map[string]int{}
		for _, svc := range services.Items {
			byNamespace[svc.Namespace]++
			byType[string(svc.Spec.Type)]++
		}
		serviceSummary["by_namespace"] = byNamespace
		serviceSummary["by_type"] = byType
	}

	if a.discoveryConn != nil {
		if versionInfo, err := a.discoveryConn.ServerVersion(); err == nil {
			info["version"] = versionInfo.GitVersion
			info["platform"] = versionInfo.Platform
		}
	}

	var cpuUsageMilli int64
	var memoryUsageBytes int64
	if a.metricsClient != nil {
		if nodeMetrics, err := a.metricsClient.MetricsV1beta1().NodeMetricses().List(ctx, metav1.ListOptions{}); err == nil {
			for _, metric := range nodeMetrics.Items {
				cpuUsageMilli += metric.Usage.Cpu().MilliValue()
				memoryUsageBytes += metric.Usage.Memory().Value()
			}
		} else {
			log.Printf("Warning: failed to query node metrics: %v", err)
		}
	}

	info["cpu_usage_milli"] = cpuUsageMilli
	info["memory_usage_bytes"] = memoryUsageBytes

	if totalCPUCapacityMilli > 0 && cpuUsageMilli >= 0 {
		info["cpu_usage"] = roundFloat(float64(cpuUsageMilli)/float64(totalCPUCapacityMilli)*100, 1)
	} else {
		info["cpu_usage"] = 0.0
	}

	if totalMemoryCapacityBytes > 0 && memoryUsageBytes >= 0 {
		info["memory_usage"] = roundFloat(float64(memoryUsageBytes)/float64(totalMemoryCapacityBytes)*100, 1)
	} else {
		info["memory_usage"] = 0.0
	}

	metrics := []map[string]interface{}{
		{
			"name":      "cpu_usage_percent",
			"value":     info["cpu_usage"],
			"unit":      "percent",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
		{
			"name":      "memory_usage_percent",
			"value":     info["memory_usage"],
			"unit":      "percent",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
		{
			"name":      "pod_count",
			"value":     info["pod_count"],
			"unit":      "count",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		},
	}

	return &clusterSnapshot{
		Info:     info,
		Services: serviceSummary,
		Metrics:  metrics,
	}, nil
}

func (a *PrysmAgent) sendClusterSnapshot(ctx context.Context, snapshot *clusterSnapshot) error {
	if snapshot == nil || snapshot.Info == nil {
		return fmt.Errorf("invalid cluster snapshot")
	}

	payload := map[string]interface{}{
		"agent_token":  a.AgentToken,
		"cluster_info": snapshot.Info,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
	}

	if snapshot.Services != nil {
		payload["services"] = snapshot.Services
	}

	if len(snapshot.Metrics) > 0 {
		payload["metrics"] = snapshot.Metrics
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal telemetry payload: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/clusters/%s/data", strings.TrimRight(a.BackendURL, "/"), a.ClusterID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("build telemetry request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("send telemetry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func nodeReady(node *corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func roundFloat(value float64, precision int) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	factor := math.Pow(10, float64(precision))
	return math.Round(value*factor) / factor
}
