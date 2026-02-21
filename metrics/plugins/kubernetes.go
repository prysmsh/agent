package plugins

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/metrics/pkg/client/clientset/versioned"

	"prysm-agent/metrics"
)

// KubernetesPlugin provides comprehensive Kubernetes cluster monitoring
type KubernetesPlugin struct {
	// Configuration
	config     *KubernetesConfig
	kubeconfig string
	clusterID  string

	// Kubernetes clients
	clientset       kubernetes.Interface
	metricsClient   versioned.Interface
	discoveryClient discovery.DiscoveryInterface

	// Plugin state
	startTime      time.Time
	lastCollection time.Time
	errorCount     int64
	metricsCount   int64

	// Prometheus metrics
	prometheusCollector *KubernetesPrometheusCollector

	// Context for operations
	ctx    context.Context
	cancel context.CancelFunc
}

// KubernetesConfig holds plugin configuration
type KubernetesConfig struct {
	// Connection settings
	Kubeconfig string `json:"kubeconfig" yaml:"kubeconfig"`
	InCluster  bool   `json:"in_cluster" yaml:"in_cluster"`
	ClusterID  string `json:"cluster_id" yaml:"cluster_id"`

	// Collection settings
	CollectResources bool `json:"collect_resources" yaml:"collect_resources"`
	CollectEvents    bool `json:"collect_events" yaml:"collect_events"`
	CollectMetrics   bool `json:"collect_metrics" yaml:"collect_metrics"`
	CollectSecurity  bool `json:"collect_security" yaml:"collect_security"`

	// Performance settings
	EventLookback     time.Duration `json:"event_lookback" yaml:"event_lookback"`
	MaxEventsPerCycle int           `json:"max_events_per_cycle" yaml:"max_events_per_cycle"`
	ResourceTimeout   time.Duration `json:"resource_timeout" yaml:"resource_timeout"`

	// Security settings
	MonitorRBAC            bool `json:"monitor_rbac" yaml:"monitor_rbac"`
	MonitorNetworkPolicies bool `json:"monitor_network_policies" yaml:"monitor_network_policies"`
	MonitorSecrets         bool `json:"monitor_secrets" yaml:"monitor_secrets"`

	// Namespaces to monitor (empty = all)
	Namespaces        []string `json:"namespaces" yaml:"namespaces"`
	ExcludeNamespaces []string `json:"exclude_namespaces" yaml:"exclude_namespaces"`
}

// KubernetesPrometheusCollector handles Kubernetes-specific Prometheus metrics
type KubernetesPrometheusCollector struct {
	// Cluster metrics
	ClusterInfo     *prometheus.GaugeVec
	NodeCount       *prometheus.GaugeVec
	PodCount        *prometheus.GaugeVec
	ServiceCount    *prometheus.GaugeVec
	DeploymentCount *prometheus.GaugeVec

	// Resource metrics
	CPUUsage     *prometheus.GaugeVec
	MemoryUsage  *prometheus.GaugeVec
	StorageUsage *prometheus.GaugeVec
	NetworkUsage *prometheus.CounterVec

	// Health metrics
	PodHealth     *prometheus.GaugeVec
	ServiceHealth *prometheus.GaugeVec
	NodeHealth    *prometheus.GaugeVec

	// Event metrics
	EventCount    *prometheus.CounterVec
	EventSeverity *prometheus.GaugeVec

	// Security metrics
	RBACEvents       *prometheus.CounterVec
	SecurityPolicies *prometheus.GaugeVec
	SecretsCount     *prometheus.GaugeVec

	// Performance metrics
	APIServerLatency  *prometheus.HistogramVec
	ControllerLatency *prometheus.HistogramVec
	SchedulingLatency *prometheus.HistogramVec
}

// NewKubernetesPlugin creates a new Kubernetes monitoring plugin
func NewKubernetesPlugin(kubeconfig, clusterID string) *KubernetesPlugin {
	ctx, cancel := context.WithCancel(context.Background())

	return &KubernetesPlugin{
		kubeconfig:          kubeconfig,
		clusterID:           clusterID,
		startTime:           time.Now(),
		ctx:                 ctx,
		cancel:              cancel,
		prometheusCollector: newKubernetesPrometheusCollector(),
	}
}

// Name returns the plugin name
func (k *KubernetesPlugin) Name() string {
	return "kubernetes"
}

// Description returns the plugin description
func (k *KubernetesPlugin) Description() string {
	return "Comprehensive Kubernetes cluster monitoring including resources, events, and security"
}

// Initialize sets up the plugin
func (k *KubernetesPlugin) Initialize(ctx context.Context, config interface{}) error {
	k.ctx = ctx

	// Parse configuration
	if cfg, ok := config.(*KubernetesConfig); ok && cfg != nil {
		k.config = cfg
	} else {
		k.config = k.defaultConfig()
	}

	// Override cluster ID if provided
	if k.clusterID != "" {
		k.config.ClusterID = k.clusterID
	}

	// Initialize Kubernetes client
	if err := k.initKubernetesClient(); err != nil {
		return fmt.Errorf("failed to initialize Kubernetes client: %w", err)
	}

	log.Printf("Kubernetes plugin initialized for cluster: %s", k.config.ClusterID)
	return nil
}

// initKubernetesClient initializes the Kubernetes client
func (k *KubernetesPlugin) initKubernetesClient() error {
	var config *rest.Config
	var err error

	if k.config.InCluster {
		// Use in-cluster configuration
		config, err = rest.InClusterConfig()
	} else {
		// Use kubeconfig file
		config, err = clientcmd.BuildConfigFromFlags("", k.kubeconfig)
	}

	if err != nil {
		return fmt.Errorf("failed to build config: %w", err)
	}

	// Create clientset
	k.clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create clientset: %w", err)
	}

	// Create metrics client
	k.metricsClient, err = versioned.NewForConfig(config)
	if err != nil {
		log.Printf("Warning: failed to create metrics client: %v", err)
		// Continue without metrics client - not all clusters have metrics-server
	}

	// Create discovery client
	k.discoveryClient, err = discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create discovery client: %w", err)
	}

	return nil
}

// Collect gathers Kubernetes metrics
func (k *KubernetesPlugin) Collect(ctx context.Context) ([]metrics.Metric, error) {
	start := time.Now()
	defer func() {
		k.lastCollection = time.Now()
		k.prometheusCollector.updateCollectionDuration(start)
	}()

	var allMetrics []metrics.Metric

	// Collect cluster info
	if clusterMetrics, err := k.collectClusterInfo(ctx); err != nil {
		k.errorCount++
		log.Printf("Error collecting cluster info: %v", err)
	} else {
		allMetrics = append(allMetrics, clusterMetrics...)
	}

	// Collect resource metrics
	if k.config.CollectResources {
		if resourceMetrics, err := k.collectResourceMetrics(ctx); err != nil {
			k.errorCount++
			log.Printf("Error collecting resource metrics: %v", err)
		} else {
			allMetrics = append(allMetrics, resourceMetrics...)
		}
	}

	// Collect events
	if k.config.CollectEvents {
		if eventMetrics, err := k.collectEvents(ctx); err != nil {
			k.errorCount++
			log.Printf("Error collecting events: %v", err)
		} else {
			allMetrics = append(allMetrics, eventMetrics...)
		}
	}

	// Collect security metrics
	if k.config.CollectSecurity {
		if securityMetrics, err := k.collectSecurityMetrics(ctx); err != nil {
			k.errorCount++
			log.Printf("Error collecting security metrics: %v", err)
		} else {
			allMetrics = append(allMetrics, securityMetrics...)
		}
	}

	// Collect performance metrics
	if performanceMetrics, err := k.collectPerformanceMetrics(ctx); err != nil {
		k.errorCount++
		log.Printf("Error collecting performance metrics: %v", err)
	} else {
		allMetrics = append(allMetrics, performanceMetrics...)
	}

	k.metricsCount += int64(len(allMetrics))
	return allMetrics, nil
}

// collectClusterInfo gathers basic cluster information
func (k *KubernetesPlugin) collectClusterInfo(ctx context.Context) ([]metrics.Metric, error) {
	var clusterMetrics []metrics.Metric
	timestamp := time.Now()

	// Get nodes
	nodes, err := k.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	// Node count metric
	clusterMetrics = append(clusterMetrics, metrics.Metric{
		Name:      "node_count",
		Type:      metrics.MetricTypeGauge,
		Value:     float64(len(nodes.Items)),
		Labels:    map[string]string{"cluster_id": k.config.ClusterID},
		Timestamp: timestamp,
		Plugin:    k.Name(),
		Component: "cluster",
		Category:  metrics.CategoryKubernetes,
		Severity:  metrics.SeverityInfo,
	})

	// Update Prometheus metrics
	k.prometheusCollector.NodeCount.WithLabelValues(k.config.ClusterID).Set(float64(len(nodes.Items)))

	// Get pods across all namespaces
	pods, err := k.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	// Pod count metric
	clusterMetrics = append(clusterMetrics, metrics.Metric{
		Name:      "pod_count",
		Type:      metrics.MetricTypeGauge,
		Value:     float64(len(pods.Items)),
		Labels:    map[string]string{"cluster_id": k.config.ClusterID},
		Timestamp: timestamp,
		Plugin:    k.Name(),
		Component: "cluster",
		Category:  metrics.CategoryKubernetes,
		Severity:  metrics.SeverityInfo,
	})

	k.prometheusCollector.PodCount.WithLabelValues(k.config.ClusterID).Set(float64(len(pods.Items)))

	// Get services
	services, err := k.clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	// Service count metric
	clusterMetrics = append(clusterMetrics, metrics.Metric{
		Name:      "service_count",
		Type:      metrics.MetricTypeGauge,
		Value:     float64(len(services.Items)),
		Labels:    map[string]string{"cluster_id": k.config.ClusterID},
		Timestamp: timestamp,
		Plugin:    k.Name(),
		Component: "cluster",
		Category:  metrics.CategoryKubernetes,
		Severity:  metrics.SeverityInfo,
	})

	k.prometheusCollector.ServiceCount.WithLabelValues(k.config.ClusterID).Set(float64(len(services.Items)))

	return clusterMetrics, nil
}

// collectResourceMetrics gathers resource usage metrics
func (k *KubernetesPlugin) collectResourceMetrics(ctx context.Context) ([]metrics.Metric, error) {
	var resourceMetrics []metrics.Metric
	timestamp := time.Now()

	// If we have metrics client, collect resource usage
	if k.metricsClient != nil {
		// Get node metrics
		nodeMetrics, err := k.metricsClient.MetricsV1beta1().NodeMetricses().List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Printf("Warning: failed to get node metrics: %v", err)
		} else {
			for _, node := range nodeMetrics.Items {
				cpuUsage := float64(node.Usage.Cpu().MilliValue()) / 1000.0
				memoryUsage := float64(node.Usage.Memory().Value())

				// CPU usage metric
				resourceMetrics = append(resourceMetrics, metrics.Metric{
					Name:  "node_cpu_usage_cores",
					Type:  metrics.MetricTypeGauge,
					Value: cpuUsage,
					Labels: map[string]string{
						"cluster_id": k.config.ClusterID,
						"node":       node.Name,
					},
					Timestamp: timestamp,
					Plugin:    k.Name(),
					Component: "node",
					Category:  metrics.CategoryKubernetes,
					Severity:  metrics.SeverityInfo,
				})

				// Memory usage metric
				resourceMetrics = append(resourceMetrics, metrics.Metric{
					Name:  "node_memory_usage_bytes",
					Type:  metrics.MetricTypeGauge,
					Value: memoryUsage,
					Labels: map[string]string{
						"cluster_id": k.config.ClusterID,
						"node":       node.Name,
					},
					Timestamp: timestamp,
					Plugin:    k.Name(),
					Component: "node",
					Category:  metrics.CategoryKubernetes,
					Severity:  metrics.SeverityInfo,
				})

				// Update Prometheus metrics
				k.prometheusCollector.CPUUsage.WithLabelValues(k.config.ClusterID, node.Name, "cores").Set(cpuUsage)
				k.prometheusCollector.MemoryUsage.WithLabelValues(k.config.ClusterID, node.Name, "bytes").Set(memoryUsage)
			}
		}

		// Get pod metrics
		podMetrics, err := k.metricsClient.MetricsV1beta1().PodMetricses("").List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Printf("Warning: failed to get pod metrics: %v", err)
		} else {
			for _, pod := range podMetrics.Items {
				for _, container := range pod.Containers {
					cpuUsage := float64(container.Usage.Cpu().MilliValue()) / 1000.0
					memoryUsage := float64(container.Usage.Memory().Value())

					// Pod CPU usage metric
					resourceMetrics = append(resourceMetrics, metrics.Metric{
						Name:  "pod_cpu_usage_cores",
						Type:  metrics.MetricTypeGauge,
						Value: cpuUsage,
						Labels: map[string]string{
							"cluster_id": k.config.ClusterID,
							"namespace":  pod.Namespace,
							"pod":        pod.Name,
							"container":  container.Name,
						},
						Timestamp: timestamp,
						Plugin:    k.Name(),
						Component: "pod",
						Category:  metrics.CategoryKubernetes,
						Severity:  metrics.SeverityInfo,
					})

					// Pod memory usage metric
					resourceMetrics = append(resourceMetrics, metrics.Metric{
						Name:  "pod_memory_usage_bytes",
						Type:  metrics.MetricTypeGauge,
						Value: memoryUsage,
						Labels: map[string]string{
							"cluster_id": k.config.ClusterID,
							"namespace":  pod.Namespace,
							"pod":        pod.Name,
							"container":  container.Name,
						},
						Timestamp: timestamp,
						Plugin:    k.Name(),
						Component: "pod",
						Category:  metrics.CategoryKubernetes,
						Severity:  metrics.SeverityInfo,
					})
				}
			}
		}
	}

	return resourceMetrics, nil
}

// collectEvents gathers Kubernetes events
func (k *KubernetesPlugin) collectEvents(ctx context.Context) ([]metrics.Metric, error) {
	var eventMetrics []metrics.Metric
	timestamp := time.Now()

	// Calculate time range for events
	since := timestamp.Add(-k.config.EventLookback)

	events, err := k.clientset.CoreV1().Events("").List(ctx, metav1.ListOptions{
		Limit: int64(k.config.MaxEventsPerCycle),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list events: %w", err)
	}

	eventCounts := make(map[string]map[string]int)

	for _, event := range events.Items {
		eventTime := event.EventTime.Time
		if eventTime.IsZero() && !event.LastTimestamp.IsZero() {
			eventTime = event.LastTimestamp.Time
		}
		if eventTime.IsZero() && !event.FirstTimestamp.IsZero() {
			eventTime = event.FirstTimestamp.Time
		}
		if eventTime.IsZero() {
			eventTime = timestamp
		}

		// Skip events outside the lookback window
		if eventTime.Before(since) {
			continue
		}

		severity := k.mapEventTypeToSeverity(event.Type, event.Reason)

		// Initialize maps
		if eventCounts[event.Type] == nil {
			eventCounts[event.Type] = make(map[string]int)
		}
		if eventCounts[event.Reason] == nil {
			eventCounts[event.Reason] = make(map[string]int)
		}

		eventCounts[event.Type][event.Reason]++

		// Create event metric
		eventMetrics = append(eventMetrics, metrics.Metric{
			Name:  "kubernetes_event",
			Type:  metrics.MetricTypeEvent,
			Value: 1.0,
			Labels: map[string]string{
				"cluster_id": k.config.ClusterID,
				"namespace":  event.Namespace,
				"type":       event.Type,
				"reason":     event.Reason,
				"object":     event.InvolvedObject.Kind + "/" + event.InvolvedObject.Name,
			},
			Timestamp: eventTime,
			Plugin:    k.Name(),
			Component: "events",
			Category:  metrics.CategoryKubernetes,
			Severity:  severity,
			Metadata: map[string]interface{}{
				"message":   event.Message,
				"count":     event.Count,
				"last_seen": event.LastTimestamp.Time,
			},
		})

		// Update Prometheus metrics
		k.prometheusCollector.EventCount.WithLabelValues(
			k.config.ClusterID,
			event.Type,
			event.Reason,
		).Inc()
	}

	return eventMetrics, nil
}

// collectSecurityMetrics gathers security-related metrics
func (k *KubernetesPlugin) collectSecurityMetrics(ctx context.Context) ([]metrics.Metric, error) {
	var securityMetrics []metrics.Metric
	timestamp := time.Now()

	// Monitor RBAC if enabled
	if k.config.MonitorRBAC {
		rbacMetrics, err := k.collectRBACMetrics(ctx)
		if err != nil {
			log.Printf("Warning: failed to collect RBAC metrics: %v", err)
		} else {
			securityMetrics = append(securityMetrics, rbacMetrics...)
		}
	}

	// Monitor Network Policies if enabled
	if k.config.MonitorNetworkPolicies {
		networkPolicies, err := k.clientset.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Printf("Warning: failed to list network policies: %v", err)
		} else {
			securityMetrics = append(securityMetrics, metrics.Metric{
				Name:      "network_policies_count",
				Type:      metrics.MetricTypeGauge,
				Value:     float64(len(networkPolicies.Items)),
				Labels:    map[string]string{"cluster_id": k.config.ClusterID},
				Timestamp: timestamp,
				Plugin:    k.Name(),
				Component: "security",
				Category:  metrics.CategorySecurity,
				Severity:  metrics.SeverityInfo,
			})
		}
	}

	// Monitor Secrets if enabled
	if k.config.MonitorSecrets {
		secrets, err := k.clientset.CoreV1().Secrets("").List(ctx, metav1.ListOptions{})
		if err != nil {
			log.Printf("Warning: failed to list secrets: %v", err)
		} else {
			secretCounts := make(map[string]int)
			for _, secret := range secrets.Items {
				secretCounts[string(secret.Type)]++
			}

			for secretType, count := range secretCounts {
				securityMetrics = append(securityMetrics, metrics.Metric{
					Name:  "secrets_count",
					Type:  metrics.MetricTypeGauge,
					Value: float64(count),
					Labels: map[string]string{
						"cluster_id":  k.config.ClusterID,
						"secret_type": secretType,
					},
					Timestamp: timestamp,
					Plugin:    k.Name(),
					Component: "security",
					Category:  metrics.CategorySecurity,
					Severity:  metrics.SeverityInfo,
				})
			}
		}
	}

	return securityMetrics, nil
}

// collectRBACMetrics collects RBAC-related metrics
func (k *KubernetesPlugin) collectRBACMetrics(ctx context.Context) ([]metrics.Metric, error) {
	var rbacMetrics []metrics.Metric
	timestamp := time.Now()

	// Get ClusterRoles
	clusterRoles, err := k.clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster roles: %w", err)
	}

	rbacMetrics = append(rbacMetrics, metrics.Metric{
		Name:      "cluster_roles_count",
		Type:      metrics.MetricTypeGauge,
		Value:     float64(len(clusterRoles.Items)),
		Labels:    map[string]string{"cluster_id": k.config.ClusterID},
		Timestamp: timestamp,
		Plugin:    k.Name(),
		Component: "rbac",
		Category:  metrics.CategorySecurity,
		Severity:  metrics.SeverityInfo,
	})

	// Get ClusterRoleBindings
	clusterRoleBindings, err := k.clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
	}

	rbacMetrics = append(rbacMetrics, metrics.Metric{
		Name:      "cluster_role_bindings_count",
		Type:      metrics.MetricTypeGauge,
		Value:     float64(len(clusterRoleBindings.Items)),
		Labels:    map[string]string{"cluster_id": k.config.ClusterID},
		Timestamp: timestamp,
		Plugin:    k.Name(),
		Component: "rbac",
		Category:  metrics.CategorySecurity,
		Severity:  metrics.SeverityInfo,
	})

	return rbacMetrics, nil
}

// collectPerformanceMetrics gathers performance metrics
func (k *KubernetesPlugin) collectPerformanceMetrics(ctx context.Context) ([]metrics.Metric, error) {
	var performanceMetrics []metrics.Metric
	timestamp := time.Now()

	// Measure API server response time
	start := time.Now()
	_, err := k.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1})
	apiLatency := time.Since(start)

	if err != nil {
		log.Printf("Warning: failed to measure API latency: %v", err)
	} else {
		performanceMetrics = append(performanceMetrics, metrics.Metric{
			Name:      "api_server_latency_seconds",
			Type:      metrics.MetricTypeHistogram,
			Value:     apiLatency.Seconds(),
			Labels:    map[string]string{"cluster_id": k.config.ClusterID},
			Timestamp: timestamp,
			Plugin:    k.Name(),
			Component: "performance",
			Category:  metrics.CategoryPerformance,
			Severity:  metrics.SeverityInfo,
		})

		k.prometheusCollector.APIServerLatency.WithLabelValues(k.config.ClusterID).Observe(apiLatency.Seconds())
	}

	return performanceMetrics, nil
}

// mapEventTypeToSeverity maps Kubernetes event types to severity levels
func (k *KubernetesPlugin) mapEventTypeToSeverity(eventType, reason string) metrics.Severity {
	if eventType == "Warning" {
		switch reason {
		case "FailedScheduling", "Failed", "Unhealthy":
			return metrics.SeverityHigh
		case "BackOff", "Pulling":
			return metrics.SeverityMedium
		default:
			return metrics.SeverityLow
		}
	}
	return metrics.SeverityInfo
}

// PrometheusCollector returns the Prometheus collector
func (k *KubernetesPlugin) PrometheusCollector() prometheus.Collector {
	return k.prometheusCollector
}

// Shutdown cleans up the plugin
func (k *KubernetesPlugin) Shutdown() error {
	k.cancel()
	return nil
}

// Health returns plugin health status
func (k *KubernetesPlugin) Health() metrics.PluginHealth {
	status := metrics.HealthStatusHealthy
	if k.errorCount > 10 {
		status = metrics.HealthStatusDegraded
	}
	if time.Since(k.lastCollection) > 5*time.Minute {
		status = metrics.HealthStatusUnhealthy
	}

	return metrics.PluginHealth{
		Status:         status,
		LastCollection: k.lastCollection,
		ErrorCount:     k.errorCount,
		Uptime:         time.Since(k.startTime),
		MetricsCount:   k.metricsCount,
		Details: map[string]string{
			"cluster_id": k.config.ClusterID,
			"kubeconfig": k.kubeconfig,
		},
	}
}

// defaultConfig returns default configuration
func (k *KubernetesPlugin) defaultConfig() *KubernetesConfig {
	return &KubernetesConfig{
		CollectResources:       true,
		CollectEvents:          true,
		CollectMetrics:         true,
		CollectSecurity:        true,
		EventLookback:          5 * time.Minute,
		MaxEventsPerCycle:      100,
		ResourceTimeout:        30 * time.Second,
		MonitorRBAC:            true,
		MonitorNetworkPolicies: true,
		MonitorSecrets:         false, // Disabled by default for security
		ExcludeNamespaces:      []string{"kube-system", "kube-public", "kube-node-lease"},
	}
}

// newKubernetesPrometheusCollector creates Prometheus collector for Kubernetes metrics
func newKubernetesPrometheusCollector() *KubernetesPrometheusCollector {
	return &KubernetesPrometheusCollector{
		ClusterInfo: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_kubernetes_cluster_info",
				Help: "Kubernetes cluster information",
			},
			[]string{"cluster_id", "version"},
		),

		NodeCount: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_kubernetes_nodes_total",
				Help: "Total number of nodes in cluster",
			},
			[]string{"cluster_id"},
		),

		PodCount: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_kubernetes_pods_total",
				Help: "Total number of pods in cluster",
			},
			[]string{"cluster_id"},
		),

		ServiceCount: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_kubernetes_services_total",
				Help: "Total number of services in cluster",
			},
			[]string{"cluster_id"},
		),

		DeploymentCount: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_kubernetes_deployments_total",
				Help: "Total number of deployments in cluster",
			},
			[]string{"cluster_id"},
		),

		CPUUsage: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_kubernetes_cpu_usage",
				Help: "CPU usage in cluster",
			},
			[]string{"cluster_id", "node", "unit"},
		),

		MemoryUsage: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_kubernetes_memory_usage_bytes",
				Help: "Memory usage in bytes",
			},
			[]string{"cluster_id", "node", "unit"},
		),

		StorageUsage: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_kubernetes_storage_usage_bytes",
				Help: "Storage usage in bytes",
			},
			[]string{"cluster_id", "node"},
		),

		NetworkUsage: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_kubernetes_network_bytes_total",
				Help: "Network usage in bytes",
			},
			[]string{"cluster_id", "direction"},
		),

		PodHealth: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_kubernetes_pod_health",
				Help: "Pod health status",
			},
			[]string{"cluster_id", "namespace", "pod", "status"},
		),

		ServiceHealth: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_kubernetes_service_health",
				Help: "Service health status",
			},
			[]string{"cluster_id", "namespace", "service"},
		),

		NodeHealth: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_kubernetes_node_health",
				Help: "Node health status",
			},
			[]string{"cluster_id", "node", "status"},
		),

		EventCount: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_kubernetes_events_total",
				Help: "Total number of Kubernetes events",
			},
			[]string{"cluster_id", "type", "reason"},
		),

		EventSeverity: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_kubernetes_event_severity",
				Help: "Event severity levels",
			},
			[]string{"cluster_id", "severity"},
		),

		RBACEvents: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kubeaccess_kubernetes_rbac_events_total",
				Help: "Total RBAC-related events",
			},
			[]string{"cluster_id", "action", "resource"},
		),

		SecurityPolicies: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_kubernetes_security_policies",
				Help: "Number of security policies",
			},
			[]string{"cluster_id", "type"},
		),

		SecretsCount: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kubeaccess_kubernetes_secrets_total",
				Help: "Total number of secrets",
			},
			[]string{"cluster_id", "namespace"},
		),

		APIServerLatency: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "kubeaccess_kubernetes_api_latency_seconds",
				Help:    "Kubernetes API server latency",
				Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
			},
			[]string{"cluster_id"},
		),
	}
}

// updateCollectionDuration updates collection duration metric
func (k *KubernetesPrometheusCollector) updateCollectionDuration(start time.Time) {
	// This would be implemented to track collection performance
	duration := time.Since(start)
	log.Printf("Kubernetes metrics collection took: %v", duration)
}

// Describe implements prometheus.Collector interface
func (k *KubernetesPrometheusCollector) Describe(ch chan<- *prometheus.Desc) {
	k.ClusterInfo.Describe(ch)
	k.NodeCount.Describe(ch)
	k.PodCount.Describe(ch)
	k.ServiceCount.Describe(ch)
	k.DeploymentCount.Describe(ch)
	k.CPUUsage.Describe(ch)
	k.MemoryUsage.Describe(ch)
	k.StorageUsage.Describe(ch)
	k.NetworkUsage.Describe(ch)
	k.PodHealth.Describe(ch)
	k.ServiceHealth.Describe(ch)
	k.NodeHealth.Describe(ch)
	k.EventCount.Describe(ch)
	k.EventSeverity.Describe(ch)
	k.RBACEvents.Describe(ch)
	k.SecurityPolicies.Describe(ch)
	k.SecretsCount.Describe(ch)
	k.APIServerLatency.Describe(ch)
}

// Collect implements prometheus.Collector interface
func (k *KubernetesPrometheusCollector) Collect(ch chan<- prometheus.Metric) {
	k.ClusterInfo.Collect(ch)
	k.NodeCount.Collect(ch)
	k.PodCount.Collect(ch)
	k.ServiceCount.Collect(ch)
	k.DeploymentCount.Collect(ch)
	k.CPUUsage.Collect(ch)
	k.MemoryUsage.Collect(ch)
	k.StorageUsage.Collect(ch)
	k.NetworkUsage.Collect(ch)
	k.PodHealth.Collect(ch)
	k.ServiceHealth.Collect(ch)
	k.NodeHealth.Collect(ch)
	k.EventCount.Collect(ch)
	k.EventSeverity.Collect(ch)
	k.RBACEvents.Collect(ch)
	k.SecurityPolicies.Collect(ch)
	k.SecretsCount.Collect(ch)
	k.APIServerLatency.Collect(ch)
}
