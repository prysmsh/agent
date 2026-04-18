// Package main: operator-style controller for Prysm CNI deployment.
// The agent bootstraps the Prysm CNI as an operator - deploys the CNI install
// DaemonSet when zero trust is enabled, removes it when disabled.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	prysmCNINamespace       = "prysm-system"
	prysmCNIDaemonSetName   = "prysm-cni-node"
	prysmCNIServiceAccount  = "prysm-cni"
	prysmCNIReconcileKey    = "PRYSM_CNI_RECONCILE_INTERVAL"
	prysmCNIEnabledKey      = "PRYSM_CNI_ENABLED"
	prysmCNIImageEnvKey     = "PRYSM_CNI_IMAGE"
	defaultPrysmCNIImage    = "ghcr.io/prysmsh/cni:latest"
	defaultTargetPort       = "15001"
	defaultExcludeNamespaces = "kube-system,kube-public,prysm-system,prysm-logging,prysm-honeypots"

	// CNI config paths - K3s uses a different path than standard Kubernetes
	standardCNINetDir = "/etc/cni/net.d"
	k3sCNINetDir      = "/var/lib/rancher/k3s/agent/etc/cni/net.d"
)

// PrysmCNIConfig holds configuration for the Prysm CNI plugin
type PrysmCNIConfig struct {
	Enabled           bool     `json:"enabled"`
	TargetPort        string   `json:"target_port"`
	ExcludeNamespaces []string `json:"exclude_namespaces"`
	ExcludeCIDR       string   `json:"exclude_cidr"`
	Image             string   `json:"image"`
}

// detectK3s checks if running on K3s by looking for k3s-specific indicators
func (a *PrysmAgent) detectK3s(ctx context.Context) bool {
	// Check if the cluster has k3s nodes (k3s.io/hostname label or k3s in version)
	nodes, err := a.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil || len(nodes.Items) == 0 {
		return false
	}
	node := nodes.Items[0]
	// K3s nodes have kubeletVersion containing "k3s"
	if strings.Contains(strings.ToLower(node.Status.NodeInfo.KubeletVersion), "k3s") {
		return true
	}
	// Also check for k3s labels
	for k := range node.Labels {
		if strings.Contains(strings.ToLower(k), "k3s") {
			return true
		}
	}
	return false
}

// getCNINetDir returns the CNI config directory path based on the cluster type
func (a *PrysmAgent) getCNINetDir(ctx context.Context) string {
	if a.detectK3s(ctx) {
		log.Println("Prysm CNI: detected K3s cluster, using K3s CNI path")
		return k3sCNINetDir
	}
	return standardCNINetDir
}

// prysmCNIReconcileLoop periodically reconciles Prysm CNI deployment.
// Config is fetched from backend when available; env vars are used as fallback.
// Set PRYSM_CNI_CONTROLLER_DISABLED=true to skip the controller entirely.
func (a *PrysmAgent) prysmCNIReconcileLoop(ctx context.Context) {
	if os.Getenv("PRYSM_CNI_CONTROLLER_DISABLED") == "true" || os.Getenv("PRYSM_CNI_CONTROLLER_DISABLED") == "1" {
		log.Println("Prysm CNI controller disabled via PRYSM_CNI_CONTROLLER_DISABLED")
		return
	}

	interval := 5 * time.Minute
	if d := os.Getenv(prysmCNIReconcileKey); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
			interval = parsed
		}
	}

	log.Printf("Prysm CNI controller started (reconcile interval: %v)", interval)

	a.reconcilePrysmCNI(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Prysm CNI controller shutting down")
			return
		case <-ticker.C:
			a.reconcilePrysmCNI(ctx)
		}
	}
}

func (a *PrysmAgent) reconcilePrysmCNI(ctx context.Context) {
	if a.clientset == nil {
		return
	}

	config := a.getPrysmCNIConfig(ctx)

	if !config.Enabled {
		a.cleanupPrysmCNI(ctx)
		return
	}

	log.Println("Reconciling Prysm CNI deployment...")

	if err := a.ensurePrysmCNINamespace(ctx); err != nil {
		log.Printf("Failed to ensure prysm-system namespace: %v", err)
		return
	}

	if err := a.ensurePrysmCNIRBAC(ctx); err != nil {
		log.Printf("Failed to ensure Prysm CNI RBAC: %v", err)
		return
	}

	if err := a.deployPrysmCNI(ctx, config); err != nil {
		log.Printf("Failed to deploy Prysm CNI: %v", err)
		return
	}

	// Report Prysm CNI status to backend
	a.reportPrysmCNIStatus(ctx, config)
}

// getPrysmCNIConfig fetches config from backend when available, falls back to env vars
func (a *PrysmAgent) getPrysmCNIConfig(ctx context.Context) *PrysmCNIConfig {
	// Start with env-based defaults
	cniImage := getEnvOrDefault(prysmCNIImageEnvKey, defaultPrysmCNIImage)
	// Prefer backend-pushed override from component config
	if a.ComponentConfig.CNIImage != "" {
		cniImage = a.ComponentConfig.CNIImage
	}
	config := &PrysmCNIConfig{
		Enabled:           os.Getenv(prysmCNIEnabledKey) == "true" || os.Getenv(prysmCNIEnabledKey) == "1",
		TargetPort:        getEnvOrDefault("PRYSM_CNI_TARGET_PORT", defaultTargetPort),
		ExcludeNamespaces: strings.Split(getEnvOrDefault("PRYSM_CNI_EXCLUDE_NAMESPACES", defaultExcludeNamespaces), ","),
		ExcludeCIDR:       getEnvOrDefault("PRYSM_CNI_EXCLUDE_CIDR", ""),
		Image:             cniImage,
	}

	// Fetch from backend when available; backend config overrides env
	backendConfig, err := a.fetchPrysmCNIConfig(ctx)
	if err != nil {
		log.Printf("Prysm CNI: failed to fetch backend config: %v (using env)", err)
	} else if backendConfig != nil {
		config.Enabled = backendConfig.Enabled
		if backendConfig.TargetPort != "" {
			config.TargetPort = backendConfig.TargetPort
		}
		if len(backendConfig.ExcludeNamespaces) > 0 {
			config.ExcludeNamespaces = backendConfig.ExcludeNamespaces
		}
		if backendConfig.Image != "" {
			config.Image = backendConfig.Image
		}
	}

	for i, ns := range config.ExcludeNamespaces {
		config.ExcludeNamespaces[i] = strings.TrimSpace(ns)
	}
	return config
}

// fetchPrysmCNIConfig fetches Zero Trust / Prysm CNI config from the control plane
func (a *PrysmAgent) fetchPrysmCNIConfig(ctx context.Context) (*PrysmCNIConfig, error) {
	if a.BackendURL == "" || a.AgentToken == "" || a.ClusterID == "" {
		return nil, nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", a.BackendURL+"/api/v1/agent/zero-trust/config", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.AgentToken)
	req.Header.Set("X-Cluster-ID", a.ClusterID)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("config fetch failed: %s", string(body))
	}

	var payload struct {
		Enabled           bool     `json:"enabled"`
		TargetPort        string   `json:"cni_target_port"`
		ExcludeNamespaces string   `json:"exclude_namespaces"`
		Image             string   `json:"cni_image"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	exclude := payload.ExcludeNamespaces
	if exclude == "" {
		exclude = defaultExcludeNamespaces
	}
	namespaces := strings.Split(exclude, ",")
	for i, ns := range namespaces {
		namespaces[i] = strings.TrimSpace(ns)
	}

	targetPort := payload.TargetPort
	if targetPort == "" {
		targetPort = defaultTargetPort
	}
	image := payload.Image
	if image == "" {
		image = defaultPrysmCNIImage
	}

	return &PrysmCNIConfig{
		Enabled:           payload.Enabled,
		TargetPort:        targetPort,
		ExcludeNamespaces: namespaces,
		Image:             image,
	}, nil
}

func (a *PrysmAgent) ensurePrysmCNINamespace(ctx context.Context) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: prysmCNINamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name": "prysm-system",
				"prysm.sh/managed":      "true",
			},
		},
	}
	_, err := a.clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func (a *PrysmAgent) ensurePrysmCNIRBAC(ctx context.Context) error {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      prysmCNIServiceAccount,
			Namespace: prysmCNINamespace,
		},
	}
	_, err := a.clientset.CoreV1().ServiceAccounts(prysmCNINamespace).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	role := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prysm-cni",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "nodes", "namespaces"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
	_, err = a.clientset.RbacV1().ClusterRoles().Create(ctx, role, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	binding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prysm-cni",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "prysm-cni",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      prysmCNIServiceAccount,
				Namespace: prysmCNINamespace,
			},
		},
	}
	_, err = a.clientset.RbacV1().ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

func (a *PrysmAgent) deployPrysmCNI(ctx context.Context, config *PrysmCNIConfig) error {
	image := config.Image
	if image == "" {
		image = defaultPrysmCNIImage
	}

	// Detect K3s and use appropriate CNI config path
	cniNetDir := a.getCNINetDir(ctx)

	cniPluginConfig := map[string]interface{}{
		"type":              "prysm-cni",
		"targetPort":        config.TargetPort,
		"excludeNamespaces": config.ExcludeNamespaces,
	}
	if config.ExcludeCIDR != "" {
		cniPluginConfig["excludeCIDR"] = config.ExcludeCIDR
	}
	cniConfigJSON, err := json.Marshal(cniPluginConfig)
	if err != nil {
		return fmt.Errorf("marshal CNI config: %w", err)
	}

	privileged := true
	hostNetwork := true

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      prysmCNIDaemonSetName,
			Namespace: prysmCNINamespace,
			Labels: map[string]string{
				"app":                    "prysm-cni-node",
				"app.kubernetes.io/name": "prysm-cni",
				"prysm.sh/managed":       "true",
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "prysm-cni-node",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":                    "prysm-cni-node",
						"app.kubernetes.io/name": "prysm-cni",
						"prysm.sh/managed":       "true",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: prysmCNIServiceAccount,
					HostNetwork:        hostNetwork,
					Tolerations: []corev1.Toleration{
						{Operator: corev1.TolerationOpExists},
					},
					PriorityClassName: "system-node-critical",
					Containers: []corev1.Container{
						{
							Name:            "install-cni",
							Image:           image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         []string{"/install-cni.sh"},
							Env: []corev1.EnvVar{
								{
									Name: "HOST_IP",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "status.hostIP",
										},
									},
								},
								{Name: "CNI_NETWORK_CONFIG", Value: string(cniConfigJSON)},
								{Name: "CHAINED_CNI_PLUGIN", Value: "true"},
								{Name: "SLEEP", Value: "true"},
								{Name: "MOUNTED_CNI_BIN_DIR_K3S", Value: "/host/bin"},
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("32Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "cni-bin-dir", MountPath: "/host/opt/cni/bin"},
								{Name: "cni-bin-dir-k3s", MountPath: "/host/bin"},
								{Name: "cni-net-dir", MountPath: "/host/etc/cni/net.d"},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "cni-bin-dir",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/opt/cni/bin",
									Type: hostPathTypePtr(corev1.HostPathDirectoryOrCreate),
								},
							},
						},
						{
							Name: "cni-bin-dir-k3s",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/bin",
									Type: hostPathTypePtr(corev1.HostPathDirectory),
								},
							},
						},
						{
							Name: "cni-net-dir",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: cniNetDir,
									Type: hostPathTypePtr(corev1.HostPathDirectoryOrCreate),
								},
							},
						},
					},
				},
			},
		},
	}

	_, err = a.clientset.AppsV1().DaemonSets(prysmCNINamespace).Create(ctx, ds, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		// Get the existing DaemonSet to obtain resourceVersion for update
		existing, getErr := a.clientset.AppsV1().DaemonSets(prysmCNINamespace).Get(ctx, prysmCNIDaemonSetName, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("get existing CNI DaemonSet: %w", getErr)
		}
		ds.ObjectMeta.ResourceVersion = existing.ObjectMeta.ResourceVersion
		ds.ObjectMeta.UID = existing.ObjectMeta.UID
		_, err = a.clientset.AppsV1().DaemonSets(prysmCNINamespace).Update(ctx, ds, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("update CNI DaemonSet: %w", err)
		}
		log.Printf("Prysm CNI DaemonSet updated (image=%s)", image)
	}

	return err
}

// reportPrysmCNIStatus sends CNI status to the control plane for the dashboard.
func (a *PrysmAgent) reportPrysmCNIStatus(ctx context.Context, config *PrysmCNIConfig) {
	if a.BackendURL == "" || a.AgentToken == "" {
		return
	}

	status := map[string]interface{}{
		"cni_ready":           false,
		"cni_pods":            0,
		"cni_pods_ready":      0,
		"enrolled_namespaces": 0,
		"enrolled_pods":       0,
		"version":             "prysm-cni",
	}

	// Get Prysm CNI DaemonSet status
	ds, err := a.clientset.AppsV1().DaemonSets(prysmCNINamespace).Get(ctx, prysmCNIDaemonSetName, metav1.GetOptions{})
	if err == nil {
		status["cni_pods"] = int(ds.Status.DesiredNumberScheduled)
		status["cni_pods_ready"] = int(ds.Status.NumberReady)
		status["cni_ready"] = ds.Status.NumberReady == ds.Status.DesiredNumberScheduled && ds.Status.NumberReady > 0
		if len(ds.Spec.Template.Spec.Containers) > 0 {
			if parts := strings.Split(ds.Spec.Template.Spec.Containers[0].Image, ":"); len(parts) > 1 {
				status["version"] = parts[len(parts)-1]
			}
		}
	}

	// Count enrolled namespaces and pods (non-excluded)
	excludeSet := make(map[string]bool)
	for _, ns := range config.ExcludeNamespaces {
		excludeSet[strings.TrimSpace(ns)] = true
	}
	namespaces, err := a.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err == nil {
		enrolledNs := 0
		enrolledPods := 0
		for _, ns := range namespaces.Items {
			if excludeSet[ns.Name] {
				continue
			}
			enrolledNs++
			pods, _ := a.clientset.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
			if pods != nil {
				enrolledPods += len(pods.Items)
			}
		}
		status["enrolled_namespaces"] = enrolledNs
		status["enrolled_pods"] = enrolledPods
	}

	body, err := json.Marshal(status)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.BackendURL+"/api/v1/agent/zero-trust/status", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.AgentToken)
	req.Header.Set("X-Cluster-ID", a.ClusterID)
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		log.Printf("⚠️  Failed to report Prysm CNI status: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Printf("📊 Reported Prysm CNI status (cni_pods=%v, enrolled=%v)", status["cni_pods_ready"], status["enrolled_pods"])
	} else {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("⚠️  Prysm CNI status report failed: %s", string(respBody))
	}
}

func (a *PrysmAgent) cleanupPrysmCNI(ctx context.Context) {
	// Remove prysm-cni from conflist on each node - the DaemonSet pods do this on exit
	// For now we just delete the DaemonSet; pods will terminate and we'd need a preStop
	// to clean the conflist. Simplest: delete DaemonSet, next install will re-chain.
	err := a.clientset.AppsV1().DaemonSets(prysmCNINamespace).Delete(ctx, prysmCNIDaemonSetName, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		log.Printf("Failed to delete Prysm CNI DaemonSet: %v", err)
		return
	}
	log.Println("Prysm CNI cleanup completed")
}

func hostPathTypePtr(t corev1.HostPathType) *corev1.HostPathType {
	return &t
}
