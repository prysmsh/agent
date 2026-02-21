// Package main: operator-style reconciler for the eBPF collector DaemonSet.
// When EBPF_COLLECTOR_ENABLED=true (default), the agent deploys and manages an
// eBPF collector DaemonSet in prysm-system so the user only installs the agent.

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ebpfCollectorNamespace    = "prysm-system"
	ebpfCollectorName         = "prysm-ebpf-collector"
	ebpfCollectorSecretName   = "prysm-ebpf-collector-token"
	ebpfCollectorEnabledEnv   = "EBPF_COLLECTOR_ENABLED"
	ebpfCollectorImageEnv     = "EBPF_COLLECTOR_IMAGE"
	ebpfCollectorImageDefault = "ghcr.io/prysmsh/ebpf-collector:latest"
)

// ensureEbpfCollectorDaemonSet creates or updates the eBPF collector DaemonSet.
// If EBPF_COLLECTOR_ENABLED is explicitly "false" or "0", it deletes any existing resources.
// Default is enabled (true).
func (a *PrysmAgent) ensureEbpfCollectorDaemonSet(ctx context.Context) {
	if a.clientset == nil {
		return
	}

	enabled := getEnvOrDefault(ebpfCollectorEnabledEnv, "true")
	if enabled == "false" || enabled == "0" {
		a.deleteEbpfCollectorResources(ctx)
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Secret for ingestion token so DaemonSet pods authenticate with the backend
	tokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: ebpfCollectorSecretName, Namespace: ebpfCollectorNamespace},
		Data:       map[string][]byte{"token": []byte(a.AgentToken)},
	}
	if _, err := a.clientset.CoreV1().Secrets(ebpfCollectorNamespace).Update(ctx, tokenSecret, metav1.UpdateOptions{}); err != nil {
		if errors.IsNotFound(err) {
			_, err = a.clientset.CoreV1().Secrets(ebpfCollectorNamespace).Create(ctx, tokenSecret, metav1.CreateOptions{})
		}
		if err != nil {
			log.Printf("ebpf-collector: failed to ensure token Secret: %v", err)
			return
		}
	}

	image := os.Getenv(ebpfCollectorImageEnv)
	if image == "" {
		// Fall back to EBPF_IMAGE_REPOSITORY:EBPF_IMAGE_TAG (set by Helm bootstrap)
		repo := os.Getenv("EBPF_IMAGE_REPOSITORY")
		tag := os.Getenv("EBPF_IMAGE_TAG")
		if repo != "" {
			if tag == "" {
				tag = "latest"
			}
			image = repo + ":" + tag
		} else {
			image = ebpfCollectorImageDefault
		}
	}
	ds := a.buildEbpfCollectorDaemonSet(image)

	existing, err := a.clientset.AppsV1().DaemonSets(ebpfCollectorNamespace).Get(ctx, ebpfCollectorName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = a.clientset.AppsV1().DaemonSets(ebpfCollectorNamespace).Create(ctx, ds, metav1.CreateOptions{})
			if err != nil {
				log.Printf("ebpf-collector: failed to create DaemonSet: %v", err)
				return
			}
			log.Printf("ebpf-collector: created DaemonSet %s/%s", ebpfCollectorNamespace, ebpfCollectorName)
			return
		}
		log.Printf("ebpf-collector: failed to get DaemonSet: %v", err)
		return
	}

	// Reconcile: sync image, env, resources, volume mounts, volumes, security context
	desired := ds.Spec.Template.Spec.Containers[0]
	existing.Spec.Template.Spec.Containers[0].Image = desired.Image
	existing.Spec.Template.Spec.Containers[0].Env = desired.Env
	existing.Spec.Template.Spec.Containers[0].Resources = desired.Resources
	existing.Spec.Template.Spec.Containers[0].VolumeMounts = desired.VolumeMounts
	existing.Spec.Template.Spec.Containers[0].SecurityContext = desired.SecurityContext
	existing.Spec.Template.Spec.Volumes = ds.Spec.Template.Spec.Volumes
	existing.Spec.Template.Spec.DNSPolicy = ds.Spec.Template.Spec.DNSPolicy
	if _, err := a.clientset.AppsV1().DaemonSets(ebpfCollectorNamespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		log.Printf("ebpf-collector: failed to update DaemonSet: %v", err)
	}
}

func (a *PrysmAgent) buildEbpfCollectorDaemonSet(image string) *appsv1.DaemonSet {
	privileged := true
	runAsUser := int64(0)

	agentHost := getEnvOrDefault("AGENT_SERVICE_HOST", "prysm-agent.prysm-system.svc.cluster.local")
	agentPort := getEnvOrDefault("AGENT_SERVICE_PORT", "8080")
	ingestEndpoint := getEnvOrDefault("EBPF_INGEST_ENDPOINT",
		fmt.Sprintf("http://%s:%s/api/v1/logs/ingest", agentHost, agentPort))
	meshEndpoint := getEnvOrDefault("EBPF_MESH_ENDPOINT",
		fmt.Sprintf("http://%s:%s/api/v1/agent/ztunnel/events", agentHost, agentPort))
	meshEnabled := getEnvOrDefault("EBPF_MESH_ENABLED", "true")
	meshCaptureAll := getEnvOrDefault("EBPF_MESH_CAPTURE_ALL", "true")

	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: ebpfCollectorName, Namespace: ebpfCollectorNamespace},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": ebpfCollectorName}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{
					"app":       ebpfCollectorName,
					"component": "security-monitoring",
				}},
				Spec: corev1.PodSpec{
					ServiceAccountName: "prysm-agent",
					HostPID:            true,
					HostNetwork:        true,
					DNSPolicy:          corev1.DNSClusterFirstWithHostNet,
					NodeSelector:       map[string]string{"kubernetes.io/os": "linux"},
					Tolerations: []corev1.Toleration{
						{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
						{Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
					},
					Containers: []corev1.Container{{
						Name:            "ebpf-collector",
						Image:           image,
						ImagePullPolicy: corev1.PullAlways,
						SecurityContext: &corev1.SecurityContext{
							Privileged: &privileged,
							RunAsUser:  &runAsUser,
						},
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("100m"),
								corev1.ResourceMemory: resource.MustParse("128Mi"),
							},
							Limits: corev1.ResourceList{
								corev1.ResourceCPU:    resource.MustParse("500m"),
								corev1.ResourceMemory: resource.MustParse("512Mi"),
							},
						},
						Env: []corev1.EnvVar{
							{Name: "PRYSM_ORG_ID", Value: fmt.Sprintf("%d", a.OrganizationID)},
							{Name: "PRYSM_CLUSTER_ID", Value: a.ClusterID},
							{Name: "PRYSM_EBPF_ENDPOINT", Value: ingestEndpoint},
							{Name: "PRYSM_MESH_ENDPOINT", Value: meshEndpoint},
							{Name: "MESH_ENABLED", Value: meshEnabled},
							{Name: "MESH_CAPTURE_ALL", Value: meshCaptureAll},
							{Name: "HOST_PROC", Value: "/host/proc"},
							{Name: "HEARTBEAT_INTERVAL", Value: "30s"},
							{Name: "HTTP_TIMEOUT", Value: "10s"},
							{Name: "PRYSM_SKIP_SIGNATURE_VERIFICATION", Value: "true"},
							{Name: "PRYSM_LOG_TOKEN", ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: ebpfCollectorSecretName},
									Key:                  "token",
								},
							}},
							{Name: "NODE_NAME", ValueFrom: &corev1.EnvVarSource{
								FieldRef: &corev1.ObjectFieldSelector{FieldPath: "spec.nodeName"},
							}},
							{Name: "POD_NAMESPACE", ValueFrom: &corev1.EnvVarSource{
								FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
							}},
						},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "bpf-maps", MountPath: "/sys/fs/bpf"},
							{Name: "host-lib-modules", MountPath: "/lib/modules", ReadOnly: true},
							{Name: "host-usr-src", MountPath: "/usr/src", ReadOnly: true},
							{Name: "proc", MountPath: "/host/proc", ReadOnly: true},
							{Name: "tracefs", MountPath: "/sys/kernel/debug", ReadOnly: true},
							{Name: "audit-logs", MountPath: "/var/log"},
							{Name: "tmp", MountPath: "/tmp"},
						},
					}},
					Volumes: []corev1.Volume{
						{Name: "bpf-maps", VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/sys/fs/bpf", Type: ptr(corev1.HostPathDirectoryOrCreate)},
						}},
						{Name: "host-lib-modules", VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/lib/modules", Type: ptr(corev1.HostPathDirectory)},
						}},
						{Name: "host-usr-src", VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/usr/src", Type: ptr(corev1.HostPathDirectoryOrCreate)},
						}},
						{Name: "proc", VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/proc", Type: ptr(corev1.HostPathDirectory)},
						}},
						{Name: "tracefs", VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/sys/kernel/debug", Type: ptr(corev1.HostPathDirectory)},
						}},
						{Name: "audit-logs", VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/prysm", Type: ptr(corev1.HostPathDirectoryOrCreate)},
						}},
						{Name: "tmp", VolumeSource: corev1.VolumeSource{
							EmptyDir: &corev1.EmptyDirVolumeSource{},
						}},
					},
				},
			},
		},
	}
}

func (a *PrysmAgent) deleteEbpfCollectorResources(ctx context.Context) {
	if a.clientset == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	_ = a.clientset.AppsV1().DaemonSets(ebpfCollectorNamespace).Delete(ctx, ebpfCollectorName, metav1.DeleteOptions{})
	_ = a.clientset.CoreV1().Secrets(ebpfCollectorNamespace).Delete(ctx, ebpfCollectorSecretName, metav1.DeleteOptions{})
}
