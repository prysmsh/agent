// Package main: operator-style reconciler for the log collector DaemonSet.
// When LOG_COLLECTOR_MODE=daemonset, the agent deploys and manages a log-collector
// DaemonSet (narrow mount: CRI + /var/log/containers) so the user installs only the agent.
// See: spec/KUBE_LOG_ARCHITECTURE.md

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	logCollectorNamespace   = "prysm-logging"
	logCollectorName        = "prysm-log-collector"
	logCollectorConfigName  = "prysm-log-collector-config"
	logCollectorModeEnv     = "LOG_COLLECTOR_MODE"
	logCollectorModeDaemon  = "daemonset"
	logCollectorImageEnv   = "LOG_COLLECTOR_IMAGE"
	logCollectorImageDefault = "fluent/fluent-bit:4.2"
)

// ensureLogCollectorDaemonSet creates or updates the log collector DaemonSet and ConfigMap.
// If LOG_COLLECTOR_MODE != daemonset, it deletes the DaemonSet/ConfigMap if present.
// Call this periodically (e.g. from a reconcile loop) or on config change.
func (a *PrysmAgent) ensureLogCollectorDaemonSet(ctx context.Context) {
	if a.clientset == nil {
		return
	}

	mode := strings.TrimSpace(strings.ToLower(os.Getenv(logCollectorModeEnv)))
	if mode != logCollectorModeDaemon {
		a.deleteLogCollectorResources(ctx)
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Ensure namespace
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: logCollectorNamespace}}
	_, err := a.clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil && !isAlreadyExists(err) {
		log.Printf("log-collector: failed to create namespace %s: %v", logCollectorNamespace, err)
		return
	}

	// Secret for ingestion token (agent creates it so DaemonSet pods don't need agent's full secret)
	tokenSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "prysm-log-collector-token", Namespace: logCollectorNamespace},
		Data:       map[string][]byte{"token": []byte(a.AgentToken)},
	}
	if _, err := a.clientset.CoreV1().Secrets(logCollectorNamespace).Update(ctx, tokenSecret, metav1.UpdateOptions{}); err != nil {
		if errors.IsNotFound(err) {
			_, err = a.clientset.CoreV1().Secrets(logCollectorNamespace).Create(ctx, tokenSecret, metav1.CreateOptions{})
		}
		if err != nil {
			log.Printf("log-collector: failed to ensure token Secret: %v", err)
			return
		}
	}

	// ConfigMap for collector config (no token; container gets PRYSM_AGENT_TOKEN from Secret)
	configData := a.buildLogCollectorConfigData()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: logCollectorConfigName, Namespace: logCollectorNamespace},
		Data:       configData,
	}
	if _, err := a.clientset.CoreV1().ConfigMaps(logCollectorNamespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		if errors.IsNotFound(err) {
			_, err = a.clientset.CoreV1().ConfigMaps(logCollectorNamespace).Create(ctx, cm, metav1.CreateOptions{})
		}
		if err != nil {
			log.Printf("log-collector: failed to ensure ConfigMap: %v", err)
			return
		}
	}

	// Count running pods to size Fluent Bit resources proportionally
	podCount := 0
	if podList, err := a.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Running",
	}); err == nil {
		podCount = len(podList.Items)
	}

	// DaemonSet: narrow mount - only /var/log/containers (and optional CRI socket)
	image := os.Getenv(logCollectorImageEnv)
	if image == "" {
		image = logCollectorImageDefault
	}
	ds := a.buildLogCollectorDaemonSet(image, podCount)

	existing, err := a.clientset.AppsV1().DaemonSets(logCollectorNamespace).Get(ctx, logCollectorName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = a.clientset.AppsV1().DaemonSets(logCollectorNamespace).Create(ctx, ds, metav1.CreateOptions{})
			if err != nil {
				log.Printf("log-collector: failed to create DaemonSet: %v", err)
				return
			}
			log.Printf("log-collector: created DaemonSet %s/%s", logCollectorNamespace, logCollectorName)
			return
		}
		log.Printf("log-collector: failed to get DaemonSet: %v", err)
		return
	}

	// Update image / template if changed
	desired := ds.Spec.Template.Spec.Containers[0]
	existing.Spec.Template.Spec.Containers[0].Image = desired.Image
	existing.Spec.Template.Spec.Containers[0].Env = desired.Env
	existing.Spec.Template.Spec.Containers[0].Resources = desired.Resources
	existing.Spec.Template.Spec.Containers[0].LivenessProbe = desired.LivenessProbe
	existing.Spec.Template.Spec.Volumes = ds.Spec.Template.Spec.Volumes
	existing.Spec.Template.Spec.Containers[0].VolumeMounts = desired.VolumeMounts
	if _, err := a.clientset.AppsV1().DaemonSets(logCollectorNamespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		log.Printf("log-collector: failed to update DaemonSet: %v", err)
	}
}

func (a *PrysmAgent) buildLogCollectorConfigData() map[string]string {
	// Fluent Bit sends to the local agent proxy, which forwards to remote prysm-ingestion-api
	// Agent runs as a Service at prysm-agent.prysm-system.svc.cluster.local
	// Use AGENT_SERVICE_PORT (service port) not AGENT_HTTP_PORT (pod targetPort) when connecting via service DNS
	agentHost := getEnvOrDefault("AGENT_SERVICE_HOST", "prysm-agent.prysm-system.svc.cluster.local")
	agentPort := getEnvOrDefault("AGENT_SERVICE_PORT", "8080")
	
	exclude := getEnvOrDefault("LOG_EXCLUDE_NAMESPACES", "kube-system,kube-public")
	// Token is provided via Secret and env PRYSM_AGENT_TOKEN; Fluent Bit 2.x expands $(VAR) in config
	config := `
[SERVICE]
    Flush        5
    Daemon       Off
    Log_Level    info
    Parsers_File /fluent-bit/etc/parsers.conf
    HTTP_Server  On
    HTTP_Listen  0.0.0.0
    HTTP_Port    2020

[INPUT]
    Name              tail
    Path              /var/log/containers/*.log
    Tag               kube.*
    Refresh_Interval  10
    Mem_Buf_Limit     5MB
    Skip_Long_Lines   On
    DB                /var/log/flb_kube.db

[FILTER]
    Name          kubernetes
    Match         kube.*
    Kube_URL      https://kubernetes.default.svc:443
    Merge_Log     On
    Keep_Log      Off
    K8s-Logging.Parser  On
    K8s-Logging.Exclude On

[OUTPUT]
    Name          http
    Match         *
    Host          ` + agentHost + `
    Port          ` + agentPort + `
    URI           /api/v1/logs/ingest/fluent
    Format        json
    Json_date_key time
    Json_date_format iso8601
    Header        Authorization Bearer ${PRYSM_AGENT_TOKEN}
    tls           Off
    Retry_Limit   False
`
	return map[string]string{
		"fluent-bit.conf":   strings.TrimSpace(config),
		"exclude_namespaces": exclude,
	}
}

// parseIngestionURL returns host and URI from https://host/path or http://host:port/path.
func parseIngestionURL(raw string) (host, uri string) {
	raw = strings.TrimSpace(raw)
	uri = "/"
	if raw == "" {
		return "localhost", uri
	}
	if strings.HasPrefix(raw, "https://") {
		raw = raw[8:]
	} else if strings.HasPrefix(raw, "http://") {
		raw = raw[7:]
	}
	idx := strings.Index(raw, "/")
	if idx >= 0 {
		uri = "/" + strings.TrimPrefix(raw[idx:], "/")
		raw = raw[:idx]
	}
	host = raw
	if host == "" {
		host = "localhost"
	}
	if portIdx := strings.LastIndex(host, ":"); portIdx > 0 {
		host = host[:portIdx]
	}
	return host, uri
}

// logCollectorResources returns CPU/memory requests and limits scaled to pod count.
// Fluent Bit memory usage grows with log volume; more pods = more container logs.
//   - base: 64Mi / 50m CPU (handles ~50 pods comfortably)
//   - per 100 pods: +32Mi memory, +25m CPU
//   - limits: 2x requests, capped at 1Gi / 500m
func logCollectorResources(podCount int) corev1.ResourceRequirements {
	memMi := 64 + (podCount/100)*32
	cpuM := 50 + (podCount/100)*25

	// Cap limits
	memLimitMi := memMi * 2
	if memLimitMi > 1024 {
		memLimitMi = 1024
	}
	cpuLimitM := cpuM * 2
	if cpuLimitM > 500 {
		cpuLimitM = 500
	}

	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse(fmt.Sprintf("%dm", cpuM)),
			corev1.ResourceMemory: resource.MustParse(fmt.Sprintf("%dMi", memMi)),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse(fmt.Sprintf("%dm", cpuLimitM)),
			corev1.ResourceMemory: resource.MustParse(fmt.Sprintf("%dMi", memLimitMi)),
		},
	}
}

func (a *PrysmAgent) buildLogCollectorDaemonSet(image string, podCount int) *appsv1.DaemonSet {
	cfg := corev1.VolumeMount{
		Name:      "config",
		MountPath: "/fluent-bit/etc/fluent-bit.conf",
		SubPath:   "fluent-bit.conf",
		ReadOnly:  true,
	}
	logPath := corev1.VolumeMount{
		Name:      "varlog",
		MountPath: "/var/log/containers",
		ReadOnly:  true,
	}
	podLogPath := corev1.VolumeMount{
		Name:      "varlogpods",
		MountPath: "/var/log/pods",
		ReadOnly:  true,
	}
	flbdbPath := corev1.VolumeMount{
		Name:      "flbdb",
		MountPath: "/var/log",
	}
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: logCollectorName, Namespace: logCollectorNamespace},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": logCollectorName}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": logCollectorName}},
				Spec: corev1.PodSpec{
					ServiceAccountName: "default",
					Containers: []corev1.Container{{
						Name:  "log-collector",
						Image: image,
						Args:  []string{"/fluent-bit/bin/fluent-bit", "-c", "/fluent-bit/etc/fluent-bit.conf"},
						Resources: logCollectorResources(podCount),
						VolumeMounts: []corev1.VolumeMount{cfg, logPath, podLogPath, flbdbPath},
						LivenessProbe: &corev1.Probe{
							ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
								Path: "/api/v1/health",
								Port: intstr.FromInt(2020),
							}},
							InitialDelaySeconds: 30,
							PeriodSeconds:       30,
							FailureThreshold:    5,
						},
						Env: []corev1.EnvVar{
							{Name: "PRYSM_CLUSTER_ID", Value: a.ClusterID},
							{Name: "PRYSM_AGENT_TOKEN", ValueFrom: &corev1.EnvVarSource{
								SecretKeyRef: &corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: "prysm-log-collector-token"},
									Key:                  "token",
								},
							}},
						},
					}},
					Volumes: []corev1.Volume{
						{Name: "config", VolumeSource: corev1.VolumeSource{
							ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: logCollectorConfigName}},
						}},
						{Name: "varlog", VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/containers", Type: ptr(corev1.HostPathDirectoryOrCreate)},
						}},
						{Name: "varlogpods", VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/pods", Type: ptr(corev1.HostPathDirectoryOrCreate)},
						}},
						{Name: "flbdb", VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/prysm-flb", Type: ptr(corev1.HostPathDirectoryOrCreate)},
						}},
					},
					Tolerations: []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
				},
			},
		},
	}
}

func (a *PrysmAgent) deleteLogCollectorResources(ctx context.Context) {
	if a.clientset == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	_ = a.clientset.AppsV1().DaemonSets(logCollectorNamespace).Delete(ctx, logCollectorName, metav1.DeleteOptions{})
	_ = a.clientset.CoreV1().ConfigMaps(logCollectorNamespace).Delete(ctx, logCollectorConfigName, metav1.DeleteOptions{})
	_ = a.clientset.CoreV1().Secrets(logCollectorNamespace).Delete(ctx, "prysm-log-collector-token", metav1.DeleteOptions{})
}

func getEnvOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
