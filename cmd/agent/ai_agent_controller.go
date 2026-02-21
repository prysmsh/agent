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
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	aiAgentNamespace    = "prysm-ai-agents"
	aiAgentLabelKey     = "prysm.sh/ai-agent"
	aiAgentTypeLabelKey = "prysm.sh/ai-agent-type"
)

// aiAgentSpec is the agent data returned by GET /agent/ai-agents/config.
type aiAgentSpec struct {
	ID             uint            `json:"id"`
	OrganizationID uint            `json:"organization_id"`
	Name           string          `json:"name"`
	Type           string          `json:"type"`    // llm-chat | model-serving
	Runtime        string          `json:"runtime"` // k8s-cluster | prysm-managed
	ClusterID      *uint           `json:"cluster_id"`
	Config         json.RawMessage `json:"config"`
	Status         string          `json:"status"`
	Replicas       int             `json:"replicas"`
}

// aiAgentStatusReport is POSTed to /agent/ai-agents/status.
type aiAgentStatusReport struct {
	AgentID       uint   `json:"agent_id"`
	Status        string `json:"status"`
	StatusMessage string `json:"status_message"`
	ReadyReplicas int    `json:"ready_replicas"`
	EndpointURL   string `json:"endpoint_url"`
}

// aiAgentController manages AI agent Deployments via HTTP polling (like honeypot controller).
type aiAgentController struct {
	agent   *PrysmAgent
	tracked sync.Map // agent_id (uint) -> deployName (string)
}

// startAIAgentController polls the backend for AI agent config, reconciles K8s resources,
// and reports status back via HTTP. Follows the honeypot controller pattern.
func (a *PrysmAgent) startAIAgentController(ctx context.Context) {
	if a.clientset == nil {
		log.Println("ai-agent-controller: disabled (no kubernetes client)")
		return
	}
	if a.BackendURL == "" || a.AgentToken == "" || a.ClusterID == "" {
		log.Println("ai-agent-controller: disabled (missing backend URL, token, or cluster ID)")
		return
	}

	ctrl := &aiAgentController{agent: a}

	interval := 30 * time.Second
	if d := os.Getenv("AI_AGENT_RECONCILE_INTERVAL"); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
			interval = parsed
		}
	}

	// Initial reconcile
	ctrl.reconcile(ctx)

	ticker := time.NewTicker(interval)
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

// reconcile fetches desired agent state from backend and converges K8s resources.
func (ctrl *aiAgentController) reconcile(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	agents, err := ctrl.fetchConfig(ctx)
	if err != nil {
		log.Printf("ai-agent-controller: fetch config: %v", err)
		return
	}

	// Build desired set (agents that should have a deployment)
	desired := map[uint]aiAgentSpec{}
	for _, ag := range agents {
		if ag.Status == "deploying" || ag.Status == "active" || ag.Status == "error" {
			desired[ag.ID] = ag
		}
	}

	// Deploy/update desired agents
	for _, ag := range desired {
		ctrl.ensureDeployment(ctx, ag)
		ctrl.tracked.Store(ag.ID, fmt.Sprintf("ai-agent-%d", ag.ID))
	}

	// Find agents that are disabled/deleted in backend but still have deployments
	for _, ag := range agents {
		if _, shouldExist := desired[ag.ID]; !shouldExist {
			if ag.Status == "disabled" {
				ctrl.deleteDeployment(ctx, ag.ID)
			}
		}
	}

	// Check status of all tracked deployments and report
	ctrl.reportAllStatus(ctx)
}

// fetchConfig calls GET /api/v1/agent/ai-agents/config to get agent specs for this cluster.
func (ctrl *aiAgentController) fetchConfig(ctx context.Context) ([]aiAgentSpec, error) {
	a := ctrl.agent
	url := fmt.Sprintf("%s/api/v1/agent/ai-agents/config?cluster_id=%s", a.BackendURL, a.ClusterID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
		return nil, fmt.Errorf("backend returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Agents []aiAgentSpec `json:"agents"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.Agents, nil
}

// ensureDeployment creates or updates the K8s Deployment + Service for an AI agent.
func (ctrl *aiAgentController) ensureDeployment(ctx context.Context, ag aiAgentSpec) {
	a := ctrl.agent

	// Ensure namespace
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: aiAgentNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "prysm-agent",
				"prysm.sh/component":           "ai-agents",
			},
		},
	}
	if _, err := a.clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil && !errors.IsAlreadyExists(err) {
		log.Printf("ai-agent-controller: create namespace: %v", err)
		return
	}

	var config map[string]interface{}
	if len(ag.Config) > 0 {
		_ = json.Unmarshal(ag.Config, &config)
	}
	if config == nil {
		config = map[string]interface{}{}
	}

	replicas := int32(ag.Replicas)
	if replicas < 1 {
		replicas = 1
	}

	deployName := fmt.Sprintf("ai-agent-%d", ag.ID)
	labels := map[string]string{
		"app.kubernetes.io/name":       deployName,
		"app.kubernetes.io/managed-by": "prysm-agent",
		aiAgentLabelKey:                fmt.Sprintf("%d", ag.ID),
		aiAgentTypeLabelKey:            ag.Type,
	}

	container := buildAIAgentContainer(ag, config)

	podSecCtx := &corev1.PodSecurityContext{
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
	// model-serving agents can run as non-root; llm-chat (Ollama) may need root
	if ag.Type != "llm-chat" {
		podSecCtx.RunAsNonRoot = boolPtr(true)
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deployName,
			Namespace: aiAgentNamespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					Containers:      []corev1.Container{container},
					SecurityContext: podSecCtx,
				},
			},
		},
	}

	existing, err := a.clientset.AppsV1().Deployments(aiAgentNamespace).Get(ctx, deployName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			if _, err := a.clientset.AppsV1().Deployments(aiAgentNamespace).Create(ctx, deployment, metav1.CreateOptions{}); err != nil {
				log.Printf("ai-agent-controller: create deployment %s: %v", deployName, err)
				return
			}
			log.Printf("ai-agent-controller: created deployment %s", deployName)
		} else {
			log.Printf("ai-agent-controller: get deployment %s: %v", deployName, err)
			return
		}
	} else {
		existing.Spec = deployment.Spec
		if _, err := a.clientset.AppsV1().Deployments(aiAgentNamespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			log.Printf("ai-agent-controller: update deployment %s: %v", deployName, err)
			return
		}
	}

	ctrl.ensureService(ctx, ag, config)
	ctrl.ensureNetworkPolicy(ctx, ag, config)
}

// deleteDeployment removes the K8s Deployment + Service for an AI agent.
func (ctrl *aiAgentController) deleteDeployment(ctx context.Context, agentID uint) {
	a := ctrl.agent
	deployName := fmt.Sprintf("ai-agent-%d", agentID)

	if err := a.clientset.AppsV1().Deployments(aiAgentNamespace).Delete(ctx, deployName, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
		log.Printf("ai-agent-controller: delete deployment %s: %v", deployName, err)
	}
	if err := a.clientset.CoreV1().Services(aiAgentNamespace).Delete(ctx, deployName, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
		log.Printf("ai-agent-controller: delete service %s: %v", deployName, err)
	}

	netpolName := fmt.Sprintf("ai-agent-%d-egress", agentID)
	if err := a.clientset.NetworkingV1().NetworkPolicies(aiAgentNamespace).Delete(ctx, netpolName, metav1.DeleteOptions{}); err != nil && !errors.IsNotFound(err) {
		log.Printf("ai-agent-controller: delete network policy %s: %v", netpolName, err)
	}

	ctrl.tracked.Delete(agentID)
	log.Printf("ai-agent-controller: deleted resources for agent %d", agentID)
}

// buildAIAgentContainer returns the container spec based on agent type and config.
func buildAIAgentContainer(ag aiAgentSpec, config map[string]interface{}) corev1.Container {
	memLimit := aiConfigStr(config, "memory_limit", "4Gi")
	cpuLimit := aiConfigStr(config, "cpu_limit", "2")
	memRequest := aiConfigStr(config, "memory_request", "1Gi")
	cpuRequest := aiConfigStr(config, "cpu_request", "500m")

	resources := corev1.ResourceRequirements{
		Limits: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse(memLimit),
			corev1.ResourceCPU:    resource.MustParse(cpuLimit),
		},
		Requests: corev1.ResourceList{
			corev1.ResourceMemory: resource.MustParse(memRequest),
			corev1.ResourceCPU:    resource.MustParse(cpuRequest),
		},
	}

	switch ag.Type {
	case "llm-chat":
		model := aiConfigStr(config, "model", "qwen2.5-coder:7b")
		return corev1.Container{
			Name:            "ollama",
			Image:           aiConfigStr(config, "image", "ollama/ollama:latest"),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Ports: []corev1.ContainerPort{
				{Name: "http", ContainerPort: 11434, Protocol: corev1.ProtocolTCP},
			},
			Resources: resources,
			Env: []corev1.EnvVar{
				{Name: "OLLAMA_HOST", Value: "0.0.0.0"},
			},
			Lifecycle: &corev1.Lifecycle{
				PostStart: &corev1.LifecycleHandler{
					Exec: &corev1.ExecAction{
						Command: []string{"sh", "-c", fmt.Sprintf("nohup sh -c 'sleep 5 && ollama pull %s' &", model)},
					},
				},
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/",
						Port: intstr.FromInt(11434),
					},
				},
				InitialDelaySeconds: 10,
				PeriodSeconds:       5,
			},
		}

	case "model-serving":
		image := aiConfigStr(config, "image", "")
		if image == "" {
			image = "nginx:alpine"
		}
		port := aiConfigInt(config, "port", 8080)
		return corev1.Container{
			Name:            "model",
			Image:           image,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Ports: []corev1.ContainerPort{
				{Name: "http", ContainerPort: int32(port), Protocol: corev1.ProtocolTCP},
			},
			Resources: resources,
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					TCPSocket: &corev1.TCPSocketAction{
						Port: intstr.FromInt(port),
					},
				},
				InitialDelaySeconds: 5,
				PeriodSeconds:       5,
			},
		}

	default:
		return corev1.Container{
			Name:    "agent",
			Image:   "busybox:latest",
			Command: []string{"sh", "-c", "echo unsupported agent type; sleep 3600"},
		}
	}
}

// ensureService creates or updates a ClusterIP Service for the AI agent.
func (ctrl *aiAgentController) ensureService(ctx context.Context, ag aiAgentSpec, config map[string]interface{}) {
	a := ctrl.agent
	svcName := fmt.Sprintf("ai-agent-%d", ag.ID)
	labels := map[string]string{
		"app.kubernetes.io/name":       svcName,
		"app.kubernetes.io/managed-by": "prysm-agent",
		aiAgentLabelKey:                fmt.Sprintf("%d", ag.ID),
	}

	var port int32
	switch ag.Type {
	case "llm-chat":
		port = 11434
	case "model-serving":
		port = int32(aiConfigInt(config, "port", 8080))
	default:
		port = 8080
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: aiAgentNamespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Selector: labels,
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       port,
					TargetPort: intstr.FromInt(int(port)),
					Protocol:   corev1.ProtocolTCP,
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}

	existing, err := a.clientset.CoreV1().Services(aiAgentNamespace).Get(ctx, svcName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			if _, err := a.clientset.CoreV1().Services(aiAgentNamespace).Create(ctx, svc, metav1.CreateOptions{}); err != nil {
				log.Printf("ai-agent-controller: create service %s: %v", svcName, err)
			}
		}
		return
	}
	existing.Spec.Ports = svc.Spec.Ports
	if _, err := a.clientset.CoreV1().Services(aiAgentNamespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		log.Printf("ai-agent-controller: update service %s: %v", svcName, err)
	}
}

// reportAllStatus checks all tracked Deployments and POSTs status to the backend.
func (ctrl *aiAgentController) reportAllStatus(ctx context.Context) {
	var statuses []aiAgentStatusReport

	ctrl.tracked.Range(func(key, value interface{}) bool {
		agentID := key.(uint)
		deployName := value.(string)

		dep, err := ctrl.agent.clientset.AppsV1().Deployments(aiAgentNamespace).Get(ctx, deployName, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				ctrl.tracked.Delete(agentID)
				statuses = append(statuses, aiAgentStatusReport{
					AgentID: agentID, Status: "error", StatusMessage: "Deployment not found",
				})
			}
			return true
		}

		ready := int(dep.Status.ReadyReplicas)
		desired := 1
		if dep.Spec.Replicas != nil {
			desired = int(*dep.Spec.Replicas)
		}
		endpointURL := fmt.Sprintf("http://%s.%s.svc.cluster.local", deployName, aiAgentNamespace)

		var status, msg string
		switch {
		case ready >= desired && desired > 0:
			status = "active"
			msg = fmt.Sprintf("%d/%d replicas ready", ready, desired)
		case ready > 0:
			status = "deploying"
			msg = fmt.Sprintf("%d/%d replicas ready", ready, desired)
		default:
			status = "deploying"
			msg = fmt.Sprintf("0/%d replicas ready", desired)
			for _, cond := range dep.Status.Conditions {
				if cond.Type == appsv1.DeploymentReplicaFailure && cond.Status == corev1.ConditionTrue {
					status = "error"
					msg = cond.Message
					break
				}
			}
		}

		statuses = append(statuses, aiAgentStatusReport{
			AgentID: agentID, Status: status, StatusMessage: msg,
			ReadyReplicas: ready, EndpointURL: endpointURL,
		})
		return true
	})

	if len(statuses) == 0 {
		return
	}

	ctrl.postStatus(ctx, statuses)
}

// postStatus sends status updates to POST /api/v1/agent/ai-agents/status.
func (ctrl *aiAgentController) postStatus(ctx context.Context, statuses []aiAgentStatusReport) {
	a := ctrl.agent
	payload, err := json.Marshal(map[string]interface{}{"statuses": statuses})
	if err != nil {
		return
	}

	url := fmt.Sprintf("%s/api/v1/agent/ai-agents/status", a.BackendURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.AgentToken)
	req.Header.Set("X-Cluster-ID", a.ClusterID)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		log.Printf("ai-agent-controller: post status: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("ai-agent-controller: status report returned %d", resp.StatusCode)
	}
}

// aiConfigStr extracts a string from a config map with a default.
func aiConfigStr(config map[string]interface{}, key, fallback string) string {
	if v, ok := config[key].(string); ok && v != "" {
		return v
	}
	return fallback
}

// aiConfigInt extracts an int from a config map with a default.
func aiConfigInt(config map[string]interface{}, key string, fallback int) int {
	if v, ok := config[key].(float64); ok {
		return int(v)
	}
	return fallback
}

// boolPtr returns a pointer to a bool value.
func boolPtr(b bool) *bool { return &b }

// ensureNetworkPolicy creates or updates an egress NetworkPolicy for the AI agent.
// Default-deny egress with allowlist for DNS, cluster-internal, and user-specified CIDRs.
func (ctrl *aiAgentController) ensureNetworkPolicy(ctx context.Context, ag aiAgentSpec, config map[string]interface{}) {
	a := ctrl.agent
	netpolName := fmt.Sprintf("ai-agent-%d-egress", ag.ID)

	labels := map[string]string{
		aiAgentLabelKey: fmt.Sprintf("%d", ag.ID),
	}

	dnsPort53 := intstr.FromInt(53)
	protoUDP := corev1.ProtocolUDP
	protoTCP := corev1.ProtocolTCP

	egressRules := []networkingv1.NetworkPolicyEgressRule{
		// Allow DNS (UDP + TCP port 53)
		{
			Ports: []networkingv1.NetworkPolicyPort{
				{Protocol: &protoUDP, Port: &dnsPort53},
				{Protocol: &protoTCP, Port: &dnsPort53},
			},
		},
		// Allow cluster-internal (RFC1918)
		{
			To: []networkingv1.NetworkPolicyPeer{
				{IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/8"}},
				{IPBlock: &networkingv1.IPBlock{CIDR: "172.16.0.0/12"}},
				{IPBlock: &networkingv1.IPBlock{CIDR: "192.168.0.0/16"}},
			},
		},
	}

	// Add user-specified egress CIDRs from config
	if cidrsRaw, ok := config["allowed_egress_cidrs"]; ok {
		if cidrs, ok := cidrsRaw.([]interface{}); ok {
			var peers []networkingv1.NetworkPolicyPeer
			for _, cidr := range cidrs {
				if s, ok := cidr.(string); ok && s != "" {
					peers = append(peers, networkingv1.NetworkPolicyPeer{
						IPBlock: &networkingv1.IPBlock{CIDR: s},
					})
				}
			}
			if len(peers) > 0 {
				egressRules = append(egressRules, networkingv1.NetworkPolicyEgressRule{To: peers})
			}
		}
	}

	policyTypes := []networkingv1.PolicyType{networkingv1.PolicyTypeEgress}

	netpol := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      netpolName,
			Namespace: aiAgentNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "prysm-agent",
				aiAgentLabelKey:                fmt.Sprintf("%d", ag.ID),
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: labels},
			PolicyTypes: policyTypes,
			Egress:      egressRules,
		},
	}

	existing, err := a.clientset.NetworkingV1().NetworkPolicies(aiAgentNamespace).Get(ctx, netpolName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			if _, err := a.clientset.NetworkingV1().NetworkPolicies(aiAgentNamespace).Create(ctx, netpol, metav1.CreateOptions{}); err != nil {
				log.Printf("ai-agent-controller: create network policy %s: %v", netpolName, err)
			} else {
				log.Printf("ai-agent-controller: created network policy %s", netpolName)
			}
		} else {
			log.Printf("ai-agent-controller: get network policy %s: %v", netpolName, err)
		}
		return
	}
	existing.Spec = netpol.Spec
	if _, err := a.clientset.NetworkingV1().NetworkPolicies(aiAgentNamespace).Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
		log.Printf("ai-agent-controller: update network policy %s: %v", netpolName, err)
	}
}
