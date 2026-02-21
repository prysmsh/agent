// Package main: operator-style controller for honeypot deployment and management.
// The agent acts as a Kubernetes operator to deploy, configure, and manage honeypots
// based on configuration received from the Prysm control plane.
// Honeypot events are collected via Fluent Bit sidecar and forwarded to the agent's log proxy.

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
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	honeypotNamespace          = "prysm-honeypots"
	honeypotLabelKey           = "prysm.sh/honeypot"
	honeypotTypeLabelKey       = "prysm.sh/honeypot-type"
	honeypotConfigName         = "prysm-honeypot-config"
	honeypotSecretName         = "prysm-honeypot-credentials"
	fluentBitConfigName        = "prysm-honeypot-fluent-bit"
	heraldingConfigMapName     = "prysm-honeypot-heralding-config"
	heraldingConfigMountPath   = "/app/heralding.yml"
	heraldingConfigKey         = "heralding.yml"
	honeypotReconcileEnvKey      = "HONEYPOT_RECONCILE_INTERVAL"
	honeypotEnabledEnvKey        = "HONEYPOT_ENABLED"
	honeypotImageRegistryEnvKey  = "HONEYPOT_IMAGE_REGISTRY"   // e.g. ghcr.io/myorg - overrides beehivesec for self-hosted
	honeypotImagePullSecretsKey = "HONEYPOT_IMAGE_PULL_SECRET" // secret name for private registry auth
	honeypotServiceAccount    = "prysm-honeypot-sa"
	honeypotRole              = "prysm-honeypot-role"
	honeypotRoleBinding       = "prysm-honeypot-rolebinding"
	honeypotClusterRole       = "prysm-honeypot-clusterrole"
	honeypotClusterRoleBinding = "prysm-honeypot-clusterrolebinding"
)

// HoneypotConfig represents the honeypot configuration from the control plane
type HoneypotConfig struct {
	Enabled        bool              `json:"enabled"`
	Profile        string            `json:"profile"` // minimal, standard, full, custom
	Honeypots      []string          `json:"honeypots,omitempty"`
	NodeSelector   map[string]string `json:"nodeSelector,omitempty"`
	ExposeExternal bool              `json:"exposeExternal"`
	NodePorts      map[string]int32  `json:"nodePorts,omitempty"`
}

// HoneypotSpec defines a honeypot's deployment specification
type HoneypotSpec struct {
	Name          string
	Image         string
	Ports         []HoneypotPort
	MemoryLimit   string
	MemoryRequest string
	CPULimit      string
	CPURequest    string
	LogPath       string
	EnvVars       []corev1.EnvVar
	Command       []string
	Args          []string
	RunAsUser     int64
}

// HoneypotPort defines a port exposed by a honeypot
type HoneypotPort struct {
	Name          string
	ContainerPort int32
	Protocol      corev1.Protocol
	ServicePort   int32 // External port when exposed
}

// Honeypot profiles: which honeypots to deploy for each profile
var honeypotProfiles = map[string][]string{
	"minimal":  {"cowrie", "heralding"},
	"standard": {"cowrie", "dionaea", "heralding", "elasticpot", "redishoneypot"},
	"full":     {"cowrie", "dionaea", "heralding", "elasticpot", "redishoneypot", "log4pot", "wordpot", "adbhoney"},
}

// Honeypot specifications - beehivesec distroless images (docker/honeypots)
var honeypotSpecs = map[string]HoneypotSpec{
	"cowrie": {
		Name:          "cowrie",
		Image:         "beehivesec/honeypot-cowrie:latest",
		MemoryLimit:   "256Mi",
		MemoryRequest: "128Mi",
		CPULimit:      "200m",
		CPURequest:    "50m",
		LogPath:       "/cowrie/var/log/cowrie",
		RunAsUser:     1000,
		Ports: []HoneypotPort{
			{Name: "ssh", ContainerPort: 2222, Protocol: corev1.ProtocolTCP, ServicePort: 22},
			{Name: "telnet", ContainerPort: 2223, Protocol: corev1.ProtocolTCP, ServicePort: 23},
		},
	},
	"dionaea": {
		Name:          "dionaea",
		Image:         "beehivesec/honeypot-dionaea:latest",
		MemoryLimit:   "256Mi",
		MemoryRequest: "128Mi",
		CPULimit:      "300m",
		CPURequest:    "100m",
		LogPath:       "/var/log/dionaea",
		RunAsUser:     0, // dionaea needs root to create /var/dionaea and bind low ports
		Ports: []HoneypotPort{
			{Name: "ftp", ContainerPort: 21, Protocol: corev1.ProtocolTCP, ServicePort: 21},
			{Name: "http", ContainerPort: 80, Protocol: corev1.ProtocolTCP, ServicePort: 80},
			{Name: "smb", ContainerPort: 445, Protocol: corev1.ProtocolTCP, ServicePort: 445},
			{Name: "mysql", ContainerPort: 3306, Protocol: corev1.ProtocolTCP, ServicePort: 3306},
			{Name: "memcached", ContainerPort: 11211, Protocol: corev1.ProtocolTCP, ServicePort: 11211},
		},
	},
	"heralding": {
		Name:          "heralding",
		Image:         "beehivesec/honeypot-heralding:latest",
		MemoryLimit:   "64Mi",
		MemoryRequest: "32Mi",
		CPULimit:      "100m",
		CPURequest:    "25m",
		LogPath:       "/var/log/heralding",
		RunAsUser:     1000,
		Ports: []HoneypotPort{
			{Name: "pop3", ContainerPort: 110, Protocol: corev1.ProtocolTCP, ServicePort: 110},
			{Name: "imap", ContainerPort: 143, Protocol: corev1.ProtocolTCP, ServicePort: 143},
			{Name: "vnc", ContainerPort: 5900, Protocol: corev1.ProtocolTCP, ServicePort: 5900},
			{Name: "postgresql", ContainerPort: 5432, Protocol: corev1.ProtocolTCP, ServicePort: 5432},
		},
	},
	"elasticpot": {
		Name:          "elasticpot",
		Image:         "beehivesec/honeypot-elasticpot:latest",
		MemoryLimit:   "64Mi",
		MemoryRequest: "32Mi",
		CPULimit:      "100m",
		CPURequest:    "25m",
		LogPath:       "/opt/elasticpot/log",
		RunAsUser:     1000,
		EnvVars: []corev1.EnvVar{
			{Name: "ELASTICPOT_JSON_LOG", Value: "/opt/elasticpot/log/elasticpot.json"},
		},
		Ports: []HoneypotPort{
			{Name: "elasticsearch", ContainerPort: 9200, Protocol: corev1.ProtocolTCP, ServicePort: 9200},
		},
	},
	"redishoneypot": {
		Name:          "redishoneypot",
		Image:         "beehivesec/honeypot-redis:latest",
		MemoryLimit:   "64Mi",
		MemoryRequest: "32Mi",
		CPULimit:      "100m",
		CPURequest:    "25m",
		LogPath:       "/var/log/redishoneypot",
		RunAsUser:     1000,
		Ports: []HoneypotPort{
			{Name: "redis", ContainerPort: 6379, Protocol: corev1.ProtocolTCP, ServicePort: 6379},
		},
	},
	"log4pot": {
		Name:          "log4pot",
		Image:         "ghcr.io/thomaspatzke/log4pot:latest",
		MemoryLimit:   "128Mi",
		MemoryRequest: "64Mi",
		CPULimit:      "200m",
		CPURequest:    "50m",
		LogPath:       "/var/log/log4pot",
		RunAsUser:     1000,
		Ports: []HoneypotPort{
			{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP, ServicePort: 8080},
			{Name: "https", ContainerPort: 8443, Protocol: corev1.ProtocolTCP, ServicePort: 8443},
		},
	},
	"wordpot": {
		Name:          "wordpot",
		Image:         "gbrindisi/wordpot:latest",
		MemoryLimit:   "64Mi",
		MemoryRequest: "32Mi",
		CPULimit:      "100m",
		CPURequest:    "25m",
		LogPath:       "/opt/wordpot/logs",
		RunAsUser:     1000,
		Ports: []HoneypotPort{
			{Name: "http", ContainerPort: 80, Protocol: corev1.ProtocolTCP, ServicePort: 80},
		},
	},
	"adbhoney": {
		Name:          "adbhoney",
		Image:         "huuck/adbhoney:latest",
		MemoryLimit:   "64Mi",
		MemoryRequest: "32Mi",
		CPULimit:      "100m",
		CPURequest:    "25m",
		LogPath:       "/opt/adbhoney/log",
		RunAsUser:     1000,
		Ports: []HoneypotPort{
			{Name: "adb", ContainerPort: 5555, Protocol: corev1.ProtocolTCP, ServicePort: 5555},
		},
	},
}

// heraldingConfigYAML is the Heralding config with hash_cracker disabled (required in newer versions)
// Format must match upstream: activity_logging.file dict, protocol_specific_data for TLS caps
const heraldingConfigYAML = `bind_host: 0.0.0.0

activity_logging:
  file:
    enabled: true
    session_csv_log_file: "/var/log/heralding/log_session.csv"
    session_json_log_file: "/var/log/heralding/log_session.json"
    authentication_log_file: "/var/log/heralding/log_auth.csv"
  syslog:
    enabled: false
  hpfeeds:
    enabled: false

hash_cracker:
  enabled: false

capabilities:
  ftp:
    enabled: true
    port: 21
    timeout: 30
    protocol_specific_data:
      max_attempts: 3
      banner: "Microsoft FTP Server"
  telnet:
    enabled: true
    port: 23
    timeout: 30
    protocol_specific_data:
      max_attempts: 3
  pop3:
    enabled: true
    port: 110
    timeout: 30
    protocol_specific_data:
      max_attempts: 3
      banner: "+OK POP3 server ready"
  pop3s:
    enabled: true
    port: 995
    timeout: 30
    protocol_specific_data:
      max_attempts: 3
      banner: "+OK POP3 server ready"
      cert:
        common_name: "*"
        country: "US"
        state: "US"
        locality: "."
        organization: "."
        organizational_unit: "."
        valid_days: 365
        serial_number: 0
  postgresql:
    enabled: true
    port: 5432
    timeout: 30
  imap:
    enabled: true
    port: 143
    timeout: 30
    protocol_specific_data:
      max_attempts: 3
      banner: "* OK IMAP4rev1 Server Ready"
  imaps:
    enabled: true
    port: 993
    timeout: 30
    protocol_specific_data:
      max_attempts: 3
      banner: "* OK IMAP4rev1 Server Ready"
      cert:
        common_name: "*"
        country: "US"
        state: "US"
        locality: "."
        organization: "."
        organizational_unit: "."
        valid_days: 365
        serial_number: 0
  ssh:
    enabled: true
    port: 2222
    timeout: 30
    protocol_specific_data:
      banner: "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.8"
  http:
    enabled: true
    port: 80
    timeout: 30
    protocol_specific_data:
      banner: ""
  https:
    enabled: true
    port: 443
    timeout: 30
    protocol_specific_data:
      banner: ""
      cert:
        common_name: "*"
        country: "US"
        state: "US"
        locality: "."
        organization: "."
        organizational_unit: "."
        valid_days: 365
        serial_number: 0
  smtp:
    enabled: true
    port: 25
    timeout: 30
    protocol_specific_data:
      banner: "Microsoft ESMTP MAIL service ready"
      fqdn: ""
  vnc:
    enabled: true
    port: 5900
    timeout: 30
  mysql:
    enabled: true
    port: 3306
    timeout: 30
  rdp:
    enabled: true
    port: 3389
    timeout: 30
    protocol_specific_data:
      banner: ""
      cert:
        common_name: "*"
        country: "US"
        state: "US"
        locality: "."
        organization: "."
        organizational_unit: "."
        valid_days: 365
        serial_number: 0
  socks5:
    enabled: true
    port: 1080
    timeout: 30
`

// honeypotReconcileLoop periodically reconciles honeypot deployments
func (a *PrysmAgent) honeypotReconcileLoop(ctx context.Context) {
	// Check if honeypots are enabled via env var (can be overridden by backend config)
	if strings.ToLower(os.Getenv(honeypotEnabledEnvKey)) == "false" {
		log.Println("honeypot-controller: disabled via HONEYPOT_ENABLED=false")
		return
	}

	interval := 2 * time.Minute
	if d := os.Getenv(honeypotReconcileEnvKey); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
			interval = parsed
		}
	}

	// Initial reconcile
	a.reconcileHoneypots(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.reconcileHoneypots(ctx)
		}
	}
}

// reconcileHoneypots fetches config from backend and ensures honeypots match desired state
func (a *PrysmAgent) reconcileHoneypots(ctx context.Context) {
	if a.clientset == nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	// Fetch config from backend
	config, err := a.fetchHoneypotConfig(ctx)
	if err != nil {
		log.Printf("honeypot-controller: failed to fetch config: %v", err)
		// Use local env-based config as fallback
		config = a.getLocalHoneypotConfig()
	}

	if !config.Enabled {
		a.deleteAllHoneypots(ctx)
		return
	}

	// Ensure namespace exists
	if err := a.ensureHoneypotNamespace(ctx); err != nil {
		log.Printf("honeypot-controller: failed to ensure namespace: %v", err)
		return
	}

	// Ensure RBAC for honeypot management
	if err := a.ensureHoneypotRBAC(ctx); err != nil {
		log.Printf("honeypot-controller: failed to ensure RBAC: %v", err)
		// Continue anyway - RBAC might already exist from Helm chart
	}

	// Ensure network policies for honeypot isolation
	if err := a.ensureHoneypotNetworkPolicies(ctx); err != nil {
		log.Printf("honeypot-controller: failed to ensure network policies: %v", err)
		// Continue anyway - honeypots can still work without network policies
	}

	// Ensure Fluent Bit config for log forwarding
	if err := a.ensureFluentBitConfig(ctx); err != nil {
		log.Printf("honeypot-controller: failed to ensure fluent-bit config: %v", err)
		return
	}

	// Ensure credentials secret
	if err := a.ensureHoneypotSecret(ctx); err != nil {
		log.Printf("honeypot-controller: failed to ensure secret: %v", err)
		return
	}

	// Determine which honeypots to deploy
	desiredHoneypots := a.resolveHoneypotList(config)

	// Get currently deployed honeypots
	currentHoneypots, err := a.listDeployedHoneypots(ctx)
	if err != nil {
		log.Printf("honeypot-controller: failed to list current honeypots: %v", err)
		return
	}

	// Deploy missing honeypots
	for _, hp := range desiredHoneypots {
		if !contains(currentHoneypots, hp) {
			if err := a.deployHoneypot(ctx, hp, config); err != nil {
				log.Printf("honeypot-controller: failed to deploy %s: %v", hp, err)
			} else {
				log.Printf("honeypot-controller: deployed honeypot %s", hp)
			}
		}
	}

	// Remove unwanted honeypots
	for _, hp := range currentHoneypots {
		if !contains(desiredHoneypots, hp) {
			if err := a.deleteHoneypot(ctx, hp); err != nil {
				log.Printf("honeypot-controller: failed to delete %s: %v", hp, err)
			} else {
				log.Printf("honeypot-controller: removed honeypot %s", hp)
			}
		}
	}

	// Report status to backend
	a.reportHoneypotStatus(ctx, desiredHoneypots)
}

// fetchHoneypotConfig retrieves honeypot configuration from the backend
func (a *PrysmAgent) fetchHoneypotConfig(ctx context.Context) (*HoneypotConfig, error) {
	if a.BackendURL == "" || a.AgentToken == "" {
		return nil, fmt.Errorf("backend URL or agent token not configured")
	}

	url := fmt.Sprintf("%s/api/v1/agent/honeypot/config", a.BackendURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

	if resp.StatusCode == http.StatusNotFound {
		// No config set, return default disabled
		return &HoneypotConfig{Enabled: false}, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("backend returned %d: %s", resp.StatusCode, string(body))
	}

	var config HoneypotConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

// getLocalHoneypotConfig returns config from environment variables (fallback)
func (a *PrysmAgent) getLocalHoneypotConfig() *HoneypotConfig {
	enabled := strings.ToLower(os.Getenv(honeypotEnabledEnvKey)) != "false"
	profile := getEnvOrDefault("HONEYPOT_PROFILE", "minimal")
	return &HoneypotConfig{
		Enabled: enabled,
		Profile: profile,
	}
}

// resolveHoneypotList determines which honeypots to deploy based on config
func (a *PrysmAgent) resolveHoneypotList(config *HoneypotConfig) []string {
	if len(config.Honeypots) > 0 {
		// Custom list specified
		var valid []string
		for _, hp := range config.Honeypots {
			if _, ok := honeypotSpecs[hp]; ok {
				valid = append(valid, hp)
			}
		}
		return valid
	}

	// Use profile
	profile := config.Profile
	if profile == "" {
		profile = "minimal"
	}

	if honeypots, ok := honeypotProfiles[profile]; ok {
		return honeypots
	}
	return honeypotProfiles["minimal"]
}

// ensureHeraldingConfigMap creates a ConfigMap with heralding.yml including hash_cracker (required in newer Heralding)
func (a *PrysmAgent) ensureHeraldingConfigMap(ctx context.Context) error {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      heraldingConfigMapName,
			Namespace: honeypotNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "prysm-agent",
				honeypotLabelKey:               "true",
			},
		},
		Data: map[string]string{
			heraldingConfigKey: heraldingConfigYAML,
		},
	}
	_, err := a.clientset.CoreV1().ConfigMaps(honeypotNamespace).Update(ctx, cm, metav1.UpdateOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = a.clientset.CoreV1().ConfigMaps(honeypotNamespace).Create(ctx, cm, metav1.CreateOptions{})
		}
	}
	return err
}

// ensureHoneypotNamespace creates the honeypot namespace if it doesn't exist
func (a *PrysmAgent) ensureHoneypotNamespace(ctx context.Context) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: honeypotNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "prysm-agent",
				"prysm.sh/component":           "honeypots",
			},
		},
	}

	_, err := a.clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

// ensureHoneypotRBAC creates the ServiceAccount, Role, and RoleBinding for honeypots.
// This allows the honeypot pods to run with minimal privileges and ensures the agent
// has the necessary permissions to manage honeypot resources.
func (a *PrysmAgent) ensureHoneypotRBAC(ctx context.Context) error {
	labels := map[string]string{
		"app.kubernetes.io/managed-by": "prysm-agent",
		"prysm.sh/component":           "honeypots",
	}

	// 1. Create ServiceAccount for honeypot pods
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      honeypotServiceAccount,
			Namespace: honeypotNamespace,
			Labels:    labels,
		},
	}
	_, err := a.clientset.CoreV1().ServiceAccounts(honeypotNamespace).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create service account: %w", err)
	}

	// 2. Create Role with permissions needed within the honeypot namespace
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      honeypotRole,
			Namespace: honeypotNamespace,
			Labels:    labels,
		},
		Rules: []rbacv1.PolicyRule{
			{
				// Allow honeypots to read their own config
				APIGroups: []string{""},
				Resources: []string{"configmaps", "secrets"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				// Allow reading pod info for health checks
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
	_, err = a.clientset.RbacV1().Roles(honeypotNamespace).Create(ctx, role, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create role: %w", err)
	}

	// 3. Create RoleBinding to bind the role to the service account
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      honeypotRoleBinding,
			Namespace: honeypotNamespace,
			Labels:    labels,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      honeypotServiceAccount,
				Namespace: honeypotNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     honeypotRole,
		},
	}
	_, err = a.clientset.RbacV1().RoleBindings(honeypotNamespace).Create(ctx, roleBinding, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create role binding: %w", err)
	}

	// 4. Create ClusterRole for the agent to manage honeypot resources
	// This grants the agent permissions to create/manage resources in the honeypot namespace
	clusterRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   honeypotClusterRole,
			Labels: labels,
		},
		Rules: []rbacv1.PolicyRule{
			{
				// Namespace management
				APIGroups: []string{""},
				Resources: []string{"namespaces"},
				Verbs:     []string{"get", "list", "watch", "create"},
			},
			{
				// Core resources in honeypot namespace
				APIGroups: []string{""},
				Resources: []string{"pods", "services", "configmaps", "secrets", "serviceaccounts"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				// Deployments for honeypots
				APIGroups: []string{"apps"},
				Resources: []string{"deployments", "daemonsets"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				// Network policies for isolation
				APIGroups: []string{"networking.k8s.io"},
				Resources: []string{"networkpolicies"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				// RBAC for creating honeypot service accounts
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"roles", "rolebindings"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
		},
	}
	existingCR, err := a.clientset.RbacV1().ClusterRoles().Get(ctx, honeypotClusterRole, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = a.clientset.RbacV1().ClusterRoles().Create(ctx, clusterRole, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create cluster role: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get cluster role: %w", err)
		}
	} else {
		// Update existing cluster role
		existingCR.Rules = clusterRole.Rules
		_, err = a.clientset.RbacV1().ClusterRoles().Update(ctx, existingCR, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update cluster role: %w", err)
		}
	}

	// 5. Create ClusterRoleBinding to bind the cluster role to the agent's service account
	// Get the agent's namespace and service account from environment
	agentNamespace := getEnvOrDefault("POD_NAMESPACE", "prysm-system")
	agentServiceAccount := getEnvOrDefault("SERVICE_ACCOUNT", "prysm-agent")

	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   honeypotClusterRoleBinding,
			Labels: labels,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      agentServiceAccount,
				Namespace: agentNamespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     honeypotClusterRole,
		},
	}
	existingCRB, err := a.clientset.RbacV1().ClusterRoleBindings().Get(ctx, honeypotClusterRoleBinding, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = a.clientset.RbacV1().ClusterRoleBindings().Create(ctx, clusterRoleBinding, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create cluster role binding: %w", err)
			}
		} else {
			return fmt.Errorf("failed to get cluster role binding: %w", err)
		}
	} else {
		// Update existing cluster role binding
		existingCRB.Subjects = clusterRoleBinding.Subjects
		existingCRB.RoleRef = clusterRoleBinding.RoleRef
		_, err = a.clientset.RbacV1().ClusterRoleBindings().Update(ctx, existingCRB, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update cluster role binding: %w", err)
		}
	}

	log.Println("honeypot-controller: RBAC resources created/updated")
	return nil
}

// ensureHoneypotNetworkPolicies creates NetworkPolicies to isolate honeypots from production workloads.
// This prevents a compromised honeypot from being used for lateral movement.
func (a *PrysmAgent) ensureHoneypotNetworkPolicies(ctx context.Context) error {
	// Policy 1: Restrict egress to private IP ranges only (RFC1918)
	// This blocks honeypots from making outbound connections to the public internet
	// while allowing cluster-internal communication for log forwarding.
	// Note: Namespace selectors don't work reliably on all CNIs (e.g., k3s Flannel),
	// so we use ipBlock which has broader compatibility.
	restrictEgress := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "honeypot-restrict-egress",
			Namespace: honeypotNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "prysm-agent",
				"prysm.sh/component":           "network-policy",
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Apply to all pods in honeypot namespace
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				// Allow egress only to private IP ranges (RFC1918)
				// This covers typical Kubernetes pod/service CIDRs and internal networks
				{
					To: []networkingv1.NetworkPolicyPeer{
						{IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/8"}},
						{IPBlock: &networkingv1.IPBlock{CIDR: "172.16.0.0/12"}},
						{IPBlock: &networkingv1.IPBlock{CIDR: "192.168.0.0/16"}},
					},
				},
			},
		},
	}

	// Policy 2: Allow all ingress (honeypots need to accept connections from attackers)
	// but deny ingress from other namespaces in the cluster
	allowExternalIngress := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "honeypot-allow-external-ingress",
			Namespace: honeypotNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "prysm-agent",
				"prysm.sh/component":           "network-policy",
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					honeypotLabelKey: "true",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				// Allow from anywhere except cluster-internal namespaces
				// By not specifying 'from', we allow all external traffic
				// Additional policy below will block internal cluster traffic
				{},
			},
		},
	}

	// Policy 3: Deny ingress from other namespaces (prevent production pods from talking to honeypots)
	denyInternalIngress := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "honeypot-deny-internal-ingress",
			Namespace: honeypotNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "prysm-agent",
				"prysm.sh/component":           "network-policy",
			},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					honeypotLabelKey: "true",
				},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				// Only allow from within the honeypot namespace (fluent-bit sidecar communication)
				// and from external sources (no namespace selector = external)
				{
					From: []networkingv1.NetworkPolicyPeer{
						// Allow from same namespace (honeypots can talk to each other)
						{
							PodSelector: &metav1.LabelSelector{},
						},
					},
				},
			},
		},
	}

	// Apply all policies
	policies := []*networkingv1.NetworkPolicy{restrictEgress, allowExternalIngress, denyInternalIngress}
	for _, policy := range policies {
		existing, err := a.clientset.NetworkingV1().NetworkPolicies(honeypotNamespace).Get(ctx, policy.Name, metav1.GetOptions{})
		if err != nil {
			if errors.IsNotFound(err) {
				_, err = a.clientset.NetworkingV1().NetworkPolicies(honeypotNamespace).Create(ctx, policy, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("failed to create network policy %s: %w", policy.Name, err)
				}
				log.Printf("honeypot-controller: created network policy %s", policy.Name)
			} else {
				return fmt.Errorf("failed to get network policy %s: %w", policy.Name, err)
			}
		} else {
			// Update existing policy
			existing.Spec = policy.Spec
			_, err = a.clientset.NetworkingV1().NetworkPolicies(honeypotNamespace).Update(ctx, existing, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("failed to update network policy %s: %w", policy.Name, err)
			}
		}
	}

	return nil
}

// protocolPtr returns a pointer to a Protocol value
func protocolPtr(p corev1.Protocol) *corev1.Protocol {
	return &p
}

// getHoneypotImagePullSecrets returns ImagePullSecrets when HONEYPOT_IMAGE_PULL_SECRET is set.
func (a *PrysmAgent) getHoneypotImagePullSecrets() []corev1.LocalObjectReference {
	name := strings.TrimSpace(os.Getenv(honeypotImagePullSecretsKey))
	if name == "" {
		return nil
	}
	return []corev1.LocalObjectReference{{Name: name}}
}

// resolveHoneypotImage applies HONEYPOT_IMAGE_REGISTRY override for beehivesec images.
// When set, "beehivesec/honeypot-X:tag" becomes "registry/honeypot-X:tag" for self-hosted/air-gapped clusters.
func resolveHoneypotImage(image string) string {
	registry := strings.TrimSpace(os.Getenv(honeypotImageRegistryEnvKey))
	if registry == "" {
		return image
	}
	if strings.HasPrefix(image, "beehivesec/") {
		return registry + "/" + strings.TrimPrefix(image, "beehivesec/")
	}
	return image
}

// portPtr returns a pointer to an IntOrString port value
func portPtr(port int) *intstr.IntOrString {
	p := intstr.FromInt(port)
	return &p
}

// ensureHoneypotSecret creates/updates the secret with agent credentials
func (a *PrysmAgent) ensureHoneypotSecret(ctx context.Context) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      honeypotSecretName,
			Namespace: honeypotNamespace,
		},
		Data: map[string][]byte{
			"agent-token":     []byte(a.AgentToken),
			"cluster-id":      []byte(a.ClusterID),
			"organization-id": []byte(fmt.Sprintf("%d", a.OrganizationID)),
		},
	}

	_, err := a.clientset.CoreV1().Secrets(honeypotNamespace).Update(ctx, secret, metav1.UpdateOptions{})
	if errors.IsNotFound(err) {
		_, err = a.clientset.CoreV1().Secrets(honeypotNamespace).Create(ctx, secret, metav1.CreateOptions{})
	}
	return err
}

// ensureFluentBitConfig creates the Fluent Bit ConfigMap for honeypot log forwarding
func (a *PrysmAgent) ensureFluentBitConfig(ctx context.Context) error {
	// Get agent service name from environment, with smart default
	agentNamespace := getEnvOrDefault("POD_NAMESPACE", "prysm-system")
	agentServiceName := getEnvOrDefault("AGENT_SERVICE_NAME", "")
	if agentServiceName == "" {
		// Try to detect from Helm release name or use default
		helmRelease := os.Getenv("HELM_RELEASE_NAME")
		if helmRelease != "" {
			agentServiceName = helmRelease
		} else {
			agentServiceName = "prysm-agent"
		}
	}
	agentHost := fmt.Sprintf("%s.%s.svc.cluster.local", agentServiceName, agentNamespace)
	// Use AGENT_SERVICE_PORT (service port) not AGENT_HTTP_PORT (pod targetPort) when connecting via service DNS
	agentPort := getEnvOrDefault("AGENT_SERVICE_PORT", "8080")

	fluentBitConf := fmt.Sprintf(`[SERVICE]
    Flush         1
    Daemon        Off
    Log_Level     info
    Parsers_File  /fluent-bit/etc/parsers.conf
    HTTP_Server   On
    HTTP_Listen   0.0.0.0
    HTTP_Port     2020

[INPUT]
    Name          tail
    Path          /var/log/honeypot/*.json,/var/log/honeypot/*.log,/var/log/honeypot/*.csv
    Tag           honeypot.*
    Read_from_Head On
    Refresh_Interval 5
    Mem_Buf_Limit 5MB
    Skip_Long_Lines On
    DB            /tmp/flb_honeypot.db

[FILTER]
    Name          record_modifier
    Match         honeypot.*
    Record        source honeypot
    Record        cluster_id ${CLUSTER_ID}
    Record        organization_id ${ORGANIZATION_ID}
    Record        honeypot_type ${HONEYPOT_TYPE}

[OUTPUT]
    Name          http
    Match         honeypot.*
    Host          %s
    Port          %s
    URI           /api/v1/logs/ingest/honeypot
    Format        json
    Json_date_key timestamp
    Json_date_format iso8601
    Header        X-Honeypot-Type ${HONEYPOT_TYPE}
    tls           Off
    Retry_Limit   5
`, agentHost, agentPort)

	parsersConf := `[PARSER]
    Name          json
    Format        json
    Time_Key      timestamp
    Time_Format   %Y-%m-%dT%H:%M:%S.%L

[PARSER]
    Name          cowrie
    Format        json
    Time_Key      timestamp
    Time_Format   %Y-%m-%dT%H:%M:%S.%f%z
`

	newData := map[string]string{
		"fluent-bit.conf": fluentBitConf,
		"parsers.conf":    parsersConf,
	}

	// Get existing configmap to update properly
	existing, err := a.clientset.CoreV1().ConfigMaps(honeypotNamespace).Get(ctx, fluentBitConfigName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			// Create new configmap
			cm := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fluentBitConfigName,
					Namespace: honeypotNamespace,
					Labels: map[string]string{
						"app.kubernetes.io/managed-by": "prysm-agent",
						"prysm.sh/component":           "honeypots",
					},
				},
				Data: newData,
			}
			_, err = a.clientset.CoreV1().ConfigMaps(honeypotNamespace).Create(ctx, cm, metav1.CreateOptions{})
			return err
		}
		return fmt.Errorf("failed to get fluent-bit configmap: %w", err)
	}

	// Update existing configmap
	existing.Data = newData
	_, err = a.clientset.CoreV1().ConfigMaps(honeypotNamespace).Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

// deployHoneypot creates a honeypot Deployment with Fluent Bit sidecar
func (a *PrysmAgent) deployHoneypot(ctx context.Context, name string, config *HoneypotConfig) error {
	spec, ok := honeypotSpecs[name]
	if !ok {
		return fmt.Errorf("unknown honeypot: %s", name)
	}

	deploymentName := fmt.Sprintf("prysm-honeypot-%s", name)
	labels := map[string]string{
		"app.kubernetes.io/name":       deploymentName,
		"app.kubernetes.io/component":  "honeypot",
		"app.kubernetes.io/managed-by": "prysm-agent",
		honeypotLabelKey:               "true",
		honeypotTypeLabelKey:           name,
	}

	replicas := int32(1)
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Namespace: honeypotNamespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Annotations: map[string]string{
						"prysm.sh/honeypot-type": name,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: honeypotServiceAccount,
					ImagePullSecrets:   a.getHoneypotImagePullSecrets(),
					Containers: []corev1.Container{
						a.buildHoneypotContainer(spec),
						a.buildFluentBitSidecar(name),
					},
					Volumes: []corev1.Volume{
						{
							Name: "honeypot-logs",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
						{
							Name: "fluent-bit-config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: fluentBitConfigName},
								},
							},
						},
					},
					// Allow scheduling on any node
					Tolerations: []corev1.Toleration{
						{Operator: corev1.TolerationOpExists},
					},
				},
			},
		},
	}

	// Heralding requires a ConfigMap with hash_cracker config (newer versions need this key)
	if name == "heralding" {
		if err := a.ensureHeraldingConfigMap(ctx); err != nil {
			return fmt.Errorf("ensure heralding config: %w", err)
		}
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: "heralding-config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: heraldingConfigMapName},
				},
			},
		})
		// Add config mount to heralding container (first container)
		deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(
			deployment.Spec.Template.Spec.Containers[0].VolumeMounts,
			corev1.VolumeMount{
				Name:      "heralding-config",
				MountPath: heraldingConfigMountPath,
				SubPath:   heraldingConfigKey,
				ReadOnly:  true,
			},
		)
		// Config mount overrides /app/heralding.yml; image ENTRYPOINT uses it by default
	}

	// Apply node selector if specified
	if len(config.NodeSelector) > 0 {
		deployment.Spec.Template.Spec.NodeSelector = config.NodeSelector
	}

	// Create or update deployment
	existing, err := a.clientset.AppsV1().Deployments(honeypotNamespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = a.clientset.AppsV1().Deployments(honeypotNamespace).Create(ctx, deployment, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		// Update existing
		existing.Spec = deployment.Spec
		_, err = a.clientset.AppsV1().Deployments(honeypotNamespace).Update(ctx, existing, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	// Create Service for the honeypot
	return a.ensureHoneypotService(ctx, name, spec, config)
}

// buildHoneypotContainer creates the honeypot container spec
func (a *PrysmAgent) buildHoneypotContainer(spec HoneypotSpec) corev1.Container {
	var ports []corev1.ContainerPort
	for _, p := range spec.Ports {
		ports = append(ports, corev1.ContainerPort{
			Name:          p.Name,
			ContainerPort: p.ContainerPort,
			Protocol:      p.Protocol,
		})
	}

	container := corev1.Container{
		Name:            spec.Name,
		Image:           resolveHoneypotImage(spec.Image),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Ports: ports,
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse(spec.MemoryLimit),
				corev1.ResourceCPU:    resource.MustParse(spec.CPULimit),
			},
			Requests: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse(spec.MemoryRequest),
				corev1.ResourceCPU:    resource.MustParse(spec.CPURequest),
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "honeypot-logs",
				MountPath: spec.LogPath,
			},
		},
		Env: append(spec.EnvVars, corev1.EnvVar{
			Name:  "HONEYPOT_TYPE",
			Value: spec.Name,
		}),
		SecurityContext: &corev1.SecurityContext{
			RunAsUser:    &spec.RunAsUser,
			RunAsNonRoot: ptr(spec.RunAsUser != 0),
		},
	}

	if len(spec.Command) > 0 {
		container.Command = spec.Command
	}
	if len(spec.Args) > 0 {
		container.Args = spec.Args
	}

	return container
}

// buildFluentBitSidecar creates the Fluent Bit sidecar container for log forwarding
func (a *PrysmAgent) buildFluentBitSidecar(honeypotType string) corev1.Container {
	return corev1.Container{
		Name:  "fluent-bit",
		Image: "fluent/fluent-bit:3.2",
		Resources: corev1.ResourceRequirements{
			Limits: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("64Mi"),
				corev1.ResourceCPU:    resource.MustParse("50m"),
			},
			Requests: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("32Mi"),
				corev1.ResourceCPU:    resource.MustParse("10m"),
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "honeypot-logs",
				MountPath: "/var/log/honeypot",
				ReadOnly:  true,
			},
			{
				Name:      "fluent-bit-config",
				MountPath: "/fluent-bit/etc",
			},
		},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: "/api/v1/health",
					Port: intstr.FromInt(2020),
				},
			},
			InitialDelaySeconds: 15,
			PeriodSeconds:       30,
			FailureThreshold:    5,
		},
		Env: []corev1.EnvVar{
			{Name: "HONEYPOT_TYPE", Value: honeypotType},
			{
				Name: "CLUSTER_ID",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: honeypotSecretName},
						Key:                  "cluster-id",
					},
				},
			},
			{
				Name: "ORGANIZATION_ID",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: honeypotSecretName},
						Key:                  "organization-id",
					},
				},
			},
			{
				Name: "PRYSM_AGENT_TOKEN",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{Name: honeypotSecretName},
						Key:                  "agent-token",
					},
				},
			},
		},
	}
}

// ensureHoneypotService creates a ClusterIP or NodePort service for the honeypot
func (a *PrysmAgent) ensureHoneypotService(ctx context.Context, name string, spec HoneypotSpec, config *HoneypotConfig) error {
	serviceName := fmt.Sprintf("prysm-honeypot-%s", name)
	labels := map[string]string{
		"app.kubernetes.io/name":      serviceName,
		"app.kubernetes.io/component": "honeypot",
		honeypotLabelKey:              "true",
		honeypotTypeLabelKey:          name,
	}

	var ports []corev1.ServicePort
	for _, p := range spec.Ports {
		sp := corev1.ServicePort{
			Name:       p.Name,
			Port:       p.ServicePort,
			TargetPort: intstr.FromInt(int(p.ContainerPort)),
			Protocol:   p.Protocol,
		}
		// Add NodePort if external exposure is enabled
		if config.ExposeExternal {
			if np, ok := config.NodePorts[fmt.Sprintf("%s-%s", name, p.Name)]; ok {
				sp.NodePort = np
			}
		}
		ports = append(ports, sp)
	}

	serviceType := corev1.ServiceTypeClusterIP
	if config.ExposeExternal {
		serviceType = corev1.ServiceTypeNodePort
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: honeypotNamespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name": fmt.Sprintf("prysm-honeypot-%s", name),
			},
			Ports: ports,
			Type:  serviceType,
		},
	}

	existing, err := a.clientset.CoreV1().Services(honeypotNamespace).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			_, err = a.clientset.CoreV1().Services(honeypotNamespace).Create(ctx, svc, metav1.CreateOptions{})
			return err
		}
		return err
	}

	// Update existing service
	existing.Spec.Ports = svc.Spec.Ports
	existing.Spec.Type = svc.Spec.Type
	_, err = a.clientset.CoreV1().Services(honeypotNamespace).Update(ctx, existing, metav1.UpdateOptions{})
	return err
}

// listDeployedHoneypots returns the names of currently deployed honeypots
func (a *PrysmAgent) listDeployedHoneypots(ctx context.Context) ([]string, error) {
	deployments, err := a.clientset.AppsV1().Deployments(honeypotNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: honeypotLabelKey + "=true",
	})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	var names []string
	for _, d := range deployments.Items {
		if hpType, ok := d.Labels[honeypotTypeLabelKey]; ok {
			names = append(names, hpType)
		}
	}
	return names, nil
}

// deleteHoneypot removes a honeypot deployment and service
func (a *PrysmAgent) deleteHoneypot(ctx context.Context, name string) error {
	deploymentName := fmt.Sprintf("prysm-honeypot-%s", name)
	serviceName := deploymentName

	// Delete deployment
	err := a.clientset.AppsV1().Deployments(honeypotNamespace).Delete(ctx, deploymentName, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	// Delete service
	err = a.clientset.CoreV1().Services(honeypotNamespace).Delete(ctx, serviceName, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		return err
	}

	return nil
}

// deleteAllHoneypots removes all honeypot resources
func (a *PrysmAgent) deleteAllHoneypots(ctx context.Context) {
	if a.clientset == nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Delete all deployments with honeypot label
	deployments, err := a.clientset.AppsV1().Deployments(honeypotNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: honeypotLabelKey + "=true",
	})
	if err == nil {
		for _, d := range deployments.Items {
			_ = a.clientset.AppsV1().Deployments(honeypotNamespace).Delete(ctx, d.Name, metav1.DeleteOptions{})
		}
	}

	// Delete all services with honeypot label
	services, err := a.clientset.CoreV1().Services(honeypotNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: honeypotLabelKey + "=true",
	})
	if err == nil {
		for _, s := range services.Items {
			_ = a.clientset.CoreV1().Services(honeypotNamespace).Delete(ctx, s.Name, metav1.DeleteOptions{})
		}
	}

	// Delete ConfigMap and Secret
	_ = a.clientset.CoreV1().ConfigMaps(honeypotNamespace).Delete(ctx, fluentBitConfigName, metav1.DeleteOptions{})
	_ = a.clientset.CoreV1().Secrets(honeypotNamespace).Delete(ctx, honeypotSecretName, metav1.DeleteOptions{})

	// Delete all network policies
	networkPolicies, err := a.clientset.NetworkingV1().NetworkPolicies(honeypotNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: "prysm.sh/component=network-policy",
	})
	if err == nil {
		for _, np := range networkPolicies.Items {
			_ = a.clientset.NetworkingV1().NetworkPolicies(honeypotNamespace).Delete(ctx, np.Name, metav1.DeleteOptions{})
		}
	}

	// Delete RBAC resources in namespace
	_ = a.clientset.RbacV1().RoleBindings(honeypotNamespace).Delete(ctx, honeypotRoleBinding, metav1.DeleteOptions{})
	_ = a.clientset.RbacV1().Roles(honeypotNamespace).Delete(ctx, honeypotRole, metav1.DeleteOptions{})
	_ = a.clientset.CoreV1().ServiceAccounts(honeypotNamespace).Delete(ctx, honeypotServiceAccount, metav1.DeleteOptions{})

	// Note: We don't delete ClusterRole/ClusterRoleBinding as they may be needed for re-deployment
	// and deleting them could affect agent permissions

	log.Println("honeypot-controller: removed all honeypot resources")
}

// reportHoneypotStatus sends honeypot deployment status to the backend
func (a *PrysmAgent) reportHoneypotStatus(ctx context.Context, deployedHoneypots []string) {
	if a.BackendURL == "" || a.AgentToken == "" {
		return
	}

	status := map[string]interface{}{
		"cluster_id":          a.ClusterID,
		"deployed_honeypots":  deployedHoneypots,
		"namespace":           honeypotNamespace,
		"last_reconcile_time": time.Now().UTC().Format(time.RFC3339),
	}

	body, err := json.Marshal(status)
	if err != nil {
		return
	}

	url := fmt.Sprintf("%s/api/v1/agent/honeypot/status", a.BackendURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.AgentToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Cluster-ID", a.ClusterID)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		log.Printf("honeypot-controller: failed to report status: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("honeypot-controller: status report returned %d", resp.StatusCode)
	}
}

// Helper function - contains checks if slice contains item
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Note: ptr and isAlreadyExists are defined in k8s_sa_provision.go
