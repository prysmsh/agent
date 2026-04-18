package main

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	agentClusterRoleName = "prysm-agent"
	inClusterNSPath      = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// desiredAgentRules returns the full set of RBAC PolicyRules the agent needs.
// This mirrors the Helm chart's clusterrole.yaml.
func desiredAgentRules() []rbacv1.PolicyRule {
	return []rbacv1.PolicyRule{
		// Core API
		{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch", "create", "delete"}},
		{APIGroups: []string{""}, Resources: []string{"nodes"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{""}, Resources: []string{"namespaces"}, Verbs: []string{"get", "list", "watch", "create"}},
		{APIGroups: []string{""}, Resources: []string{"services"}, Verbs: []string{"get", "list", "watch", "create", "update", "delete"}},
		{APIGroups: []string{""}, Resources: []string{"endpoints"}, Verbs: []string{"get", "list", "create", "update", "delete", "watch"}},
		{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create", "update", "delete"}},
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list", "watch", "create", "update", "delete"}},
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, Verbs: []string{"create", "delete"}},
		{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, Verbs: []string{"create"}},
		{APIGroups: []string{""}, Resources: []string{"events"}, Verbs: []string{"list", "watch"}},
		// Apps API
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list", "watch", "create", "update", "delete"}},
		{APIGroups: []string{"apps"}, Resources: []string{"daemonsets"}, Verbs: []string{"get", "list", "watch", "create", "update", "delete"}},
		{APIGroups: []string{"apps"}, Resources: []string{"replicasets"}, Verbs: []string{"get", "list", "watch"}},
		{APIGroups: []string{"apps"}, Resources: []string{"statefulsets"}, Verbs: []string{"get", "list", "watch"}},
		// RBAC
		{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}, Verbs: []string{"get", "list", "watch", "create", "update"}},
		{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterrolebindings"}, Verbs: []string{"get", "list", "watch", "create", "update"}},
		{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"roles"}, Verbs: []string{"get", "list", "watch", "create", "delete"}},
		{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"rolebindings"}, Verbs: []string{"get", "list", "watch", "create", "delete"}},
		// Networking
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"networkpolicies"}, Verbs: []string{"get", "list", "watch", "create", "update", "delete"}},
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"get", "list", "watch"}},
		// Autoscaling
		{APIGroups: []string{"autoscaling"}, Resources: []string{"horizontalpodautoscalers"}, Verbs: []string{"get", "list", "watch"}},
		// Metrics API
		{APIGroups: []string{"metrics.k8s.io"}, Resources: []string{"nodes", "pods"}, Verbs: []string{"get", "list", "watch"}},
	}
}

// ensureAgentRBAC reconciles the agent's own ClusterRole and ClusterRoleBinding
// so that permissions stay up-to-date even if the Helm chart wasn't re-applied.
func (a *PrysmAgent) ensureAgentRBAC(ctx context.Context) {
	if a.clientset == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	saName, saNamespace := detectServiceAccount()
	if saName == "" || saNamespace == "" {
		log.Printf("RBAC reconcile: could not detect agent service account, skipping")
		return
	}

	rules := desiredAgentRules()

	// Reconcile ClusterRole: Get + Update, or Create
	existing, err := a.clientset.RbacV1().ClusterRoles().Get(ctx, agentClusterRoleName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		cr := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:   agentClusterRoleName,
				Labels: map[string]string{"app.kubernetes.io/managed-by": "prysm-agent"},
			},
			Rules: rules,
		}
		if _, err := a.clientset.RbacV1().ClusterRoles().Create(ctx, cr, metav1.CreateOptions{}); err != nil {
			log.Printf("RBAC reconcile: failed to create ClusterRole %s: %v", agentClusterRoleName, err)
			return
		}
		log.Printf("RBAC reconcile: created ClusterRole %s", agentClusterRoleName)
	} else if err != nil {
		log.Printf("RBAC reconcile: failed to get ClusterRole %s: %v", agentClusterRoleName, err)
		return
	} else {
		// Update rules to match desired state
		existing.Rules = rules
		if _, err := a.clientset.RbacV1().ClusterRoles().Update(ctx, existing, metav1.UpdateOptions{}); err != nil {
			log.Printf("RBAC reconcile: failed to update ClusterRole %s: %v", agentClusterRoleName, err)
			return
		}
		log.Printf("RBAC reconcile: updated ClusterRole %s", agentClusterRoleName)
	}

	// Reconcile ClusterRoleBinding
	bindingName := agentClusterRoleName
	existingBinding, err := a.clientset.RbacV1().ClusterRoleBindings().Get(ctx, bindingName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		crb := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   bindingName,
				Labels: map[string]string{"app.kubernetes.io/managed-by": "prysm-agent"},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     agentClusterRoleName,
			},
			Subjects: []rbacv1.Subject{{
				Kind:      "ServiceAccount",
				Name:      saName,
				Namespace: saNamespace,
			}},
		}
		if _, err := a.clientset.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{}); err != nil {
			log.Printf("RBAC reconcile: failed to create ClusterRoleBinding %s: %v", bindingName, err)
			return
		}
		log.Printf("RBAC reconcile: created ClusterRoleBinding %s (SA=%s/%s)", bindingName, saNamespace, saName)
	} else if err != nil {
		log.Printf("RBAC reconcile: failed to get ClusterRoleBinding %s: %v", bindingName, err)
		return
	} else {
		// Ensure the binding points to the correct SA and role
		existingBinding.RoleRef = rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     agentClusterRoleName,
		}
		existingBinding.Subjects = []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      saName,
			Namespace: saNamespace,
		}}
		if _, err := a.clientset.RbacV1().ClusterRoleBindings().Update(ctx, existingBinding, metav1.UpdateOptions{}); err != nil {
			log.Printf("RBAC reconcile: failed to update ClusterRoleBinding %s: %v", bindingName, err)
			return
		}
		log.Printf("RBAC reconcile: updated ClusterRoleBinding %s (SA=%s/%s)", bindingName, saNamespace, saName)
	}
}

// detectServiceAccount returns the agent's service account name and namespace
// by reading the in-cluster token path and POD_SERVICE_ACCOUNT / HOSTNAME env vars.
func detectServiceAccount() (name, namespace string) {
	// Namespace: read from the downward API / mounted token
	if data, err := os.ReadFile(inClusterNSPath); err == nil {
		namespace = strings.TrimSpace(string(data))
	}
	if namespace == "" {
		namespace = os.Getenv("POD_NAMESPACE")
	}

	// SA name: prefer explicit env, otherwise use the well-known default
	name = os.Getenv("POD_SERVICE_ACCOUNT")
	if name == "" {
		// The Helm chart defaults to "prysm-agent" as the SA name
		name = agentClusterRoleName
	}

	return name, namespace
}
