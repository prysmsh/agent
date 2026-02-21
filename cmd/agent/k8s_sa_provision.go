package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	prysmSystemNamespace = "prysm-system"
	saTokenDuration      = 10 * 365 * 24 * time.Hour // 10 years
)

// ensurePrysmK8sSAs creates the prysm-system namespace, ServiceAccounts (admin/developer/viewer),
// ClusterRoleBindings, and pushes the SA tokens to the backend for role-based proxy auth.
func (a *PrysmAgent) ensurePrysmK8sSAs(ctx context.Context) {
	if a.clientset == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: prysmSystemNamespace}}
	_, err := a.clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil && !isAlreadyExists(err) {
		log.Printf("Prysm K8s SA: failed to create namespace %s: %v", prysmSystemNamespace, err)
		return
	}

	sas := []struct {
		name string
		role string // cluster-admin, edit, view
	}{
		{"prysm-admin", "cluster-admin"},
		{"prysm-developer", "edit"},
		{"prysm-viewer", "view"},
	}

	for _, s := range sas {
		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: s.name, Namespace: prysmSystemNamespace}}
		_, err := a.clientset.CoreV1().ServiceAccounts(prysmSystemNamespace).Create(ctx, sa, metav1.CreateOptions{})
		if err != nil && !isAlreadyExists(err) {
			log.Printf("Prysm K8s SA: failed to create ServiceAccount %s: %v", s.name, err)
			continue
		}

		crb := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "prysm-" + s.name + "-binding"},
			RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: s.role},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: s.name, Namespace: prysmSystemNamespace}},
		}
		_, err = a.clientset.RbacV1().ClusterRoleBindings().Create(ctx, crb, metav1.CreateOptions{})
		if err != nil && !isAlreadyExists(err) {
			log.Printf("Prysm K8s SA: failed to create ClusterRoleBinding for %s: %v", s.name, err)
		}
	}

	// Create tokens and send to backend
	tokens := make(map[string]string)
	for _, s := range sas {
		tok, err := a.createSAToken(ctx, s.name)
		if err != nil {
			log.Printf("Prysm K8s SA: failed to create token for %s: %v", s.name, err)
			continue
		}
		switch s.name {
		case "prysm-admin":
			tokens["admin"] = tok
		case "prysm-developer":
			tokens["developer"] = tok
		case "prysm-viewer":
			tokens["viewer"] = tok
		}
	}

	if len(tokens) == 0 {
		log.Printf("Prysm K8s SA: no tokens created; proxy auth will be unavailable")
		return
	}

	if err := a.sendK8sSATokensToBackend(ctx, tokens); err != nil {
		log.Printf("Prysm K8s SA: failed to send tokens to backend: %v", err)
		return
	}
	log.Printf("Prysm K8s SA: provisioned and sent %d tokens to backend", len(tokens))
}

func (a *PrysmAgent) createSAToken(ctx context.Context, saName string) (string, error) {
	audiences := []string{
		"kubernetes.default.svc",
		"https://kubernetes.default.svc",
		"kubernetes.default.svc.cluster.local",
		"https://kubernetes.default.svc.cluster.local",
	}
	tr := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences:         audiences,
			ExpirationSeconds: ptr(int64(saTokenDuration.Seconds())),
		},
	}
	resp, err := a.clientset.CoreV1().ServiceAccounts(prysmSystemNamespace).CreateToken(ctx, saName, tr, metav1.CreateOptions{})
	if err != nil {
		return "", err
	}
	return resp.Status.Token, nil
}

func (a *PrysmAgent) sendK8sSATokensToBackend(ctx context.Context, tokens map[string]string) error {
	payload, err := json.Marshal(tokens)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/api/v1/clusters/%s/k8s-sa-tokens", strings.TrimSuffix(a.BackendURL, "/"), a.ClusterID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", a.AgentToken)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("backend returned %d", resp.StatusCode)
	}
	return nil
}

func isAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "AlreadyExists") || strings.Contains(err.Error(), "already exists")
}

func ptr[T any](v T) *T { return &v }
