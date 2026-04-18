package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const ccrClusterRoleName = "prysm-agent-crd"

// ensureCRDRBAC creates or updates the ClusterRole and ClusterRoleBinding
// that grant the agent permission to manage route/tunnel CRDs and instances.
// This is separate from the main agent ClusterRole because the agent cannot
// self-escalate to add these permissions to its own role.
func ensureCRDRBAC(ctx context.Context, cs kubernetes.Interface) error {
	tCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	saName, saNamespace := detectServiceAccount()
	if saName == "" || saNamespace == "" {
		saName = "prysm-agent"
		saNamespace = ccRouteAgentNamespace()
	}

	rules := []rbacv1.PolicyRule{
		// create+list are unrestrictable by resourceNames (K8s limitation for create)
		{APIGroups: []string{"apiextensions.k8s.io"}, Resources: []string{"customresourcedefinitions"}, Verbs: []string{"create", "list"}},
		// get+update locked to only the prysm-owned CRDs
		{APIGroups: []string{"apiextensions.k8s.io"}, Resources: []string{"customresourcedefinitions"},
			ResourceNames: []string{"crossclusterroutes.prysm.sh", "clustertunnels.prysm.sh", "meshroutes.prysm.sh"},
			Verbs:         []string{"get", "update"}},
		{APIGroups: []string{"prysm.sh"}, Resources: []string{"crossclusterroutes"}, Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"}},
		{APIGroups: []string{"prysm.sh"}, Resources: []string{"crossclusterroutes/status"}, Verbs: []string{"get", "update", "patch"}},
		{APIGroups: []string{"prysm.sh"}, Resources: []string{"clustertunnels"}, Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"}},
		{APIGroups: []string{"prysm.sh"}, Resources: []string{"clustertunnels/status"}, Verbs: []string{"get", "update", "patch"}},
		{APIGroups: []string{"prysm.sh"}, Resources: []string{"meshroutes"}, Verbs: []string{"get", "list", "watch", "create", "update", "patch", "delete"}},
		{APIGroups: []string{"prysm.sh"}, Resources: []string{"meshroutes/status"}, Verbs: []string{"get", "update", "patch"}},
	}

	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:   ccrClusterRoleName,
			Labels: map[string]string{"app.kubernetes.io/managed-by": "prysm-agent"},
		},
		Rules: rules,
	}

	existing, err := cs.RbacV1().ClusterRoles().Get(tCtx, ccrClusterRoleName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, err := cs.RbacV1().ClusterRoles().Create(tCtx, cr, metav1.CreateOptions{}); err != nil {
			return err
		}
		log.Printf("ccr-crd: created ClusterRole %s", ccrClusterRoleName)
	} else if err != nil {
		return err
	} else {
		existing.Rules = rules
		if _, err := cs.RbacV1().ClusterRoles().Update(tCtx, existing, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}

	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   ccrClusterRoleName,
			Labels: map[string]string{"app.kubernetes.io/managed-by": "prysm-agent"},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     ccrClusterRoleName,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      "ServiceAccount",
			Name:      saName,
			Namespace: saNamespace,
		}},
	}

	existingBinding, err := cs.RbacV1().ClusterRoleBindings().Get(tCtx, ccrClusterRoleName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, err := cs.RbacV1().ClusterRoleBindings().Create(tCtx, crb, metav1.CreateOptions{}); err != nil {
			return err
		}
		log.Printf("ccr-crd: created ClusterRoleBinding %s", ccrClusterRoleName)
	} else if err != nil {
		return err
	} else {
		existingBinding.RoleRef = crb.RoleRef
		existingBinding.Subjects = crb.Subjects
		if _, err := cs.RbacV1().ClusterRoleBindings().Update(tCtx, existingBinding, metav1.UpdateOptions{}); err != nil {
			return err
		}
	}

	return nil
}

// ensureCRD creates or updates the CrossClusterRoute CRD in the cluster.
func ensureCRD(ctx context.Context, restCfg *rest.Config) error {
	client, err := apiextclient.NewForConfig(restCfg)
	if err != nil {
		return err
	}

	crd := buildCCRCRD()

	tCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	existing, err := client.ApiextensionsV1().CustomResourceDefinitions().Get(tCtx, crd.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, err := client.ApiextensionsV1().CustomResourceDefinitions().Create(tCtx, crd, metav1.CreateOptions{}); err != nil {
			return err
		}
		log.Printf("ccr-crd: created CRD %s", crd.Name)
		return nil
	}
	if err != nil {
		return err
	}

	// Update: preserve resourceVersion
	crd.ResourceVersion = existing.ResourceVersion
	if _, err := client.ApiextensionsV1().CustomResourceDefinitions().Update(tCtx, crd, metav1.UpdateOptions{}); err != nil {
		return err
	}
	log.Printf("ccr-crd: updated CRD %s", crd.Name)
	return nil
}

func buildCCRCRD() *apiextv1.CustomResourceDefinition {
	return &apiextv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "crossclusterroutes.prysm.sh",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "prysm-agent",
			},
		},
		Spec: apiextv1.CustomResourceDefinitionSpec{
			Group: ccrGroup,
			Names: apiextv1.CustomResourceDefinitionNames{
				Plural:     ccrResource,
				Singular:   "crossclusterroute",
				Kind:       ccrKind,
				ShortNames: []string{"ccr"},
			},
			Scope: apiextv1.NamespaceScoped,
			Versions: []apiextv1.CustomResourceDefinitionVersion{
				{
					Name:    ccrVersion,
					Served:  true,
					Storage: true,
					Schema:  &apiextv1.CustomResourceValidation{OpenAPIV3Schema: ccrOpenAPISchema()},
					Subresources: &apiextv1.CustomResourceSubresources{
						Status: &apiextv1.CustomResourceSubresourceStatus{},
					},
					AdditionalPrinterColumns: []apiextv1.CustomResourceColumnDefinition{
						{Name: "Source", Type: "integer", JSONPath: ".spec.sourceClusterID"},
						{Name: "Target", Type: "integer", JSONPath: ".spec.targetClusterID"},
						{Name: "Service", Type: "string", JSONPath: ".spec.targetService"},
						{Name: "Port", Type: "integer", JSONPath: ".spec.targetPort"},
						{Name: "Phase", Type: "string", JSONPath: ".status.phase"},
						{Name: "Age", Type: "date", JSONPath: ".metadata.creationTimestamp"},
					},
				},
			},
		},
	}
}

// ensureMeshRouteCRD creates or updates the MeshRoute CRD in the cluster.
func ensureMeshRouteCRD(ctx context.Context, restCfg *rest.Config) error {
	client, err := apiextclient.NewForConfig(restCfg)
	if err != nil {
		return err
	}

	crd := buildMeshRouteCRD()

	tCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	existing, err := client.ApiextensionsV1().CustomResourceDefinitions().Get(tCtx, crd.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, err := client.ApiextensionsV1().CustomResourceDefinitions().Create(tCtx, crd, metav1.CreateOptions{}); err != nil {
			return err
		}
		log.Printf("mesh-route-crd: created CRD %s", crd.Name)
		return nil
	}
	if err != nil {
		return err
	}

	crd.ResourceVersion = existing.ResourceVersion
	if _, err := client.ApiextensionsV1().CustomResourceDefinitions().Update(tCtx, crd, metav1.UpdateOptions{}); err != nil {
		return err
	}
	log.Printf("mesh-route-crd: updated CRD %s", crd.Name)
	return nil
}

func buildMeshRouteCRD() *apiextv1.CustomResourceDefinition {
	return &apiextv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "meshroutes.prysm.sh",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "prysm-agent",
			},
		},
		Spec: apiextv1.CustomResourceDefinitionSpec{
			Group: ccrGroup,
			Names: apiextv1.CustomResourceDefinitionNames{
				Plural:     mrResource,
				Singular:   "meshroute",
				Kind:       mrKind,
				ShortNames: []string{"mr"},
			},
			Scope: apiextv1.NamespaceScoped,
			Versions: []apiextv1.CustomResourceDefinitionVersion{
				{
					Name:    ccrVersion,
					Served:  true,
					Storage: true,
					Schema:  &apiextv1.CustomResourceValidation{OpenAPIV3Schema: meshRouteOpenAPISchema()},
					Subresources: &apiextv1.CustomResourceSubresources{
						Status: &apiextv1.CustomResourceSubresourceStatus{},
					},
					AdditionalPrinterColumns: []apiextv1.CustomResourceColumnDefinition{
						{Name: "Slug", Type: "string", JSONPath: ".spec.slug"},
						{Name: "ExternalPort", Type: "integer", JSONPath: ".spec.externalPort"},
						{Name: "Service", Type: "string", JSONPath: ".spec.serviceName"},
						{Name: "ServicePort", Type: "integer", JSONPath: ".spec.servicePort"},
						{Name: "Phase", Type: "string", JSONPath: ".status.phase"},
						{Name: "Age", Type: "date", JSONPath: ".metadata.creationTimestamp"},
					},
				},
			},
		},
	}
}

func meshRouteOpenAPISchema() *apiextv1.JSONSchemaProps {
	return &apiextv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextv1.JSONSchemaProps{
			"spec": {
				Type:     "object",
				Required: []string{"externalPort", "serviceName", "servicePort"},
				Properties: map[string]apiextv1.JSONSchemaProps{
					"routeID":          {Type: "integer"},
					"name":             {Type: "string"},
					"slug":             {Type: "string"},
					"externalPort":     {Type: "integer", Minimum: jsonFloat(1), Maximum: jsonFloat(65535)},
					"serviceName":      {Type: "string"},
					"serviceNamespace": {Type: "string"},
					"servicePort":      {Type: "integer", Minimum: jsonFloat(1), Maximum: jsonFloat(65535)},
					"protocol":         {Type: "string", Enum: []apiextv1.JSON{jsonVal("tcp"), jsonVal("udp")}},
					"enabled":          {Type: "boolean"},
				},
			},
			"status": {
				Type: "object",
				Properties: map[string]apiextv1.JSONSchemaProps{
					"phase":              {Type: "string"},
					"message":            {Type: "string"},
					"lastSyncedAt":       {Type: "string", Format: "date-time"},
					"observedGeneration": {Type: "integer"},
				},
			},
		},
	}
}

func ccrOpenAPISchema() *apiextv1.JSONSchemaProps {
	return &apiextv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextv1.JSONSchemaProps{
			"spec": {
				Type:     "object",
				Required: []string{"sourceClusterID", "targetClusterID", "targetService", "targetPort", "localPort"},
				Properties: map[string]apiextv1.JSONSchemaProps{
					"sourceClusterID": {Type: "integer"},
					"targetClusterID": {Type: "integer"},
					"targetService":   {Type: "string"},
					"targetNamespace": {Type: "string"},
					"targetPort":      {Type: "integer", Minimum: jsonFloat(1), Maximum: jsonFloat(65535)},
					"localPort":       {Type: "integer", Minimum: jsonFloat(1), Maximum: jsonFloat(65535)},
					"protocol":        {Type: "string", Enum: []apiextv1.JSON{jsonVal("tcp"), jsonVal("udp")}},
					"enabled":         {Type: "boolean"},
					"backendRouteID":  {Type: "integer"},
				},
			},
			"status": {
				Type: "object",
				Properties: map[string]apiextv1.JSONSchemaProps{
					"phase":              {Type: "string"},
					"connectionMethod":   {Type: "string"},
					"serviceIP":          {Type: "string"},
					"serviceName":        {Type: "string"},
					"proxyPodName":       {Type: "string"},
					"proxyPodPhase":      {Type: "string"},
					"proxyPodIP":         {Type: "string"},
					"proxyPodReady":      {Type: "boolean"},
					"proxyMessage":       {Type: "string"},
					"message":            {Type: "string"},
					"lastSyncedAt":       {Type: "string", Format: "date-time"},
					"observedGeneration": {Type: "integer"},
				},
			},
		},
	}
}

func jsonFloat(v float64) *float64 { return &v }

func jsonVal(s string) apiextv1.JSON {
	raw, _ := json.Marshal(s)
	return apiextv1.JSON{Raw: raw}
}

// ensureClusterTunnelCRD creates or updates the ClusterTunnel CRD in the cluster.
func ensureClusterTunnelCRD(ctx context.Context, restCfg *rest.Config) error {
	client, err := apiextclient.NewForConfig(restCfg)
	if err != nil {
		return err
	}

	crd := buildClusterTunnelCRD()

	tCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	existing, err := client.ApiextensionsV1().CustomResourceDefinitions().Get(tCtx, crd.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		if _, err := client.ApiextensionsV1().CustomResourceDefinitions().Create(tCtx, crd, metav1.CreateOptions{}); err != nil {
			return err
		}
		log.Printf("ct-crd: created CRD %s", crd.Name)
		return nil
	}
	if err != nil {
		return err
	}

	crd.ResourceVersion = existing.ResourceVersion
	if _, err := client.ApiextensionsV1().CustomResourceDefinitions().Update(tCtx, crd, metav1.UpdateOptions{}); err != nil {
		return err
	}
	log.Printf("ct-crd: updated CRD %s", crd.Name)
	return nil
}

func buildClusterTunnelCRD() *apiextv1.CustomResourceDefinition {
	return &apiextv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "clustertunnels.prysm.sh",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "prysm-agent",
			},
		},
		Spec: apiextv1.CustomResourceDefinitionSpec{
			Group: ctGroup,
			Names: apiextv1.CustomResourceDefinitionNames{
				Plural:     ctResource,
				Singular:   "clustertunnel",
				Kind:       ctKind,
				ShortNames: []string{"ct"},
			},
			Scope: apiextv1.NamespaceScoped,
			Versions: []apiextv1.CustomResourceDefinitionVersion{
				{
					Name:    ctVersion,
					Served:  true,
					Storage: true,
					Schema:  &apiextv1.CustomResourceValidation{OpenAPIV3Schema: ctOpenAPISchema()},
					Subresources: &apiextv1.CustomResourceSubresources{
						Status: &apiextv1.CustomResourceSubresourceStatus{},
					},
					AdditionalPrinterColumns: []apiextv1.CustomResourceColumnDefinition{
						{Name: "Service", Type: "string", JSONPath: ".spec.service"},
						{Name: "Namespace", Type: "string", JSONPath: ".spec.namespace"},
						{Name: "Port", Type: "integer", JSONPath: ".spec.port"},
						{Name: "Phase", Type: "string", JSONPath: ".status.phase"},
						{Name: "Age", Type: "date", JSONPath: ".metadata.creationTimestamp"},
					},
				},
			},
		},
	}
}

func ctOpenAPISchema() *apiextv1.JSONSchemaProps {
	return &apiextv1.JSONSchemaProps{
		Type: "object",
		Properties: map[string]apiextv1.JSONSchemaProps{
			"spec": {
				Type:     "object",
				Required: []string{"service", "port"},
				Properties: map[string]apiextv1.JSONSchemaProps{
					"service":         {Type: "string"},
					"namespace":       {Type: "string"},
					"port":            {Type: "integer", Minimum: jsonFloat(1), Maximum: jsonFloat(65535)},
					"protocol":        {Type: "string", Enum: []apiextv1.JSON{jsonVal("tcp"), jsonVal("udp")}},
					"enabled":         {Type: "boolean"},
					"backendTunnelID": {Type: "integer"},
				},
			},
			"status": {
				Type: "object",
				Properties: map[string]apiextv1.JSONSchemaProps{
					"phase":              {Type: "string"},
					"message":            {Type: "string"},
					"lastSyncedAt":       {Type: "string", Format: "date-time"},
					"observedGeneration": {Type: "integer"},
				},
			},
		},
	}
}

// namespaceSecretAccess describes which namespaces the agent needs secrets write access in,
// and whether that namespace also needs serviceaccounts/token create.
var namespaceSecretAccess = []struct {
	namespace string
	saToken   bool
}{
	{"prysm-system", true},     // ebpf collector secrets + SA token provisioning
	{"prysm-logging", false},   // log collector secrets
	{"prysm-honeypots", false}, // honeypot secrets
}

// ensureNamespacedRBAC creates namespace-scoped Roles and RoleBindings that grant the
// agent write access to secrets (and serviceaccounts/token in prysm-system) in its
// operational namespaces. This replaces the former cluster-wide secret access.
//
// It also ensures the namespaces themselves exist, so the function is safe to call
// before the domain controllers run.
func ensureNamespacedRBAC(ctx context.Context, cs kubernetes.Interface) error {
	tCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	saName, saNamespace := detectServiceAccount()
	if saName == "" || saNamespace == "" {
		saName = "prysm-agent"
		saNamespace = ccRouteAgentNamespace()
	}

	const roleName = "prysm-agent-secrets"
	managedLabel := map[string]string{"app.kubernetes.io/managed-by": "prysm-agent"}

	for _, entry := range namespaceSecretAccess {
		ns := entry.namespace

		// Ensure namespace exists (idempotent).
		_, nsErr := cs.CoreV1().Namespaces().Create(tCtx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: managedLabel},
		}, metav1.CreateOptions{})
		if nsErr != nil && !apierrors.IsAlreadyExists(nsErr) {
			log.Printf("namespaced-rbac: create namespace %s failed: %v (continuing)", ns, nsErr)
		}

		// Build Role rules.
		rules := []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"create", "update", "delete"}},
		}
		if entry.saToken {
			rules = append(rules, rbacv1.PolicyRule{
				APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, Verbs: []string{"create"},
			})
		}

		role := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: ns, Labels: managedLabel},
			Rules:      rules,
		}
		existingRole, err := cs.RbacV1().Roles(ns).Get(tCtx, roleName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if _, err := cs.RbacV1().Roles(ns).Create(tCtx, role, metav1.CreateOptions{}); err != nil {
				log.Printf("namespaced-rbac: create Role %s/%s failed: %v", ns, roleName, err)
				continue
			}
			log.Printf("namespaced-rbac: created Role %s/%s", ns, roleName)
		} else if err == nil {
			existingRole.Rules = rules
			if _, err := cs.RbacV1().Roles(ns).Update(tCtx, existingRole, metav1.UpdateOptions{}); err != nil {
				log.Printf("namespaced-rbac: update Role %s/%s failed: %v", ns, roleName, err)
			}
		}

		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: roleName, Namespace: ns, Labels: managedLabel},
			RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: roleName},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: saName, Namespace: saNamespace}},
		}
		existingRB, err := cs.RbacV1().RoleBindings(ns).Get(tCtx, roleName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if _, err := cs.RbacV1().RoleBindings(ns).Create(tCtx, rb, metav1.CreateOptions{}); err != nil {
				log.Printf("namespaced-rbac: create RoleBinding %s/%s failed: %v", ns, roleName, err)
				continue
			}
			log.Printf("namespaced-rbac: created RoleBinding %s/%s", ns, roleName)
		} else if err == nil {
			existingRB.RoleRef = rb.RoleRef
			existingRB.Subjects = rb.Subjects
			if _, err := cs.RbacV1().RoleBindings(ns).Update(tCtx, existingRB, metav1.UpdateOptions{}); err != nil {
				log.Printf("namespaced-rbac: update RoleBinding %s/%s failed: %v", ns, roleName, err)
			}
		}
	}
	return nil
}
