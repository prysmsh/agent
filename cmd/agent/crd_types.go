package main

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	ccrGroup    = "prysm.sh"
	ccrVersion  = "v1alpha1"
	ccrResource = "crossclusterroutes"
	ccrKind     = "CrossClusterRoute"
	mrResource  = "meshroutes"
	mrKind      = "MeshRoute"
)

var ccrGVR = schema.GroupVersionResource{
	Group:    ccrGroup,
	Version:  ccrVersion,
	Resource: ccrResource,
}

var mrGVR = schema.GroupVersionResource{
	Group:    ccrGroup,
	Version:  ccrVersion,
	Resource: mrResource,
}

// CrossClusterRouteCR is the in-memory Go representation of the
// prysm.sh/v1alpha1 CrossClusterRoute custom resource.
type CrossClusterRouteCR struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              CrossClusterRouteSpec   `json:"spec"`
	Status            CrossClusterRouteStatus `json:"status,omitempty"`
}

type CrossClusterRouteSpec struct {
	SourceClusterID uint   `json:"sourceClusterID"`
	TargetClusterID uint   `json:"targetClusterID"`
	TargetService   string `json:"targetService"`
	TargetNamespace string `json:"targetNamespace,omitempty"`
	TargetPort      int    `json:"targetPort"`
	LocalPort       int    `json:"localPort"`
	Protocol        string `json:"protocol,omitempty"`
	Enabled         *bool  `json:"enabled,omitempty"`
	BackendRouteID  uint   `json:"backendRouteID,omitempty"`
}

type CrossClusterRouteStatus struct {
	Phase              string     `json:"phase,omitempty"`              // Pending, Syncing, Active, Error, Disabled
	ConnectionMethod   string     `json:"connectionMethod,omitempty"`   // e.g. "derp"
	ServiceIP          string     `json:"serviceIP,omitempty"`          // ClusterIP of the K8s Service
	ServiceName        string     `json:"serviceName,omitempty"`        // K8s Service name
	ProxyPodName       string     `json:"proxyPodName,omitempty"`       // proxy pod name (typically prysm-cc-proxy)
	ProxyPodPhase      string     `json:"proxyPodPhase,omitempty"`      // Running, Pending, Missing, etc.
	ProxyPodIP         string     `json:"proxyPodIP,omitempty"`         // current proxy pod IP
	ProxyPodReady      bool       `json:"proxyPodReady,omitempty"`      // true when pod Ready condition is True
	ProxyMessage       string     `json:"proxyMessage,omitempty"`       // additional health/reconcile detail
	Message            string     `json:"message,omitempty"`            // Human-readable status message
	LastSyncedAt       *time.Time `json:"lastSyncedAt,omitempty"`       // Last time synced with backend
	ObservedGeneration int64      `json:"observedGeneration,omitempty"` // Spec generation last processed
}

// MeshRouteCR mirrors backend-managed mesh route assignments in-cluster.
type MeshRouteCR struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              MeshRouteSpec   `json:"spec"`
	Status            MeshRouteStatus `json:"status,omitempty"`
}

type MeshRouteSpec struct {
	RouteID          uint   `json:"routeID,omitempty"`
	Name             string `json:"name,omitempty"`
	Slug             string `json:"slug,omitempty"`
	ExternalPort     int    `json:"externalPort"`
	ServiceName      string `json:"serviceName"`
	ServiceNamespace string `json:"serviceNamespace,omitempty"`
	ServicePort      int    `json:"servicePort"`
	Protocol         string `json:"protocol,omitempty"`
	Enabled          *bool  `json:"enabled,omitempty"`
}

type MeshRouteStatus struct {
	Phase              string     `json:"phase,omitempty"`
	Message            string     `json:"message,omitempty"`
	LastSyncedAt       *time.Time `json:"lastSyncedAt,omitempty"`
	ObservedGeneration int64      `json:"observedGeneration,omitempty"`
}

type MeshRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MeshRouteCR `json:"items"`
}

// CrossClusterRouteList represents a list of CrossClusterRoute CRs.
type CrossClusterRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CrossClusterRouteCR `json:"items"`
}

// DeepCopyObject satisfies runtime.Object for CrossClusterRouteCR.
func (in *CrossClusterRouteCR) DeepCopyObject() runtime.Object {
	out := new(CrossClusterRouteCR)
	in.DeepCopyInto(out)
	return out
}

func (in *CrossClusterRouteCR) DeepCopyInto(out *CrossClusterRouteCR) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	if in.Spec.Enabled != nil {
		b := *in.Spec.Enabled
		out.Spec.Enabled = &b
	}
	out.Status = in.Status
	if in.Status.LastSyncedAt != nil {
		t := *in.Status.LastSyncedAt
		out.Status.LastSyncedAt = &t
	}
}

// DeepCopyObject satisfies runtime.Object for CrossClusterRouteList.
func (in *CrossClusterRouteList) DeepCopyObject() runtime.Object {
	out := new(CrossClusterRouteList)
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]CrossClusterRouteCR, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
	return out
}

// DeepCopyObject satisfies runtime.Object for MeshRouteCR.
func (in *MeshRouteCR) DeepCopyObject() runtime.Object {
	out := new(MeshRouteCR)
	in.DeepCopyInto(out)
	return out
}

func (in *MeshRouteCR) DeepCopyInto(out *MeshRouteCR) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	if in.Spec.Enabled != nil {
		b := *in.Spec.Enabled
		out.Spec.Enabled = &b
	}
	out.Status = in.Status
	if in.Status.LastSyncedAt != nil {
		t := *in.Status.LastSyncedAt
		out.Status.LastSyncedAt = &t
	}
}

// DeepCopyObject satisfies runtime.Object for MeshRouteList.
func (in *MeshRouteList) DeepCopyObject() runtime.Object {
	out := new(MeshRouteList)
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]MeshRouteCR, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
	return out
}

// ccrSpecEnabled returns the Enabled value from the spec, defaulting to true.
func ccrSpecEnabled(spec CrossClusterRouteSpec) bool {
	if spec.Enabled == nil {
		return true
	}
	return *spec.Enabled
}
