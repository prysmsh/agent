package main

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	ctGroup    = "prysm.sh"
	ctVersion  = "v1alpha1"
	ctResource = "clustertunnels"
	ctKind     = "ClusterTunnel"
)

var ctGVR = schema.GroupVersionResource{
	Group:    ctGroup,
	Version:  ctVersion,
	Resource: ctResource,
}

// ClusterTunnelCR is the in-memory Go representation of the
// prysm.sh/v1alpha1 ClusterTunnel custom resource.
type ClusterTunnelCR struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ClusterTunnelSpec   `json:"spec"`
	Status            ClusterTunnelStatus `json:"status,omitempty"`
}

type ClusterTunnelSpec struct {
	Service         string `json:"service"`                   // K8s service name (required)
	Namespace       string `json:"namespace,omitempty"`       // K8s namespace (default: "default")
	Port            int    `json:"port"`                      // Service port (required)
	Protocol        string `json:"protocol,omitempty"`        // "tcp" (default)
	Enabled         *bool  `json:"enabled,omitempty"`         // default true
	BackendTunnelID int64  `json:"backendTunnelID,omitempty"` // set by controller after sync
}

type ClusterTunnelStatus struct {
	Phase              string     `json:"phase,omitempty"` // Pending, Active, Error, Disabled
	Message            string     `json:"message,omitempty"`
	LastSyncedAt       *time.Time `json:"lastSyncedAt,omitempty"`
	ObservedGeneration int64      `json:"observedGeneration,omitempty"`
}

// ClusterTunnelList represents a list of ClusterTunnel CRs.
type ClusterTunnelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterTunnelCR `json:"items"`
}

// DeepCopyObject satisfies runtime.Object for ClusterTunnelCR.
func (in *ClusterTunnelCR) DeepCopyObject() runtime.Object {
	out := new(ClusterTunnelCR)
	in.DeepCopyInto(out)
	return out
}

func (in *ClusterTunnelCR) DeepCopyInto(out *ClusterTunnelCR) {
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

// DeepCopyObject satisfies runtime.Object for ClusterTunnelList.
func (in *ClusterTunnelList) DeepCopyObject() runtime.Object {
	out := new(ClusterTunnelList)
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]ClusterTunnelCR, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
	return out
}

// ctSpecEnabled returns the Enabled value from the spec, defaulting to true.
func ctSpecEnabled(spec ClusterTunnelSpec) bool {
	if spec.Enabled == nil {
		return true
	}
	return *spec.Enabled
}
