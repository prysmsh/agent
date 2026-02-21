package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func TestNewPodCertStore(t *testing.T) {
	agent := &PrysmAgent{
		BackendURL:     "https://api.prysm.sh",
		AgentToken:     "test-token",
		ClusterID:      "test-cluster",
		OrganizationID: 1,
	}

	store := newPodCertStore(agent, 0)
	if store.ttl != DefaultWorkloadCertTTL {
		t.Errorf("expected default TTL %v, got %v", DefaultWorkloadCertTTL, store.ttl)
	}

	customTTL := 1 * time.Hour
	store = newPodCertStore(agent, customTTL)
	if store.ttl != customTTL {
		t.Errorf("expected custom TTL %v, got %v", customTTL, store.ttl)
	}
}

func TestPodCertStoreStats(t *testing.T) {
	agent := &PrysmAgent{
		BackendURL:     "https://api.prysm.sh",
		AgentToken:     "test-token",
		ClusterID:      "test-cluster",
		OrganizationID: 1,
	}

	store := newPodCertStore(agent, time.Hour)

	// Add some test certs to the store
	store.certs["default/pod1"] = &workloadCert{
		identity:  "spiffe://prysm.sh/org-1/cluster-test/ns-default/pod-pod1",
		expiresAt: time.Now().Add(30 * time.Minute), // active
		namespace: "default",
		podName:   "pod1",
	}
	store.certs["default/pod2"] = &workloadCert{
		identity:  "spiffe://prysm.sh/org-1/cluster-test/ns-default/pod-pod2",
		expiresAt: time.Now().Add(-10 * time.Minute), // expired
		namespace: "default",
		podName:   "pod2",
	}

	stats := store.Stats()

	if stats["total"].(int) != 2 {
		t.Errorf("expected total 2, got %v", stats["total"])
	}

	if stats["active"].(int) != 1 {
		t.Errorf("expected active 1, got %v", stats["active"])
	}

	if stats["expired"].(int) != 1 {
		t.Errorf("expected expired 1, got %v", stats["expired"])
	}
}

func TestPodCertStoreCleanup(t *testing.T) {
	agent := &PrysmAgent{}
	store := newPodCertStore(agent, time.Hour)

	// Add expired cert
	store.certs["default/expired-pod"] = &workloadCert{
		identity:  "spiffe://prysm.sh/org-1/cluster-test/ns-default/pod-expired-pod",
		expiresAt: time.Now().Add(-1 * time.Hour),
		namespace: "default",
		podName:   "expired-pod",
	}

	// Add active cert
	store.certs["default/active-pod"] = &workloadCert{
		identity:  "spiffe://prysm.sh/org-1/cluster-test/ns-default/pod-active-pod",
		expiresAt: time.Now().Add(1 * time.Hour),
		namespace: "default",
		podName:   "active-pod",
	}

	if len(store.certs) != 2 {
		t.Fatalf("expected 2 certs before cleanup, got %d", len(store.certs))
	}

	store.Cleanup()

	if len(store.certs) != 1 {
		t.Errorf("expected 1 cert after cleanup, got %d", len(store.certs))
	}

	if _, exists := store.certs["default/active-pod"]; !exists {
		t.Error("expected active-pod to still exist")
	}

	if _, exists := store.certs["default/expired-pod"]; exists {
		t.Error("expected expired-pod to be removed")
	}
}

func TestGetIdentityFromCert(t *testing.T) {
	// Create a test certificate with SPIFFE URI
	spiffeURI, _ := url.Parse("spiffe://prysm.sh/org-1/cluster-test/ns-default/pod-test-pod")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-pod.default.pod.cluster.local",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		URIs:      []*url.URL{spiffeURI},
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	identity := GetIdentityFromCert(cert)
	expected := "spiffe://prysm.sh/org-1/cluster-test/ns-default/pod-test-pod"
	if identity != expected {
		t.Errorf("expected identity %q, got %q", expected, identity)
	}
}

func TestGetIdentityFromCertNoSPIFFE(t *testing.T) {
	// Create a test certificate without SPIFFE URI
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-pod.default.pod.cluster.local",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	identity := GetIdentityFromCert(cert)
	if identity != "" {
		t.Errorf("expected empty identity, got %q", identity)
	}
}

func TestParsePodIdentity(t *testing.T) {
	tests := []struct {
		name      string
		identity  string
		wantNS    string
		wantPod   string
		wantError bool
	}{
		{
			name:     "valid identity",
			identity: "spiffe://prysm.sh/org-1/cluster-test-cluster/ns-default/pod-my-pod",
			wantNS:   "default",
			wantPod:  "my-pod",
		},
		{
			name:     "valid identity with dashes",
			identity: "spiffe://prysm.sh/org-1/cluster-my-cluster/ns-kube-system/pod-coredns-abc123",
			wantNS:   "kube-system",
			wantPod:  "coredns-abc123",
		},
		{
			name:      "invalid scheme",
			identity:  "https://prysm.sh/org-1/cluster-test/ns-default/pod-my-pod",
			wantError: true,
		},
		{
			name:      "invalid format",
			identity:  "spiffe://prysm.sh/invalid",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, pod, err := ParsePodIdentity(tt.identity)

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if ns != tt.wantNS {
				t.Errorf("expected namespace %q, got %q", tt.wantNS, ns)
			}

			if pod != tt.wantPod {
				t.Errorf("expected pod %q, got %q", tt.wantPod, pod)
			}
		})
	}
}
