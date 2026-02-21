// Package main provides per-pod certificate management for the tunnel daemon.
// Each pod gets a unique X.509 certificate with a SPIFFE-like identity that
// is used for mTLS authentication between tunnel daemons.

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultWorkloadCertTTL is the default TTL for workload certificates in cache
	DefaultWorkloadCertTTL = 24 * time.Hour

	// CertRenewalBuffer is how long before expiry we should renew
	CertRenewalBuffer = 1 * time.Hour

	// SPIFFETrustDomain is the trust domain for SPIFFE identities
	SPIFFETrustDomain = "prysm.sh"
)

// workloadCert represents a cached workload certificate
type workloadCert struct {
	cert       *tls.Certificate
	x509Cert   *x509.Certificate
	identity   string // SPIFFE URI
	expiresAt  time.Time
	issuedAt   time.Time
	namespace  string
	podName    string
}

// podCertStore manages per-pod certificates for the tunnel daemon.
// It caches issued certificates and handles automatic renewal.
type podCertStore struct {
	agent      *PrysmAgent
	certs      map[string]*workloadCert // key: "namespace/podName"
	mu         sync.RWMutex
	ttl        time.Duration
	caCertPool *x509.CertPool
	caCertPEM  []byte
}

// newPodCertStore creates a new certificate store
func newPodCertStore(agent *PrysmAgent, ttl time.Duration) *podCertStore {
	if ttl <= 0 {
		ttl = DefaultWorkloadCertTTL
	}
	return &podCertStore{
		agent: agent,
		certs: make(map[string]*workloadCert),
		ttl:   ttl,
	}
}

// Initialize fetches the CA certificate from the backend
func (s *podCertStore) Initialize(ctx context.Context) error {
	if s.agent.BackendURL == "" {
		return fmt.Errorf("backend URL not configured")
	}

	// Fetch CA certificate
	req, err := http.NewRequestWithContext(ctx, "GET", s.agent.BackendURL+"/api/v1/agent/mtls/ca", nil)
	if err != nil {
		return fmt.Errorf("failed to create CA request: %w", err)
	}

	resp, err := s.agent.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch CA certificate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("CA fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	var caResp struct {
		CACertificate string `json:"ca_certificate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&caResp); err != nil {
		return fmt.Errorf("failed to decode CA response: %w", err)
	}

	// Parse CA certificate
	s.caCertPEM = []byte(caResp.CACertificate)
	s.caCertPool = x509.NewCertPool()
	if !s.caCertPool.AppendCertsFromPEM(s.caCertPEM) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	log.Println("tunnel: initialized pod certificate store with CA")
	return nil
}

// GetCACertPool returns the CA certificate pool for TLS verification
func (s *podCertStore) GetCACertPool() *x509.CertPool {
	return s.caCertPool
}

// GetCACertPEM returns the CA certificate in PEM format
func (s *podCertStore) GetCACertPEM() []byte {
	return s.caCertPEM
}

// GetOrIssue retrieves a cached certificate or issues a new one for the given pod
func (s *podCertStore) GetOrIssue(ctx context.Context, namespace, podName string) (*workloadCert, error) {
	key := namespace + "/" + podName

	// Check cache first
	s.mu.RLock()
	if cert, ok := s.certs[key]; ok {
		// Check if cert is still valid with buffer time
		if time.Now().Before(cert.expiresAt.Add(-CertRenewalBuffer)) {
			s.mu.RUnlock()
			return cert, nil
		}
	}
	s.mu.RUnlock()

	// Issue new certificate
	cert, err := s.issueCertificate(ctx, namespace, podName)
	if err != nil {
		return nil, err
	}

	// Cache the certificate
	s.mu.Lock()
	s.certs[key] = cert
	s.mu.Unlock()

	log.Printf("tunnel: issued certificate for pod %s/%s (expires: %s)",
		namespace, podName, cert.expiresAt.Format(time.RFC3339))

	return cert, nil
}

// issueCertificate requests a new workload certificate from the backend
func (s *podCertStore) issueCertificate(ctx context.Context, namespace, podName string) (*workloadCert, error) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Build SPIFFE identity
	identity := fmt.Sprintf("spiffe://%s/org-%d/cluster-%s/ns-%s/pod-%s",
		SPIFFETrustDomain, s.agent.OrganizationID, s.agent.ClusterID, namespace, podName)

	spiffeURI, err := url.Parse(identity)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SPIFFE URI: %w", err)
	}

	// Create CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("%s.%s.pod.cluster.local", podName, namespace),
			Organization: []string{fmt.Sprintf("org-%d", s.agent.OrganizationID)},
		},
		URIs: []*url.URL{spiffeURI},
		DNSNames: []string{
			fmt.Sprintf("%s.%s.pod.cluster.local", podName, namespace),
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// Request certificate from backend
	reqBody := map[string]interface{}{
		"csr": string(csrPEM),
		"identity": map[string]interface{}{
			"organization_id": s.agent.OrganizationID,
			"cluster_id":      s.agent.ClusterID,
			"namespace":       namespace,
			"service_account": "default", // Required by backend
			"pod_name":        podName,
		},
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		s.agent.BackendURL+"/api/v1/agent/mtls/workload", bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.agent.AgentToken)
	req.Header.Set("X-Cluster-ID", s.agent.ClusterID)

	resp, err := s.agent.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certificate request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("certificate issuance failed with status %d: %s", resp.StatusCode, string(body))
	}

	var certResp struct {
		Certificate      string    `json:"certificate"`
		CACertificate    string    `json:"ca_certificate"`
		CertificateChain string    `json:"certificate_chain"`
		SerialNumber     string    `json:"serial_number"`
		SPIFFEID         string    `json:"spiffe_id"`
		NotBefore        time.Time `json:"not_before"`
		NotAfter         time.Time `json:"not_after"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return nil, fmt.Errorf("failed to decode certificate response: %w", err)
	}

	// Encode private key to PEM
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	// Parse TLS certificate
	tlsCert, err := tls.X509KeyPair([]byte(certResp.Certificate), keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	// Parse X509 certificate for inspection
	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse X509 certificate: %w", err)
	}

	return &workloadCert{
		cert:      &tlsCert,
		x509Cert:  x509Cert,
		identity:  certResp.SPIFFEID,
		expiresAt: certResp.NotAfter,
		issuedAt:  certResp.NotBefore,
		namespace: namespace,
		podName:   podName,
	}, nil
}

// Cleanup removes expired certificates from the cache
func (s *podCertStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, cert := range s.certs {
		if now.After(cert.expiresAt) {
			delete(s.certs, key)
			log.Printf("tunnel: cleaned up expired certificate for %s", key)
		}
	}
}

// StartCleanupLoop starts a background goroutine that periodically cleans up expired certificates
func (s *podCertStore) StartCleanupLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Cleanup()
			}
		}
	}()
}

// Stats returns statistics about the certificate store
func (s *podCertStore) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	active := 0
	expired := 0

	for _, cert := range s.certs {
		if now.Before(cert.expiresAt) {
			active++
		} else {
			expired++
		}
	}

	return map[string]interface{}{
		"total":   len(s.certs),
		"active":  active,
		"expired": expired,
		"ttl":     s.ttl.String(),
	}
}

// GetTLSConfig returns a TLS config that uses the certificate for the given pod.
// Uses TLS 1.3 with ML-KEM-768 hybrid key exchange for post-quantum security.
func (s *podCertStore) GetTLSConfig(ctx context.Context, namespace, podName string) (*tls.Config, error) {
	cert, err := s.GetOrIssue(ctx, namespace, podName)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*cert.cert},
		RootCAs:      s.caCertPool,
		MinVersion:   tls.VersionTLS13, // TLS 1.3 required for PQC
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768, // Hybrid PQ: X25519 + ML-KEM-768
			tls.X25519,         // Fallback
			tls.CurveP256,
		},
	}, nil
}

// GetIdentityFromCert extracts the SPIFFE identity from a peer certificate
func GetIdentityFromCert(cert *x509.Certificate) string {
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" && uri.Host == SPIFFETrustDomain {
			return uri.String()
		}
	}
	return ""
}

// ParsePodIdentity extracts namespace and pod name from a SPIFFE identity
func ParsePodIdentity(identity string) (namespace, podName string, err error) {
	u, err := url.Parse(identity)
	if err != nil {
		return "", "", fmt.Errorf("invalid SPIFFE identity: %w", err)
	}

	if u.Scheme != "spiffe" {
		return "", "", fmt.Errorf("invalid scheme: %s", u.Scheme)
	}

	// Path format: /org-{id}/cluster-{id}/ns-{ns}/pod-{name}
	// Use strings.Split instead of Sscanf for better handling of dashes
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) != 4 {
		return "", "", fmt.Errorf("invalid identity path format: expected 4 parts, got %d", len(parts))
	}

	// Validate and extract each part
	if !strings.HasPrefix(parts[0], "org-") {
		return "", "", fmt.Errorf("invalid org part: %s", parts[0])
	}
	if !strings.HasPrefix(parts[1], "cluster-") {
		return "", "", fmt.Errorf("invalid cluster part: %s", parts[1])
	}
	if !strings.HasPrefix(parts[2], "ns-") {
		return "", "", fmt.Errorf("invalid namespace part: %s", parts[2])
	}
	if !strings.HasPrefix(parts[3], "pod-") {
		return "", "", fmt.Errorf("invalid pod part: %s", parts[3])
	}

	namespace = strings.TrimPrefix(parts[2], "ns-")
	podName = strings.TrimPrefix(parts[3], "pod-")

	return namespace, podName, nil
}
