package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/prysmsh/pkg/tlsutil"
)

const (
	// MTLSCertPath is the path where mTLS certificates are stored
	MTLSCertPath = "/var/lib/prysm/mtls"

	// CertificateFile is the filename for the agent certificate
	CertificateFile = "agent.crt"

	// KeyFile is the filename for the agent private key
	KeyFile = "agent.key"

	// CACertFile is the filename for the CA certificate
	CACertFile = "ca.crt"

	// RSAKeySize for agent key generation
	RSAKeySize = 4096

	// CertRenewalThreshold triggers renewal when cert expires within this duration
	CertRenewalThreshold = 6 * time.Hour
)

// MTLSClient handles mTLS certificate bootstrap, renewal, and authentication
type MTLSClient struct {
	controlPlaneURL string
	clusterID       string
	bootstrapToken  string

	privateKey *rsa.PrivateKey
	cert       *x509.Certificate
	caCert     *x509.Certificate
	tlsConfig  *tls.Config
	httpClient *http.Client

	certPath string
	mu       sync.RWMutex
}

// CertificateRequest is the bootstrap request format
type CertificateRequest struct {
	BootstrapToken string `json:"bootstrap_token"`
	CSR            string `json:"csr"`
	ClusterID      string `json:"cluster_id"`
}

// RenewalRequest is the certificate renewal request format
type RenewalRequest struct {
	CSR string `json:"csr"`
}

// CertificateResponse is the response from certificate issuance
type CertificateResponse struct {
	Certificate   string    `json:"certificate"`
	CACertificate string    `json:"ca_certificate"`
	SerialNumber  string    `json:"serial_number"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
}

// NewMTLSClient creates a new mTLS client
func NewMTLSClient(controlPlaneURL, clusterID string) *MTLSClient {
	certPath := os.Getenv("MTLS_CERT_PATH")
	if certPath == "" {
		certPath = MTLSCertPath
	}

	return &MTLSClient{
		controlPlaneURL: controlPlaneURL,
		clusterID:       clusterID,
		certPath:        certPath,
	}
}

// Initialize loads existing certificates or bootstraps new ones
func (c *MTLSClient) Initialize(ctx context.Context) error {
	// Create cert directory if needed
	if err := os.MkdirAll(c.certPath, 0700); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Try to load existing certificates
	if err := c.loadCertificates(); err == nil {
		log.Println("✅ Loaded existing mTLS certificates")
		if err := c.setupTLSConfig(); err != nil {
			return fmt.Errorf("failed to setup TLS config: %w", err)
		}
		return nil
	}

	// Need to bootstrap - check for bootstrap token
	c.bootstrapToken = os.Getenv("MTLS_BOOTSTRAP_TOKEN")
	if c.bootstrapToken == "" {
		log.Println("⚠️  No mTLS certificates found and no bootstrap token provided")
		log.Println("ℹ️  Agent will use token-based authentication")
		return nil
	}

	// Bootstrap with token
	log.Println("🔐 Bootstrapping mTLS certificates...")
	if err := c.bootstrap(ctx); err != nil {
		return fmt.Errorf("mTLS bootstrap failed: %w", err)
	}

	log.Println("✅ mTLS bootstrap completed successfully")
	return nil
}

// loadCertificates loads certificates from disk
func (c *MTLSClient) loadCertificates() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Load private key
	keyPEM, err := os.ReadFile(filepath.Join(c.certPath, KeyFile))
	if err != nil {
		return fmt.Errorf("failed to read key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("failed to decode key PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS8
		parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse key: %w", err)
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return errors.New("key is not RSA")
		}
	}
	c.privateKey = key

	// Load certificate
	certPEM, err := os.ReadFile(filepath.Join(c.certPath, CertificateFile))
	if err != nil {
		return fmt.Errorf("failed to read cert: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return errors.New("failed to decode cert PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse cert: %w", err)
	}
	c.cert = cert

	// Load CA certificate
	caCertPEM, err := os.ReadFile(filepath.Join(c.certPath, CACertFile))
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %w", err)
	}

	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return errors.New("failed to decode CA cert PEM")
	}

	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA cert: %w", err)
	}
	c.caCert = caCert

	// Check if certificate is still valid
	if time.Now().After(c.cert.NotAfter) {
		return errors.New("certificate has expired")
	}

	return nil
}

// saveCertificates saves certificates to disk
func (c *MTLSClient) saveCertificates() error {
	// Save private key
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(c.privateKey),
	})
	if err := os.WriteFile(filepath.Join(c.certPath, KeyFile), keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save key: %w", err)
	}

	// Save certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.cert.Raw,
	})
	if err := os.WriteFile(filepath.Join(c.certPath, CertificateFile), certPEM, 0644); err != nil {
		return fmt.Errorf("failed to save cert: %w", err)
	}

	// Save CA certificate
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.caCert.Raw,
	})
	if err := os.WriteFile(filepath.Join(c.certPath, CACertFile), caCertPEM, 0644); err != nil {
		return fmt.Errorf("failed to save CA cert: %w", err)
	}

	return nil
}

// generateKeyAndCSR creates a new key pair and certificate signing request
func (c *MTLSClient) generateKeyAndCSR() ([]byte, error) {
	// Generate new key pair
	key, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	c.privateKey = key

	// Create CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   c.clusterID,
			Organization: []string{"prysm-agent"},
		},
		DNSNames: []string{c.clusterID},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}

// bootstrap performs initial certificate bootstrap using a bootstrap token
func (c *MTLSClient) bootstrap(ctx context.Context) error {
	// Generate key and CSR
	csrPEM, err := c.generateKeyAndCSR()
	if err != nil {
		return err
	}

	// Create bootstrap request
	req := CertificateRequest{
		BootstrapToken: c.bootstrapToken,
		CSR:            string(csrPEM),
		ClusterID:      c.clusterID,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send bootstrap request (no mTLS yet)
	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		c.controlPlaneURL+"/api/v1/agent/mtls/bootstrap", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Use a basic HTTP client for bootstrap
	bootstrapTLS := &tls.Config{
		InsecureSkipVerify: os.Getenv("MTLS_SKIP_VERIFY") == "true",
	}
	tlsutil.ApplyPQCConfig(bootstrapTLS)
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: bootstrapTLS,
		},
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("bootstrap request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bootstrap failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var certResp CertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Parse and store certificates
	certBlock, _ := pem.Decode([]byte(certResp.Certificate))
	if certBlock == nil {
		return errors.New("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	c.cert = cert

	caBlock, _ := pem.Decode([]byte(certResp.CACertificate))
	if caBlock == nil {
		return errors.New("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	c.caCert = caCert

	// Save to disk
	if err := c.saveCertificates(); err != nil {
		return fmt.Errorf("failed to save certificates: %w", err)
	}

	// Setup TLS config
	if err := c.setupTLSConfig(); err != nil {
		return fmt.Errorf("failed to setup TLS config: %w", err)
	}

	log.Printf("✅ mTLS certificate issued (serial: %s, expires: %s)",
		certResp.SerialNumber, certResp.NotAfter.Format(time.RFC3339))

	return nil
}

// setupTLSConfig creates the TLS configuration for mTLS
func (c *MTLSClient) setupTLSConfig() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Create cert pool with CA
	caPool := x509.NewCertPool()
	caPool.AddCert(c.caCert)

	// Create TLS certificate
	tlsCert := tls.Certificate{
		Certificate: [][]byte{c.cert.Raw},
		PrivateKey:  c.privateKey,
	}

	c.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}
	tlsutil.ApplyPQCConfig(c.tlsConfig)

	c.httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: c.tlsConfig,
		},
	}

	return nil
}

// GetHTTPClient returns an HTTP client configured for mTLS
func (c *MTLSClient) GetHTTPClient() *http.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.httpClient
}

// GetTLSConfig returns the TLS configuration
func (c *MTLSClient) GetTLSConfig() *tls.Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tlsConfig
}

// NeedsRenewal checks if the certificate needs renewal
func (c *MTLSClient) NeedsRenewal() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.cert == nil {
		return false
	}

	return time.Until(c.cert.NotAfter) < CertRenewalThreshold
}

// Renew renews the certificate using the existing mTLS connection
func (c *MTLSClient) Renew(ctx context.Context) error {
	c.mu.Lock()

	// Generate new CSR (keeping existing key for continuity during rotation)
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   c.clusterID,
			Organization: []string{"prysm-agent"},
		},
		DNSNames: []string{c.clusterID},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, c.privateKey)
	if err != nil {
		c.mu.Unlock()
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	c.mu.Unlock()

	// Create renewal request
	req := RenewalRequest{
		CSR: string(csrPEM),
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send renewal request with mTLS
	httpReq, err := http.NewRequestWithContext(ctx, "POST",
		c.controlPlaneURL+"/api/v1/agent/mtls/renew", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := c.GetHTTPClient()
	if client == nil {
		return errors.New("mTLS not initialized")
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("renewal request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("renewal failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var certResp CertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Parse new certificate
	certBlock, _ := pem.Decode([]byte(certResp.Certificate))
	if certBlock == nil {
		return errors.New("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Update certificate
	c.mu.Lock()
	c.cert = cert
	c.mu.Unlock()

	// Save to disk
	if err := c.saveCertificates(); err != nil {
		return fmt.Errorf("failed to save certificates: %w", err)
	}

	// Refresh TLS config
	if err := c.setupTLSConfig(); err != nil {
		return fmt.Errorf("failed to setup TLS config: %w", err)
	}

	log.Printf("✅ mTLS certificate renewed (serial: %s, expires: %s)",
		certResp.SerialNumber, certResp.NotAfter.Format(time.RFC3339))

	return nil
}

// StartRenewalLoop starts a background goroutine that renews certificates
func (c *MTLSClient) StartRenewalLoop(ctx context.Context) {
	go func() {
		// Check every hour
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if c.NeedsRenewal() {
					log.Println("🔄 Certificate approaching expiry, renewing...")
					if err := c.Renew(ctx); err != nil {
						log.Printf("⚠️  Certificate renewal failed: %v", err)
						// Try again sooner
						time.Sleep(5 * time.Minute)
					}
				}
			}
		}
	}()
}

// IsEnabled returns true if mTLS is configured and ready
func (c *MTLSClient) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert != nil && c.httpClient != nil
}

// GetCertificateInfo returns information about the current certificate
func (c *MTLSClient) GetCertificateInfo() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.cert == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	return map[string]interface{}{
		"enabled":       true,
		"serial_number": c.cert.SerialNumber.String(),
		"subject":       c.cert.Subject.String(),
		"issuer":        c.cert.Issuer.String(),
		"not_before":    c.cert.NotBefore,
		"not_after":     c.cert.NotAfter,
		"time_to_expiry": time.Until(c.cert.NotAfter).String(),
	}
}
