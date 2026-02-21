package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// trivyReport is the structure of Trivy's JSON output (vulnerability scanner).
type trivyReport struct {
	SchemaVersion   int            `json:"SchemaVersion"`
	ArtifactName    string         `json:"ArtifactName"`
	ArtifactType    string         `json:"ArtifactType"`
	Metadata        trivyMetadata  `json:"Metadata,omitempty"`
	Results         []trivyResult  `json:"Results"`
}

type trivyMetadata struct {
	RepoDigests []string `json:"RepoDigests,omitempty"`
	Digest      string   `json:"Digest,omitempty"`
}

type trivyResult struct {
	Target          string              `json:"Target"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities,omitempty"`
}

type trivyCVSS struct {
	V2Vector string  `json:"V2Vector"`
	V2Score  float64 `json:"V2Score"`
	V3Vector string  `json:"V3Vector"`
	V3Score  float64 `json:"V3Score"`
}

type trivyVulnerability struct {
	VulnerabilityID  string            `json:"VulnerabilityID"`
	PkgName          string            `json:"PkgName"`
	InstalledVersion string            `json:"InstalledVersion"`
	FixedVersion     string            `json:"FixedVersion"`
	Severity         string            `json:"Severity"`
	Title            string            `json:"Title"`
	Description      string            `json:"Description"`
	References       []string          `json:"References"`
	PublishedDate    string            `json:"PublishedDate"`
	LastModifiedDate string            `json:"LastModifiedDate"`
	CVSS             map[string]trivyCVSS `json:"CVSS"`
	PrimaryURL       string            `json:"PrimaryURL"`
}

// TrivyScanner runs Trivy CLI to scan container images and caches results.
type TrivyScanner struct {
	config Config
	mu     sync.RWMutex
	cache  map[string]cachedResult
}

type cachedResult struct {
	Result    *ImageScanResult
	ExpiresAt time.Time
}

// NewTrivyScanner creates a new Trivy scanner with the given config.
func NewTrivyScanner(config Config) *TrivyScanner {
	if config.TrivyPath == "" {
		config.TrivyPath = "trivy"
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 24 * time.Hour
	}
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Minute
	}
	if config.ConcurrentScans <= 0 {
		config.ConcurrentScans = 5
	}
	s := &TrivyScanner{
		config: config,
		cache:  make(map[string]cachedResult),
	}
	return s
}

// ScanImage runs Trivy on the given image reference and returns vulnerabilities.
// Image ref can be a tag (e.g. nginx:1.21) or digest. Registry auth is handled via
// Trivy's use of DOCKER_CONFIG / container runtime config when present.
func (s *TrivyScanner) ScanImage(ctx context.Context, imageRef string) (*ImageScanResult, error) {
	cacheKey := imageRef
	if s.config.CacheEnabled {
		if cached := s.getCached(cacheKey); cached != nil {
			return cached, nil
		}
	}

	result, err := s.runTrivy(ctx, imageRef)
	if err != nil {
		return &ImageScanResult{
			ImageName:        imageRef,
			ScanTime:         time.Now(),
			ComplianceStatus: "UNKNOWN",
			ScanError:        err.Error(),
		}, err
	}

	if s.config.CacheEnabled {
		s.setCached(cacheKey, result)
	}
	return result, nil
}

func (s *TrivyScanner) runTrivy(ctx context.Context, imageRef string) (*ImageScanResult, error) {
	tmpDir, err := os.MkdirTemp("", "trivy-scan-")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	outputPath := filepath.Join(tmpDir, "report.json")

	args := []string{
		"image",
		"--format", "json",
		"--output", outputPath,
		"--scanners", "vuln",
		"--severity", "CRITICAL,HIGH,MEDIUM,LOW",
		"--no-progress",
		"--quiet",
	}
	if s.config.SkipDBUpdate {
		args = append(args, "--skip-db-update")
	}
	if s.config.Insecure {
		args = append(args, "--insecure")
	}
	if s.config.TrivyCacheDir != "" {
		args = append(args, "--cache-dir", s.config.TrivyCacheDir)
	}
	args = append(args, imageRef)

	runCtx := ctx
	if s.config.Timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, s.config.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(runCtx, s.config.TrivyPath, args...)
	var stderr bytes.Buffer
	cmd.Stdout = nil
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if runCtx.Err() != nil {
			return nil, runCtx.Err()
		}
		errDetail := err.Error()
		if stderr.Len() > 0 {
			stderrStr := strings.TrimSpace(stderr.String())
			if len(stderrStr) > 400 {
				stderrStr = stderrStr[:400] + "..."
			}
			errDetail = errDetail + ": " + stderrStr
			log.Printf("[scanner] trivy stderr for %s: %s", imageRef, strings.TrimSpace(stderr.String()))
		}
		return nil, fmt.Errorf("trivy scan: %s", errDetail)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("read trivy output: %w", err)
	}

	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse trivy json: %w", err)
	}

	return s.convertReport(&report, imageRef), nil
}

func (s *TrivyScanner) convertReport(r *trivyReport, imageRef string) *ImageScanResult {
	res := &ImageScanResult{
		ImageName:        imageRef,
		ScanTime:         time.Now(),
		Vulnerabilities:  []ContainerVulnerability{},
	}
	if r.Metadata.Digest != "" {
		res.ImageDigest = r.Metadata.Digest
	}

	severityMin := severityOrder(s.config.SeverityThreshold)
	for i := range r.Results {
		for _, v := range r.Results[i].Vulnerabilities {
			if !meetsSeverityThreshold(v.Severity, severityMin) {
				continue
			}
			cv := ContainerVulnerability{
				VulnerabilityID:  v.VulnerabilityID,
				PackageName:      v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Severity:         v.Severity,
				Title:            v.Title,
				Description:      v.Description,
				References:       append([]string(nil), v.References...),
				PrimaryURL:       v.PrimaryURL,
			}
			if v.PublishedDate != "" {
				if t, err := time.Parse(time.RFC3339, v.PublishedDate); err == nil {
					cv.PublishedDate = t
				}
			}
			if v.LastModifiedDate != "" {
				if t, err := time.Parse(time.RFC3339, v.LastModifiedDate); err == nil {
					cv.LastModifiedDate = t
				}
			}
			// Parse CVSS scores - Trivy provides them in a map by vendor
			if len(v.CVSS) > 0 {
				// Try to get NVD scores first, fall back to any other vendor
				for vendor, cvss := range v.CVSS {
					if vendor == "nvd" || vendor == "NVD" {
						cv.CVSS.V2Vector = cvss.V2Vector
						cv.CVSS.V2Score = cvss.V2Score
						cv.CVSS.V3Vector = cvss.V3Vector
						cv.CVSS.V3Score = cvss.V3Score
						break
					}
				}
				// If NVD not found, use first available
				if cv.CVSS.V2Vector == "" && cv.CVSS.V3Vector == "" {
					for _, cvss := range v.CVSS {
						cv.CVSS.V2Vector = cvss.V2Vector
						cv.CVSS.V2Score = cvss.V2Score
						cv.CVSS.V3Vector = cvss.V3Vector
						cv.CVSS.V3Score = cvss.V3Score
						break
					}
				}
			}
			res.Vulnerabilities = append(res.Vulnerabilities, cv)
			res.TotalVulns++
			switch strings.ToUpper(v.Severity) {
			case "CRITICAL":
				res.CriticalCount++
			case "HIGH":
				res.HighCount++
			case "MEDIUM":
				res.MediumCount++
			case "LOW":
				res.LowCount++
			}
		}
	}

	res.ComplianceStatus = s.complianceStatus(res)
	return res
}

func meetsSeverityThreshold(severity string, minOrder int) bool {
	return severityOrder(severity) >= minOrder
}

func severityOrder(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func (s *TrivyScanner) complianceStatus(res *ImageScanResult) string {
	if res.ScanError != "" {
		return "UNKNOWN"
	}
	if res.CriticalCount > s.config.MaxCritical {
		return "NON_COMPLIANT"
	}
	if res.HighCount > s.config.MaxHigh {
		return "NON_COMPLIANT"
	}
	if res.CriticalCount > 0 || res.HighCount > 0 {
		return "NON_COMPLIANT"
	}
	if res.MediumCount > s.config.MaxMedium || res.MediumCount > 0 {
		return "WARNING"
	}
	return "COMPLIANT"
}

func (s *TrivyScanner) getCached(key string) *ImageScanResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.cache[key]
	if !ok || time.Now().After(c.ExpiresAt) {
		return nil
	}
	return c.Result
}

func (s *TrivyScanner) setCached(key string, result *ImageScanResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[key] = cachedResult{Result: result, ExpiresAt: time.Now().Add(s.config.CacheTTL)}
}

// ClearCache removes all cached scan results.
func (s *TrivyScanner) ClearCache() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache = make(map[string]cachedResult)
	log.Println("[scanner] cache cleared")
}

// EnsureTrivyAvailable checks that the Trivy binary is in PATH and runnable.
func EnsureTrivyAvailable(path string) error {
	if path == "" {
		path = "trivy"
	}
	_, err := exec.LookPath(path)
	if err != nil {
		return fmt.Errorf("trivy not found in PATH: %w", err)
	}
	cmd := exec.Command(path, "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trivy --version failed: %w", err)
	}
	return nil
}
