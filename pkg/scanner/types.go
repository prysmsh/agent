package scanner

import "time"

// CVSS represents CVSS scoring information for a vulnerability.
type CVSS struct {
	V2Vector string  `json:"v2_vector,omitempty"`
	V2Score  float64 `json:"v2_score,omitempty"`
	V3Vector string  `json:"v3_vector,omitempty"`
	V3Score  float64 `json:"v3_score,omitempty"`
}

// ContainerVulnerability represents a single CVE/vulnerability finding.
type ContainerVulnerability struct {
	VulnerabilityID  string    `json:"vulnerability_id"`
	PackageName      string    `json:"package_name"`
	InstalledVersion string    `json:"installed_version"`
	FixedVersion     string    `json:"fixed_version"`
	Severity         string    `json:"severity"`
	Title            string    `json:"title"`
	Description      string    `json:"description"`
	References       []string  `json:"references"`
	PublishedDate    time.Time `json:"published_date,omitempty"`
	LastModifiedDate time.Time `json:"last_modified_date,omitempty"`
	CVSS             CVSS      `json:"cvss,omitempty"`
	PrimaryURL       string    `json:"primary_url,omitempty"`
}

// ImageScanResult holds the result of scanning a container image.
type ImageScanResult struct {
	ImageName        string
	ImageDigest      string
	ScanTime         time.Time
	TotalVulns       int
	CriticalCount    int
	HighCount        int
	MediumCount      int
	LowCount         int
	Vulnerabilities  []ContainerVulnerability
	ComplianceStatus string // COMPLIANT, NON_COMPLIANT, WARNING, UNKNOWN
	ScanError        string `json:"scan_error,omitempty"`
}

// Config holds scanner configuration.
type Config struct {
	Enabled              bool
	ScanInterval         time.Duration
	SeverityThreshold    string   // minimum severity to report: CRITICAL, HIGH, MEDIUM, LOW
	IncludeNamespaces    []string // empty = all
	ExcludeNamespaces    []string
	CacheEnabled         bool
	CacheTTL             time.Duration
	ConcurrentScans      int
	TrivyPath            string
	TrivyCacheDir        string
	SkipDBUpdate         bool
	Insecure             bool
	Timeout              time.Duration
	MaxCritical          int // compliance: max allowed critical (0 = none)
	MaxHigh              int
	MaxMedium            int
}
