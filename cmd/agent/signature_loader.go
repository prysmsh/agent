// Package main provides hot-reloadable YAML signature loading for the DPI engine.
// Custom signatures are loaded from /etc/prysm/dpi/signatures.d/*.yaml and merged
// with built-in Go signatures. File changes are detected via polling for zero-downtime
// signature updates (same pattern as ebpf-collector rules engine).
package main

import (
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultSignatureDir is the default directory for custom YAML signatures.
	DefaultSignatureDir = "/etc/prysm/dpi/signatures.d"

	// signaturePollInterval is how often we check for file changes.
	signaturePollInterval = 5 * time.Second
)

// YAMLSignatureFile represents a YAML signature definition file.
type YAMLSignatureFile struct {
	Signatures []YAMLSignature `yaml:"signatures"`
}

// YAMLSignature is a single signature in YAML format.
type YAMLSignature struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Pattern     string `yaml:"pattern"`
	Category    string `yaml:"category"`
	Level       string `yaml:"level"`
	Score       int    `yaml:"score"`
	MitreATTCK  string `yaml:"mitre"`
	Direction   string `yaml:"direction"`
	Enabled     *bool  `yaml:"enabled"` // pointer so we can distinguish unset from false
}

// SignatureLoader watches a directory for YAML signature files and hot-reloads them.
type SignatureLoader struct {
	dir     string
	scanner *NetworkSignatureScanner
	stopCh  chan struct{}
	mu      sync.Mutex
}

// NewSignatureLoader creates a loader for the given directory.
func NewSignatureLoader(dir string, scanner *NetworkSignatureScanner) *SignatureLoader {
	if dir == "" {
		dir = DefaultSignatureDir
	}
	return &SignatureLoader{
		dir:     dir,
		scanner: scanner,
		stopCh:  make(chan struct{}),
	}
}

// LoadOnce performs a single load of all YAML signature files. Returns the count loaded.
func (sl *SignatureLoader) LoadOnce() int {
	sl.mu.Lock()
	defer sl.mu.Unlock()

	sigs, err := sl.loadFromDir()
	if err != nil {
		log.Printf("dpi: signature loader: failed to load from %s: %v", sl.dir, err)
		return 0
	}

	sl.scanner.SetExternalSignatures(sigs)
	if len(sigs) > 0 {
		log.Printf("dpi: signature loader: loaded %d external signatures from %s", len(sigs), sl.dir)
	}
	return len(sigs)
}

// Start begins watching the signature directory for changes using polling.
// ConfigMap mounts use atomic symlink swaps, so polling is more reliable than inotify.
func (sl *SignatureLoader) Start() {
	sl.LoadOnce()
	go sl.pollLoop()
}

// Stop stops the signature loader.
func (sl *SignatureLoader) Stop() {
	close(sl.stopCh)
}

// pollLoop checks the directory for changes periodically.
func (sl *SignatureLoader) pollLoop() {
	if _, err := os.Stat(sl.dir); os.IsNotExist(err) {
		return
	}

	log.Printf("dpi: signature loader: watching %s for changes", sl.dir)
	lastMod := dirModTime(sl.dir)

	ticker := time.NewTicker(signaturePollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sl.stopCh:
			return
		case <-ticker.C:
			mod := dirModTime(sl.dir)
			if mod != lastMod {
				lastMod = mod
				log.Printf("dpi: signature loader: detected change in %s, reloading", sl.dir)
				sl.LoadOnce()
			}
		}
	}
}

// loadFromDir reads all .yaml/.yml files in the directory and parses signatures.
func (sl *SignatureLoader) loadFromDir() ([]*NetworkSignature, error) {
	entries, err := os.ReadDir(sl.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var allSigs []*NetworkSignature

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(sl.dir, entry.Name())
		sigs, err := sl.loadFile(path)
		if err != nil {
			log.Printf("dpi: signature loader: error loading %s: %v", path, err)
			continue
		}
		allSigs = append(allSigs, sigs...)
	}

	return allSigs, nil
}

// loadFile parses a single YAML signature file.
func (sl *SignatureLoader) loadFile(path string) ([]*NetworkSignature, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var file YAMLSignatureFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, err
	}

	var sigs []*NetworkSignature
	for _, ys := range file.Signatures {
		if ys.Enabled != nil && !*ys.Enabled {
			continue
		}
		if ys.ID == "" || ys.Pattern == "" {
			continue
		}

		compiled, err := regexp.Compile(ys.Pattern)
		if err != nil {
			log.Printf("dpi: signature loader: invalid regex in %s/%s: %v", path, ys.ID, err)
			continue
		}

		direction := ys.Direction
		if direction == "" {
			direction = "any"
		}

		sigs = append(sigs, &NetworkSignature{
			ID:          ys.ID,
			Name:        ys.Name,
			Description: ys.Description,
			Pattern:     compiled,
			Category:    ThreatCategory(ys.Category),
			Level:       parseThreatLevel(ys.Level),
			Score:       ys.Score,
			MitreATTCK:  ys.MitreATTCK,
			Direction:   direction,
		})
	}

	return sigs, nil
}

// parseThreatLevel converts a string level to ThreatLevel.
func parseThreatLevel(s string) ThreatLevel {
	switch s {
	case "critical":
		return ThreatCritical
	case "high":
		return ThreatHigh
	case "medium":
		return ThreatMedium
	case "low":
		return ThreatLow
	default:
		return ThreatMedium
	}
}

// dirModTime returns a combined hash of all file modification times in a directory.
func dirModTime(dir string) int64 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var sum int64
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			sum += info.ModTime().UnixNano()
		}
	}
	return sum
}
