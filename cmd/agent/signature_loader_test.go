package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignatureLoader_LoadFile(t *testing.T) {
	dir := t.TempDir()

	yamlContent := `signatures:
  - id: "custom-001"
    name: "Log4Shell JNDI"
    description: "Detected Log4Shell exploit attempt"
    pattern: '(?i)\$\{(?:jndi|lower|upper):.*\}'
    category: "command_injection"
    level: "critical"
    score: 95
    mitre: "T1190"
    direction: "inbound"
  - id: "custom-002"
    name: "Test pattern"
    description: "Test signature"
    pattern: 'test-pattern-\d+'
    category: "xss"
    level: "medium"
    score: 50
`

	path := filepath.Join(dir, "custom.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewNetworkSignatureScanner()
	loader := NewSignatureLoader(dir, scanner)
	count := loader.LoadOnce()

	if count != 2 {
		t.Errorf("LoadOnce() = %d, want 2", count)
	}

	// Check that external sigs are accessible via allSignatures
	all := scanner.allSignatures()
	foundCustom := false
	for _, sig := range all {
		if sig.ID == "custom-001" {
			foundCustom = true
			if sig.Level != ThreatCritical {
				t.Errorf("custom-001 level = %v, want Critical", sig.Level)
			}
			if sig.Direction != "inbound" {
				t.Errorf("custom-001 direction = %q, want inbound", sig.Direction)
			}
		}
	}
	if !foundCustom {
		t.Error("custom-001 not found in merged signatures")
	}
}

func TestSignatureLoader_DisabledSignature(t *testing.T) {
	dir := t.TempDir()

	disabled := false
	_ = disabled
	yamlContent := `signatures:
  - id: "disabled-001"
    name: "Disabled sig"
    description: "Should not load"
    pattern: 'disabled'
    category: "xss"
    level: "low"
    score: 10
    enabled: false
  - id: "enabled-001"
    name: "Enabled sig"
    description: "Should load"
    pattern: 'enabled'
    category: "xss"
    level: "low"
    score: 10
    enabled: true
`

	path := filepath.Join(dir, "mixed.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewNetworkSignatureScanner()
	loader := NewSignatureLoader(dir, scanner)
	count := loader.LoadOnce()

	if count != 1 {
		t.Errorf("LoadOnce() = %d, want 1 (disabled sig should be skipped)", count)
	}
}

func TestSignatureLoader_InvalidRegex(t *testing.T) {
	dir := t.TempDir()

	yamlContent := `signatures:
  - id: "bad-regex-001"
    name: "Bad regex"
    description: "Invalid regex pattern"
    pattern: '[invalid('
    category: "xss"
    level: "low"
    score: 10
  - id: "good-001"
    name: "Good sig"
    description: "Valid signature"
    pattern: 'good-pattern'
    category: "xss"
    level: "low"
    score: 10
`

	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewNetworkSignatureScanner()
	loader := NewSignatureLoader(dir, scanner)
	count := loader.LoadOnce()

	if count != 1 {
		t.Errorf("LoadOnce() = %d, want 1 (invalid regex should be skipped)", count)
	}
}

func TestSignatureLoader_OverrideBuiltin(t *testing.T) {
	dir := t.TempDir()

	// Override built-in sqli-001 with different score
	yamlContent := `signatures:
  - id: "sqli-001"
    name: "Custom SQL UNION"
    description: "Overridden SQL UNION detection"
    pattern: '(?i)union\s+select'
    category: "sql_injection"
    level: "critical"
    score: 99
`

	path := filepath.Join(dir, "override.yaml")
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	scanner := NewNetworkSignatureScanner()
	loader := NewSignatureLoader(dir, scanner)
	loader.LoadOnce()

	all := scanner.allSignatures()
	for _, sig := range all {
		if sig.ID == "sqli-001" {
			if sig.Score != 99 {
				t.Errorf("overridden sqli-001 score = %d, want 99", sig.Score)
			}
			if sig.Level != ThreatCritical {
				t.Errorf("overridden sqli-001 level = %v, want Critical", sig.Level)
			}
			return
		}
	}
	t.Error("sqli-001 not found in merged signatures")
}

func TestSignatureLoader_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	scanner := NewNetworkSignatureScanner()
	loader := NewSignatureLoader(dir, scanner)
	count := loader.LoadOnce()

	if count != 0 {
		t.Errorf("LoadOnce() = %d for empty dir, want 0", count)
	}
}

func TestSignatureLoader_NonexistentDir(t *testing.T) {
	scanner := NewNetworkSignatureScanner()
	loader := NewSignatureLoader("/nonexistent/path", scanner)
	count := loader.LoadOnce()

	if count != 0 {
		t.Errorf("LoadOnce() = %d for nonexistent dir, want 0", count)
	}
}

func TestSignatureLoader_MultipleFiles(t *testing.T) {
	dir := t.TempDir()

	yaml1 := `signatures:
  - id: "file1-001"
    name: "File 1 sig"
    description: "From file 1"
    pattern: 'file1'
    category: "xss"
    level: "low"
    score: 10
`
	yaml2 := `signatures:
  - id: "file2-001"
    name: "File 2 sig"
    description: "From file 2"
    pattern: 'file2'
    category: "xss"
    level: "low"
    score: 10
`

	os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(yaml1), 0644)
	os.WriteFile(filepath.Join(dir, "b.yml"), []byte(yaml2), 0644)

	scanner := NewNetworkSignatureScanner()
	loader := NewSignatureLoader(dir, scanner)
	count := loader.LoadOnce()

	if count != 2 {
		t.Errorf("LoadOnce() = %d for 2 files, want 2", count)
	}
}

func TestParseThreatLevel(t *testing.T) {
	tests := []struct {
		input string
		want  ThreatLevel
	}{
		{"critical", ThreatCritical},
		{"high", ThreatHigh},
		{"medium", ThreatMedium},
		{"low", ThreatLow},
		{"unknown", ThreatMedium},
		{"", ThreatMedium},
	}

	for _, tt := range tests {
		got := parseThreatLevel(tt.input)
		if got != tt.want {
			t.Errorf("parseThreatLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
