package main

import (
	"testing"
)

func TestDLPInspector_CreditCardVisa(t *testing.T) {
	d := NewDLPInspector()
	// Valid Visa test number (Luhn-valid)
	data := []byte(`{"card": "4111111111111111", "exp": "12/26"}`)
	results := d.Inspect(data, "outbound", nil)

	found := false
	for _, r := range results {
		if r.Category == ThreatCategoryDLP && r.ThreatLevel == ThreatHigh {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DLP detection for Visa card number")
	}
}

func TestDLPInspector_CreditCardMastercard(t *testing.T) {
	d := NewDLPInspector()
	data := []byte(`card=5555555555554444`)
	results := d.Inspect(data, "outbound", nil)

	found := false
	for _, r := range results {
		if r.Category == ThreatCategoryDLP {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DLP detection for Mastercard number")
	}
}

func TestDLPInspector_CreditCardAmex(t *testing.T) {
	d := NewDLPInspector()
	data := []byte(`cc=378282246310005`)
	results := d.Inspect(data, "outbound", nil)

	found := false
	for _, r := range results {
		if r.Category == ThreatCategoryDLP {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DLP detection for Amex card number")
	}
}

func TestDLPInspector_InvalidLuhn(t *testing.T) {
	d := NewDLPInspector()
	// Invalid Luhn number
	data := []byte(`card=4111111111111112`)
	results := d.Inspect(data, "outbound", nil)

	for _, r := range results {
		if r.Category == ThreatCategoryDLP {
			for _, ind := range r.Indicators {
				if ind == "dlp-cc-001" || ind == "dlp-cc-002" || ind == "dlp-cc-003" || ind == "dlp-cc-004" {
					t.Error("should not flag invalid Luhn number as credit card")
				}
			}
		}
	}
}

func TestDLPInspector_SSN(t *testing.T) {
	d := NewDLPInspector()
	data := []byte(`ssn: 123-45-6789`)
	results := d.Inspect(data, "outbound", nil)

	found := false
	for _, r := range results {
		if r.Category == ThreatCategoryDLP {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DLP detection for SSN")
	}
}

func TestDLPInspector_SSN_Invalid(t *testing.T) {
	d := NewDLPInspector()
	// 000 and 666 prefixes are invalid SSNs
	data := []byte(`ssn: 000-12-3456`)
	results := d.Inspect(data, "outbound", nil)

	for _, r := range results {
		if r.Category == ThreatCategoryDLP {
			for _, ind := range r.Indicators {
				if ind == "dlp-ssn-001" {
					t.Error("should not flag invalid SSN prefix 000")
				}
			}
		}
	}
}

func TestDLPInspector_AWSKey(t *testing.T) {
	d := NewDLPInspector()
	data := []byte(`export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`)
	results := d.Inspect(data, "outbound", nil)

	found := false
	for _, r := range results {
		if r.Category == ThreatCategoryDLP && r.ThreatLevel == ThreatCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DLP detection for AWS access key")
	}
}

func TestDLPInspector_GitHubToken(t *testing.T) {
	d := NewDLPInspector()
	data := []byte(`token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`)
	results := d.Inspect(data, "outbound", nil)

	found := false
	for _, r := range results {
		if r.Category == ThreatCategoryDLP {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DLP detection for GitHub token")
	}
}

func TestDLPInspector_StripeKey(t *testing.T) {
	d := NewDLPInspector()
	data := []byte("stripe_key = \"sk_" + "live_ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abc\"")
	results := d.Inspect(data, "outbound", nil)

	found := false
	for _, r := range results {
		if r.Category == ThreatCategoryDLP && r.ThreatLevel == ThreatCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DLP detection for Stripe live key")
	}
}

func TestDLPInspector_PrivateKey(t *testing.T) {
	d := NewDLPInspector()
	data := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...`)
	results := d.Inspect(data, "outbound", nil)

	found := false
	for _, r := range results {
		if r.Category == ThreatCategoryDLP && r.ThreatLevel == ThreatCritical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DLP detection for RSA private key")
	}
}

func TestDLPInspector_CredentialsInURL(t *testing.T) {
	d := NewDLPInspector()
	data := []byte(`connecting to https://admin:secretpass@db.internal.svc:5432/mydb`)
	results := d.Inspect(data, "outbound", nil)

	found := false
	for _, r := range results {
		if r.Category == ThreatCategoryDLP {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DLP detection for credentials in URL")
	}
}

func TestDLPInspector_SlackToken(t *testing.T) {
	d := NewDLPInspector()
	data := []byte("SLACK_TOKEN=" + "xoxb-123456789012-1234567890" + "12-AbCdEfGhIjKlMnOpQrStUv")
	results := d.Inspect(data, "outbound", nil)

	found := false
	for _, r := range results {
		if r.Category == ThreatCategoryDLP {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DLP detection for Slack token")
	}
}

func TestDLPInspector_InboundIgnored(t *testing.T) {
	d := NewDLPInspector()
	data := []byte(`card=4111111111111111`)
	results := d.Inspect(data, "inbound", nil)

	if len(results) != 0 {
		t.Error("DLP should not scan inbound traffic")
	}
}

func TestDLPInspector_NoSensitiveData(t *testing.T) {
	d := NewDLPInspector()
	data := []byte(`{"message": "Hello, World!", "status": "ok", "count": 42}`)
	results := d.Inspect(data, "outbound", nil)

	if len(results) != 0 {
		t.Errorf("expected no DLP results for benign data, got %d", len(results))
	}
}

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"4111111111111111", true},  // Visa test
		{"5555555555554444", true},  // MC test
		{"378282246310005", true},   // Amex test
		{"6011111111111117", true},  // Discover test
		{"4111111111111112", false}, // Invalid
		{"1234", false},            // Too short
	}

	for _, tt := range tests {
		got := luhnCheck(tt.input)
		if got != tt.valid {
			t.Errorf("luhnCheck(%q) = %v, want %v", tt.input, got, tt.valid)
		}
	}
}

func TestRedactMatch(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"4111111111111111", "4111****1111"},
		{"short", "****"},
		{"abcdefghij", "abcd****ghij"},
	}

	for _, tt := range tests {
		got := redactMatch(tt.input)
		if got != tt.want {
			t.Errorf("redactMatch(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
