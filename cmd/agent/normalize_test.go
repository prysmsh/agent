package main

import (
	"testing"
)

func TestNormalizePayload_URLDecode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"single encoded quote", "%27", "'"},
		{"double encoded quote", "%2527", "'"},
		{"url encoded union select", "%27%20union%20select", "' union select"},
		{"plus as space", "a+b+c", "a b c"},
		{"mixed encoding", "test%3Cscript%3E", "test<script>"},
		{"partial percent", "100%", "100%"},
		{"no encoding", "hello world", "hello world"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(NormalizePayload([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("NormalizePayload(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizePayload_HTMLEntityDecode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"hex entity", "&#x27;", "'"},
		{"decimal entity", "&#39;", "'"},
		{"named entity amp", "&amp;", "&"},
		{"named entity lt", "&lt;", "<"},
		{"named entity gt", "&gt;", ">"},
		{"named entity quot", "&quot;", "\""},
		{"xss via entities", "&lt;script&gt;alert(1)&lt;/script&gt;", "<script>alert(1)</script>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(NormalizePayload([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("NormalizePayload(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizePayload_NullByteRemoval(t *testing.T) {
	input := "un\x00io\x00n sel\x00ect"
	got := string(NormalizePayload([]byte(input)))
	want := "union select"
	if got != want {
		t.Errorf("NormalizePayload(with nulls) = %q, want %q", got, want)
	}
}

func TestNormalizePayload_UnicodeFullwidth(t *testing.T) {
	// Fullwidth 'S' is U+FF33, fullwidth 'E' is U+FF25, etc.
	// \uff33\uff25\uff2c\uff25\uff23\uff34 = "SELECT" in fullwidth
	input := "\uff33\uff25\uff2c\uff25\uff23\uff34"
	got := string(NormalizePayload([]byte(input)))
	want := "select" // lowercased after normalization
	if got != want {
		t.Errorf("NormalizePayload(fullwidth) = %q, want %q", got, want)
	}
}

func TestNormalizePayload_CaseInsensitive(t *testing.T) {
	input := "UNION SELECT"
	got := string(NormalizePayload([]byte(input)))
	want := "union select"
	if got != want {
		t.Errorf("NormalizePayload(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizePayload_Combined(t *testing.T) {
	// Double-encoded + null bytes + uppercase
	input := "%2527%20UNI%00ON%20SELECT"
	got := string(NormalizePayload([]byte(input)))
	want := "' union select"
	if got != want {
		t.Errorf("NormalizePayload(%q) = %q, want %q", input, got, want)
	}
}

func TestNormalizePayload_Empty(t *testing.T) {
	got := NormalizePayload(nil)
	if got != nil {
		t.Errorf("NormalizePayload(nil) = %v, want nil", got)
	}

	got = NormalizePayload([]byte{})
	if len(got) != 0 {
		t.Errorf("NormalizePayload(empty) = %v, want empty", got)
	}
}

func TestURLDecode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"%41%42%43", "ABC"},
		{"%2f%2e%2e%2f", "/../"},
		{"%00", "\x00"},
		{"no encoding", "no encoding"},
		{"%ZZ", "%ZZ"}, // invalid hex - pass through
	}

	for _, tt := range tests {
		got := urlDecode(tt.input)
		if got != tt.want {
			t.Errorf("urlDecode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestHTMLEntityDecode(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"&#x41;", "A"},
		{"&#65;", "A"},
		{"&amp;&lt;&gt;", "&<>"},
		{"no entities", "no entities"},
		{"&invalid;", "&invalid;"}, // unknown named entity - pass through
	}

	for _, tt := range tests {
		got := htmlEntityDecode(tt.input)
		if got != tt.want {
			t.Errorf("htmlEntityDecode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func BenchmarkNormalizePayload(b *testing.B) {
	data := []byte("%27%20UNION%20SELECT%20*%20FROM%20users%20WHERE%20id%3D1%20--%20")
	for i := 0; i < b.N; i++ {
		NormalizePayload(data)
	}
}
