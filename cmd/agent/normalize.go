// Package main provides payload normalization for the DPI engine.
// Attackers bypass regex signatures using URL encoding (%27), double encoding
// (%2527), HTML entities (&#x27;), unicode escapes, and null byte injection.
// NormalizePayload decodes these layers before signature matching.
package main

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"
)

// NormalizePayload applies multiple decoding layers to detect obfuscated attacks.
// The original data is preserved for reporting; this returns a decoded copy.
func NormalizePayload(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	s := string(data)

	// 1. URL decode (handles %xx and double-encoded %25xx)
	//    Must happen before null byte removal so %00 is decoded first
	s = urlDecode(s)
	// Second pass catches double-encoded payloads (%2527 → %27 → ')
	s = urlDecode(s)

	// 2. Remove null bytes (null-byte injection bypass)
	s = strings.ReplaceAll(s, "\x00", "")

	// 3. HTML entity decode (&#xNN;, &#NNN;, &name;)
	s = htmlEntityDecode(s)

	// 4. Unicode normalization (fullwidth chars → ASCII)
	s = normalizeUnicode(s)

	// 5. Lowercase for case-insensitive matching
	s = strings.ToLower(s)

	return []byte(s)
}

// urlDecode decodes percent-encoded sequences (%XX).
func urlDecode(s string) string {
	var buf strings.Builder
	buf.Grow(len(s))

	i := 0
	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) {
			h := s[i+1 : i+3]
			if b, err := hex.DecodeString(h); err == nil && len(b) == 1 {
				buf.WriteByte(b[0])
				i += 3
				continue
			}
		}
		if s[i] == '+' {
			buf.WriteByte(' ')
			i++
			continue
		}
		buf.WriteByte(s[i])
		i++
	}
	return buf.String()
}

// htmlEntityDecode decodes HTML numeric and named entities.
func htmlEntityDecode(s string) string {
	var buf strings.Builder
	buf.Grow(len(s))

	i := 0
	for i < len(s) {
		if s[i] == '&' {
			// Try to decode entity
			if decoded, advance := decodeHTMLEntity(s[i:]); advance > 0 {
				buf.WriteString(decoded)
				i += advance
				continue
			}
		}
		buf.WriteByte(s[i])
		i++
	}
	return buf.String()
}

// decodeHTMLEntity decodes a single HTML entity starting with '&'.
// Returns the decoded string and the number of bytes consumed.
func decodeHTMLEntity(s string) (string, int) {
	if len(s) < 3 || s[0] != '&' {
		return "", 0
	}

	// Find the semicolon
	end := strings.IndexByte(s, ';')
	if end < 0 || end > 10 {
		return "", 0
	}

	body := s[1:end]

	// Hex numeric: &#xNN;
	if len(body) >= 3 && body[0] == '#' && (body[1] == 'x' || body[1] == 'X') {
		if n, err := strconv.ParseInt(body[2:], 16, 32); err == nil && n > 0 && n < 0x110000 {
			return string(rune(n)), end + 1
		}
	}

	// Decimal numeric: &#NNN;
	if len(body) >= 2 && body[0] == '#' {
		if n, err := strconv.ParseInt(body[1:], 10, 32); err == nil && n > 0 && n < 0x110000 {
			return string(rune(n)), end + 1
		}
	}

	// Named entities (common ones)
	switch body {
	case "amp":
		return "&", end + 1
	case "lt":
		return "<", end + 1
	case "gt":
		return ">", end + 1
	case "quot":
		return "\"", end + 1
	case "apos":
		return "'", end + 1
	case "nbsp":
		return " ", end + 1
	case "tab":
		return "\t", end + 1
	}

	return "", 0
}

// normalizeUnicode converts fullwidth characters (U+FF01-U+FF5E) to ASCII
// and normalizes overlong UTF-8 sequences.
func normalizeUnicode(s string) string {
	// Quick check: if all ASCII, nothing to do
	if isAllASCII(s) {
		return s
	}

	var buf bytes.Buffer
	buf.Grow(len(s))

	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])

		// Fullwidth ASCII variants (U+FF01 to U+FF5E) → ASCII (0x21 to 0x7E)
		if r >= 0xFF01 && r <= 0xFF5E {
			buf.WriteByte(byte(r - 0xFF01 + 0x21))
		} else if r == 0xFF00 { // Fullwidth space-like
			buf.WriteByte(' ')
		} else if r == utf8.RuneError && size == 1 {
			// Skip invalid UTF-8 bytes (could be overlong encoding attack)
			// fall through
		} else {
			buf.WriteRune(r)
		}

		i += size
	}

	return buf.String()
}

// isAllASCII returns true if s contains only ASCII bytes.
func isAllASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
