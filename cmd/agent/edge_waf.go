package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func fingerprint(r *http.Request) string {
	var b strings.Builder
	b.WriteString(r.Method)
	b.WriteByte(' ')
	b.WriteString(r.URL.Path)

	ua := r.UserAgent()
	if ua != "" {
		b.WriteString(" ua:")
		b.WriteString(uaFamily(ua))
	}

	ct := r.Header.Get("Content-Type")
	if ct != "" {
		if idx := strings.Index(ct, ";"); idx > 0 {
			ct = ct[:idx]
		}
		b.WriteString(" ct:")
		b.WriteString(strings.TrimSpace(ct))
	}

	b.WriteString(" len:")
	b.WriteString(bodySizeBucket(r.ContentLength))

	if keys := queryKeys(r); len(keys) > 0 {
		b.WriteString(" q:")
		b.WriteString(strings.Join(keys, ","))
	}

	return b.String()
}

func uaFamily(ua string) string {
	ua = strings.ToLower(ua)
	tools := []string{"sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster", "wfuzz", "hydra", "curl", "wget", "python-requests", "go-http-client", "httpie"}
	for _, t := range tools {
		if strings.Contains(ua, t) {
			return t
		}
	}
	browsers := []string{"chrome", "firefox", "safari", "edge", "opera"}
	for _, br := range browsers {
		if strings.Contains(ua, br) {
			return br
		}
	}
	if idx := strings.IndexAny(ua, "/ "); idx > 0 {
		return ua[:idx]
	}
	if len(ua) > 20 {
		return ua[:20]
	}
	return ua
}

func bodySizeBucket(contentLength int64) string {
	switch {
	case contentLength <= 0:
		return "empty"
	case contentLength < 1024:
		return "small"
	case contentLength < 10240:
		return "medium"
	case contentLength < 102400:
		return "large"
	default:
		return "huge"
	}
}

func queryKeys(r *http.Request) []string {
	q := r.URL.Query()
	if len(q) == 0 {
		return nil
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

const (
	wafAttackCollection    = "edge_attacks"
	wafSimilarityThreshold = float32(0.85)
)

type warpVectorClient struct {
	baseURL    string
	httpClient *http.Client
}

func newWarpVectorClient(baseURL string) *warpVectorClient {
	return &warpVectorClient{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

type vectorSearchRequest struct {
	Vector []float32 `json:"vector"`
	TopK   int       `json:"top_k"`
}

type vectorSearchResponse struct {
	Points []struct {
		ID      uint64         `json:"id"`
		Score   float32        `json:"score"`
		Payload map[string]any `json:"payload"`
	} `json:"points"`
	SearchMs int64 `json:"search_ms"`
}

func (c *warpVectorClient) search(collection string, vector []float32, topK int) (*vectorSearchResponse, error) {
	body, _ := json.Marshal(vectorSearchRequest{Vector: vector, TopK: topK})
	resp, err := c.httpClient.Post(
		c.baseURL+"/api/v1/vectors/collections/"+url.PathEscape(collection)+"/search",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result vectorSearchResponse
	json.NewDecoder(resp.Body).Decode(&result)
	return &result, nil
}

type wafResult struct {
	Blocked    bool
	ThreatType string
	Score      float32
	Latency    time.Duration
}

func checkRequest(r *http.Request, embedFn func(string) []float32, vectorClient *warpVectorClient) wafResult {
	start := time.Now()
	fp := fingerprint(r)

	vec := embedFn(fp)
	if vec == nil {
		return wafResult{Latency: time.Since(start)}
	}

	resp, err := vectorClient.search(wafAttackCollection, vec, 1)
	if err != nil {
		log.Printf("ai-waf: vector search failed: %v", err)
		return wafResult{Latency: time.Since(start)}
	}

	latency := time.Since(start)
	if len(resp.Points) > 0 && resp.Points[0].Score >= wafSimilarityThreshold {
		threatType := "unknown"
		if t, ok := resp.Points[0].Payload["threat_type"].(string); ok {
			threatType = t
		}
		return wafResult{Blocked: true, ThreatType: threatType, Score: resp.Points[0].Score, Latency: latency}
	}
	return wafResult{Latency: latency}
}
