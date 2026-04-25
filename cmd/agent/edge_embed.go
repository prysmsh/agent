package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// embedClient calls prysm-ai's /embed/text endpoint to get vector embeddings.
type embedClient struct {
	baseURL    string
	model      string
	httpClient *http.Client
}

func newEmbedClient(baseURL, model string) *embedClient {
	if model == "" {
		model = "minilm"
	}
	return &embedClient{
		baseURL:    baseURL,
		model:      model,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// embed sends text to prysm-ai and returns a vector.
func (c *embedClient) embed(text string) []float32 {
	body, _ := json.Marshal(map[string]string{"text": text, "model": c.model})
	req, err := http.NewRequest("POST", c.baseURL+"/embed/text", bytes.NewReader(body))
	if err != nil {
		log.Printf("ai-waf: embed request creation failed: %v", err)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Organization-ID", "0")
	req.Header.Set("X-User-ID", "0")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("ai-waf: embed request failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("ai-waf: embed returned %d", resp.StatusCode)
		return nil
	}

	var result struct {
		Vector []float32 `json:"vector"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("ai-waf: embed decode failed: %v", err)
		return nil
	}

	return result.Vector
}

// seedAttackVectors embeds all attack seed patterns and inserts them into warp.
func seedAttackVectors(ec *embedClient, vc *warpVectorClient) error {
	// Check if collection exists, create if not
	createBody, _ := json.Marshal(map[string]any{
		"name":       wafAttackCollection,
		"dimensions": 768,
		"distance":   "cosine",
	})
	resp, err := vc.httpClient.Post(
		vc.baseURL+"/api/v1/vectors/collections",
		"application/json",
		bytes.NewReader(createBody),
	)
	if err != nil {
		return fmt.Errorf("create collection: %w", err)
	}
	resp.Body.Close()

	// Embed and insert each attack seed
	type point struct {
		ID      uint64         `json:"id"`
		Vector  []float32      `json:"vector"`
		Payload map[string]any `json:"payload,omitempty"`
	}

	var points []point
	for i, seed := range owasp2025Seeds {
		vec := ec.embed(seed.Pattern)
		if vec == nil {
			log.Printf("ai-waf: failed to embed seed %d: %s", i, seed.Pattern)
			continue
		}
		points = append(points, point{
			ID:     uint64(i + 1),
			Vector: vec,
			Payload: map[string]any{
				"threat_type": seed.ThreatType,
				"pattern":     seed.Pattern,
			},
		})
	}

	if len(points) == 0 {
		return fmt.Errorf("no seeds embedded successfully")
	}

	insertBody, _ := json.Marshal(map[string]any{"points": points})
	resp, err = vc.httpClient.Post(
		vc.baseURL+"/api/v1/vectors/collections/"+wafAttackCollection+"/points",
		"application/json",
		bytes.NewReader(insertBody),
	)
	if err != nil {
		return fmt.Errorf("insert seeds: %w", err)
	}
	resp.Body.Close()

	log.Printf("ai-waf: seeded %d attack vectors into %s", len(points), wafAttackCollection)
	return nil
}
