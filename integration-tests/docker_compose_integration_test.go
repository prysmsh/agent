package integration_tests

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
	"os"
)

// TestDockerComposeIntegration tests the complete Docker Compose stack integration
func TestDockerComposeIntegration(t *testing.T) {
	if os.Getenv("PRYSM_K8S_AGENT_INTEGRATION") != "1" {
		t.Skip("skipping docker-compose integration tests; set PRYSM_K8S_AGENT_INTEGRATION=1 to enable")
	}

	// Wait for services to stabilize
	time.Sleep(10 * time.Second)

	t.Run("SaaS Backend Health", func(t *testing.T) {
		resp, err := http.Get("http://localhost:8080/health")
		if err != nil {
			t.Fatalf("Failed to connect to SaaS backend: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		var health map[string]interface{}
		if err := json.Unmarshal(body, &health); err != nil {
			t.Fatalf("Failed to parse health response: %v", err)
		}

		if health["status"] != "healthy" {
			t.Fatalf("Expected healthy status, got %v", health["status"])
		}
	})

	t.Run("Metrics Collection", func(t *testing.T) {
		resp, err := http.Get("http://localhost:8080/metrics")
		if err != nil {
			t.Fatalf("Failed to get metrics: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read metrics response: %v", err)
		}

		var metrics map[string]interface{}
		if err := json.Unmarshal(body, &metrics); err != nil {
			t.Fatalf("Failed to parse metrics response: %v", err)
		}

		// Verify essential metrics are present
		requiredMetrics := []string{
			"uptime_seconds",
			"total_requests",
			"database_connected",
			"redis_connected",
			"clusters_total",
			"services_total",
		}

		for _, metric := range requiredMetrics {
			if _, exists := metrics[metric]; !exists {
				t.Errorf("Missing required metric: %s", metric)
			}
		}

		// Verify database and Redis connections
		if metrics["database_connected"] != true {
			t.Error("Database should be connected")
		}

		if metrics["redis_connected"] != true {
			t.Error("Redis should be connected")
		}
	})

	t.Run("DERP Network Status", func(t *testing.T) {
		resp, err := http.Get("http://localhost:8080/api/v1/derp/status")
		if err != nil {
			t.Fatalf("Failed to get DERP status: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read DERP status response: %v", err)
		}

		var status map[string]interface{}
		if err := json.Unmarshal(body, &status); err != nil {
			t.Fatalf("Failed to parse DERP status response: %v", err)
		}

		// Verify DERP status structure
		requiredFields := []string{
			"network_status",
			"total_servers",
			"active_servers",
			"total_clients",
			"regions",
			"mesh_connectivity",
		}

		for _, field := range requiredFields {
			if _, exists := status[field]; !exists {
				t.Errorf("Missing required DERP status field: %s", field)
			}
		}

		// Verify regions is an array (not null)
		if regions, ok := status["regions"].([]interface{}); ok {
			t.Logf("DERP regions: %v", regions)
		} else {
			t.Error("DERP regions should be an array")
		}
	})

	t.Run("DERP Peers Discovery", func(t *testing.T) {
		resp, err := http.Get("http://localhost:8080/api/v1/derp/peers")
		if err != nil {
			t.Fatalf("Failed to get DERP peers: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read DERP peers response: %v", err)
		}

		var peers map[string]interface{}
		if err := json.Unmarshal(body, &peers); err != nil {
			t.Fatalf("Failed to parse DERP peers response: %v", err)
		}

		// Verify peers structure
		if _, exists := peers["peers"]; !exists {
			t.Error("Missing peers field")
		}

		if _, exists := peers["total"]; !exists {
			t.Error("Missing total field")
		}
	})

	t.Run("API Endpoints Accessibility", func(t *testing.T) {
		endpoints := []string{
			"/health",
			"/metrics",
			"/api/v1/clusters",
			"/api/v1/services", 
			"/api/v1/analytics/clusters",
			"/api/v1/analytics/performance",
			"/api/v1/analytics/usage",
			"/api/v1/derp/status",
			"/api/v1/derp/metrics",
			"/api/v1/derp/peers",
		}

		for _, endpoint := range endpoints {
			t.Run(fmt.Sprintf("GET %s", endpoint), func(t *testing.T) {
				resp, err := http.Get("http://localhost:8080" + endpoint)
				if err != nil {
					t.Fatalf("Failed to access %s: %v", endpoint, err)
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					t.Fatalf("Expected status 200 for %s, got %d", endpoint, resp.StatusCode)
				}

				// Verify response is valid JSON
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Failed to read response from %s: %v", endpoint, err)
				}

				var jsonData interface{}
				if err := json.Unmarshal(body, &jsonData); err != nil {
					t.Fatalf("Invalid JSON response from %s: %v", endpoint, err)
				}
			})
		}
	})
}

// TestE2EFullStack tests the complete end-to-end functionality
func TestE2EFullStack(t *testing.T) {
	if os.Getenv("PRYSM_K8S_AGENT_INTEGRATION") != "1" {
		t.Skip("skipping full-stack integration tests; set PRYSM_K8S_AGENT_INTEGRATION=1 to enable")
	}

	// Allow more time for the complete stack to initialize
	time.Sleep(30 * time.Second)

	t.Run("Complete Stack Health Check", func(t *testing.T) {
		// Test SaaS Backend
		resp, err := http.Get("http://localhost:8080/health")
		if err != nil {
			t.Fatalf("SaaS Backend not accessible: %v", err)
		}
		resp.Body.Close()

		// Test UI (if running)
		resp, err = http.Get("http://localhost:3000/")
		if err != nil {
			t.Logf("UI not accessible (may not be running in this test): %v", err)
		} else {
			resp.Body.Close()
			t.Log("UI is accessible")
		}
	})

	t.Run("Agent Registration Flow", func(t *testing.T) {
		// Check if any clusters have registered
		resp, err := http.Get("http://localhost:8080/api/v1/clusters")
		if err != nil {
			t.Fatalf("Failed to get clusters: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read clusters response: %v", err)
		}

		var clusters map[string]interface{}
		if err := json.Unmarshal(body, &clusters); err != nil {
			t.Fatalf("Failed to parse clusters response: %v", err)
		}

		t.Logf("Cluster registration data: %v", clusters)
	})

	t.Run("Service Discovery Flow", func(t *testing.T) {
		// Check if any services have been discovered
		resp, err := http.Get("http://localhost:8080/api/v1/services")
		if err != nil {
			t.Fatalf("Failed to get services: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read services response: %v", err)
		}

		var services map[string]interface{}
		if err := json.Unmarshal(body, &services); err != nil {
			t.Fatalf("Failed to parse services response: %v", err)
		}

		t.Logf("Service discovery data: %v", services)
	})

	t.Run("DERP Network Integration", func(t *testing.T) {
		// Test DERP metrics collection
		resp, err := http.Get("http://localhost:8080/api/v1/derp/metrics")
		if err != nil {
			t.Fatalf("Failed to get DERP metrics: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read DERP metrics response: %v", err)
		}

		var metrics map[string]interface{}
		if err := json.Unmarshal(body, &metrics); err != nil {
			t.Fatalf("Failed to parse DERP metrics response: %v", err)
		}

		// Verify DERP metrics are being collected
		requiredMetrics := []string{
			"total_connections",
			"messages_relayed",
			"bytes_transferred",
			"avg_latency_ms",
			"connection_success_rate",
			"uptime_seconds",
		}

		for _, metric := range requiredMetrics {
			if _, exists := metrics[metric]; !exists {
				t.Errorf("Missing required DERP metric: %s", metric)
			}
		}

		t.Logf("DERP metrics: %v", metrics)
	})

	t.Run("Data Flow Integrity", func(t *testing.T) {
		// Verify that data flows correctly through the system
		// K8s Clusters -> Agents -> Backend -> UI

		// Get initial metrics
		resp, err := http.Get("http://localhost:8080/metrics")
		if err != nil {
			t.Fatalf("Failed to get initial metrics: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read initial metrics: %v", err)
		}

		var initialMetrics map[string]interface{}
		if err := json.Unmarshal(body, &initialMetrics); err != nil {
			t.Fatalf("Failed to parse initial metrics: %v", err)
		}

		initialRequests := initialMetrics["total_requests"].(float64)
		t.Logf("Initial request count: %v", initialRequests)

		// Make a few API calls to generate activity
		time.Sleep(2 * time.Second)
		http.Get("http://localhost:8080/api/v1/clusters")
		http.Get("http://localhost:8080/api/v1/services")
		http.Get("http://localhost:8080/api/v1/derp/status")

		// Get updated metrics
		time.Sleep(1 * time.Second)
		resp, err = http.Get("http://localhost:8080/metrics")
		if err != nil {
			t.Fatalf("Failed to get updated metrics: %v", err)
		}
		defer resp.Body.Close()

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read updated metrics: %v", err)
		}

		var updatedMetrics map[string]interface{}
		if err := json.Unmarshal(body, &updatedMetrics); err != nil {
			t.Fatalf("Failed to parse updated metrics: %v", err)
		}

		updatedRequests := updatedMetrics["total_requests"].(float64)
		t.Logf("Updated request count: %v", updatedRequests)

		// Verify request count increased (metrics are being collected)
		if updatedRequests <= initialRequests {
			t.Error("Request metrics should increase after making API calls")
		}

		// Verify database and Redis are healthy
		if updatedMetrics["database_connected"] != true {
			t.Error("Database connection should be healthy")
		}

		if updatedMetrics["redis_connected"] != true {
			t.Error("Redis connection should be healthy")
		}
	})
}
