package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newMeshTestManager creates a minimal derpManager for unit-testing mesh route resolution.
func newMeshTestManager(backendURL, clusterID, agentToken string) *derpManager {
	return &derpManager{
		agent: &PrysmAgent{
			BackendURL: backendURL,
			ClusterID:  clusterID,
			AgentToken: agentToken,
		},
		meshRoutesCache:    make(map[int]struct{ ServiceName string; ServicePort int }),
		meshRouteSlugCache: make(map[string]struct{ ServiceName string; ServicePort int }),
	}
}

func TestHandleRouteSetup_SlugResolution(t *testing.T) {
	// Backend mock that returns mesh routes.
	meshRoutes := []struct {
		ExternalPort int    `json:"external_port"`
		ServiceName  string `json:"service_name"`
		ServicePort  int    `json:"service_port"`
		Slug         string `json:"slug"`
	}{
		{30002, "api", 8080, "apifrank"},
		{30003, "web", 3000, "myapi"},
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"routes": meshRoutes})
	}))
	defer backend.Close()

	tests := []struct {
		name     string
		address  string
		wantDial string // expected resolved address; empty means "not found"
	}{
		{
			name:     "slug via .mesh path",
			address:  "apifrank.frank.mesh:80",
			wantDial: "api.default.svc.cluster.local:8080",
		},
		{
			name:     "slug via .mesh port ignored",
			address:  "apifrank.frank.mesh:30002",
			wantDial: "api.default.svc.cluster.local:8080",
		},
		{
			name:     "different slug via .mesh",
			address:  "myapi.cluster1.mesh:443",
			wantDial: "web.default.svc.cluster.local:3000",
		},
		{
			name:     "unknown slug via .mesh returns empty",
			address:  "unknown.frank.mesh:80",
			wantDial: "",
		},
		{
			name:     "non-.mesh host returns empty",
			address:  "example.com:8080",
			wantDial: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMeshTestManager(backend.URL, "5", "test-token")

			got := resolveAddressForTest(m, tt.address)
			if got != tt.wantDial {
				t.Errorf("resolve(%q) = %q, want %q", tt.address, got, tt.wantDial)
			}
		})
	}
}

// resolveAddressForTest mirrors the slug-only resolution logic from handleRouteSetup
// without actually dialing, to test the resolution branch in isolation.
func resolveAddressForTest(m *derpManager, targetAddress string) string {
	idx := strings.LastIndex(targetAddress, ":")
	if idx < 0 {
		return ""
	}
	host := targetAddress[:idx]

	if strings.HasSuffix(host, ".mesh") {
		parts := strings.Split(strings.TrimSuffix(host, ".mesh"), ".")
		if len(parts) >= 1 && parts[0] != "" {
			if svcAddr := m.resolveMeshRouteBySlug(parts[0]); svcAddr != "" {
				return svcAddr
			}
		}
		return ""
	}

	return ""
}

func TestResolveMeshRouteBySlug(t *testing.T) {
	callCount := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(map[string]interface{}{
			"routes": []map[string]interface{}{
				{"external_port": 30001, "service_name": "api", "service_port": 8080, "slug": "myapi"},
				{"external_port": 30002, "service_name": "web", "service_port": 3000, "slug": "myweb"},
			},
		})
	}))
	defer backend.Close()

	m := newMeshTestManager(backend.URL, "1", "tok")

	t.Run("cache miss triggers fetch then resolves", func(t *testing.T) {
		callCount = 0
		got := m.resolveMeshRouteBySlug("myapi")
		if got != "api.default.svc.cluster.local:8080" {
			t.Errorf("got %q, want api.default.svc.cluster.local:8080", got)
		}
		if callCount == 0 {
			t.Error("expected backend fetch on cache miss")
		}
	})

	t.Run("cache hit returns immediately", func(t *testing.T) {
		before := callCount
		got := m.resolveMeshRouteBySlug("myweb")
		if got != "web.default.svc.cluster.local:3000" {
			t.Errorf("got %q, want web.default.svc.cluster.local:3000", got)
		}
		if callCount != before {
			t.Error("expected no backend fetch on cache hit")
		}
	})

	t.Run("unknown slug returns empty", func(t *testing.T) {
		got := m.resolveMeshRouteBySlug("nonexistent")
		if got != "" {
			t.Errorf("got %q, want empty string for unknown slug", got)
		}
	})

	t.Run("cache expires after 2 minutes", func(t *testing.T) {
		// Manually expire the cache.
		m.meshRoutesMu.Lock()
		m.meshRoutesAt = time.Now().Add(-3 * time.Minute)
		m.meshRoutesMu.Unlock()

		before := callCount
		m.resolveMeshRouteBySlug("myapi")
		if callCount == before {
			t.Error("expected refetch after cache expiry")
		}
	})
}

func TestResolveMeshRoutePort(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"routes": []map[string]interface{}{
				{"external_port": 30001, "service_name": "api", "service_port": 8080, "slug": "myapi"},
			},
		})
	}))
	defer backend.Close()

	m := newMeshTestManager(backend.URL, "1", "tok")

	t.Run("port lookup returns correct service", func(t *testing.T) {
		got := m.resolveMeshRoutePort(30001)
		if got != "api.default.svc.cluster.local:8080" {
			t.Errorf("got %q, want api.default.svc.cluster.local:8080", got)
		}
	})

	t.Run("unknown port returns empty", func(t *testing.T) {
		got := m.resolveMeshRoutePort(99999)
		if got != "" {
			t.Errorf("got %q, want empty for unknown port", got)
		}
	})

	t.Run("cache shared with slug resolution", func(t *testing.T) {
		// After port fetch, slug cache should be populated too.
		got := m.resolveMeshRouteBySlug("myapi")
		if got != "api.default.svc.cluster.local:8080" {
			t.Errorf("slug cache got %q, want api.default.svc.cluster.local:8080", got)
		}
	})

	t.Run("backend unreachable returns empty", func(t *testing.T) {
		mBad := newMeshTestManager("http://127.0.0.1:1", "1", "tok")
		got := mBad.resolveMeshRoutePort(30001)
		if got != "" {
			t.Errorf("got %q, want empty when backend unreachable", got)
		}
	})
}

func TestResolveMeshRoutePort_Concurrency(t *testing.T) {
	var mu sync.Mutex
	callCount := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"routes": []map[string]interface{}{
				{"external_port": 30001, "service_name": "api", "service_port": 8080, "slug": "myapi"},
			},
		})
	}))
	defer backend.Close()

	m := newMeshTestManager(backend.URL, "1", "tok")

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.resolveMeshRoutePort(30001)
		}()
	}
	wg.Wait()

	// Should resolve without panics or data races.
	got := m.resolveMeshRoutePort(30001)
	if got != "api.default.svc.cluster.local:8080" {
		t.Errorf("concurrent resolve got %q", got)
	}
}
