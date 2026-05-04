package main

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestDockerClient starts an httptest.Server and returns a DockerClient pointing at it.
// The caller is responsible for closing the server after the test.
func newTestDockerClient(handler http.Handler) (*DockerClient, *httptest.Server) {
	srv := httptest.NewServer(handler)
	dc := &DockerClient{
		client:  srv.Client(),
		baseURL: srv.URL,
	}
	return dc, srv
}

// newTestEngineWithDocker creates a SysscriptEngine with the given DockerClient wired in.
func newTestEngineWithDocker(dc *DockerClient) *SysscriptEngine {
	return &SysscriptEngine{
		Entitlements: &Entitlements{AllowContainers: true},
		cm:           &ConfigManager{},
		dockerClient: dc,
	}
}

// TestContainersList verifies that a single container is returned and fields are mapped.
func TestContainersList(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/json") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode([]DockerContainer{
				{Id: "abc123", Names: []string{"/mycontainer"}, Image: "nginx:latest", State: "running"},
			})
			return
		}
		http.NotFound(w, r)
	})

	dc, srv := newTestDockerClient(handler)
	defer srv.Close()

	engine := newTestEngineWithDocker(dc)
	out, err := engine.Execute(`
containers = sys.containers.list()
print(len(containers))
`)
	if err != nil {
		t.Fatalf("containersList unexpected error: %v", err)
	}
	if strings.TrimSpace(out) != "1" {
		t.Errorf("expected output '1', got %q", out)
	}
}

// TestContainersListEmpty verifies that an empty Docker response returns empty list.
func TestContainersListEmpty(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/containers/json") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[]"))
			return
		}
		http.NotFound(w, r)
	})

	dc, srv := newTestDockerClient(handler)
	defer srv.Close()

	engine := newTestEngineWithDocker(dc)
	out, err := engine.Execute(`
containers = sys.containers.list()
print(len(containers))
`)
	if err != nil {
		t.Fatalf("containersList empty unexpected error: %v", err)
	}
	if strings.TrimSpace(out) != "0" {
		t.Errorf("expected output '0', got %q", out)
	}
}

// TestContainersListDockerDown verifies that Docker unavailability returns empty list per D-02.
func TestContainersListDockerDown(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	})

	dc, srv := newTestDockerClient(handler)
	defer srv.Close()

	engine := newTestEngineWithDocker(dc)
	out, err := engine.Execute(`
containers = sys.containers.list()
print(len(containers))
`)
	if err != nil {
		t.Fatalf("containersList Docker-down should not propagate error to Starlark: %v", err)
	}
	if strings.TrimSpace(out) != "0" {
		t.Errorf("expected empty list (0) on Docker down, got %q", out)
	}
}

// TestContainersStats verifies CPU% and Mem% are correctly computed from known raw values.
func TestContainersStats(t *testing.T) {
	// Craft a stats payload where:
	// cpuDelta = 200000000 - 100000000 = 100000000
	// sysDelta  = 2000000000 - 1000000000 = 1000000000
	// onlineCPUs = 2
	// cpuPct = (100000000 / 1000000000) * 2 * 100 = 20.0
	// memPct = 512 / 1024 * 100 = 50.0
	raw := DockerStatsResponse{}
	raw.CPUStats.CPUUsage.TotalUsage = 200000000
	raw.CPUStats.SystemCPUUsage = 2000000000
	raw.CPUStats.OnlineCPUs = 2
	raw.PreCPUStats.CPUUsage.TotalUsage = 100000000
	raw.PreCPUStats.SystemCPUUsage = 1000000000
	raw.MemoryStats.Usage = 512
	raw.MemoryStats.Limit = 1024
	raw.Networks = map[string]struct {
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
	}{
		"eth0": {RxBytes: 1000, TxBytes: 500},
		"eth1": {RxBytes: 2000, TxBytes: 800},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/stats") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(raw)
			return
		}
		http.NotFound(w, r)
	})

	dc, srv := newTestDockerClient(handler)
	defer srv.Close()

	stats, err := dc.GetContainerStats("abc123")
	if err != nil {
		t.Fatalf("GetContainerStats error: %v", err)
	}

	wantCPU := 20.0
	if math.Abs(stats.CpuPct-wantCPU) > 0.01 {
		t.Errorf("CpuPct: want %.2f, got %.2f", wantCPU, stats.CpuPct)
	}
	wantMem := 50.0
	if math.Abs(stats.MemPct-wantMem) > 0.01 {
		t.Errorf("MemPct: want %.2f, got %.2f", wantMem, stats.MemPct)
	}
	if stats.RxBytes != 3000 {
		t.Errorf("RxBytes: want 3000, got %d", stats.RxBytes)
	}
	if stats.TxBytes != 1300 {
		t.Errorf("TxBytes: want 1300, got %d", stats.TxBytes)
	}
}

// TestContainersStatsStreamFalse verifies that the stats request URL contains stream=false (T-03-07).
func TestContainersStatsStreamFalse(t *testing.T) {
	var capturedURL string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DockerStatsResponse{})
	})

	dc, srv := newTestDockerClient(handler)
	defer srv.Close()

	_, _ = dc.GetContainerStats("abc123")

	if !strings.Contains(capturedURL, "stream=false") {
		t.Errorf("expected stream=false in query, got %q", capturedURL)
	}
}

// TestContainersStop verifies that a 204 response from Docker maps to success=True.
func TestContainersStop(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/stop") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})

	dc, srv := newTestDockerClient(handler)
	defer srv.Close()

	engine := newTestEngineWithDocker(dc)
	out, err := engine.Execute(`
result = sys.containers.stop("abc123")
print(result["success"])
`)
	if err != nil {
		t.Fatalf("containersStop error: %v", err)
	}
	if strings.TrimSpace(out) != "True" {
		t.Errorf("expected 'True', got %q", out)
	}
}

// TestContainersStart verifies that a 204 response from Docker maps to success=True.
func TestContainersStart(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/start") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})

	dc, srv := newTestDockerClient(handler)
	defer srv.Close()

	engine := newTestEngineWithDocker(dc)
	out, err := engine.Execute(`
result = sys.containers.start("abc123")
print(result["success"])
`)
	if err != nil {
		t.Fatalf("containersStart error: %v", err)
	}
	if strings.TrimSpace(out) != "True" {
		t.Errorf("expected 'True', got %q", out)
	}
}

// TestContainersRestart verifies that a 204 response from Docker maps to success=True.
func TestContainersRestart(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/restart") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})

	dc, srv := newTestDockerClient(handler)
	defer srv.Close()

	engine := newTestEngineWithDocker(dc)
	out, err := engine.Execute(`
result = sys.containers.restart("abc123")
print(result["success"])
`)
	if err != nil {
		t.Fatalf("containersRestart error: %v", err)
	}
	if strings.TrimSpace(out) != "True" {
		t.Errorf("expected 'True', got %q", out)
	}
}

// TestContainerIDValidation verifies isValidContainerID enforces the allowlist (T-03-06).
func TestContainerIDValidation(t *testing.T) {
	cases := []struct {
		id    string
		valid bool
	}{
		{"", false},
		{"abc123", true},
		{"../../../etc", false}, // path traversal: contains /
		{"my-container.1", true},
		{"valid_ID-here.ok", true},
		{strings.Repeat("a", 129), false}, // too long
		{"has space", false},
		{"has/slash", false},
	}

	for _, tc := range cases {
		got := isValidContainerID(tc.id)
		if got != tc.valid {
			t.Errorf("isValidContainerID(%q) = %v, want %v", tc.id, got, tc.valid)
		}
	}
}
