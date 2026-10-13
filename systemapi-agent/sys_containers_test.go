package main

import (
	"encoding/binary"
	"encoding/json"
	"io"
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
		{"..", false},
	}

	for _, tc := range cases {
		got := isValidContainerID(tc.id)
		if got != tc.valid {
			t.Errorf("isValidContainerID(%q) = %v, want %v", tc.id, got, tc.valid)
		}
	}
}

func dockerFrame(stream byte, payload string) []byte {
	buf := make([]byte, 8+len(payload))
	buf[0] = stream
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(payload)))
	copy(buf[8:], payload)
	return buf
}

func TestContainersRunBuildsHostConfig(t *testing.T) {
	var createBody []byte
	var methods []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/containers/create"):
			body, err := io.ReadAll(io.LimitReader(r.Body, int64(dockerBodyCap)+1))
			if err != nil {
				t.Error(err)
			}
			if len(body) > dockerBodyCap {
				t.Error("create body exceeds cap")
			}
			createBody = body
			w.WriteHeader(http.StatusCreated)
			if _, err := w.Write([]byte(`{"Id":"abc123"}`)); err != nil {
				t.Error(err)
			}
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/start"):
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})
	dc, srv := newTestDockerClient(handler)
	defer srv.Close()
	engine := newTestEngineWithDocker(dc)
	engine.Entitlements.AllowImages = []string{"nginx:latest"}
	out, err := engine.Execute("id = sys.containers.run(\"nginx:latest\")\nprint(id)\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "abc123" {
		t.Fatalf("%q", out)
	}
	raw := string(createBody)
	if strings.Contains(raw, "docker.sock") || strings.Contains(raw, `"Privileged":true`) {
		t.Fatal(raw)
	}
	if !strings.Contains(raw, `"Privileged":false`) || !strings.Contains(raw, `"Binds":null`) || !strings.Contains(raw, `"Mounts":null`) {
		t.Fatal(raw)
	}
	var body struct {
		HostConfig struct {
			Privileged  bool
			NetworkMode string
			PidMode     string
			Binds       []string
			Mounts      []string
			CapDrop     []string
			SecurityOpt []string
		}
	}
	if err := json.Unmarshal(createBody, &body); err != nil {
		t.Fatal(err)
	}
	if body.HostConfig.Privileged || body.HostConfig.NetworkMode != "bridge" || body.HostConfig.PidMode != "" || body.HostConfig.Binds != nil || body.HostConfig.Mounts != nil {
		t.Fatalf("%+v", body.HostConfig)
	}
	if len(body.HostConfig.CapDrop) != 1 || body.HostConfig.CapDrop[0] != "ALL" || !strings.Contains(strings.Join(body.HostConfig.SecurityOpt, ","), "no-new-privileges") {
		t.Fatalf("%+v", body.HostConfig)
	}
	if strings.Contains(strings.Join(methods, "\n"), "DELETE") {
		t.Fatal(methods)
	}
}

func TestContainersRunStartFailureDoesNotDelete(t *testing.T) {
	startHits := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			t.Error("delete after failed start")
		}
		if strings.HasSuffix(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"Id":"abc123"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/start") {
			startHits++
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.NotFound(w, r)
	})
	dc, srv := newTestDockerClient(handler)
	defer srv.Close()
	engine := newTestEngineWithDocker(dc)
	engine.Entitlements.AllowImages = []string{"nginx:latest"}
	_, err := engine.Execute("sys.containers.run(\"nginx:latest\")\n")
	if err == nil || startHits != 1 {
		t.Fatalf("err=%v startHits=%d", err, startHits)
	}
}

func TestContainersRunRejectsBadCreateID(t *testing.T) {
	startHits := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/start") {
			startHits++
		}
		if strings.HasSuffix(r.URL.Path, "/containers/create") {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"Id":".."}`))
			return
		}
		http.NotFound(w, r)
	})
	dc, srv := newTestDockerClient(handler)
	defer srv.Close()
	engine := newTestEngineWithDocker(dc)
	engine.Entitlements.AllowImages = []string{"nginx:latest"}
	_, err := engine.Execute("sys.containers.run(\"nginx:latest\")\n")
	if err == nil || !strings.Contains(err.Error(), "invalid container id") || startHits != 0 {
		t.Fatalf("err=%v startHits=%d", err, startHits)
	}
}

func TestContainersRunPolicyBeforeHTTP(t *testing.T) {
	hits := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusCreated)
	})
	dc, srv := newTestDockerClient(handler)
	defer srv.Close()
	engine := newTestEngineWithDocker(dc)
	engine.Entitlements.AllowImages = []string{"*"}
	_, err := engine.Execute("sys.containers.run(\"nginx:latest\")\n")
	if err == nil || !strings.Contains(err.Error(), "image not allowed") || hits != 0 {
		t.Fatalf("err=%v hits=%d", err, hits)
	}
	_, err = engine.Execute("sys.containers.run(\"nginx:latest\", (\"echo\",))\n")
	if err == nil || hits != 0 {
		t.Fatalf("tuple err=%v hits=%d", err, hits)
	}
}

func TestContainersRunNilClient(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowContainers: true, AllowImages: []string{"nginx:latest"}})
	_, err := engine.Execute("sys.containers.run(\"nginx:latest\")\n")
	if err == nil || !strings.Contains(err.Error(), "docker client not initialized") {
		t.Fatal(err)
	}
}

func TestContainersInspectAndLogs(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/json") {
			w.Write([]byte(`{"Id":"abc123","Name":"/mycontainer","Config":{"Image":"nginx:latest","Env":["SECRET=nope"]},"State":{"Status":"running"}}`))
			return
		}
		if strings.Contains(r.URL.Path, "/logs") {
			w.Write(dockerFrame(1, "hello"))
			return
		}
		http.NotFound(w, r)
	})
	dc, srv := newTestDockerClient(handler)
	defer srv.Close()
	engine := newTestEngineWithDocker(dc)
	out, err := engine.Execute("info = sys.containers.inspect(\"abc123\")\nprint(info[\"id\"])\nprint(info[\"name\"])\nprint(info[\"image\"])\nprint(info[\"state\"])\nprint(\"env\" in info)\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "abc123") || !strings.Contains(out, "mycontainer") || !strings.Contains(out, "nginx:latest") || !strings.Contains(out, "running") || !strings.Contains(out, "False") || strings.Contains(out, "SECRET") {
		t.Fatalf("%q", out)
	}
	out, err = engine.Execute("print(sys.containers.logs(\"abc123\"))\n")
	if err != nil || strings.TrimSpace(out) != "hello" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestContainersExecAndBadID(t *testing.T) {
	hits := 0
	startHits := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if strings.HasSuffix(r.URL.Path, "/exec") && r.Method == http.MethodPost && !strings.Contains(r.URL.Path, "/exec/") {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"Id":"abc"}`))
			return
		}
		if strings.Contains(r.URL.Path, "/exec/") && strings.HasSuffix(r.URL.Path, "/start") {
			startHits++
			w.Write(dockerFrame(1, "hello"))
			return
		}
		http.NotFound(w, r)
	})
	dc, srv := newTestDockerClient(handler)
	defer srv.Close()
	engine := newTestEngineWithDocker(dc)
	out, err := engine.Execute("print(sys.containers.exec(\"abc123\", [\"echo\", \"hi\"]))\n")
	if err != nil || strings.TrimSpace(out) != "hello" || startHits != 1 {
		t.Fatalf("%q %v start=%d", out, err, startHits)
	}
	before := hits
	_, err = engine.Execute("sys.containers.exec(\"../x\", [\"echo\"])\n")
	if err == nil || !strings.Contains(err.Error(), "invalid container id") || hits != before {
		t.Fatalf("err=%v hits=%d before=%d", err, hits, before)
	}
}

func TestContainersExecRejectsBadExecID(t *testing.T) {
	startHits := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/start") {
			startHits++
		}
		if strings.HasSuffix(r.URL.Path, "/exec") {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"Id":".."}`))
			return
		}
		http.NotFound(w, r)
	})
	dc, srv := newTestDockerClient(handler)
	defer srv.Close()
	engine := newTestEngineWithDocker(dc)
	_, err := engine.Execute("sys.containers.exec(\"abc123\", [\"echo\"])\n")
	if err == nil || !strings.Contains(err.Error(), "invalid exec id") || startHits != 0 {
		t.Fatalf("err=%v start=%d", err, startHits)
	}
}

func TestDockerStreamHelpers(t *testing.T) {
	if _, err := demuxDocker([]byte{1, 0, 0, 0, 0, 0, 0, 1}); err == nil || !strings.Contains(err.Error(), "docker stream: short frame") {
		t.Fatal(err)
	}
	frame := append(dockerFrame(3, "skip"), dockerFrame(1, "ok")...)
	got, err := demuxDocker(frame)
	if err != nil || got != "ok" {
		t.Fatalf("%q %v", got, err)
	}
	body, err := parseDockerHTTP([]byte("HTTP/1.1 200 OK\r\n\r\nhello"))
	if err != nil || string(body) != "hello" {
		t.Fatalf("%q %v", body, err)
	}
	if _, err := parseDockerHTTP([]byte("HTTP/1.1 500 ERR\r\n\r\nx")); err == nil {
		t.Fatal("accepted 500")
	}
}
