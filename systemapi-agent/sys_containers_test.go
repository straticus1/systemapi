package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newTestDockerClient starts an httptest.Server and returns a DockerClient pointing at it.
// The caller is responsible for closing the server after the test.
func newTestDockerClient(handler http.Handler) (*DockerClient, *httptest.Server) {
	srv := httptest.NewServer(handler)
	dc := &DockerClient{
		ctx:     context.Background(),
		client:  srv.Client(),
		baseURL: srv.URL,
	}
	return dc, srv
}

// newTestEngineWithDocker creates a SysscriptEngine with the given DockerClient wired in.
func newTestEngineWithDocker(dc *DockerClient) *SysscriptEngine {
	return &SysscriptEngine{
		ctx:          context.Background(),
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

func TestImageRefValidation(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		ref   string
		valid bool
	}{
		{"nginx", true},
		{"nginx:1.25-alpine", true},
		{"library/nginx:latest", true},
		{"ghcr.io/org/app:v1.2.3", true},
		{"localhost:5000/app", true},
		{"registry.example.com:443/team/app_x:tag", true},
		{"nginx@" + digest, true},
		{"nginx:1@" + digest, true},
		{"", false},
		{"Nginx", false},
		{"nginx:", false},
		{"nginx:-bad", false},
		{"../etc", false},
		{"a/../b", false},
		{"nginx latest", false},
		{"nginx\n", false},
		{"nginx?x=1", false},
		{"nginx#x", false},
		{"/nginx", false},
		{"nginx/", false},
		{"nginx@sha256:short", false},
		{"nginx@md5:" + strings.Repeat("a", 32), false},
		{"--help", false},
		{strings.Repeat("a", 256), false},
	}
	for _, tc := range cases {
		if got := isValidImageRef(tc.ref); got != tc.valid {
			t.Errorf("isValidImageRef(%q) = %v, want %v", tc.ref, got, tc.valid)
		}
	}
}

func TestDockerNameValidation(t *testing.T) {
	cases := []struct {
		name  string
		valid bool
	}{
		{"data", true},
		{"my_vol-1.x", true},
		{"ab", true},
		{"a", false},
		{"", false},
		{"-vol", false},
		{".vol", false},
		{"a..b", false},
		{"a/b", false},
		{"a b", false},
		{"a%2fb", false},
		{strings.Repeat("a", 129), false},
	}
	for _, tc := range cases {
		if got := isValidDockerName(tc.name); got != tc.valid {
			t.Errorf("isValidDockerName(%q) = %v, want %v", tc.name, got, tc.valid)
		}
	}
}

func TestSplitImageRef(t *testing.T) {
	digest := "sha256:" + strings.Repeat("b", 64)
	cases := []struct{ ref, repo, tag string }{
		{"nginx", "nginx", "latest"},
		{"nginx:1.25", "nginx", "1.25"},
		{"localhost:5000/app", "localhost:5000/app", "latest"},
		{"localhost:5000/app:v2", "localhost:5000/app", "v2"},
		{"app@" + digest, "app", digest},
	}
	for _, tc := range cases {
		repo, tag := splitImageRef(tc.ref)
		if repo != tc.repo || tag != tc.tag {
			t.Errorf("splitImageRef(%q) = %q,%q want %q,%q", tc.ref, repo, tag, tc.repo, tc.tag)
		}
	}
}

func TestContainersListings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/v1.41/images/json":
			w.Write([]byte(`[{"Id":"sha256:abc","RepoTags":["nginx:latest","nginx:1"],"Size":42,"Created":7}]`))
		case "/v1.41/volumes":
			w.Write([]byte(`{"Volumes":[{"Name":"data","Driver":"local","Mountpoint":"/var/lib/docker/volumes/data/_data","Scope":"local"}],"Warnings":null}`))
		case "/v1.41/networks":
			w.Write([]byte(`[{"Id":"n1","Name":"bridge","Driver":"bridge","Scope":"local"},{"Id":"n2","Name":"app","Driver":"bridge","Scope":"local"}]`))
		default:
			http.NotFound(w, r)
		}
	})
	dc, srv := newTestDockerClient(handler)
	defer srv.Close()
	engine := newTestEngineWithDocker(dc)
	cases := []struct {
		script string
		want   string
	}{
		{"i = sys.containers.images()\nprint(len(i), i[0]['id'], i[0]['tags'][1], i[0]['size'])\n", "1 sha256:abc nginx:1 42"},
		{"v = sys.containers.volumes()\nprint(len(v), v[0]['name'], v[0]['driver'])\n", "1 data local"},
		{"n = sys.containers.networks()\nprint(len(n), n[1]['name'], n[1]['id'])\n", "2 app n2"},
	}
	for _, tc := range cases {
		out, err := engine.Execute(tc.script)
		if err != nil {
			t.Fatalf("%q: %v", tc.script, err)
		}
		if strings.TrimSpace(out) != tc.want {
			t.Errorf("%q: got %q want %q", tc.script, out, tc.want)
		}
	}
}

func TestContainersListingsBodyCap(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("["))
		w.Write([]byte(strings.Repeat(" ", dockerBodyCap+1)))
		w.Write([]byte("]"))
	})
	dc, srv := newTestDockerClient(handler)
	defer srv.Close()
	engine := newTestEngineWithDocker(dc)
	for _, fn := range []string{"images", "volumes", "networks"} {
		_, err := engine.Execute("sys.containers." + fn + "()\n")
		if err == nil || !strings.Contains(err.Error(), "body exceeds cap") {
			t.Errorf("%s: err=%v", fn, err)
		}
	}
}

func TestContainersPull(t *testing.T) {
	digest := "sha256:" + strings.Repeat("c", 64)
	cases := []struct {
		name      string
		ref       string
		stream    string
		wantImage string
		wantTag   string
		wantErr   string
		wantHits  int
	}{
		{"default tag", "nginx", `{"status":"Pulling"}` + "\n" + `{"status":"Status: Downloaded newer image for nginx:latest"}`, "nginx", "latest", "", 1},
		{"tag", "ghcr.io/org/app:v1", `{"status":"done"}`, "ghcr.io/org/app", "v1", "", 1},
		{"digest", "app@" + digest, `{"status":"done"}`, "app", digest, "", 1},
		{"stream error", "nginx:nope", `{"status":"Pulling"}` + "\n" + `{"error":"manifest unknown","errorDetail":{"message":"manifest unknown"}}`, "nginx", "nope", "manifest unknown", 1},
		{"bad ref traversal", "../x", "", "", "", "invalid image reference", 0},
		{"bad ref query", "nginx?tag=x", "", "", "", "invalid image reference", 0},
		{"bad ref space", "nginx latest", "", "", "", "invalid image reference", 0},
		{"bad ref upper", "NGINX", "", "", "", "invalid image reference", 0},
		{"not granted", "redis", "", "", "", "image not allowed", 0},
		{"other tag not granted", "nginx:1.25", "", "", "", "image not allowed", 0},
		{"other registry not granted", "ghcr.io/org/app:v2", "", "", "", "image not allowed", 0},
		{"digest not granted", "nginx@" + digest, "", "", "", "image not allowed", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := 0
			var gotImage, gotTag, gotAuth string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				if r.Method != http.MethodPost || r.URL.Path != "/v1.41/images/create" {
					http.NotFound(w, r)
					return
				}
				gotImage = r.URL.Query().Get("fromImage")
				gotTag = r.URL.Query().Get("tag")
				gotAuth = r.Header.Get("X-Registry-Auth")
				w.Write([]byte(tc.stream))
			})
			dc, srv := newTestDockerClient(handler)
			defer srv.Close()
			engine := newTestEngineWithDocker(dc)
			engine.Entitlements.AllowImages = []string{"nginx", "ghcr.io/org/app:v1", "app@" + digest, "nginx:nope"}
			out, err := engine.Execute("r = sys.containers.pull(" + strconvQuote(tc.ref) + ")\nprint(r['ref'], r['status'])\n")
			if hits != tc.wantHits {
				t.Fatalf("hits=%d want %d", hits, tc.wantHits)
			}
			if gotAuth != "" {
				t.Fatalf("registry auth sent")
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if gotImage != tc.wantImage || gotTag != tc.wantTag {
				t.Fatalf("fromImage=%q tag=%q", gotImage, gotTag)
			}
			if !strings.HasPrefix(out, tc.ref+" ") {
				t.Fatalf("out=%q", out)
			}
		})
	}
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestContainersRemoveImage(t *testing.T) {
	cases := []struct {
		name      string
		script    string
		status    int
		wantPath  string
		wantForce string
		wantErr   string
		wantHits  int
	}{
		{"plain", `sys.containers.remove_image("nginx:latest")`, 200, "/v1.41/images/nginx:latest", "false", "", 1},
		{"force", `sys.containers.remove_image("ghcr.io/org/app:v1", force=True)`, 200, "/v1.41/images/ghcr.io/org/app:v1", "true", "", 1},
		{"conflict", `sys.containers.remove_image("nginx")`, 409, "/v1.41/images/nginx", "false", "unexpected status 409", 1},
		{"bad ref", `sys.containers.remove_image("../../containers/x")`, 200, "", "", "invalid image reference", 0},
		{"bad ref slash", `sys.containers.remove_image("nginx/")`, 200, "", "", "invalid image reference", 0},
		{"not granted", `sys.containers.remove_image("redis:7")`, 200, "", "", "image not allowed", 0},
		{"other tag not granted", `sys.containers.remove_image("nginx:1.25", force=True)`, 200, "", "", "image not allowed", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := 0
			var gotPath, gotForce string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				if r.Method != http.MethodDelete {
					http.NotFound(w, r)
					return
				}
				gotPath = r.URL.Path
				gotForce = r.URL.Query().Get("force")
				w.WriteHeader(tc.status)
				w.Write([]byte(`[{"Untagged":"x"}]`))
			})
			dc, srv := newTestDockerClient(handler)
			defer srv.Close()
			engine := newTestEngineWithDocker(dc)
			engine.Entitlements.AllowImages = []string{"nginx:latest", "ghcr.io/org/app:v1"}
			_, err := engine.Execute(tc.script + "\n")
			if hits != tc.wantHits {
				t.Fatalf("hits=%d", hits)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v", err)
				}
				return
			}
			if err != nil || gotPath != tc.wantPath || gotForce != tc.wantForce {
				t.Fatalf("err=%v path=%q force=%q", err, gotPath, gotForce)
			}
		})
	}
}

func TestContainersVolumeMutations(t *testing.T) {
	cases := []struct {
		name     string
		script   string
		status   int
		wantReq  string
		wantBody string
		wantErr  string
		wantHits int
	}{
		{"create", `print(sys.containers.create_volume("data_1")["name"])`, 201, "POST /v1.41/volumes/create", `{"Driver":"local","Name":"data_1"}`, "", 1},
		{"remove", `sys.containers.remove_volume("data_1")`, 204, "DELETE /v1.41/volumes/data_1", "", "", 1},
		{"remove in use", `sys.containers.remove_volume("data_1")`, 409, "DELETE /v1.41/volumes/data_1", "", "unexpected status 409", 1},
		{"create bad name slash", `sys.containers.create_volume("a/b")`, 201, "", "", "invalid volume name", 0},
		{"create bad name dots", `sys.containers.create_volume("..")`, 201, "", "", "invalid volume name", 0},
		{"create bad name leading", `sys.containers.create_volume("-x")`, 201, "", "", "invalid volume name", 0},
		{"remove bad name", `sys.containers.remove_volume("../containers")`, 204, "", "", "invalid volume name", 0},
		{"remove empty", `sys.containers.remove_volume("")`, 204, "", "", "invalid volume name", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := 0
			var gotReq, gotBody string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				gotReq = r.Method + " " + r.URL.Path
				b, _ := io.ReadAll(r.Body)
				gotBody = string(b)
				w.WriteHeader(tc.status)
				if r.Method == http.MethodPost {
					w.Write([]byte(`{"Name":"data_1","Driver":"local","Mountpoint":"/m","Scope":"local"}`))
				}
			})
			dc, srv := newTestDockerClient(handler)
			defer srv.Close()
			out, err := newTestEngineWithDocker(dc).Execute(tc.script + "\n")
			if hits != tc.wantHits {
				t.Fatalf("hits=%d", hits)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v", err)
				}
				return
			}
			if err != nil || gotReq != tc.wantReq {
				t.Fatalf("err=%v req=%q", err, gotReq)
			}
			if tc.wantBody != "" && gotBody != tc.wantBody {
				t.Fatalf("body=%q", gotBody)
			}
			if tc.status == 201 && strings.TrimSpace(out) != "data_1" {
				t.Fatalf("out=%q", out)
			}
		})
	}
}

func TestContainersNetworkMutations(t *testing.T) {
	cases := []struct {
		name     string
		script   string
		status   int
		respID   string
		wantReq  string
		wantBody string
		wantErr  string
		wantHits int
	}{
		{"create default driver", `print(sys.containers.create_network("appnet")["id"])`, 201, "abc123", "POST /v1.41/networks/create", `{"CheckDuplicate":true,"Driver":"bridge","Name":"appnet"}`, "", 1},
		{"create overlay", `sys.containers.create_network("appnet", driver="overlay")`, 201, "abc123", "POST /v1.41/networks/create", `{"CheckDuplicate":true,"Driver":"overlay","Name":"appnet"}`, "", 1},
		{"create bad id from daemon", `sys.containers.create_network("appnet")`, 201, "../x", "POST /v1.41/networks/create", "", "invalid network id", 1},
		{"create host driver", `sys.containers.create_network("appnet", driver="host")`, 201, "", "", "", "network driver not allowed", 0},
		{"create macvlan", `sys.containers.create_network("appnet", driver="macvlan")`, 201, "", "", "", "network driver not allowed", 0},
		{"create bad name", `sys.containers.create_network("a b")`, 201, "", "", "", "invalid network name", 0},
		{"create builtin name", `sys.containers.create_network("host")`, 201, "", "", "", "invalid network name", 0},
		{"remove", `sys.containers.remove_network("appnet")`, 204, "", "DELETE /v1.41/networks/appnet", "", "", 1},
		{"remove missing", `sys.containers.remove_network("appnet")`, 404, "", "DELETE /v1.41/networks/appnet", "", "unexpected status 404", 1},
		{"remove builtin", `sys.containers.remove_network("bridge")`, 204, "", "", "", "invalid network name", 0},
		{"remove traversal", `sys.containers.remove_network("../containers/x")`, 204, "", "", "", "invalid network name", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits := 0
			var gotReq, gotBody string
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				gotReq = r.Method + " " + r.URL.Path
				b, _ := io.ReadAll(r.Body)
				gotBody = string(b)
				w.WriteHeader(tc.status)
				if r.Method == http.MethodPost {
					json.NewEncoder(w).Encode(map[string]string{"Id": tc.respID, "Warning": ""})
				}
			})
			dc, srv := newTestDockerClient(handler)
			defer srv.Close()
			out, err := newTestEngineWithDocker(dc).Execute(tc.script + "\n")
			if hits != tc.wantHits {
				t.Fatalf("hits=%d", hits)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v", err)
				}
				return
			}
			if err != nil || gotReq != tc.wantReq {
				t.Fatalf("err=%v req=%q", err, gotReq)
			}
			if tc.wantBody != "" && gotBody != tc.wantBody {
				t.Fatalf("body=%q", gotBody)
			}
			if strings.HasPrefix(tc.script, "print") && strings.TrimSpace(out) != tc.respID {
				t.Fatalf("out=%q", out)
			}
		})
	}
}

func TestContainersNewBuiltinsNilClient(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowContainers: true, AllowImages: []string{"nginx"}})
	for _, script := range []string{
		"sys.containers.images()",
		`sys.containers.pull("nginx")`,
		`sys.containers.remove_image("nginx")`,
		"sys.containers.volumes()",
		`sys.containers.create_volume("data")`,
		`sys.containers.remove_volume("data")`,
		"sys.containers.networks()",
		`sys.containers.create_network("appnet")`,
		`sys.containers.remove_network("appnet")`,
	} {
		_, err := engine.Execute(script + "\n")
		if err == nil || !strings.Contains(err.Error(), "docker client not initialized") {
			t.Errorf("%s: err=%v", script, err)
		}
	}
}

func TestContainersCompose(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(base, "proj")
	other := filepath.Join(base, "proj2")
	empty := filepath.Join(base, "empty")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{proj, other, empty, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{proj, other, outside} {
		if err := os.WriteFile(filepath.Join(d, "compose.yaml"), []byte("services: {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	linkDir := filepath.Join(proj, "link")
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Fatal(err)
	}
	symCompose := filepath.Join(base, "symcompose")
	if err := os.MkdirAll(symCompose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "compose.yaml"), filepath.Join(symCompose, "compose.yaml")); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		action   string
		dir      string
		read     []string
		write    []string
		config   []string
		code     int
		execErr  error
		wantArgv []string
		wantErr  string
	}{
		{"up", "up", proj, []string{proj}, nil, nil, 0, nil, []string{"docker", "compose", "-f", "-", "--project-directory", proj, "up", "-d"}, ""},
		{"down", "down", proj, []string{proj}, nil, nil, 0, nil, []string{"docker", "compose", "-f", "-", "--project-directory", proj, "down"}, ""},
		{"ps", "ps", proj, []string{base}, nil, nil, 0, nil, []string{"docker", "compose", "-f", "-", "--project-directory", proj, "ps"}, ""},
		{"pull nonzero", "pull", proj, []string{"*"}, nil, nil, 3, nil, []string{"docker", "compose", "-f", "-", "--project-directory", proj, "pull"}, ""},
		{"exec failure", "ps", proj, []string{proj}, nil, nil, 0, errors.New("docker not found"), nil, "docker not found"},
		{"bad action", "exec", proj, []string{proj}, nil, nil, 0, nil, nil, "compose action not allowed"},
		{"bad action run", "run", proj, []string{proj}, nil, nil, 0, nil, nil, "compose action not allowed"},
		{"bad action flag", "--file=/etc/x", proj, []string{proj}, nil, nil, 0, nil, nil, "compose action not allowed"},
		{"bad action empty", "", proj, []string{proj}, nil, nil, 0, nil, nil, "compose action not allowed"},
		{"relative", "ps", "proj", []string{"*"}, nil, nil, 0, nil, nil, "absolute and clean"},
		{"unclean dots", "ps", proj + "/../proj", []string{"*"}, nil, nil, 0, nil, nil, "absolute and clean"},
		{"trailing slash", "ps", proj + "/", []string{"*"}, nil, nil, 0, nil, nil, "absolute and clean"},
		{"root", "ps", "/", []string{"*"}, nil, nil, 0, nil, nil, "absolute and clean"},
		{"empty", "ps", "", []string{"*"}, nil, nil, 0, nil, nil, "invalid project dir"},
		{"newline", "ps", proj + "\n", []string{"*"}, nil, nil, 0, nil, nil, "invalid project dir"},
		{"no read grant", "ps", proj, nil, nil, nil, 0, nil, nil, "not granted"},
		{"other read grant", "ps", proj, []string{outside}, nil, nil, 0, nil, nil, "not granted"},
		{"prefix boundary", "ps", other, []string{proj}, nil, nil, 0, nil, nil, "not granted"},
		{"write grant covers", "up", proj, []string{proj}, []string{base}, nil, 0, nil, nil, "writable"},
		{"write grant inside", "up", proj, []string{proj}, []string{filepath.Join(proj, "compose")}, nil, 0, nil, nil, "writable"},
		{"write grant star", "up", proj, []string{proj}, []string{"*"}, nil, 0, nil, nil, "writable"},
		{"config write covers", "up", proj, []string{proj}, nil, []string{proj}, 0, nil, nil, "writable"},
		{"symlink escape", "ps", linkDir, []string{proj}, nil, nil, 0, nil, nil, "symlink escape"},
		{"missing dir", "ps", filepath.Join(base, "nope"), []string{base}, nil, nil, 0, nil, nil, "not found"},
		{"no compose file", "ps", empty, []string{empty}, nil, nil, 0, nil, nil, "no compose file"},
		{"symlinked compose file", "ps", symCompose, []string{symCompose}, nil, nil, 0, nil, nil, "no compose file"},
	}
	orig := composeExec
	defer func() { composeExec = orig }()
	const checkedCfg = `{"name":"proj","services":{"web":{"image":"nginx"}}}`
	scriptDeadline := time.Now().Add(time.Minute)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotArgv []string
			var gotDir string
			calls := 0
			composeExec = func(ctx context.Context, dir string, argv []string, stdin string, stdoutOnly bool) (int, string, error) {
				calls++
				// compose runs under the script's own context.
				if d, ok := ctx.Deadline(); !ok || !d.Equal(scriptDeadline) {
					t.Error("not the script's deadline")
				}
				if len(argv) > 4 && argv[4] == "config" {
					want := []string{"docker", "compose", "--project-directory", proj, "config", "--format", "json"}
					if strings.Join(argv, "\x00") != strings.Join(want, "\x00") || !stdoutOnly || dir != proj {
						t.Errorf("config argv=%q stdoutOnly=%v dir=%q", argv, stdoutOnly, dir)
					}
					return 0, checkedCfg, nil
				}
				if stdoutOnly {
					t.Error("action output must include stderr")
				}
				// Every action runs the checked document from stdin.
				if argv[2] != "-f" || argv[3] != "-" || stdin != checkedCfg {
					t.Errorf("argv=%q stdin=%q", argv, stdin)
				}
				gotArgv = argv
				gotDir = dir
				return tc.code, "out:" + argv[len(argv)-1], tc.execErr
			}
			engine := newTestEngine(&Entitlements{AllowContainers: true, AllowImages: []string{"nginx"}, AllowFSRead: tc.read, AllowFSWrite: tc.write, AllowConfigWrite: tc.config})
			ctx, cancel := context.WithDeadline(context.Background(), scriptDeadline)
			defer cancel()
			engine.ctx = ctx
			out, err := engine.Execute("r = sys.containers.compose(" + strconvQuote(tc.action) + ", " + strconvQuote(tc.dir) + ")\nprint(r['exit_code'], r['output'])\n")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v want %q", err, tc.wantErr)
				}
				if tc.execErr == nil && calls != 0 {
					t.Fatalf("exec called on rejected input")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(gotArgv, "\x00") != strings.Join(tc.wantArgv, "\x00") || gotDir != proj {
				t.Fatalf("argv=%q dir=%q", gotArgv, gotDir)
			}
			want := fmt.Sprintf("%d out:%s", tc.code, tc.wantArgv[len(tc.wantArgv)-1])
			if strings.TrimSpace(out) != want {
				t.Fatalf("out=%q want %q", out, want)
			}
		})
	}
}

func TestComposeCapWriter(t *testing.T) {
	w := &capWriter{max: 4}
	for _, s := range []string{"ab", "cdef", "gh"} {
		n, err := w.Write([]byte(s))
		if err != nil || n != len(s) {
			t.Fatalf("n=%d err=%v", n, err)
		}
	}
	if w.buf.String() != "abcd" {
		t.Fatalf("buf=%q", w.buf.String())
	}
}

func TestImageGranted(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		grant []string
		ref   string
		want  bool
	}{
		{[]string{"nginx"}, "nginx", true},
		{[]string{"nginx"}, "nginx:latest", true},
		{[]string{"nginx:latest"}, "nginx", true},
		{[]string{"nginx:latest"}, "nginx:1.25", false},
		{[]string{"nginx:1.25"}, "nginx", false},
		{[]string{"localhost:5000/app"}, "localhost:5000/app:latest", true},
		{[]string{"localhost:5000/app:latest"}, "localhost:5000/app", true},
		{[]string{"localhost:5000/app"}, "localhost:5000/app:v2", false},
		{[]string{"app@" + digest}, "app@" + digest, true},
		{[]string{"app"}, "app@" + digest, false},
		{[]string{"*"}, "nginx", false},
		{[]string{"ngin*"}, "nginx", false},
		{nil, "nginx", false},
	}
	for _, c := range cases {
		if got := imageGranted(c.grant, c.ref); got != c.want {
			t.Errorf("grant=%v ref=%q: got %v want %v", c.grant, c.ref, got, c.want)
		}
	}
}

// fakeCompose answers config with cfg and records the action argv.
func fakeCompose(t *testing.T, cfg string, cfgCode int) *[][]string {
	t.Helper()
	orig := composeExec
	t.Cleanup(func() { composeExec = orig })
	var calls [][]string
	composeExec = func(ctx context.Context, dir string, argv []string, stdin string, stdoutOnly bool) (int, string, error) {
		calls = append(calls, argv)
		if len(argv) > 4 && argv[4] == "config" {
			return cfgCode, cfg, nil
		}
		return 0, "ok", nil
	}
	return &calls
}

func composeProject(t *testing.T, files map[string]string) (string, string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(base, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(proj, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return base, proj
}

func runCompose(proj, action string) error {
	engine := newTestEngine(&Entitlements{AllowContainers: true, AllowImages: []string{"nginx", "app:v1"}, AllowFSRead: []string{proj}})
	_, err := engine.Execute("sys.containers.compose(" + strconvQuote(action) + ", " + strconvQuote(proj) + ")\n")
	return err
}

func TestComposePreflightRefusesHostAccess(t *testing.T) {
	base, proj := composeProject(t, map[string]string{"compose.yaml": "services: {}\n"})
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	// A symlink inside the project dir that points out of it.
	if err := os.Symlink(outside, filepath.Join(proj, "escape")); err != nil {
		t.Fatal(err)
	}
	svc := func(body string) string { return `{"services":{"web":{"image":"nginx",` + body + `}}}` }
	q := func(s string) string { return strconvQuote(s) }
	cases := []struct {
		name, cfg, wantErr string
	}{
		{"privileged", svc(`"privileged":true`), "uses privileged"},
		{"cap_add", svc(`"cap_add":["NET_ADMIN"]`), "uses cap_add"},
		{"devices", svc(`"devices":[{"source":"/dev/sda","target":"/dev/sda","permissions":"rwm"}]`), "uses devices"},
		{"device_cgroup_rules", svc(`"device_cgroup_rules":["c 1:3 mr"]`), "uses device_cgroup_rules"},
		{"security_opt", svc(`"security_opt":["seccomp=unconfined"]`), "uses security_opt"},
		{"pid host", svc(`"pid":"host"`), "uses pid"},
		{"pid container", svc(`"pid":"container:abc"`), "uses pid"},
		{"ipc host", svc(`"ipc":"host"`), "uses ipc"},
		{"ipc service", svc(`"ipc":"service:db"`), "uses ipc"},
		{"network host", svc(`"network_mode":"host"`), "network_mode \"host\""},
		{"network container", svc(`"network_mode":"container:abc"`), "network_mode \"container:abc\""},
		{"network service", svc(`"network_mode":"service:db"`), "network_mode \"service:db\""},
		{"userns host", svc(`"userns_mode":"host"`), "uses userns_mode"},
		{"uts host", svc(`"uts":"host"`), "uses uts"},
		{"cgroup host", svc(`"cgroup":"host"`), "uses cgroup"},
		{"cgroup_parent", svc(`"cgroup_parent":"/"`), "uses cgroup_parent"},
		{"runtime", svc(`"runtime":"runc-unsafe"`), "uses runtime"},
		{"gpus", svc(`"gpus":"all"`), "uses gpus"},
		{"volumes_from", svc(`"volumes_from":["other"]`), "uses volumes_from"},
		{"sysctls", svc(`"sysctls":{"net.ipv4.ip_forward":"1"}`), "uses sysctls"},
		{"provider", svc(`"provider":{"type":"model"}`), "uses provider"},
		{"env_file", svc(`"env_file":[{"path":"/etc/secrets.env","required":true}]`), "uses env_file"},
		{"extends file", svc(`"extends":{"file":"/etc/x.yml","service":"a"}`), "uses extends"},
		{"post_start hook", svc(`"post_start":[{"command":["id"],"privileged":true}]`), "uses post_start"},
		{"unknown future key", svc(`"some_new_field":true`), "uses some_new_field"},
		{"bind root", svc(`"volumes":[{"type":"bind","source":"/","target":"/host"}]`), "bind mount outside"},
		{"bind sibling", svc(`"volumes":[{"type":"bind","source":` + q(proj+"-secrets") + `,"target":"/x"}]`), "bind mount outside"},
		{"bind dotdot", svc(`"volumes":[{"type":"bind","source":` + q(proj+"/../outside") + `,"target":"/x"}]`), "bind mount outside"},
		{"bind symlink escape", svc(`"volumes":[{"type":"bind","source":` + q(filepath.Join(proj, "escape")) + `,"target":"/x"}]`), "bind mount outside"},
		{"bind relative", svc(`"volumes":[{"type":"bind","source":"data","target":"/x"}]`), "bind mount outside"},
		{"bind propagation", svc(`"volumes":[{"type":"bind","source":` + q(filepath.Join(proj, "d")) + `,"target":"/x","read_only":true,"bind":{"propagation":"rshared"}}]`), "bind option key \"propagation\""},
		{"writable bind in project", svc(`"volumes":[{"type":"bind","source":` + q(filepath.Join(proj, "d")) + `,"target":"/x"}]`), "writable bind mount"},
		{"bind read_only false", svc(`"volumes":[{"type":"bind","source":` + q(proj) + `,"target":"/x","read_only":false}]`), "writable bind mount"},
		{"image not granted", `{"services":{"web":{"image":"redis"}}}`, "image \"redis\""},
		{"image other tag", `{"services":{"web":{"image":"nginx:1.25"}}}`, "image \"nginx:1.25\""},
		{"image star", `{"services":{"web":{"image":"*"}}}`, "image \"*\""},
		{"build tag not granted", `{"services":{"b":{"build":{"context":` + q(proj) + `,"tags":["evil/app:1"]}}}}`, "build tag \"evil/app:1\""},
		{"build image not granted", `{"services":{"b":{"image":"evil/app:1","build":{"context":` + q(proj) + `}}}}`, "image \"evil/app:1\""},
		{"volume adopts another", `{"name":"proj","services":{},"volumes":{"data":{"name":"otherproj_data"}}}`, "names another volume"},
		{"volume name without project", `{"services":{},"volumes":{"data":{"name":"_data"}}}`, "names another volume"},
		{"network named host", `{"name":"proj","services":{},"networks":{"n":{"name":"host"}}}`, "names another network"},
		{"network adopts another", `{"name":"proj","services":{},"networks":{"default":{"name":"other_default"}}}`, "names another network"},
		{"npipe", svc(`"volumes":[{"type":"npipe","source":"x","target":"/x"}]`), "volume type"},
		{"image mount", svc(`"volumes":[{"type":"image","source":"alpine","target":"/x"}]`), "volume type"},
		{"short volume", svc(`"volumes":["/:/host"]`), "unparsed volumes"},
		{"build outside", svc(`"build":{"context":"/etc","dockerfile":"Dockerfile"}`), "build context outside"},
		{"build url", svc(`"build":{"context":"https://example.com/repo.git"}`), "build context outside"},
		{"dockerfile outside", svc(`"build":{"context":` + q(proj) + `,"dockerfile":"/etc/Dockerfile"}`), "Dockerfile outside"},
		{"additional contexts", svc(`"build":{"context":` + q(proj) + `,"additional_contexts":{"x":"/etc"}}`), "build key \"additional_contexts\""},
		{"build privileged", svc(`"build":{"context":` + q(proj) + `,"privileged":true}`), "build key \"privileged\""},
		{"build entitlements", svc(`"build":{"context":` + q(proj) + `,"entitlements":["security.insecure"]}`), "build key \"entitlements\""},
		{"build network host", svc(`"build":{"context":` + q(proj) + `,"network":"host"}`), "build network \"host\""},
		{"build cache_from local", svc(`"build":{"context":` + q(proj) + `,"cache_from":["type=local,src=/etc"]}`), "build key \"cache_from\""},
		{"service network driver_opts", svc(`"networks":{"default":{"driver_opts":{"x":"y"}}}`), "network key \"driver_opts\""},
		{"deploy gpu reservation", svc(`"deploy":{"resources":{"reservations":{"devices":[{"capabilities":["gpu"]}]}}}`), "deploy.resources.reservations key \"devices\""},
		{"logging driver", svc(`"logging":{"driver":"syslog","options":{"syslog-address":"unix:///dev/log"}}`), "logging driver \"syslog\""},
		{"external volume", `{"services":{},"volumes":{"v":{"external":true,"name":"host-data"}}}`, "volume key \"external\""},
		{"volume device", `{"services":{},"volumes":{"v":{"driver_opts":{"type":"none","o":"bind","device":"/etc"}}}}`, "volume key \"driver_opts\""},
		{"volume driver", `{"services":{},"volumes":{"v":{"driver":"local-persist"}}}`, "driver \"local-persist\""},
		{"external network", `{"services":{},"networks":{"n":{"external":true,"name":"host"}}}`, "network key \"external\""},
		{"network driver_opts", `{"services":{},"networks":{"n":{"driver_opts":{"com.docker.network.bridge.name":"eth0"}}}}`, "network key \"driver_opts\""},
		{"network macvlan", `{"services":{},"networks":{"n":{"driver":"macvlan"}}}`, "driver \"macvlan\""},
		{"secret file", `{"services":{},"secrets":{"s":{"file":"/etc/shadow"}}}`, "reads a host file"},
		{"secret external", `{"services":{},"secrets":{"s":{"external":true}}}`, "secrets key \"external\""},
		{"config file", `{"services":{},"configs":{"c":{"file":"/etc/passwd"}}}`, "reads a host file"},
		{"include", `{"include":[{"path":["/etc/x.yml"]}],"services":{}}`, "project uses include"},
		{"unknown top key", `{"services":{},"models":{"m":{}}}`, "project uses models"},
		{"not json", `time="..." level=warning msg="x"`, "does not parse"},
		{"truncated", `{"services":{"web":`, "does not parse"},
		{"services not a map", `{"services":["web"]}`, "does not parse"},
		{"service not a map", `{"services":{"web":"nginx"}}`, "does not parse"},
		{"empty", ``, "does not parse"},
	}
	for _, c := range cases {
		for _, action := range []string{"up", "pull", "down", "ps"} {
			calls := fakeCompose(t, c.cfg, 0)
			err := runCompose(proj, action)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s %s: err=%v want %q", c.name, action, err, c.wantErr)
			}
			if len(*calls) != 1 {
				t.Errorf("%s %s: the action ran after a refused config (%d calls)", c.name, action, len(*calls))
			}
		}
	}

	// Allowed: named volumes, tmpfs, a bind and build inside the project.
	ok := `{"name":"proj","x-meta":{"a":1},"networks":{"default":{"name":"proj_default","ipam":{}}},"services":{"web":{"image":"nginx","network_mode":"bridge","restart":"always","ports":[{"target":80,"published":"8080"}],` +
		`"deploy":{"resources":{"limits":{"cpus":"0.5","memory":"256M"}}},"logging":{"driver":"json-file","options":{"max-size":"10m"}},"volumes":[` +
		`{"type":"volume","source":"data","target":"/data"},{"type":"tmpfs","target":"/tmp"},` +
		`{"type":"bind","source":` + q(filepath.Join(proj, "html")) + `,"target":"/usr/share/nginx/html","read_only":true}],` +
		`"build":{"context":` + q(proj) + `,"dockerfile":"Dockerfile"}}},` +
		`"volumes":{"data":{"name":"proj_data"}},"secrets":{"s":{"file":` + q(filepath.Join(proj, "s.txt")) + `}}}`
	calls := fakeCompose(t, ok, 0)
	if err := runCompose(proj, "up"); err != nil || len(*calls) != 2 {
		t.Fatalf("clean project: err=%v calls=%d", err, len(*calls))
	}
	for _, build := range []string{
		`{"services":{"b":{"build":{"context":` + q(proj) + `}}}}`,
		`{"services":{"b":{"build":{"context":` + q(proj) + `,"tags":["app:v1"]},"image":"app:v1"}}}`,
	} {
		calls = fakeCompose(t, build, 0)
		if err := runCompose(proj, "up"); err != nil || len(*calls) != 2 {
			t.Fatalf("granted build %s: err=%v", build, err)
		}
	}

	// A failing config command refuses every action, down and ps included:
	// down would otherwise start a provider service's plugin binary.
	for _, action := range []string{"up", "pull", "down", "ps"} {
		calls = fakeCompose(t, "", 1)
		if err := runCompose(proj, action); err == nil || !strings.Contains(err.Error(), "config failed") || len(*calls) != 1 {
			t.Fatalf("%s config exit 1: err=%v calls=%d", action, err, len(*calls))
		}
	}
}

func TestComposeRawFilesRefused(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		wantErr string
	}{
		{"include", map[string]string{"compose.yaml": "include:\n  - /etc/other.yml\nservices: {}\n"}, "uses include"},
		{"extends file", map[string]string{"compose.yaml": "services:\n  web:\n    extends:\n      file: /etc/base.yml\n      service: web\n"}, "extends a file"},
		{"env_file", map[string]string{"compose.yaml": "services:\n  web:\n    image: nginx\n    env_file: /etc/app.env\n"}, "env_file"},
		{"override env_file", map[string]string{"compose.yaml": "services:\n  web:\n    image: nginx\n", "compose.override.yaml": "services:\n  web:\n    env_file: [../x.env]\n"}, "env_file"},
		{"bad yaml", map[string]string{"compose.yaml": "services: [\n"}, "does not parse"},
		{"services list", map[string]string{"compose.yaml": "services: [a]\n"}, "does not parse"},
	}
	for _, c := range cases {
		_, proj := composeProject(t, c.files)
		calls := fakeCompose(t, `{"services":{}}`, 0)
		err := runCompose(proj, "up")
		if err == nil || !strings.Contains(err.Error(), c.wantErr) || len(*calls) != 0 {
			t.Errorf("%s: err=%v calls=%d want %q", c.name, err, len(*calls), c.wantErr)
		}
	}

	// A symlinked override file is refused even though compose.yaml is fine.
	base, proj := composeProject(t, map[string]string{"compose.yaml": "services: {}\n"})
	if err := os.WriteFile(filepath.Join(base, "evil.yml"), []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "evil.yml"), filepath.Join(proj, "docker-compose.override.yml")); err != nil {
		t.Fatal(err)
	}
	calls := fakeCompose(t, `{"services":{}}`, 0)
	if err := runCompose(proj, "up"); err == nil || !strings.Contains(err.Error(), "not a regular file") || len(*calls) != 0 {
		t.Fatalf("symlinked override: err=%v calls=%d", err, len(*calls))
	}
}

// TestComposeStopsAtScriptDeadline: compose has no timeout of its own; it
// ends with the script's context.
func TestComposeStopsAtScriptDeadline(t *testing.T) {
	_, proj := composeProject(t, map[string]string{"compose.yaml": "services: {}\n"})
	orig := composeExec
	t.Cleanup(func() { composeExec = orig })
	composeExec = func(ctx context.Context, dir string, argv []string, stdin string, stdoutOnly bool) (int, string, error) {
		<-ctx.Done()
		return -1, "", nil // a killed child reports an exit code, not an error
	}
	for _, action := range []string{"up", "ps"} {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		engine := newTestEngine(&Entitlements{AllowContainers: true, AllowImages: []string{"nginx", "app:v1"}, AllowFSRead: []string{proj}})
		engine.ctx = ctx
		_, err := engine.Execute("sys.containers.compose(" + strconvQuote(action) + ", " + strconvQuote(proj) + ")\n")
		cancel()
		if err == nil || !errors.Is(err, errScriptTimedOut) {
			t.Fatalf("%s: err=%v", action, err)
		}
	}
	// A cancel (not a deadline) inside the builtin is reported as cancelled.
	ctx, cancel := context.WithCancelCause(context.Background())
	composeExec = func(ctx context.Context, dir string, argv []string, stdin string, stdoutOnly bool) (int, string, error) {
		cancel(errors.New("user"))
		<-ctx.Done()
		return -1, "", nil
	}
	engine := newTestEngine(&Entitlements{AllowContainers: true, AllowFSRead: []string{proj}})
	engine.ctx = ctx
	if _, err := engine.Execute("sys.containers.compose(\"ps\", " + strconvQuote(proj) + ")\n"); err == nil || !errors.Is(err, errScriptCancelled) || !strings.Contains(err.Error(), "user") {
		t.Fatalf("cancel: err=%v", err)
	}
}

func TestPullTimeoutError(t *testing.T) {
	bg := context.Background()
	if err := pullErr(bg, timeoutErr{}); !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err=%v", err)
	}
	if err := pullErr(bg, errors.New("refused")); strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err=%v", err)
	}
	ctx, cancel := context.WithTimeout(bg, time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	if err := pullErr(ctx, errors.New("context deadline exceeded")); !strings.Contains(err.Error(), "script deadline") {
		t.Fatalf("err=%v", err)
	}
}

func TestComposeEnvIsFixed(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://198.51.100.1:2375")
	t.Setenv("COMPOSE_FILE", "/etc/evil.yml")
	t.Setenv("PATH", "/tmp/evil:/usr/bin")
	for _, kv := range composeEnv() {
		k := strings.SplitN(kv, "=", 2)[0]
		switch k {
		case "PATH":
			if kv != "PATH="+composePATH {
				t.Errorf("PATH not fixed: %q", kv)
			}
		case "LC_ALL", "HOME":
		default:
			t.Errorf("unexpected env %q", kv)
		}
	}
}

func TestWriteGrantOverlapsBoundaries(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(base, "proj")
	if err := os.MkdirAll(filepath.Join(proj, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(proj, "sub"), link); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		grant string
		want  bool
	}{
		{base, true},
		{proj, true},
		{filepath.Join(proj, "sub"), true},
		{proj + "/../proj/sub", true},
		{link, true}, // a symlinked grant that lands inside the project
		{proj + "-other", false},
		{filepath.Join(base, "pro"), false},
		{"*", true},
		{"relative", false},
	}
	for _, c := range cases {
		if got := writeGrantOverlaps([]string{c.grant}, proj); got != c.want {
			t.Errorf("grant %q: got %v want %v", c.grant, got, c.want)
		}
	}
}

// realComposeConfig is docker compose v2 "config --format json" output for a
// project with a build, a bind mount, a named volume, a network, a secret,
// depends_on, a healthcheck and an escaped "$$"; @PROJ@ is the project dir.
const realComposeConfig = `{
  "name": "cproj",
  "networks": {
    "back": {
      "name": "cproj_back",
      "ipam": {}
    },
    "default": {
      "name": "cproj_default",
      "ipam": {}
    }
  },
  "secrets": {
    "s": {
      "name": "cproj_s",
      "file": "@PROJ@/s.txt"
    }
  },
  "services": {
    "app": {
      "build": {
        "context": "@PROJ@",
        "dockerfile": "Dockerfile"
      },
      "command": null,
      "entrypoint": null,
      "networks": {
        "back": null
      }
    },
    "web": {
      "command": null,
      "depends_on": {
        "app": {
          "condition": "service_started",
          "required": true
        }
      },
      "entrypoint": null,
      "environment": {
        "A": "x$$y"
      },
      "healthcheck": {
        "test": [
          "CMD",
          "true"
        ]
      },
      "image": "nginx",
      "networks": {
        "default": null
      },
      "ports": [
        {
          "mode": "ingress",
          "target": 80,
          "published": "8080",
          "protocol": "tcp"
        }
      ],
      "restart": "always",
      "secrets": [
        {
          "source": "s",
          "target": "/run/secrets/s"
        }
      ],
      "volumes": [
        {
          "type": "bind",
          "source": "@PROJ@/html",
          "target": "/usr/share/nginx/html",
          "read_only": true,
          "bind": {}
        },
        {
          "type": "volume",
          "source": "data",
          "target": "/data",
          "volume": {}
        }
      ]
    }
  },
  "volumes": {
    "data": {
      "name": "cproj_data"
    }
  }
}`

func TestComposeAllowsRealConfigOutput(t *testing.T) {
	_, proj := composeProject(t, map[string]string{"compose.yaml": "services: {}\n"})
	cfg := strings.ReplaceAll(realComposeConfig, "@PROJ@", proj)
	if err := checkComposeConfig(proj, []byte(cfg), []string{"nginx"}); err != nil {
		t.Fatalf("real config refused: %v", err)
	}
	var stdin string
	orig := composeExec
	t.Cleanup(func() { composeExec = orig })
	composeExec = func(ctx context.Context, dir string, argv []string, in string, stdoutOnly bool) (int, string, error) {
		if argv[len(argv)-1] == "json" {
			return 0, cfg, nil
		}
		stdin = in
		return 0, "", nil
	}
	if err := runCompose(proj, "up"); err != nil || stdin != cfg {
		t.Fatalf("up: err=%v, stdin is the checked config: %v", err, stdin == cfg)
	}
}
