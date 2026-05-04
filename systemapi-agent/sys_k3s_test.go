package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestK3sClient starts an httptest.Server and returns a K3sClient pointing at it.
// This bypasses TLS by using the plain HTTP test server's client.
func newTestK3sClient(handler http.Handler) (*K3sClient, *httptest.Server) {
	srv := httptest.NewServer(handler)
	kc := &K3sClient{
		client:    srv.Client(),
		serverURL: srv.URL,
	}
	return kc, srv
}

// newTestEngineWithK3s creates a SysscriptEngine with the given K3sClient wired in.
func newTestEngineWithK3s(kc *K3sClient) *SysscriptEngine {
	return &SysscriptEngine{
		Entitlements: &Entitlements{AllowK3s: true},
		cm:           &ConfigManager{},
		k3sClient:    kc,
	}
}

// TestK3sNodes verifies that a node list is returned and fields are correctly mapped.
func TestK3sNodes(t *testing.T) {
	nodeJSON := `{"items":[{"metadata":{"name":"node1","labels":{"node-role.kubernetes.io/master":""}},"status":{"conditions":[{"type":"Ready","status":"True"}],"nodeInfo":{"kubeletVersion":"v1.28.2"}}}]}`

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/nodes" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(nodeJSON))
			return
		}
		http.NotFound(w, r)
	})

	kc, srv := newTestK3sClient(handler)
	defer srv.Close()

	nodes, err := kc.ListNodes()
	if err != nil {
		t.Fatalf("ListNodes unexpected error: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	if nodes[0].Metadata.Name != "node1" {
		t.Errorf("expected node name 'node1', got %q", nodes[0].Metadata.Name)
	}
}

// TestK3sNodesEmpty verifies that an empty items list is returned correctly.
func TestK3sNodesEmpty(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/nodes" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"items":[]}`))
			return
		}
		http.NotFound(w, r)
	})

	kc, srv := newTestK3sClient(handler)
	defer srv.Close()

	nodes, err := kc.ListNodes()
	if err != nil {
		t.Fatalf("ListNodes (empty) unexpected error: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}
}

// TestK3sNodesUnavailable verifies that the k3sNodes Starlark builtin returns empty list on 500 (D-05).
func TestK3sNodesUnavailable(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	})

	kc, srv := newTestK3sClient(handler)
	defer srv.Close()

	engine := newTestEngineWithK3s(kc)
	out, err := engine.Execute(`
nodes = sys.k3s.nodes()
print(len(nodes))
`)
	if err != nil {
		t.Fatalf("k3sNodes unavailability should not propagate error to Starlark: %v", err)
	}
	if strings.TrimSpace(out) != "0" {
		t.Errorf("expected empty list (0) on k3s down, got %q", out)
	}
}

// TestK3sPods verifies that all-namespace and namespace-scoped pod listing work correctly.
func TestK3sPods(t *testing.T) {
	allPods := K8sPodList{
		Items: []K8sPod{
			{Metadata: struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			}{Name: "pod1", Namespace: "default"}, Status: struct {
				Phase string `json:"phase"`
			}{Phase: "Running"}},
			{Metadata: struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			}{Name: "pod2", Namespace: "default"}, Status: struct {
				Phase string `json:"phase"`
			}{Phase: "Running"}},
			{Metadata: struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			}{Name: "pod3", Namespace: "kube-system"}, Status: struct {
				Phase string `json:"phase"`
			}{Phase: "Running"}},
		},
	}
	ksPods := K8sPodList{
		Items: []K8sPod{
			{Metadata: struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			}{Name: "pod3", Namespace: "kube-system"}, Status: struct {
				Phase string `json:"phase"`
			}{Phase: "Running"}},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch r.URL.Path {
		case "/api/v1/pods":
			json.NewEncoder(w).Encode(allPods)
		case "/api/v1/namespaces/kube-system/pods":
			json.NewEncoder(w).Encode(ksPods)
		default:
			http.NotFound(w, r)
		}
	})

	kc, srv := newTestK3sClient(handler)
	defer srv.Close()

	// All namespaces
	pods, err := kc.ListPods("")
	if err != nil {
		t.Fatalf("ListPods('') error: %v", err)
	}
	if len(pods) != 3 {
		t.Errorf("expected 3 pods for all namespaces, got %d", len(pods))
	}

	// Namespace-scoped
	pods, err = kc.ListPods("kube-system")
	if err != nil {
		t.Fatalf("ListPods('kube-system') error: %v", err)
	}
	if len(pods) != 1 {
		t.Errorf("expected 1 pod for kube-system, got %d", len(pods))
	}
}

// TestK3sPodsOptionalNamespace verifies the Starlark builtin accepts both no-arg and with-arg forms.
func TestK3sPodsOptionalNamespace(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"items":[]}`))
	})

	kc, srv := newTestK3sClient(handler)
	defer srv.Close()

	engine := newTestEngineWithK3s(kc)

	// No arg
	_, err := engine.Execute(`result = sys.k3s.pods()`)
	if err != nil {
		t.Fatalf("k3sPods() no-arg error: %v", err)
	}

	// With namespace arg
	_, err = engine.Execute(`result = sys.k3s.pods("kube-system")`)
	if err != nil {
		t.Fatalf("k3sPods('kube-system') error: %v", err)
	}
}

// TestK3sApplyCreate verifies that a successful POST (201) maps to no error.
func TestK3sApplyCreate(t *testing.T) {
	var capturedPath string
	var capturedMethod string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedMethod = r.Method
		w.WriteHeader(http.StatusCreated)
	})

	kc, srv := newTestK3sClient(handler)
	defer srv.Close()

	configMapYAML := `apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
  namespace: default
data:
  key: value
`
	err := kc.Apply(configMapYAML)
	if err != nil {
		t.Fatalf("Apply() unexpected error: %v", err)
	}
	if capturedMethod != http.MethodPost {
		t.Errorf("expected POST, got %q", capturedMethod)
	}
	if !strings.Contains(capturedPath, "/api/v1/namespaces/default/configmaps") {
		t.Errorf("expected path to contain '/api/v1/namespaces/default/configmaps', got %q", capturedPath)
	}
}

// TestK3sApplyConflict verifies that a 409 POST triggers a PATCH retry and succeeds.
func TestK3sApplyConflict(t *testing.T) {
	callCount := 0

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusConflict)
			return
		}
		// PATCH succeeds
		w.WriteHeader(http.StatusOK)
	})

	kc, srv := newTestK3sClient(handler)
	defer srv.Close()

	configMapYAML := `apiVersion: v1
kind: ConfigMap
metadata:
  name: existing-config
  namespace: default
`
	err := kc.Apply(configMapYAML)
	if err != nil {
		t.Fatalf("Apply() conflict retry unexpected error: %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected 2 calls (POST + PATCH), got %d", callCount)
	}
}

// TestK3sApplyInvalidYAML verifies that malformed YAML returns an error.
func TestK3sApplyInvalidYAML(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	kc, srv := newTestK3sClient(handler)
	defer srv.Close()

	err := kc.Apply("not: valid: yaml: [")
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

// TestResourcePath verifies that API paths are correctly computed for v1 and apps/v1 resources.
func TestResourcePath(t *testing.T) {
	cases := []struct {
		apiVersion string
		kind       string
		namespace  string
		want       string
		wantErr    bool
	}{
		{"v1", "ConfigMap", "default", "/api/v1/namespaces/default/configmaps", false},
		{"apps/v1", "Deployment", "myns", "/apis/apps/v1/namespaces/myns/deployments", false},
		{"v1", "Pod", "kube-system", "/api/v1/namespaces/kube-system/pods", false},
		{"v1", "Service", "default", "/api/v1/namespaces/default/services", false},
		{"v1", "ConfigMap", "../../etc", "", true},
	}

	for _, tc := range cases {
		got, err := resourcePath(tc.apiVersion, tc.kind, tc.namespace)
		if tc.wantErr {
			if err == nil {
				t.Errorf("resourcePath(%q, %q, %q): expected error, got %q", tc.apiVersion, tc.kind, tc.namespace, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("resourcePath(%q, %q, %q): unexpected error: %v", tc.apiVersion, tc.kind, tc.namespace, err)
			continue
		}
		if got != tc.want {
			t.Errorf("resourcePath(%q, %q, %q) = %q, want %q", tc.apiVersion, tc.kind, tc.namespace, got, tc.want)
		}
	}
}

// TestNamespaceValidation verifies that isValidNamespace enforces the allowlist (T-03-09).
func TestNamespaceValidation(t *testing.T) {
	cases := []struct {
		ns    string
		valid bool
	}{
		{"default", true},
		{"kube-system", true},
		{"my-namespace", true},
		{"ns123", true},
		{"../../etc", false},  // path traversal: contains / and .
		{"bad/path", false},   // contains /
		{"", false},           // empty
		{"a]b", false},        // invalid char
		{"Uppercase", false},  // uppercase not allowed
		{"has space", false},  // space not allowed
		{"dot.in.ns", false},  // dot not allowed (k8s namespace rules: only [a-z0-9-])
	}

	for _, tc := range cases {
		got := isValidNamespace(tc.ns)
		if got != tc.valid {
			t.Errorf("isValidNamespace(%q) = %v, want %v", tc.ns, got, tc.valid)
		}
	}

	// Also test via ListPods with malicious namespace — expect error containing "invalid namespace"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"items":[]}`))
	})
	kc, srv := newTestK3sClient(handler)
	defer srv.Close()

	_, err := kc.ListPods("../../etc")
	if err == nil {
		t.Error("ListPods('../../etc') expected error, got nil")
	} else if !strings.Contains(err.Error(), "invalid namespace") {
		t.Errorf("ListPods('../../etc') error should contain 'invalid namespace', got: %v", err)
	}

	// Also test via resourcePath
	_, err = resourcePath("v1", "ConfigMap", "../../etc")
	if err == nil {
		t.Error("resourcePath with '../../etc' namespace expected error, got nil")
	} else if !strings.Contains(err.Error(), "invalid namespace") {
		t.Errorf("resourcePath error should contain 'invalid namespace', got: %v", err)
	}
}
