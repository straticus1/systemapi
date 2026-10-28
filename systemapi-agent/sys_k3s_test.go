package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// newTestK3sClient starts an httptest.Server and returns a K3sClient pointing at it.
// This bypasses TLS by using the plain HTTP test server's client.
func newTestK3sClient(handler http.Handler) (*K3sClient, *httptest.Server) {
	srv := httptest.NewServer(handler)
	kc := &K3sClient{
		ctx:       context.Background(),
		client:    srv.Client(),
		serverURL: srv.URL,
	}
	return kc, srv
}

// newTestEngineWithK3s creates a SysscriptEngine with the given K3sClient wired in.
func newTestEngineWithK3s(kc *K3sClient) *SysscriptEngine {
	return &SysscriptEngine{
		ctx:          context.Background(),
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

// TestK3sPodsOptionalNamespace requires an allowed namespace. An empty call
// and a namespace outside the list fail before the API is contacted.
func TestK3sPodsOptionalNamespace(t *testing.T) {
	hits := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/api/v1/namespaces/kube-system/pods" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"items":[{"metadata":{"name":"coredns","namespace":"kube-system"},"status":{"phase":"Running"}}]}`)); err != nil {
			t.Error(err)
		}
	})

	kc, srv := newTestK3sClient(handler)
	defer srv.Close()

	engine := newTestEngineWithK3s(kc)
	engine.Entitlements.AllowK3sNamespaces = []string{"kube-system"}

	_, err := engine.Execute(`result = sys.k3s.pods()`)
	if err == nil || !strings.Contains(err.Error(), "namespace") || hits != 0 {
		t.Fatalf("no-arg err=%v hits=%d", err, hits)
	}

	out, err := engine.Execute("pods = sys.k3s.pods(\"kube-system\")\nprint(len(pods))\n")
	if err != nil || strings.TrimSpace(out) != "1" || hits != 1 {
		t.Fatalf("err=%v out=%q hits=%d", err, out, hits)
	}

	_, err = engine.Execute(`sys.k3s.pods("default")`)
	if err == nil || !strings.Contains(err.Error(), "namespace not allowed") || hits != 1 {
		t.Fatalf("outside err=%v hits=%d", err, hits)
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
		{"../../etc", false}, // path traversal: contains / and .
		{"bad/path", false},  // contains /
		{"", false},          // empty
		{"a]b", false},       // invalid char
		{"Uppercase", false}, // uppercase not allowed
		{"has space", false}, // space not allowed
		{"dot.in.ns", false}, // dot not allowed (k8s namespace rules: only [a-z0-9-])
	}

	for _, tc := range cases {
		got := isValidNamespace(tc.ns)
		if got != tc.valid {
			t.Errorf("isValidNamespace(%q) = %v, want %v", tc.ns, got, tc.valid)
		}
	}

	// Also test via ListPods with malicious namespace - expect error containing "invalid namespace"
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

func TestK3sApplyManifestPolicy(t *testing.T) {
	hits := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		t.Errorf("policy failure reached %s %s", r.Method, r.URL.Path)
	})
	kc, srv := newTestK3sClient(handler)
	defer srv.Close()
	engine := newTestEngineWithK3s(kc)
	engine.Entitlements.AllowK3sNamespaces = []string{"default"}

	priv := "r = sys.k3s.apply('''apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n  containers:\n  - name: c\n    securityContext:\n      privileged: true\n''')\nprint(r[\"success\"])\nprint(r[\"error\"])\n"
	out, err := engine.Execute(priv)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || lines[0] != "False" || !strings.Contains(lines[1], "manifest denied") || hits != 0 {
		t.Fatalf("priv out=%q hits=%d", out, hits)
	}

	hostPath := "r = sys.k3s.apply('''apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n  volumes:\n  - name: h\n    hostPath:\n      path: /etc\n''')\nprint(r[\"success\"])\nprint(r[\"error\"])\n"
	out, err = engine.Execute(hostPath)
	if err != nil {
		t.Fatal(err)
	}
	lines = strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || lines[0] != "False" || !strings.Contains(lines[1], "manifest denied") || hits != 0 {
		t.Fatalf("hostPath out=%q hits=%d", out, hits)
	}

	engine.Entitlements.AllowK3sNamespaces = nil
	good := "r = sys.k3s.apply('''apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: my-config\n  namespace: default\ndata:\n  key: value\n''')\nprint(r[\"success\"])\nprint(r[\"error\"])\n"
	out, err = engine.Execute(good)
	if err != nil {
		t.Fatal(err)
	}
	lines = strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || lines[0] != "False" || !strings.Contains(lines[1], "namespace") || hits != 0 {
		t.Fatalf("nil list out=%q hits=%d", out, hits)
	}
}

func TestK3sApplyAllowedConfigMap(t *testing.T) {
	hits := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/namespaces/default/configmaps" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
	})
	kc, srv := newTestK3sClient(handler)
	defer srv.Close()

	denied := newTestEngineWithK3s(kc)
	denied.Entitlements.AllowK3sNamespaces = []string{"kube-system"}
	implicit := "r = sys.k3s.apply('''apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: my-config\ndata:\n  key: value\n''')\nprint(r[\"success\"])\nprint(r[\"error\"])\n"
	out, err := denied.Execute(implicit)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || lines[0] != "False" || !strings.Contains(lines[1], "namespace not allowed") || hits != 0 {
		t.Fatalf("default ns out=%q hits=%d", out, hits)
	}

	engine := newTestEngineWithK3s(kc)
	engine.Entitlements.AllowK3sNamespaces = []string{"default"}
	good := "r = sys.k3s.apply('''apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: my-config\n  namespace: default\ndata:\n  key: value\n''')\nprint(r[\"success\"])\nprint(r[\"error\"])\n"
	out, err = engine.Execute(good)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimRight(out, "\n") != "True" || hits != 1 {
		t.Fatalf("allowed out=%q hits=%d", out, hits)
	}
}

func TestK3sListFailClosed(t *testing.T) {
	allow := []string{"default"}
	script := "print(len(sys.k3s.list(\"Pod\", \"default\")))\n"

	t.Run("too many", func(t *testing.T) {
		var body bytes.Buffer
		body.WriteString(`{"items":[`)
		for i := 0; i < kubeItemCap+1; i++ {
			if i > 0 {
				body.WriteByte(',')
			}
			fmt.Fprintf(&body, `{"metadata":{"name":"p%d","namespace":"default"}}`, i)
		}
		body.WriteString(`]}`)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(body.Bytes()); err != nil {
				t.Error(err)
			}
		})
		kc, srv := newTestK3sClient(handler)
		defer srv.Close()
		engine := newTestEngineWithK3s(kc)
		engine.Entitlements.AllowK3sNamespaces = allow
		_, err := engine.Execute(script)
		if err == nil || !strings.Contains(err.Error(), "too many items") {
			t.Fatal(err)
		}
	})

	t.Run("status", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "down", http.StatusInternalServerError)
		})
		kc, srv := newTestK3sClient(handler)
		defer srv.Close()
		engine := newTestEngineWithK3s(kc)
		engine.Entitlements.AllowK3sNamespaces = allow
		out, err := engine.Execute(script)
		if err != nil || strings.TrimSpace(out) != "0" {
			t.Fatalf("err=%v out=%q", err, out)
		}
	})

	t.Run("cap", func(t *testing.T) {
		var writeErr error
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write(bytes.Repeat([]byte("x"), kubeListCap+1)); err != nil {
				writeErr = err
			}
		})
		kc, srv := newTestK3sClient(handler)
		defer srv.Close()
		engine := newTestEngineWithK3s(kc)
		engine.Entitlements.AllowK3sNamespaces = allow
		_, err := engine.Execute(script)
		if err == nil || !strings.Contains(err.Error(), "body exceeds cap") {
			t.Fatalf("err=%v writeErr=%v", err, writeErr)
		}
	})
}

func TestK3sPodsDownAndGetDown(t *testing.T) {
	hits := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "down", http.StatusInternalServerError)
	})
	kc, srv := newTestK3sClient(handler)
	defer srv.Close()
	engine := newTestEngineWithK3s(kc)
	engine.Entitlements.AllowK3sNamespaces = []string{"kube-system"}

	out, err := engine.Execute("print(len(sys.k3s.pods(\"kube-system\")))\n")
	if err != nil || strings.TrimSpace(out) != "0" || hits != 1 {
		t.Fatalf("pods err=%v out=%q hits=%d", err, out, hits)
	}

	_, err = engine.Execute("sys.k3s.get(\"ConfigMap\", \"my-config\", \"kube-system\")\n")
	if err == nil || hits != 2 {
		t.Fatalf("get err=%v hits=%d", err, hits)
	}
}

func TestKubeListResourceBounds(t *testing.T) {
	dead := &K3sClient{ctx: context.Background(), client: &http.Client{}, serverURL: "http://127.0.0.1:1"}
	if _, err := dead.ListResource("Pod", ""); err == nil || !strings.Contains(err.Error(), "namespace required") {
		t.Fatal(err)
	}
	if _, err := dead.ListResource("Pod", "../../etc"); err == nil || !strings.Contains(err.Error(), "invalid namespace") {
		t.Fatal(err)
	}

	var body bytes.Buffer
	body.WriteString(`{"items":[`)
	for i := 0; i < kubeItemCap+1; i++ {
		if i > 0 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body, `{"metadata":{"name":"p%d","namespace":"default"},"data":{"token":"sekret"}}`, i)
	}
	body.WriteString(`]}`)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(body.Bytes()); err != nil {
			t.Error(err)
		}
	})
	kc, srv := newTestK3sClient(handler)
	defer srv.Close()
	if _, err := kc.ListResource("Pod", "default"); err == nil || !strings.Contains(err.Error(), "too many items") {
		t.Fatal(err)
	}
}

func TestGetResourceDropsSecrets(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{"metadata":{"name":"my-config","namespace":"default"},"data":{"token":"sekret"},"spec":{"containers":[{"env":[{"name":"PASSWORD","value":"sekret"}]}]}}`)); err != nil {
			t.Error(err)
		}
	})
	kc, srv := newTestK3sClient(handler)
	defer srv.Close()
	got, err := kc.GetResource("ConfigMap", "my-config", "default")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["name"] != "my-config" || got["namespace"] != "default" {
		t.Fatalf("%v", got)
	}
	for _, value := range got {
		if strings.Contains(value, "sekret") {
			t.Fatalf("%v", got)
		}
	}
}

func TestPodExecWebsocket(t *testing.T) {
	out, origin, sub, query, err := dialPodExec(t, func(conn *websocket.Conn) error {
		if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte{1}, []byte("hello")...)); err != nil {
			return err
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte{2}, []byte(" world")...)); err != nil {
			return err
		}
		return conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	}, []string{"echo", "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if out != "hello world" || !origin || sub != "v4.channel.k8s.io" {
		t.Fatalf("out=%q origin=%v sub=%q", out, origin, sub)
	}
	if query.Get("stdout") != "true" || query.Get("stderr") != "true" || query.Get("tty") != "false" || query.Has("stdin") {
		t.Fatalf("%v", query)
	}
	if strings.Join(query["command"], " ") != "echo hi" {
		t.Fatalf("%v", query["command"])
	}

	got, origin, _, _, err := dialPodExec(t, func(conn *websocket.Conn) error {
		if err := conn.WriteMessage(websocket.BinaryMessage, append([]byte{1}, []byte("LEAK")...)); err != nil {
			return err
		}
		return conn.WriteMessage(websocket.BinaryMessage, append([]byte{3}, []byte("denied")...))
	}, []string{"echo", "hi"})
	if err == nil || got != "" || !strings.Contains(err.Error(), "denied") || strings.Contains(err.Error(), "LEAK") || !origin {
		t.Fatalf("got=%q err=%v origin=%v", got, err, origin)
	}
}

func dialPodExec(t *testing.T, write func(*websocket.Conn) error, cmd []string) (string, bool, string, url.Values, error) {
	t.Helper()
	origin := false
	sub := ""
	var query url.Values
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query()
		upgrader := websocket.Upgrader{
			CheckOrigin: func(*http.Request) bool {
				origin = true
				return true
			},
			Subprotocols: []string{"v4.channel.k8s.io"},
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		sub = conn.Subprotocol()
		if err := write(conn); err != nil {
			t.Error(err)
		}
	})
	kc, srv := newTestK3sClient(handler)
	defer srv.Close()
	text, err := kc.PodExec("default", "nginx", cmd)
	return text, origin, sub, query, err
}

func TestNewK3sClientIgnoresKubeconfig(t *testing.T) {
	if _, err := os.Stat(k3sKubeconfigPath); err == nil {
		t.Skip("k3s kubeconfig present")
	}
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "ignored"))
	_, err := NewK3sClient(context.Background())
	if err == nil || !strings.Contains(err.Error(), k3sKubeconfigPath) {
		t.Fatal(err)
	}
}

func TestNewK8sClientRequiresTLS13(t *testing.T) {
	t.Setenv("KUBECONFIG", "")
	if _, err := NewK8sClient(context.Background()); err == nil || !strings.Contains(err.Error(), "KUBECONFIG not set") {
		t.Fatal(err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTpl, caTpl, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	clientPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kube := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
    certificate-authority-data: %s
  name: test
users:
- user:
    client-certificate-data: %s
    client-key-data: %s
  name: test
`, base64.StdEncoding.EncodeToString(caPEM), base64.StdEncoding.EncodeToString(clientPEM), base64.StdEncoding.EncodeToString(keyPEM))
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(kube), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)
	kc, err := NewK8sClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if kc.tlsConfig == nil || kc.tlsConfig.MinVersion != tls.VersionTLS13 || kc.tlsConfig.InsecureSkipVerify {
		t.Fatalf("min=%v skip=%v", kc.tlsConfig.MinVersion, kc.tlsConfig.InsecureSkipVerify)
	}
}
