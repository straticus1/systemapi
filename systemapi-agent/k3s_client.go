package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

// K3sClient communicates with the Kubernetes API using TLS from kubeconfig.
// k3s and k8s share this type. The script never receives the kubeconfig.
type K3sClient struct {
	ctx       context.Context // parent of every call; nil refuses all calls
	client    *http.Client
	serverURL string
	tlsConfig *tls.Config
}

const kubeCallTimeout = 15 * time.Second

const k3sKubeconfigPath = "/etc/rancher/k3s/k3s.yaml"

// kubeconfig represents the minimal kubeconfig YAML structure.
type kubeconfig struct {
	Clusters []struct {
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// K8sNodeList is the response type for GET /api/v1/nodes.
type K8sNodeList struct {
	Items []K8sNode `json:"items"`
}

// K8sNode represents a Kubernetes node from the API.
type K8sNode struct {
	Metadata struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Status struct {
		Conditions []struct {
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"conditions"`
		NodeInfo struct {
			KubeletVersion string `json:"kubeletVersion"`
		} `json:"nodeInfo"`
	} `json:"status"`
}

// K8sPodList is the response type for GET /api/v1/pods or /api/v1/namespaces/{ns}/pods.
type K8sPodList struct {
	Items []K8sPod `json:"items"`
}

// K8sPod represents a Kubernetes pod from the API.
type K8sPod struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

// NewK3sClient reads only /etc/rancher/k3s/k3s.yaml. It does not fall back to
// KUBECONFIG. Every call is bounded by ctx (the script's context) and by
// kubeCallTimeout.
func NewK3sClient(ctx context.Context) (*K3sClient, error) {
	kc, err := newKubeClient(k3sKubeconfigPath)
	if err != nil {
		return nil, err
	}
	kc.ctx = ctx
	return kc, nil
}

// NewK8sClient reads KUBECONFIG and nothing else. See NewK3sClient for ctx.
func NewK8sClient(ctx context.Context) (*K3sClient, error) {
	path := os.Getenv("KUBECONFIG")
	if path == "" {
		return nil, fmt.Errorf("KUBECONFIG not set")
	}
	kc, err := newKubeClient(path)
	if err != nil {
		return nil, err
	}
	kc.ctx = ctx
	return kc, nil
}

// Threats: TLS minimum is 1.3 and certificate verification stays on.
// InsecureSkipVerify is never set. The kubeconfig is not returned to the script.
func newKubeClient(path string) (*K3sClient, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read kubeconfig %s: %w", path, err)
	}

	var kc kubeconfig
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return nil, fmt.Errorf("parse kubeconfig: %w", err)
	}
	if len(kc.Clusters) == 0 || len(kc.Users) == 0 {
		return nil, fmt.Errorf("kubeconfig missing clusters or users")
	}

	caCertPEM, err := base64.StdEncoding.DecodeString(kc.Clusters[0].Cluster.CertificateAuthorityData)
	if err != nil {
		return nil, fmt.Errorf("decode CA cert: %w", err)
	}
	clientCertPEM, err := base64.StdEncoding.DecodeString(kc.Users[0].User.ClientCertificateData)
	if err != nil {
		return nil, fmt.Errorf("decode client cert: %w", err)
	}
	clientKeyPEM, err := base64.StdEncoding.DecodeString(kc.Users[0].User.ClientKeyData)
	if err != nil {
		return nil, fmt.Errorf("decode client key: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("kubeconfig CA cert rejected")
	}
	tlsCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load TLS keypair: %w", err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{tlsCert},
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &K3sClient{
		client:    &http.Client{Transport: transport, Timeout: kubeCallTimeout},
		serverURL: kc.Clusters[0].Cluster.Server,
		tlsConfig: tlsConfig,
	}, nil
}

// isValidNamespace validates that a namespace string is safe for URL construction.
// Rejects values containing path separators, traversal sequences, or non-alphanumeric chars
// beyond dash (matching Kubernetes namespace naming rules).
// T-03-09 mitigation.
func isValidNamespace(ns string) bool {
	if len(ns) == 0 || len(ns) > 253 {
		return false
	}
	for _, r := range ns {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return false
		}
	}
	return true
}

// resourcePath computes the k8s API path for a given apiVersion, kind, and namespace.
func resourcePath(apiVersion, kind, namespace string) (string, error) {
	kindPlural := strings.ToLower(kind) + "s" // simple pluralization
	if namespace == "" {
		namespace = "default"
	}
	if !isValidNamespace(namespace) {
		return "", fmt.Errorf("invalid namespace: %q", namespace)
	}
	switch {
	case apiVersion == "v1":
		return fmt.Sprintf("/api/v1/namespaces/%s/%s", namespace, kindPlural), nil
	case strings.HasPrefix(apiVersion, "apps/"):
		return fmt.Sprintf("/apis/%s/namespaces/%s/%s", apiVersion, namespace, kindPlural), nil
	default:
		return fmt.Sprintf("/apis/%s/namespaces/%s/%s", apiVersion, namespace, kindPlural), nil
	}
}

// ListNodes returns all nodes from the Kubernetes API.
// On error, returns nil slice and the error.
func (kc *K3sClient) ListNodes() ([]K8sNode, error) {
	resp, err := kc.send(http.MethodGet, kc.serverURL+"/api/v1/nodes", "", nil)
	if err != nil {
		return nil, fmt.Errorf("k3s list nodes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("k3s list nodes: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("k3s list nodes: read body: %w", err)
	}

	var nodeList K8sNodeList
	if err := json.Unmarshal(body, &nodeList); err != nil {
		return nil, fmt.Errorf("k3s list nodes: parse response: %w", err)
	}
	return nodeList.Items, nil
}

// ListPods returns pods from the Kubernetes API.
// If namespace is empty, returns pods from all namespaces.
// If namespace is set, validates it (T-03-09) and returns namespace-scoped pods.
func (kc *K3sClient) ListPods(namespace string) ([]K8sPod, error) {
	var path string
	if namespace == "" {
		path = kc.serverURL + "/api/v1/pods"
	} else {
		if !isValidNamespace(namespace) {
			return nil, fmt.Errorf("invalid namespace: %q", namespace)
		}
		path = kc.serverURL + "/api/v1/namespaces/" + namespace + "/pods"
	}

	resp, err := kc.send(http.MethodGet, path, "", nil)
	if err != nil {
		return nil, fmt.Errorf("k3s list pods: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("k3s list pods: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("k3s list pods: read body: %w", err)
	}

	var podList K8sPodList
	if err := json.Unmarshal(body, &podList); err != nil {
		return nil, fmt.Errorf("k3s list pods: parse response: %w", err)
	}
	return podList.Items, nil
}

// Apply applies a YAML manifest to the Kubernetes API.
// Parses the YAML to determine the API path, POSTs to create, and PATCHes on 409 Conflict.
func (kc *K3sClient) Apply(yamlStr string) error {
	// Parse YAML to extract kind, apiVersion, metadata
	var manifest struct {
		Kind       string `yaml:"kind"`
		APIVersion string `yaml:"apiVersion"`
		Metadata   struct {
			Name      string `yaml:"name"`
			Namespace string `yaml:"namespace"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal([]byte(yamlStr), &manifest); err != nil {
		return fmt.Errorf("k3s apply: parse yaml: %w", err)
	}
	if manifest.Kind == "" {
		return fmt.Errorf("k3s apply: missing 'kind' in manifest")
	}
	if manifest.APIVersion == "" {
		return fmt.Errorf("k3s apply: missing 'apiVersion' in manifest")
	}

	ns := manifest.Metadata.Namespace
	if ns == "" {
		ns = "default"
	}

	path, err := resourcePath(manifest.APIVersion, manifest.Kind, ns)
	if err != nil {
		return fmt.Errorf("k3s apply: %w", err)
	}

	// Convert YAML to JSON for the API request
	var rawDoc interface{}
	if err := yaml.Unmarshal([]byte(yamlStr), &rawDoc); err != nil {
		return fmt.Errorf("k3s apply: parse yaml for json conversion: %w", err)
	}
	// yaml.v3 unmarshals maps as map[string]interface{} on Go 1.18+
	// but may produce map[interface{}]interface{} on older versions.
	// Use the normalization helper.
	normalized := normalizeYAMLForJSON(rawDoc)
	jsonBytes, err := json.Marshal(normalized)
	if err != nil {
		return fmt.Errorf("k3s apply: marshal to json: %w", err)
	}

	fullURL := kc.serverURL + path

	// POST to create
	resp, err := kc.send(http.MethodPost, fullURL, "application/json", bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("k3s apply POST: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	switch {
	case resp.StatusCode == http.StatusConflict:
		// 409: resource exists - PATCH with strategic merge
		patchResp, err := kc.doPatch(fullURL, jsonBytes)
		if err != nil {
			return fmt.Errorf("k3s apply PATCH: %w", err)
		}
		defer patchResp.Body.Close()
		io.Copy(io.Discard, patchResp.Body)
		if patchResp.StatusCode < 200 || patchResp.StatusCode >= 300 {
			return fmt.Errorf("k3s apply PATCH: unexpected status %d", patchResp.StatusCode)
		}
		return nil
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	default:
		return fmt.Errorf("k3s apply POST: unexpected status %d", resp.StatusCode)
	}
}

// doPatch sends a strategic-merge-patch request to the given URL.
func (kc *K3sClient) doPatch(url string, body []byte) (*http.Response, error) {
	return kc.send(http.MethodPatch, url, "application/strategic-merge-patch+json", bytes.NewReader(body))
}

// send makes one request bound to the client's context (the script's
// deadline and cancel) and to the client's kubeCallTimeout.
func (kc *K3sClient) send(method, url, contentType string, body io.Reader) (*http.Response, error) {
	if err := kc.requireClient(); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(kc.ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return kc.client.Do(req)
}

// normalizeYAMLForJSON converts yaml.v3 unmarshaled types to JSON-compatible types.
// yaml.v3 returns map[string]interface{} for maps on modern Go, but we normalize
// recursively to handle any nested structures.
func normalizeYAMLForJSON(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, v2 := range val {
			out[k] = normalizeYAMLForJSON(v2)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(val))
		for k, v2 := range val {
			out[fmt.Sprintf("%v", k)] = normalizeYAMLForJSON(v2)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(val))
		for i, v2 := range val {
			out[i] = normalizeYAMLForJSON(v2)
		}
		return out
	default:
		return v
	}
}

// Threats: list and get decode name and namespace only, so env and data
// secrets in the API body are dropped. Logs and exec are capped and are not
// logged. The error stream fails the call. An empty namespace is rejected
// here. This does not grant cluster-admin and does not disable TLS verification.

type kubeObjectMeta struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
}

type kubeObjectList struct {
	Items []kubeObjectMeta `json:"items"`
}

func (kc *K3sClient) requireClient() error {
	if kc == nil || kc.client == nil || kc.ctx == nil {
		return fmt.Errorf("kube client not initialized")
	}
	return nil
}

func kubeResourceNames(kind, name, namespace string) (string, error) {
	if namespace == "" {
		return "", fmt.Errorf("namespace required")
	}
	if !isValidNamespace(namespace) {
		return "", fmt.Errorf("invalid namespace: %q", namespace)
	}
	if name != "" && !dns1123Name(name) {
		return "", fmt.Errorf("name not allowed")
	}
	api, err := kubeAPI(kind)
	if err != nil {
		return "", err
	}
	path, err := resourcePath(api, kind, namespace)
	if err != nil {
		return "", err
	}
	if name != "" {
		path += "/" + name
	}
	return path, nil
}

func (kc *K3sClient) kubeDo(method, path string, max int) ([]byte, int, error) {
	if err := kc.requireClient(); err != nil {
		return nil, 0, err
	}
	ctx, cancel := context.WithTimeout(kc.ctx, kubeCallTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, kc.serverURL+path, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := kc.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("kube %s: %w", method, err)
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, max)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func kubeMetaMap(item kubeObjectMeta) map[string]string {
	return map[string]string{
		"name":      item.Metadata.Name,
		"namespace": item.Metadata.Namespace,
	}
}

// ListResource returns name and namespace for one namespaced kind.
// An empty namespace is an error. More than kubeItemCap items is an error.
func (kc *K3sClient) ListResource(kind, namespace string) ([]map[string]string, error) {
	path, err := kubeResourceNames(kind, "", namespace)
	if err != nil {
		return nil, err
	}
	body, status, err := kc.kubeDo(http.MethodGet, path, kubeListCap)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("kube list: unexpected status %d", status)
	}
	var list kubeObjectList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("kube list: decode: %w", err)
	}
	if len(list.Items) > kubeItemCap {
		return nil, fmt.Errorf("too many items")
	}
	out := make([]map[string]string, 0, len(list.Items))
	for _, item := range list.Items {
		out = append(out, kubeMetaMap(item))
	}
	return out, nil
}

// GetResource returns name and namespace. Other object fields are discarded.
func (kc *K3sClient) GetResource(kind, name, namespace string) (map[string]string, error) {
	if name == "" {
		return nil, fmt.Errorf("name not allowed")
	}
	path, err := kubeResourceNames(kind, name, namespace)
	if err != nil {
		return nil, err
	}
	body, status, err := kc.kubeDo(http.MethodGet, path, kubeListCap)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("kube get: unexpected status %d", status)
	}
	var item kubeObjectMeta
	if err := json.Unmarshal(body, &item); err != nil {
		return nil, fmt.Errorf("kube get: decode: %w", err)
	}
	return kubeMetaMap(item), nil
}

// DeleteResource accepts 200, 202, and 204.
func (kc *K3sClient) DeleteResource(kind, name, namespace string) error {
	if name == "" {
		return fmt.Errorf("name not allowed")
	}
	path, err := kubeResourceNames(kind, name, namespace)
	if err != nil {
		return err
	}
	_, status, err := kc.kubeDo(http.MethodDelete, path, kubeListCap)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusOK, http.StatusAccepted, http.StatusNoContent:
		return nil
	default:
		return fmt.Errorf("kube delete: unexpected status %d", status)
	}
}

// PodLogs reads a capped pod log. container may be empty.
func (kc *K3sClient) PodLogs(namespace, name, container string) (string, error) {
	if namespace == "" {
		return "", fmt.Errorf("namespace required")
	}
	if !isValidNamespace(namespace) {
		return "", fmt.Errorf("invalid namespace: %q", namespace)
	}
	if !dns1123Name(name) {
		return "", fmt.Errorf("name not allowed")
	}
	if container != "" && !dns1123Name(container) {
		return "", fmt.Errorf("name not allowed")
	}
	q := url.Values{}
	q.Set("tailLines", "200")
	if container != "" {
		q.Set("container", container)
	}
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/log?%s", namespace, name, q.Encode())
	body, status, err := kc.kubeDo(http.MethodGet, path, outputCap)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("kube logs: unexpected status %d", status)
	}
	return string(body), nil
}

// PodExec attaches to one pod command over the Kubernetes exec websocket.
// Stream 3 is an error and discards any partial output.
func (kc *K3sClient) PodExec(namespace, name string, cmd []string) (string, error) {
	if namespace == "" {
		return "", fmt.Errorf("namespace required")
	}
	if !isValidNamespace(namespace) {
		return "", fmt.Errorf("invalid namespace: %q", namespace)
	}
	if !dns1123Name(name) {
		return "", fmt.Errorf("name not allowed")
	}
	if len(cmd) == 0 {
		return "", fmt.Errorf("command required")
	}
	if err := validateArgv(cmd); err != nil {
		return "", err
	}
	if err := kc.requireClient(); err != nil {
		return "", err
	}
	base, err := url.Parse(kc.serverURL)
	if err != nil || base.Host == "" {
		return "", fmt.Errorf("kube exec: bad server")
	}
	switch base.Scheme {
	case "http":
		base.Scheme = "ws"
	case "https":
		base.Scheme = "wss"
	default:
		return "", fmt.Errorf("kube exec: bad server")
	}
	q := url.Values{}
	q.Set("stdout", "true")
	q.Set("stderr", "true")
	q.Set("tty", "false")
	for _, arg := range cmd {
		q.Add("command", arg)
	}
	base.Path = fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/exec", namespace, name)
	base.RawQuery = q.Encode()
	dialer := websocket.Dialer{
		TLSClientConfig:  kc.tlsConfig,
		HandshakeTimeout: kubeCallTimeout,
		Subprotocols:     []string{"v4.channel.k8s.io"},
	}
	ctx, cancel := context.WithTimeout(kc.ctx, kubeCallTimeout)
	defer cancel()
	conn, resp, err := dialer.DialContext(ctx, base.String(), nil)
	if resp != nil && resp.Body != nil {
		_, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, outputCap))
		closeErr := resp.Body.Close()
		if err == nil && copyErr != nil {
			if conn != nil {
				conn.Close()
			}
			return "", fmt.Errorf("kube exec: %w", copyErr)
		}
		if err == nil && closeErr != nil {
			if conn != nil {
				conn.Close()
			}
			return "", fmt.Errorf("kube exec: %w", closeErr)
		}
	}
	if err != nil {
		return "", fmt.Errorf("kube exec: %w", err)
	}
	defer conn.Close()
	// The read loop also ends when the script's deadline or cancel closes
	// the stream.
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()
	if err := conn.SetReadDeadline(time.Now().Add(kubeCallTimeout)); err != nil {
		return "", err
	}
	var out strings.Builder
	for {
		_, msg, readErr := conn.ReadMessage()
		if readErr != nil {
			if websocket.IsCloseError(readErr, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived) || errors.Is(readErr, io.EOF) {
				return out.String(), nil
			}
			return "", fmt.Errorf("kube exec: %w", readErr)
		}
		if len(msg) == 0 {
			continue
		}
		payload := msg[1:]
		switch msg[0] {
		case 1, 2:
			if out.Len()+len(payload) > outputCap {
				return "", fmt.Errorf("body exceeds cap")
			}
			out.Write(payload)
		case 3:
			return "", fmt.Errorf("kube exec: %s", capText(string(payload), installErrCap))
		}
	}
}
