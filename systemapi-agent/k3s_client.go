package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// K3sClient communicates with the Kubernetes API using TLS from kubeconfig.
type K3sClient struct {
	client    *http.Client
	serverURL string
}

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

// NewK3sClient creates a client from kubeconfig.
// Per D-04: tries /etc/rancher/k3s/k3s.yaml first, then KUBECONFIG env var.
func NewK3sClient() (*K3sClient, error) {
	kubeconfigPath := "/etc/rancher/k3s/k3s.yaml"
	if _, err := os.Stat(kubeconfigPath); os.IsNotExist(err) {
		kubeconfigPath = os.Getenv("KUBECONFIG")
		if kubeconfigPath == "" {
			return nil, fmt.Errorf("no kubeconfig found: /etc/rancher/k3s/k3s.yaml missing and KUBECONFIG not set")
		}
	}

	data, err := os.ReadFile(kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("read kubeconfig: %w", err)
	}

	var kc kubeconfig
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return nil, fmt.Errorf("parse kubeconfig: %w", err)
	}
	if len(kc.Clusters) == 0 || len(kc.Users) == 0 {
		return nil, fmt.Errorf("kubeconfig missing clusters or users")
	}

	// Decode base64-encoded PEM certs (Pitfall 3 from RESEARCH.md)
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
	caCertPool.AppendCertsFromPEM(caCertPEM)
	tlsCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load TLS keypair: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      caCertPool,
			Certificates: []tls.Certificate{tlsCert},
		},
	}

	return &K3sClient{
		client:    &http.Client{Transport: transport, Timeout: 10 * time.Second},
		serverURL: kc.Clusters[0].Cluster.Server,
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
	resp, err := kc.client.Get(kc.serverURL + "/api/v1/nodes")
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

	resp, err := kc.client.Get(path)
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
	resp, err := kc.client.Post(fullURL, "application/json", bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("k3s apply POST: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	switch {
	case resp.StatusCode == http.StatusConflict:
		// 409: resource exists — PATCH with strategic merge
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
	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/strategic-merge-patch+json")
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
