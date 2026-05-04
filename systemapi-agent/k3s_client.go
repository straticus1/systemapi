package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
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
