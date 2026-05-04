package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const dockerAPIVersion = "v1.41"

// DockerClient communicates with the Docker Engine API over a Unix socket.
type DockerClient struct {
	client     *http.Client
	socketPath string
	baseURL    string // default "http://localhost" for Unix socket; overridden in tests
}

// DockerContainer represents a container from the Docker API list endpoint.
type DockerContainer struct {
	Id    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
	State string   `json:"State"`
}

// NewDockerClient creates a client that talks to the Docker Engine API.
// Per D-01: reads DOCKER_HOST env var; falls back to /var/run/docker.sock.
func NewDockerClient() *DockerClient {
	socketPath := "/var/run/docker.sock"
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		if strings.HasPrefix(h, "unix://") {
			socketPath = strings.TrimPrefix(h, "unix://")
		} else {
			socketPath = h
		}
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &DockerClient{
		client:     &http.Client{Transport: transport, Timeout: 10 * time.Second},
		socketPath: socketPath,
		baseURL:    "http://localhost",
	}
}
