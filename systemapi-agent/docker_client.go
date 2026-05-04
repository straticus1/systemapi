package main

import (
	"context"
	"encoding/json"
	"fmt"
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

// DockerStatsResponse represents the Docker stats API response (stream=false).
type DockerStatsResponse struct {
	CPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs     int    `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemCPUUsage uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64 `json:"usage"`
		Limit uint64 `json:"limit"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
	} `json:"networks"`
}

// ContainerStats holds computed stats for a single container.
type ContainerStats struct {
	Id            string
	Name          string
	Image         string
	State         string
	CpuPct        float64
	MemUsedBytes  uint64
	MemLimitBytes uint64
	MemPct        float64
	RxBytes       uint64
	TxBytes       uint64
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

// isValidContainerID validates that a container ID is safe to use in a URL path.
// T-03-06: prevents path injection via / and .. sequences.
func isValidContainerID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// ListContainers returns all containers (running and stopped) from the Docker API.
func (dc *DockerClient) ListContainers() ([]DockerContainer, error) {
	url := fmt.Sprintf("%s/%s/containers/json?all=true", dc.baseURL, dockerAPIVersion)
	resp, err := dc.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("docker list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker list: unexpected status %d", resp.StatusCode)
	}

	var containers []DockerContainer
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("docker list: decode: %w", err)
	}
	return containers, nil
}

// GetContainerStats fetches resource stats for a single container.
// T-03-07: always uses stream=false to avoid blocking forever.
func (dc *DockerClient) GetContainerStats(id string) (*ContainerStats, error) {
	if !isValidContainerID(id) {
		return nil, fmt.Errorf("docker stats: invalid container ID %q", id)
	}

	url := fmt.Sprintf("%s/%s/containers/%s/stats?stream=false", dc.baseURL, dockerAPIVersion, id)
	resp, err := dc.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("docker stats: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker stats: unexpected status %d", resp.StatusCode)
	}

	var raw DockerStatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("docker stats: decode: %w", err)
	}

	// CPU% = (cpu_delta / sys_delta) * online_cpus * 100
	cpuDelta := raw.CPUStats.CPUUsage.TotalUsage - raw.PreCPUStats.CPUUsage.TotalUsage
	sysDelta := raw.CPUStats.SystemCPUUsage - raw.PreCPUStats.SystemCPUUsage
	var cpuPct float64
	if sysDelta > 0 && raw.CPUStats.OnlineCPUs > 0 {
		cpuPct = (float64(cpuDelta) / float64(sysDelta)) * float64(raw.CPUStats.OnlineCPUs) * 100.0
	}

	// Mem% = usage / limit * 100
	var memPct float64
	if raw.MemoryStats.Limit > 0 {
		memPct = (float64(raw.MemoryStats.Usage) / float64(raw.MemoryStats.Limit)) * 100.0
	}

	// Sum network bytes across all interfaces
	var rxBytes, txBytes uint64
	for _, iface := range raw.Networks {
		rxBytes += iface.RxBytes
		txBytes += iface.TxBytes
	}

	return &ContainerStats{
		Id:            id,
		CpuPct:        cpuPct,
		MemUsedBytes:  raw.MemoryStats.Usage,
		MemLimitBytes: raw.MemoryStats.Limit,
		MemPct:        memPct,
		RxBytes:       rxBytes,
		TxBytes:       txBytes,
	}, nil
}

// StartContainer starts a stopped container. 204 = success, 304 = already running (also success).
func (dc *DockerClient) StartContainer(id string) error {
	if !isValidContainerID(id) {
		return fmt.Errorf("docker start: invalid container ID %q", id)
	}
	url := fmt.Sprintf("%s/%s/containers/%s/start", dc.baseURL, dockerAPIVersion, id)
	return dc.doContainerPost(url, "start")
}

// StopContainer stops a running container.
func (dc *DockerClient) StopContainer(id string) error {
	if !isValidContainerID(id) {
		return fmt.Errorf("docker stop: invalid container ID %q", id)
	}
	url := fmt.Sprintf("%s/%s/containers/%s/stop?t=10", dc.baseURL, dockerAPIVersion, id)
	return dc.doContainerPost(url, "stop")
}

// RestartContainer restarts a container.
func (dc *DockerClient) RestartContainer(id string) error {
	if !isValidContainerID(id) {
		return fmt.Errorf("docker restart: invalid container ID %q", id)
	}
	url := fmt.Sprintf("%s/%s/containers/%s/restart?t=10", dc.baseURL, dockerAPIVersion, id)
	return dc.doContainerPost(url, "restart")
}

// doContainerPost sends a POST to a Docker container lifecycle endpoint and checks status.
// 204 (No Content) and 304 (Not Modified / already in target state) are both success.
func (dc *DockerClient) doContainerPost(url, op string) error {
	resp, err := dc.client.Post(url, "application/json", nil)
	if err != nil {
		return fmt.Errorf("docker %s: %w", op, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusNotModified:
		return nil
	default:
		return fmt.Errorf("docker %s: unexpected status %d", op, resp.StatusCode)
	}
}
