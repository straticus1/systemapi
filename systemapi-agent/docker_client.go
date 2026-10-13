package main

import (
	"bytes"
	"context"
	"encoding/binary"
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
	if len(id) == 0 || len(id) > 128 || strings.Contains(id, "..") {
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

// Threats: inspect, logs, run, and exec fail closed. Run builds the host
// config itself: no privileged, no host network, no host PID, no mounts,
// no docker socket, and no user HostConfig. Output over the cap is an
// error. Bodies are not logged. A bad id never reaches HTTP.

type dockerInspectBody struct {
	Id   string `json:"Id"`
	Name string `json:"Name"`
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
	State struct {
		Status string `json:"Status"`
	} `json:"State"`
}

func (dc *DockerClient) Inspect(id string) (map[string]string, error) {
	if dc == nil || dc.client == nil {
		return nil, fmt.Errorf("docker client not initialized")
	}
	if !isValidContainerID(id) {
		return nil, fmt.Errorf("invalid container id")
	}
	url := fmt.Sprintf("%s/%s/containers/%s/json", dc.baseURL, dockerAPIVersion, id)
	resp, err := dc.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("docker inspect: %w", err)
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, dockerBodyCap)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker inspect: unexpected status %d", resp.StatusCode)
	}
	var raw dockerInspectBody
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("docker inspect: decode: %w", err)
	}
	status := raw.State.Status
	return map[string]string{
		"id":     raw.Id,
		"name":   strings.TrimPrefix(raw.Name, "/"),
		"image":  raw.Config.Image,
		"state":  status,
		"status": status,
	}, nil
}

func (dc *DockerClient) Logs(id string) (string, error) {
	if dc == nil || dc.client == nil {
		return "", fmt.Errorf("docker client not initialized")
	}
	if !isValidContainerID(id) {
		return "", fmt.Errorf("invalid container id")
	}
	url := fmt.Sprintf("%s/%s/containers/%s/logs?stdout=1&stderr=1&tail=200", dc.baseURL, dockerAPIVersion, id)
	resp, err := dc.client.Get(url)
	if err != nil {
		return "", fmt.Errorf("docker logs: %w", err)
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, outputCap)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("docker logs: unexpected status %d", resp.StatusCode)
	}
	return demuxDocker(body)
}

func (dc *DockerClient) Run(image string, cmd []string) (string, error) {
	if dc == nil || dc.client == nil {
		return "", fmt.Errorf("docker client not initialized")
	}
	if !imageAllowed(image) {
		return "", fmt.Errorf("image not allowed")
	}
	if len(cmd) > 0 {
		if err := validateArgv(cmd); err != nil {
			return "", err
		}
	}
	id, err := dc.createContainer(image, cmd)
	if err != nil {
		return "", err
	}
	if !isValidContainerID(id) {
		return "", fmt.Errorf("invalid container id")
	}
	if err := dc.StartContainer(id); err != nil {
		return "", err
	}
	return id, nil
}

func (dc *DockerClient) createContainer(image string, cmd []string) (string, error) {
	body := struct {
		Image      string   `json:"Image"`
		Cmd        []string `json:"Cmd,omitempty"`
		HostConfig struct {
			Privileged  bool     `json:"Privileged"`
			NetworkMode string   `json:"NetworkMode"`
			PidMode     string   `json:"PidMode"`
			Binds       []string `json:"Binds"`
			Mounts      []string `json:"Mounts"`
			CapDrop     []string `json:"CapDrop"`
			SecurityOpt []string `json:"SecurityOpt"`
		} `json:"HostConfig"`
	}{
		Image: image,
	}
	if len(cmd) > 0 {
		body.Cmd = cmd
	}
	body.HostConfig.Privileged = false
	body.HostConfig.NetworkMode = "bridge"
	body.HostConfig.PidMode = ""
	body.HostConfig.CapDrop = []string{"ALL"}
	body.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/%s/containers/create", dc.baseURL, dockerAPIVersion)
	resp, err := dc.client.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		return "", fmt.Errorf("docker create: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := readLimited(resp.Body, dockerBodyCap)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("docker create: unexpected status %d", resp.StatusCode)
	}
	var created struct {
		Id string `json:"Id"`
	}
	if err := json.Unmarshal(respBody, &created); err != nil {
		return "", fmt.Errorf("docker create: decode: %w", err)
	}
	return created.Id, nil
}

func (dc *DockerClient) Exec(id string, cmd []string) (string, error) {
	if dc == nil || dc.client == nil {
		return "", fmt.Errorf("docker client not initialized")
	}
	if !isValidContainerID(id) {
		return "", fmt.Errorf("invalid container id")
	}
	if len(cmd) == 0 {
		return "", fmt.Errorf("command required")
	}
	if err := validateArgv(cmd); err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{
		"AttachStdout": true,
		"AttachStderr": true,
		"Tty":          false,
		"Cmd":          cmd,
	})
	if err != nil {
		return "", err
	}
	createURL := fmt.Sprintf("%s/%s/containers/%s/exec", dc.baseURL, dockerAPIVersion, id)
	resp, err := dc.client.Post(createURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("docker exec: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := readLimited(resp.Body, dockerBodyCap)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("docker exec: unexpected status %d", resp.StatusCode)
	}
	var created struct {
		Id string `json:"Id"`
	}
	if err := json.Unmarshal(respBody, &created); err != nil {
		return "", fmt.Errorf("docker exec: decode: %w", err)
	}
	if !isValidContainerID(created.Id) {
		return "", fmt.Errorf("invalid exec id")
	}
	startPath := fmt.Sprintf("/%s/exec/%s/start", dockerAPIVersion, created.Id)
	startBody := []byte(`{"Detach":false,"Tty":false}`)
	var stream []byte
	if dc.useUnixExec() {
		stream, err = dc.execUnix(startPath, startBody)
		if err != nil {
			return "", err
		}
	} else {
		stream, err = dc.execHTTP(dc.baseURL+startPath, startBody)
		if err != nil {
			return "", err
		}
	}
	return demuxDocker(stream)
}

func (dc *DockerClient) useUnixExec() bool {
	return dc.socketPath != "" && dc.baseURL == "http://localhost"
}

func (dc *DockerClient) execHTTP(url string, body []byte) ([]byte, error) {
	client := &http.Client{Transport: dc.client.Transport, Timeout: 15 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("docker exec: %w", err)
	}
	defer resp.Body.Close()
	raw, err := readLimited(resp.Body, outputCap)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("docker exec: unexpected status %d", resp.StatusCode)
	}
	return raw, nil
}

func (dc *DockerClient) execUnix(path string, body []byte) ([]byte, error) {
	conn, err := net.DialTimeout("unix", dc.socketPath, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("docker exec: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return nil, err
	}
	var req bytes.Buffer
	fmt.Fprintf(&req, "POST %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n", path, len(body))
	req.Write(body)
	if _, err := req.WriteTo(conn); err != nil {
		return nil, fmt.Errorf("docker exec: %w", err)
	}
	raw, err := readLimited(conn, dockerBodyCap)
	if err != nil {
		return nil, err
	}
	return parseDockerHTTP(raw)
}

func parseDockerHTTP(raw []byte) ([]byte, error) {
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil, fmt.Errorf("docker exec: bad response")
	}
	header := raw[:idx]
	line := header
	if nl := bytes.Index(header, []byte("\r\n")); nl >= 0 {
		line = header[:nl]
	}
	status := string(line)
	if !strings.Contains(status, " 200 ") && !strings.Contains(status, " 101 ") {
		return nil, fmt.Errorf("docker exec: unexpected status")
	}
	return raw[idx+4:], nil
}

func demuxDocker(body []byte) (string, error) {
	if len(body) == 0 {
		return "", nil
	}
	var out []byte
	for len(body) > 0 {
		if len(body) < 8 {
			return "", fmt.Errorf("docker stream: short frame")
		}
		stream := body[0]
		size := binary.BigEndian.Uint32(body[4:8])
		if size > outputCap {
			return "", fmt.Errorf("body exceeds cap")
		}
		body = body[8:]
		if int(size) > len(body) {
			return "", fmt.Errorf("docker stream: short frame")
		}
		frame := body[:size]
		body = body[size:]
		if stream != 1 && stream != 2 {
			continue
		}
		if len(out)+len(frame) > outputCap {
			return "", fmt.Errorf("body exceeds cap")
		}
		out = append(out, frame...)
	}
	return string(out), nil
}
