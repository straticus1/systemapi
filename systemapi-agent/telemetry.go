package main

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// TelemetryPayload represents the physical state of the host
type TelemetryPayload struct {
	Timestamp   int64                 `json:"timestamp"`
	Host        HostInfo              `json:"host"`
	CPU         CPUMetrics            `json:"cpu"`
	Memory      MemoryMetrics         `json:"memory"`
	Disk        []DiskMetrics         `json:"disk"`
	Network     NetworkMetrics        `json:"network"`
	Software    []SoftwareMetrics     `json:"software,omitempty"`
	Docker      *DockerStatsTelemetry `json:"docker,omitempty"`
	K3s         *K3sStatsTelemetry    `json:"k3s,omitempty"`
}

// HostInfo.Hostname is the enrolled --hostname, the name the control plane
// resolves. OSHostname is what the OS reports; it is informational only.
type HostInfo struct {
	Hostname   string `json:"hostname"`
	OSHostname string `json:"os_hostname,omitempty"`
	OS       string `json:"os"`
	Platform string `json:"platform"`
	Uptime   uint64 `json:"uptime"`
}

type CPUMetrics struct {
	UsagePercent float64 `json:"usage_percent"`
	Cores        int     `json:"cores"`
}

type MemoryMetrics struct {
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

type DiskMetrics struct {
	Path        string  `json:"path"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

type NetworkMetrics struct {
	BytesRecv uint64 `json:"bytes_recv"`
	BytesSent uint64 `json:"bytes_sent"`
}

// ContainerStatsTelemetry mirrors proto ContainerStats JSON shape (AGENT-06).
// Note: rx_bytes and tx_bytes store cumulative byte counts, not per-second rates.
type ContainerStatsTelemetry struct {
	Id            string  `json:"id"`
	Name          string  `json:"name"`
	Image         string  `json:"image"`
	State         string  `json:"state"`
	CpuPct        float64 `json:"cpu_pct"`
	MemUsedBytes  int64   `json:"mem_used_bytes"`
	MemLimitBytes int64   `json:"mem_limit_bytes"`
	MemPct        float64 `json:"mem_pct"`
	RxBytes       uint64  `json:"rx_bytes"`
	TxBytes       uint64  `json:"tx_bytes"`
	RestartCount  int32   `json:"restart_count"`
}

// DockerStatsTelemetry mirrors proto DockerStats JSON shape (AGENT-06).
type DockerStatsTelemetry struct {
	Available         bool                      `json:"available"`
	TotalContainers   int32                     `json:"total_containers"`
	RunningContainers int32                     `json:"running_containers"`
	Containers        []ContainerStatsTelemetry `json:"containers"`
}

// NodeInfoTelemetry mirrors proto NodeInfo JSON shape (AGENT-06).
type NodeInfoTelemetry struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	Status  string `json:"status"`
	Version string `json:"version"`
}

// K3sStatsTelemetry mirrors proto K3SStats JSON shape (AGENT-06).
type K3sStatsTelemetry struct {
	Available   bool                `json:"available"`
	TotalNodes  int32               `json:"total_nodes"`
	ReadyNodes  int32               `json:"ready_nodes"`
	TotalPods   int32               `json:"total_pods"`
	RunningPods int32               `json:"running_pods"`
	FailedPods  int32               `json:"failed_pods"`
	Nodes       []NodeInfoTelemetry `json:"nodes"`
}

var lastNetStats []net.IOCountersStat
var lastNetTime time.Time

var lastSoftwareGather time.Time
var cachedSoftware []SoftwareMetrics

var dockerClientTelemetry *DockerClient
var k3sClientTelemetry *K3sClient
var telemetryClientsOnce sync.Once

func ensureTelemetryClients() {
	telemetryClientsOnce.Do(func() {
		dockerClientTelemetry = NewDockerClient(context.Background())
		k3sClientTelemetry, _ = NewK3sClient(context.Background()) // nil if no kubeconfig (D-05: non-fatal)
	})
}

// gatherDockerStats collects Docker container stats. Returns available=false on error (D-02).
func gatherDockerStats() *DockerStatsTelemetry {
	ensureTelemetryClients()
	result := &DockerStatsTelemetry{}

	containers, err := dockerClientTelemetry.ListContainers()
	if err != nil {
		log.Printf("[telemetry] Docker stats unavailable: %v", err)
		result.Available = false
		return result
	}

	result.Available = true
	result.TotalContainers = int32(len(containers))

	var running int32
	for _, c := range containers {
		if c.State == "running" {
			running++
		}
		stats, err := dockerClientTelemetry.GetContainerStats(c.Id)
		if err != nil {
			log.Printf("[telemetry] container stats for %s: %v", c.Id, err)
			continue
		}
		name := c.Id[:12] // short ID as fallback
		if len(c.Id) < 12 {
			name = c.Id
		}
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		result.Containers = append(result.Containers, ContainerStatsTelemetry{
			Id:            c.Id,
			Name:          name,
			Image:         c.Image,
			State:         c.State,
			CpuPct:        stats.CpuPct,
			MemUsedBytes:  int64(stats.MemUsedBytes),
			MemLimitBytes: int64(stats.MemLimitBytes),
			MemPct:        stats.MemPct,
			RxBytes:       stats.RxBytes,
			TxBytes:       stats.TxBytes,
		})
	}
	result.RunningContainers = running
	return result
}

// gatherK3sStats collects k3s cluster state. Returns nil when k3s is unavailable (D-05).
func gatherK3sStats() *K3sStatsTelemetry {
	ensureTelemetryClients()
	if k3sClientTelemetry == nil {
		return nil // k3s not available (D-05)
	}
	result := &K3sStatsTelemetry{}

	nodes, err := k3sClientTelemetry.ListNodes()
	if err != nil {
		log.Printf("[telemetry] k3s stats unavailable: %v", err)
		result.Available = false
		return result
	}
	result.Available = true
	result.TotalNodes = int32(len(nodes))

	for _, n := range nodes {
		status := "NotReady"
		for _, cond := range n.Status.Conditions {
			if cond.Type == "Ready" && cond.Status == "True" {
				status = "Ready"
				result.ReadyNodes++
				break
			}
		}
		role := "worker"
		for label := range n.Metadata.Labels {
			if strings.HasPrefix(label, "node-role.kubernetes.io/") {
				role = strings.TrimPrefix(label, "node-role.kubernetes.io/")
				if role == "" {
					role = "master"
				}
				break
			}
		}
		result.Nodes = append(result.Nodes, NodeInfoTelemetry{
			Name:    n.Metadata.Name,
			Role:    role,
			Status:  status,
			Version: n.Status.NodeInfo.KubeletVersion,
		})
	}

	pods, err := k3sClientTelemetry.ListPods("")
	if err == nil {
		result.TotalPods = int32(len(pods))
		for _, p := range pods {
			switch p.Status.Phase {
			case "Running":
				result.RunningPods++
			case "Failed":
				result.FailedPods++
			}
		}
	}

	return result
}

func gatherTelemetry(enrolledHostname string) (TelemetryPayload, error) {
	var payload TelemetryPayload
	payload.Timestamp = time.Now().Unix()

	// 1. Host Info
	payload.Host.Hostname = enrolledHostname
	hInfo, err := host.Info()
	if err == nil {
		payload.Host = HostInfo{
			Hostname:   enrolledHostname,
			OSHostname: hInfo.Hostname,
			OS:       hInfo.OS,
			Platform: hInfo.Platform,
			Uptime:   hInfo.Uptime,
		}
	}

	// 2. CPU
	cpuPercents, err := cpu.Percent(0, false)
	if err == nil && len(cpuPercents) > 0 {
		cores, _ := cpu.Counts(true)
		payload.CPU = CPUMetrics{
			UsagePercent: cpuPercents[0],
			Cores:        cores,
		}
	}

	// 3. Memory
	vMem, err := mem.VirtualMemory()
	if err == nil {
		payload.Memory = MemoryMetrics{
			Total:       vMem.Total,
			Used:        vMem.Used,
			Free:        vMem.Free,
			UsedPercent: vMem.UsedPercent,
		}
	}

	// 4. Disk
	partitions, _ := disk.Partitions(false)
	// Just grab the root partition to avoid massive payloads, or grab all physical
	for _, p := range partitions {
		// Example: limit to root or main drives to be simple
		if p.Mountpoint == "/" || p.Mountpoint == "C:\\" {
			usage, err := disk.Usage(p.Mountpoint)
			if err == nil {
				payload.Disk = append(payload.Disk, DiskMetrics{
					Path:        p.Mountpoint,
					Total:       usage.Total,
					Used:        usage.Used,
					Free:        usage.Free,
					UsedPercent: usage.UsedPercent,
				})
			}
		}
	}

	// 5. Network (calculate bytes/sec since last call)
	netStats, err := net.IOCounters(false)
	if err == nil && len(netStats) > 0 {
		now := time.Now()
		stat := netStats[0]

		if len(lastNetStats) > 0 {
			duration := now.Sub(lastNetTime).Seconds()
			if duration > 0 {
				payload.Network = NetworkMetrics{
					BytesRecv: uint64(float64(stat.BytesRecv-lastNetStats[0].BytesRecv) / duration),
					BytesSent: uint64(float64(stat.BytesSent-lastNetStats[0].BytesSent) / duration),
				}
			}
		} else {
			// First run
			payload.Network = NetworkMetrics{
				BytesRecv: 0,
				BytesSent: 0,
			}
		}

		lastNetStats = netStats
		lastNetTime = now
	}

	// 6. Software Inventory
	now := time.Now()
	// Only scan installed software every 5 minutes to reduce IO overhead
	if now.Sub(lastSoftwareGather) > 5*time.Minute {
		cachedSoftware = gatherSoftware()
		lastSoftwareGather = now
	}
	payload.Software = cachedSoftware

	// 7. Docker stats (non-fatal, re-query every tick, no caching)
	payload.Docker = gatherDockerStats()

	// 8. k3s stats (non-fatal, re-query every tick)
	payload.K3s = gatherK3sStats()

	return payload, nil
}
