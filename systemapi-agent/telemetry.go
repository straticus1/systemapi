package main

import (
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
)

// TelemetryPayload represents the physical state of the host
type TelemetryPayload struct {
	Timestamp   int64              `json:"timestamp"`
	Host        HostInfo           `json:"host"`
	CPU         CPUMetrics         `json:"cpu"`
	Memory      MemoryMetrics      `json:"memory"`
	Disk        []DiskMetrics      `json:"disk"`
	Network     NetworkMetrics     `json:"network"`
}

type HostInfo struct {
	Hostname string `json:"hostname"`
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

var lastNetStats []net.IOCountersStat
var lastNetTime time.Time

func gatherTelemetry() (TelemetryPayload, error) {
	var payload TelemetryPayload
	payload.Timestamp = time.Now().Unix()

	// 1. Host Info
	hInfo, err := host.Info()
	if err == nil {
		payload.Host = HostInfo{
			Hostname: hInfo.Hostname,
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

	return payload, nil
}
