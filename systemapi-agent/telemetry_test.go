package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestTelemetryStructTags verifies that telemetry struct JSON tags match proto-compatible values (AGENT-06).
// Note: RxBytes/TxBytes use rx_bytes/tx_bytes tags (cumulative counts), diverging from proto's
// rx_bytes_per_sec/tx_bytes_per_sec since we store cumulative values, not rates.
func TestTelemetryStructTags(t *testing.T) {
	// Verify DockerStatsTelemetry JSON tags
	dt := reflect.TypeOf(DockerStatsTelemetry{})
	expectedDocker := map[string]string{
		"Available":         "available",
		"TotalContainers":   "total_containers",
		"RunningContainers": "running_containers",
		"Containers":        "containers",
	}
	for field, tag := range expectedDocker {
		f, ok := dt.FieldByName(field)
		if !ok {
			t.Errorf("DockerStatsTelemetry missing field %s", field)
			continue
		}
		got := f.Tag.Get("json")
		if got != tag {
			t.Errorf("DockerStatsTelemetry.%s json tag = %q, want %q", field, got, tag)
		}
	}

	// Verify ContainerStatsTelemetry JSON tags
	ct := reflect.TypeOf(ContainerStatsTelemetry{})
	expectedContainer := map[string]string{
		"Id": "id", "Name": "name", "Image": "image", "State": "state",
		"CpuPct": "cpu_pct", "MemUsedBytes": "mem_used_bytes",
		"MemLimitBytes": "mem_limit_bytes", "MemPct": "mem_pct",
		"RxBytes": "rx_bytes", "TxBytes": "tx_bytes",
		"RestartCount": "restart_count",
	}
	for field, tag := range expectedContainer {
		f, ok := ct.FieldByName(field)
		if !ok {
			t.Errorf("ContainerStatsTelemetry missing field %s", field)
			continue
		}
		got := f.Tag.Get("json")
		if got != tag {
			t.Errorf("ContainerStatsTelemetry.%s json tag = %q, want %q", field, got, tag)
		}
	}

	// Verify K3sStatsTelemetry JSON tags
	kt := reflect.TypeOf(K3sStatsTelemetry{})
	expectedK3s := map[string]string{
		"Available": "available", "TotalNodes": "total_nodes",
		"ReadyNodes": "ready_nodes", "TotalPods": "total_pods",
		"RunningPods": "running_pods", "FailedPods": "failed_pods",
		"Nodes": "nodes",
	}
	for field, tag := range expectedK3s {
		f, ok := kt.FieldByName(field)
		if !ok {
			t.Errorf("K3sStatsTelemetry missing field %s", field)
			continue
		}
		got := f.Tag.Get("json")
		if got != tag {
			t.Errorf("K3sStatsTelemetry.%s json tag = %q, want %q", field, got, tag)
		}
	}

	// Verify TelemetryPayload has Docker and K3s fields
	tp := reflect.TypeOf(TelemetryPayload{})
	dockerField, ok := tp.FieldByName("Docker")
	if !ok {
		t.Fatal("TelemetryPayload missing Docker field")
	}
	if dockerField.Tag.Get("json") != "docker,omitempty" {
		t.Errorf("TelemetryPayload.Docker json tag = %q, want %q", dockerField.Tag.Get("json"), "docker,omitempty")
	}
	k3sField, ok := tp.FieldByName("K3s")
	if !ok {
		t.Fatal("TelemetryPayload missing K3s field")
	}
	if k3sField.Tag.Get("json") != "k3s,omitempty" {
		t.Errorf("TelemetryPayload.K3s json tag = %q, want %q", k3sField.Tag.Get("json"), "k3s,omitempty")
	}
}

// TestTelemetryPayloadJSON verifies that Docker and k3s fields are correctly serialized to JSON.
func TestTelemetryPayloadJSON(t *testing.T) {
	payload := TelemetryPayload{
		Timestamp: 1234567890,
		Docker: &DockerStatsTelemetry{
			Available:         true,
			TotalContainers:   2,
			RunningContainers: 1,
			Containers: []ContainerStatsTelemetry{
				{Id: "abc", Name: "test", CpuPct: 5.5, MemPct: 25.0, RxBytes: 1024, TxBytes: 2048},
			},
		},
		K3s: &K3sStatsTelemetry{
			Available:  true,
			TotalNodes: 1,
			ReadyNodes: 1,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, key := range []string{`"docker"`, `"k3s"`, `"available"`, `"total_containers"`, `"cpu_pct"`, `"total_nodes"`, `"rx_bytes"`, `"tx_bytes"`} {
		if !strings.Contains(s, key) {
			t.Errorf("JSON missing expected key %s", key)
		}
	}
	// Verify we do NOT have per_sec field names in JSON
	if strings.Contains(s, `"rx_bytes_per_sec"`) {
		t.Error("JSON should not contain rx_bytes_per_sec (use rx_bytes)")
	}
	if strings.Contains(s, `"tx_bytes_per_sec"`) {
		t.Error("JSON should not contain tx_bytes_per_sec (use tx_bytes)")
	}
}

// TestTelemetryPayloadOmitEmpty verifies that nil Docker and K3s fields are omitted from JSON.
func TestTelemetryPayloadOmitEmpty(t *testing.T) {
	payload := TelemetryPayload{Timestamp: 1234567890}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if strings.Contains(s, `"docker"`) {
		t.Error("JSON should not contain docker when nil")
	}
	if strings.Contains(s, `"k3s"`) {
		t.Error("JSON should not contain k3s when nil")
	}
}
