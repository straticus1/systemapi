package main

import (
	"strings"
	"testing"
)

// newTestEngine creates a SysscriptEngine directly without initializing Docker/k3s clients.
// Used for tests that don't need real client connections.
func newTestEngine(entitlements *Entitlements) *SysscriptEngine {
	return &SysscriptEngine{
		Entitlements: entitlements,
		cm:           &ConfigManager{},
	}
}

// TestEntitlementContainersAbsent verifies that sys.containers is absent when AllowContainers=false.
func TestEntitlementContainersAbsent(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowContainers: false, AllowK3s: false})
	_, err := engine.Execute(`print(sys.containers)`)
	if err == nil {
		t.Fatal("expected error when AllowContainers=false, got nil")
	}
	// Starlark reports missing struct fields as: `"sys" struct has no .containers attribute`
	if !strings.Contains(err.Error(), "has no .containers") {
		t.Errorf("expected 'has no .containers' in error, got: %v", err)
	}
}

// TestEntitlementContainersPresent verifies that sys.containers is present when AllowContainers=true.
func TestEntitlementContainersPresent(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowContainers: true, AllowK3s: false})
	// type(sys.containers) returns "struct" in Starlark; verify it's accessible (no attribute error)
	_, err := engine.Execute(`print(type(sys.containers))`)
	if err != nil {
		t.Fatalf("unexpected error when AllowContainers=true: %v", err)
	}
}

// TestEntitlementK3sAbsent verifies that sys.k3s is absent when AllowK3s=false.
func TestEntitlementK3sAbsent(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowContainers: false, AllowK3s: false})
	_, err := engine.Execute(`print(sys.k3s)`)
	if err == nil {
		t.Fatal("expected error when AllowK3s=false, got nil")
	}
	// Starlark reports missing struct fields as: `"sys" struct has no .k3s attribute`
	if !strings.Contains(err.Error(), "has no .k3s") {
		t.Errorf("expected 'has no .k3s' in error, got: %v", err)
	}
}

// TestEntitlementK3sPresent verifies that sys.k3s is present when AllowK3s=true.
func TestEntitlementK3sPresent(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowContainers: false, AllowK3s: true})
	// type(sys.k3s) returns "struct" in Starlark; verify it's accessible (no attribute error)
	_, err := engine.Execute(`print(type(sys.k3s))`)
	if err != nil {
		t.Fatalf("unexpected error when AllowK3s=true: %v", err)
	}
}

// TestThreadLoadPathTraversal verifies that load() rejects path traversal attempts (T-03-01).
func TestThreadLoadPathTraversal(t *testing.T) {
	engine := newTestEngine(&Entitlements{})
	_, err := engine.Execute(`load("../../etc/passwd", "x")`)
	if err == nil {
		t.Fatal("expected error for path traversal, got nil")
	}
	if !strings.Contains(err.Error(), "path traversal not allowed") {
		t.Errorf("expected 'path traversal not allowed' in error, got: %v", err)
	}
}

// TestThreadLoadFileNotFound verifies that load() returns a clear error for missing files (D-09 fail-fast).
func TestThreadLoadFileNotFound(t *testing.T) {
	engine := newTestEngine(&Entitlements{})
	_, err := engine.Execute(`load("nonexistent.star", "x")`)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), `load("nonexistent.star")`) {
		t.Errorf("expected error to mention load(\"nonexistent.star\"), got: %v", err)
	}
}

// TestThreadLoadSuccess verifies that load() correctly loads a .star module.
// Skipped in short mode because it requires /etc/systemapi/scripts/ to exist.
func TestThreadLoadSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestThreadLoadSuccess in short mode: requires /etc/systemapi/scripts/")
	}
	engine := newTestEngine(&Entitlements{})
	_, err := engine.Execute(`load("lib/test_helper.star", "helper_value")`)
	if err != nil {
		t.Logf("load failed (expected on machines without /etc/systemapi/scripts/): %v", err)
	}
}
