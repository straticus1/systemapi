//go:build darwin

package main

// launchd ServiceManager for macOS. launchctl is the init system; services are
// addressed by label. This backend is darwin-only, mirroring the
// host_linux.go / host_other.go build-tag split. macOS is the design's second
// target (Decision 1), so the verb mapping is intentionally conservative.
//
// Threats: root-equivalent on a system domain label. argv is fixed, there is
// no shell, the verb is a closed set and the label is checked against
// serviceNameRE before it reaches an argument. The caller's AllowServiceReload
// grant still applies.

import (
	"context"
	"fmt"
	"strings"
)

func newLaunchdServiceManager() ServiceManager { return launchdServiceManager{} }

type launchdServiceManager struct{}

func (launchdServiceManager) Name() string { return "launchd" }

func (launchdServiceManager) Available() bool {
	_, ok := findExecutable("launchctl", execDirs)
	return ok
}

func (m launchdServiceManager) Action(ctx context.Context, verb, service string) (string, error) {
	if err := validService(verb, service); err != nil {
		return "", err
	}
	run := func(args ...string) (string, error) {
		out, err := jobCommand(ctx, "launchctl", args...).CombinedOutput()
		return string(out), err
	}
	switch verb {
	case "start":
		return run("start", service)
	case "stop":
		return run("stop", service)
	case "restart":
		stopOut, _ := run("stop", service)
		startOut, err := run("start", service)
		return stopOut + startOut, err
	case "enable":
		return run("enable", "system/"+service)
	case "disable":
		return run("disable", "system/"+service)
	default:
		return "", validService(verb, service)
	}
}

func (m launchdServiceManager) Status(ctx context.Context, service string) (ServiceStatus, error) {
	if !serviceNameRE.MatchString(service) {
		return ServiceStatus{}, nil
	}
	out, err := jobCommand(ctx, "launchctl", "list", service).CombinedOutput()
	text := strings.TrimSpace(string(out))
	state := "inactive"
	if err == nil {
		state = "active"
	}
	return ServiceStatus{Active: err == nil, State: state, Output: text}, nil
}

// IsEnabled reads the system domain's disabled list.
func (m launchdServiceManager) IsEnabled(ctx context.Context, service string) (bool, error) {
	if !serviceNameRE.MatchString(service) {
		return false, fmt.Errorf("service not allowed")
	}
	out, err := jobCommand(ctx, "launchctl", "print-disabled", "system").Output()
	if err != nil {
		return false, fmt.Errorf("launchctl print-disabled failed")
	}
	return launchdEnabledFrom(string(out), service), nil
}
