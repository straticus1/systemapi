package main

// ServiceManager backends: systemd and openrc (Linux), plus a "none" backend
// for unsupported platforms. The launchd backend is darwin-only and lives in
// platform_launchd_darwin.go. Each Action is a mutating, root-equivalent verb.
//
// Threats: service control is root-equivalent. argv is fixed and there is no
// shell, so a service name can never inject a command. The verb is validated
// against a closed set and the service name against serviceNameRE before it
// reaches an argument. The AllowServiceReload grant is still checked by the
// caller (sys_extras.go / sys_config.go). An unsupported platform returns the
// noneServiceManager error, never a silent success. Output is returned to the
// caller, which caps and does not log it.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// serviceVerbs is the closed set of mutating verbs.
var serviceVerbs = map[string]struct{}{
	"start": {}, "stop": {}, "restart": {}, "enable": {}, "disable": {},
}

// execDirs are the fixed directories a managed binary may live in. brew lives
// outside the system dirs, so its locations are included for darwin.
var execDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/opt/homebrew/bin", "/usr/local/bin"}

// findExecutable reports the first dir in dirs holding an executable regular
// file named name. It never consults $PATH.
func findExecutable(name string, dirs []string) (string, bool) {
	for _, dir := range dirs {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}
		return path, true
	}
	return "", false
}

func validService(verb, service string) error {
	if _, ok := serviceVerbs[verb]; !ok {
		return fmt.Errorf("unsupported service action %q", verb)
	}
	if !serviceNameRE.MatchString(service) {
		return fmt.Errorf("service not allowed")
	}
	return nil
}

// selectServiceManager picks the backend for a family. Linux prefers systemd
// when it is the live init system, else openrc; darwin uses launchd; anything
// else fails closed.
func selectServiceManager(fam OSFamily) ServiceManager {
	switch fam {
	case familyDarwin:
		return newLaunchdServiceManager()
	case familyWindows:
		return noneServiceManager{reason: "service management not supported on windows"}
	default:
		sd := systemdServiceManager{}
		if sd.Available() {
			return sd
		}
		oc := openrcServiceManager{}
		if oc.Available() {
			return oc
		}
		return sd // fails closed: Available() is false and Action errors
	}
}

// --- systemd ---

type systemdServiceManager struct{}

func (systemdServiceManager) Name() string { return "systemd" }

func (systemdServiceManager) Available() bool {
	// A live systemd exposes /run/systemd/system; fall back to the binary.
	if info, err := os.Stat("/run/systemd/system"); err == nil && info.IsDir() {
		return true
	}
	_, ok := findExecutable("systemctl", execDirs)
	return ok
}

func (m systemdServiceManager) Action(ctx context.Context, verb, service string) (string, error) {
	if err := validService(verb, service); err != nil {
		return "", err
	}
	out, err := jobCommand(ctx, "systemctl", verb, service).CombinedOutput()
	return string(out), err
}

func (m systemdServiceManager) Status(ctx context.Context, service string) (ServiceStatus, error) {
	if !serviceNameRE.MatchString(service) {
		return ServiceStatus{}, fmt.Errorf("service not allowed")
	}
	out, err := jobCommand(ctx, "systemctl", "is-active", service).Output()
	state := strings.TrimSpace(string(out))
	full, _ := jobCommand(ctx, "systemctl", "status", "--no-pager", "-n", "0", service).CombinedOutput()
	return ServiceStatus{
		Active: err == nil && state == "active",
		State:  state,
		Output: strings.TrimSpace(string(full)),
	}, nil
}

// --- openrc ---

type openrcServiceManager struct{}

func (openrcServiceManager) Name() string { return "openrc" }

func (openrcServiceManager) Available() bool {
	_, ok := findExecutable("rc-service", execDirs)
	return ok
}

func (m openrcServiceManager) Action(ctx context.Context, verb, service string) (string, error) {
	if err := validService(verb, service); err != nil {
		return "", err
	}
	// enable/disable are rc-update; the rest are rc-service verbs.
	var cmd *jobCmd
	switch verb {
	case "enable":
		cmd = jobCommand(ctx, "rc-update", "add", service)
	case "disable":
		cmd = jobCommand(ctx, "rc-update", "del", service)
	default:
		cmd = jobCommand(ctx, "rc-service", service, verb)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (m openrcServiceManager) Status(ctx context.Context, service string) (ServiceStatus, error) {
	if !serviceNameRE.MatchString(service) {
		return ServiceStatus{}, fmt.Errorf("service not allowed")
	}
	out, err := jobCommand(ctx, "rc-service", service, "status").CombinedOutput()
	text := strings.TrimSpace(string(out))
	active := err == nil && strings.Contains(text, "started")
	state := "stopped"
	if active {
		state = "started"
	}
	return ServiceStatus{Active: active, State: state, Output: text}, nil
}

// --- none (unsupported platform) ---

type noneServiceManager struct{ reason string }

func (n noneServiceManager) Name() string    { return "none" }
func (n noneServiceManager) Available() bool { return false }
func (n noneServiceManager) errReason() error {
	if n.reason != "" {
		return fmt.Errorf("%s", n.reason)
	}
	return fmt.Errorf("no service manager on this host")
}
func (n noneServiceManager) Action(ctx context.Context, verb, service string) (string, error) {
	return "", n.errReason()
}
func (n noneServiceManager) Status(ctx context.Context, service string) (ServiceStatus, error) {
	return ServiceStatus{}, n.errReason()
}
