package main

// Phase 0 platform abstraction (docs/sah-os-management-design.md). The agent
// used to hardcode apt-get/dnf, systemctl, and /proc/sys. This package-main
// set detects the OS family and routes OS operations through four backend
// interfaces so the same sys.* surface works across init systems and package
// managers. The existing sys_* Starlark modules call through these backends.
//
// Threats: this file only *selects* a backend from the detected OS family and
// advertises capability probes. It opens no socket, runs no command, and
// writes nothing; selection grants nothing. Every mutating backend
// (platform_service.go, platform_package.go, platform_config.go,
// platform_tweak.go) re-checks its own grant and uses fixed argv with no
// shell. An unsupported platform is answered by a "none" backend that fails
// closed, never a silent success.

import (
	"context"
	"regexp"
	"runtime"
	"sync"
)

// OSFamily is the coarse OS grouping that decides which backends apply.
type OSFamily string

const (
	familyRHEL    OSFamily = "rhel"    // Rocky/CentOS/Fedora/Oracle/Amazon (dnf/yum)
	familyDebian  OSFamily = "debian"  // Debian/Ubuntu/Mint (apt-get)
	familySUSE    OSFamily = "suse"    // openSUSE/SLES (zypper)
	familyArch    OSFamily = "arch"    // Arch/Manjaro
	familyDarwin  OSFamily = "darwin"  // macOS (launchd/brew)
	familyWindows OSFamily = "windows" // Windows (deferred)
	familyOther   OSFamily = "other"   // unknown Linux or unknown OS
)

// Service/unit name guards. argv is always fixed and shell-free, so these are
// defence in depth against a control character or an overlong name slipping
// through an entitlement list into an argument position.
var (
	serviceNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9@._:-]{0,127}$`)
	unitNameRE    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9@._:-]{0,127}$`)
)

// ServiceStatus is the structured result of a service status query.
type ServiceStatus struct {
	Active bool
	State  string
	Output string
}

// ServiceManager controls init-system services. Verbs mirror the existing
// sys.services surface: status, start, stop, restart, enable, disable.
type ServiceManager interface {
	Name() string
	// Available reports whether this backend can run on the host now.
	Available() bool
	// Action runs one mutating verb (start/stop/restart/enable/disable) and
	// returns the combined command output. An unknown verb is rejected. The
	// command is stopped when ctx (the script's context) ends.
	Action(ctx context.Context, verb, service string) (output string, err error)
	// Status returns a structured status for one service.
	Status(ctx context.Context, service string) (ServiceStatus, error)
}

// PackageManager builds fixed argv for a package manager and reports whether
// its binary is present. Verbs: query, install, remove, upgrade.
type PackageManager interface {
	Name() string
	Available() bool
	InstallArgv(name string) ([]string, error)
	RemoveArgv(name string) ([]string, error)
	UpgradeArgv(name string) ([]string, error)
	QueryArgv(name string) ([]string, error)
	ListArgv() ([]string, error)
}

// ConfigStore owns config file writes and the reload/validate hooks around
// them: atomic write (via config_manager.go), a per-service validate hook,
// and a per-init-system reload hook.
type ConfigStore interface {
	Name() string
	Available() bool
	AtomicWrite(path, content string) error
	Validate(ctx context.Context, service, path string) (output string, err error)
	Reload(ctx context.Context, service string) (output string, err error)
}

// Tweaks covers kernel and service-limit knobs: sysctl get/set, resource
// limits, and unit/launchd overrides. Kernel modules and firewall rules are
// out of v1 (design Decision 2).
type Tweaks interface {
	Name() string
	Available() bool
	SysctlGet(key string, allow []string) (string, error)
	SysctlSet(key, value string, allow []string) error
	// SetResourceLimit writes a service resource limit as a unit/launchd
	// override, gated by allowConfigWrite (the existing AllowConfigWrite list).
	SetResourceLimit(unit, limit, value string, allowConfigWrite []string) error
	// SetUnitOverride writes a validated unit/launchd override file, gated by
	// allowConfigWrite.
	SetUnitOverride(unit, name, content string, allowConfigWrite []string) error
}

// Platform bundles the detected family with its four backends.
type Platform struct {
	Family   OSFamily
	Services ServiceManager
	Packages PackageManager
	Config   ConfigStore
	Tweaks   Tweaks
}

// detectFamily maps a GOOS plus a parsed os-release map to an OSFamily. It is
// pure so it can be exercised for every distro without touching the host.
func detectFamily(goos string, osRelease map[string]string) OSFamily {
	switch goos {
	case "darwin":
		return familyDarwin
	case "windows":
		return familyWindows
	case "linux":
		if fam := familyFromID(osRelease["ID"]); fam != familyOther {
			return fam
		}
		for _, like := range splitIDLike(osRelease["ID_LIKE"]) {
			if fam := familyFromID(like); fam != familyOther {
				return fam
			}
		}
		return familyOther
	default:
		return familyOther
	}
}

func familyFromID(id string) OSFamily {
	switch id {
	case "rhel", "fedora", "centos", "rocky", "almalinux", "ol", "oracle", "amzn", "scientific":
		return familyRHEL
	case "debian", "ubuntu", "raspbian", "linuxmint", "mint", "pop", "neon", "elementary", "kali":
		return familyDebian
	case "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "suse", "sled":
		return familySUSE
	case "arch", "archarm", "manjaro", "endeavouros", "artix":
		return familyArch
	default:
		return familyOther
	}
}

// splitIDLike splits the space-separated ID_LIKE field. os-release quoting is
// already stripped by parseOSRelease.
func splitIDLike(s string) []string {
	var out []string
	for _, f := range regexp.MustCompile(`\s+`).Split(s, -1) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

var (
	familyOnce sync.Once
	familyVal  OSFamily
)

// currentFamily detects the host family once. On Linux it reads os-release
// (already capped and key-filtered in host_linux.go); elsewhere it uses GOOS.
func currentFamily() OSFamily {
	familyOnce.Do(func() {
		var osr map[string]string
		if runtime.GOOS == "linux" {
			osr, _ = hostLinuxOSRelease()
		}
		familyVal = detectFamily(runtime.GOOS, osr)
	})
	return familyVal
}

var (
	platformOnce sync.Once
	platformInst *Platform
)

// currentPlatform builds the backend set for this host once.
func currentPlatform() *Platform {
	platformOnce.Do(func() {
		fam := currentFamily()
		platformInst = &Platform{
			Family:   fam,
			Services: selectServiceManager(fam),
			Packages: selectPackageManager(fam),
			Config:   newConfigStore(fam),
			Tweaks:   newTweaks(fam),
		}
	})
	return platformInst
}

// Capability probes. Each is advertised like file/tcp/xfer, true only when the
// platform really supports it (docs/sah-file-protocol.md §5.4 pattern).
func serviceCapable() bool { return currentPlatform().Services.Available() }
func packageCapable() bool { return currentPlatform().Packages.Available() }
func configCapable() bool  { return currentPlatform().Config.Available() }
func tweakCapable() bool   { return currentPlatform().Tweaks.Available() }

func init() {
	registerCapability("service", serviceCapable)
	registerCapability("package", packageCapable)
	registerCapability("config", configCapable)
	registerCapability("tweak", tweakCapable)
}
