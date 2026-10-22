package main

// Tweaks backend: sysctl get/set (routed to the linux host helpers), service
// resource limits, and unit/launchd overrides. Kernel modules and firewall
// rules are out of v1 (design Decision 2). There is one implementation; the
// linux host helpers already fail closed off Linux.
//
// Threats: every op here is root-equivalent.
//   - sysctl get/set re-check sysctlGranted (hard-denied keys such as
//     kernel.core_pattern can never be granted), validate the value, resolve a
//     fixed /proc/sys path, and reject a traversal. "*" is not allow-all.
//   - A unit override is a root-equivalent config write. Its path is pinned
//     under /etc/systemd/system/<unit>.d/<name>.conf, the unit and file names
//     are regex-checked, the content is size-capped and null-free, and the
//     final path must still be inside an AllowConfigWrite prefix (the same gate
//     sys.config.write uses; it is not widened here). The write is the audited
//     AtomicWrite. A resource limit is a typed override: the directive is from
//     a closed allowlist and the value is charset- and length-checked.
// An unsupported platform returns an error, never a silent success.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const overrideContentCap = 64 * 1024

var (
	overrideNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
	limitValueRE   = regexp.MustCompile(`^[a-zA-Z0-9:._]{1,64}$`)
)

// resourceLimits is the closed set of systemd [Service] Limit* directives v1
// will set. Kernel-level and security-sensitive knobs are not here.
var resourceLimits = map[string]struct{}{
	"LimitCPU": {}, "LimitFSIZE": {}, "LimitDATA": {}, "LimitSTACK": {},
	"LimitCORE": {}, "LimitRSS": {}, "LimitNOFILE": {}, "LimitAS": {},
	"LimitNPROC": {}, "LimitMEMLOCK": {}, "LimitLOCKS": {}, "LimitSIGPENDING": {},
	"LimitMSGQUEUE": {}, "LimitNICE": {}, "LimitRTPRIO": {}, "LimitRTTIME": {},
}

func newTweaks(fam OSFamily) Tweaks {
	return &tweaksBackend{fam: fam, cm: &ConfigManager{}}
}

type tweaksBackend struct {
	fam OSFamily
	cm  *ConfigManager
}

func (t *tweaksBackend) Name() string { return "tweak" }

// Available is true where sysctl works: Linux (/proc/sys). Darwin sysctl and
// launchd overrides are not implemented in v1, so tweak is not advertised
// there.
func (t *tweaksBackend) Available() bool { return hostLinux() }

func (t *tweaksBackend) SysctlGet(key string, allow []string) (string, error) {
	if !sysctlGranted(allow, key) {
		return "", fmt.Errorf("sysctl not allowed")
	}
	if _, err := sysctlProcPath(key); err != nil {
		return "", err
	}
	return hostSysctlGet(key, allow)
}

func (t *tweaksBackend) SysctlSet(key, value string, allow []string) error {
	if !sysctlGranted(allow, key) || !sysctlValueOK(value) {
		return fmt.Errorf("sysctl not allowed")
	}
	if _, err := sysctlProcPath(key); err != nil {
		return err
	}
	return hostSysctlSet(key, value, allow)
}

func (t *tweaksBackend) SetResourceLimit(unit, limit, value string, allowConfigWrite []string) error {
	if _, ok := resourceLimits[limit]; !ok {
		return fmt.Errorf("resource limit not allowed")
	}
	if !limitValueRE.MatchString(value) {
		return fmt.Errorf("resource limit value not allowed")
	}
	content := "[Service]\n" + limit + "=" + value + "\n"
	return t.SetUnitOverride(unit, "limit-"+strings.ToLower(limit), content, allowConfigWrite)
}

func (t *tweaksBackend) SetUnitOverride(unit, name, content string, allowConfigWrite []string) error {
	// Validate the inputs first so malformed input is rejected identically on
	// every platform.
	if !unitNameRE.MatchString(unit) || !overrideNameRE.MatchString(name) {
		return fmt.Errorf("unit override not allowed")
	}
	if content == "" || len(content) > overrideContentCap || strings.ContainsRune(content, 0) {
		return fmt.Errorf("unit override content not allowed")
	}
	// v1 implements systemd drop-ins (Linux). launchd overrides on darwin and
	// any other platform fail closed rather than pretend to succeed.
	switch t.fam {
	case familyRHEL, familyDebian, familySUSE, familyArch, familyOther:
		if !hostLinux() {
			return fmt.Errorf("unit override not supported on this platform")
		}
	default:
		return fmt.Errorf("unit override not supported on this platform")
	}
	dir := filepath.Join("/etc/systemd/system", unit+".d")
	path := filepath.Join(dir, name+".conf")
	if !configWriteAllowed(path, allowConfigWrite) {
		return fmt.Errorf("unit override to %s not granted", path)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("unit override: %w", err)
	}
	return t.cm.AtomicWrite(path, content)
}

// configWriteAllowed is the AllowConfigWrite prefix gate used by
// sys.config.write, applied here so a unit override cannot escape it.
func configWriteAllowed(path string, allow []string) bool {
	for _, prefix := range allow {
		if prefix == "*" || strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
