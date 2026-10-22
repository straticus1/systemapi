package main

// ConfigStore backend: the atomic config write (config_manager.go), a
// per-service validate hook, and a per-init-system reload hook. There is one
// implementation; only the reload command varies by family. The
// AllowConfigWrite / AllowServiceReload grants stay in sys_config.go; this
// backend does not widen them.
//
// Threats: a config write is root-equivalent. The write itself is the audited
// AtomicWrite (temp file, backup, atomic rename) and the caller has already
// checked the path against AllowConfigWrite. Validate and Reload run fixed
// argv with no shell; the service name is checked against serviceNameRE before
// it becomes an argument and the validator set is closed. An unsupported
// platform's reload returns an error, never a silent success.

import (
	"fmt"
	"os/exec"
	"strings"
)

func newConfigStore(fam OSFamily) ConfigStore {
	return &configStore{fam: fam, cm: &ConfigManager{}}
}

type configStore struct {
	fam OSFamily
	cm  *ConfigManager
}

func (c *configStore) Name() string { return "config" }

// Available is true everywhere: an atomic config write is a filesystem
// operation, independent of the init system.
func (c *configStore) Available() bool { return true }

func (c *configStore) AtomicWrite(path, content string) error {
	return c.cm.AtomicWrite(path, content)
}

// Validate runs the config checker for a service, if one is known. An unknown
// service is not an error: it returns a clear "no validator" note so a script
// never mistakes a missing checker for a passing check.
func (c *configStore) Validate(service, path string) (string, error) {
	var cmd *exec.Cmd
	switch strings.ToLower(service) {
	case "postfix":
		cmd = exec.Command("postfix", "check")
	case "bind", "named":
		cmd = exec.Command("named", "-checkconf", path)
	case "nsd":
		cmd = exec.Command("nsd-checkconf", path)
	case "unbound":
		cmd = exec.Command("unbound-checkconf", path)
	default:
		return "no validator for service", nil
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Reload reloads a service through the family's init system.
func (c *configStore) Reload(service string) (string, error) {
	if !serviceNameRE.MatchString(service) {
		return "", fmt.Errorf("service not allowed")
	}
	var cmd *exec.Cmd
	switch c.fam {
	case familyDarwin:
		cmd = exec.Command("launchctl", "kickstart", "-k", "system/"+service)
	case familyWindows:
		return "", fmt.Errorf("service reload not supported on windows")
	default:
		cmd = exec.Command("systemctl", "reload", service)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}
