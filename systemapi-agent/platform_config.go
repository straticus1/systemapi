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
	"path/filepath"
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
	argv, err := configCheckArgv(service, path)
	if err != nil {
		return "", err
	}
	if argv == nil {
		return "no validator for service", nil
	}
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	return string(out), err
}

// configCheckArgv is the checker argv for service, nil when there is none.
// path must be absolute, so it can never read as an option; the getopt
// checkers also get "--" before it.
func configCheckArgv(service, path string) ([]string, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return nil, fmt.Errorf("config path must be absolute")
	}
	switch strings.ToLower(service) {
	case "postfix":
		return []string{"postfix", "check"}, nil
	case "bind", "named":
		return []string{"named-checkconf", "--", path}, nil
	case "nsd":
		return []string{"nsd-checkconf", "--", path}, nil
	case "unbound":
		return []string{"unbound-checkconf", "--", path}, nil
	default:
		return nil, nil
	}
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
