package main

// PackageManager backends: apt-get, dnf, yum, zypper, brew. Each builds fixed
// argv for the four verbs (install, remove, upgrade, query). This extends the
// agent's old apt-get/dnf-only support to the RHEL (dnf/yum), SUSE (zypper)
// and macOS (brew) families (design Decision 1).
//
// Threats: package operations are root-equivalent. argv is fixed, there is no
// shell, and the package name must match packageNameRE before it reaches an
// argument position, so a name can never inject a flag or a command. The
// exact-grant check ("*" is not allow-all) and the hostLinux gate stay in
// sys_packages.go. An unknown or absent manager returns a clean
// "package manager unavailable" error, never a silent success. Output is
// capped and not logged by the caller.

import "fmt"

// pkgNameToken is replaced by the validated package name when argv is built.
const pkgNameToken = "@name"

// pkgManager is one package manager's probe binaries and per-verb argv
// templates. A verb absent from verbs is unsupported for that manager.
type pkgManager struct {
	id    string
	bins  []string
	verbs map[string][]string
}

func (m *pkgManager) Name() string { return m.id }

func (m *pkgManager) Available() bool {
	for _, bin := range m.bins {
		if _, ok := findExecutable(bin, execDirs); ok {
			return true
		}
	}
	return false
}

func (m *pkgManager) argv(verb, name string) ([]string, error) {
	if !packageNameRE.MatchString(name) {
		return nil, fmt.Errorf("package not allowed")
	}
	tmpl, ok := m.verbs[verb]
	if !ok {
		return nil, fmt.Errorf("package manager unavailable")
	}
	out := make([]string, len(tmpl))
	for i, tok := range tmpl {
		if tok == pkgNameToken {
			out[i] = name
		} else {
			out[i] = tok
		}
	}
	return out, nil
}

func (m *pkgManager) InstallArgv(name string) ([]string, error) { return m.argv("install", name) }
func (m *pkgManager) RemoveArgv(name string) ([]string, error)  { return m.argv("remove", name) }
func (m *pkgManager) UpgradeArgv(name string) ([]string, error) { return m.argv("upgrade", name) }
func (m *pkgManager) QueryArgv(name string) ([]string, error)   { return m.argv("query", name) }

// packageManagers is the backend registry. The apt-get and dnf install argv
// are byte-for-byte what the agent emitted before this abstraction.
var packageManagers = map[string]*pkgManager{
	"apt-get": {
		id:   "apt-get",
		bins: []string{"apt-get"},
		verbs: map[string][]string{
			"install": {"apt-get", "install", "-y", "--no-install-recommends", "--", pkgNameToken},
			"remove":  {"apt-get", "remove", "-y", "--", pkgNameToken},
			"upgrade": {"apt-get", "install", "-y", "--only-upgrade", "--", pkgNameToken},
			"query":   {"dpkg-query", "-W", "--", pkgNameToken},
		},
	},
	"dnf": {
		id:   "dnf",
		bins: []string{"dnf"},
		verbs: map[string][]string{
			"install": {"dnf", "install", "-y", "--", pkgNameToken},
			"remove":  {"dnf", "remove", "-y", "--", pkgNameToken},
			"upgrade": {"dnf", "upgrade", "-y", "--", pkgNameToken},
			"query":   {"rpm", "-q", pkgNameToken},
		},
	},
	"yum": {
		id:   "yum",
		bins: []string{"yum"},
		verbs: map[string][]string{
			"install": {"yum", "install", "-y", "--", pkgNameToken},
			"remove":  {"yum", "remove", "-y", "--", pkgNameToken},
			"upgrade": {"yum", "upgrade", "-y", "--", pkgNameToken},
			"query":   {"rpm", "-q", pkgNameToken},
		},
	},
	"zypper": {
		id:   "zypper",
		bins: []string{"zypper"},
		verbs: map[string][]string{
			"install": {"zypper", "--non-interactive", "install", "--", pkgNameToken},
			"remove":  {"zypper", "--non-interactive", "remove", "--", pkgNameToken},
			"upgrade": {"zypper", "--non-interactive", "update", "--", pkgNameToken},
			"query":   {"rpm", "-q", pkgNameToken},
		},
	},
	"brew": {
		id:   "brew",
		bins: []string{"brew"},
		verbs: map[string][]string{
			"install": {"brew", "install", pkgNameToken},
			"remove":  {"brew", "uninstall", pkgNameToken},
			"upgrade": {"brew", "upgrade", pkgNameToken},
			"query":   {"brew", "list", "--versions", pkgNameToken},
		},
	},
}

// packageManagerOrder is the probe/preference order for a family: the native
// manager first, then the rest, so a host that happens to carry two managers
// resolves to the expected one.
func packageManagerOrder(fam OSFamily) []string {
	rest := []string{"apt-get", "dnf", "yum", "zypper", "brew"}
	var first []string
	switch fam {
	case familyDebian:
		first = []string{"apt-get"}
	case familyRHEL:
		first = []string{"dnf", "yum"}
	case familySUSE:
		first = []string{"zypper"}
	case familyDarwin:
		first = []string{"brew"}
	}
	order := make([]string, 0, len(rest)+len(first))
	seen := map[string]bool{}
	for _, id := range append(first, rest...) {
		if !seen[id] {
			order = append(order, id)
			seen[id] = true
		}
	}
	return order
}

func packageManagerByName(id string) *pkgManager { return packageManagers[id] }

// selectPackageManager returns the first available manager in family order,
// or a none backend. It probes real binaries and ignores the install test
// hooks, so the capability it feeds reflects the host.
func selectPackageManager(fam OSFamily) PackageManager {
	for _, id := range packageManagerOrder(fam) {
		if m := packageManagers[id]; m != nil && m.Available() {
			return m
		}
	}
	return nonePackageManager{}
}

// lookupFixedPackageManager is the default implementation behind the
// lookupPackageManager hook: it returns the id of the first available manager
// in family order, or an error.
func lookupFixedPackageManager() (string, error) {
	fam := currentFamily()
	for _, id := range packageManagerOrder(fam) {
		if m := packageManagers[id]; m != nil && m.Available() {
			return m.id, nil
		}
	}
	return "", fmt.Errorf("package manager unavailable")
}

// packageArgv returns the install argv for a named manager. It is the seam the
// package tests pin: apt-get and dnf keep their exact argv, a bad name or "*"
// is rejected, and an unknown manager is unavailable.
func packageArgv(mgr, name string) ([]string, error) {
	m := packageManagerByName(mgr)
	if m == nil {
		return nil, fmt.Errorf("package manager unavailable")
	}
	return m.InstallArgv(name)
}

// nonePackageManager fails closed where no known package manager exists.
type nonePackageManager struct{}

func (nonePackageManager) Name() string    { return "none" }
func (nonePackageManager) Available() bool { return false }
func (nonePackageManager) InstallArgv(string) ([]string, error) {
	return nil, fmt.Errorf("package manager unavailable")
}
func (nonePackageManager) RemoveArgv(string) ([]string, error) {
	return nil, fmt.Errorf("package manager unavailable")
}
func (nonePackageManager) UpgradeArgv(string) ([]string, error) {
	return nil, fmt.Errorf("package manager unavailable")
}
func (nonePackageManager) QueryArgv(string) ([]string, error) {
	return nil, fmt.Errorf("package manager unavailable")
}
