package main

// PackageManager backends: apt-get, dnf, yum, zypper, brew. Each builds fixed
// argv for the verbs (install, remove, upgrade, query, list). This extends the
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

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

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

// ListArgv returns the inventory argv. It takes no name, so it is copied from
// the template as is. The format strings are literal argv, never a shell.
func (m *pkgManager) ListArgv() ([]string, error) {
	tmpl, ok := m.verbs["list"]
	if !ok {
		return nil, fmt.Errorf("package manager unavailable")
	}
	return append([]string(nil), tmpl...), nil
}

// List and query formats. dpkg-query adds the status so a removed package
// that left config behind ("rc") is not reported as installed.
const (
	aptListFormat = "${Package}\t${Version}\t${db:Status-Abbrev}\n"
	rpmListFormat = "%{NAME}\t%{VERSION}-%{RELEASE}\n"
)

// packageManagers is the backend registry. The apt-get and dnf install argv
// are byte-for-byte what the agent emitted before this abstraction.
var packageManagers = map[string]*pkgManager{
	"apt-get": {
		id:   "apt-get",
		bins: []string{"apt-get"},
		verbs: map[string][]string{
			"install":    {"apt-get", "install", "-y", "--no-install-recommends", "--", pkgNameToken},
			"remove":     {"apt-get", "remove", "-y", "--", pkgNameToken},
			"upgrade":    {"apt-get", "install", "-y", "--only-upgrade", "--", pkgNameToken},
			"query":      {"dpkg-query", "-W", "-f", aptListFormat, "--", pkgNameToken},
			"list":       {"dpkg-query", "-W", "-f", aptListFormat},
			"remove-sim": {"apt-get", "-s", "remove", "--", pkgNameToken},
		},
	},
	"dnf": {
		id:   "dnf",
		bins: []string{"dnf"},
		verbs: map[string][]string{
			"install":    {"dnf", "install", "-y", "--", pkgNameToken},
			"remove":     {"dnf", "remove", "-y", "--", pkgNameToken},
			"upgrade":    {"dnf", "upgrade", "-y", "--", pkgNameToken},
			"query":      {"rpm", "-q", pkgNameToken},
			"list":       {"rpm", "-qa", "--qf", rpmListFormat},
			"remove-sim": {"dnf", "remove", "--assumeno", "--", pkgNameToken},
		},
	},
	"yum": {
		id:   "yum",
		bins: []string{"yum"},
		verbs: map[string][]string{
			"install":    {"yum", "install", "-y", "--", pkgNameToken},
			"remove":     {"yum", "remove", "-y", "--", pkgNameToken},
			"upgrade":    {"yum", "upgrade", "-y", "--", pkgNameToken},
			"query":      {"rpm", "-q", pkgNameToken},
			"list":       {"rpm", "-qa", "--qf", rpmListFormat},
			"remove-sim": {"yum", "remove", "--assumeno", "--", pkgNameToken},
		},
	},
	"zypper": {
		id:   "zypper",
		bins: []string{"zypper"},
		verbs: map[string][]string{
			"install":    {"zypper", "--non-interactive", "install", "--", pkgNameToken},
			"remove":     {"zypper", "--non-interactive", "remove", "--", pkgNameToken},
			"upgrade":    {"zypper", "--non-interactive", "update", "--", pkgNameToken},
			"query":      {"rpm", "-q", pkgNameToken},
			"list":       {"rpm", "-qa", "--qf", rpmListFormat},
			"remove-sim": {"zypper", "--non-interactive", "remove", "--dry-run", "--", pkgNameToken},
		},
	},
	"brew": {
		id:   "brew",
		bins: []string{"brew"},
		verbs: map[string][]string{
			"install":    {"brew", "install", pkgNameToken},
			"remove":     {"brew", "uninstall", pkgNameToken},
			"upgrade":    {"brew", "upgrade", pkgNameToken},
			"query":      {"brew", "list", "--versions", pkgNameToken},
			"list":       {"brew", "list", "--versions"},
			"remove-sim": {"brew", "uses", "--installed", pkgNameToken},
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
func (nonePackageManager) ListArgv() ([]string, error) {
	return nil, fmt.Errorf("package manager unavailable")
}

// pkgEntry is one installed package as the inventory reports it.
type pkgEntry struct {
	Name    string
	Version string
}

// rpmArches are the arch suffixes stripped from "rpm -q" NVRA output.
var rpmArches = map[string]bool{
	"x86_64": true, "noarch": true, "aarch64": true, "i686": true, "i386": true,
	"ppc64le": true, "s390x": true, "armv7hl": true, "riscv64": true,
}

// parsePackageList parses ListArgv output for a manager into entries, capped
// at max. pacman ("pacman -Q": "name version") is parsed but not registered
// as a backend. An unknown manager yields nothing.
func parsePackageList(mgr, out string, max int) []pkgEntry {
	var entries []pkgEntry
	for _, line := range strings.Split(out, "\n") {
		if len(entries) >= max {
			break
		}
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e pkgEntry
		switch mgr {
		case "apt-get":
			f := strings.Split(line, "\t")
			if len(f) < 3 || f[1] == "" || !dpkgInstalled(f[2]) {
				continue
			}
			e = pkgEntry{f[0], f[1]}
		case "dnf", "yum", "zypper":
			f := strings.Split(line, "\t")
			if len(f) < 2 || f[0] == "" {
				continue
			}
			e = pkgEntry{f[0], f[1]}
		case "brew", "pacman":
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			// brew lists every installed version; the last one is newest.
			e = pkgEntry{f[0], f[len(f)-1]}
		default:
			return nil
		}
		entries = append(entries, e)
	}
	return entries
}

// parsePackageQuery parses QueryArgv output for one validated name. It
// reports installed only when a line names that exact package, so "package
// nginx is not installed" or an empty reply is never a false positive.
func parsePackageQuery(mgr, name, out string) (bool, string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch mgr {
		case "apt-get":
			// aptListFormat: "name\tversion\tstatus". Only a status whose
			// second letter is "i" is installed ("ii", held "hi"); "rc"
			// (config files left) and half-installed states are not.
			f := strings.Split(line, "\t")
			pkg := strings.SplitN(f[0], ":", 2)[0]
			if len(f) >= 3 && pkg == name && f[1] != "" && dpkgInstalled(f[2]) {
				return true, f[1]
			}
		case "dnf", "yum", "zypper":
			// NVRA: "nginx-1.20.1-14.el9.x86_64".
			if !strings.HasPrefix(line, name+"-") || strings.Contains(line, " ") {
				continue
			}
			ver := strings.TrimPrefix(line, name+"-")
			if i := strings.LastIndex(ver, "."); i > 0 && rpmArches[ver[i+1:]] {
				ver = ver[:i]
			}
			// "name-x" must leave version-release, not another name part
			// ("nginx-mod-...").
			if ver == "" || ver[0] < '0' || ver[0] > '9' {
				continue
			}
			return true, ver
		case "brew", "pacman":
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == name {
				return true, f[len(f)-1]
			}
		}
	}
	return false, ""
}

// dpkgInstalled reads a ${db:Status-Abbrev} field: the second letter is the
// package state, "i" for installed (the first is the selection: install,
// hold, remove, purge).
func dpkgInstalled(status string) bool {
	status = strings.TrimSpace(status)
	return len(status) >= 2 && status[1] == 'i'
}

// RemoveSimArgv returns the dry-run argv for remove.
func (m *pkgManager) RemoveSimArgv(name string) ([]string, error) { return m.argv("remove-sim", name) }

var (
	zypperRemoveHeadRE = regexp.MustCompile(`^The following (?:\d+ )?(?:[a-zA-Z]+ )?(?:package|packages|patterns?|products?|applications?) (?:is|are) going to be REMOVED:$`)
	dnfSummaryRE       = regexp.MustCompile(`^(?:Remove|Removing:?)\s+(\d+)\s+[Pp]ackages?`)
)

// parseRemoveSim returns the set of packages a remove dry run would take
// out. ok is false when the output cannot be read with confidence, so the
// caller refuses. code is the dry run's exit code.
func parseRemoveSim(mgr, out string, code int) (map[string]bool, bool) {
	removed := map[string]bool{}
	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	switch mgr {
	case "apt-get":
		// apt-get -s prints "Remv name [version]" per package.
		if code != 0 {
			return nil, false
		}
		for _, l := range lines {
			f := strings.Fields(l)
			if len(f) >= 2 && (f[0] == "Remv" || f[0] == "Purg") {
				removed[strings.SplitN(f[1], ":", 2)[0]] = true
			}
		}
		return removed, true
	case "dnf", "yum":
		// --assumeno prints the transaction table and exits 1. Package rows
		// sit under the "Removing..." section headers; a row's first field
		// is the name. The summary count must agree with the rows.
		if code != 0 && code != 1 {
			return nil, false
		}
		in := false
		summary := -1
		for _, l := range lines {
			t := strings.TrimSpace(l)
			if m := dnfSummaryRE.FindStringSubmatch(t); m != nil && !strings.HasSuffix(t, ":") {
				n, err := strconv.Atoi(m[1])
				if err != nil {
					return nil, false
				}
				summary = n
				in = false
				continue
			}
			if strings.HasPrefix(t, "Removing") && strings.HasSuffix(t, ":") {
				in = true
				continue
			}
			if t == "" || strings.HasSuffix(t, ":") || strings.HasPrefix(t, "Transaction Summary") || strings.HasPrefix(t, "=") {
				in = false
				continue
			}
			if in && strings.HasPrefix(l, " ") {
				removed[strings.Fields(t)[0]] = true
			}
		}
		if summary < 0 || summary != len(removed) {
			return nil, false
		}
		return removed, true
	case "zypper":
		if code != 0 {
			return nil, false
		}
		in := false
		for _, l := range lines {
			t := strings.TrimSpace(l)
			if zypperRemoveHeadRE.MatchString(t) {
				in = true
				continue
			}
			if t == "" {
				in = false
				continue
			}
			if in {
				for _, n := range strings.Fields(t) {
					removed[n] = true
				}
			}
		}
		return removed, true
	case "brew":
		// "brew uses --installed name" lists installed dependents.
		if code != 0 {
			return nil, false
		}
		for _, l := range lines {
			for _, n := range strings.Fields(l) {
				removed[n] = true
			}
		}
		return removed, true
	}
	return nil, false
}
