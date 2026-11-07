package main

import (
	"context"
	"errors"
	"fmt"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// Threats: a patched sash asking for a verb the grant does not name, a write
// whose target is outside the grant or the delivered policy, a journal verb
// (there is no reader), a hard-denied sysctl or a sysctl value the setter
// would refuse, and a helper call after the session lease has expired. The
// check order is lease, history, entitlement, policy, helper. history is
// not an entitlement: the store key is the verified actor and host. A
// failed re-check returns "denied" and does not call the helper. journal
// is not a journalctl shell-out. file.write uses file_write roots and the
// delivered files_write list, not the read roots. Does NOT import sash.
// Does NOT mint a sys lease to call the helpers.

var errSashDenied = errors.New("denied")

type sashProc struct {
	User string
	Pid  int
	Cmd  string
}

var (
	sashProcs          = sashProcsDefault
	sashUnitStatus     = sashUnitStatusDefault
	sashPackageQuery   = sashPackageQueryDefault
	sashSysctlGet      = sashSysctlGetDefault
	sashConfigRead     = sashConfigReadDefault
	sashFile           = sashFileDefault
	sashUnitRestart    = sashUnitRestartDefault
	sashPackageInstall = sashPackageInstallDefault
	sashSysctlSet      = sashSysctlSetDefault
	sashFileWrite      = sashFileWriteDefault
)

func sashUnitRestartDefault(name string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("requires linux")
	}
	mgr := selectServiceManager(detectFamily(runtime.GOOS, nil))
	return mgr.Action(context.Background(), "restart", name)
}

func sashPackageInstallDefault(name string, allow []string) error {
	return installPackage(context.Background(), name, allow)
}

func sashSysctlSetDefault(key, value string, allow []string) error {
	return hostSysctlSet(key, value, allow)
}

func sashProcsDefault() ([]sashProc, error) {
	list, err := process.Processes()
	if err != nil {
		return nil, err
	}
	out := make([]sashProc, 0, len(list))
	for _, p := range list {
		if p == nil {
			continue
		}
		user, _ := p.Username()
		cmd, _ := p.Cmdline()
		out = append(out, sashProc{User: user, Pid: int(p.Pid), Cmd: cmd})
	}
	return out, nil
}

func sashUnitStatusDefault(name string) (bool, string, error) {
	mgr := selectServiceManager(detectFamily(runtime.GOOS, nil))
	st, err := mgr.Status(context.Background(), name)
	if err != nil {
		return false, "", err
	}
	return st.Active, st.State, nil
}

func sashPackageQueryDefault(name string, allow []string) (bool, string, error) {
	return queryPackage(context.Background(), name, allow)
}

func sashSysctlGetDefault(key string, allow []string) (string, error) {
	return hostSysctlGet(key, allow)
}

func sashConfigReadDefault(p string) (string, error) {
	return sysConfigReadBeneath(p)
}

func sashLeaseLive(leaseFn func() time.Time) bool {
	if leaseFn == nil {
		return false
	}
	return !time.Now().After(leaseFn())
}

// sashPinDenied drops the sash verbs the agent performs as root (unit.restart,
// package.install, sysctl.set, and file.write in a root session) on a host
// whose require-intent pin lists sys-write, or whose pin is damaged, whatever
// the grant says (contract 5.1/5.2, N33 on the agent side).
func sashPinDenied(g sashGrant, key string) bool {
	switch key {
	case "unit.restart", "package.install", "sysctl.set":
	case "file.write":
		if g.Purpose != sashPurposeRoot {
			return false
		}
	default:
		return false
	}
	pinned, err := pinnedFor([]string{"sys-write"})
	return err != nil || pinned
}

func sashDispatch(g sashGrant, targets sashTargets, leaseFn func() time.Time, id *ptyIdentity, v sashCall) (sashResult, error) {
	return sashDispatchAt(g, targets, leaseFn, id, v, sashHistoryRoot)
}

func sashDispatchAt(g sashGrant, targets sashTargets, leaseFn func() time.Time, id *ptyIdentity, v sashCall, histRoot string) (sashResult, error) {
	if !sashLeaseLive(leaseFn) {
		return sashResult{}, errSashDenied
	}
	if v.Key == "history" {
		return sashHistory(g, v, histRoot)
	}
	if v.Key == "journal" || !sashEntitled(g, v.Key) || sashPinDenied(g, v.Key) {
		return sashResult{}, errSashDenied
	}
	switch v.Key {
	case "ps":
		return sashDoPS()
	case "unit.status":
		return sashDoUnit(targets, v)
	case "unit.restart":
		return sashDoUnitRestart(targets, v)
	case "package.query":
		return sashDoPackage(targets, v)
	case "package.install":
		return sashDoPackageInstall(targets, v)
	case "sysctl.get":
		return sashDoSysctl(targets, v)
	case "sysctl.set":
		return sashDoSysctlSet(targets, v)
	case "config.read":
		return sashDoConfig(targets, v)
	case "file.read":
		return sashDoFile(g, targets, id, v)
	case "file.write":
		return sashDoFileWrite(g, targets, id, v)
	default:
		return sashResult{}, errSashDenied
	}
}

func sashDoPS() (sashResult, error) {
	list, err := sashProcs()
	if err != nil {
		return sashResult{Kind: "rows", Cols: []string{"user", "pid", "cmd"}, Exit: 1}, nil
	}
	rows := make([]map[string]string, 0, len(list))
	for _, p := range list {
		rows = append(rows, map[string]string{
			"user": p.User,
			"pid":  strconv.Itoa(p.Pid),
			"cmd":  p.Cmd,
		})
	}
	return sashResult{Kind: "rows", Rows: rows, Cols: []string{"user", "pid", "cmd"}, Exit: 0}, nil
}

func sashDoUnit(targets sashTargets, v sashCall) (sashResult, error) {
	if len(v.Argv) != 3 || v.Argv[0] != "unit" || v.Argv[1] != "status" {
		return sashResult{}, errSashDenied
	}
	name := v.Argv[2]
	if !serviceNameRE.MatchString(name) || !exactGrant(targets.Units, name) {
		return sashResult{}, errSashDenied
	}
	active, state, err := sashUnitStatus(name)
	if err != nil {
		return sashResult{Kind: "rows", Cols: []string{"unit", "active", "state"}, Exit: 1}, nil
	}
	flag := "false"
	if active {
		flag = "true"
	}
	return sashResult{
		Kind: "rows",
		Cols: []string{"unit", "active", "state"},
		Rows: []map[string]string{{"unit": name, "active": flag, "state": state}},
		Exit: 0,
	}, nil
}

func sashDoPackage(targets sashTargets, v sashCall) (sashResult, error) {
	if len(v.Argv) != 3 || v.Argv[0] != "package" || v.Argv[1] != "query" {
		return sashResult{}, errSashDenied
	}
	name := v.Argv[2]
	if !packageNameRE.MatchString(name) || !exactGrant(targets.Packages, name) {
		return sashResult{}, errSashDenied
	}
	installed, version, err := sashPackageQuery(name, targets.Packages)
	if err != nil {
		return sashResult{Kind: "rows", Cols: []string{"name", "installed", "version"}, Exit: 1}, nil
	}
	flag := "false"
	if installed {
		flag = "true"
	}
	return sashResult{
		Kind: "rows",
		Cols: []string{"name", "installed", "version"},
		Rows: []map[string]string{{"name": name, "installed": flag, "version": version}},
		Exit: 0,
	}, nil
}

func sashDoSysctl(targets sashTargets, v sashCall) (sashResult, error) {
	if len(v.Argv) != 3 || v.Argv[0] != "sysctl" || v.Argv[1] != "get" {
		return sashResult{}, errSashDenied
	}
	key := v.Argv[2]
	if sysctlDenied(key) || !sysctlKeyOK(key) || !exactGrant(targets.Sysctls, key) {
		return sashResult{}, errSashDenied
	}
	val, err := sashSysctlGet(key, targets.Sysctls)
	if err != nil {
		return sashResult{Kind: "bytes", Exit: 1}, nil
	}
	return sashResult{Kind: "bytes", Bytes: []byte(val), Exit: 0}, nil
}

func sashConfigUnder(policies []string, p string) bool {
	if path.Clean(p) != p || !strings.HasPrefix(p, "/") {
		return false
	}
	for _, base := range policies {
		if strings.Contains(base, "*") {
			continue
		}
		if p == base || base == "/" || strings.HasPrefix(p, base+"/") {
			if base != "~" && p != "~" {
				return true
			}
		}
	}
	return false
}

func sashDoConfig(targets sashTargets, v sashCall) (sashResult, error) {
	if len(v.Argv) != 3 || v.Argv[0] != "config" || v.Argv[1] != "read" || v.Argv[2] != v.Path || v.Path == "" {
		return sashResult{}, errSashDenied
	}
	p := v.Path
	if path.Clean(p) != p || !configTargetShapeOK(p) || configTargetDenied(p) || !sashConfigUnder(targets.Configs, p) {
		return sashResult{}, errSashDenied
	}
	text, err := sashConfigRead(p)
	if err != nil {
		return sashResult{Kind: "bytes", Exit: 1}, nil
	}
	return sashResult{Kind: "bytes", Bytes: []byte(text), Exit: 0}, nil
}

// sashLongestRoot returns the longest grant root p sits under on a component
// boundary. /var/logbook is not under /var/log.
func sashLongestRoot(roots []string, p string) (string, bool) {
	if path.Clean(p) != p || !strings.HasPrefix(p, "/") {
		return "", false
	}
	best := ""
	for _, r := range roots {
		if strings.Contains(r, "*") {
			continue
		}
		if p == r || strings.HasPrefix(p, r+"/") {
			if len(r) > len(best) {
				best = r
			}
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

func sashDoFile(g sashGrant, targets sashTargets, id *ptyIdentity, v sashCall) (sashResult, error) {
	if v.Path == "" || len(v.Argv) == 0 {
		return sashResult{}, errSashDenied
	}
	if len(targets.Files) == 0 {
		return sashResult{}, errSashDenied
	}
	root, ok := sashLongestRoot(g.FileRead, v.Path)
	if !ok {
		return sashResult{}, errSashDenied
	}
	if _, ok := sashLongestRoot(targets.Files, v.Path); !ok {
		return sashResult{}, errSashDenied
	}
	rel := "."
	if v.Path != root {
		rel = strings.TrimPrefix(v.Path, root+"/")
	}
	op := v.Argv[0]
	switch op {
	case "stat", "ls", "cat", "<":
	default:
		return sashResult{}, errSashDenied
	}
	return sashFile(id, op, root, rel)
}

func sashDoUnitRestart(targets sashTargets, v sashCall) (sashResult, error) {
	if len(v.Argv) != 3 || v.Argv[0] != "unit" || v.Argv[1] != "restart" {
		return sashResult{}, errSashDenied
	}
	name := v.Argv[2]
	if !serviceNameRE.MatchString(name) || !exactGrant(targets.Units, name) {
		return sashResult{}, errSashDenied
	}
	out, err := sashUnitRestart(name)
	if err != nil {
		return sashResult{Kind: "bytes", Exit: 1}, nil
	}
	return sashResult{Kind: "bytes", Bytes: []byte(out), Exit: 0}, nil
}

func sashDoPackageInstall(targets sashTargets, v sashCall) (sashResult, error) {
	if len(v.Argv) != 3 || v.Argv[0] != "package" || v.Argv[1] != "install" {
		return sashResult{}, errSashDenied
	}
	name := v.Argv[2]
	if !packageNameRE.MatchString(name) || !exactGrant(targets.Packages, name) {
		return sashResult{}, errSashDenied
	}
	if err := sashPackageInstall(name, targets.Packages); err != nil {
		return sashResult{Kind: "bytes", Exit: 1}, nil
	}
	return sashResult{Kind: "bytes", Exit: 0}, nil
}

func sashDoSysctlSet(targets sashTargets, v sashCall) (sashResult, error) {
	if len(v.Argv) != 4 || v.Argv[0] != "sysctl" || v.Argv[1] != "set" {
		return sashResult{}, errSashDenied
	}
	key, value := v.Argv[2], v.Argv[3]
	if sysctlDenied(key) || !sysctlKeyOK(key) || !sysctlValueOK(value) || !exactGrant(targets.Sysctls, key) {
		return sashResult{}, errSashDenied
	}
	if err := sashSysctlSet(key, value, targets.Sysctls); err != nil {
		return sashResult{Kind: "bytes", Exit: 1}, nil
	}
	return sashResult{Kind: "bytes", Exit: 0}, nil
}

// sashDoFileWrite refuses before the helper when the path is not a file
// under both the grant's file_write roots and the delivered files_write
// list. The read roots are not consulted. An empty body is a real write.
func sashDoFileWrite(g sashGrant, targets sashTargets, id *ptyIdentity, v sashCall) (sashResult, error) {
	if v.Path == "" || len(v.Argv) != 2 || v.Argv[0] != ">" || v.Argv[1] != v.Path {
		return sashResult{}, errSashDenied
	}
	if len(v.Body) > fileReadMax || len(targets.FilesWrite) == 0 {
		return sashResult{}, errSashDenied
	}
	root, ok := sashLongestRoot(g.FileWrite, v.Path)
	if !ok {
		return sashResult{}, errSashDenied
	}
	if _, ok = sashLongestRoot(targets.FilesWrite, v.Path); !ok {
		return sashResult{}, errSashDenied
	}
	if v.Path == root {
		return sashResult{}, errSashDenied
	}
	rel := strings.TrimPrefix(v.Path, root+"/")
	return sashFileWrite(id, root, rel, append([]byte(nil), v.Body...))
}
