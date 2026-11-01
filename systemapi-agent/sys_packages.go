package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"go.starlark.net/starlark"
)

// Threats: package install, remove and upgrade are root-equivalent. The argv
// is fixed, there is no shell, and the child gets PATH plus two locale
// variables. A name must match the package regex and an exact grant. "*" is
// not allow-all. query needs the same exact grant. list takes no name, so it
// needs at least one exact package grant. Output is capped and is not logged.
// Non-linux returns before the package manager is looked up. remove first
// runs the manager's dry run and refuses unless the named package is the
// only one it would take out (for brew: unless nothing installed depends on
// it); output it cannot parse refuses.

// Every verb runs under the script's context (its deadline and cancel), and
// the package manager's whole process group is stopped when it ends
// (jobCommand: SIGTERM, a grace, then SIGKILL). Scripts run concurrently, so
// every verb that invokes the package manager holds packageLock: one at a
// time per agent, as when scripts ran one after another.

// packageLock serializes package manager runs across scripts. It is a
// channel so waiting for it ends with the script's context.
var packageLock = make(chan struct{}, 1)

// lockPackages takes packageLock or fails when ctx ends first. The caller
// must call the returned unlock.
func lockPackages(ctx context.Context, mgr, what string) (func(), error) {
	select {
	case packageLock <- struct{}{}:
		return func() { <-packageLock }, nil
	case <-ctx.Done():
		return nil, packageCtxErr(ctx, mgr, what+" (waiting for another package operation)", false)
	}
}

// packageListMax caps inventory rows. A large host carries a few thousand.
const packageListMax = 20000

const packagePATH = "/usr/sbin:/usr/bin:/sbin:/bin"

var lookupPackageManager = lookupFixedPackageManager
var runPackageInstall = runFixedPackageInstall
var runPackageQuery = runFixedPackageQuery

func runFixedPackageInstall(ctx context.Context, argv []string) error {
	if len(argv) < 2 {
		return fmt.Errorf("package install failed")
	}
	cmd := jobCommand(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{
		"PATH=" + packagePATH,
		"DEBIAN_FRONTEND=noninteractive",
		"LC_ALL=C",
	}
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("package install failed: %s", capText(string(out), installErrCap))
	}
	return nil
}

// runFixedPackageQuery runs a read-only query and returns capped stdout and
// the exit code. err is set only when the command could not run to an exit.
func runFixedPackageQuery(ctx context.Context, argv []string) (string, int, error) {
	if len(argv) < 1 {
		return "", 0, fmt.Errorf("package query failed")
	}
	cmd := jobCommand(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{
		"PATH=" + packagePATH,
		"LC_ALL=C",
	}
	cmd.Dir = "/"
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", 0, fmt.Errorf("package query failed")
	}
	if err := cmd.Start(); err != nil {
		return "", 0, fmt.Errorf("package query failed")
	}
	out, readErr := readLimited(stdout, hostFileCap)
	if readErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if readErr != nil {
		return "", 0, fmt.Errorf("package query output exceeds cap")
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return string(out), exitErr.ExitCode(), nil
	}
	if waitErr != nil {
		return "", 0, fmt.Errorf("package query failed")
	}
	return string(out), 0, nil
}

func installPackage(ctx context.Context, name string, allow []string) error {
	return changePackage(ctx, "install", name, allow)
}

// packageCtxErr is the error for a verb stopped by the script's deadline or
// cancel. An interrupted apt/dpkg can leave the package database half
// configured, so a mutating apt verb says how to repair it.
func packageCtxErr(ctx context.Context, mgr, what string, mutating bool) error {
	msg := fmt.Sprintf("%s %s", what, jobCtxReason(ctx))
	if mutating && (mgr == "apt-get" || strings.HasPrefix(mgr, "dpkg")) {
		msg += "; dpkg may need 'dpkg --configure -a'"
	}
	return errors.New(msg)
}

// changePackage runs one mutating verb (install, remove, upgrade) after the
// grant and host checks.
func changePackage(ctx context.Context, verb, name string, allow []string) error {
	if !packageNameRE.MatchString(name) || !exactGrant(allow, name) {
		return fmt.Errorf("package not allowed")
	}
	if !hostLinux() {
		return fmt.Errorf("requires linux")
	}
	mgr, err := lookupPackageManager()
	if err != nil {
		return err
	}
	m := packageManagerByName(mgr)
	if m == nil {
		return fmt.Errorf("package manager unavailable")
	}
	argv, err := m.argv(verb, name)
	if err != nil {
		return err
	}
	unlock, err := lockPackages(ctx, mgr, "package "+verb)
	if err != nil {
		return err
	}
	defer unlock()
	if verb == "remove" {
		if err := checkRemoveOnly(ctx, mgr, m, name); err != nil {
			return err
		}
	}
	if err := runPackageInstall(ctx, argv); err != nil {
		if ctx.Err() != nil {
			return packageCtxErr(ctx, mgr, "package "+verb, true)
		}
		return err
	}
	return nil
}

// checkRemoveOnly runs the remove dry run and refuses unless it would remove
// only name (brew: unless no installed formula uses name).
func checkRemoveOnly(ctx context.Context, mgr string, m *pkgManager, name string) error {
	argv, err := m.RemoveSimArgv(name)
	if err != nil {
		return fmt.Errorf("package remove refused: no dry run for %s", mgr)
	}
	out, code, err := runPackageQuery(ctx, argv)
	if err != nil {
		if ctx.Err() != nil {
			return packageCtxErr(ctx, mgr, "package remove dry run", false)
		}
		return fmt.Errorf("package remove refused: dry run failed")
	}
	removed, ok := parseRemoveSim(mgr, out, code)
	if !ok {
		return fmt.Errorf("package remove refused: dry run output not understood")
	}
	if mgr == "brew" {
		if len(removed) != 0 {
			return fmt.Errorf("package remove refused: installed packages depend on %s", name)
		}
		return nil
	}
	if len(removed) != 1 || !removed[name] {
		return fmt.Errorf("package remove refused: it would remove %d packages, not only %s", len(removed), name)
	}
	return nil
}

// queryPackage reports whether one granted package is installed. Exit 1 is
// how dpkg-query, rpm and brew say "not installed"; any other non-zero exit
// is an error.
func queryPackage(ctx context.Context, name string, allow []string) (bool, string, error) {
	if !packageNameRE.MatchString(name) || !exactGrant(allow, name) {
		return false, "", fmt.Errorf("package not allowed")
	}
	if !hostLinux() {
		return false, "", fmt.Errorf("requires linux")
	}
	mgr, err := lookupPackageManager()
	if err != nil {
		return false, "", err
	}
	m := packageManagerByName(mgr)
	if m == nil {
		return false, "", fmt.Errorf("package manager unavailable")
	}
	argv, err := m.QueryArgv(name)
	if err != nil {
		return false, "", err
	}
	unlock, err := lockPackages(ctx, mgr, "package query")
	if err != nil {
		return false, "", err
	}
	defer unlock()
	out, code, err := runPackageQuery(ctx, argv)
	if ctx.Err() != nil {
		return false, "", packageCtxErr(ctx, mgr, "package query", false)
	}
	if err != nil {
		return false, "", err
	}
	if code != 0 && code != 1 {
		return false, "", fmt.Errorf("package query failed")
	}
	installed, version := parsePackageQuery(mgr, name, out)
	return installed, version, nil
}

// listPackages returns the installed package inventory. It needs at least one
// exact package grant, since it names no package to check.
func listPackages(ctx context.Context, allow []string) ([]pkgEntry, error) {
	granted := false
	for _, item := range allow {
		if exactItemOK(item) && packageNameRE.MatchString(item) {
			granted = true
			break
		}
	}
	if !granted {
		return nil, fmt.Errorf("package not allowed")
	}
	if !hostLinux() {
		return nil, fmt.Errorf("requires linux")
	}
	mgr, err := lookupPackageManager()
	if err != nil {
		return nil, err
	}
	m := packageManagerByName(mgr)
	if m == nil {
		return nil, fmt.Errorf("package manager unavailable")
	}
	argv, err := m.ListArgv()
	if err != nil {
		return nil, err
	}
	unlock, err := lockPackages(ctx, mgr, "package list")
	if err != nil {
		return nil, err
	}
	defer unlock()
	out, code, err := runPackageQuery(ctx, argv)
	if ctx.Err() != nil {
		return nil, packageCtxErr(ctx, mgr, "package list", false)
	}
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("package list failed")
	}
	return parsePackageList(mgr, out, packageListMax), nil
}

func (engine *SysscriptEngine) packagesInstall(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("install", args, kwargs, "name", &name); err != nil {
		return starlark.None, err
	}
	if !packageNameRE.MatchString(name) || !exactGrant(engine.Entitlements.AllowPackages, name) {
		return starlark.None, fmt.Errorf("package not allowed")
	}
	if err := installPackage(engine.ctx, name, engine.Entitlements.AllowPackages); err != nil {
		return starlark.None, err
	}
	return starlark.True, nil
}

func (engine *SysscriptEngine) packagesChange(verb string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs(verb, args, kwargs, "name", &name); err != nil {
		return starlark.None, err
	}
	if !packageNameRE.MatchString(name) || !exactGrant(engine.Entitlements.AllowPackages, name) {
		return starlark.None, fmt.Errorf("package not allowed")
	}
	if err := changePackage(engine.ctx, verb, name, engine.Entitlements.AllowPackages); err != nil {
		return starlark.None, err
	}
	return starlark.True, nil
}

// sys.packages.remove(name)
func (engine *SysscriptEngine) packagesRemove(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return engine.packagesChange("remove", args, kwargs)
}

// sys.packages.upgrade(name)
func (engine *SysscriptEngine) packagesUpgrade(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return engine.packagesChange("upgrade", args, kwargs)
}

// sys.packages.query(name) - returns {installed, version}
func (engine *SysscriptEngine) packagesQuery(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("query", args, kwargs, "name", &name); err != nil {
		return starlark.None, err
	}
	installed, version, err := queryPackage(engine.ctx, name, engine.Entitlements.AllowPackages)
	if err != nil {
		return starlark.None, err
	}
	d := starlark.NewDict(2)
	d.SetKey(starlark.String("installed"), starlark.Bool(installed))
	d.SetKey(starlark.String("version"), starlark.String(version))
	return d, nil
}

// sys.packages.list() - returns [{name, version}]
func (engine *SysscriptEngine) packagesList(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("list", args, kwargs); err != nil {
		return starlark.None, err
	}
	entries, err := listPackages(engine.ctx, engine.Entitlements.AllowPackages)
	if err != nil {
		return starlark.None, err
	}
	vals := make([]starlark.Value, 0, len(entries))
	for _, e := range entries {
		d := starlark.NewDict(2)
		d.SetKey(starlark.String("name"), starlark.String(e.Name))
		d.SetKey(starlark.String("version"), starlark.String(e.Version))
		vals = append(vals, d)
	}
	return starlark.NewList(vals), nil
}
