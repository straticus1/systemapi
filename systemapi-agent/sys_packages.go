package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

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

// packageInstallTimeout is sysscriptOpTimeout: the server stops waiting for
// the script at 30 s, so a longer install would finish unseen.
const packageInstallTimeout = sysscriptOpTimeout

// packageQueryTimeout also bounds remove (dry run plus remove together) and
// upgrade; see sysscriptOpTimeout.
const packageQueryTimeout = sysscriptOpTimeout

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
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
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
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
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

func installPackage(name string, allow []string) error {
	return changePackage("install", name, allow)
}

// changePackage runs one mutating verb (install, remove, upgrade) after the
// grant and host checks.
func changePackage(verb, name string, allow []string) error {
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
	timeout := packageInstallTimeout
	if verb != "install" {
		timeout = packageQueryTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if verb == "remove" {
		if err := checkRemoveOnly(ctx, mgr, m, name); err != nil {
			return err
		}
	}
	if err := runPackageInstall(ctx, argv); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("package %s timed out after %s", verb, timeout)
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
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("package remove dry run timed out after %s", packageQueryTimeout)
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
func queryPackage(name string, allow []string) (bool, string, error) {
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
	ctx, cancel := context.WithTimeout(context.Background(), packageQueryTimeout)
	defer cancel()
	out, code, err := runPackageQuery(ctx, argv)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return false, "", fmt.Errorf("package query timed out after %s", packageQueryTimeout)
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
func listPackages(allow []string) ([]pkgEntry, error) {
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
	ctx, cancel := context.WithTimeout(context.Background(), packageQueryTimeout)
	defer cancel()
	out, code, err := runPackageQuery(ctx, argv)
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("package list timed out after %s", packageQueryTimeout)
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
	if err := installPackage(name, engine.Entitlements.AllowPackages); err != nil {
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
	if err := changePackage(verb, name, engine.Entitlements.AllowPackages); err != nil {
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
	installed, version, err := queryPackage(name, engine.Entitlements.AllowPackages)
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
	entries, err := listPackages(engine.Entitlements.AllowPackages)
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
