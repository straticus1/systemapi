package main

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"go.starlark.net/starlark"
)

// Threats: package install is root-equivalent. The argv is fixed, there is
// no shell, and the child gets PATH plus two locale variables. A name must
// match the package regex and an exact grant. "*" is not allow-all. Output
// is capped and is not logged. Non-linux returns before the package manager
// is looked up.

const packageInstallTimeout = 60 * time.Second

const packagePATH = "/usr/sbin:/usr/bin:/sbin:/bin"

var lookupPackageManager = lookupFixedPackageManager
var runPackageInstall = runFixedPackageInstall

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

func installPackage(name string, allow []string) error {
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
	argv, err := packageArgv(mgr, name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), packageInstallTimeout)
	defer cancel()
	return runPackageInstall(ctx, argv)
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
