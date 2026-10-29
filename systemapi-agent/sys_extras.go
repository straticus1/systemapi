package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.starlark.net/starlark"
)

// =============================================================================
// sys.fs extended
// =============================================================================

// sys.fs.stat(path) - returns dict {exists, size, mode, is_dir, mod_time} or None
func (engine *SysscriptEngine) fsStat(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs("stat", args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}
	resolved, err := fsGrantPath(engine.Entitlements.AllowFSRead, path, "read", true)
	if err != nil {
		return starlark.None, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		d := starlark.NewDict(1)
		d.SetKey(starlark.String("exists"), starlark.False)
		return d, nil
	}
	d := starlark.NewDict(5)
	d.SetKey(starlark.String("exists"), starlark.True)
	d.SetKey(starlark.String("size"), starlark.MakeInt64(info.Size()))
	d.SetKey(starlark.String("mode"), starlark.String(fmt.Sprintf("%04o", info.Mode().Perm())))
	d.SetKey(starlark.String("is_dir"), starlark.Bool(info.IsDir()))
	d.SetKey(starlark.String("mod_time"), starlark.MakeInt64(info.ModTime().Unix()))
	return d, nil
}

// sys.fs.glob(pattern) - returns list of matching paths
func (engine *SysscriptEngine) fsGlob(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pattern string
	if err := starlark.UnpackArgs("glob", args, kwargs, "pattern", &pattern); err != nil {
		return starlark.None, err
	}
	allow := engine.Entitlements.AllowFSRead
	if pattern == "" || strings.ContainsRune(pattern, 0) || !filepath.IsAbs(pattern) {
		return starlark.None, fmt.Errorf("security exception: read to %s not granted", pattern)
	}
	cleaned := filepath.Clean(pattern)
	if !fsPrefixAllowed(allow, cleaned) {
		return starlark.None, fmt.Errorf("security exception: read to %s not granted", pattern)
	}
	matches, err := filepath.Glob(cleaned)
	if err != nil {
		return starlark.None, fmt.Errorf("fs.glob: %w", err)
	}
	// A match reached through a symlink out of the grant is dropped.
	results := make([]starlark.Value, 0, len(matches))
	for _, m := range matches {
		if _, err := fsGrantPath(allow, m, "read", true); err == nil {
			results = append(results, starlark.String(m))
		}
	}
	return starlark.NewList(results), nil
}

// sys.fs.mkdir(path, mode="0755") - create directory and parents
func (engine *SysscriptEngine) fsMkdir(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, modeStr string
	if err := starlark.UnpackArgs("mkdir", args, kwargs, "path", &path, "mode?", &modeStr); err != nil {
		return starlark.None, err
	}
	root, resolved, err := fsGrantRootPath(engine.Entitlements.AllowFSWrite, path, "write", true)
	if err != nil {
		return starlark.None, err
	}
	mode := os.FileMode(0755)
	if modeStr != "" {
		parsed, err := strconv.ParseUint(modeStr, 8, 32)
		if err != nil {
			return starlark.None, fmt.Errorf("fs.mkdir: invalid mode %q", modeStr)
		}
		mode = os.FileMode(parsed)
	}
	if err := mkdirBeneath(root, resolved, mode); err != nil {
		return starlark.None, fmt.Errorf("fs.mkdir: %w", err)
	}
	return starlark.True, nil
}

// sys.fs.rm(path, recursive=False) - remove file or directory
func (engine *SysscriptEngine) fsRm(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	var recursive bool
	if err := starlark.UnpackArgs("rm", args, kwargs, "path", &path, "recursive?", &recursive); err != nil {
		return starlark.None, err
	}
	// The final component is not followed: rm of a symlink removes the link.
	resolved, err := fsGrantPath(engine.Entitlements.AllowFSWrite, path, "write", false)
	if err != nil {
		return starlark.None, err
	}
	if recursive {
		err = os.RemoveAll(resolved)
	} else {
		err = os.Remove(resolved)
	}
	if err != nil {
		return starlark.None, fmt.Errorf("fs.rm: %w", err)
	}
	return starlark.True, nil
}

// sys.fs.chmod(path, mode) - change permissions, mode is octal string e.g. "0644"
func (engine *SysscriptEngine) fsChmod(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, modeStr string
	if err := starlark.UnpackArgs("chmod", args, kwargs, "path", &path, "mode", &modeStr); err != nil {
		return starlark.None, err
	}
	root, resolved, err := fsGrantRootPath(engine.Entitlements.AllowFSWrite, path, "write", true)
	if err != nil {
		return starlark.None, err
	}
	parsed, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		return starlark.None, fmt.Errorf("fs.chmod: invalid mode %q", modeStr)
	}
	if err := chmodBeneath(root, resolved, os.FileMode(parsed)); err != nil {
		return starlark.None, fmt.Errorf("fs.chmod: %w", err)
	}
	return starlark.True, nil
}

// =============================================================================
// sys.services  (systemctl wrappers)
// =============================================================================

func (engine *SysscriptEngine) svcAction(action, service string) (starlark.Value, error) {
	allowed := false
	for _, s := range engine.Entitlements.AllowServiceReload {
		if s == "*" || s == service {
			allowed = true
			break
		}
	}
	if !allowed {
		return starlark.None, fmt.Errorf("security exception: service %q not in allow_service_reload", service)
	}
	out, err := currentPlatform().Services.Action(engine.ctx, action, service)
	d := starlark.NewDict(3)
	d.SetKey(starlark.String("success"), starlark.Bool(err == nil))
	d.SetKey(starlark.String("output"), starlark.String(strings.TrimSpace(out)))
	if err != nil {
		d.SetKey(starlark.String("error"), starlark.String(err.Error()))
	} else {
		d.SetKey(starlark.String("error"), starlark.String(""))
	}
	return d, nil
}

func (engine *SysscriptEngine) svcStart(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var service string
	if err := starlark.UnpackArgs("start", args, kwargs, "service", &service); err != nil {
		return starlark.None, err
	}
	return engine.svcAction("start", service)
}

func (engine *SysscriptEngine) svcStop(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var service string
	if err := starlark.UnpackArgs("stop", args, kwargs, "service", &service); err != nil {
		return starlark.None, err
	}
	return engine.svcAction("stop", service)
}

func (engine *SysscriptEngine) svcRestart(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var service string
	if err := starlark.UnpackArgs("restart", args, kwargs, "service", &service); err != nil {
		return starlark.None, err
	}
	return engine.svcAction("restart", service)
}

func (engine *SysscriptEngine) svcEnable(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var service string
	if err := starlark.UnpackArgs("enable", args, kwargs, "service", &service); err != nil {
		return starlark.None, err
	}
	return engine.svcAction("enable", service)
}

func (engine *SysscriptEngine) svcDisable(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var service string
	if err := starlark.UnpackArgs("disable", args, kwargs, "service", &service); err != nil {
		return starlark.None, err
	}
	return engine.svcAction("disable", service)
}

// sys.services.status(service) - returns {active: bool, sub_state: str, output: str}
func (engine *SysscriptEngine) svcStatus(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var service string
	if err := starlark.UnpackArgs("status", args, kwargs, "service", &service); err != nil {
		return starlark.None, err
	}
	// status doesn't modify - no entitlement required
	st, _ := currentPlatform().Services.Status(engine.ctx, service)
	d := starlark.NewDict(3)
	d.SetKey(starlark.String("active"), starlark.Bool(st.Active))
	d.SetKey(starlark.String("state"), starlark.String(st.State))
	d.SetKey(starlark.String("output"), starlark.String(st.Output))
	return d, nil
}
