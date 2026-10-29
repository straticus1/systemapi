package main

// sys.state: imperative desired-state verbs over the providers in
// state_providers.go. ensure_<kind>(...) checks one resource and, when it
// drifts, applies it and verifies; check_<kind>(...) only checks. Kinds:
// file, directory, absent, package, service, sysctl.
//
// Threats: arguments come from the script and are validated here (absolute
// clean paths, octal modes up to 0777, owner names by regex, package,
// service and sysctl names by the existing regexes, content capped). Grants
// are not checked here but in the providers' host views, before any backend
// call, against the run's entitlements: these verbs reach nothing the
// matching sys.fs, sys.config, sys.packages, sys.services and sys.procfs
// verbs could not, and services need an exact grant ("*" is refused). A
// check_* verb builds only a ReadOnlyHost. Results carry facts and a capped
// error, never a sensitive file's hash, size or diff.

import (
	"fmt"
	"sort"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// restartOnMax bounds a service's restart_on list.
const restartOnMax = 32

// stateParser builds one resource from builtin arguments.
type stateParser func(fn string, args starlark.Tuple, kwargs []starlark.Tuple) (Applier, error)

// stateKinds maps each kind to its parser, for sys.state (no restart_on).
var stateKinds = []struct {
	kind  string
	parse stateParser
}{
	{"file", func(fn string, a starlark.Tuple, kw []starlark.Tuple) (Applier, error) {
		return parseFileResource(fn, a, kw)
	}},
	{"directory", func(fn string, a starlark.Tuple, kw []starlark.Tuple) (Applier, error) {
		return parseDirResource(fn, a, kw)
	}},
	{"absent", func(fn string, a starlark.Tuple, kw []starlark.Tuple) (Applier, error) {
		return parseAbsentResource(fn, a, kw)
	}},
	{"package", func(fn string, a starlark.Tuple, kw []starlark.Tuple) (Applier, error) {
		return parsePackageResource(fn, a, kw)
	}},
	{"service", func(fn string, a starlark.Tuple, kw []starlark.Tuple) (Applier, error) {
		return parseServiceResource(fn, a, kw, false)
	}},
	{"sysctl", func(fn string, a starlark.Tuple, kw []starlark.Tuple) (Applier, error) {
		return parseSysctlResource(fn, a, kw)
	}},
}

func parsePath(fn, path string) error {
	if !statePathOK(path) {
		return fmt.Errorf("%s: path must be absolute and clean, not /", fn)
	}
	return nil
}

func parseOwners(fn, owner, group string) error {
	if !ownerSpecOK(owner) {
		return fmt.Errorf("%s: invalid owner %q", fn, owner)
	}
	if !ownerSpecOK(group) {
		return fmt.Errorf("%s: invalid group %q", fn, group)
	}
	return nil
}

// parseFileResource: (path, content, mode="0644", owner="", group="",
// sensitive=False).
func parseFileResource(fn string, args starlark.Tuple, kwargs []starlark.Tuple) (*fileResource, error) {
	var path, content, owner, group string
	mode := "0644"
	var sensitive bool
	if err := starlark.UnpackArgs(fn, args, kwargs, "path", &path, "content", &content,
		"mode?", &mode, "owner?", &owner, "group?", &group, "sensitive?", &sensitive); err != nil {
		return nil, err
	}
	if err := parsePath(fn, path); err != nil {
		return nil, err
	}
	if len(content) > stateContentMax {
		return nil, fmt.Errorf("%s: content exceeds %d bytes", fn, stateContentMax)
	}
	m, err := parseStateMode(mode)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn, err)
	}
	if err := parseOwners(fn, owner, group); err != nil {
		return nil, err
	}
	return &fileResource{path: path, content: content, mode: m, owner: owner, group: group, sensitive: sensitive}, nil
}

// parseDirResource: (path, mode="0755", owner="", group="").
func parseDirResource(fn string, args starlark.Tuple, kwargs []starlark.Tuple) (*dirResource, error) {
	var path, owner, group string
	mode := "0755"
	if err := starlark.UnpackArgs(fn, args, kwargs, "path", &path, "mode?", &mode, "owner?", &owner, "group?", &group); err != nil {
		return nil, err
	}
	if err := parsePath(fn, path); err != nil {
		return nil, err
	}
	m, err := parseStateMode(mode)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn, err)
	}
	if err := parseOwners(fn, owner, group); err != nil {
		return nil, err
	}
	return &dirResource{path: path, mode: m, owner: owner, group: group}, nil
}

// parseAbsentResource: (path).
func parseAbsentResource(fn string, args starlark.Tuple, kwargs []starlark.Tuple) (*absentResource, error) {
	var path string
	if err := starlark.UnpackArgs(fn, args, kwargs, "path", &path); err != nil {
		return nil, err
	}
	if err := parsePath(fn, path); err != nil {
		return nil, err
	}
	return &absentResource{path: path}, nil
}

// parsePackageResource: (name, present=True, version=None).
func parsePackageResource(fn string, args starlark.Tuple, kwargs []starlark.Tuple) (*packageResource, error) {
	var name string
	present := true
	var version starlark.Value = starlark.None
	if err := starlark.UnpackArgs(fn, args, kwargs, "name", &name, "present?", &present, "version?", &version); err != nil {
		return nil, err
	}
	if !packageNameRE.MatchString(name) {
		return nil, fmt.Errorf("%s: invalid package name", fn)
	}
	r := &packageResource{name: name, present: present}
	switch v := version.(type) {
	case starlark.NoneType:
	case starlark.String:
		s := string(v)
		if s == "" || len(s) > packageVersionMax || strings.ContainsAny(s, " \t\r\n\x00") {
			return nil, fmt.Errorf("%s: invalid version", fn)
		}
		if !present {
			return nil, fmt.Errorf("%s: version needs present=True", fn)
		}
		r.version = s
	default:
		return nil, fmt.Errorf("%s: version must be a string or None", fn)
	}
	return r, nil
}

// parseServiceResource: (name, running=True, enabled=True), plus
// restart_on=[keys] when withRestartOn (the converge declaration only).
func parseServiceResource(fn string, args starlark.Tuple, kwargs []starlark.Tuple, withRestartOn bool) (*serviceResource, error) {
	var name string
	running, enabled := true, true
	var restartOn starlark.Value = starlark.None
	pairs := []any{"name", &name, "running?", &running, "enabled?", &enabled}
	if withRestartOn {
		pairs = append(pairs, "restart_on?", &restartOn)
	}
	if err := starlark.UnpackArgs(fn, args, kwargs, pairs...); err != nil {
		return nil, err
	}
	if !serviceNameRE.MatchString(name) {
		return nil, fmt.Errorf("%s: invalid service name", fn)
	}
	r := &serviceResource{name: name, running: running, enabled: enabled}
	if restartOn != starlark.None {
		seq, ok := restartOn.(starlark.Indexable)
		if !ok {
			return nil, fmt.Errorf("%s: restart_on must be a list of resource keys", fn)
		}
		if seq.Len() > restartOnMax {
			return nil, fmt.Errorf("%s: restart_on has more than %d keys", fn, restartOnMax)
		}
		for i := 0; i < seq.Len(); i++ {
			k, ok := seq.Index(i).(starlark.String)
			if !ok || len(k) == 0 || len(k) > statePathMax+16 {
				return nil, fmt.Errorf("%s: restart_on must be a list of resource keys", fn)
			}
			r.restartOn = append(r.restartOn, string(k))
		}
		if len(r.restartOn) > 0 && !running {
			return nil, fmt.Errorf("%s: restart_on needs running=True", fn)
		}
	}
	return r, nil
}

// parseSysctlResource: (key, value).
func parseSysctlResource(fn string, args starlark.Tuple, kwargs []starlark.Tuple) (*sysctlResource, error) {
	var key, value string
	if err := starlark.UnpackArgs(fn, args, kwargs, "key", &key, "value", &value); err != nil {
		return nil, err
	}
	if !sysctlKeyRE.MatchString(key) {
		return nil, fmt.Errorf("%s: invalid sysctl key", fn)
	}
	if !sysctlValueOK(value) {
		return nil, fmt.Errorf("%s: invalid sysctl value", fn)
	}
	return &sysctlResource{key: key, value: value}, nil
}

// factsValue converts facts to a dict with sorted keys (None for nil).
func factsValue(f Facts) (starlark.Value, error) {
	if f == nil {
		return starlark.None, nil
	}
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	d := starlark.NewDict(len(f))
	for _, k := range keys {
		if err := d.SetKey(starlark.String(k), goToStarlark(f[k])); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// stateDict builds a result dict from name/value pairs, converting Facts.
func stateDict(kv ...any) (starlark.Value, error) {
	d := starlark.NewDict(len(kv) / 2)
	for i := 0; i+1 < len(kv); i += 2 {
		v := kv[i+1]
		var sv starlark.Value
		switch x := v.(type) {
		case Facts:
			fv, err := factsValue(x)
			if err != nil {
				return nil, err
			}
			sv = fv
		case starlark.Value:
			sv = x
		default:
			return nil, fmt.Errorf("state result: unexpected %T", v)
		}
		if err := d.SetKey(starlark.String(kv[i].(string)), sv); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// stateBackendFor is the engine's host: the real one unless a test set it.
func (engine *SysscriptEngine) stateBackendFor() hostBackend {
	if engine.stateBackend != nil {
		return *engine.stateBackend
	}
	return osHostBackend()
}

// stateModule builds sys.state.
func (engine *SysscriptEngine) stateModule() *starlarkstruct.Struct {
	d := starlark.StringDict{}
	for _, k := range stateKinds {
		ensure, check := "ensure_"+k.kind, "check_"+k.kind
		parse := k.parse
		d[ensure] = starlark.NewBuiltin(ensure, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			a, err := parse(ensure, args, kwargs)
			if err != nil {
				return starlark.None, err
			}
			return engine.stateEnsure(a)
		})
		d[check] = starlark.NewBuiltin(check, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			a, err := parse(check, args, kwargs)
			if err != nil {
				return starlark.None, err
			}
			return engine.stateCheck(a)
		})
	}
	return starlarkstruct.FromStringDict(starlark.String("state"), d)
}

// stateEnsure returns {changed, status, before, after, backup_id, error}.
func (engine *SysscriptEngine) stateEnsure(a Applier) (starlark.Value, error) {
	b := engine.stateBackendFor()
	ro := newReadOnlyHost(engine.Entitlements, b.reads)
	res := checkResource(engine.ctx, a, ro)
	after := res.Before
	if res.Status == statusDrift {
		res = applyChecked(engine.ctx, a, ro, newWriteHost(engine.Entitlements, b.newWrites()), res)
		after = res.After
	}
	return stateDict(
		"changed", starlark.Bool(res.Status == statusChanged),
		"status", starlark.String(res.Status),
		"before", res.Before,
		"after", after,
		"backup_id", starlark.String(res.BackupID),
		"error", starlark.String(res.Error),
	)
}

// stateCheck returns {status, before, desired, diff, error}. It never
// builds a WriteHost.
func (engine *SysscriptEngine) stateCheck(c Checker) (starlark.Value, error) {
	res := checkResource(engine.ctx, c, newReadOnlyHost(engine.Entitlements, engine.stateBackendFor().reads))
	return stateDict(
		"status", starlark.String(res.Status),
		"before", res.Before,
		"desired", res.Desired,
		"diff", starlark.String(res.Diff),
		"error", starlark.String(res.Error),
	)
}
