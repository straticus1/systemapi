package main

import (
	"os"
	"path/filepath"
	"strings"

	"go.starlark.net/starlark"
)

// Threats: read-only. selinux() and apparmor() read fixed files under fixed
// roots, each capped at hostFileCap, and never write, load or toggle a
// policy. A missing or unreadable file means "not enabled" or a zero count,
// never an error, so a script can probe any host.

// lsmPaths are the files the LSM status readers use. Tests point them at a
// temp dir.
type lsmPaths struct {
	selinuxFS       string // selinuxfs mount, holds "enforce"
	selinuxConfig   string // /etc/selinux/config
	apparmorFS      string // securityfs apparmor dir, holds "profiles"
	apparmorEnabled string // module parameter, "Y" when enabled
}

var lsmRoots = lsmPaths{
	selinuxFS:       "/sys/fs/selinux",
	selinuxConfig:   "/etc/selinux/config",
	apparmorFS:      "/sys/kernel/security/apparmor",
	apparmorEnabled: "/sys/module/apparmor/parameters/enabled",
}

func readLSMFile(path string) (string, bool) {
	text, err := readFileCapped(path, hostFileCap)
	if err != nil {
		return "", false
	}
	return text, true
}

type selinuxStatus struct {
	Enabled bool
	Mode    string
	Policy  string
}

// readSELinux reports the runtime mode from selinuxfs and the policy name
// from the config file. Without selinuxfs the mode is "disabled".
func readSELinux(p lsmPaths) selinuxStatus {
	st := selinuxStatus{Mode: "disabled"}
	if enforce, ok := readLSMFile(filepath.Join(p.selinuxFS, "enforce")); ok {
		switch strings.TrimSpace(enforce) {
		case "1":
			st.Enabled, st.Mode = true, "enforcing"
		case "0":
			st.Enabled, st.Mode = true, "permissive"
		}
	}
	if conf, ok := readLSMFile(p.selinuxConfig); ok {
		for _, line := range strings.Split(conf, "\n") {
			line = strings.TrimSpace(line)
			if v, found := strings.CutPrefix(line, "SELINUXTYPE="); found {
				st.Policy = strings.Trim(strings.TrimSpace(v), `"'`)
			}
		}
	}
	return st
}

type apparmorStatus struct {
	Enabled  bool
	Profiles int
	Enforce  int
	Complain int
}

// readAppArmor reports whether the module is enabled and counts loaded
// profiles by mode. The profiles file is root-only; when it cannot be read
// the counts stay zero.
func readAppArmor(p lsmPaths) apparmorStatus {
	var st apparmorStatus
	if v, ok := readLSMFile(p.apparmorEnabled); ok {
		st.Enabled = strings.HasPrefix(strings.TrimSpace(v), "Y")
	} else if info, err := os.Stat(p.apparmorFS); err == nil && info.IsDir() {
		st.Enabled = true
	}
	if !st.Enabled {
		return st
	}
	profiles, ok := readLSMFile(filepath.Join(p.apparmorFS, "profiles"))
	if !ok {
		return st
	}
	// Each line is "name (mode)".
	for _, line := range strings.Split(profiles, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		st.Profiles++
		switch {
		case strings.HasSuffix(line, "(enforce)"):
			st.Enforce++
		case strings.HasSuffix(line, "(complain)"):
			st.Complain++
		}
	}
	return st
}

// sys.linux.selinux() - returns {enabled, mode, policy}
func (engine *SysscriptEngine) linuxSELinux(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("selinux", args, kwargs); err != nil {
		return starlark.None, err
	}
	st := readSELinux(lsmRoots)
	d := starlark.NewDict(3)
	d.SetKey(starlark.String("enabled"), starlark.Bool(st.Enabled))
	d.SetKey(starlark.String("mode"), starlark.String(st.Mode))
	d.SetKey(starlark.String("policy"), starlark.String(st.Policy))
	return d, nil
}

// sys.linux.apparmor() - returns {enabled, profiles, enforce, complain}
func (engine *SysscriptEngine) linuxAppArmor(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("apparmor", args, kwargs); err != nil {
		return starlark.None, err
	}
	st := readAppArmor(lsmRoots)
	d := starlark.NewDict(4)
	d.SetKey(starlark.String("enabled"), starlark.Bool(st.Enabled))
	d.SetKey(starlark.String("profiles"), starlark.MakeInt(st.Profiles))
	d.SetKey(starlark.String("enforce"), starlark.MakeInt(st.Enforce))
	d.SetKey(starlark.String("complain"), starlark.MakeInt(st.Complain))
	return d, nil
}
