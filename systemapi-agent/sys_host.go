package main

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"go.starlark.net/starlark"
)

// Threats: Starlark wrappers check the exact grant before any host call, so
// a denied name fails the same way on every OS. "*" is not allow-all. Net
// writes validate the address before the linux function. Disk writes check
// the cleaned target before symlink resolution. Procfs and sysctl reject
// anything outside the fixed sets. This file does not open a socket.

func (engine *SysscriptEngine) ents() *Entitlements {
	if engine == nil || engine.Entitlements == nil {
		return &Entitlements{}
	}
	return engine.Entitlements
}

func starlarkDict(m map[string]string) (starlark.Value, error) {
	d := starlark.NewDict(len(m))
	for k, v := range m {
		if err := d.SetKey(starlark.String(k), starlark.String(v)); err != nil {
			return nil, err
		}
	}
	return d, nil
}

func starlarkDictList(items []map[string]string) (starlark.Value, error) {
	vals := make([]starlark.Value, 0, len(items))
	for _, item := range items {
		d, err := starlarkDict(item)
		if err != nil {
			return nil, err
		}
		vals = append(vals, d)
	}
	return starlark.NewList(vals), nil
}

func listStrings(list *starlark.List) ([]string, error) {
	if list == nil {
		return nil, nil
	}
	n := list.Len()
	if n > starlarkListMax {
		return nil, fmt.Errorf("too many arguments")
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		s, ok := list.Index(i).(starlark.String)
		if !ok || strings.ContainsRune(string(s), 0) {
			return nil, fmt.Errorf("invalid argument")
		}
		out = append(out, string(s))
	}
	return out, nil
}

func hostRows(rows []map[string]string, err error) (starlark.Value, error) {
	if err != nil {
		return starlark.None, err
	}
	return starlarkDictList(rows)
}

func (engine *SysscriptEngine) linuxOSRelease(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("os_release", args, kwargs); err != nil {
		return starlark.None, err
	}
	info, err := hostLinuxOSRelease()
	if err != nil {
		return starlark.None, err
	}
	return starlarkDict(info)
}

func (engine *SysscriptEngine) linuxUname(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("uname", args, kwargs); err != nil {
		return starlark.None, err
	}
	info, err := hostLinuxUname()
	if err != nil {
		return starlark.None, err
	}
	return starlarkDict(info)
}

func (engine *SysscriptEngine) linuxHostname(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("hostname", args, kwargs); err != nil {
		return starlark.None, err
	}
	name, err := hostLinuxHostname()
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(name), nil
}

func (engine *SysscriptEngine) linuxUptime(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("uptime", args, kwargs); err != nil {
		return starlark.None, err
	}
	up, err := hostLinuxUptime()
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(up), nil
}

func (engine *SysscriptEngine) linuxUsers(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("users", args, kwargs); err != nil {
		return starlark.None, err
	}
	return hostRows(hostLinuxUsers())
}

func (engine *SysscriptEngine) linuxGroups(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("groups", args, kwargs); err != nil {
		return starlark.None, err
	}
	return hostRows(hostLinuxGroups())
}

func (engine *SysscriptEngine) diskMounts(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("mounts", args, kwargs); err != nil {
		return starlark.None, err
	}
	return hostRows(hostDiskMounts())
}

func (engine *SysscriptEngine) diskUsage(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs("usage", args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		return starlark.None, fmt.Errorf("path not allowed")
	}
	info, err := hostDiskUsage(cleaned)
	if err != nil {
		return starlark.None, err
	}
	return starlarkDict(info)
}

func (engine *SysscriptEngine) diskBlockDevices(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("block_devices", args, kwargs); err != nil {
		return starlark.None, err
	}
	return hostRows(hostDiskBlockDevices())
}

func (engine *SysscriptEngine) diskMount(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source, target, fstype string
	var readonly bool
	if err := starlark.UnpackArgs("mount", args, kwargs, "source", &source, "target", &target, "fstype", &fstype, "readonly?", &readonly); err != nil {
		return starlark.None, err
	}
	cleaned := filepath.Clean(target)
	if err := mountTargetPolicy(cleaned, engine.ents().AllowMountTargets); err != nil {
		return starlark.None, err
	}
	if !mountSourceOK(fstype, source) {
		return starlark.None, fmt.Errorf("mount source not allowed")
	}
	if err := hostDiskMount(source, target, fstype, readonly, engine.ents().AllowMountTargets); err != nil {
		return starlark.None, err
	}
	return starlark.True, nil
}

func (engine *SysscriptEngine) diskUmount(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var target string
	if err := starlark.UnpackArgs("umount", args, kwargs, "target", &target); err != nil {
		return starlark.None, err
	}
	cleaned := filepath.Clean(target)
	if err := mountTargetPolicy(cleaned, engine.ents().AllowMountTargets); err != nil {
		return starlark.None, err
	}
	if err := hostDiskUmount(target, engine.ents().AllowMountTargets); err != nil {
		return starlark.None, err
	}
	return starlark.True, nil
}

func (engine *SysscriptEngine) procfsRead(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var rel string
	if err := starlark.UnpackArgs("read", args, kwargs, "path", &rel); err != nil {
		return starlark.None, err
	}
	if !procfsRelOK(rel) {
		return starlark.None, fmt.Errorf("procfs path not allowed")
	}
	text, err := hostProcfsRead(rel)
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(text), nil
}

func (engine *SysscriptEngine) procfsSysctlGet(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key string
	if err := starlark.UnpackArgs("sysctl_get", args, kwargs, "key", &key); err != nil {
		return starlark.None, err
	}
	if !sysctlGranted(engine.ents().AllowSysctl, key) {
		return starlark.None, fmt.Errorf("sysctl not allowed")
	}
	if _, err := sysctlProcPath(key); err != nil {
		return starlark.None, err
	}
	text, err := hostSysctlGet(key, engine.ents().AllowSysctl)
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(text), nil
}

func (engine *SysscriptEngine) procfsSysctlSet(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key, value string
	if err := starlark.UnpackArgs("sysctl_set", args, kwargs, "key", &key, "value", &value); err != nil {
		return starlark.None, err
	}
	if !sysctlGranted(engine.ents().AllowSysctl, key) || !sysctlValueOK(value) {
		return starlark.None, fmt.Errorf("sysctl not allowed")
	}
	if _, err := sysctlProcPath(key); err != nil {
		return starlark.None, err
	}
	if err := hostSysctlSet(key, value, engine.ents().AllowSysctl); err != nil {
		return starlark.None, err
	}
	return starlark.True, nil
}

func (engine *SysscriptEngine) netLinks(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("links", args, kwargs); err != nil {
		return starlark.None, err
	}
	return hostRows(hostNetLinks())
}

func (engine *SysscriptEngine) netAddresses(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("addresses", args, kwargs); err != nil {
		return starlark.None, err
	}
	return hostRows(hostNetAddresses())
}

func (engine *SysscriptEngine) netRoutes(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("routes", args, kwargs); err != nil {
		return starlark.None, err
	}
	return hostRows(hostNetRoutes())
}

func (engine *SysscriptEngine) netSetAddress(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var iface, cidr string
	if err := starlark.UnpackArgs("set_address", args, kwargs, "iface", &iface, "cidr", &cidr); err != nil {
		return starlark.None, err
	}
	allow := engine.ents().AllowNetManage
	if err := ifaceGranted(allow, iface); err != nil {
		return starlark.None, err
	}
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return starlark.None, fmt.Errorf("cidr rejected")
	}
	if err := hostNetSetAddress(iface, cidr, allow); err != nil {
		return starlark.None, err
	}
	return starlark.True, nil
}

func (engine *SysscriptEngine) netSetRoute(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var iface, gateway string
	if err := starlark.UnpackArgs("set_route", args, kwargs, "iface", &iface, "gateway", &gateway); err != nil {
		return starlark.None, err
	}
	allow := engine.ents().AllowNetManage
	if err := ifaceGranted(allow, iface); err != nil {
		return starlark.None, err
	}
	if net.ParseIP(gateway) == nil {
		return starlark.None, fmt.Errorf("gateway rejected")
	}
	if err := hostNetSetDefaultRoute(iface, gateway, allow); err != nil {
		return starlark.None, err
	}
	return starlark.True, nil
}

func (engine *SysscriptEngine) netLinkUp(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return engine.netLinkSet("link_up", true, args, kwargs)
}

func (engine *SysscriptEngine) netLinkDown(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return engine.netLinkSet("link_down", false, args, kwargs)
}

func (engine *SysscriptEngine) netLinkSet(name string, up bool, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var iface string
	if err := starlark.UnpackArgs(name, args, kwargs, "iface", &iface); err != nil {
		return starlark.None, err
	}
	allow := engine.ents().AllowNetManage
	if err := ifaceGranted(allow, iface); err != nil {
		return starlark.None, err
	}
	var err error
	if up {
		err = hostNetLinkUp(iface, allow)
	} else {
		err = hostNetLinkDown(iface, allow)
	}
	if err != nil {
		return starlark.None, err
	}
	return starlark.True, nil
}

func (engine *SysscriptEngine) netSetDNS(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var iface string
	var servers *starlark.List
	if err := starlark.UnpackArgs("set_dns", args, kwargs, "iface", &iface, "nameservers", &servers); err != nil {
		return starlark.None, err
	}
	allow := engine.ents().AllowNetManage
	if err := ifaceGranted(allow, iface); err != nil {
		return starlark.None, err
	}
	list, err := listStrings(servers)
	if err != nil {
		return starlark.None, err
	}
	if _, err := resolvBody(list); err != nil {
		return starlark.None, err
	}
	if err := hostNetSetDNS(iface, list, allow); err != nil {
		return starlark.None, err
	}
	return starlark.True, nil
}
