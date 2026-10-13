//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Threats: linux host calls re-check the grant, then use a fixed path or
// netlink. Mount rejects bind flags, host roots, and symlink escape. Sysctl
// writes only an allowed key under /proc/sys and never the three hard-denied
// kernel keys. resolv.conf is a fixed path of nameserver lines. Package
// install is not in this file. Nothing here is logged.

func hostLinux() bool { return true }

func readCappedFile(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	buf, readErr := readLimited(f, max)
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return buf, nil
}

func utsString(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, c)
	}
	return string(out)
}

func hostLinuxOSRelease() (map[string]string, error) {
	data, err := readCappedFile("/etc/os-release", osReleaseCap)
	if err != nil {
		return nil, err
	}
	return parseOSRelease(string(data)), nil
}

func hostLinuxUname() (map[string]string, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return nil, err
	}
	return map[string]string{
		"sysname":  utsString(u.Sysname[:]),
		"nodename": utsString(u.Nodename[:]),
		"release":  utsString(u.Release[:]),
		"version":  utsString(u.Version[:]),
		"machine":  utsString(u.Machine[:]),
	}, nil
}

func hostLinuxHostname() (string, error) {
	name, err := os.Hostname()
	if err != nil {
		return "", err
	}
	if name == "" || len(name) > 255 || strings.ContainsAny(name, "\n\r\x00") {
		return "", fmt.Errorf("hostname rejected")
	}
	return name, nil
}

func hostLinuxUptime() (string, error) {
	data, err := readCappedFile("/proc/uptime", 128)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 || !uptimeRE.MatchString(fields[0]) {
		return "", fmt.Errorf("uptime rejected")
	}
	return fields[0], nil
}

func hostLinuxUsers() ([]map[string]string, error) {
	data, err := readCappedFile("/etc/passwd", hostFileCap)
	if err != nil {
		return nil, err
	}
	return parsePasswd(string(data))
}

func hostLinuxGroups() ([]map[string]string, error) {
	data, err := readCappedFile("/etc/group", hostFileCap)
	if err != nil {
		return nil, err
	}
	return parseGroup(string(data))
}

func hostNetLinks() ([]map[string]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]string, 0, len(links))
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil {
			continue
		}
		state := "down"
		if attrs.Flags&net.FlagUp != 0 {
			state = "up"
		}
		out = append(out, map[string]string{
			"name":  attrs.Name,
			"mtu":   strconv.Itoa(attrs.MTU),
			"state": state,
		})
		if len(out) > rowCap {
			return nil, fmt.Errorf("too many rows")
		}
	}
	return out, nil
}

func hostNetAddresses() ([]map[string]string, error) {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]string, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IPNet == nil {
			continue
		}
		link, err := netlink.LinkByIndex(addr.LinkIndex)
		if err != nil || link.Attrs() == nil {
			continue
		}
		out = append(out, map[string]string{
			"iface": link.Attrs().Name,
			"cidr":  addr.IPNet.String(),
		})
		if len(out) > rowCap {
			return nil, fmt.Errorf("too many rows")
		}
	}
	return out, nil
}

func routeDefault(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, bits := dst.Mask.Size()
	return ones == 0 && (bits == 32 || bits == 128)
}

func hostNetRoutes() ([]map[string]string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]string, 0, len(routes))
	for _, rt := range routes {
		link, err := netlink.LinkByIndex(rt.LinkIndex)
		if err != nil || link.Attrs() == nil {
			continue
		}
		dst := ""
		isDefault := "false"
		if routeDefault(rt.Dst) {
			dst = "default"
			isDefault = "true"
		} else if rt.Dst != nil {
			dst = rt.Dst.String()
		}
		gw := ""
		if rt.Gw != nil {
			gw = rt.Gw.String()
		}
		out = append(out, map[string]string{
			"dst":     dst,
			"gw":      gw,
			"iface":   link.Attrs().Name,
			"default": isDefault,
		})
		if len(out) > rowCap {
			return nil, fmt.Errorf("too many rows")
		}
	}
	return out, nil
}

func hostNetSetAddress(iface, cidr string, allow []string) error {
	if err := ifaceGranted(allow, iface); err != nil {
		return err
	}
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("cidr rejected")
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("cidr rejected")
	}
	addr.LinkIndex = link.Attrs().Index
	return netlink.AddrReplace(link, addr)
}

func hostNetSetDefaultRoute(iface, gateway string, allow []string) error {
	if err := ifaceGranted(allow, iface); err != nil {
		return err
	}
	gw := net.ParseIP(gateway)
	if gw == nil {
		return fmt.Errorf("gateway rejected")
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	return netlink.RouteReplace(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Gw:        gw,
	})
}

func hostNetLinkUp(iface string, allow []string) error {
	if err := ifaceGranted(allow, iface); err != nil {
		return err
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func hostNetLinkDown(iface string, allow []string) error {
	if err := ifaceGranted(allow, iface); err != nil {
		return err
	}
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	return netlink.LinkSetDown(link)
}

func writeResolv(body string) (err error) {
	f, err := os.CreateTemp("/etc", ".resolv-*.tmp")
	if err != nil {
		return err
	}
	name := f.Name()
	ok := false
	defer func() {
		if ok {
			return
		}
		if rmErr := os.Remove(name); rmErr != nil && !os.IsNotExist(rmErr) && err != nil {
			err = fmt.Errorf("%w (cleanup: %v)", err, rmErr)
		}
	}()
	if err = f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if _, err = f.WriteString(body); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, "/etc/resolv.conf"); err != nil {
		return err
	}
	ok = true
	return nil
}

func hostNetSetDNS(iface string, servers []string, allow []string) error {
	if err := ifaceGranted(allow, iface); err != nil {
		return err
	}
	body, err := resolvBody(servers)
	if err != nil {
		return err
	}
	return writeResolv(body)
}

func hostDiskMounts() ([]map[string]string, error) {
	data, err := readCappedFile("/proc/mounts", outputCap)
	if err != nil {
		return nil, err
	}
	return parseMounts(string(data))
}

func hostDiskUsage(path string) (map[string]string, error) {
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		return nil, fmt.Errorf("path not allowed")
	}
	var st unix.Statfs_t
	if err := unix.Statfs(cleaned, &st); err != nil {
		return nil, err
	}
	if st.Bsize <= 0 {
		return nil, fmt.Errorf("statfs rejected")
	}
	bsize := uint64(st.Bsize)
	return map[string]string{
		"total_bytes": strconv.FormatUint(st.Blocks*bsize, 10),
		"free_bytes":  strconv.FormatUint(st.Bfree*bsize, 10),
		"avail_bytes": strconv.FormatUint(st.Bavail*bsize, 10),
	}, nil
}

func hostDiskBlockDevices() ([]map[string]string, error) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}
	out := make([]map[string]string, 0, len(entries))
	for _, ent := range entries {
		name := ent.Name()
		if name == "." || name == ".." || strings.ContainsAny(name, `/\`) || !blockDevRE.MatchString(name) {
			continue
		}
		out = append(out, map[string]string{"name": name})
		if len(out) > rowCap {
			return nil, fmt.Errorf("too many rows")
		}
	}
	return out, nil
}

func hostDiskMount(source, target, fstype string, readonly bool, allow []string) error {
	cleaned := filepath.Clean(target)
	if err := mountTargetPolicy(cleaned, allow); err != nil {
		return err
	}
	if !mountSourceOK(fstype, source) {
		return fmt.Errorf("mount source not allowed")
	}
	resolved, err := resolveMountTarget(target, allow)
	if err != nil {
		return err
	}
	src := source
	if fstype != "tmpfs" {
		srcResolved, err := filepath.EvalSymlinks(filepath.Clean(source))
		if err != nil {
			return err
		}
		srcResolved = filepath.Clean(srcResolved)
		if !blockSourcePathOK(srcResolved) {
			return fmt.Errorf("mount source not allowed")
		}
		src = srcResolved
	}
	var flags uintptr
	if readonly {
		flags = unix.MS_RDONLY
	}
	return unix.Mount(src, resolved, fstype, flags, "")
}

func hostDiskUmount(target string, allow []string) error {
	resolved, err := resolveMountTarget(target, allow)
	if err != nil {
		return err
	}
	return unix.Unmount(resolved, 0)
}

func hostProcfsRead(rel string) (string, error) {
	if !procfsRelOK(rel) {
		return "", fmt.Errorf("procfs path not allowed")
	}
	full := filepath.Clean(filepath.Join("/proc", rel))
	if full == "/proc" || !pathWithin("/proc", full) {
		return "", fmt.Errorf("procfs path not allowed")
	}
	data, err := readCappedFile(full, outputCap)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func hostSysctlGet(key string, allow []string) (string, error) {
	if !sysctlGranted(allow, key) {
		return "", fmt.Errorf("sysctl not allowed")
	}
	path, err := sysctlProcPath(key)
	if err != nil {
		return "", err
	}
	data, err := readCappedFile(path, sysctlValueCap+1)
	if err != nil {
		return "", err
	}
	text := string(data)
	text = strings.TrimSuffix(text, "\n")
	if len(text) > sysctlValueCap || strings.ContainsAny(text, "\n\r\x00") {
		return "", fmt.Errorf("sysctl rejected")
	}
	return text, nil
}

func hostSysctlSet(key, value string, allow []string) error {
	if !sysctlGranted(allow, key) || !sysctlValueOK(value) {
		return fmt.Errorf("sysctl not allowed")
	}
	path, err := sysctlProcPath(key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString(value + "\n")
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
