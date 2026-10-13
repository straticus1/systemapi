package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Threats: a lease that names "*", a JSON boolean, or a hard-denied sysctl
// must not become a grant. Path checks reject prefix tricks (/mnt vs
// /mnt-evil) and symlink escape. Manifest checks reject privileged pods,
// host namespaces, and hostPath. This file does not open a socket, mount,
// or write sysctl. An empty list is not allow-all.

const (
	outputCap             = 64 * 1024
	manifestCap           = 64 * 1024
	sysctlValueCap        = 256
	listCap               = 32
	exactItemMax          = 256
	installErrCap         = 512
	dockerBodyCap         = 1 << 20
	kubeListCap           = 2 << 20
	execArgMax            = 32
	execArgLen            = 4096
	starlarkListMax       = 32
	resolvMax             = 3
	rowCap                = 4096
	osReleaseCap          = 16 * 1024
	manifestDepthMax      = 32
	kubeItemCap           = 500
	hostFileCap           = 1 << 20
)

var (
	packageNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.+_-]{0,127}$`)
	imageNameRE   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,200}$`)
	ifaceNameRE   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9._:-]{0,14}$`)
	sysctlKeyRE   = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,127}$`)
	osReleaseKeyRE = regexp.MustCompile(`^[A-Z0-9_]+$`)
	procfsPIDFile = regexp.MustCompile(`^[0-9]+/(status|cmdline|io|limits|stat|cgroup)$`)
	dns1123RE     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*$`)
	blockDevRE    = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
	uptimeRE      = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
)

var deniedSysctl = map[string]struct{}{
	"kernel.core_pattern": {},
	"kernel.modprobe":     {},
	"kernel.hotplug":      {},
}

var deniedMountRoots = []string{
	"/etc", "/proc", "/sys", "/dev", "/boot", "/bin", "/sbin",
	"/usr", "/lib", "/lib64", "/root", "/home", "/var", "/run",
}

var allowedFstype = map[string]struct{}{
	"ext4": {}, "xfs": {}, "btrfs": {}, "vfat": {}, "tmpfs": {}, "nfs": {}, "nfs4": {},
}

var procfsFixed = map[string]struct{}{
	"meminfo": {}, "cpuinfo": {}, "loadavg": {}, "uptime": {}, "mounts": {}, "net/dev": {},
}

// exactGrant matches one list entry. "*" never matches, including a Go
// value that bypassed JSON filtering.
func exactGrant(list []string, name string) bool {
	if name == "" || strings.Contains(name, "*") || strings.Contains(name, "..") || strings.ContainsAny(name, "\x00\n\r") {
		return false
	}
	for _, item := range list {
		if strings.Contains(item, "*") {
			continue
		}
		if item == name {
			return true
		}
	}
	return false
}

func exactItemOK(s string) bool {
	if s == "" || len(s) > exactItemMax {
		return false
	}
	if strings.Contains(s, "*") || strings.Contains(s, "..") || strings.ContainsAny(s, "\x00\n\r") {
		return false
	}
	return true
}

func dropDeniedSysctl(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, item := range in {
		if _, denied := deniedSysctl[item]; denied {
			continue
		}
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sysctlGranted(allow []string, key string) bool {
	if _, denied := deniedSysctl[key]; denied {
		return false
	}
	if !sysctlKeyRE.MatchString(key) {
		return false
	}
	return exactGrant(allow, key)
}

func sysctlValueOK(v string) bool {
	if v == "" || len(v) > sysctlValueCap {
		return false
	}
	return !strings.ContainsAny(v, "\n\r\x00")
}

func sysctlProcPath(key string) (string, error) {
	if !sysctlKeyRE.MatchString(key) {
		return "", fmt.Errorf("sysctl not allowed")
	}
	if _, denied := deniedSysctl[key]; denied {
		return "", fmt.Errorf("sysctl not allowed")
	}
	rel := strings.ReplaceAll(key, ".", "/")
	full := filepath.Clean(filepath.Join("/proc/sys", rel))
	if full == "/proc/sys" || !pathWithin("/proc/sys", full) {
		return "", fmt.Errorf("sysctl not allowed")
	}
	return full, nil
}

func procfsRelOK(rel string) bool {
	if rel == "" || len(rel) > 128 || strings.ContainsAny(rel, "\x00\n\r\\") {
		return false
	}
	if strings.HasPrefix(rel, "/") || strings.Contains(rel, "..") {
		return false
	}
	if rel != filepath.Clean(rel) {
		return false
	}
	if _, ok := procfsFixed[rel]; ok {
		return true
	}
	return procfsPIDFile.MatchString(rel)
}

func imageAllowed(image string) bool {
	if strings.Contains(image, "..") || strings.Contains(image, "@") || strings.ContainsAny(image, " \t\r\n") {
		return false
	}
	return imageNameRE.MatchString(image)
}

func dns1123Name(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	return dns1123RE.MatchString(name)
}

func kubeAPI(kind string) (string, error) {
	switch kind {
	case "Pod", "Service", "ConfigMap":
		return "v1", nil
	case "Deployment":
		return "apps/v1", nil
	default:
		return "", fmt.Errorf("kind not allowed")
	}
}

func validateArgv(args []string) error {
	if len(args) > execArgMax {
		return fmt.Errorf("too many arguments")
	}
	for _, arg := range args {
		if arg == "" || len(arg) > execArgLen || strings.ContainsRune(arg, 0) {
			return fmt.Errorf("invalid argument")
		}
	}
	return nil
}

func pathWithin(root, candidate string) bool {
	root = filepath.Clean(root)
	candidate = filepath.Clean(candidate)
	if root == "" || candidate == "" {
		return false
	}
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false
	}
	return !filepath.IsAbs(rel)
}

func mountHardDenied(cleaned string) bool {
	if cleaned == "/" {
		return true
	}
	for _, root := range deniedMountRoots {
		if pathWithin(root, cleaned) {
			return true
		}
	}
	return false
}

func mountListed(cleaned string, allow []string) bool {
	for _, item := range allow {
		if item == "" || strings.Contains(item, "*") || strings.Contains(item, "..") || strings.ContainsAny(item, "\x00\n\r") {
			continue
		}
		root := filepath.Clean(item)
		if !filepath.IsAbs(root) || mountHardDenied(root) {
			continue
		}
		if pathWithin(root, cleaned) {
			return true
		}
	}
	return false
}

func mountTargetPolicy(target string, allow []string) error {
	cleaned := filepath.Clean(target)
	if !filepath.IsAbs(cleaned) {
		return fmt.Errorf("mount target not allowed")
	}
	if mountHardDenied(cleaned) {
		return fmt.Errorf("mount target denied")
	}
	if !mountListed(cleaned, allow) {
		return fmt.Errorf("mount target not allowed")
	}
	return nil
}

func resolveMountTarget(target string, allow []string) (string, error) {
	cleaned := filepath.Clean(target)
	if err := mountTargetPolicy(cleaned, allow); err != nil {
		return "", err
	}
	resolved, err := resolvePath(cleaned)
	if err != nil {
		return "", err
	}
	resolved = filepath.Clean(resolved)
	if err := mountTargetPolicy(resolved, allow); err != nil {
		return "", fmt.Errorf("mount target symlink escape")
	}
	return resolved, nil
}

func resolvePath(p string) (string, error) {
	if _, err := os.Lstat(p); err == nil {
		return filepath.EvalSymlinks(p)
	}
	parent := filepath.Dir(p)
	base := filepath.Base(p)
	if base == "." || base == string(os.PathSeparator) {
		return "", fmt.Errorf("mount target not allowed")
	}
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolvedParent, base), nil
}

func fstypeAllowed(fstype string) bool {
	_, ok := allowedFstype[fstype]
	return ok
}

func blockSourcePathOK(source string) bool {
	cleaned := filepath.Clean(source)
	if !filepath.IsAbs(cleaned) || cleaned == "/dev" {
		return false
	}
	return pathWithin("/dev", cleaned)
}

func mountSourceOK(fstype, source string) bool {
	if !fstypeAllowed(fstype) {
		return false
	}
	if fstype == "tmpfs" {
		return source == "tmpfs"
	}
	return blockSourcePathOK(source)
}

func resolvBody(servers []string) (string, error) {
	if len(servers) == 0 || len(servers) > resolvMax {
		return "", fmt.Errorf("nameserver rejected")
	}
	var b strings.Builder
	for _, server := range servers {
		if server == "" || strings.ContainsAny(server, " \t\r\n\x00") {
			return "", fmt.Errorf("nameserver rejected")
		}
		ip := net.ParseIP(server)
		if ip == nil {
			return "", fmt.Errorf("nameserver rejected")
		}
		b.WriteString("nameserver ")
		b.WriteString(ip.String())
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func ifaceGranted(allow []string, name string) error {
	if len(allow) == 0 || !ifaceNameRE.MatchString(name) || !exactGrant(allow, name) {
		return fmt.Errorf("interface not allowed")
	}
	return nil
}

func readLimited(r io.Reader, max int) ([]byte, error) {
	if max < 0 {
		return nil, fmt.Errorf("invalid limit")
	}
	buf, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(buf) > max {
		return nil, fmt.Errorf("body exceeds cap")
	}
	return buf, nil
}

func capText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func inspectManifest(yamlStr string) (kind, name, namespace string, err error) {
	if len(yamlStr) == 0 || len(yamlStr) > manifestCap {
		return "", "", "", fmt.Errorf("manifest rejected")
	}
	dec := yaml.NewDecoder(strings.NewReader(yamlStr))
	var doc interface{}
	if err := dec.Decode(&doc); err != nil {
		return "", "", "", fmt.Errorf("manifest rejected")
	}
	var extra interface{}
	if err := dec.Decode(&extra); err != io.EOF {
		return "", "", "", fmt.Errorf("multiple documents rejected")
	}
	root, ok := doc.(map[string]interface{})
	if !ok {
		return "", "", "", fmt.Errorf("manifest rejected")
	}
	if manifestUnsafe(doc, 0) {
		return "", "", "", fmt.Errorf("manifest denied")
	}
	kind, _ = root["kind"].(string)
	api, _ := root["apiVersion"].(string)
	switch kind {
	case "Pod", "Service", "ConfigMap":
		if api != "v1" {
			return "", "", "", fmt.Errorf("kind not allowed")
		}
	case "Deployment":
		if api != "apps/v1" {
			return "", "", "", fmt.Errorf("kind not allowed")
		}
	default:
		return "", "", "", fmt.Errorf("kind not allowed")
	}
	meta, _ := root["metadata"].(map[string]interface{})
	if meta == nil {
		return "", "", "", fmt.Errorf("manifest rejected")
	}
	name, _ = meta["name"].(string)
	if !dns1123Name(name) {
		return "", "", "", fmt.Errorf("name not allowed")
	}
	namespace = "default"
	if raw, exists := meta["namespace"]; exists {
		ns, ok := raw.(string)
		if !ok || !isValidNamespace(ns) {
			return "", "", "", fmt.Errorf("namespace not allowed")
		}
		namespace = ns
	}
	if !isValidNamespace(namespace) {
		return "", "", "", fmt.Errorf("namespace not allowed")
	}
	return kind, name, namespace, nil
}

func manifestUnsafe(v interface{}, depth int) bool {
	if depth > manifestDepthMax {
		return true
	}
	switch val := v.(type) {
	case map[string]interface{}:
		for key, child := range val {
			switch key {
			case "privileged", "hostNetwork", "hostPID":
				if manifestTruthy(child) {
					return true
				}
			case "hostPath":
				return true
			}
			if manifestUnsafe(child, depth+1) {
				return true
			}
		}
	case map[interface{}]interface{}:
		for key, child := range val {
			name := fmt.Sprint(key)
			switch name {
			case "privileged", "hostNetwork", "hostPID":
				if manifestTruthy(child) {
					return true
				}
			case "hostPath":
				return true
			}
			if manifestUnsafe(child, depth+1) {
				return true
			}
		}
	case []interface{}:
		for _, child := range val {
			if manifestUnsafe(child, depth+1) {
				return true
			}
		}
	}
	return false
}

func manifestTruthy(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "True"
	case int:
		return t != 0
	case int64:
		return t != 0
	case uint64:
		return t != 0
	case float64:
		return t != 0
	default:
		return false
	}
}
