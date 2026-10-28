package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// A script runs under one context (SysscriptEngine.ctx) that carries its
// whole-script deadline and its cancel. Every blocking builtin derives from
// it, so a long operation (package install, image pull, compose) may use the
// rest of the script's time and no more; there is no per-operation timeout.

// scriptOutputMax caps the printed output a script keeps; the rest is
// dropped and the result says output_truncated.
const scriptOutputMax = 1 << 20

var (
	// errScriptTimedOut ends a script whose deadline passed.
	errScriptTimedOut = errors.New("timed_out")
	// errScriptCancelled ends a script whose context was cancelled.
	errScriptCancelled = errors.New("cancelled")
)

// jobCtxReason says why ctx ended, for builtin error text.
func jobCtxReason(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "timed out (script deadline)"
	}
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return "cancelled (" + cause.Error() + ")"
	}
	return "cancelled"
}

// scriptCtxErr is the script error once ctx has ended.
func scriptCtxErr(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: script deadline exceeded", errScriptTimedOut)
	}
	if cause := context.Cause(ctx); cause != nil && !errors.Is(cause, context.Canceled) {
		return fmt.Errorf("%w: %s", errScriptCancelled, cause.Error())
	}
	return errScriptCancelled
}

// Entitlements define what the current script is permitted to do
type Entitlements struct {
	AllowFSWrite       []string `json:"allow_fs_write"`
	AllowFSRead        []string `json:"allow_fs_read"`
	AllowNetOutbound   []string `json:"allow_net_outbound"`
	AllowExec          bool     `json:"allow_exec"`
	AllowConfigWrite   []string `json:"allow_config_write"`   // paths allowed for atomic config writes
	AllowServiceReload []string `json:"allow_service_reload"` // service names allowed to reload
	AllowContainers    bool     `json:"allow_containers"`
	AllowK3s           bool     `json:"allow_k3s"`
	AllowLinux         bool     `json:"allow_linux"`
	AllowK8s           bool     `json:"allow_k8s"`
	AllowPackages      []string `json:"allow_packages"`
	AllowImages        []string `json:"allow_images"`
	AllowK3sNamespaces []string `json:"allow_k3s_namespaces"`
	AllowK8sNamespaces []string `json:"allow_k8s_namespaces"`
	AllowNetManage     []string `json:"allow_net_manage"`
	AllowMountTargets  []string `json:"allow_mount_targets"`
	AllowSysctl        []string `json:"allow_sysctl"`
}

// UnmarshalJSON accepts the control plane's clamped entitlement object.
// A JSON boolean for a path list grants no paths. It does not mean allow-all.
// AllowExec, AllowContainers, and AllowK3s stay booleans and fail closed
// when the value is not a boolean. A JSON boolean for a new list grants
// nothing. "*" is dropped. Hard-denied sysctls are dropped even if named.
func (e *Entitlements) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	e.AllowFSWrite = entitlementPaths(raw["allow_fs_write"])
	e.AllowFSRead = entitlementPaths(raw["allow_fs_read"])
	e.AllowNetOutbound = entitlementPaths(raw["allow_net_outbound"])
	e.AllowConfigWrite = entitlementPaths(raw["allow_config_write"])
	e.AllowServiceReload = entitlementPaths(raw["allow_service_reload"])
	e.AllowExec = entitlementBool(raw["allow_exec"])
	e.AllowContainers = entitlementBool(raw["allow_containers"])
	e.AllowK3s = entitlementBool(raw["allow_k3s"])
	e.AllowLinux = entitlementBool(raw["allow_linux"])
	e.AllowK8s = entitlementBool(raw["allow_k8s"])
	e.AllowPackages = entitlementExactList(raw["allow_packages"])
	e.AllowImages = entitlementExactList(raw["allow_images"])
	e.AllowK3sNamespaces = entitlementExactList(raw["allow_k3s_namespaces"])
	e.AllowK8sNamespaces = entitlementExactList(raw["allow_k8s_namespaces"])
	e.AllowNetManage = entitlementExactList(raw["allow_net_manage"])
	e.AllowMountTargets = entitlementExactList(raw["allow_mount_targets"])
	e.AllowSysctl = dropDeniedSysctl(entitlementExactList(raw["allow_sysctl"]))
	return nil
}

func entitlementPaths(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var flag bool
	if err := json.Unmarshal(raw, &flag); err == nil {
		return nil
	}
	var paths []string
	if err := json.Unmarshal(raw, &paths); err != nil {
		return nil
	}
	return paths
}

func entitlementBool(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return false
	}
	var flag bool
	if err := json.Unmarshal(raw, &flag); err != nil {
		return false
	}
	return flag
}

// entitlementExactList keeps short exact strings. A JSON boolean, "*",
// "..", and control characters grant nothing.
func entitlementExactList(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var flag bool
	if err := json.Unmarshal(raw, &flag); err == nil {
		return nil
	}
	var items []string
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if !exactItemOK(item) {
			continue
		}
		out = append(out, item)
		if len(out) >= listCap {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SysscriptEngine wraps the Starlark execution
type SysscriptEngine struct {
	// ctx is the script's context: its deadline and cancel. Execute refuses
	// to run without one.
	ctx          context.Context
	Entitlements *Entitlements
	cm           *ConfigManager
	dockerClient *DockerClient
	k3sClient    *K3sClient
	k8sClient    *K3sClient
	alerts       *alertSink // sys.alerts.push delivery; nil means not connected
	// outputTruncated is set by Execute when printed output passed
	// scriptOutputMax.
	outputTruncated bool
}

func NewSysscriptEngine(ctx context.Context, perms *Entitlements) *SysscriptEngine {
	if perms == nil {
		perms = &Entitlements{} // default deny all
	}
	engine := &SysscriptEngine{ctx: ctx, Entitlements: perms, cm: &ConfigManager{}}
	if perms.AllowContainers {
		engine.dockerClient = NewDockerClient()
	}
	if perms.AllowK3s {
		var err error
		engine.k3sClient, err = NewK3sClient(ctx)
		if err != nil {
			log.Printf("[sysscript] k3s client init failed: %v", err)
		}
	}
	if perms.AllowK8s {
		var err error
		engine.k8sClient, err = NewK8sClient(ctx)
		if err != nil {
			log.Printf("[sysscript] k8s client init failed: %v", err)
		}
	}
	return engine
}

// sysscriptLoadBase is the only directory load() reads modules from. A var
// so tests can point it at a temp dir.
var sysscriptLoadBase = "/etc/systemapi/scripts"

// threadSet tracks a script's Starlark threads (the main one and every
// load() sub-thread) so a deadline or cancel reaches all of them. A thread
// added after cancellation is cancelled at once.
type threadSet struct {
	mu      sync.Mutex
	threads []*starlark.Thread
	reason  string
}

func (s *threadSet) add(t *starlark.Thread) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reason != "" {
		t.Cancel(s.reason)
	}
	s.threads = append(s.threads, t)
}

func (s *threadSet) cancelAll(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reason = reason
	for _, t := range s.threads {
		t.Cancel(reason)
	}
}

// Execute runs a snippet of Starlark code to completion and returns its
// printed output (capped at scriptOutputMax; see outputTruncated). When the
// engine's context ends, every thread is cancelled and the error wraps
// errScriptTimedOut or errScriptCancelled.
func (engine *SysscriptEngine) Execute(scriptSource string) (string, error) {
	ctx := engine.ctx
	if ctx == nil {
		return "", errors.New("sysscript: no script context")
	}
	if ctx.Err() != nil {
		return "", scriptCtxErr(ctx)
	}
	outBuffer := &capWriter{max: scriptOutputMax}
	threads := &threadSet{}
	stopWatch := context.AfterFunc(ctx, func() { threads.cancelAll(jobCtxReason(ctx)) })
	defer stopWatch()
	defer func() { engine.outputTruncated = outBuffer.truncated }()

	scriptsBase := sysscriptLoadBase
	cache := make(map[string]starlark.StringDict)
	var loadFn func(*starlark.Thread, string) (starlark.StringDict, error)
	loadFn = func(thread *starlark.Thread, module string) (starlark.StringDict, error) {
		if g, ok := cache[module]; ok {
			return g, nil
		}
		// T-03-01: path traversal protection
		resolved := filepath.Clean(filepath.Join(scriptsBase, module))
		if !strings.HasPrefix(resolved, scriptsBase+string(os.PathSeparator)) && resolved != scriptsBase {
			return nil, fmt.Errorf("load(%q): path traversal not allowed", module)
		}
		src, err := os.ReadFile(resolved)
		if err != nil {
			return nil, fmt.Errorf("load(%q): %w", module, err) // D-09: fail fast
		}
		mt := &starlark.Thread{Name: "load " + module, Load: loadFn} // Pitfall 5: sub-thread needs Load too
		threads.add(mt)
		g, err := starlark.ExecFile(mt, module, src, nil)
		if err != nil {
			return nil, err
		}
		cache[module] = g
		return g, nil
	}

	thread := &starlark.Thread{
		Name:  "Sysscript",
		Print: func(_ *starlark.Thread, msg string) { _, _ = outBuffer.Write([]byte(msg + "\n")) },
		Load:  loadFn,
	}
	threads.add(thread)

	sysModule := engine.buildSysModule()
	predeclared := starlark.StringDict{"sys": sysModule}
	_, err := starlark.ExecFile(thread, "sysscript.star", scriptSource, predeclared)
	if err != nil {
		if ctx.Err() != nil {
			return outBuffer.buf.String(), scriptCtxErr(ctx)
		}
		return outBuffer.buf.String(), err
	}
	return outBuffer.buf.String(), nil
}

// buildSysModule assembles the `sys` object with nested `sys.fs`, `sys.net`, etc.
func (engine *SysscriptEngine) buildSysModule() *starlarkstruct.Struct {

	// sys.net
	sysNet := starlark.StringDict{
		"http_get":    starlark.NewBuiltin("http_get", engine.netHTTPGet),
		"dns_lookup":  starlark.NewBuiltin("dns_lookup", engine.netDNSLookup),
		"reverse_dns": starlark.NewBuiltin("reverse_dns", engine.netReverseDNS),
		"port_check":  starlark.NewBuiltin("port_check", engine.netPortCheck),
		"links":       starlark.NewBuiltin("links", engine.netLinks),
		"addresses":   starlark.NewBuiltin("addresses", engine.netAddresses),
		"routes":      starlark.NewBuiltin("routes", engine.netRoutes),
		"set_address": starlark.NewBuiltin("set_address", engine.netSetAddress),
		"set_route":   starlark.NewBuiltin("set_route", engine.netSetRoute),
		"link_up":     starlark.NewBuiltin("link_up", engine.netLinkUp),
		"link_down":   starlark.NewBuiltin("link_down", engine.netLinkDown),
		"set_dns":     starlark.NewBuiltin("set_dns", engine.netSetDNS),
	}

	// sys.exec
	sysExec := starlark.StringDict{
		"run": starlark.NewBuiltin("run", engine.execRun),
	}

	// sys.fs
	sysFS := starlark.StringDict{
		"read":  starlark.NewBuiltin("read", engine.fsRead),
		"write": starlark.NewBuiltin("write", engine.fsWrite),
		"stat":  starlark.NewBuiltin("stat", engine.fsStat),
		"glob":  starlark.NewBuiltin("glob", engine.fsGlob),
		"mkdir": starlark.NewBuiltin("mkdir", engine.fsMkdir),
		"rm":    starlark.NewBuiltin("rm", engine.fsRm),
		"chmod": starlark.NewBuiltin("chmod", engine.fsChmod),
		"chown": starlark.NewBuiltin("chown", engine.fsChown),
		"diff":  starlark.NewBuiltin("diff", engine.fsDiff),
	}

	// sys.alerts forwards to the control plane; sys.security and sys.events fail as not implemented.
	sysAlerts := starlark.StringDict{
		"push": starlark.NewBuiltin("push", engine.alertsPush),
	}
	sysSecurity := starlark.StringDict{
		"yara_scan":   starlark.NewBuiltin("yara_scan", engine.securityYaraScan),
		"scan_memory": starlark.NewBuiltin("scan_memory", engine.securityScanMemory),
	}
	sysEvents := starlark.StringDict{
		"listen": starlark.NewBuiltin("listen", engine.eventsListen),
	}
	sysPackages := starlark.StringDict{
		"install": starlark.NewBuiltin("install", engine.packagesInstall),
		"remove":  starlark.NewBuiltin("remove", engine.packagesRemove),
		"upgrade": starlark.NewBuiltin("upgrade", engine.packagesUpgrade),
		"query":   starlark.NewBuiltin("query", engine.packagesQuery),
		"list":    starlark.NewBuiltin("list", engine.packagesList),
	}

	// sys.config
	sysConfig := starlark.StringDict{
		"write":    starlark.NewBuiltin("write", engine.configWrite),
		"template": starlark.NewBuiltin("template", engine.configTemplate),
		"validate": starlark.NewBuiltin("validate", engine.configValidate),
		"reload":   starlark.NewBuiltin("reload", engine.configReload),
		"backup":   starlark.NewBuiltin("backup", engine.configBackup),
		"restore":  starlark.NewBuiltin("restore", engine.configRestore),
	}

	// sys.yaml
	sysYAML := starlark.StringDict{
		"parse":  starlark.NewBuiltin("parse", engine.yamlParse),
		"encode": starlark.NewBuiltin("encode", engine.yamlEncode),
	}

	// sys.json
	sysJSON := starlark.StringDict{
		"parse":         starlark.NewBuiltin("parse", engine.jsonParse),
		"encode":        starlark.NewBuiltin("encode", engine.jsonEncode),
		"encode_pretty": starlark.NewBuiltin("encode_pretty", engine.jsonEncodePretty),
	}

	// sys.ini
	sysINI := starlark.StringDict{
		"parse":  starlark.NewBuiltin("parse", engine.iniParse),
		"encode": starlark.NewBuiltin("encode", engine.iniEncode),
		"get":    starlark.NewBuiltin("get", engine.iniGet),
	}

	// sys.services
	sysSvc := starlark.StringDict{
		"start":   starlark.NewBuiltin("start", engine.svcStart),
		"stop":    starlark.NewBuiltin("stop", engine.svcStop),
		"restart": starlark.NewBuiltin("restart", engine.svcRestart),
		"enable":  starlark.NewBuiltin("enable", engine.svcEnable),
		"disable": starlark.NewBuiltin("disable", engine.svcDisable),
		"status":  starlark.NewBuiltin("status", engine.svcStatus),
	}

	// sys.proc
	sysProc := starlark.StringDict{
		"list": starlark.NewBuiltin("list", engine.procList),
		"get":  starlark.NewBuiltin("get", engine.procGet),
		"find": starlark.NewBuiltin("find", engine.procFind),
		"kill": starlark.NewBuiltin("kill", engine.procKill),
	}

	sysDict := starlark.StringDict{
		"net":      starlarkstruct.FromStringDict(starlark.String("net"), sysNet),
		"exec":     starlarkstruct.FromStringDict(starlark.String("exec"), sysExec),
		"fs":       starlarkstruct.FromStringDict(starlark.String("fs"), sysFS),
		"alerts":   starlarkstruct.FromStringDict(starlark.String("alerts"), sysAlerts),
		"security": starlarkstruct.FromStringDict(starlark.String("security"), sysSecurity),
		"events":   starlarkstruct.FromStringDict(starlark.String("events"), sysEvents),
		"packages": starlarkstruct.FromStringDict(starlark.String("packages"), sysPackages),
		"config":   starlarkstruct.FromStringDict(starlark.String("config"), sysConfig),
		"yaml":     starlarkstruct.FromStringDict(starlark.String("yaml"), sysYAML),
		"proc":     starlarkstruct.FromStringDict(starlark.String("proc"), sysProc),
		"json":     starlarkstruct.FromStringDict(starlark.String("json"), sysJSON),
		"ini":      starlarkstruct.FromStringDict(starlark.String("ini"), sysINI),
		"services": starlarkstruct.FromStringDict(starlark.String("services"), sysSvc),
	}

	// D-11: containers namespace absent when not entitled
	if engine.Entitlements.AllowContainers {
		sysContainers := starlark.StringDict{
			"list":           starlark.NewBuiltin("list", engine.containersList),
			"stats":          starlark.NewBuiltin("stats", engine.containersStats),
			"stop":           starlark.NewBuiltin("stop", engine.containersStop),
			"start":          starlark.NewBuiltin("start", engine.containersStart),
			"restart":        starlark.NewBuiltin("restart", engine.containersRestart),
			"inspect":        starlark.NewBuiltin("inspect", engine.containersInspect),
			"logs":           starlark.NewBuiltin("logs", engine.containersLogs),
			"run":            starlark.NewBuiltin("run", engine.containersRun),
			"exec":           starlark.NewBuiltin("exec", engine.containersExec),
			"images":         starlark.NewBuiltin("images", engine.containersImages),
			"pull":           starlark.NewBuiltin("pull", engine.containersPull),
			"remove_image":   starlark.NewBuiltin("remove_image", engine.containersRemoveImage),
			"volumes":        starlark.NewBuiltin("volumes", engine.containersVolumes),
			"create_volume":  starlark.NewBuiltin("create_volume", engine.containersCreateVolume),
			"remove_volume":  starlark.NewBuiltin("remove_volume", engine.containersRemoveVolume),
			"networks":       starlark.NewBuiltin("networks", engine.containersNetworks),
			"create_network": starlark.NewBuiltin("create_network", engine.containersCreateNetwork),
			"remove_network": starlark.NewBuiltin("remove_network", engine.containersRemoveNetwork),
			"compose":        starlark.NewBuiltin("compose", engine.containersCompose),
		}
		sysDict["containers"] = starlarkstruct.FromStringDict(starlark.String("containers"), sysContainers)
	}

	// D-11: k3s namespace absent when not entitled
	if engine.Entitlements.AllowK3s {
		sysDict["k3s"] = engine.kubeModule("k3s")
	}
	if engine.Entitlements.AllowK8s {
		sysDict["k8s"] = engine.kubeModule("k8s")
	}
	if engine.Entitlements.AllowLinux && hostLinux() {
		sysDict["linux"] = starlarkstruct.FromStringDict(starlark.String("linux"), starlark.StringDict{
			"os_release": starlark.NewBuiltin("os_release", engine.linuxOSRelease),
			"uname":      starlark.NewBuiltin("uname", engine.linuxUname),
			"hostname":   starlark.NewBuiltin("hostname", engine.linuxHostname),
			"uptime":     starlark.NewBuiltin("uptime", engine.linuxUptime),
			"users":      starlark.NewBuiltin("users", engine.linuxUsers),
			"groups":     starlark.NewBuiltin("groups", engine.linuxGroups),
			"selinux":    starlark.NewBuiltin("selinux", engine.linuxSELinux),
			"apparmor":   starlark.NewBuiltin("apparmor", engine.linuxAppArmor),
		})
		sysDict["disk"] = starlarkstruct.FromStringDict(starlark.String("disk"), starlark.StringDict{
			"mounts":        starlark.NewBuiltin("mounts", engine.diskMounts),
			"usage":         starlark.NewBuiltin("usage", engine.diskUsage),
			"block_devices": starlark.NewBuiltin("block_devices", engine.diskBlockDevices),
			"mount":         starlark.NewBuiltin("mount", engine.diskMount),
			"umount":        starlark.NewBuiltin("umount", engine.diskUmount),
		})
		sysDict["procfs"] = starlarkstruct.FromStringDict(starlark.String("procfs"), starlark.StringDict{
			"read":       starlark.NewBuiltin("read", engine.procfsRead),
			"sysctl_get": starlark.NewBuiltin("sysctl_get", engine.procfsSysctlGet),
			"sysctl_set": starlark.NewBuiltin("sysctl_set", engine.procfsSysctlSet),
		})
	}

	return starlarkstruct.FromStringDict(starlark.String("sys"), sysDict)
}

// --- Starlark Builtin Implementations ---

// sys.exec.run(command, args...)
func (engine *SysscriptEngine) execRun(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if !engine.Entitlements.AllowExec {
		return starlark.None, fmt.Errorf("security exception: execution entitlement not granted")
	}

	if args.Len() < 1 {
		return starlark.None, fmt.Errorf("sys.exec.run requires at least one argument")
	}

	cmdStr, ok := args.Index(0).(starlark.String)
	if !ok {
		return starlark.None, fmt.Errorf("expected string for command")
	}

	var cmdArgs []string
	for i := 1; i < args.Len(); i++ {
		cmdArgs = expandExecArg(cmdArgs, args.Index(i))
	}

	cmd := jobCommand(engine.ctx, string(cmdStr), cmdArgs...)
	out := &capWriter{max: outputCap}
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	if engine.ctx.Err() != nil {
		err = fmt.Errorf("%s: %s", string(cmdStr), jobCtxReason(engine.ctx))
	}

	resultDict := starlark.NewDict(0)

	if err != nil {
		resultDict.SetKey(starlark.String("error"), starlark.String(err.Error()))
	} else {
		resultDict.SetKey(starlark.String("error"), starlark.None)
	}

	resultDict.SetKey(starlark.String("output"), starlark.String(out.buf.String()))
	resultDict.SetKey(starlark.String("truncated"), starlark.Bool(out.truncated))

	return resultDict, nil
}

// expandExecArg keeps positional strings and flattens a list or tuple of
// strings. Non-strings are ignored. This is how diagnostics pass argv.
func expandExecArg(dst []string, v starlark.Value) []string {
	switch x := v.(type) {
	case starlark.String:
		return append(dst, string(x))
	case *starlark.List:
		for i := 0; i < x.Len(); i++ {
			if s, ok := x.Index(i).(starlark.String); ok {
				dst = append(dst, string(s))
			}
		}
		return dst
	case starlark.Tuple:
		for i := 0; i < x.Len(); i++ {
			if s, ok := x.Index(i).(starlark.String); ok {
				dst = append(dst, string(s))
			}
		}
		return dst
	default:
		return dst
	}
}

// sys.net.http_get(url)
func (engine *SysscriptEngine) netHTTPGet(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var reqUrl string
	if err := starlark.UnpackArgs("http_get", args, kwargs, "url", &reqUrl); err != nil {
		return starlark.None, err
	}

	u, err := url.Parse(reqUrl)
	if err != nil {
		return starlark.None, fmt.Errorf("invalid url: %v", err)
	}

	allowed := false
	for _, domain := range engine.Entitlements.AllowNetOutbound {
		if domain == "*" || domain == u.Hostname() {
			allowed = true
			break
		}
	}
	if !allowed {
		return starlark.None, fmt.Errorf("security exception: outbound to %s not granted", u.Hostname())
	}

	req, err := http.NewRequestWithContext(engine.ctx, http.MethodGet, reqUrl, nil)
	if err != nil {
		return starlark.None, fmt.Errorf("invalid url: %v", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return starlark.None, err
	}
	defer resp.Body.Close()

	body, err := readLimited(resp.Body, hostFileCap)
	if err != nil {
		return starlark.None, fmt.Errorf("http_get: %w", err)
	}

	resultDict := starlark.NewDict(0)
	resultDict.SetKey(starlark.String("status_code"), starlark.MakeInt(resp.StatusCode))
	resultDict.SetKey(starlark.String("body"), starlark.String(string(body)))
	return resultDict, nil
}

// sys.fs.read(path)
func (engine *SysscriptEngine) fsRead(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs("read", args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}

	resolved, err := fsGrantPath(engine.Entitlements.AllowFSRead, path, "read", true)
	if err != nil {
		return starlark.None, err
	}

	data, err := readFileCapped(resolved, hostFileCap)
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(data), nil
}

// sys.fs.write(path, content)
func (engine *SysscriptEngine) fsWrite(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, content string
	if err := starlark.UnpackArgs("write", args, kwargs, "path", &path, "content", &content); err != nil {
		return starlark.None, err
	}

	root, resolved, err := fsGrantRootPath(engine.Entitlements.AllowFSWrite, path, "write", true)
	if err != nil {
		return starlark.None, err
	}

	err = writeBeneath(root, resolved, []byte(content), 0644)
	if err != nil {
		return starlark.None, err
	}
	return starlark.True, nil
}
