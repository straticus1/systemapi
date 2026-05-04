package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// Entitlements define what the current script is permitted to do
type Entitlements struct {
	AllowFSWrite       []string `json:"allow_fs_write"`
	AllowFSRead        []string `json:"allow_fs_read"`
	AllowNetOutbound   []string `json:"allow_net_outbound"`
	AllowExec          bool     `json:"allow_exec"`
	AllowConfigWrite   []string `json:"allow_config_write"`   // paths allowed for atomic config writes
	AllowServiceReload []string `json:"allow_service_reload"` // service names allowed to reload
}

// SysscriptEngine wraps the Starlark execution
type SysscriptEngine struct {
	Entitlements *Entitlements
	cm           *ConfigManager
}

func NewSysscriptEngine(perms *Entitlements) *SysscriptEngine {
	if perms == nil {
		perms = &Entitlements{} // default deny all
	}
	return &SysscriptEngine{Entitlements: perms, cm: &ConfigManager{}}
}

// Execute runs a snippet of Starlark code to completion and returns its printed output and return value
func (engine *SysscriptEngine) Execute(scriptSource string) (string, error) {
	var outBuffer bytes.Buffer

	thread := &starlark.Thread{
		Name:  "Sysscript",
		Print: func(_ *starlark.Thread, msg string) { outBuffer.WriteString(msg + "\n") },
	}

	// Build the builtins based on entitlements
	sysModule := engine.buildSysModule()

	predeclared := starlark.StringDict{
		"sys": sysModule,
	}

	_, err := starlark.ExecFile(thread, "sysscript.star", scriptSource, predeclared)
	if err != nil {
		return outBuffer.String(), err
	}

	return outBuffer.String(), nil
}

// buildSysModule assembles the `sys` object with nested `sys.fs`, `sys.net`, etc.
func (engine *SysscriptEngine) buildSysModule() *starlarkstruct.Struct {

	// sys.net
	sysNet := starlark.StringDict{
		"http_get":    starlark.NewBuiltin("http_get", engine.netHTTPGet),
		"dns_lookup":  starlark.NewBuiltin("dns_lookup", engine.netDNSLookup),
		"reverse_dns": starlark.NewBuiltin("reverse_dns", engine.netReverseDNS),
		"port_check":  starlark.NewBuiltin("port_check", engine.netPortCheck),
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
	}

	// Advanced Modules (Stubs)
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
	}
	sysContainers := starlark.StringDict{
		"run": starlark.NewBuiltin("run", engine.containersRun),
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
		"parse":        starlark.NewBuiltin("parse", engine.jsonParse),
		"encode":       starlark.NewBuiltin("encode", engine.jsonEncode),
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
		"list":  starlark.NewBuiltin("list", engine.procList),
		"get":   starlark.NewBuiltin("get", engine.procGet),
		"find":  starlark.NewBuiltin("find", engine.procFind),
		"kill":  starlark.NewBuiltin("kill", engine.procKill),
	}

	sysDict := starlark.StringDict{
		"net":        starlarkstruct.FromStringDict(starlark.String("net"), sysNet),
		"exec":       starlarkstruct.FromStringDict(starlark.String("exec"), sysExec),
		"fs":         starlarkstruct.FromStringDict(starlark.String("fs"), sysFS),
		"alerts":     starlarkstruct.FromStringDict(starlark.String("alerts"), sysAlerts),
		"security":   starlarkstruct.FromStringDict(starlark.String("security"), sysSecurity),
		"events":     starlarkstruct.FromStringDict(starlark.String("events"), sysEvents),
		"packages":   starlarkstruct.FromStringDict(starlark.String("packages"), sysPackages),
		"containers": starlarkstruct.FromStringDict(starlark.String("containers"), sysContainers),
		"config":     starlarkstruct.FromStringDict(starlark.String("config"), sysConfig),
		"yaml":       starlarkstruct.FromStringDict(starlark.String("yaml"), sysYAML),
		"proc":     starlarkstruct.FromStringDict(starlark.String("proc"), sysProc),
		"json":     starlarkstruct.FromStringDict(starlark.String("json"), sysJSON),
		"ini":      starlarkstruct.FromStringDict(starlark.String("ini"), sysINI),
		"services": starlarkstruct.FromStringDict(starlark.String("services"), sysSvc),
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
		strArg, ok := args.Index(i).(starlark.String)
		if ok {
			cmdArgs = append(cmdArgs, string(strArg))
		}
	}

	cmd := exec.Command(string(cmdStr), cmdArgs...)
	out, err := cmd.CombinedOutput()
	
	resultDict := starlark.NewDict(0)
	
	if err != nil {
		resultDict.SetKey(starlark.String("error"), starlark.String(err.Error()))
	} else {
		resultDict.SetKey(starlark.String("error"), starlark.None)
	}
	
	resultDict.SetKey(starlark.String("output"), starlark.String(string(out)))
	
	return resultDict, nil
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

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(reqUrl)
	if err != nil {
		return starlark.None, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	
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

	allowed := false
	for _, prefix := range engine.Entitlements.AllowFSRead {
		if prefix == "*" || strings.HasPrefix(path, prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return starlark.None, fmt.Errorf("security exception: read to %s not granted", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(string(data)), nil
}

// sys.fs.write(path, content)
func (engine *SysscriptEngine) fsWrite(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, content string
	if err := starlark.UnpackArgs("write", args, kwargs, "path", &path, "content", &content); err != nil {
		return starlark.None, err
	}

	allowed := false
	for _, prefix := range engine.Entitlements.AllowFSWrite {
		if prefix == "*" || strings.HasPrefix(path, prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return starlark.None, fmt.Errorf("security exception: write to %s not granted", path)
	}

	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		return starlark.None, err
	}
	return starlark.True, nil
}
