package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"go.starlark.net/starlark"
)

// --- sys.net.dns_lookup(host, type="A") ---
// Returns a list of strings (addresses, MX targets, TXT records, etc.)
func (engine *SysscriptEngine) netDNSLookup(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var host, rrType string
	if err := starlark.UnpackArgs("dns_lookup", args, kwargs, "host", &host, "type?", &rrType); err != nil {
		return starlark.None, err
	}
	if rrType == "" {
		rrType = "A"
	}

	results := []starlark.Value{}

	switch strings.ToUpper(rrType) {
	case "A", "AAAA":
		addrs, err := net.LookupHost(host)
		if err != nil {
			return starlark.None, fmt.Errorf("dns_lookup: %w", err)
		}
		for _, a := range addrs {
			ip := net.ParseIP(a)
			if ip == nil {
				continue
			}
			if strings.ToUpper(rrType) == "A" && ip.To4() != nil {
				results = append(results, starlark.String(a))
			} else if strings.ToUpper(rrType) == "AAAA" && ip.To4() == nil {
				results = append(results, starlark.String(a))
			}
		}
	case "MX":
		records, err := net.LookupMX(host)
		if err != nil {
			return starlark.None, fmt.Errorf("dns_lookup: %w", err)
		}
		for _, r := range records {
			results = append(results, starlark.String(fmt.Sprintf("%d %s", r.Pref, r.Host)))
		}
	case "NS":
		records, err := net.LookupNS(host)
		if err != nil {
			return starlark.None, fmt.Errorf("dns_lookup: %w", err)
		}
		for _, r := range records {
			results = append(results, starlark.String(r.Host))
		}
	case "TXT":
		records, err := net.LookupTXT(host)
		if err != nil {
			return starlark.None, fmt.Errorf("dns_lookup: %w", err)
		}
		for _, r := range records {
			results = append(results, starlark.String(r))
		}
	case "CNAME":
		cname, err := net.LookupCNAME(host)
		if err != nil {
			return starlark.None, fmt.Errorf("dns_lookup: %w", err)
		}
		results = append(results, starlark.String(cname))
	default:
		return starlark.None, fmt.Errorf("dns_lookup: unsupported type %q (supported: A, AAAA, MX, NS, TXT, CNAME)", rrType)
	}

	return starlark.NewList(results), nil
}

// --- sys.net.reverse_dns(ip) ---
// Returns list of PTR hostnames for the given IP.
func (engine *SysscriptEngine) netReverseDNS(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ip string
	if err := starlark.UnpackArgs("reverse_dns", args, kwargs, "ip", &ip); err != nil {
		return starlark.None, err
	}
	names, err := net.LookupAddr(ip)
	if err != nil {
		return starlark.None, fmt.Errorf("reverse_dns: %w", err)
	}
	results := make([]starlark.Value, len(names))
	for i, n := range names {
		results[i] = starlark.String(n)
	}
	return starlark.NewList(results), nil
}

// --- sys.net.port_check(host, port, timeout_ms=2000) ---
// Returns dict {open: bool, latency_ms: int, error: str}
func (engine *SysscriptEngine) netPortCheck(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var host string
	var port, timeoutMs int
	if err := starlark.UnpackArgs("port_check", args, kwargs, "host", &host, "port", &port, "timeout_ms?", &timeoutMs); err != nil {
		return starlark.None, err
	}
	if timeoutMs <= 0 {
		timeoutMs = 2000
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeoutMs)*time.Millisecond)
	latency := int(time.Since(start).Milliseconds())

	result := starlark.NewDict(3)
	if err != nil {
		result.SetKey(starlark.String("open"), starlark.False)
		result.SetKey(starlark.String("latency_ms"), starlark.MakeInt(latency))
		result.SetKey(starlark.String("error"), starlark.String(err.Error()))
	} else {
		conn.Close()
		result.SetKey(starlark.String("open"), starlark.True)
		result.SetKey(starlark.String("latency_ms"), starlark.MakeInt(latency))
		result.SetKey(starlark.String("error"), starlark.String(""))
	}
	return result, nil
}

// --- sys.proc.list() ---
// Returns list of dicts: {pid, name, status, cpu_percent, mem_percent, username, cmdline}
func (engine *SysscriptEngine) procList(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	procs, err := process.Processes()
	if err != nil {
		return starlark.None, fmt.Errorf("proc.list: %w", err)
	}

	results := make([]starlark.Value, 0, len(procs))
	for _, p := range procs {
		d, err := procToDict(p)
		if err != nil {
			continue // skip processes that vanished or lack permissions
		}
		results = append(results, d)
	}
	return starlark.NewList(results), nil
}

// --- sys.proc.get(pid) ---
// Returns dict for a single process, or None if not found.
func (engine *SysscriptEngine) procGet(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pid int
	if err := starlark.UnpackArgs("get", args, kwargs, "pid", &pid); err != nil {
		return starlark.None, err
	}
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return starlark.None, nil // not found -> None
	}
	return procToDict(p)
}

// --- sys.proc.find(name) ---
// Returns list of dicts for processes whose name contains the given string (case-insensitive).
func (engine *SysscriptEngine) procFind(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("find", args, kwargs, "name", &name); err != nil {
		return starlark.None, err
	}
	procs, err := process.Processes()
	if err != nil {
		return starlark.None, fmt.Errorf("proc.find: %w", err)
	}

	nameLower := strings.ToLower(name)
	results := []starlark.Value{}
	for _, p := range procs {
		n, err := p.Name()
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(n), nameLower) {
			if d, err := procToDict(p); err == nil {
				results = append(results, d)
			}
		}
	}
	return starlark.NewList(results), nil
}

// --- sys.proc.kill(pid, signal=15) ---
// Sends a signal to a process. Gated by AllowExec entitlement (reuses exec gate).
func (engine *SysscriptEngine) procKill(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if !engine.Entitlements.AllowExec {
		return starlark.None, fmt.Errorf("security exception: exec entitlement required for proc.kill")
	}
	var pid, sig int
	if err := starlark.UnpackArgs("kill", args, kwargs, "pid", &pid, "signal?", &sig); err != nil {
		return starlark.None, err
	}
	if sig == 0 {
		sig = 15 // SIGTERM
	}
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return starlark.None, fmt.Errorf("proc.kill: pid %d not found", pid)
	}
	if err := p.SendSignal(syscall.Signal(sig)); err != nil {
		return starlark.None, fmt.Errorf("proc.kill: %w", err)
	}
	return starlark.True, nil
}

// procToDict converts a gopsutil Process to a Starlark dict.
// Fields that require elevated permissions gracefully degrade to empty string / 0.
func procToDict(p *process.Process) (*starlark.Dict, error) {
	name, _ := p.Name()
	status, _ := p.Status()
	cpuPct, _ := p.CPUPercent()
	memPct, _ := p.MemoryPercent()
	username, _ := p.Username()
	cmdSlice, _ := p.CmdlineSlice()

	cmdline := make([]starlark.Value, len(cmdSlice))
	for i, c := range cmdSlice {
		cmdline[i] = starlark.String(c)
	}

	d := starlark.NewDict(7)
	d.SetKey(starlark.String("pid"), starlark.MakeInt(int(p.Pid)))
	d.SetKey(starlark.String("name"), starlark.String(name))
	d.SetKey(starlark.String("status"), starlark.String(strings.Join(status, ",")))
	d.SetKey(starlark.String("cpu_percent"), starlark.Float(cpuPct))
	d.SetKey(starlark.String("mem_percent"), starlark.Float(float64(memPct)))
	d.SetKey(starlark.String("username"), starlark.String(username))
	d.SetKey(starlark.String("cmdline"), starlark.NewList(cmdline))
	return d, nil
}
