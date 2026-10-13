package main

import (
	"fmt"
	"log"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// containersList implements sys.containers.list().
// Returns a Starlark list of container structs. On Docker unavailability, logs and returns empty list (D-02).
func (engine *SysscriptEngine) containersList(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	containers, err := engine.dockerClient.ListContainers()
	if err != nil {
		log.Printf("[sys.containers.list] Docker unavailable: %v", err)
		return starlark.NewList(nil), nil // D-02: return empty list, not error
	}

	items := make([]starlark.Value, 0, len(containers))
	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		s := starlarkstruct.FromStringDict(starlark.String("container"), starlark.StringDict{
			"id":    starlark.String(c.Id),
			"name":  starlark.String(name),
			"image": starlark.String(c.Image),
			"state": starlark.String(c.State),
		})
		items = append(items, s)
	}
	return starlark.NewList(items), nil
}

// containersStats implements sys.containers.stats(id).
// Returns a stats struct or None on error.
func (engine *SysscriptEngine) containersStats(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs("stats", args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}

	stats, err := engine.dockerClient.GetContainerStats(id)
	if err != nil {
		log.Printf("[sys.containers.stats] error for %q: %v", id, err)
		return starlark.None, nil
	}

	s := starlarkstruct.FromStringDict(starlark.String("stats"), starlark.StringDict{
		"id":              starlark.String(stats.Id),
		"name":            starlark.String(stats.Name),
		"image":           starlark.String(stats.Image),
		"state":           starlark.String(stats.State),
		"cpu_pct":         starlark.Float(stats.CpuPct),
		"mem_used_bytes":  starlark.MakeUint64(stats.MemUsedBytes),
		"mem_limit_bytes": starlark.MakeUint64(stats.MemLimitBytes),
		"mem_pct":         starlark.Float(stats.MemPct),
		"rx_bytes":        starlark.MakeUint64(stats.RxBytes),
		"tx_bytes":        starlark.MakeUint64(stats.TxBytes),
	})
	return s, nil
}

// containersStop implements sys.containers.stop(id).
func (engine *SysscriptEngine) containersStop(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs("stop", args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}
	return containerActionResult(engine.dockerClient.StopContainer(id))
}

// containersStart implements sys.containers.start(id).
func (engine *SysscriptEngine) containersStart(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs("start", args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}
	return containerActionResult(engine.dockerClient.StartContainer(id))
}

// containersRestart implements sys.containers.restart(id).
func (engine *SysscriptEngine) containersRestart(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs("restart", args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}
	return containerActionResult(engine.dockerClient.RestartContainer(id))
}

// containerActionResult builds a {success, error} dict following the sys_config.go pattern.
func containerActionResult(err error) (starlark.Value, error) {
	result := starlark.NewDict(2)
	if err != nil {
		result.SetKey(starlark.String("success"), starlark.False)
		result.SetKey(starlark.String("error"), starlark.String(fmt.Sprintf("%v", err)))
	} else {
		result.SetKey(starlark.String("success"), starlark.True)
		result.SetKey(starlark.String("error"), starlark.String(""))
	}
	return result, nil
}

func (engine *SysscriptEngine) containersInspect(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs("inspect", args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}
	if !isValidContainerID(id) {
		return starlark.None, fmt.Errorf("invalid container id")
	}
	if engine.dockerClient == nil {
		return starlark.None, fmt.Errorf("docker client not initialized")
	}
	info, err := engine.dockerClient.Inspect(id)
	if err != nil {
		return starlark.None, err
	}
	return starlarkDict(info)
}

func (engine *SysscriptEngine) containersLogs(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs("logs", args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}
	if !isValidContainerID(id) {
		return starlark.None, fmt.Errorf("invalid container id")
	}
	if engine.dockerClient == nil {
		return starlark.None, fmt.Errorf("docker client not initialized")
	}
	text, err := engine.dockerClient.Logs(id)
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(text), nil
}

func (engine *SysscriptEngine) containersRun(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var image string
	var cmd *starlark.List
	if err := starlark.UnpackArgs("run", args, kwargs, "image", &image, "cmd?", &cmd); err != nil {
		return starlark.None, err
	}
	if !imageAllowed(image) || !exactGrant(engine.Entitlements.AllowImages, image) {
		return starlark.None, fmt.Errorf("image not allowed")
	}
	argv, err := listStrings(cmd)
	if err != nil {
		return starlark.None, err
	}
	if len(argv) > 0 {
		if err := validateArgv(argv); err != nil {
			return starlark.None, err
		}
	}
	if engine.dockerClient == nil {
		return starlark.None, fmt.Errorf("docker client not initialized")
	}
	id, err := engine.dockerClient.Run(image, argv)
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(id), nil
}

func (engine *SysscriptEngine) containersExec(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	var cmd *starlark.List
	if err := starlark.UnpackArgs("exec", args, kwargs, "id", &id, "cmd", &cmd); err != nil {
		return starlark.None, err
	}
	if !isValidContainerID(id) {
		return starlark.None, fmt.Errorf("invalid container id")
	}
	if cmd == nil {
		return starlark.None, fmt.Errorf("command required")
	}
	argv, err := listStrings(cmd)
	if err != nil {
		return starlark.None, err
	}
	if len(argv) == 0 {
		return starlark.None, fmt.Errorf("command required")
	}
	if err := validateArgv(argv); err != nil {
		return starlark.None, err
	}
	if engine.dockerClient == nil {
		return starlark.None, fmt.Errorf("docker client not initialized")
	}
	text, err := engine.dockerClient.Exec(id, argv)
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(text), nil
}
