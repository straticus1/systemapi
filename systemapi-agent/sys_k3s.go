package main

import "go.starlark.net/starlark"

func (engine *SysscriptEngine) k3sNodes(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k3s")
	return kubeNodes("k3s", client, allow, args, kwargs)
}

func (engine *SysscriptEngine) k3sPods(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k3s")
	return kubePods("k3s", client, allow, args, kwargs)
}

func (engine *SysscriptEngine) k3sApply(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k3s")
	return kubeApply(client, allow, args, kwargs)
}

func (engine *SysscriptEngine) k3sGet(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k3s")
	return kubeGet(client, allow, args, kwargs)
}

func (engine *SysscriptEngine) k3sList(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k3s")
	return kubeList(client, allow, args, kwargs)
}

func (engine *SysscriptEngine) k3sLogs(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k3s")
	return kubeLogs(client, allow, args, kwargs)
}

func (engine *SysscriptEngine) k3sExec(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k3s")
	return kubeExec(client, allow, args, kwargs)
}

func (engine *SysscriptEngine) k3sDelete(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k3s")
	return kubeDelete(client, allow, args, kwargs)
}
