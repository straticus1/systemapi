package main

import (
	"fmt"
	"log"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// Threats: namespace and manifest policy run before any API call. An empty
// namespace cannot list every pod. Privileged, hostPath, hostNetwork, and
// hostPID manifests are refused. Secrets are not an allowed kind. Apply and
// delete report policy failure in the result dict. get, list, logs, and exec
// return a Starlark error. API-down for an allowed list returns an empty list.
// Cap and policy errors do not.

func (engine *SysscriptEngine) kubePair(label string) (*K3sClient, []string) {
	if engine == nil || engine.Entitlements == nil {
		return nil, nil
	}
	if label == "k8s" {
		return engine.k8sClient, engine.Entitlements.AllowK8sNamespaces
	}
	return engine.k3sClient, engine.Entitlements.AllowK3sNamespaces
}

func (engine *SysscriptEngine) kubeModule(label string) starlark.Value {
	nodes := engine.k3sNodes
	pods := engine.k3sPods
	apply := engine.k3sApply
	get := engine.k3sGet
	list := engine.k3sList
	logs := engine.k3sLogs
	execFn := engine.k3sExec
	del := engine.k3sDelete
	if label == "k8s" {
		nodes = engine.k8sNodes
		pods = engine.k8sPods
		apply = engine.k8sApply
		get = engine.k8sGet
		list = engine.k8sList
		logs = engine.k8sLogs
		execFn = engine.k8sExec
		del = engine.k8sDelete
	}
	return starlarkstruct.FromStringDict(starlark.String(label), starlark.StringDict{
		"nodes":  starlark.NewBuiltin("nodes", nodes),
		"pods":   starlark.NewBuiltin("pods", pods),
		"apply":  starlark.NewBuiltin("apply", apply),
		"get":    starlark.NewBuiltin("get", get),
		"list":   starlark.NewBuiltin("list", list),
		"logs":   starlark.NewBuiltin("logs", logs),
		"exec":   starlark.NewBuiltin("exec", execFn),
		"delete": starlark.NewBuiltin("delete", del),
	})
}

func (engine *SysscriptEngine) k8sNodes(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k8s")
	return kubeNodes("k8s", client, allow, args, kwargs)
}

func (engine *SysscriptEngine) k8sPods(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k8s")
	return kubePods("k8s", client, allow, args, kwargs)
}

func (engine *SysscriptEngine) k8sApply(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k8s")
	return kubeApply(client, allow, args, kwargs)
}

func (engine *SysscriptEngine) k8sGet(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k8s")
	return kubeGet(client, allow, args, kwargs)
}

func (engine *SysscriptEngine) k8sList(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k8s")
	return kubeList(client, allow, args, kwargs)
}

func (engine *SysscriptEngine) k8sLogs(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k8s")
	return kubeLogs(client, allow, args, kwargs)
}

func (engine *SysscriptEngine) k8sExec(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k8s")
	return kubeExec(client, allow, args, kwargs)
}

func (engine *SysscriptEngine) k8sDelete(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	client, allow := engine.kubePair("k8s")
	return kubeDelete(client, allow, args, kwargs)
}

func kubeNS(allow []string, namespace string) error {
	if namespace == "" {
		return fmt.Errorf("namespace required")
	}
	if !isValidNamespace(namespace) || !exactGrant(allow, namespace) {
		return fmt.Errorf("namespace not allowed")
	}
	return nil
}

func kubeResult(ok bool, msg string) (starlark.Value, error) {
	result := starlark.NewDict(2)
	success := starlark.False
	if ok {
		success = starlark.True
	}
	if err := result.SetKey(starlark.String("success"), success); err != nil {
		return starlark.None, err
	}
	if err := result.SetKey(starlark.String("error"), starlark.String(msg)); err != nil {
		return starlark.None, err
	}
	return result, nil
}

func kubeListFailClosed(err error) bool {
	msg := err.Error()
	for _, phrase := range []string{
		"too many items",
		"body exceeds cap",
		"namespace required",
		"invalid namespace",
		"kind not allowed",
		"namespace not allowed",
		"name not allowed",
	} {
		if strings.Contains(msg, phrase) {
			return true
		}
	}
	return false
}

func kubeNodes(label string, client *K3sClient, _ []string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("nodes", args, kwargs); err != nil {
		return starlark.None, err
	}
	if client == nil {
		log.Printf("[sys.%s.nodes] client not initialized", label)
		return starlark.NewList(nil), nil
	}
	nodes, err := client.ListNodes()
	if err != nil {
		log.Printf("[sys.%s.nodes] unavailable: %v", label, err)
		return starlark.NewList(nil), nil
	}
	items := make([]starlark.Value, 0, len(nodes))
	for _, n := range nodes {
		role := "worker"
		for labelName := range n.Metadata.Labels {
			if labelName == "node-role.kubernetes.io/master" || labelName == "node-role.kubernetes.io/control-plane" {
				role = "master"
				break
			}
		}
		status := "NotReady"
		for _, cond := range n.Status.Conditions {
			if cond.Type == "Ready" && cond.Status == "True" {
				status = "Ready"
				break
			}
		}
		s := starlarkstruct.FromStringDict(starlark.String("node"), starlark.StringDict{
			"name":    starlark.String(n.Metadata.Name),
			"role":    starlark.String(role),
			"status":  starlark.String(status),
			"version": starlark.String(n.Status.NodeInfo.KubeletVersion),
		})
		items = append(items, s)
	}
	return starlark.NewList(items), nil
}

func kubePods(label string, client *K3sClient, allow []string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var namespace string
	if err := starlark.UnpackArgs("pods", args, kwargs, "namespace?", &namespace); err != nil {
		return starlark.None, err
	}
	if err := kubeNS(allow, namespace); err != nil {
		return starlark.None, err
	}
	if client == nil {
		log.Printf("[sys.%s.pods] client not initialized", label)
		return starlark.NewList(nil), nil
	}
	pods, err := client.ListPods(namespace)
	if err != nil {
		log.Printf("[sys.%s.pods] unavailable: %v", label, err)
		return starlark.NewList(nil), nil
	}
	items := make([]starlark.Value, 0, len(pods))
	for _, p := range pods {
		s := starlarkstruct.FromStringDict(starlark.String("pod"), starlark.StringDict{
			"name":      starlark.String(p.Metadata.Name),
			"namespace": starlark.String(p.Metadata.Namespace),
			"status":    starlark.String(p.Status.Phase),
		})
		items = append(items, s)
	}
	return starlark.NewList(items), nil
}

func kubeApply(client *K3sClient, allow []string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var yamlStr string
	if err := starlark.UnpackArgs("apply", args, kwargs, "yaml_str", &yamlStr); err != nil {
		return starlark.None, err
	}
	_, _, namespace, err := inspectManifest(yamlStr)
	if err != nil {
		return kubeResult(false, err.Error())
	}
	if err := kubeNS(allow, namespace); err != nil {
		return kubeResult(false, err.Error())
	}
	if client == nil {
		return kubeResult(false, "kube client not initialized")
	}
	if err := client.Apply(yamlStr); err != nil {
		return kubeResult(false, err.Error())
	}
	return kubeResult(true, "")
}

func kubeGet(client *K3sClient, allow []string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kind, name, namespace string
	if err := starlark.UnpackArgs("get", args, kwargs, "kind", &kind, "name", &name, "namespace", &namespace); err != nil {
		return starlark.None, err
	}
	if _, err := kubeAPI(kind); err != nil {
		return starlark.None, err
	}
	if err := kubeNS(allow, namespace); err != nil {
		return starlark.None, err
	}
	if !dns1123Name(name) {
		return starlark.None, fmt.Errorf("name not allowed")
	}
	if client == nil {
		return starlark.None, fmt.Errorf("kube client not initialized")
	}
	info, err := client.GetResource(kind, name, namespace)
	if err != nil {
		return starlark.None, err
	}
	return starlarkDict(info)
}

func kubeList(client *K3sClient, allow []string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kind, namespace string
	if err := starlark.UnpackArgs("list", args, kwargs, "kind", &kind, "namespace", &namespace); err != nil {
		return starlark.None, err
	}
	if _, err := kubeAPI(kind); err != nil {
		return starlark.None, err
	}
	if err := kubeNS(allow, namespace); err != nil {
		return starlark.None, err
	}
	if client == nil {
		return starlark.NewList(nil), nil
	}
	items, err := client.ListResource(kind, namespace)
	if err != nil {
		if kubeListFailClosed(err) {
			return starlark.None, err
		}
		log.Printf("[sys.kube.list] unavailable: %v", err)
		return starlark.NewList(nil), nil
	}
	return starlarkDictList(items)
}

func kubeLogs(client *K3sClient, allow []string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, namespace, container string
	if err := starlark.UnpackArgs("logs", args, kwargs, "name", &name, "namespace", &namespace, "container?", &container); err != nil {
		return starlark.None, err
	}
	if err := kubeNS(allow, namespace); err != nil {
		return starlark.None, err
	}
	if !dns1123Name(name) || (container != "" && !dns1123Name(container)) {
		return starlark.None, fmt.Errorf("name not allowed")
	}
	if client == nil {
		return starlark.None, fmt.Errorf("kube client not initialized")
	}
	text, err := client.PodLogs(namespace, name, container)
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(text), nil
}

func kubeExec(client *K3sClient, allow []string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, namespace string
	var cmd *starlark.List
	if err := starlark.UnpackArgs("exec", args, kwargs, "name", &name, "namespace", &namespace, "cmd", &cmd); err != nil {
		return starlark.None, err
	}
	if err := kubeNS(allow, namespace); err != nil {
		return starlark.None, err
	}
	if !dns1123Name(name) {
		return starlark.None, fmt.Errorf("name not allowed")
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
	if client == nil {
		return starlark.None, fmt.Errorf("kube client not initialized")
	}
	text, err := client.PodExec(namespace, name, argv)
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(text), nil
}

func kubeDelete(client *K3sClient, allow []string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var kind, name, namespace string
	if err := starlark.UnpackArgs("delete", args, kwargs, "kind", &kind, "name", &name, "namespace", &namespace); err != nil {
		return starlark.None, err
	}
	if _, err := kubeAPI(kind); err != nil {
		return kubeResult(false, err.Error())
	}
	if err := kubeNS(allow, namespace); err != nil {
		return kubeResult(false, err.Error())
	}
	if !dns1123Name(name) {
		return kubeResult(false, "name not allowed")
	}
	if client == nil {
		return kubeResult(false, "kube client not initialized")
	}
	if err := client.DeleteResource(kind, name, namespace); err != nil {
		return kubeResult(false, err.Error())
	}
	return kubeResult(true, "")
}
