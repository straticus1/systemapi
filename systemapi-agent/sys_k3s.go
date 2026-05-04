package main

import (
	"fmt"
	"log"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// k3sNodes implements sys.k3s.nodes().
// Returns a Starlark list of node structs. On k3s unavailability, logs and returns empty list (D-05).
func (engine *SysscriptEngine) k3sNodes(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("nodes", args, kwargs); err != nil {
		return starlark.None, err
	}

	if engine.k3sClient == nil {
		log.Printf("[sys.k3s.nodes] k3s client not initialized")
		return starlark.NewList(nil), nil // D-05: return empty list
	}

	nodes, err := engine.k3sClient.ListNodes()
	if err != nil {
		log.Printf("[sys.k3s.nodes] k3s unavailable: %v", err)
		return starlark.NewList(nil), nil // D-05: return empty list, not error
	}

	items := make([]starlark.Value, 0, len(nodes))
	for _, n := range nodes {
		// Derive role from labels
		role := "worker"
		for label := range n.Metadata.Labels {
			if label == "node-role.kubernetes.io/master" || label == "node-role.kubernetes.io/control-plane" {
				role = "master"
				break
			}
		}

		// Derive status from Ready condition
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

// k3sPods implements sys.k3s.pods(namespace="").
// Returns a Starlark list of pod structs. On k3s unavailability, logs and returns empty list (D-05).
func (engine *SysscriptEngine) k3sPods(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var namespace string
	if err := starlark.UnpackArgs("pods", args, kwargs, "namespace?", &namespace); err != nil {
		return starlark.None, err
	}

	if engine.k3sClient == nil {
		log.Printf("[sys.k3s.pods] k3s client not initialized")
		return starlark.NewList(nil), nil // D-05: return empty list
	}

	pods, err := engine.k3sClient.ListPods(namespace)
	if err != nil {
		log.Printf("[sys.k3s.pods] k3s unavailable: %v", err)
		return starlark.NewList(nil), nil // D-05: return empty list, not error
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

// k3sApply implements sys.k3s.apply(yaml_str).
// Returns a {success, error} dict following the sys_config.go pattern.
func (engine *SysscriptEngine) k3sApply(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var yamlStr string
	if err := starlark.UnpackArgs("apply", args, kwargs, "yaml_str", &yamlStr); err != nil {
		return starlark.None, err
	}

	applyErr := func(msg string) starlark.Value {
		result := starlark.NewDict(2)
		result.SetKey(starlark.String("success"), starlark.False)
		result.SetKey(starlark.String("error"), starlark.String(msg))
		return result
	}

	if engine.k3sClient == nil {
		return applyErr("k3s client not initialized"), nil
	}

	err := engine.k3sClient.Apply(yamlStr)
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
