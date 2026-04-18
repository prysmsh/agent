package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// agentToolDef describes an available action tool.
type agentToolDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"input_schema"`
}

// agentToolRequest is the JSON body for POST /tools/execute.
type agentToolRequest struct {
	Tool      string                 `json:"tool"`
	Arguments map[string]interface{} `json:"arguments"`
	DryRun    bool                   `json:"dry_run"`
}

// agentToolResult is the JSON response from tool execution.
type agentToolResult struct {
	Tool    string      `json:"tool"`
	DryRun  bool        `json:"dry_run"`
	Success bool        `json:"success"`
	Result  interface{} `json:"result,omitempty"`
	Error   string      `json:"error,omitempty"`
}

var actionTools = []agentToolDef{
	{
		Name:        "scale_deployment",
		Description: "Scale a Kubernetes deployment to a specified number of replicas",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"namespace": map[string]interface{}{"type": "string", "description": "Kubernetes namespace (default: default)"},
				"name":      map[string]interface{}{"type": "string", "description": "deployment name"},
				"replicas":  map[string]interface{}{"type": "integer", "description": "desired replica count"},
			},
			"required": []string{"name", "replicas"},
		},
	},
	{
		Name:        "restart_pod",
		Description: "Restart (delete) a specific pod so it gets recreated by its controller",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"namespace": map[string]interface{}{"type": "string", "description": "Kubernetes namespace (default: default)"},
				"name":      map[string]interface{}{"type": "string", "description": "pod name"},
			},
			"required": []string{"name"},
		},
	},
	{
		Name:        "delete_pod",
		Description: "Delete a specific Kubernetes pod",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"namespace": map[string]interface{}{"type": "string", "description": "Kubernetes namespace (default: default)"},
				"name":      map[string]interface{}{"type": "string", "description": "pod name"},
			},
			"required": []string{"name"},
		},
	},
	{
		Name:        "rollback_deployment",
		Description: "Trigger a rollout restart of a deployment by patching the restartedAt annotation",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"namespace": map[string]interface{}{"type": "string", "description": "Kubernetes namespace (default: default)"},
				"name":      map[string]interface{}{"type": "string", "description": "deployment name"},
			},
			"required": []string{"name"},
		},
	},
}

// setupToolRoutes registers /tools and /tools/execute on the agent HTTP mux.
func (a *PrysmAgent) setupToolRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/tools", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"tools": actionTools,
			"count": len(actionTools),
		})
	})

	mux.HandleFunc("/tools/execute", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		var req agentToolRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(agentToolResult{Tool: req.Tool, Error: "invalid request: " + err.Error()})
			return
		}

		// Validate tool name
		valid := false
		for _, t := range actionTools {
			if t.Name == req.Tool {
				valid = true
				break
			}
		}
		if !valid {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(agentToolResult{Tool: req.Tool, Error: "unknown tool: " + req.Tool})
			return
		}

		if a.clientset == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(agentToolResult{Tool: req.Tool, Error: "kubernetes client not initialized"})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		result := executeAgentTool(ctx, a.clientset, req)

		w.Header().Set("Content-Type", "application/json")
		if !result.Success && result.Error != "" {
			w.WriteHeader(http.StatusInternalServerError)
		}
		json.NewEncoder(w).Encode(result)
	})
}

// executeAgentTool dispatches to the correct K8s action.
func executeAgentTool(ctx context.Context, cs kubernetes.Interface, req agentToolRequest) agentToolResult {
	args := req.Arguments
	if args == nil {
		args = map[string]interface{}{}
	}

	ns := stringArg(args, "namespace", "default")
	name := stringArg(args, "name", "")
	if name == "" {
		return agentToolResult{Tool: req.Tool, Error: "name is required"}
	}

	switch req.Tool {
	case "scale_deployment":
		return execScaleDeployment(ctx, cs, ns, name, args, req.DryRun)
	case "restart_pod":
		return execDeletePod(ctx, cs, ns, name, req.DryRun, "restart_pod")
	case "delete_pod":
		return execDeletePod(ctx, cs, ns, name, req.DryRun, "delete_pod")
	case "rollback_deployment":
		return execRollbackDeployment(ctx, cs, ns, name, req.DryRun)
	default:
		return agentToolResult{Tool: req.Tool, Error: "unimplemented tool"}
	}
}

func execScaleDeployment(ctx context.Context, cs kubernetes.Interface, ns, name string, args map[string]interface{}, dryRun bool) agentToolResult {
	replicasVal, ok := args["replicas"]
	if !ok {
		return agentToolResult{Tool: "scale_deployment", Error: "replicas is required"}
	}
	var replicas int32
	switch v := replicasVal.(type) {
	case float64:
		replicas = int32(v)
	case json.Number:
		i, _ := v.Int64()
		replicas = int32(i)
	default:
		return agentToolResult{Tool: "scale_deployment", Error: "replicas must be a number"}
	}

	if replicas < 0 || replicas > 100 {
		return agentToolResult{Tool: "scale_deployment", Error: "replicas must be between 0 and 100"}
	}

	// Get current state
	deploy, err := cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return agentToolResult{Tool: "scale_deployment", Error: fmt.Sprintf("get deployment: %v", err)}
	}

	currentReplicas := int32(1)
	if deploy.Spec.Replicas != nil {
		currentReplicas = *deploy.Spec.Replicas
	}

	if dryRun {
		return agentToolResult{
			Tool:    "scale_deployment",
			DryRun:  true,
			Success: true,
			Result: map[string]interface{}{
				"action":           "scale_deployment",
				"namespace":        ns,
				"name":             name,
				"current_replicas": currentReplicas,
				"desired_replicas": replicas,
				"preview":          fmt.Sprintf("Would scale %s/%s from %d to %d replicas", ns, name, currentReplicas, replicas),
			},
		}
	}

	scale, err := cs.AppsV1().Deployments(ns).GetScale(ctx, name, metav1.GetOptions{})
	if err != nil {
		return agentToolResult{Tool: "scale_deployment", Error: fmt.Sprintf("get scale: %v", err)}
	}
	scale.Spec.Replicas = replicas
	_, err = cs.AppsV1().Deployments(ns).UpdateScale(ctx, name, scale, metav1.UpdateOptions{})
	if err != nil {
		return agentToolResult{Tool: "scale_deployment", Error: fmt.Sprintf("update scale: %v", err)}
	}

	log.Printf("[tools] scaled deployment %s/%s from %d to %d replicas", ns, name, currentReplicas, replicas)
	return agentToolResult{
		Tool:    "scale_deployment",
		Success: true,
		Result: map[string]interface{}{
			"action":            "scale_deployment",
			"namespace":         ns,
			"name":              name,
			"previous_replicas": currentReplicas,
			"new_replicas":      replicas,
		},
	}
}

func execDeletePod(ctx context.Context, cs kubernetes.Interface, ns, name string, dryRun bool, toolName string) agentToolResult {
	// Verify pod exists
	pod, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return agentToolResult{Tool: toolName, Error: fmt.Sprintf("get pod: %v", err)}
	}

	if dryRun {
		return agentToolResult{
			Tool:    toolName,
			DryRun:  true,
			Success: true,
			Result: map[string]interface{}{
				"action":    toolName,
				"namespace": ns,
				"name":      name,
				"phase":     string(pod.Status.Phase),
				"node":      pod.Spec.NodeName,
				"preview":   fmt.Sprintf("Would delete pod %s/%s (phase: %s, node: %s)", ns, name, pod.Status.Phase, pod.Spec.NodeName),
			},
		}
	}

	err = cs.CoreV1().Pods(ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return agentToolResult{Tool: toolName, Error: fmt.Sprintf("delete pod: %v", err)}
	}

	log.Printf("[tools] deleted pod %s/%s", ns, name)
	return agentToolResult{
		Tool:    toolName,
		Success: true,
		Result: map[string]interface{}{
			"action":    toolName,
			"namespace": ns,
			"name":      name,
			"deleted":   true,
		},
	}
}

func execRollbackDeployment(ctx context.Context, cs kubernetes.Interface, ns, name string, dryRun bool) agentToolResult {
	// Verify deployment exists
	deploy, err := cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return agentToolResult{Tool: "rollback_deployment", Error: fmt.Sprintf("get deployment: %v", err)}
	}

	currentImage := ""
	if len(deploy.Spec.Template.Spec.Containers) > 0 {
		currentImage = deploy.Spec.Template.Spec.Containers[0].Image
	}
	currentGen := deploy.Generation

	if dryRun {
		return agentToolResult{
			Tool:    "rollback_deployment",
			DryRun:  true,
			Success: true,
			Result: map[string]interface{}{
				"action":     "rollback_deployment",
				"namespace":  ns,
				"name":       name,
				"image":      currentImage,
				"generation": currentGen,
				"preview":    fmt.Sprintf("Would trigger rollout restart of %s/%s (current image: %s)", ns, name, currentImage),
			},
		}
	}

	// Patch the deployment to trigger a rollout restart
	restartPatch := fmt.Sprintf(
		`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":"%s"}}}}}`,
		time.Now().UTC().Format(time.RFC3339),
	)
	_, err = cs.AppsV1().Deployments(ns).Patch(ctx, name, types.StrategicMergePatchType, []byte(restartPatch), metav1.PatchOptions{})
	if err != nil {
		return agentToolResult{Tool: "rollback_deployment", Error: fmt.Sprintf("patch deployment: %v", err)}
	}

	log.Printf("[tools] triggered rollout restart for %s/%s", ns, name)
	return agentToolResult{
		Tool:    "rollback_deployment",
		Success: true,
		Result: map[string]interface{}{
			"action":    "rollback_deployment",
			"namespace": ns,
			"name":      name,
			"restarted": true,
		},
	}
}

func stringArg(args map[string]interface{}, key, def string) string {
	if v, ok := args[key].(string); ok && v != "" {
		return v
	}
	return def
}

// Ensure appsv1 import is used (for types.StrategicMergePatchType)
var _ = appsv1.SchemeGroupVersion
