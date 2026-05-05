package mcp

import (
	"encoding/json"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/service"
)

type toolDiscoverySummary struct {
	evaluated int
	hidden    int
}

type toolDiscoveryMode string

const (
	toolDiscoveryAllowed          toolDiscoveryMode = "allowed"
	toolDiscoveryApprovalRequired toolDiscoveryMode = "approval_required"
	toolDiscoveryHidden           toolDiscoveryMode = "hidden"
)

type toolDiscoverySpec struct {
	Name       string
	ActionType string
	Resource   string
	Params     map[string]any
	Exempt     bool
}

var directToolDiscoverySpecs = []toolDiscoverySpec{
	{
		Name:       "nomos.capabilities",
		ActionType: "",
		Resource:   "",
		Params:     nil,
		Exempt:     true,
	},
	{
		Name:       "nomos.fs_read",
		ActionType: "fs.read",
		Resource:   "file://workspace/README.md",
		Params:     map[string]any{"resource": "README.md"},
	},
	{
		Name:       "nomos.fs_write",
		ActionType: "fs.write",
		Resource:   "file://workspace/README.md",
		Params:     map[string]any{"resource": "README.md", "content": "sample"},
	},
	{
		Name:       "nomos.apply_patch",
		ActionType: "repo.apply_patch",
		Resource:   "repo://local/workspace",
		Params:     map[string]any{"path": "README.md", "content": "sample"},
	},
	{
		Name:       "nomos.exec",
		ActionType: "process.exec",
		Resource:   "file://workspace/",
		Params:     map[string]any{"argv": []string{"echo", "sample"}, "cwd": "", "env_allowlist_keys": []string{}},
	},
	{
		Name:       "nomos.http_request",
		ActionType: "net.http_request",
		Resource:   "url://example.com/status",
		Params:     map[string]any{"resource": "url://example.com/status", "method": "GET", "body": "", "headers": map[string]string{}},
	},
	{
		Name:       "repo.validate_change_set",
		ActionType: "repo.apply_patch",
		Resource:   "repo://local/workspace",
		Params:     map[string]any{"paths": []string{"README.md"}},
	},
}

func (s *Server) toolsList() []map[string]any {
	tools, _ := s.toolsListForIdentityWithSummary(s.identity, false)
	return tools
}

func (s *Server) toolsListForSession(session *downstreamSession) []map[string]any {
	tools, _ := s.toolsListForSessionWithSummary(session)
	return tools
}

func (s *Server) toolsListForSessionWithSummary(session *downstreamSession) ([]map[string]any, toolDiscoverySummary) {
	if session == nil {
		return s.toolsListForIdentityWithSummary(s.identity, false)
	}
	return s.toolsListForIdentityWithSummary(session.actionIdentity(), true)
}

func (s *Server) toolsListForIdentity(id identity.VerifiedIdentity, filterUnavailable bool) []map[string]any {
	tools, _ := s.toolsListForIdentityWithSummary(id, filterUnavailable)
	return tools
}

func (s *Server) toolsListForIdentityWithSummary(id identity.VerifiedIdentity, filterUnavailable bool) ([]map[string]any, toolDiscoverySummary) {
	_ = filterUnavailable
	summary := toolDiscoverySummary{}
	surface := ToolSurfaceCanonical
	if s != nil && s.toolSurface != "" {
		surface = s.toolSurface
	}
	tools := []map[string]any{
		{"name": advertisedToolName("nomos.capabilities"), "description": "Return the policy-derived capability contract for this session", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}},
	}
	for _, spec := range directToolDiscoverySpecs {
		summary.evaluated++
		if spec.Exempt {
			continue
		}
		discovery, err := s.discoverDirectToolVisibility(id, spec)
		if err != nil || discovery == toolDiscoveryHidden {
			summary.hidden++
			continue
		}
		for _, advertised := range advertisedToolNamesForSurface(spec.Name, surface) {
			tools = append(tools, toolListEntryForSpec(spec.Name, advertised, toolSchemaForSpec(spec.Name), discovery))
		}
	}
	if s.upstream != nil {
		for _, tool := range s.upstream.snapshotTools() {
			summary.evaluated++
			if !s.upstreamVisibleForIdentity(id, tool.ServerName) {
				summary.hidden++
				continue
			}
			discovery, err := s.discoverToolVisibility(id, "mcp.call", "mcp://"+tool.ServerName+"/"+tool.ToolName, map[string]any{
				"upstream_server": tool.ServerName,
				"upstream_tool":   tool.ToolName,
			})
			if err != nil || discovery == toolDiscoveryHidden {
				summary.hidden++
				continue
			}
			tools = append(tools, toolListEntryForUpstream(tool, discovery))
		}
	}
	return tools, summary
}

// discoverDirectToolVisibility decides whether a Nomos-direct tool (one of the
// friendly aliases or canonical nomos.* names) is advertised in tools/list under
// the calling identity.
//
// Two-stage decision:
//
//  1. External-policy health probe — issue a synthetic EvaluateAction so that an
//     error from a configured external policy backend (e.g. an unreachable OPA)
//     causes the tool to be hidden. Decision outcomes from the probe are
//     discarded; only the error path matters here. This preserves the
//     fail-closed safety contract that an unhealthy policy backend must not
//     advertise governed tools.
//
//  2. Rule-based capability scan — match the local policy bundle by
//     action_type and identity only, ignoring resource pattern, params, and
//     exec_match. If at least one ALLOW or REQUIRE_APPROVAL rule matches, the
//     tool is advertised. This is M63's "Nomos becomes the default execution
//     boundary" precedence over M31's resource-aware probe-based hiding: a
//     synthetic probe with placeholder values (argv=["echo","sample"],
//     url://example.com/status) must not cause governed tools to disappear
//     from tools/list under realistic profiles like safe-dev, where those
//     specific placeholders legitimately default-deny but the action_type as
//     a whole has many legitimate allow paths.
//
// Resource-aware hiding still applies to upstream MCP fanout via
// discoverToolVisibility, where each tool maps to a distinct mcp:// resource
// and the resource pattern carries the visibility signal.
func (s *Server) discoverDirectToolVisibility(id identity.VerifiedIdentity, spec toolDiscoverySpec) (toolDiscoveryMode, error) {
	if strings.TrimSpace(spec.ActionType) == "" {
		return toolDiscoveryAllowed, nil
	}
	if act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_discovery",
		ActionType:    spec.ActionType,
		Resource:      spec.Resource,
		Params:        mustJSONBytes(spec.Params),
		TraceID:       "mcp_discovery",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, id); err == nil {
		if _, decision, evalErr := s.service.EvaluateAction(act); evalErr != nil {
			return toolDiscoveryHidden, evalErr
		} else if decision.ReasonCode == "deny_by_external_policy_error" {
			return toolDiscoveryHidden, nil
		}
	}
	cap := s.service.ActionCapability(spec.ActionType, id)
	switch cap.State {
	case service.ToolStateAllow, service.ToolStateMixed:
		return toolDiscoveryAllowed, nil
	case service.ToolStateRequireApproval:
		return toolDiscoveryApprovalRequired, nil
	default:
		return toolDiscoveryHidden, nil
	}
}

func (s *Server) discoverToolVisibility(id identity.VerifiedIdentity, actionType, resource string, params map[string]any) (toolDiscoveryMode, error) {
	if strings.TrimSpace(actionType) == "" {
		return toolDiscoveryAllowed, nil
	}
	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_discovery",
		ActionType:    actionType,
		Resource:      resource,
		Params:        mustJSONBytes(params),
		TraceID:       "mcp_discovery",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, id)
	if err != nil {
		return toolDiscoveryHidden, err
	}
	_, decision, err := s.service.EvaluateAction(act)
	if err != nil {
		return toolDiscoveryHidden, err
	}
	switch decision.Decision {
	case policy.DecisionAllow:
		return toolDiscoveryAllowed, nil
	case policy.DecisionRequireApproval:
		return toolDiscoveryApprovalRequired, nil
	default:
		return toolDiscoveryHidden, nil
	}
}

func toolListEntryForSpec(name, advertisedName string, schema map[string]any, discovery toolDiscoveryMode) map[string]any {
	entry := map[string]any{
		"name":        advertisedName,
		"description": toolDiscoveryDescription(name, advertisedName),
		"inputSchema": schema,
	}
	if discovery == toolDiscoveryApprovalRequired {
		entry["_meta"] = map[string]any{"approval_required": true}
	}
	return entry
}

func toolListEntryForUpstream(tool upstreamTool, discovery toolDiscoveryMode) map[string]any {
	entry := map[string]any{
		"name":        tool.DownstreamName,
		"description": forwardedToolDescription(tool),
		"inputSchema": tool.InputSchema,
	}
	if discovery == toolDiscoveryApprovalRequired {
		entry["_meta"] = map[string]any{"approval_required": true}
	}
	return entry
}

func toolDiscoveryDescription(name, advertisedName string) string {
	if isFriendlyToolName(advertisedName) {
		switch advertisedName {
		case "read_file":
			return "Default governed file-read tool for local workspace reads. Backed by Nomos fs.read policy, approval, and audit."
		case "write_file":
			return "Default governed file-write tool for local workspace edits. Backed by Nomos fs.write policy, approval, and audit."
		case "apply_patch":
			return "Default governed patch tool for repository changes. Backed by Nomos repo.apply_patch policy, approval, and audit."
		case "run_command":
			return "Default governed command tool for local process execution. Pass direct argv tokens such as [\"git\",\"status\"]; simple shell wrappers are normalized, complex shell syntax is rejected. Backed by Nomos process.exec policy, approval, and audit."
		case "http_request":
			return "Default governed HTTP tool for network requests. Backed by Nomos net.http_request policy, approval, and audit."
		}
	}
	switch name {
	case "nomos.capabilities":
		return "Return the policy-derived capability contract for this session"
	case "nomos.fs_read":
		return "Read a workspace file. Use a workspace-relative path like README.md or a canonical file://workspace/... resource. Check nomos.capabilities for current allow versus approval state."
	case "nomos.fs_write":
		return "Write a workspace file. Use a workspace-relative path like notes.txt or a canonical file://workspace/... resource. Check nomos.capabilities for current allow versus approval state."
	case "nomos.apply_patch":
		return "Apply deterministic patch payload. Check nomos.capabilities for current allow versus approval state."
	case "nomos.exec":
		return "Run a bounded process action with direct argv tokens. Simple shell wrappers are normalized; complex shell syntax is rejected. Check nomos.capabilities for current allow versus approval state."
	case "nomos.http_request":
		return "Run a policy-gated HTTP request. Check nomos.capabilities for current allow versus approval state."
	case "repo.validate_change_set":
		return "Validate changed repo paths against policy before attempting a patch action."
	default:
		return "Nomos tool"
	}
}

func toolSchemaForSpec(name string) map[string]any {
	switch name {
	case "nomos.capabilities":
		return map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}
	case "nomos.fs_read":
		return map[string]any{"type": "object", "properties": map[string]any{"resource": map[string]any{"type": "string"}, "approval_id": map[string]any{"type": "string"}}, "required": []string{"resource"}, "additionalProperties": false}
	case "nomos.fs_write":
		return map[string]any{"type": "object", "properties": map[string]any{"resource": map[string]any{"type": "string"}, "content": map[string]any{"type": "string"}, "approval_id": map[string]any{"type": "string"}}, "required": []string{"resource", "content"}, "additionalProperties": false}
	case "nomos.apply_patch":
		return map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}, "content": map[string]any{"type": "string"}, "approval_id": map[string]any{"type": "string"}}, "required": []string{"path", "content"}, "additionalProperties": false}
	case "nomos.exec":
		return map[string]any{"type": "object", "properties": map[string]any{"argv": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "cwd": map[string]any{"type": "string"}, "env_allowlist_keys": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "approval_id": map[string]any{"type": "string"}}, "required": []string{"argv"}, "additionalProperties": false}
	case "nomos.http_request":
		return map[string]any{"type": "object", "properties": map[string]any{"resource": map[string]any{"type": "string"}, "method": map[string]any{"type": "string"}, "body": map[string]any{"type": "string"}, "headers": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}}, "approval_id": map[string]any{"type": "string"}}, "required": []string{"resource"}, "additionalProperties": false}
	case "repo.validate_change_set":
		return map[string]any{"type": "object", "properties": map[string]any{"paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}, "required": []string{"paths"}, "additionalProperties": false}
	default:
		return map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}
	}
}
