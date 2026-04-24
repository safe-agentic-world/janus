package service

import (
	"encoding/json"
	"sort"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

const (
	ToolStateAllow           = "allow"
	ToolStateRequireApproval = "require_approval"
	ToolStateMixed           = "mixed"
	ToolStateUnavailable     = "unavailable"
)

type ToolCapability struct {
	Name                string                `json:"name"`
	ActionType          string                `json:"action_type,omitempty"`
	State               string                `json:"state"`
	ImmediatelyCallable bool                  `json:"immediately_callable"`
	ApprovalRequired    bool                  `json:"approval_required"`
	Advertised          bool                  `json:"advertised"`
	Constraints         CapabilityConstraints `json:"constraints,omitempty"`
}

type CapabilityEnvelope struct {
	ContractVersion       string                    `json:"contract_version,omitempty"`
	CapabilitySetHash     string                    `json:"capability_set_hash,omitempty"`
	AdvisoryOnly          bool                      `json:"advisory_only"`
	AuthorizationNotice   string                    `json:"authorization_notice,omitempty"`
	EnabledTools          []string                  `json:"enabled_tools"`
	ImmediateTools        []string                  `json:"immediate_tools,omitempty"`
	ApprovalGatedTools    []string                  `json:"approval_gated_tools,omitempty"`
	MixedTools            []string                  `json:"mixed_tools,omitempty"`
	UnavailableTools      []string                  `json:"unavailable_tools,omitempty"`
	AdvertisedTools       []string                  `json:"advertised_tools,omitempty"`
	ToolStates            map[string]ToolCapability `json:"tool_states,omitempty"`
	ToolAdvertisementMode string                    `json:"tool_advertisement_mode,omitempty"`
	SandboxModes          []string                  `json:"sandbox_modes"`
	NetworkMode           string                    `json:"network_mode"`
	OutputMaxBytes        int                       `json:"output_max_bytes"`
	OutputMaxLines        int                       `json:"output_max_lines"`
	ApprovalsEnabled      bool                      `json:"approvals_enabled"`
	AssuranceLevel        string                    `json:"assurance_level,omitempty"`
	MediationNotice       string                    `json:"mediation_notice,omitempty"`
	ForwardedTools        []map[string]any          `json:"forwarded_tools,omitempty"`
	MCPSurfaces           map[string]ToolCapability `json:"mcp_surfaces,omitempty"`
}

type CapabilityConstraints struct {
	ResourceClasses []string `json:"resource_classes,omitempty"`
	HostClasses     []string `json:"host_classes,omitempty"`
	ExecClasses     []string `json:"exec_classes,omitempty"`
	ApprovalScopes  []string `json:"approval_scopes,omitempty"`
}

type toolDefinition struct {
	Name            string
	ActionType      string
	AlwaysImmediate bool
}

func capabilityToolDefinitions() []toolDefinition {
	return []toolDefinition{
		{Name: "nomos.fs_read", ActionType: "fs.read"},
		{Name: "nomos.fs_write", ActionType: "fs.write"},
		{Name: "nomos.apply_patch", ActionType: "repo.apply_patch"},
		{Name: "nomos.exec", ActionType: "process.exec"},
		{Name: "nomos.http_request", ActionType: "net.http_request"},
		{Name: "repo.validate_change_set", ActionType: "repo.apply_patch", AlwaysImmediate: true},
	}
}

func toolCapabilityState(def toolDefinition, actionCapability policy.ActionCapability) ToolCapability {
	state := actionCapability.State()
	immediate := actionCapability.Allow
	approvalRequired := actionCapability.RequireApproval
	if def.AlwaysImmediate {
		switch state {
		case ToolStateAllow, ToolStateRequireApproval, ToolStateMixed:
			state = ToolStateAllow
			immediate = true
			approvalRequired = false
		default:
			state = ToolStateUnavailable
			immediate = false
			approvalRequired = false
		}
	}
	return ToolCapability{
		Name:                def.Name,
		ActionType:          def.ActionType,
		State:               state,
		ImmediatelyCallable: immediate,
		ApprovalRequired:    approvalRequired,
		Advertised:          true,
		Constraints: CapabilityConstraints{
			ResourceClasses: append([]string{}, actionCapability.ResourceClasses...),
			HostClasses:     append([]string{}, actionCapability.HostClasses...),
			ExecClasses:     append([]string{}, actionCapability.ExecClasses...),
			ApprovalScopes:  append([]string{}, actionCapability.ApprovalScopes...),
		},
	}
}

func actionCapabilityState(actionType string, actionCapability policy.ActionCapability) ToolCapability {
	return ToolCapability{
		ActionType:          actionType,
		State:               actionCapability.State(),
		ImmediatelyCallable: actionCapability.Allow,
		ApprovalRequired:    actionCapability.RequireApproval,
		Advertised:          actionCapability.Available(),
		Constraints: CapabilityConstraints{
			ResourceClasses: append([]string{}, actionCapability.ResourceClasses...),
			HostClasses:     append([]string{}, actionCapability.HostClasses...),
			ExecClasses:     append([]string{}, actionCapability.ExecClasses...),
			ApprovalScopes:  append([]string{}, actionCapability.ApprovalScopes...),
		},
	}
}

func (s *Service) ToolCapabilities(id identity.VerifiedIdentity) map[string]ToolCapability {
	capabilities := make(map[string]ToolCapability, len(capabilityToolDefinitions()))
	for _, def := range capabilityToolDefinitions() {
		actionCapability := s.policy.CapabilityForActionType(def.ActionType, id.Principal, id.Agent, id.Environment)
		capabilities[def.Name] = toolCapabilityState(def, actionCapability)
	}
	return capabilities
}

func (s *Service) ActionCapability(actionType string, id identity.VerifiedIdentity) ToolCapability {
	actionCapability := s.policy.CapabilityForActionType(actionType, id.Principal, id.Agent, id.Environment)
	return actionCapabilityState(actionType, actionCapability)
}

func (s *Service) EnabledTools(id identity.VerifiedIdentity) []string {
	capabilities := s.ToolCapabilities(id)
	enabled := make([]string, 0, len(capabilities))
	for name, tool := range capabilities {
		if tool.State != ToolStateUnavailable {
			enabled = append(enabled, name)
		}
	}
	sort.Strings(enabled)
	return enabled
}

func CapabilityEnvelopeFromToolStates(capabilities map[string]ToolCapability) CapabilityEnvelope {
	envelope := CapabilityEnvelope{
		ContractVersion:       "nomos.capabilities.v2",
		AdvisoryOnly:          true,
		AuthorizationNotice:   "Advisory only. Nomos evaluates every action live against policy and runtime controls.",
		EnabledTools:          []string{},
		ImmediateTools:        []string{},
		ApprovalGatedTools:    []string{},
		MixedTools:            []string{},
		UnavailableTools:      []string{},
		AdvertisedTools:       []string{},
		ToolStates:            make(map[string]ToolCapability, len(capabilities)),
		ToolAdvertisementMode: "mcp_tools_list_static",
	}
	for name, tool := range capabilities {
		envelope.AdvertisedTools = append(envelope.AdvertisedTools, name)
		envelope.ToolStates[name] = tool
		switch tool.State {
		case ToolStateAllow:
			envelope.EnabledTools = append(envelope.EnabledTools, name)
			envelope.ImmediateTools = append(envelope.ImmediateTools, name)
		case ToolStateRequireApproval:
			envelope.EnabledTools = append(envelope.EnabledTools, name)
			envelope.ApprovalGatedTools = append(envelope.ApprovalGatedTools, name)
		case ToolStateMixed:
			envelope.EnabledTools = append(envelope.EnabledTools, name)
			envelope.MixedTools = append(envelope.MixedTools, name)
		default:
			envelope.UnavailableTools = append(envelope.UnavailableTools, name)
		}
	}
	sort.Strings(envelope.EnabledTools)
	sort.Strings(envelope.ImmediateTools)
	sort.Strings(envelope.ApprovalGatedTools)
	sort.Strings(envelope.MixedTools)
	sort.Strings(envelope.UnavailableTools)
	sort.Strings(envelope.AdvertisedTools)
	return envelope
}

func FinalizeCapabilityEnvelope(envelope CapabilityEnvelope, id identity.VerifiedIdentity, policyBundleHash string) CapabilityEnvelope {
	if envelope.ContractVersion == "" {
		envelope.ContractVersion = "nomos.capabilities.v2"
	}
	hashInput := map[string]any{
		"contract_version":        envelope.ContractVersion,
		"policy_bundle_hash":      policyBundleHash,
		"identity":                map[string]string{"principal": id.Principal, "agent": id.Agent, "environment": id.Environment},
		"advisory_only":           envelope.AdvisoryOnly,
		"authorization_notice":    envelope.AuthorizationNotice,
		"enabled_tools":           envelope.EnabledTools,
		"immediate_tools":         envelope.ImmediateTools,
		"approval_gated_tools":    envelope.ApprovalGatedTools,
		"mixed_tools":             envelope.MixedTools,
		"unavailable_tools":       envelope.UnavailableTools,
		"advertised_tools":        envelope.AdvertisedTools,
		"tool_states":             envelope.ToolStates,
		"tool_advertisement_mode": envelope.ToolAdvertisementMode,
		"sandbox_modes":           envelope.SandboxModes,
		"network_mode":            envelope.NetworkMode,
		"output_max_bytes":        envelope.OutputMaxBytes,
		"output_max_lines":        envelope.OutputMaxLines,
		"approvals_enabled":       envelope.ApprovalsEnabled,
		"assurance_level":         envelope.AssuranceLevel,
		"mediation_notice":        envelope.MediationNotice,
		"forwarded_tools":         envelope.ForwardedTools,
		"mcp_surfaces":            envelope.MCPSurfaces,
	}
	data, err := json.Marshal(hashInput)
	if err != nil {
		envelope.CapabilitySetHash = ""
		return envelope
	}
	canonical, err := canonicaljson.Canonicalize(data)
	if err != nil {
		envelope.CapabilitySetHash = ""
		return envelope
	}
	envelope.CapabilitySetHash = canonicaljson.HashSHA256(canonical)
	return envelope
}

func (s *Service) ValidateChangeSet(id identity.VerifiedIdentity, paths []string) (bool, []string, error) {
	blocked := make([]string, 0)
	for _, path := range paths {
		act := action.Action{
			SchemaVersion: "v1",
			ActionID:      "validate_change",
			ActionType:    "repo.apply_patch",
			Resource:      "file://workspace/" + path,
			Params:        []byte(`{}`),
			Principal:     id.Principal,
			Agent:         id.Agent,
			Environment:   id.Environment,
			Context:       action.Context{Extensions: map[string]json.RawMessage{}},
			TraceID:       "validate_change",
		}
		normalized, err := normalize.Action(act)
		if err != nil {
			blocked = append(blocked, path)
			continue
		}
		decision := s.policy.Evaluate(normalized)
		if decision.Decision != policy.DecisionAllow {
			blocked = append(blocked, path)
		}
	}
	return len(blocked) == 0, blocked, nil
}
