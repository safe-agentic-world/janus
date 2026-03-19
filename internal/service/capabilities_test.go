package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/assurance"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

func TestToolCapabilitiesClassifyAllowRequireApprovalMixedAndUnavailable(t *testing.T) {
	engine := policy.NewEngine(policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{
				ID:           "allow-read",
				ActionType:   "fs.read",
				Resource:     "file://workspace/**",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
			},
			{
				ID:           "approve-http",
				ActionType:   "net.http_request",
				Resource:     "url://shop.example.com/checkout/**",
				Decision:     policy.DecisionRequireApproval,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
			},
			{
				ID:           "approve-exec",
				ActionType:   "process.exec",
				Resource:     "file://workspace/",
				Decision:     policy.DecisionRequireApproval,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
			},
			{
				ID:           "allow-exec",
				ActionType:   "process.exec",
				Resource:     "file://workspace/",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
			},
		},
	})
	svc := &Service{policy: engine}
	id := identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}

	capabilities := svc.ToolCapabilities(id)
	if got := capabilities["nomos.fs_read"].State; got != ToolStateAllow {
		t.Fatalf("expected fs_read allow, got %q", got)
	}
	if got := capabilities["nomos.http_request"].State; got != ToolStateRequireApproval {
		t.Fatalf("expected http_request require_approval, got %q", got)
	}
	if got := capabilities["nomos.exec"].State; got != ToolStateMixed {
		t.Fatalf("expected exec mixed, got %q", got)
	}
	if got := capabilities["nomos.fs_write"].State; got != ToolStateUnavailable {
		t.Fatalf("expected fs_write unavailable, got %q", got)
	}
	if got := capabilities["repo.validate_change_set"].State; got != ToolStateUnavailable {
		t.Fatalf("expected validate_change_set unavailable without repo.apply_patch support, got %q", got)
	}
	if got := capabilities["nomos.fs_read"].Constraints.ResourceClasses; len(got) != 1 || got[0] != "workspace_tree" {
		t.Fatalf("expected bounded fs.read resource class, got %+v", got)
	}
	if got := capabilities["nomos.http_request"].Constraints.HostClasses; len(got) != 1 || got[0] != "host_allowlist" {
		t.Fatalf("expected bounded host class, got %+v", got)
	}
	if got := capabilities["nomos.exec"].Constraints.ExecClasses; len(got) != 1 || got[0] != "generic_exec" {
		t.Fatalf("expected conservative exec class summary, got %+v", got)
	}
}

func TestCapabilityEnvelopeFromToolStatesPreservesLegacyEnabledToolsAndNewBuckets(t *testing.T) {
	envelope := CapabilityEnvelopeFromToolStates(map[string]ToolCapability{
		"nomos.fs_read": {
			Name:                "nomos.fs_read",
			ActionType:          "fs.read",
			State:               ToolStateAllow,
			ImmediatelyCallable: true,
			Advertised:          true,
		},
		"nomos.http_request": {
			Name:             "nomos.http_request",
			ActionType:       "net.http_request",
			State:            ToolStateRequireApproval,
			ApprovalRequired: true,
			Advertised:       true,
		},
		"nomos.exec": {
			Name:                "nomos.exec",
			ActionType:          "process.exec",
			State:               ToolStateMixed,
			ImmediatelyCallable: true,
			ApprovalRequired:    true,
			Advertised:          true,
		},
		"nomos.fs_write": {
			Name:       "nomos.fs_write",
			ActionType: "fs.write",
			State:      ToolStateUnavailable,
			Advertised: true,
		},
	})

	if envelope.ToolAdvertisementMode != "mcp_tools_list_static" {
		t.Fatalf("expected static tool advertisement mode, got %q", envelope.ToolAdvertisementMode)
	}
	if !envelope.AdvisoryOnly || envelope.ContractVersion == "" || envelope.AuthorizationNotice == "" {
		t.Fatalf("expected explicit advisory capability contract metadata, got %+v", envelope)
	}
	if len(envelope.EnabledTools) != 3 {
		t.Fatalf("expected 3 enabled tools, got %+v", envelope.EnabledTools)
	}
	if len(envelope.ImmediateTools) != 1 || envelope.ImmediateTools[0] != "nomos.fs_read" {
		t.Fatalf("unexpected immediate tools: %+v", envelope.ImmediateTools)
	}
	if len(envelope.ApprovalGatedTools) != 1 || envelope.ApprovalGatedTools[0] != "nomos.http_request" {
		t.Fatalf("unexpected approval-gated tools: %+v", envelope.ApprovalGatedTools)
	}
	if len(envelope.MixedTools) != 1 || envelope.MixedTools[0] != "nomos.exec" {
		t.Fatalf("unexpected mixed tools: %+v", envelope.MixedTools)
	}
	if len(envelope.UnavailableTools) != 1 || envelope.UnavailableTools[0] != "nomos.fs_write" {
		t.Fatalf("unexpected unavailable tools: %+v", envelope.UnavailableTools)
	}
}

func TestFinalizeCapabilityEnvelopeIsDeterministicAndHashChangesWithState(t *testing.T) {
	base := CapabilityEnvelopeFromToolStates(map[string]ToolCapability{
		"nomos.fs_read": {
			Name:                "nomos.fs_read",
			ActionType:          "fs.read",
			State:               ToolStateAllow,
			ImmediatelyCallable: true,
			Advertised:          true,
			Constraints:         CapabilityConstraints{ResourceClasses: []string{"workspace_single_path"}},
		},
	})
	base.SandboxModes = []string{"sandboxed"}
	base.NetworkMode = "deny"
	base.OutputMaxBytes = 1024
	base.OutputMaxLines = 10
	base.ApprovalsEnabled = false
	base.AssuranceLevel = assurance.LevelGuarded

	id := identity.VerifiedIdentity{Principal: "system", Agent: "nomos", Environment: "dev"}
	first := FinalizeCapabilityEnvelope(base, id, "bundle-hash-a")
	second := FinalizeCapabilityEnvelope(base, id, "bundle-hash-a")
	if first.CapabilitySetHash == "" || first.CapabilitySetHash != second.CapabilitySetHash {
		t.Fatalf("expected deterministic capability hash, got %q vs %q", first.CapabilitySetHash, second.CapabilitySetHash)
	}

	changed := base
	changed.ToolStates = map[string]ToolCapability{
		"nomos.fs_read": {
			Name:             "nomos.fs_read",
			ActionType:       "fs.read",
			State:            ToolStateRequireApproval,
			ApprovalRequired: true,
			Advertised:       true,
			Constraints:      CapabilityConstraints{ResourceClasses: []string{"workspace_single_path"}},
		},
	}
	changed.EnabledTools = []string{"nomos.fs_read"}
	changed.ImmediateTools = nil
	changed.ApprovalGatedTools = []string{"nomos.fs_read"}
	third := FinalizeCapabilityEnvelope(changed, id, "bundle-hash-a")
	if third.CapabilitySetHash == first.CapabilitySetHash {
		t.Fatalf("expected capability hash to change when surfaced state changes: %q", third.CapabilitySetHash)
	}
}

func TestCapabilityContractAvoidsLeakingSensitiveResourceNames(t *testing.T) {
	engine := policy.NewEngine(policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{
				ID:           "allow-secret-file",
				ActionType:   "fs.read",
				Resource:     "file://workspace/secrets/customer-prod.env",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
			},
		},
	})
	svc := &Service{policy: engine}
	id := identity.VerifiedIdentity{Principal: "system", Agent: "nomos", Environment: "dev"}
	envelope := CapabilityEnvelopeFromToolStates(svc.ToolCapabilities(id))
	envelope = FinalizeCapabilityEnvelope(envelope, id, "bundle-hash")
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal capability envelope: %v", err)
	}
	text := string(data)
	if containsAny(text, []string{"customer-prod.env", "secrets"}) {
		t.Fatalf("capability contract leaked sensitive resource detail: %s", text)
	}
}

func containsAny(text string, values []string) bool {
	for _, value := range values {
		if value != "" && strings.Contains(text, value) {
			return true
		}
	}
	return false
}
