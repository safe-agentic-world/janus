package service

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

func TestCompletedAuditEventFields(t *testing.T) {
	dir := t.TempDir()
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{ID: "allow-readme", ActionType: "fs.read", Resource: "file://workspace/README.md", Decision: policy.DecisionAllow, Obligations: map[string]any{"net_allowlist": []any{"example.com"}}},
		},
		Hash: "bundlehash123",
		SourceBundles: []policy.BundleSource{
			{Path: "base.yaml", Hash: "hash-base", Role: "baseline"},
			{Path: "repo.yaml", Hash: "hash-repo", Role: "repo"},
		},
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(dir, 64*1024, 200)
	writer := executor.NewFSWriter(dir, 64*1024)
	patcher := executor.NewPatchApplier(dir, 64*1024)
	execRunner := executor.NewExecRunner(dir, 64*1024)
	httpRunner := executor.NewHTTPRunner(64 * 1024)
	recorder := &recordSink{}
	now := time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC)
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), nil, nil, "local", func() time.Time {
		now = now.Add(10 * time.Millisecond)
		return now
	})

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act-audit-1",
		ActionType:    "fs.read",
		Resource:      "file://workspace/README.md",
		Params:        []byte(`{"note":"Authorization: secret-token"}`),
		TraceID:       "trace-audit-1",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{Principal: "system", Agent: "nomos", Environment: "dev"})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	_, _ = svc.Process(act)

	var completedFound bool
	for _, e := range recorder.events {
		if e.EventType != "action.completed" {
			continue
		}
		completedFound = true
		if e.SchemaVersion != "v1" {
			t.Fatalf("expected schema version v1, got %s", e.SchemaVersion)
		}
		if e.TraceID == "" || e.ActionID == "" || e.Principal == "" || e.Agent == "" || e.Environment == "" {
			t.Fatalf("missing identity/trace fields: %+v", e)
		}
		if e.ActionType == "" || e.ResourceNormalized == "" || e.ParamsHash == "" {
			t.Fatalf("missing normalized action fields: %+v", e)
		}
		if e.Decision == "" || e.ResultClassification == "" {
			t.Fatalf("missing decision/classification fields: %+v", e)
		}
		if len(e.MatchedRuleIDs) == 0 {
			t.Fatalf("expected matched rules in completed event: %+v", e)
		}
		if e.PolicyBundleHash != "bundlehash123" {
			t.Fatalf("expected policy bundle hash, got %s", e.PolicyBundleHash)
		}
		if len(e.PolicyBundleSources) != 2 {
			t.Fatalf("expected ordered bundle provenance labels, got %+v", e.PolicyBundleSources)
		}
		if len(e.PolicyBundleInputs) != 2 {
			t.Fatalf("expected structured bundle inputs, got %+v", e.PolicyBundleInputs)
		}
		if e.PolicyBundleInputs[0].Role != "baseline" || e.PolicyBundleInputs[1].Role != "repo" {
			t.Fatalf("expected bundle roles preserved in audit event, got %+v", e.PolicyBundleInputs)
		}
		if e.EngineVersion == "" {
			t.Fatal("expected engine version")
		}
		if e.DurationMS <= 0 {
			t.Fatalf("expected positive duration, got %d", e.DurationMS)
		}
		if strings.Contains(e.ParamsRedactedSummary, "secret-token") {
			t.Fatalf("expected params summary redacted, got %s", e.ParamsRedactedSummary)
		}
	}
	if !completedFound {
		t.Fatal("expected action.completed event")
	}
}

func TestCompletedAuditExecMetadataIncludesEnforcementMode(t *testing.T) {
	dir := t.TempDir()
	argv, _, allowPattern := benignExecFixture()
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{
				ID:         "allow-git",
				ActionType: "process.exec",
				Resource:   "file://workspace/",
				Decision:   policy.DecisionAllow,
				ExecMatch: &policy.ExecMatch{
					ArgvPatterns: [][]string{allowPattern},
				},
				Obligations: map[string]any{
					"sandbox_mode": "local",
				},
			},
		},
		Hash: "bundlehash-exec",
	}
	engine := policy.NewEngine(bundle)
	recorder := &recordSink{}
	now := time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC)
	svc := New(engine, executor.NewFSReader(dir, 64*1024, 200), executor.NewFSWriter(dir, 64*1024), executor.NewPatchApplier(dir, 64*1024), executor.NewExecRunner(dir, 64*1024), executor.NewHTTPRunner(64*1024), recorder, redact.DefaultRedactor(), nil, nil, "local", func() time.Time {
		now = now.Add(10 * time.Millisecond)
		return now
	})

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act-audit-exec",
		ActionType:    "process.exec",
		Resource:      "file://workspace/",
		Params:        mustExecParams(t, argv),
		TraceID:       "trace-audit-exec",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{Principal: "system", Agent: "nomos", Environment: "dev"})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	if _, err := svc.Process(act); err != nil {
		t.Fatalf("process: %v", err)
	}
	for _, e := range recorder.events {
		if e.EventType != "action.completed" {
			continue
		}
		if e.ExecutorMetadata["exec_enforcement_mode"] != "exec_constraints" {
			t.Fatalf("expected exec_enforcement_mode exec_constraints, got %+v", e.ExecutorMetadata)
		}
		if e.ExecutorMetadata["exec_compatibility_mode"] != policy.ExecCompatibilityLegacyAllowlistFallback {
			t.Fatalf("expected exec compatibility mode metadata, got %+v", e.ExecutorMetadata)
		}
		return
	}
	t.Fatal("expected action.completed event")
}
