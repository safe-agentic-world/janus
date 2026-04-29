package service

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/approval"
	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

func TestMCPApprovalRecordIncludesRedactedArgumentPreviewAndFingerprintParity(t *testing.T) {
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	dir := t.TempDir()
	store, err := approval.Open(filepath.Join(dir, "approvals.db"), 5*time.Minute, nowFn)
	if err != nil {
		t.Fatalf("open approval store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	svc := newMCPApprovalPreviewService(t, dir, store, nowFn)

	first := mustMCPApprovalAction(t, "act-mcp-preview-1", "trace-mcp-preview-1", `{"tool_schema_validated":true,"upstream_server":"retail","upstream_tool":"refund.request","tool_arguments":{"reason":"damaged","authorization":"Bearer very-secret-token","order_id":"ORD-1001"},"tool_arguments_hash":"`+hashJSON(t, `{"authorization":"Bearer very-secret-token","order_id":"ORD-1001","reason":"damaged"}`)+`"}`, "")
	resp, err := svc.Process(first)
	if err != nil {
		t.Fatalf("process first: %v", err)
	}
	if resp.Decision != policy.DecisionRequireApproval || resp.ApprovalID == "" {
		t.Fatalf("expected approval response, got %+v", resp)
	}
	rec, err := store.Lookup(context.Background(), resp.ApprovalID)
	if err != nil {
		t.Fatalf("lookup approval: %v", err)
	}
	if rec.ArgumentPreviewJSON == "" {
		t.Fatal("expected stored argument preview")
	}
	if strings.Contains(rec.ArgumentPreviewJSON, "very-secret-token") {
		t.Fatalf("argument preview leaked secret: %s", rec.ArgumentPreviewJSON)
	}
	if !strings.Contains(rec.ArgumentPreviewJSON, `"order_id":"ORD-1001"`) || !strings.Contains(rec.ArgumentPreviewJSON, `"params_hash":"`+rec.ParamsHash+`"`) {
		t.Fatalf("argument preview does not reflect canonical params: %s", rec.ArgumentPreviewJSON)
	}
	if rec.Fingerprint != resp.ApprovalFingerprint {
		t.Fatalf("approval fingerprint mismatch: record=%s response=%s", rec.Fingerprint, resp.ApprovalFingerprint)
	}

	if _, err := store.Decide(context.Background(), resp.ApprovalID, "APPROVE"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	second := mustMCPApprovalAction(t, "act-mcp-preview-1", "trace-mcp-preview-1", `{"upstream_tool":"refund.request","tool_arguments_hash":"`+hashJSON(t, `{"authorization":"Bearer very-secret-token","order_id":"ORD-1001","reason":"damaged"}`)+`","tool_arguments":{"order_id":"ORD-1001","reason":"damaged","authorization":"Bearer very-secret-token"},"tool_schema_validated":true,"upstream_server":"retail"}`, resp.ApprovalID)
	resp2, err := svc.Process(second)
	if err != nil {
		t.Fatalf("process approved retry: %v", err)
	}
	if resp2.Decision != policy.DecisionAllow || resp2.Reason != "allow_by_approval" {
		t.Fatalf("expected approved fingerprint to resume execution, got %+v", resp2)
	}
	if resp2.ApprovalFingerprint != resp.ApprovalFingerprint {
		t.Fatalf("expected fingerprint parity across canonical argument order: %s != %s", resp2.ApprovalFingerprint, resp.ApprovalFingerprint)
	}
}

func newMCPApprovalPreviewService(t *testing.T, dir string, store *approval.Store, nowFn func() time.Time) *Service {
	t.Helper()
	engine := policy.NewEngine(policy.Bundle{
		Version: "v1",
		Hash:    "bundle",
		Rules: []policy.Rule{{
			ID:           "require-approval-mcp-call",
			ActionType:   "mcp.call",
			Resource:     "mcp://retail/refund.request",
			Decision:     policy.DecisionRequireApproval,
			Principals:   []string{"system"},
			Agents:       []string{"nomos"},
			Environments: []string{"dev"},
		}},
	})
	recorder := &recordSink{}
	return New(
		engine,
		executor.NewFSReader(dir, 64*1024, 100),
		executor.NewFSWriter(dir, 64*1024),
		executor.NewPatchApplier(dir, 64*1024),
		executor.NewExecRunner(dir, 64*1024),
		executor.NewHTTPRunner(64*1024),
		recorder,
		redact.DefaultRedactor(),
		store,
		nil,
		"local",
		nowFn,
	)
}

func mustMCPApprovalAction(t *testing.T, actionID, traceID, params, approvalID string) action.Action {
	t.Helper()
	ext := map[string]json.RawMessage{}
	if approvalID != "" {
		ext["approval"] = json.RawMessage(`{"approval_id":"` + approvalID + `"}`)
	}
	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      actionID,
		ActionType:    "mcp.call",
		Resource:      "mcp://retail/refund.request",
		Params:        []byte(params),
		TraceID:       traceID,
		Context:       action.Context{Extensions: ext},
	}, identity.VerifiedIdentity{Principal: "system", Agent: "nomos", Environment: "dev"})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	return act
}

func hashJSON(t *testing.T, raw string) string {
	t.Helper()
	canonical, err := canonicaljson.Canonicalize([]byte(raw))
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	return canonicaljson.HashSHA256(canonical)
}
