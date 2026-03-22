package service

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/approval"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

func TestCustomActionAllowReturnsExternalAuthorization(t *testing.T) {
	svc, recorder := newCustomActionService(t, policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{ID: "allow-refund", ActionType: "payments.refund", Resource: "payment://shop.example.com/orders/*", Decision: policy.DecisionAllow},
		},
		Hash: "bundle-custom-allow",
	}, nil)

	resp, err := svc.Process(mustCustomAction(t, "act-custom-1", "trace-custom-1", "payments.refund", "payment://shop.example.com/orders/ORD-1001", `{}`, ""))
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if resp.Decision != policy.DecisionAllow || resp.ExecutionMode != action.ExecutionModeExternalAuthorized || resp.ReportPath != "/actions/report" {
		t.Fatalf("unexpected response %+v", resp)
	}
	for _, ev := range recorder.events {
		if ev.EventType != "action.completed" {
			continue
		}
		if ev.ExecutorMetadata["execution_mode"] != action.ExecutionModeExternalAuthorized || ev.ExecutorMetadata["nomos_executed"] != false {
			t.Fatalf("expected external execution metadata, got %+v", ev.ExecutorMetadata)
		}
		if _, ok := ev.ExecutorMetadata["status_code"]; ok {
			t.Fatalf("custom action should not look like net executor metadata: %+v", ev.ExecutorMetadata)
		}
		return
	}
	t.Fatal("expected action.completed event")
}

func TestCustomActionDenyAndApproval(t *testing.T) {
	now := time.Date(2026, 3, 22, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	dir := t.TempDir()
	store, err := approval.Open(filepath.Join(dir, "approvals.db"), 5*time.Minute, nowFn)
	if err != nil {
		t.Fatalf("open approvals: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	svc, _ := newCustomActionService(t, policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{ID: "deny-export", ActionType: "crm.contact_export", Resource: "crm://salesforce/contacts/*", Decision: policy.DecisionDeny},
			{ID: "approve-refund", ActionType: "payments.refund", Resource: "payment://shop.example.com/orders/*", Decision: policy.DecisionRequireApproval},
		},
		Hash: "bundle-custom-mixed",
	}, store)

	denyResp, err := svc.Process(mustCustomAction(t, "act-custom-2", "trace-custom-2", "crm.contact_export", "crm://salesforce/contacts/segment-a", `{}`, ""))
	if err != nil {
		t.Fatalf("deny process: %v", err)
	}
	if denyResp.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %+v", denyResp)
	}

	first, err := svc.Process(mustCustomAction(t, "act-custom-3", "trace-custom-3", "payments.refund", "payment://shop.example.com/orders/ORD-1001", `{}`, ""))
	if err != nil {
		t.Fatalf("approval process: %v", err)
	}
	if first.Decision != policy.DecisionRequireApproval || first.ApprovalID == "" {
		t.Fatalf("expected approval response, got %+v", first)
	}
	if _, err := store.Decide(context.Background(), first.ApprovalID, "APPROVE"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	second, err := svc.Process(mustCustomAction(t, "act-custom-3", "trace-custom-3", "payments.refund", "payment://shop.example.com/orders/ORD-1001", `{}`, first.ApprovalID))
	if err != nil {
		t.Fatalf("approved process: %v", err)
	}
	if second.Decision != policy.DecisionAllow || second.Reason != "allow_by_approval" || second.ExecutionMode != action.ExecutionModeExternalAuthorized {
		t.Fatalf("expected approved external allow, got %+v", second)
	}
}

func newCustomActionService(t *testing.T, bundle policy.Bundle, store *approval.Store) (*Service, *recordSink) {
	t.Helper()
	dir := t.TempDir()
	engine := policy.NewEngine(bundle)
	recorder := &recordSink{}
	svc := New(
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
		func() time.Time { return time.Unix(0, 0) },
	)
	return svc, recorder
}

func mustCustomAction(t *testing.T, actionID, traceID, actionType, resource, params, approvalID string) action.Action {
	t.Helper()
	ext := map[string]json.RawMessage{}
	if approvalID != "" {
		ext["approval"] = json.RawMessage(`{"approval_id":"` + approvalID + `"}`)
	}
	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      actionID,
		ActionType:    actionType,
		Resource:      resource,
		Params:        []byte(params),
		TraceID:       traceID,
		Context:       action.Context{Extensions: ext},
	}, identity.VerifiedIdentity{Principal: "system", Agent: "nomos", Environment: "dev"})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	return act
}
