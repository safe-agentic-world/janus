package approval

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestCreatePendingAndDecideIdempotent(t *testing.T) {
	now := time.Date(2026, 2, 26, 10, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "approvals.db")
	store, err := Open(path, 5*time.Minute, nowFn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	req := PendingRequest{
		Fingerprint:         "fp1",
		ScopeType:           ScopeFingerprint,
		ScopeKey:            "fp1",
		TraceID:             "trace1",
		ActionID:            "act1",
		ActionType:          "fs.write",
		Resource:            "file://workspace/a.txt",
		ParamsHash:          "hash1",
		ArgumentPreviewJSON: `{"kind":"mcp_call_arguments","tool_arguments":{"order_id":"ORD-1"}}`,
		Principal:           "p1",
		Agent:               "a1",
		Environment:         "dev",
	}
	rec1, err := store.CreateOrGetPending(context.Background(), req)
	if err != nil {
		t.Fatalf("create pending: %v", err)
	}
	rec2, err := store.CreateOrGetPending(context.Background(), req)
	if err != nil {
		t.Fatalf("create pending second: %v", err)
	}
	if rec1.ApprovalID != rec2.ApprovalID {
		t.Fatal("expected idempotent pending request reuse")
	}
	if rec2.ArgumentPreviewJSON != req.ArgumentPreviewJSON {
		t.Fatalf("expected argument preview round trip, got %q", rec2.ArgumentPreviewJSON)
	}
	listed, err := store.ListPending(context.Background(), 10)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(listed) != 1 || listed[0].ArgumentPreviewJSON != req.ArgumentPreviewJSON {
		t.Fatalf("expected listed argument preview, got %+v", listed)
	}

	decided, err := store.Decide(context.Background(), rec1.ApprovalID, "APPROVE")
	if err != nil {
		t.Fatalf("decide approve: %v", err)
	}
	if decided.Status != StatusApproved {
		t.Fatalf("expected approved, got %s", decided.Status)
	}
	decidedAgain, err := store.Decide(context.Background(), rec1.ApprovalID, "approved")
	if err != nil {
		t.Fatalf("idempotent approve failed: %v", err)
	}
	if decidedAgain.Status != StatusApproved {
		t.Fatalf("expected approved on idempotent call, got %s", decidedAgain.Status)
	}
	_, err = store.Decide(context.Background(), rec1.ApprovalID, "DENY")
	if !errors.Is(err, ErrAlreadyFinalized) {
		t.Fatalf("expected ErrAlreadyFinalized, got %v", err)
	}
}

func TestOpenMigratesLegacyStoreForArgumentPreview(t *testing.T) {
	now := time.Date(2026, 2, 26, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "legacy-approvals.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	_, err = db.Exec(`
CREATE TABLE approvals (
  approval_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  scope_type TEXT NOT NULL,
  scope_key TEXT NOT NULL,
  status TEXT NOT NULL,
  trace_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  resource TEXT NOT NULL,
  params_hash TEXT NOT NULL,
  principal TEXT NOT NULL,
  agent TEXT NOT NULL,
  environment TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);`)
	if closeErr := db.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}

	store, err := Open(path, time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("open migrated store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rec, err := store.CreateOrGetPending(context.Background(), PendingRequest{
		Fingerprint:         "fp-legacy",
		ScopeType:           ScopeFingerprint,
		ScopeKey:            "fp-legacy",
		TraceID:             "trace-legacy",
		ActionID:            "act-legacy",
		ActionType:          "mcp.call",
		Resource:            "mcp://retail/refund.request",
		ParamsHash:          "hash-legacy",
		ArgumentPreviewJSON: `{"kind":"mcp_call_arguments"}`,
		Principal:           "p1",
		Agent:               "a1",
		Environment:         "dev",
	})
	if err != nil {
		t.Fatalf("create pending after migration: %v", err)
	}
	if rec.ArgumentPreviewJSON == "" {
		t.Fatal("expected argument preview after migration")
	}
}

func TestTTLAndBinding(t *testing.T) {
	now := time.Date(2026, 2, 26, 10, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "approvals.db")
	store, err := Open(path, time.Minute, nowFn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	rec, err := store.CreateOrGetPending(context.Background(), PendingRequest{
		Fingerprint: "fp2",
		ScopeType:   ScopeFingerprint,
		ScopeKey:    "fp2",
		TraceID:     "trace2",
		ActionID:    "act2",
		ActionType:  "fs.read",
		Resource:    "file://workspace/README.md",
		ParamsHash:  "hash2",
		Principal:   "p1",
		Agent:       "a1",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("create pending: %v", err)
	}
	if _, err := store.Decide(context.Background(), rec.ApprovalID, "APPROVE"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	ok, _, err := store.CheckApproved(context.Background(), rec.ApprovalID, "fp2", "")
	if err != nil {
		t.Fatalf("check approved: %v", err)
	}
	if !ok {
		t.Fatal("expected approval match")
	}
	ok, _, err = store.CheckApproved(context.Background(), rec.ApprovalID, "fp_other", "")
	if err != nil {
		t.Fatalf("check mismatch: %v", err)
	}
	if ok {
		t.Fatal("expected mismatch to fail")
	}

	now = now.Add(2 * time.Minute)
	ok, _, err = store.CheckApproved(context.Background(), rec.ApprovalID, "fp2", "")
	if err != nil {
		t.Fatalf("check expired: %v", err)
	}
	if ok {
		t.Fatal("expected expired approval to fail")
	}
}
