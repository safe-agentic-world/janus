package approval

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestFileStorePersistsApprovalStatesAcrossRestart(t *testing.T) {
	now := time.Date(2026, 4, 30, 10, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "approvals.json")
	store, err := OpenFile(path, 10*time.Minute, nowFn)
	if err != nil {
		t.Fatalf("open file store: %v", err)
	}
	pending, err := store.CreateOrGetPending(context.Background(), pendingRequest("fp-pending", "act-pending"))
	if err != nil {
		t.Fatalf("create pending: %v", err)
	}
	approved, err := store.CreateOrGetPending(context.Background(), pendingRequest("fp-approved", "act-approved"))
	if err != nil {
		t.Fatalf("create approved pending: %v", err)
	}
	approved, err = store.Decide(context.Background(), approved.ApprovalID, "APPROVE")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	denied, err := store.CreateOrGetPending(context.Background(), pendingRequest("fp-denied", "act-denied"))
	if err != nil {
		t.Fatalf("create denied pending: %v", err)
	}
	denied, err = store.Decide(context.Background(), denied.ApprovalID, "DENY")
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := OpenFile(path, 10*time.Minute, nowFn)
	if err != nil {
		t.Fatalf("reopen file store: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	assertLookupStatus(t, reopened, pending.ApprovalID, StatusPending)
	assertLookupStatus(t, reopened, approved.ApprovalID, StatusApproved)
	assertLookupStatus(t, reopened, denied.ApprovalID, StatusDenied)
	ok, rec, err := reopened.CheckApproved(context.Background(), approved.ApprovalID, approved.Fingerprint, "")
	if err != nil {
		t.Fatalf("check approved after restart: %v", err)
	}
	if !ok || rec.Status != StatusApproved {
		t.Fatalf("expected approved binding after restart, ok=%v rec=%+v", ok, rec)
	}
}

func TestFileStoreCrashTempDoesNotCorruptCommittedStore(t *testing.T) {
	now := time.Date(2026, 4, 30, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "approvals.json")
	store, err := OpenFile(path, 10*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("open file store: %v", err)
	}
	rec, err := store.CreateOrGetPending(context.Background(), pendingRequest("fp-crash", "act-crash"))
	if err != nil {
		t.Fatalf("create pending: %v", err)
	}
	if err := os.WriteFile(path+".tmp", []byte(`{"version":"approval_store.v1","records":[`), 0o600); err != nil {
		t.Fatalf("write crash temp: %v", err)
	}
	reopened, err := OpenFile(path, 10*time.Minute, func() time.Time { return now })
	if err != nil {
		t.Fatalf("reopen should ignore crash temp: %v", err)
	}
	assertLookupStatus(t, reopened, rec.ApprovalID, StatusPending)
}

func TestFileStoreIntegrityCheckRejectsCorruptMainFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	if err := os.WriteFile(path, []byte(`{"version":"approval_store.v1","records":[],"checksum":"bad"}`), 0o600); err != nil {
		t.Fatalf("write corrupt store: %v", err)
	}
	_, err := OpenFile(path, 10*time.Minute, time.Now)
	if err == nil || !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("expected integrity failure, got %v", err)
	}
}

func TestFileStoreTTLPurgeSurvivesRestart(t *testing.T) {
	now := time.Date(2026, 4, 30, 10, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	path := filepath.Join(t.TempDir(), "approvals.json")
	store, err := OpenFile(path, time.Minute, nowFn)
	if err != nil {
		t.Fatalf("open file store: %v", err)
	}
	rec, err := store.CreateOrGetPending(context.Background(), pendingRequest("fp-ttl", "act-ttl"))
	if err != nil {
		t.Fatalf("create pending: %v", err)
	}
	now = now.Add(2 * time.Minute)
	reopened, err := OpenFile(path, time.Minute, nowFn)
	if err != nil {
		t.Fatalf("reopen file store: %v", err)
	}
	if _, err := reopened.Lookup(context.Background(), rec.ApprovalID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected expired record purged on restart, got %v", err)
	}
	listed, err := reopened.ListPending(context.Background(), 10)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("expected no pending approvals after TTL purge, got %+v", listed)
	}
}

func TestFileAndSQLiteBackendsHaveApprovalLifecycleParity(t *testing.T) {
	now := time.Date(2026, 4, 30, 10, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	dir := t.TempDir()
	fileStore, err := OpenBackend(Options{Backend: BackendFile, Path: filepath.Join(dir, "approvals.json"), TTL: 5 * time.Minute, Now: nowFn})
	if err != nil {
		t.Fatalf("open file backend: %v", err)
	}
	t.Cleanup(func() { _ = fileStore.Close() })
	sqliteStore, err := OpenBackend(Options{Backend: BackendSQLite, Path: filepath.Join(dir, "approvals.db"), TTL: 5 * time.Minute, Now: nowFn})
	if err != nil {
		t.Fatalf("open sqlite backend: %v", err)
	}
	t.Cleanup(func() { _ = sqliteStore.Close() })
	for name, store := range map[string]Backend{"file": fileStore, "sqlite": sqliteStore} {
		rec, err := store.CreateOrGetPending(context.Background(), pendingRequest("fp-parity-"+name, "act-parity-"+name))
		if err != nil {
			t.Fatalf("%s create pending: %v", name, err)
		}
		reused, err := store.CreateOrGetPending(context.Background(), pendingRequest("fp-parity-"+name, "act-parity-"+name))
		if err != nil {
			t.Fatalf("%s reuse pending: %v", name, err)
		}
		if reused.ApprovalID != rec.ApprovalID {
			t.Fatalf("%s expected reusable pending approval", name)
		}
		decided, err := store.Decide(context.Background(), rec.ApprovalID, "approve")
		if err != nil {
			t.Fatalf("%s approve: %v", name, err)
		}
		if decided.Status != StatusApproved {
			t.Fatalf("%s expected approved, got %+v", name, decided)
		}
		ok, checked, err := store.CheckApproved(context.Background(), rec.ApprovalID, rec.Fingerprint, "")
		if err != nil {
			t.Fatalf("%s check approved: %v", name, err)
		}
		if !ok || checked.Status != StatusApproved {
			t.Fatalf("%s expected approved binding, ok=%v rec=%+v", name, ok, checked)
		}
		if _, err := store.Decide(context.Background(), rec.ApprovalID, "DENY"); !errors.Is(err, ErrAlreadyFinalized) {
			t.Fatalf("%s expected finalized conflict, got %v", name, err)
		}
	}
}

func pendingRequest(fingerprint, actionID string) PendingRequest {
	return PendingRequest{
		Fingerprint:         fingerprint,
		ScopeType:           ScopeFingerprint,
		ScopeKey:            fingerprint,
		TraceID:             "trace-" + actionID,
		ActionID:            actionID,
		ActionType:          "fs.write",
		Resource:            "file://workspace/a.txt",
		ParamsHash:          "hash-" + fingerprint,
		ArgumentPreviewJSON: `{"kind":"test"}`,
		Principal:           "p1",
		Agent:               "a1",
		Environment:         "dev",
	}
}

func assertLookupStatus(t *testing.T, store Backend, approvalID, status string) {
	t.Helper()
	rec, err := store.Lookup(context.Background(), approvalID)
	if err != nil {
		t.Fatalf("lookup %s: %v", approvalID, err)
	}
	if rec.Status != status {
		t.Fatalf("expected %s status %s, got %+v", approvalID, status, rec)
	}
}
