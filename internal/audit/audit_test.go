package audit

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/redact"
)

func TestSQLiteSinkStoresRedactedPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	writer, err := NewWriter("sqlite:"+path, redact.DefaultRedactor())
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	event := Event{
		SchemaVersion:         "v1",
		Timestamp:             time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC),
		EventType:             "action.completed",
		TraceID:               "trace1",
		ActionID:              "act1",
		Decision:              "ALLOW",
		ResultRedactedSummary: "Authorization: secret-token",
	}
	if err := writer.WriteEvent(event); err != nil {
		t.Fatalf("write event: %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	var payload string
	if err := db.QueryRow(`SELECT payload_json FROM audit_events LIMIT 1`).Scan(&payload); err != nil {
		t.Fatalf("query row: %v", err)
	}
	if strings.Contains(payload, "secret-token") {
		t.Fatalf("payload should be redacted: %s", payload)
	}
	if !strings.Contains(payload, "[REDACTED]") {
		t.Fatalf("expected redaction marker in payload: %s", payload)
	}
}

func TestWebhookSinkPostsRedactedPayload(t *testing.T) {
	received := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		received = string(body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	writer, err := NewWriter("webhook:"+server.URL, redact.DefaultRedactor())
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	event := Event{
		SchemaVersion:         "v1",
		Timestamp:             time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC),
		EventType:             "action.completed",
		TraceID:               "trace1",
		ActionID:              "act1",
		Decision:              "ALLOW",
		ResultRedactedSummary: "Authorization: super-secret",
	}
	if err := writer.WriteEvent(event); err != nil {
		t.Fatalf("write event: %v", err)
	}
	if strings.Contains(received, "super-secret") {
		t.Fatalf("webhook payload should be redacted: %s", received)
	}
	if !strings.Contains(received, "[REDACTED]") {
		t.Fatalf("expected redaction marker in webhook payload: %s", received)
	}
}

func TestMultiSinkIncludesStdoutAndSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() {
		_ = w.Close()
		os.Stdout = old
		_ = r.Close()
	}()

	writer, err := NewWriter("stdout,sqlite:"+path, redact.DefaultRedactor())
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	event := Event{Timestamp: time.Now().UTC(), EventType: "trace.start", TraceID: "t1", ActionID: "a1"}
	if err := writer.WriteEvent(event); err != nil {
		t.Fatalf("write event: %v", err)
	}
	_ = w.Close()
	body, _ := io.ReadAll(r)
	if !strings.Contains(string(body), "\"event_type\":\"trace.start\"") {
		t.Fatalf("expected stdout jsonl output, got %s", string(body))
	}
}

func TestStderrSinkWritesJSONL(t *testing.T) {
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	defer func() {
		_ = w.Close()
		os.Stderr = old
		_ = r.Close()
	}()

	writer, err := NewWriter("stderr", redact.DefaultRedactor())
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	event := Event{Timestamp: time.Now().UTC(), EventType: "trace.start", TraceID: "t1", ActionID: "a1"}
	if err := writer.WriteEvent(event); err != nil {
		t.Fatalf("write event: %v", err)
	}
	_ = w.Close()
	body, _ := io.ReadAll(r)
	if !strings.Contains(string(body), "\"event_type\":\"trace.start\"") {
		t.Fatalf("expected stderr jsonl output, got %s", string(body))
	}
}

func TestChainHashesLinkedInSQLiteStream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	writer, err := NewWriter("sqlite:"+path, redact.DefaultRedactor())
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	events := []Event{
		{SchemaVersion: "v1", Timestamp: time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC), EventType: "trace.start", TraceID: "t1", ActionID: "a1"},
		{SchemaVersion: "v1", Timestamp: time.Date(2026, 2, 26, 12, 0, 1, 0, time.UTC), EventType: "action.decision", TraceID: "t1", ActionID: "a1"},
	}
	for _, e := range events {
		if err := writer.WriteEvent(e); err != nil {
			t.Fatalf("write event: %v", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT payload_json FROM audit_events ORDER BY id`)
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	defer rows.Close()
	out := make([]Event, 0)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			t.Fatalf("scan: %v", err)
		}
		var e Event
		if err := json.Unmarshal([]byte(payload), &e); err != nil {
			t.Fatalf("decode: %v", err)
		}
		out = append(out, e)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 events, got %d", len(out))
	}
	if out[0].EventHash == "" {
		t.Fatal("expected first event hash")
	}
	if out[0].PrevEventHash != "" {
		t.Fatalf("expected empty prev hash on first event, got %s", out[0].PrevEventHash)
	}
	if out[1].PrevEventHash != out[0].EventHash {
		t.Fatalf("expected chain linkage, got prev=%s first=%s", out[1].PrevEventHash, out[0].EventHash)
	}
}

func TestTenantPartitionedAuditQueries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	writer, err := NewWriter("sqlite:"+path, redact.DefaultRedactor())
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	events := []Event{
		{SchemaVersion: "v1", Timestamp: time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC), EventType: "trace.start", TraceID: "trace-shared", ActionID: "shared-action", TenantID: "team-a", Principal: "alice"},
		{SchemaVersion: "v1", Timestamp: time.Date(2026, 4, 30, 12, 0, 1, 0, time.UTC), EventType: "action.completed", TraceID: "trace-shared", ActionID: "shared-action", TenantID: "team-a", Principal: "alice", ActionType: "fs.read", Decision: "ALLOW"},
		{SchemaVersion: "v1", Timestamp: time.Date(2026, 4, 30, 12, 0, 2, 0, time.UTC), EventType: "trace.start", TraceID: "trace-shared", ActionID: "shared-action", TenantID: "team-b", Principal: "bob"},
		{SchemaVersion: "v1", Timestamp: time.Date(2026, 4, 30, 12, 0, 3, 0, time.UTC), EventType: "action.completed", TraceID: "trace-shared", ActionID: "shared-action", TenantID: "team-b", Principal: "bob", ActionType: "fs.read", Decision: "DENY"},
	}
	for _, event := range events {
		if err := writer.WriteEvent(event); err != nil {
			t.Fatalf("write event: %v", err)
		}
	}
	detail, err := LoadActionDetailForTenant(path, "shared-action", "team-a")
	if err != nil {
		t.Fatalf("load action detail for tenant: %v", err)
	}
	if detail.TenantID != "team-a" || detail.Decision != "ALLOW" {
		t.Fatalf("expected team-a action detail, got %+v", detail)
	}
	traceEvents, err := LoadTraceEventsForTenant(path, "trace-shared", "team-b")
	if err != nil {
		t.Fatalf("load trace events for tenant: %v", err)
	}
	if len(traceEvents) != 2 {
		t.Fatalf("expected two team-b trace events, got %+v", traceEvents)
	}
	for _, event := range traceEvents {
		if event.TenantID != "team-b" {
			t.Fatalf("expected only team-b events, got %+v", traceEvents)
		}
	}
	summaries, err := ListTraceSummaries(path, TraceListFilter{TenantID: "team-a", Limit: 10})
	if err != nil {
		t.Fatalf("list trace summaries: %v", err)
	}
	if len(summaries) != 1 || summaries[0].TenantID != "team-a" || summaries[0].Decision != "ALLOW" {
		t.Fatalf("expected team-a summary, got %+v", summaries)
	}
}

func TestChainHashGoldenVector(t *testing.T) {
	event := Event{
		SchemaVersion: "v1",
		Timestamp:     time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC),
		EventType:     "action.completed",
		TraceID:       "trace-golden",
		ActionID:      "act-golden",
		Decision:      "ALLOW",
	}
	got, err := withChainHash(event, "")
	if err != nil {
		t.Fatalf("withChainHash: %v", err)
	}
	const expected = "04ae64afdfb5b314211c7e14ef9fbd243fe5d43e9464755b183a54b8a043ba6c"
	if got.EventHash != expected {
		t.Fatalf("golden mismatch: got %s want %s", got.EventHash, expected)
	}
}

func TestWithChainHashRejectsOversizedInput(t *testing.T) {
	event := Event{
		SchemaVersion: "v1",
		Timestamp:     time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC),
		EventType:     "action.completed",
		TraceID:       "trace-oversize",
	}
	prevHash := strings.Repeat("a", maxChainHashInputBytes+1)
	if _, err := withChainHash(event, prevHash); err == nil {
		t.Fatal("expected oversized chain hash input to be rejected")
	}
}
