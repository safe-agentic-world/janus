package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/approval"
	"github.com/safe-agentic-world/nomos/internal/audit"
)

func TestUIApprovalsRejectsAnonymousAccess(t *testing.T) {
	gw := newUITestGateway(t)
	req := httptest.NewRequest(http.MethodGet, "/api/ui/approvals", nil)
	w := httptest.NewRecorder()

	gw.handleUIApprovals(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestUITraceRejectsAnonymousAccess(t *testing.T) {
	gw := newUITestGateway(t)
	req := httptest.NewRequest(http.MethodGet, "/api/ui/traces", nil)
	w := httptest.NewRecorder()

	gw.handleUITraceList(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestUIApprovalsListAndDecisionFlow(t *testing.T) {
	gw := newUITestGateway(t)
	_, err := gw.approvals.CreateOrGetPending(context.Background(), approval.PendingRequest{
		Fingerprint: "fp1",
		ScopeType:   approval.ScopeFingerprint,
		ScopeKey:    "fp1",
		TraceID:     "trace-ui-1",
		ActionID:    "act-ui-1",
		ActionType:  "net.http_request",
		Resource:    "url://shop.example.com/refunds/ord-1",
		ParamsHash:  "params1",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("create pending approval: %v", err)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/ui/approvals", nil)
	listReq.Header.Set("Authorization", "Bearer ui-key")
	listW := httptest.NewRecorder()
	gw.handleUIApprovals(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", listW.Code)
	}
	var listPayload struct {
		Approvals []uiApprovalRecord `json:"approvals"`
	}
	if err := json.Unmarshal(listW.Body.Bytes(), &listPayload); err != nil {
		t.Fatalf("decode approvals response: %v", err)
	}
	if len(listPayload.Approvals) != 1 {
		t.Fatalf("expected 1 approval, got %+v", listPayload.Approvals)
	}
	if listPayload.Approvals[0].ApprovalID == "" {
		t.Fatal("expected approval id")
	}

	decideReq := httptest.NewRequest(http.MethodPost, "/api/ui/approvals/decide", strings.NewReader(`{"approval_id":"`+listPayload.Approvals[0].ApprovalID+`","decision":"approve"}`))
	decideReq.Header.Set("Authorization", "Bearer ui-key")
	decideW := httptest.NewRecorder()
	gw.handleUIApprovalDecision(decideW, decideReq)
	if decideW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", decideW.Code, decideW.Body.String())
	}
	if !strings.Contains(decideW.Body.String(), "approval_recorded") {
		t.Fatalf("expected approval_recorded response, got %s", decideW.Body.String())
	}
}

func TestUIReadinessReturnsDoctorState(t *testing.T) {
	gw := newUITestGateway(t)
	req := httptest.NewRequest(http.MethodGet, "/api/ui/readiness", nil)
	req.Header.Set("Authorization", "Bearer ui-key")
	w := httptest.NewRecorder()

	gw.handleUIReadiness(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var payload uiReadinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode readiness: %v", err)
	}
	if payload.OverallStatus != "READY" {
		t.Fatalf("expected READY, got %+v", payload)
	}
	if payload.PolicyBundleHash == "" {
		t.Fatal("expected policy bundle hash")
	}
	if !payload.ApprovalsEnabled {
		t.Fatal("expected approvals enabled")
	}
}

func TestUIActionDetailUsesRedactedAuditData(t *testing.T) {
	gw := newUITestGateway(t)
	sqlitePath := audit.FirstSQLiteSinkPath(gw.cfg.Audit.Sink)
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer db.Close()
	event := audit.Event{
		SchemaVersion:         "v1",
		Timestamp:             time.Unix(0, 0).UTC(),
		EventType:             "action.completed",
		TraceID:               "trace-a1",
		ActionID:              "act-a1",
		ActionType:            "fs.read",
		Resource:              "file://workspace/README.md",
		ResourceNormalized:    "file://workspace/README.md",
		ParamsHash:            "params-hash",
		MatchedRuleIDs:        []string{"allow-readme"},
		Obligations:           map[string]any{"output_max_bytes": 16},
		ResultClassification:  "SUCCESS",
		AssuranceLevel:        "BEST_EFFORT",
		Reason:                "Authorization: Bearer super-secret-value",
		ParamsRedactedSummary: `{"authorization":"Bearer super-secret-value"}`,
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal audit event: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO audit_events (timestamp, trace_id, action_id, event_type, decision, result_classification, retryable, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		event.Timestamp.Format(time.RFC3339Nano),
		event.TraceID,
		event.ActionID,
		event.EventType,
		event.Decision,
		event.ResultClassification,
		0,
		string(payload),
	); err != nil {
		t.Fatalf("insert audit event: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/ui/actions/act-a1", nil)
	req.Header.Set("Authorization", "Bearer ui-key")
	w := httptest.NewRecorder()
	gw.handleUIActionDetail(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, "super-secret-value") {
		t.Fatalf("expected redacted response, got %s", body)
	}
	if !strings.Contains(body, "act-a1") {
		t.Fatalf("expected action detail payload, got %s", body)
	}
}

func TestUIStaticShellServesIndex(t *testing.T) {
	gw := newUITestGateway(t)
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	w := httptest.NewRecorder()

	gw.handleUIStatic(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Nomos Operator UI") {
		t.Fatalf("expected operator ui shell, got %s", w.Body.String())
	}
}

func TestUITraceListAndDetail(t *testing.T) {
	gw := newUITestGateway(t)
	sqlitePath := audit.FirstSQLiteSinkPath(gw.cfg.Audit.Sink)
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer db.Close()
	events := []audit.Event{
		{Timestamp: time.Unix(1, 0).UTC(), EventType: "trace.start", TraceID: "trace-ui-x", ActionID: "act-ui-x", ActionType: "fs.read", Principal: "system", Agent: "nomos", Environment: "dev"},
		{Timestamp: time.Unix(2, 0).UTC(), EventType: "action.decision", TraceID: "trace-ui-x", ActionID: "act-ui-x", ActionType: "fs.read", Decision: "ALLOW", Principal: "system", Agent: "nomos", Environment: "dev"},
		{Timestamp: time.Unix(3, 0).UTC(), EventType: "action.completed", TraceID: "trace-ui-x", ActionID: "act-ui-x", ActionType: "fs.read", Decision: "ALLOW", Principal: "system", Agent: "nomos", Environment: "dev"},
		{Timestamp: time.Unix(4, 0).UTC(), EventType: "trace.end", TraceID: "trace-ui-x", ActionID: "act-ui-x", ActionType: "fs.read", Decision: "ALLOW", Principal: "system", Agent: "nomos", Environment: "dev"},
	}
	for _, event := range events {
		payload, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		if _, err := db.Exec(`INSERT INTO audit_events (timestamp, trace_id, action_id, event_type, decision, result_classification, retryable, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			event.Timestamp.Format(time.RFC3339Nano),
			event.TraceID,
			event.ActionID,
			event.EventType,
			event.Decision,
			event.ResultClassification,
			0,
			string(payload),
		); err != nil {
			t.Fatalf("insert event: %v", err)
		}
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/ui/traces?decision=ALLOW&action_type=fs.read", nil)
	listReq.Header.Set("Authorization", "Bearer ui-key")
	listW := httptest.NewRecorder()
	gw.handleUITraceList(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", listW.Code, listW.Body.String())
	}
	if !strings.Contains(listW.Body.String(), "trace-ui-x") {
		t.Fatalf("expected trace summary, got %s", listW.Body.String())
	}

	detailReq := httptest.NewRequest(http.MethodGet, "/api/ui/traces/trace-ui-x", nil)
	detailReq.Header.Set("Authorization", "Bearer ui-key")
	detailW := httptest.NewRecorder()
	gw.handleUITraceDetail(detailW, detailReq)
	if detailW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", detailW.Code, detailW.Body.String())
	}
	body := detailW.Body.String()
	for _, want := range []string{"trace.start", "action.decision", "action.completed", "trace.end"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected timeline event %s in %s", want, body)
		}
	}
}

func TestUIExplainDoesNotExecuteActions(t *testing.T) {
	gw := newUITestGateway(t)
	sqlitePath := audit.FirstSQLiteSinkPath(gw.cfg.Audit.Sink)
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer db.Close()
	var before int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&before); err != nil {
		t.Fatalf("count before: %v", err)
	}

	body := `{"schema_version":"v1","action_id":"explain-ui-1","action_type":"net.http_request","resource":"url://shop.example.com/refunds/ord-1","params":{"authorization":"Bearer very-secret-token"},"principal":"system","agent":"nomos","environment":"dev","context":{"extensions":{}},"trace_id":"trace-explain-ui-1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/ui/explain", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer ui-key")
	w := httptest.NewRecorder()
	gw.handleUIExplain(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	respBody := w.Body.String()
	if !strings.Contains(respBody, "\"decision\"") || !strings.Contains(respBody, "minimal_allowing_change") {
		t.Fatalf("expected explain payload, got %s", respBody)
	}
	if strings.Contains(respBody, "very-secret-token") {
		t.Fatalf("expected redacted explain response, got %s", respBody)
	}

	var after int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&after); err != nil {
		t.Fatalf("count after: %v", err)
	}
	if before != after {
		t.Fatalf("expected explain-only call not to write audit events: before=%d after=%d", before, after)
	}
}

func TestBuildUIReadinessResponseSupportsNotReadyFixtures(t *testing.T) {
	cfg := Config{
		Runtime:    RuntimeConfig{DeploymentMode: "unmanaged"},
		Approvals:  ApprovalsConfig{Enabled: false},
		SourcePath: "C:\\tmp\\config.json",
	}
	resp := buildUIReadinessResponse(UIReadinessReport{
		OverallStatus: "NOT_READY",
		Checks: []UIReadinessCheck{{
			ID: "config.load", Status: "FAIL", Message: "config loaded failed",
		}},
		EngineVersion: "test-version",
	}, cfg, "hash1", nil, "BEST_EFFORT", "operator")
	if resp.OverallStatus != "NOT_READY" {
		t.Fatalf("expected NOT_READY, got %+v", resp)
	}
	if resp.OperatorPrincipal != "operator" {
		t.Fatalf("expected operator principal, got %+v", resp)
	}
}

func newUITestGateway(t *testing.T) *Gateway {
	t.Helper()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway":  map[string]any{"listen": "127.0.0.1:0", "transport": "http"},
		"runtime":  map[string]any{"deployment_mode": "unmanaged"},
		"policy":   map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{"workspace_root": dir},
		"audit":    map[string]any{"sink": "sqlite:" + filepath.Join(dir, "audit.db")},
		"mcp":      map[string]any{"enabled": false},
		"upstream": map[string]any{"routes": []any{}},
		"approvals": map[string]any{
			"enabled":     true,
			"store_path":  filepath.Join(dir, "approvals.db"),
			"ttl_seconds": 900,
		},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"ui-key": "system"},
			"agent_secrets": map[string]any{"nomos": "agent-secret"},
			"oidc":          map[string]any{"enabled": false, "issuer": "", "audience": "", "public_key_path": ""},
		},
	})
	if err := os.WriteFile(configPath, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(configPath, os.Getenv, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	t.Cleanup(func() {
		_ = gw.Shutdown(context.Background())
	})
	gw.SetUIReadinessReporter(func() (UIReadinessReport, error) {
		return UIReadinessReport{
			OverallStatus:    "READY",
			Checks:           []UIReadinessCheck{{ID: "config.load", Status: "PASS", Message: "config loaded"}},
			PolicyBundleHash: gw.policyBundleHash,
			AssuranceLevel:   gw.assuranceLevel,
			EngineVersion:    "test-version",
		}, nil
	})
	return gw
}
