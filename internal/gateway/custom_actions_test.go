package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGatewayCustomActionHTTPFlowAndReport(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-refund","action_type":"payments.refund","resource":"payment://shop.example.com/orders/*","decision":"ALLOW"},{"id":"approve-export","action_type":"crm.contact_export","resource":"crm://salesforce/contacts/*","decision":"REQUIRE_APPROVAL"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	cfg := Config{
		Gateway: GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Audit:   AuditConfig{Sink: "stdout"},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "dev",
			APIKeys:     map[string]string{"key1": "system"},
			AgentSecrets: map[string]string{
				"nomos": "agent-secret",
			},
		},
		Policy: PolicyConfig{BundlePath: bundlePath},
	}
	gw, err := NewWithRecorder(cfg, recorder, func() time.Time { return time.Unix(0, 0) })
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}

	body := `{"schema_version":"v1","action_id":"act-custom-http","action_type":"payments.refund","resource":"payment://shop.example.com/orders/ORD-1001","params":{},"trace_id":"trace-custom-http","context":{"extensions":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	w := httptest.NewRecorder()
	gw.handleAction(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Decision      string `json:"decision"`
		ExecutionMode string `json:"execution_mode"`
		ReportPath    string `json:"report_path"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Decision != "ALLOW" || resp.ExecutionMode != "external_authorized" || resp.ReportPath != "/actions/report" {
		t.Fatalf("unexpected custom action response %+v", resp)
	}

	reportBody := `{"schema_version":"v1","action_id":"act-custom-http","trace_id":"trace-custom-http","action_type":"payments.refund","resource":"payment://shop.example.com/orders/ORD-1001","outcome":"SUCCEEDED","external_reference":"refund_123"}`
	reportReq := httptest.NewRequest(http.MethodPost, "/actions/report", strings.NewReader(reportBody))
	reportReq.Header.Set("Authorization", "Bearer key1")
	reportReq.Header.Set("X-Nomos-Agent-Id", "nomos")
	reportReq.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(reportBody)))
	reportW := httptest.NewRecorder()
	gw.handleExternalReport(reportW, reportReq)
	if reportW.Code != http.StatusOK {
		t.Fatalf("expected report 200, got %d body=%s", reportW.Code, reportW.Body.String())
	}
	foundReported := false
	for _, ev := range recorder.events {
		if ev.EventType == "action.external_reported" {
			foundReported = true
			if ev.ActionType != "payments.refund" || ev.ResourceNormalized != "payment://shop.example.com/orders/ORD-1001" {
				t.Fatalf("unexpected report event %+v", ev)
			}
		}
	}
	if !foundReported {
		t.Fatal("expected action.external_reported event")
	}
}

func TestGatewayRejectsMalformedCustomActionAndBuiltInReport(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	cfg := Config{
		Gateway: GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Audit:   AuditConfig{Sink: "stdout"},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "dev",
			APIKeys:     map[string]string{"key1": "system"},
			AgentSecrets: map[string]string{
				"nomos": "agent-secret",
			},
		},
		Policy: PolicyConfig{BundlePath: bundlePath},
	}
	gw, err := NewWithRecorder(cfg, recorder, func() time.Time { return time.Unix(0, 0) })
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}

	body := `{"schema_version":"v1","action_id":"act-bad-custom","action_type":"BadAction","resource":"payment://shop.example.com/orders/ORD-1001","params":{},"trace_id":"trace-bad-custom","context":{"extensions":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	w := httptest.NewRecorder()
	gw.handleAction(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "action_type has invalid format") {
		t.Fatalf("expected malformed custom action rejection, got %d %s", w.Code, w.Body.String())
	}

	reportBody := `{"schema_version":"v1","action_id":"act-read","trace_id":"trace-read","action_type":"fs.read","resource":"file://workspace/README.md","outcome":"SUCCEEDED"}`
	reportReq := httptest.NewRequest(http.MethodPost, "/actions/report", strings.NewReader(reportBody))
	reportReq.Header.Set("Authorization", "Bearer key1")
	reportReq.Header.Set("X-Nomos-Agent-Id", "nomos")
	reportReq.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(reportBody)))
	reportW := httptest.NewRecorder()
	gw.handleExternalReport(reportW, reportReq)
	if reportW.Code != http.StatusBadRequest || !strings.Contains(reportW.Body.String(), "built-in action types do not support external outcome reporting") {
		t.Fatalf("expected built-in report rejection, got %d %s", reportW.Code, reportW.Body.String())
	}
}
