package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
)

func TestGatewayReloadPolicyFailurePreservesStateAndAudits(t *testing.T) {
	gw, recorder, bundlePath := newReloadTestGateway(t, `{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`)
	oldHash := gw.PolicyBundleHash()
	resp := performReloadTestAction(t, gw)
	if resp.Decision != "ALLOW" {
		t.Fatalf("expected initial allow, got %+v", resp)
	}

	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[`), 0o600); err != nil {
		t.Fatalf("write malformed bundle: %v", err)
	}
	result, err := gw.ReloadPolicy(context.Background(), "test")
	if err == nil {
		t.Fatal("expected reload failure")
	}
	if result.Outcome != "failure" || result.PolicyBundleHash != oldHash {
		t.Fatalf("unexpected reload result: %+v", result)
	}
	if got := gw.PolicyBundleHash(); got != oldHash {
		t.Fatalf("expected old hash to remain active, got %s want %s", got, oldHash)
	}
	resp = performReloadTestAction(t, gw)
	if resp.Decision != "ALLOW" {
		t.Fatalf("expected old allow policy after failed reload, got %+v", resp)
	}
	if !hasReloadAuditEvent(recorder.events, "failure") {
		t.Fatalf("expected failure reload audit event, got %+v", recorder.events)
	}
}

func TestGatewayAdminReloadTightensPolicy(t *testing.T) {
	gw, recorder, bundlePath := newReloadTestGateway(t, `{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`)
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"deny-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"DENY"}]}`), 0o600); err != nil {
		t.Fatalf("write deny bundle: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/reload", nil)
	req.Header.Set("Authorization", "Bearer key1")
	w := httptest.NewRecorder()
	gw.handleAdminReload(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("admin reload status=%d body=%s", w.Code, w.Body.String())
	}
	var result ReloadResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode reload result: %v", err)
	}
	if result.Outcome != "success" || result.PolicyBundleHash == "" {
		t.Fatalf("unexpected reload result: %+v", result)
	}
	resp := performReloadTestAction(t, gw)
	if resp.Decision != "DENY" {
		t.Fatalf("expected tightened deny policy after reload, got %+v", resp)
	}
	if !hasReloadAuditEvent(recorder.events, "success") {
		t.Fatalf("expected success reload audit event, got %+v", recorder.events)
	}
}

func newReloadTestGateway(t *testing.T, bundle string) (*Gateway, *recordSink, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	recorder := &recordSink{}
	cfg := Config{
		Gateway: GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Executor: ExecutorConfig{
			WorkspaceRoot: dir,
		},
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
	return gw, recorder, bundlePath
}

func performReloadTestAction(t *testing.T, gw *Gateway) action.Response {
	t.Helper()
	body := `{"schema_version":"v1","action_id":"reload-act","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"reload-trace","context":{"extensions":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", reloadHMACHex("agent-secret", []byte(body)))
	w := httptest.NewRecorder()
	gw.handleAction(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("action status=%d body=%s", w.Code, w.Body.String())
	}
	var resp action.Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode action response: %v", err)
	}
	return resp
}

func hasReloadAuditEvent(events []audit.Event, outcome string) bool {
	for _, event := range events {
		if event.EventType == "runtime.reload" && strings.EqualFold(event.Decision, outcome) {
			return true
		}
	}
	return false
}

func reloadHMACHex(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
