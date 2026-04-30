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

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/tenant"
)

func TestGatewayTenantScopedBundlesDriveDecisionAuditAndExplain(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "shared.txt"), []byte("tenant data"), 0o600); err != nil {
		t.Fatalf("write workspace file: %v", err)
	}
	basePath := writeTenantPolicyBundle(t, dir, "base.json", `{"version":"v1","rules":[{"id":"base-unrelated","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`)
	teamAPath := writeTenantPolicyBundle(t, dir, "team-a.json", `{"version":"v1","rules":[{"id":"team-a-allow-shared","action_type":"fs.read","resource":"file://workspace/shared.txt","decision":"ALLOW","principals":["alice@example.com"],"agents":["nomos"],"environments":["dev"]}]}`)
	teamBPath := writeTenantPolicyBundle(t, dir, "team-b.json", `{"version":"v1","rules":[{"id":"team-b-deny-shared","action_type":"fs.read","resource":"file://workspace/shared.txt","decision":"DENY","principals":["bob@example.com"],"agents":["nomos"],"environments":["dev"]}]}`)
	cfg := tenantGatewayTestConfig(dir, basePath)
	cfg.Tenancy = tenant.Config{
		Enabled: true,
		Tenants: []tenant.Definition{
			{ID: "team-a", Principals: []string{"alice@example.com"}, PolicyBundlePath: teamAPath},
			{ID: "team-b", Principals: []string{"bob@example.com"}, PolicyBundlePath: teamBPath},
		},
	}
	gw, err := NewWithRecorder(cfg, recorder, func() time.Time { return time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	state := gw.policyState.Load()
	teamSources := state.TenantPolicies["team-a"].BundleSources
	if len(teamSources) != 2 || !strings.HasPrefix(teamSources[0], basePath+"#") || !strings.HasPrefix(teamSources[1], teamAPath+"#") {
		t.Fatalf("expected deterministic base then tenant source order, got %+v", teamSources)
	}

	respA := postTenantAction(t, gw, "key-a", "act-a", "trace-a")
	if respA.Decision != policy.DecisionAllow {
		t.Fatalf("expected team-a allow, got %+v", respA)
	}
	respB := postTenantAction(t, gw, "key-b", "act-b", "trace-b")
	if respB.Decision != policy.DecisionDeny {
		t.Fatalf("expected team-b deny, got %+v", respB)
	}
	assertTenantDecisionEvent(t, recorder.events, "act-a", "team-a", "team-a-allow-shared")
	assertTenantDecisionEvent(t, recorder.events, "act-b", "team-b", "team-b-deny-shared")

	explain := postTenantExplain(t, gw, "key-a", "alice@example.com")
	if explain.TenantID != "team-a" || explain.Decision != policy.DecisionAllow {
		t.Fatalf("expected tenant-scoped explain output, got %+v", explain)
	}
	explain = postTenantExplain(t, gw, "key-b", "bob@example.com")
	if explain.TenantID != "team-b" || explain.Decision != policy.DecisionDeny {
		t.Fatalf("expected team-b explain output, got %+v", explain)
	}
}

func TestGatewayFailsClosedWhenTenantCannotBeResolved(t *testing.T) {
	dir := t.TempDir()
	basePath := writeTenantPolicyBundle(t, dir, "base.json", `{"version":"v1","rules":[{"id":"base-allow","action_type":"fs.read","resource":"file://workspace/shared.txt","decision":"ALLOW"}]}`)
	cfg := tenantGatewayTestConfig(dir, basePath)
	cfg.Identity.APIKeys["key-x"] = "mallory@example.com"
	cfg.Tenancy = tenant.Config{
		Enabled: true,
		Tenants: []tenant.Definition{
			{ID: "team-a", Principals: []string{"alice@example.com"}},
		},
	}
	gw, err := NewWithRecorder(cfg, &recordSink{}, func() time.Time { return time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	body := tenantActionBody("act-x", "trace-x")
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer key-x")
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	w := httptest.NewRecorder()
	gw.handleAction(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected fail-closed 403, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "tenant_resolution_error") {
		t.Fatalf("expected tenant resolution error, got %s", w.Body.String())
	}
}

func tenantGatewayTestConfig(workspaceRoot, bundlePath string) Config {
	return Config{
		Gateway: GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Audit:   AuditConfig{Sink: "stdout"},
		Executor: ExecutorConfig{
			WorkspaceRoot:  workspaceRoot,
			SandboxEnabled: true,
			SandboxProfile: "local",
			MaxOutputBytes: 4096,
			MaxOutputLines: 20,
		},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "dev",
			APIKeys: map[string]string{
				"key-a": "alice@example.com",
				"key-b": "bob@example.com",
			},
			AgentSecrets: map[string]string{
				"nomos": "agent-secret",
			},
		},
		Policy: PolicyConfig{BundlePath: bundlePath},
	}
}

func writeTenantPolicyBundle(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func postTenantAction(t *testing.T, gw *Gateway, apiKey, actionID, traceID string) action.Response {
	t.Helper()
	body := tenantActionBody(actionID, traceID)
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	w := httptest.NewRecorder()
	gw.handleAction(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp action.Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

func tenantActionBody(actionID, traceID string) string {
	return `{"schema_version":"v1","action_id":"` + actionID + `","action_type":"fs.read","resource":"file://workspace/shared.txt","params":{},"trace_id":"` + traceID + `","context":{"extensions":{}}}`
}

func postTenantExplain(t *testing.T, gw *Gateway, apiKey, principal string) explainResponse {
	t.Helper()
	actionID := strings.NewReplacer("@", "-", ".", "-").Replace("explain-" + principal)
	body := `{"schema_version":"v1","action_id":"` + actionID + `","action_type":"fs.read","resource":"file://workspace/shared.txt","params":{},"trace_id":"explain","context":{"extensions":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/explain", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	w := httptest.NewRecorder()
	gw.handleExplain(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp explainResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode explain response: %v", err)
	}
	return resp
}

func assertTenantDecisionEvent(t *testing.T, events []audit.Event, actionID, tenantID, ruleID string) {
	t.Helper()
	for _, event := range events {
		if event.EventType != "action.decision" || event.ActionID != actionID {
			continue
		}
		if event.TenantID != tenantID {
			t.Fatalf("expected tenant %q on %s, got %+v", tenantID, actionID, event)
		}
		for _, matched := range event.MatchedRuleIDs {
			if matched == ruleID {
				return
			}
		}
		t.Fatalf("expected matched rule %q on %s, got %+v", ruleID, actionID, event.MatchedRuleIDs)
	}
	t.Fatalf("missing action.decision audit event for %s", actionID)
}
