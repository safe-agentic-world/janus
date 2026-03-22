package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
)

func TestGatewayStartAndShutdown(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": "127.0.0.1:0", "transport": "http"},
		"policy":  map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit":     map[string]any{"sink": "stdout"},
		"mcp":       map[string]any{"enabled": false},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":   "system",
			"agent":       "nomos",
			"environment": "dev",
			"api_keys": map[string]any{
				"key1": "system",
			},
			"agent_secrets": map[string]any{
				"nomos": "secret",
			},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(path, os.Getenv, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	gw, err := New(cfg)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	if err := gw.Start(); err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := gw.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown gateway: %v", err)
	}
}

type recordSink struct {
	events []audit.Event
}

func (r *recordSink) WriteEvent(event audit.Event) error {
	r.events = append(r.events, event)
	return nil
}

func TestGatewayEmitsTraceEvents(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	cfg := Config{
		Gateway: GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Audit:   AuditConfig{Sink: "stdout"},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "dev",
			APIKeys: map[string]string{
				"key1": "system",
			},
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
	body := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	w := httptest.NewRecorder()
	gw.handleAction(w, req)
	if len(recorder.events) < 3 {
		t.Fatalf("expected at least 3 events, got %d", len(recorder.events))
	}
	if recorder.events[0].EventType != "trace.start" {
		t.Fatalf("expected trace.start, got %s", recorder.events[0].EventType)
	}
	foundTraceEnd := false
	for _, event := range recorder.events {
		if event.EventType == "trace.end" {
			foundTraceEnd = true
			break
		}
	}
	if !foundTraceEnd {
		t.Fatal("expected trace.end event")
	}
	for _, event := range recorder.events {
		if event.TraceID != "trace1" {
			t.Fatalf("expected trace_id trace1, got %s", event.TraceID)
		}
	}
	decisionEvent := recorder.events[1]
	if decisionEvent.Principal != "system" || decisionEvent.Agent != "nomos" || decisionEvent.Environment != "dev" {
		t.Fatalf("expected identity in audit event, got principal=%s agent=%s env=%s", decisionEvent.Principal, decisionEvent.Agent, decisionEvent.Environment)
	}
}

func TestGatewayDerivesAndPropagatesAssuranceLevel(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("ok"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	cfg := Config{
		Gateway: GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Runtime: RuntimeConfig{StrongGuarantee: true, DeploymentMode: "k8s", Evidence: RuntimeEvidenceConfig{
			ContainerBackendReady:    true,
			Rootless:                 true,
			ReadOnlyFS:               true,
			NoNewPrivileges:          true,
			NetworkDefaultDeny:       true,
			WorkloadIdentityVerified: true,
			DurableAuditVerified:     true,
		}},
		Audit:    AuditConfig{Sink: "sqlite:" + filepath.Join(dir, "audit.db")},
		Executor: ExecutorConfig{WorkspaceRoot: dir, SandboxEnabled: true, SandboxProfile: "container"},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "prod",
			AgentSecrets: map[string]string{
				"nomos": "agent-secret",
			},
			SPIFFE: SPIFFEConfig{
				Enabled:     true,
				TrustDomain: "example.org",
			},
		},
		Policy: PolicyConfig{BundlePath: bundlePath},
	}
	gw, err := NewWithRecorder(cfg, recorder, func() time.Time { return time.Unix(0, 0) })
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	body := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	spiffeID, _ := url.Parse("spiffe://example.org/workload/nomos")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{spiffeID}}},
	}
	w := httptest.NewRecorder()
	gw.handleAction(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if gw.assuranceLevel != "STRONG" {
		t.Fatalf("expected gateway assurance STRONG, got %s", gw.assuranceLevel)
	}
	if len(recorder.events) == 0 {
		t.Fatal("expected audit events")
	}
	for _, event := range recorder.events {
		if event.AssuranceLevel != "STRONG" {
			t.Fatalf("expected assurance STRONG on %s, got %q", event.EventType, event.AssuranceLevel)
		}
	}
}

func TestGatewayStrongGuaranteeDegradesWithoutRuntimeEvidence(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("ok"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	cfg := Config{
		Gateway:  GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Runtime:  RuntimeConfig{StrongGuarantee: true, DeploymentMode: "k8s"},
		Audit:    AuditConfig{Sink: "stdout"},
		Executor: ExecutorConfig{WorkspaceRoot: dir},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "prod",
			APIKeys: map[string]string{
				"key1": "system",
			},
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
	if gw.assuranceLevel != "GUARDED" {
		t.Fatalf("expected degraded gateway assurance GUARDED, got %s", gw.assuranceLevel)
	}
}

func TestGatewayRunEndpointUsesActionHandler(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("ok"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	cfg := Config{
		Gateway:  GatewayConfig{Listen: "127.0.0.1:0", Transport: "http", ConcurrencyLimit: 2},
		Audit:    AuditConfig{Sink: "stdout"},
		Executor: ExecutorConfig{WorkspaceRoot: dir},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "dev",
			APIKeys: map[string]string{
				"key1": "system",
			},
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
	if err := gw.Start(); err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	t.Cleanup(func() {
		_ = gw.Shutdown(context.Background())
	})
	body := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{}}}`
	req, err := http.NewRequest(http.MethodPost, "http://"+gw.listener.Addr().String()+"/run", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestGatewayConcurrencyLimitReturns429(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	cfg := Config{
		Gateway: GatewayConfig{Listen: "127.0.0.1:0", Transport: "http", ConcurrencyLimit: 1},
		Audit:   AuditConfig{Sink: "stdout"},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "dev",
			APIKeys: map[string]string{
				"key1": "system",
			},
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
	// Occupy the only slot to force rate-limit path deterministically.
	gw.actionTokens <- struct{}{}

	body := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	w := httptest.NewRecorder()
	gw.handleAction(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestGatewayRateLimitPerPrincipal(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("ok"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	cfg := Config{
		Gateway:  GatewayConfig{Listen: "127.0.0.1:0", Transport: "http", ConcurrencyLimit: 2, RateLimitPerMin: 1, CircuitFailures: 5, CircuitCooldownS: 60},
		Audit:    AuditConfig{Sink: "stdout"},
		Executor: ExecutorConfig{WorkspaceRoot: dir},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "dev",
			APIKeys: map[string]string{
				"key1": "system",
			},
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
	body := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	w := httptest.NewRecorder()
	gw.handleAction(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	gw.handleAction(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
}

func TestGatewayCircuitBreakerOpensAfterFailures(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	now := time.Unix(0, 0)
	cfg := Config{
		Gateway:  GatewayConfig{Listen: "127.0.0.1:0", Transport: "http", ConcurrencyLimit: 2, RateLimitPerMin: 100, CircuitFailures: 2, CircuitCooldownS: 60},
		Audit:    AuditConfig{Sink: "stdout"},
		Executor: ExecutorConfig{WorkspaceRoot: dir},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "dev",
			APIKeys: map[string]string{
				"key1": "system",
			},
			AgentSecrets: map[string]string{
				"nomos": "agent-secret",
			},
		},
		Policy: PolicyConfig{BundlePath: bundlePath},
	}
	gw, err := NewWithRecorder(cfg, recorder, func() time.Time { return now })
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	body := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/missing.txt","params":{},"trace_id":"trace1","context":{"extensions":{}}}`
	makeReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer key1")
		req.Header.Set("X-Nomos-Agent-Id", "nomos")
		req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
		w := httptest.NewRecorder()
		gw.handleAction(w, req)
		return w
	}
	if w := makeReq(); w.Code != http.StatusBadRequest {
		t.Fatalf("expected first failure 400, got %d", w.Code)
	}
	if w := makeReq(); w.Code != http.StatusBadRequest {
		t.Fatalf("expected second failure 400, got %d", w.Code)
	}
	if w := makeReq(); w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected circuit open 429, got %d", w.Code)
	}
}

func TestGatewayUpstreamRouteTypedMatchAllowsConfiguredRequest(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-http","action_type":"net.http_request","resource":"url://api.example.com/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"],"obligations":{"net_allowlist":["api.example.com"]}}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	cfg := Config{
		Gateway: GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Audit:   AuditConfig{Sink: "stdout"},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "dev",
			APIKeys: map[string]string{
				"key1": "system",
			},
			AgentSecrets: map[string]string{
				"nomos": "agent-secret",
			},
		},
		Policy:   PolicyConfig{BundlePath: bundlePath},
		Upstream: UpstreamConfig{Routes: []UpstreamRoute{{URL: "https://api.example.com/v1", Methods: []string{"GET"}, PathPrefix: "/v1"}}},
	}
	gw, err := NewWithRecorder(cfg, &recordSink{}, func() time.Time { return time.Unix(0, 0) })
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	act := actionAction("act-upstream-ok", "net.http_request", "url://api.example.com/v1/status", `{"method":"GET"}`)
	if err := gw.validateUpstreamRoute(act); err != nil {
		t.Fatalf("expected upstream route match, got %v", err)
	}
}

func TestGatewayUpstreamRouteMismatchFailsClosed(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-http","action_type":"net.http_request","resource":"url://api.example.com/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"],"obligations":{"net_allowlist":["api.example.com"]}}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	cfg := Config{
		Gateway: GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Audit:   AuditConfig{Sink: "stdout"},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "dev",
			APIKeys: map[string]string{
				"key1": "system",
			},
			AgentSecrets: map[string]string{
				"nomos": "agent-secret",
			},
		},
		Policy:   PolicyConfig{BundlePath: bundlePath},
		Upstream: UpstreamConfig{Routes: []UpstreamRoute{{URL: "https://api.example.com/v1", Methods: []string{"POST"}, PathPrefix: "/v1"}}},
	}
	gw, err := NewWithRecorder(cfg, &recordSink{}, func() time.Time { return time.Unix(0, 0) })
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	act := actionAction("act-upstream-deny", "net.http_request", "url://api.example.com/v2/status", `{"method":"GET"}`)
	if err := gw.validateUpstreamRoute(act); err == nil || !strings.Contains(err.Error(), "upstream route not configured") {
		t.Fatalf("expected upstream mismatch error, got %v", err)
	}
}

func actionAction(actionID, actionType, resource, params string) action.Action {
	return action.Action{
		SchemaVersion: "v1",
		ActionID:      actionID,
		ActionType:    actionType,
		Resource:      resource,
		Params:        []byte(params),
		Principal:     "system",
		Agent:         "nomos",
		Environment:   "dev",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
		TraceID:       "trace-" + actionID,
	}
}

func TestGatewayRequiresMTLSClientCert(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("ok"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	cfg := Config{
		Gateway:  GatewayConfig{Listen: "127.0.0.1:0", Transport: "http", ConcurrencyLimit: 2, RateLimitPerMin: 100, CircuitFailures: 5, CircuitCooldownS: 60, TLS: TLSConfig{RequireMTLS: true}},
		Audit:    AuditConfig{Sink: "stdout"},
		Executor: ExecutorConfig{WorkspaceRoot: dir},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "dev",
			APIKeys: map[string]string{
				"key1": "system",
			},
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
	body := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace1","context":{"extensions":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	w := httptest.NewRecorder()
	gw.handleAction(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when mTLS required, got %d", w.Code)
	}
}

func TestGatewayPropagatesAcceptedTraceContext(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("ok"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	cfg := Config{
		Gateway:  GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Audit:    AuditConfig{Sink: "stdout"},
		Executor: ExecutorConfig{WorkspaceRoot: dir},
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
	body := `{"schema_version":"v1","action_id":"act-trace","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace-http","context":{"extensions":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	req.Header.Set("tracestate", "vendor=value")
	w := httptest.NewRecorder()
	gw.handleAction(w, req)
	if got := w.Header().Get("Traceparent"); got == "" {
		t.Fatal("expected traceparent to propagate")
	}
	if got := w.Header().Get("Tracestate"); got != "vendor=value" {
		t.Fatalf("expected tracestate propagation, got %q", got)
	}
}

func TestGatewayExplainEndpointUsesRequestEnvelopeAndSkipsAudit(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"refund-approval","action_type":"net.http_request","resource":"url://api.example.com/**","decision":"REQUIRE_APPROVAL","obligations":{"net_allowlist":["api.example.com"]}}]}`), 0o600); err != nil {
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
	body := `{"schema_version":"v1","action_id":"act-explain","action_type":"net.http_request","resource":"url://api.example.com/refunds/ord-1","params":{"method":"POST"},"trace_id":"trace-explain","context":{"extensions":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/explain", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	w := httptest.NewRecorder()
	gw.handleExplain(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	respBody := w.Body.String()
	if !strings.Contains(respBody, `"decision":"REQUIRE_APPROVAL"`) {
		t.Fatalf("expected explain decision in response, got %s", respBody)
	}
	if !strings.Contains(respBody, `"action_id":"act-explain"`) || !strings.Contains(respBody, `"trace_id":"trace-explain"`) {
		t.Fatalf("expected explain response to preserve ids, got %s", respBody)
	}
	if len(recorder.events) != 0 {
		t.Fatalf("expected explain endpoint not to write audit events, got %d", len(recorder.events))
	}
}

func TestGatewaySPIFFEIdentityPropagatesIntoAudit(t *testing.T) {
	recorder := &recordSink{}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["spiffe://example.org/workload/nomos"],"agents":["nomos"],"environments":["prod"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("ok"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	cfg := Config{
		Gateway:  GatewayConfig{Listen: "127.0.0.1:0", Transport: "http"},
		Audit:    AuditConfig{Sink: "stdout"},
		Executor: ExecutorConfig{WorkspaceRoot: dir},
		Identity: IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "prod",
			AgentSecrets: map[string]string{
				"nomos": "agent-secret",
			},
			SPIFFE: SPIFFEConfig{
				Enabled:     true,
				TrustDomain: "example.org",
			},
		},
		Policy: PolicyConfig{BundlePath: bundlePath},
	}
	gw, err := NewWithRecorder(cfg, recorder, func() time.Time { return time.Unix(0, 0) })
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	body := `{"schema_version":"v1","action_id":"act-spiffe","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"trace_id":"trace-spiffe","context":{"extensions":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/action", strings.NewReader(body))
	req.Header.Set("X-Nomos-Agent-Id", "nomos")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", []byte(body)))
	spiffeID, _ := url.Parse("spiffe://example.org/workload/nomos")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{URIs: []*url.URL{spiffeID}}},
	}
	w := httptest.NewRecorder()
	gw.handleAction(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	found := false
	for _, event := range recorder.events {
		if event.EventType == "action.decision" || event.EventType == "action.completed" {
			found = true
			if event.Principal != "spiffe://example.org/workload/nomos" {
				t.Fatalf("expected SPIFFE principal in audit, got %q", event.Principal)
			}
		}
	}
	if !found {
		t.Fatal("expected decision/completed audit events")
	}
}

func hmacHex(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
