package sdk

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testLogger struct {
	lines []string
}

func (l *testLogger) Printf(format string, args ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func TestSignRequestBodyMatchesHMACSHA256(t *testing.T) {
	got := SignRequestBody("secret", []byte(`{"a":1}`))
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write([]byte(`{"a":1}`))
	want := hex.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestRunActionBuildsEnvelopeAndHeaders(t *testing.T) {
	var captured ActionRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer key1" {
			t.Fatalf("unexpected auth header %q", got)
		}
		if got := r.Header.Get("X-Nomos-Agent-Id"); got != "agent-http" {
			t.Fatalf("unexpected agent id %q", got)
		}
		if got := r.Header.Get("X-Nomos-SDK-Contract"); got != SupportedHTTPContract {
			t.Fatalf("unexpected contract header %q", got)
		}
		if got := r.Header.Get("X-Nomos-Agent-Signature"); got == "" {
			t.Fatal("expected signature header")
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "ALLOW", ActionID: captured.ActionID, TraceID: captured.TraceID})
	}))
	defer server.Close()

	client, err := NewClient(Config{
		BaseURL:     server.URL,
		BearerToken: "key1",
		AgentID:     "agent-http",
		AgentSecret: "agent-secret",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	resp, err := client.RunAction(context.Background(), NewActionRequest("fs.read", "file://workspace/README.md", map[string]any{}))
	if err != nil {
		t.Fatalf("run action: %v", err)
	}
	if !resp.IsAllowed() {
		t.Fatalf("expected allow response, got %+v", resp)
	}
	if captured.SchemaVersion != "v1" || captured.ActionID == "" || captured.TraceID == "" {
		t.Fatalf("expected defaults in envelope, got %+v", captured)
	}
}

func TestRunActionDecodesApprovalResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DecisionResponse{
			Decision:            "REQUIRE_APPROVAL",
			Reason:              "require_approval_by_rule",
			ApprovalID:          "apr_123",
			ApprovalFingerprint: "fp_123",
		})
	}))
	defer server.Close()
	client, err := NewClient(Config{
		BaseURL:     server.URL,
		BearerToken: "key1",
		AgentID:     "agent-http",
		AgentSecret: "agent-secret",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	resp, err := client.RunAction(context.Background(), NewActionRequest("net.http_request", "url://shop.example.com/refunds/ord-1", map[string]any{"method": "POST"}))
	if err != nil {
		t.Fatalf("run action: %v", err)
	}
	if !resp.RequiresApproval() || resp.ApprovalID != "apr_123" || resp.ApprovalFingerprint != "fp_123" {
		t.Fatalf("unexpected approval response %+v", resp)
	}
}

func TestExplainActionDecodesAdditiveFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"action_id":"act1","trace_id":"trace1","decision":"DENY","reason_code":"deny_by_rule","matched_rule_ids":["deny-1"],"policy_bundle_hash":"hash","engine_version":"dev","assurance_level":"BEST_EFFORT","obligations_preview":{},"future_field":"ok"}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{
		BaseURL:     server.URL,
		BearerToken: "key1",
		AgentID:     "agent-http",
		AgentSecret: "agent-secret",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	resp, err := client.ExplainAction(context.Background(), NewActionRequest("fs.read", "file://workspace/.env", map[string]any{}))
	if err != nil {
		t.Fatalf("explain action: %v", err)
	}
	if resp.Decision != "DENY" || resp.ActionID != "act1" || resp.TraceID != "trace1" {
		t.Fatalf("unexpected explain response %+v", resp)
	}
}

func TestGatewayErrorsAreTyped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "DENY", Reason: "auth_error: invalid signature"})
	}))
	defer server.Close()
	client, err := NewClient(Config{
		BaseURL:     server.URL,
		BearerToken: "key1",
		AgentID:     "agent-http",
		AgentSecret: "agent-secret",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	_, err = client.RunAction(context.Background(), NewActionRequest("fs.read", "file://workspace/README.md", map[string]any{}))
	if err == nil {
		t.Fatal("expected typed error")
	}
	var sdkErr *Error
	if !errors.As(err, &sdkErr) {
		t.Fatalf("expected sdk error, got %T", err)
	}
	if sdkErr.Kind != ErrorKindAuth || sdkErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unexpected error %+v", sdkErr)
	}
}

func TestClientTimeoutReturnsTypedError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"decision":"ALLOW"}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{
		BaseURL:     server.URL,
		BearerToken: "key1",
		AgentID:     "agent-http",
		AgentSecret: "agent-secret",
		Timeout:     5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	_, err = client.RunAction(context.Background(), NewActionRequest("fs.read", "file://workspace/README.md", map[string]any{}))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	var sdkErr *Error
	if !errors.As(err, &sdkErr) || sdkErr.Kind != ErrorKindTimeout {
		t.Fatalf("expected timeout sdk error, got %v", err)
	}
}

func TestRunActionDoesNotRetryByDefault(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "DENY", Reason: "internal_error: upstream unavailable"})
	}))
	defer server.Close()
	client, err := NewClient(Config{
		BaseURL:     server.URL,
		BearerToken: "key1",
		AgentID:     "agent-http",
		AgentSecret: "agent-secret",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	_, err = client.RunAction(context.Background(), NewActionRequest("fs.read", "file://workspace/README.md", map[string]any{}))
	if err == nil {
		t.Fatal("expected gateway error")
	}
	if calls != 1 {
		t.Fatalf("expected exactly one attempt, got %d", calls)
	}
}

func TestDebugLoggingDoesNotLeakSecrets(t *testing.T) {
	logger := &testLogger{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "ALLOW"})
	}))
	defer server.Close()
	client, err := NewClient(Config{
		BaseURL:     server.URL,
		BearerToken: "super-secret-token",
		AgentID:     "agent-http",
		AgentSecret: "super-secret-signing-key",
		Logger:      logger,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	req := NewActionRequest("net.http_request", "url://api.example.com/v1", map[string]any{"authorization": "Bearer hidden"})
	if _, err := client.RunAction(context.Background(), req); err != nil {
		t.Fatalf("run action: %v", err)
	}
	joined := strings.Join(logger.lines, "\n")
	if strings.Contains(joined, "super-secret-token") || strings.Contains(joined, "super-secret-signing-key") || strings.Contains(joined, "authorization") {
		t.Fatalf("expected debug logs to avoid secrets, got %s", joined)
	}
}
