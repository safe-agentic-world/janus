package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/identity"
)

type downstreamHTTPRecordSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *downstreamHTTPRecordSink) WriteEvent(event audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *downstreamHTTPRecordSink) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]audit.Event, len(r.events))
	copy(out, r.events)
	return out
}

func TestDownstreamHTTPConcurrentSessionsRemainIsolated(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[
{"id":"allow-read-alice","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["alice"],"agents":["nomos"],"environments":["dev"]},
{"id":"allow-write-bob","action_type":"fs.write","resource":"file://workspace/**","decision":"ALLOW","principals":["bob"],"agents":["nomos"],"environments":["dev"]}
]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	ts := newTestDownstreamHTTPServer(t, downstreamHTTPServerOptions{
		bundlePath: bundlePath,
		apiKeys: map[string]string{
			"alice-key": "alice",
			"bob-key":   "bob",
		},
	})

	type result struct {
		sessionID string
		tools     []string
		err       error
	}
	results := make(chan result, 2)
	for _, token := range []string{"alice-key", "bob-key"} {
		go func(token string) {
			sessionID, _, err := ts.initialize(token)
			if err != nil {
				results <- result{err: err}
				return
			}
			body, status, err := ts.rpc(token, sessionID, map[string]any{
				"jsonrpc": "2.0",
				"id":      "tools",
				"method":  "tools/list",
				"params":  map[string]any{},
			})
			if err != nil {
				results <- result{err: err}
				return
			}
			if status != http.StatusOK {
				results <- result{err: io.ErrUnexpectedEOF}
				return
			}
			results <- result{sessionID: sessionID, tools: toolNamesFromToolsList(t, body)}
		}(token)
	}

	var aliceSessionID, bobSessionID string
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("session flow failed: %v", result.err)
		}
		if contains(result.tools, "nomos_fs_read") {
			aliceSessionID = result.sessionID
			if contains(result.tools, "nomos_fs_write") {
				t.Fatalf("alice should not see fs_write, got %+v", result.tools)
			}
		}
		if contains(result.tools, "nomos_fs_write") {
			bobSessionID = result.sessionID
			if contains(result.tools, "nomos_fs_read") {
				t.Fatalf("bob should not see fs_read, got %+v", result.tools)
			}
		}
	}
	if aliceSessionID == "" || bobSessionID == "" || aliceSessionID == bobSessionID {
		t.Fatalf("expected distinct sessions, got alice=%q bob=%q", aliceSessionID, bobSessionID)
	}

	body, status, err := ts.rpc("bob-key", aliceSessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      "cross",
		"method":  "tools/list",
		"params":  map[string]any{},
	})
	if err != nil {
		t.Fatalf("cross-session request: %v", err)
	}
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-session request, got %d body=%s", status, string(body))
	}
	var authErr map[string]any
	if err := json.Unmarshal(body, &authErr); err != nil {
		t.Fatalf("decode auth error: %v", err)
	}
	if authErr["error"] != "session_identity_mismatch" {
		t.Fatalf("expected stable session mismatch error, got %+v", authErr)
	}
}

func TestDownstreamHTTPRejectsUnauthenticatedSessions(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["alice"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	recorder := &downstreamHTTPRecordSink{}
	ts := newTestDownstreamHTTPServer(t, downstreamHTTPServerOptions{
		bundlePath: bundlePath,
		apiKeys: map[string]string{
			"alice-key": "alice",
		},
		recorder: recorder,
	})

	body, status, err := ts.rpc("", "", map[string]any{
		"jsonrpc": "2.0",
		"id":      "init",
		"method":  "initialize",
		"params":  map[string]any{"capabilities": map[string]any{}},
	})
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", status, string(body))
	}
	var authErr map[string]any
	if err := json.Unmarshal(body, &authErr); err != nil {
		t.Fatalf("decode auth error: %v", err)
	}
	if authErr["error"] != "auth_error" || authErr["message"] == "" {
		t.Fatalf("expected stable auth error shape, got %+v", authErr)
	}
	for _, event := range recorder.snapshot() {
		if event.EventType == "action.decision" {
			t.Fatalf("unauthenticated request should not reach policy evaluation, got %+v", event)
		}
	}
}

func TestDownstreamHTTPAuditIncludesPrincipalAndTransportMetadata(t *testing.T) {
	dir := t.TempDir()
	readmePath := filepath.Join(dir, "README.md")
	if err := os.WriteFile(readmePath, []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["alice"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	recorder := &downstreamHTTPRecordSink{}
	ts := newTestDownstreamHTTPServer(t, downstreamHTTPServerOptions{
		bundlePath: bundlePath,
		apiKeys: map[string]string{
			"alice-key": "alice",
		},
		recorder:      recorder,
		workspaceRoot: dir,
	})

	sessionID, _, err := ts.initialize("alice-key")
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	body, status, err := ts.rpc("alice-key", sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      "read",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "nomos_fs_read",
			"arguments": map[string]any{
				"resource": "README.md",
			},
		},
	})
	if err != nil {
		t.Fatalf("fs_read call: %v", err)
	}
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"isError":false`)) {
		t.Fatalf("expected successful call, got status=%d body=%s", status, string(body))
	}

	var decisionFound bool
	var completed audit.Event
	for _, event := range recorder.snapshot() {
		if event.EventType == "action.decision" {
			decisionFound = true
			if event.Principal != "alice" || event.Agent != "nomos" || event.Environment != "dev" {
				t.Fatalf("unexpected decision identity: %+v", event)
			}
		}
		if event.EventType == "action.completed" {
			completed = event
		}
	}
	if !decisionFound {
		t.Fatal("expected action.decision audit event")
	}
	if completed.EventType == "" {
		t.Fatal("expected action.completed audit event")
	}
	if completed.Principal != "alice" {
		t.Fatalf("expected completed principal alice, got %+v", completed)
	}
	if got := completed.ExecutorMetadata["downstream_transport"]; got != "streamable_http" {
		t.Fatalf("expected downstream transport metadata, got %+v", completed.ExecutorMetadata)
	}
	if got := completed.ExecutorMetadata["downstream_session_id"]; got != sessionID {
		t.Fatalf("expected downstream session id %q, got %+v", sessionID, completed.ExecutorMetadata)
	}
}

func TestDownstreamHTTPMatchesStdioDecisionAndFingerprint(t *testing.T) {
	dir := t.TempDir()
	readmePath := filepath.Join(dir, "README.md")
	if err := os.WriteFile(readmePath, []byte("parity\n"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["alice"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	stdioRecorder := &downstreamHTTPRecordSink{}
	stdioServer, err := NewServerWithRuntimeOptionsAndRecorder(bundlePath, identity.VerifiedIdentity{
		Principal:   "alice",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 32, false, false, "none", RuntimeOptions{}, stdioRecorder)
	if err != nil {
		t.Fatalf("new stdio server: %v", err)
	}
	t.Cleanup(func() { _ = stdioServer.Close() })
	stdioResp := stdioServer.handleRPCRequest(rpcRequest{
		JSONRPC: "2.0",
		ID:      mustJSONRaw(t, "stdio"),
		Method:  "tools/call",
		Params: mustJSONRaw(t, map[string]any{
			"name": "nomos_fs_read",
			"arguments": map[string]any{
				"resource": "README.md",
			},
		}),
	}, newDownstreamSession(stdioServer, strings.NewReader(""), io.Discard))
	if stdioResp == nil || stdioResp.Error != nil {
		t.Fatalf("expected stdio success, got %+v", stdioResp)
	}
	stdioDecision := findDecisionEvent(t, stdioRecorder.snapshot())

	httpRecorder := &downstreamHTTPRecordSink{}
	ts := newTestDownstreamHTTPServer(t, downstreamHTTPServerOptions{
		bundlePath: bundlePath,
		apiKeys: map[string]string{
			"alice-key": "alice",
		},
		recorder:      httpRecorder,
		workspaceRoot: dir,
	})
	sessionID, _, err := ts.initialize("alice-key")
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	body, status, err := ts.rpc("alice-key", sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      "http",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "nomos_fs_read",
			"arguments": map[string]any{
				"resource": "README.md",
			},
		},
	})
	if err != nil {
		t.Fatalf("http call: %v", err)
	}
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"isError":false`)) {
		t.Fatalf("expected HTTP success, got status=%d body=%s", status, string(body))
	}
	httpDecision := findDecisionEvent(t, httpRecorder.snapshot())

	if stdioDecision.Decision != httpDecision.Decision {
		t.Fatalf("expected same decision, stdio=%q http=%q", stdioDecision.Decision, httpDecision.Decision)
	}
	if stdioDecision.Fingerprint != httpDecision.Fingerprint {
		t.Fatalf("expected same fingerprint, stdio=%q http=%q", stdioDecision.Fingerprint, httpDecision.Fingerprint)
	}
}

type downstreamHTTPServerOptions struct {
	bundlePath    string
	apiKeys       map[string]string
	recorder      audit.Recorder
	rateLimit     int
	workspaceRoot string
}

type testDownstreamHTTPServer struct {
	t       *testing.T
	baseURL string
	client  *http.Client
}

func newTestDownstreamHTTPServer(t *testing.T, opts downstreamHTTPServerOptions) *testDownstreamHTTPServer {
	t.Helper()
	workspaceRoot := opts.workspaceRoot
	if workspaceRoot == "" {
		workspaceRoot = filepath.Dir(opts.bundlePath)
	}
	server, err := NewServerWithRuntimeOptionsAndRecorder(opts.bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, workspaceRoot, 4096, 64, false, false, "none", RuntimeOptions{}, opts.recorder)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	auth, err := identity.NewAuthenticator(identity.AuthConfig{
		APIKeys:      opts.apiKeys,
		Environment:  "dev",
		AgentSecrets: map[string]string{"nomos": "unused"},
	})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	httpServer, err := NewDownstreamHTTPServer(server, auth, "127.0.0.1:0", "nomos", opts.rateLimit)
	if err != nil {
		t.Fatalf("new downstream http server: %v", err)
	}
	if err := httpServer.Start(); err != nil {
		t.Fatalf("start downstream http server: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
		_ = server.Close()
	})
	return &testDownstreamHTTPServer{
		t:       t,
		baseURL: "http://" + httpServer.Addr() + "/mcp",
		client:  &http.Client{Timeout: 2 * time.Second},
	}
}

func (s *testDownstreamHTTPServer) initialize(token string) (string, []byte, error) {
	body, headers, err := s.rpcWithHeaders(token, "", map[string]any{
		"jsonrpc": "2.0",
		"id":      "init",
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": SupportedProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"clientInfo":      map[string]any{"name": "test", "version": "1.0.0"},
		},
	})
	if err != nil {
		return "", nil, err
	}
	sessionID := strings.TrimSpace(headers.Get(downstreamHTTPSessionHeader))
	if sessionID == "" {
		return "", nil, io.ErrUnexpectedEOF
	}
	return sessionID, body, nil
}

func (s *testDownstreamHTTPServer) rpc(token, sessionID string, payload map[string]any) ([]byte, int, error) {
	body, status, _, err := s.rpcWithStatusHeaders(token, sessionID, payload)
	return body, status, err
}

func (s *testDownstreamHTTPServer) deleteSession(token, sessionID string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodDelete, s.baseURL, nil)
	if err != nil {
		return nil, 0, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if sessionID != "" {
		req.Header.Set(downstreamHTTPSessionHeader, sessionID)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

func (s *testDownstreamHTTPServer) rpcWithHeaders(token, sessionID string, payload map[string]any) ([]byte, http.Header, error) {
	body, status, headers, err := s.rpcWithStatusHeaders(token, sessionID, payload)
	if err != nil {
		return nil, nil, err
	}
	if status != http.StatusOK {
		return body, headers, io.ErrUnexpectedEOF
	}
	return body, headers, nil
}

func (s *testDownstreamHTTPServer) rpcWithStatusHeaders(token, sessionID string, payload map[string]any) ([]byte, int, http.Header, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, s.baseURL, bytes.NewReader(data))
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if sessionID != "" {
		req.Header.Set(downstreamHTTPSessionHeader, sessionID)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, resp.Header.Clone(), err
}

func toolNamesFromToolsList(t *testing.T, body []byte) []string {
	t.Helper()
	var resp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode tools list: %v body=%s", err, string(body))
	}
	names := make([]string, 0, len(resp.Result.Tools))
	for _, tool := range resp.Result.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func mustJSONRaw(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal raw json: %v", err)
	}
	return data
}

func findDecisionEvent(t *testing.T, events []audit.Event) audit.Event {
	t.Helper()
	for _, event := range events {
		if event.EventType == "action.decision" {
			return event
		}
	}
	t.Fatal("missing action.decision event")
	return audit.Event{}
}

func TestDownstreamHTTPSessionRateLimit(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["alice"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	ts := newTestDownstreamHTTPServer(t, downstreamHTTPServerOptions{
		bundlePath: bundlePath,
		apiKeys: map[string]string{
			"alice-key": "alice",
		},
		rateLimit: 1,
	})

	sessionID, _, err := ts.initialize("alice-key")
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	body, status, err := ts.rpc("alice-key", sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      "tools",
		"method":  "tools/list",
		"params":  map[string]any{},
	})
	if err != nil {
		t.Fatalf("first tools/list: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected first request allowed, got %d body=%s", status, string(body))
	}

	body, status, err = ts.rpc("alice-key", sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      "again",
		"method":  "tools/list",
		"params":  map[string]any{},
	})
	if err != nil {
		t.Fatalf("second tools/list: %v", err)
	}
	if status != http.StatusTooManyRequests {
		t.Fatalf("expected rate-limited second request, got %d body=%s", status, string(body))
	}
	var limitErr map[string]any
	if err := json.Unmarshal(body, &limitErr); err != nil {
		t.Fatalf("decode rate limit error: %v", err)
	}
	if limitErr["error"] != "rate_limited" {
		t.Fatalf("expected stable rate limit error, got %+v", limitErr)
	}
}

func TestDownstreamHTTPSessionDeleteInvalidatesResumption(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["alice"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	ts := newTestDownstreamHTTPServer(t, downstreamHTTPServerOptions{
		bundlePath: bundlePath,
		apiKeys: map[string]string{
			"alice-key": "alice",
		},
	})

	sessionID, _, err := ts.initialize("alice-key")
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	body, status, err := ts.rpc("alice-key", sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      "tools",
		"method":  "tools/list",
		"params":  map[string]any{},
	})
	if err != nil {
		t.Fatalf("tools/list before delete: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("expected session to work before delete, got %d body=%s", status, string(body))
	}

	body, status, err = ts.deleteSession("alice-key", sessionID)
	if err != nil {
		t.Fatalf("delete session: %v", err)
	}
	if status != http.StatusNoContent {
		t.Fatalf("expected 204 on delete, got %d body=%s", status, string(body))
	}

	body, status, err = ts.rpc("alice-key", sessionID, map[string]any{
		"jsonrpc": "2.0",
		"id":      "again",
		"method":  "tools/list",
		"params":  map[string]any{},
	})
	if err != nil {
		t.Fatalf("tools/list after delete: %v", err)
	}
	if status != http.StatusBadRequest {
		t.Fatalf("expected invalid session after delete, got %d body=%s", status, string(body))
	}
	var sessionErr map[string]any
	if err := json.Unmarshal(body, &sessionErr); err != nil {
		t.Fatalf("decode invalid session error: %v", err)
	}
	if sessionErr["error"] != "invalid_session" {
		t.Fatalf("expected invalid_session error, got %+v", sessionErr)
	}
}
