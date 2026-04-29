package mcp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/identity"
)

const reloadForwardedAllowBundle = `{"version":"v1","rules":[` +
	`{"id":"allow-retail","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},` +
	`{"id":"allow-orders","action_type":"mcp.call","resource":"mcp://orders/refund.request","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}` +
	`]}`

func TestMCPReloadUpstreamRegistryAddRemoveWithLiveSession(t *testing.T) {
	retail := reloadTestUpstream(t, "retail")
	orders := reloadTestUpstream(t, "orders")
	server, recorder, bundlePath := newReloadMCPServer(t, []UpstreamServerConfig{retail})
	t.Cleanup(func() { _ = server.Close() })
	session := newDownstreamSession(server, bytes.NewReader(nil), io.Discard)
	if !containsForwardedTool(server.toolsList(), "upstream_retail_refund_request") {
		t.Fatalf("expected retail tool before reload, got %+v", server.toolsList())
	}
	if containsForwardedTool(server.toolsList(), "upstream_orders_refund_request") {
		t.Fatalf("did not expect orders tool before reload, got %+v", server.toolsList())
	}
	retailSession := server.upstream.sessionForTest("retail")
	if retailSession == nil {
		t.Fatal("expected retail upstream session")
	}

	addResult, err := server.Reload(nil, ReloadOptions{
		BundlePaths: []string{bundlePath},
		RuntimeOptions: RuntimeOptions{
			LogLevel:        "error",
			LogFormat:       "text",
			ErrWriter:       io.Discard,
			UpstreamServers: []UpstreamServerConfig{retail, orders},
		},
		Trigger: "test",
	})
	if err != nil {
		t.Fatalf("add reload: %v", err)
	}
	if addResult.Outcome != "success" || !stringSliceContains(addResult.AddedUpstreams, "orders") {
		t.Fatalf("unexpected add reload result: %+v", addResult)
	}
	if server.upstream.sessionForTest("retail") != retailSession {
		t.Fatal("expected unchanged retail upstream session to be reused")
	}
	if !containsForwardedTool(server.toolsList(), "upstream_orders_refund_request") {
		t.Fatalf("expected orders tool after reload, got %+v", server.toolsList())
	}
	ordersResp := server.handleRequestWithSession(Request{
		ID:     "orders-call",
		Method: "upstream_orders_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-2", "reason": "reload"}),
	}, session)
	assertForwardedAllow(t, ordersResp, "ORD-2")

	removeResult, err := server.Reload(nil, ReloadOptions{
		BundlePaths: []string{bundlePath},
		RuntimeOptions: RuntimeOptions{
			LogLevel:        "error",
			LogFormat:       "text",
			ErrWriter:       io.Discard,
			UpstreamServers: []UpstreamServerConfig{orders},
		},
		Trigger: "test",
	})
	if err != nil {
		t.Fatalf("remove reload: %v", err)
	}
	if removeResult.Outcome != "success" || !stringSliceContains(removeResult.RemovedUpstreams, "retail") {
		t.Fatalf("unexpected remove reload result: %+v", removeResult)
	}
	if containsForwardedTool(server.toolsList(), "upstream_retail_refund_request") {
		t.Fatalf("retail tool should be removed, got %+v", server.toolsList())
	}
	retailResp := server.handleRequestWithSession(Request{
		ID:     "retail-call",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1", "reason": "removed"}),
	}, session)
	if retailResp.Error != "method_not_found" {
		t.Fatalf("expected removed retail tool to fail method_not_found, got %+v", retailResp)
	}
	ordersResp = server.handleRequestWithSession(Request{
		ID:     "orders-call-2",
		Method: "upstream_orders_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-3", "reason": "still-live"}),
	}, session)
	assertForwardedAllow(t, ordersResp, "ORD-3")
	if !hasMCPReloadAuditEvent(recorder.snapshot(), "success") {
		t.Fatalf("expected success reload audit event, got %+v", recorder.snapshot())
	}
}

func TestMCPReloadMalformedBundlePreservesState(t *testing.T) {
	retail := reloadTestUpstream(t, "retail")
	server, recorder, bundlePath := newReloadMCPServer(t, []UpstreamServerConfig{retail})
	t.Cleanup(func() { _ = server.Close() })
	oldHash, _ := server.policyMetadata()
	oldVersion := server.upstream.registryVersionSnapshot()
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[`), 0o600); err != nil {
		t.Fatalf("write malformed bundle: %v", err)
	}
	result, err := server.Reload(nil, ReloadOptions{
		BundlePaths: []string{bundlePath},
		RuntimeOptions: RuntimeOptions{
			LogLevel:        "error",
			LogFormat:       "text",
			ErrWriter:       io.Discard,
			UpstreamServers: []UpstreamServerConfig{retail},
		},
		Trigger: "test",
	})
	if err == nil {
		t.Fatal("expected reload failure")
	}
	if result.Outcome != "failure" || result.PolicyBundleHash != oldHash {
		t.Fatalf("unexpected failure result: %+v", result)
	}
	if got, _ := server.policyMetadata(); got != oldHash {
		t.Fatalf("expected old policy hash after failed reload, got %s want %s", got, oldHash)
	}
	if got := server.upstream.registryVersionSnapshot(); got != oldVersion {
		t.Fatalf("expected registry version unchanged after failed reload, got %d want %d", got, oldVersion)
	}
	if !containsForwardedTool(server.toolsList(), "upstream_retail_refund_request") {
		t.Fatalf("expected old retail tool after failed reload, got %+v", server.toolsList())
	}
	if !hasMCPReloadAuditEvent(recorder.snapshot(), "failure") {
		t.Fatalf("expected failure reload audit event, got %+v", recorder.snapshot())
	}
}

func TestDownstreamHTTPAdminReloadIsAuthenticated(t *testing.T) {
	server, _, _ := newReloadMCPServer(t, nil)
	t.Cleanup(func() { _ = server.Close() })
	auth, err := identity.NewAuthenticator(identity.AuthConfig{
		APIKeys:     map[string]string{"reload-key": "system"},
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	httpServer, err := NewDownstreamHTTPServer(server, auth, "127.0.0.1:0", "nomos", 120)
	if err != nil {
		t.Fatalf("new downstream http: %v", err)
	}
	called := 0
	httpServer.SetReloadHandler(func(ctx context.Context) (ReloadResult, error) {
		called++
		return ReloadResult{Outcome: "success", Trigger: "admin", PolicyBundleHash: "hash", RegistryVersion: 1}, nil
	})
	if err := httpServer.Start(); err != nil {
		t.Fatalf("start downstream http: %v", err)
	}
	t.Cleanup(func() { _ = httpServer.Shutdown(context.Background()) })

	unauthReq, err := http.NewRequest(http.MethodPost, "http://"+httpServer.Addr()+"/admin/reload", nil)
	if err != nil {
		t.Fatalf("build unauth reload request: %v", err)
	}
	unauthResp, err := http.DefaultClient.Do(unauthReq)
	if err != nil {
		t.Fatalf("unauth reload request: %v", err)
	}
	_ = unauthResp.Body.Close()
	if unauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthenticated reload to be 401, got %d", unauthResp.StatusCode)
	}
	authReq, err := http.NewRequest(http.MethodPost, "http://"+httpServer.Addr()+"/admin/reload", nil)
	if err != nil {
		t.Fatalf("build auth reload request: %v", err)
	}
	authReq.Header.Set("Authorization", "Bearer reload-key")
	authResp, err := http.DefaultClient.Do(authReq)
	if err != nil {
		t.Fatalf("auth reload request: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusOK {
		t.Fatalf("expected authenticated reload to be 200, got %d", authResp.StatusCode)
	}
	if called != 1 {
		t.Fatalf("expected reload handler once, got %d", called)
	}
}

func newReloadMCPServer(t *testing.T, upstreams []UpstreamServerConfig) (*Server, *recordingSink, string) {
	t.Helper()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(reloadForwardedAllowBundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	recorder := &recordingSink{}
	server, err := NewServerWithRuntimeOptionsAndRecorder(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:        "error",
		LogFormat:       "text",
		ErrWriter:       io.Discard,
		UpstreamServers: upstreams,
	}, recorder)
	if err != nil {
		t.Fatalf("new mcp server: %v", err)
	}
	server.upstream.setBackoffForTest(0, 0)
	return server, recorder, bundlePath
}

func reloadTestUpstream(t *testing.T, name string) UpstreamServerConfig {
	t.Helper()
	return UpstreamServerConfig{
		Name:      name,
		Transport: "stdio",
		Command:   os.Args[0],
		Args:      []string{"-test.run=TestUpstreamMCPHelperProcess", "--", "retail"},
		Env:       map[string]string{"GO_WANT_UPSTREAM_MCP_HELPER": "1"},
		Workdir:   t.TempDir(),
	}
}

func assertForwardedAllow(t *testing.T, resp Response, wantText string) {
	t.Helper()
	if resp.Error != "" {
		t.Fatalf("unexpected response error: %+v", resp)
	}
	result, ok := resp.Result.(action.Response)
	if !ok {
		t.Fatalf("expected action.Response, got %T", resp.Result)
	}
	if result.Decision != "ALLOW" || !strings.Contains(result.Output, wantText) {
		t.Fatalf("expected allow output containing %q, got %+v", wantText, result)
	}
}

func hasMCPReloadAuditEvent(events []audit.Event, outcome string) bool {
	for _, event := range events {
		if event.EventType == "runtime.reload" && strings.EqualFold(event.Decision, outcome) {
			return true
		}
	}
	return false
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
