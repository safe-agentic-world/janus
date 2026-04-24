package mcp

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/identity"
)

type upstreamHTTPTestServer struct {
	t          *testing.T
	httpServer *httptest.Server
	streaming  bool
	authHeader string
	authValue  string
	toolOutput string
	callCount  atomic.Int32
	authCalls  atomic.Int32
}

func newUpstreamHTTPTestServer(t *testing.T, streaming bool, tlsMode string) *upstreamHTTPTestServer {
	t.Helper()
	srv := &upstreamHTTPTestServer{t: t, streaming: streaming, toolOutput: "refund accepted for ORD-1001\nreason: damaged"}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", srv.handle)
	switch tlsMode {
	case "tls":
		srv.httpServer = httptest.NewTLSServer(mux)
	case "plaintext":
		srv.httpServer = httptest.NewServer(mux)
	default:
		t.Fatalf("unknown tls mode %q", tlsMode)
	}
	t.Cleanup(func() { srv.httpServer.Close() })
	return srv
}

func (s *upstreamHTTPTestServer) requireAuth(header, value string) {
	s.authHeader = header
	s.authValue = value
}

func (s *upstreamHTTPTestServer) endpoint() string {
	return s.httpServer.URL + "/mcp"
}

func (s *upstreamHTTPTestServer) handle(w http.ResponseWriter, r *http.Request) {
	if s.authHeader != "" {
		if r.Header.Get(s.authHeader) != s.authValue {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.authCalls.Add(1)
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	method, _ := req["method"].(string)
	id := req["id"]
	switch method {
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
		return
	case "initialize":
		s.writeResponse(w, id, map[string]any{
			"protocolVersion": SupportedProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "http-upstream", "version": "test"},
		})
	case "tools/list":
		s.writeResponse(w, id, map[string]any{
			"tools": []map[string]any{{
				"name":        "refund.request",
				"description": "Submit a retail refund request.",
				"inputSchema": map[string]any{
					"type":       "object",
					"properties": map[string]any{"order_id": map[string]any{"type": "string"}},
					"required":   []string{"order_id"},
				},
			}},
		})
	case "tools/call":
		s.callCount.Add(1)
		s.writeResponse(w, id, map[string]any{
			"content": []map[string]any{{"type": "text", "text": s.toolOutput}},
			"isError": false,
		})
	default:
		s.writeResponse(w, id, map[string]any{})
	}
}

func (s *upstreamHTTPTestServer) writeResponse(w http.ResponseWriter, id any, result any) {
	payload := map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
	data, _ := json.Marshal(payload)
	if s.streaming {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		// split into two data lines for streaming delivery
		fmt.Fprintf(w, ": keep-alive\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		fmt.Fprintf(w, "data: %s\n\n", data)
		if flusher != nil {
			flusher.Flush()
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func newHTTPUpstreamNomosServer(t *testing.T, bundle string, upstream UpstreamServerConfig, tlsRoots *tls.Config) *Server {
	t.Helper()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:        "error",
		LogFormat:       "text",
		ErrWriter:       io.Discard,
		UpstreamServers: []UpstreamServerConfig{upstream},
	})
	if err != nil {
		t.Fatalf("new http upstream server: %v", err)
	}
	_ = tlsRoots
	return server
}

const retailAllowBundle = `{"version":"v1","rules":[{"id":"allow-refund","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`

func TestUpstreamStreamableHTTPSingleResponse(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	server := newHTTPUpstreamNomosServer(t, retailAllowBundle, UpstreamServerConfig{
		Name:        "retail",
		Transport:   "streamable_http",
		Endpoint:    upstream.endpoint(),
		TLSInsecure: true,
	}, nil)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleRequest(Request{
		ID:     "http",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "damaged"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected error: %+v", resp)
	}
	result, ok := resp.Result.(action.Response)
	if !ok || result.Decision != "ALLOW" || result.ExecutionMode != "mcp_forwarded" {
		t.Fatalf("expected forwarded ALLOW, got %+v", resp.Result)
	}
	if !strings.Contains(result.Output, "refund accepted for ORD-1001") {
		t.Fatalf("expected forwarded output, got %q", result.Output)
	}
	if upstream.callCount.Load() == 0 {
		t.Fatal("expected upstream tools/call to be invoked")
	}
}

func TestUpstreamStreamableHTTPStreamedResponse(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, true, "plaintext")
	server := newHTTPUpstreamNomosServer(t, retailAllowBundle, UpstreamServerConfig{
		Name:        "retail",
		Transport:   "streamable_http",
		Endpoint:    upstream.endpoint(),
		TLSInsecure: true,
	}, nil)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleRequest(Request{
		ID:     "stream",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "damaged"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected error: %+v", resp)
	}
	result := resp.Result.(action.Response)
	if result.Decision != "ALLOW" || !strings.Contains(result.Output, "refund accepted for ORD-1001") {
		t.Fatalf("unexpected streamed response: %+v", result)
	}
}

func TestUpstreamStreamableHTTPRedactsResponse(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, true, "plaintext")
	upstream.toolOutput = "refund receipt AKIA1234567890ABCDEF accepted"
	server := newHTTPUpstreamNomosServer(t, retailAllowBundle, UpstreamServerConfig{
		Name:        "retail",
		Transport:   "streamable_http",
		Endpoint:    upstream.endpoint(),
		TLSInsecure: true,
	}, nil)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleRequest(Request{
		ID:     "redact",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "damaged"}),
	})
	result := resp.Result.(action.Response)
	if strings.Contains(result.Output, "AKIA1234567890ABCDEF") {
		t.Fatalf("expected secret to be redacted from forwarded output, got %q", result.Output)
	}
}

func TestUpstreamStreamableHTTPTLSFailureFailsClosed(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "tls")
	bundleDir := t.TempDir()
	bundlePath := filepath.Join(bundleDir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(retailAllowBundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	_, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, bundleDir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "error",
		LogFormat: "text",
		ErrWriter: io.Discard,
		UpstreamServers: []UpstreamServerConfig{{
			Name:      "retail",
			Transport: "streamable_http",
			Endpoint:  upstream.endpoint(),
		}},
	})
	if err == nil {
		t.Fatal("expected TLS verification failure to fail closed")
	}
	if !strings.Contains(err.Error(), "upstream server \"retail\"") {
		t.Fatalf("expected stage-aware upstream error, got %v", err)
	}
}

func TestUpstreamStreamableHTTPAllowlistViolationFailsClosed(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(retailAllowBundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	_, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "error",
		LogFormat: "text",
		ErrWriter: io.Discard,
		UpstreamServers: []UpstreamServerConfig{{
			Name:         "retail",
			Transport:    "streamable_http",
			Endpoint:     upstream.endpoint(),
			TLSInsecure:  true,
			AllowedHosts: []string{"not-the-test-host.invalid"},
		}},
	})
	if err == nil {
		t.Fatal("expected allowlist violation to fail closed")
	}
	if !strings.Contains(err.Error(), "allowed_hosts") {
		t.Fatalf("expected allowed_hosts error, got %v", err)
	}
	if upstream.callCount.Load() != 0 {
		t.Fatal("upstream should not have been reached due to allowlist pre-check")
	}
}

func TestUpstreamStreamableHTTPInjectsAuthHeaders(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	upstream.requireAuth("Authorization", "Bearer secret-token")
	server := newHTTPUpstreamNomosServer(t, retailAllowBundle, UpstreamServerConfig{
		Name:        "retail",
		Transport:   "streamable_http",
		Endpoint:    upstream.endpoint(),
		TLSInsecure: true,
		AuthType:    "bearer",
		AuthToken:   "secret-token",
	}, nil)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleRequest(Request{
		ID:     "auth",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "damaged"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected error: %+v", resp)
	}
	if upstream.authCalls.Load() == 0 {
		t.Fatal("expected upstream to see authenticated request")
	}
}

func TestUpstreamStreamableHTTPAuthFailureFailsClosed(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	upstream.requireAuth("Authorization", "Bearer good-token")
	bundleDir := t.TempDir()
	bundlePath := filepath.Join(bundleDir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(retailAllowBundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	_, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, bundleDir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "error",
		LogFormat: "text",
		ErrWriter: io.Discard,
		UpstreamServers: []UpstreamServerConfig{{
			Name:        "retail",
			Transport:   "streamable_http",
			Endpoint:    upstream.endpoint(),
			TLSInsecure: true,
			AuthType:    "bearer",
			AuthToken:   "wrong-token",
		}},
	})
	if err == nil {
		t.Fatal("expected upstream auth failure to fail closed")
	}
	if !strings.Contains(err.Error(), "auth") && !strings.Contains(err.Error(), "401") && !strings.Contains(err.Error(), "Unauthorized") {
		t.Fatalf("expected auth-related error, got %v", err)
	}
}

func TestUpstreamStreamableHTTPPolicyIdentityParity(t *testing.T) {
	// Verify that the normalized action identity used for policy/audit is
	// identical whether the upstream server is stdio or streamable_http.
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")

	denyBundle := `{"version":"v1","rules":[{"id":"deny-refund","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"DENY","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	server := newHTTPUpstreamNomosServer(t, denyBundle, UpstreamServerConfig{
		Name:        "retail",
		Transport:   "streamable_http",
		Endpoint:    upstream.endpoint(),
		TLSInsecure: true,
	}, nil)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleRequest(Request{
		ID:     "parity",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "damaged"}),
	})
	result := resp.Result.(action.Response)
	if result.Decision != "DENY" {
		t.Fatalf("expected DENY via mcp.call identity parity, got %+v", result)
	}
	if upstream.callCount.Load() != 0 {
		t.Fatal("denied call should not reach upstream")
	}
}

func TestUpstreamStreamableHTTPRejectsInsecureHTTPWithoutOptIn(t *testing.T) {
	u := &url.URL{Scheme: "http", Host: "example.internal:9000", Path: "/mcp"}
	bundleDir := t.TempDir()
	bundlePath := filepath.Join(bundleDir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(retailAllowBundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	_, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, bundleDir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "error",
		LogFormat: "text",
		ErrWriter: io.Discard,
		UpstreamServers: []UpstreamServerConfig{{
			Name:      "retail",
			Transport: "streamable_http",
			Endpoint:  u.String(),
		}},
	})
	if err == nil {
		t.Fatal("expected plaintext http to be rejected without tls_insecure")
	}
	if !strings.Contains(err.Error(), "https") && !strings.Contains(err.Error(), "tls_insecure") {
		t.Fatalf("expected tls-related failure, got %v", err)
	}
}

func TestReadSSEEventParsesDataLines(t *testing.T) {
	raw := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{}}\n\n"
	evt, err := readSSEEvent(newBufReader(raw))
	if err != nil {
		t.Fatalf("read sse event: %v", err)
	}
	if evt.event != "message" || !strings.Contains(evt.data, "\"result\"") {
		t.Fatalf("unexpected event: %+v", evt)
	}
}

func newBufReader(s string) *bufio.Reader { return bufio.NewReader(bytes.NewBufferString(s)) }
