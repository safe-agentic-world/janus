package mcp

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/identity"
)

type upstreamHTTPTestServer struct {
	t                  *testing.T
	httpServer         *httptest.Server
	streaming          bool
	hangStreamResponse bool
	authHeader         string
	authValue          string
	toolOutput         string
	callCount          atomic.Int32
	authCalls          atomic.Int32
	protoCalls         atomic.Int32
	deleteSeen         atomic.Int32
	eventSeq           atomic.Int64
	extraTool          atomic.Bool
	sessionID          string

	sseMu        sync.Mutex
	sseWriter    http.ResponseWriter
	sseFlush     http.Flusher
	sseReady     chan struct{}
	ssePostURL   string
	streamMu     sync.Mutex
	streamWriter http.ResponseWriter
	streamFlush  http.Flusher
	streamReady  chan struct{}
}

func newUpstreamHTTPTestServer(t *testing.T, streaming bool, tlsMode string) *upstreamHTTPTestServer {
	t.Helper()
	srv := &upstreamHTTPTestServer{
		t:           t,
		streaming:   streaming,
		toolOutput:  "refund accepted for ORD-1001\nreason: damaged",
		sessionID:   "test-session-id",
		sseReady:    make(chan struct{}),
		streamReady: make(chan struct{}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", srv.handle)
	mux.HandleFunc("/sse/messages", srv.handleLegacySSEPost)
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
	if got := r.Header.Get("MCP-Protocol-Version"); got == upstreamHTTPProtocolVersion {
		s.protoCalls.Add(1)
	}
	if s.authHeader != "" {
		if r.Header.Get(s.authHeader) != s.authValue {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.authCalls.Add(1)
	}
	if r.Method == http.MethodDelete {
		if r.Header.Get("MCP-Session-Id") == s.sessionID {
			s.deleteSeen.Add(1)
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if r.Method == http.MethodGet {
		if r.Header.Get("MCP-Session-Id") != "" {
			s.handleStreamableHTTPGet(w, r)
		} else {
			s.handleLegacySSEGet(w, r)
		}
		return
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
		w.Header().Set("MCP-Session-Id", s.sessionID)
		s.writeResponse(w, id, map[string]any{
			"protocolVersion": upstreamHTTPProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": true}},
			"serverInfo":      map[string]any{"name": "http-upstream", "version": "test"},
		})
	case "tools/list":
		s.writeResponse(w, id, map[string]any{"tools": s.toolsList()})
	case "tools/call":
		s.callCount.Add(1)
		if s.streaming && s.hangStreamResponse {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			flusher, ok := w.(http.Flusher)
			if !ok {
				s.t.Fatal("expected streamable HTTP response writer to support flushing")
			}
			fmt.Fprint(w, "event: message\n")
			flusher.Flush()
			<-r.Context().Done()
			return
		}
		s.writeResponse(w, id, map[string]any{
			"content": []map[string]any{{"type": "text", "text": s.toolOutput}},
			"isError": false,
		})
	default:
		s.writeResponse(w, id, map[string]any{})
	}
}

func (s *upstreamHTTPTestServer) toolsList() []map[string]any {
	tools := []map[string]any{{
		"name":        "refund.request",
		"description": "Submit a retail refund request.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{"order_id": map[string]any{"type": "string"}},
			"required":   []string{"order_id"},
		},
	}}
	if s.extraTool.Load() {
		tools = append(tools, map[string]any{
			"name":        "refund.status",
			"description": "Fetch a retail refund status.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"order_id": map[string]any{"type": "string"}},
				"required":   []string{"order_id"},
			},
		})
	}
	return tools
}

func (s *upstreamHTTPTestServer) handleLegacySSEGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.t.Fatal("expected SSE response writer to support flushing")
	}
	s.sseMu.Lock()
	s.sseWriter = w
	s.sseFlush = flusher
	s.sseMu.Unlock()
	s.ssePostURL = s.httpServer.URL + "/sse/messages"
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", s.ssePostURL)
	flusher.Flush()
	select {
	case <-s.sseReady:
	default:
		close(s.sseReady)
	}
	<-r.Context().Done()
}

func (s *upstreamHTTPTestServer) handleLegacySSEPost(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("MCP-Protocol-Version"); got == upstreamHTTPProtocolVersion {
		s.protoCalls.Add(1)
	}
	if s.authHeader != "" {
		if r.Header.Get(s.authHeader) != s.authValue {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.authCalls.Add(1)
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
	if method == "notifications/initialized" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var result any
	switch method {
	case "initialize":
		result = map[string]any{
			"protocolVersion": upstreamHTTPProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": true}},
			"serverInfo":      map[string]any{"name": "legacy-sse-upstream", "version": "test"},
		}
	case "tools/list":
		result = map[string]any{"tools": s.toolsList()}
	case "tools/call":
		s.callCount.Add(1)
		result = map[string]any{
			"content": []map[string]any{{"type": "text", "text": s.toolOutput}},
			"isError": false,
		}
	default:
		result = map[string]any{}
	}
	w.WriteHeader(http.StatusAccepted)
	s.emitLegacySSEMessage(id, result)
}

func (s *upstreamHTTPTestServer) handleStreamableHTTPGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.t.Fatal("expected streamable HTTP response writer to support flushing")
	}
	s.streamMu.Lock()
	s.streamWriter = w
	s.streamFlush = flusher
	s.streamMu.Unlock()
	select {
	case <-s.streamReady:
	default:
		close(s.streamReady)
	}
	<-r.Context().Done()
}

func (s *upstreamHTTPTestServer) emitLegacySSEMessage(id any, result any) {
	<-s.sseReady
	payload := map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
	data, _ := json.Marshal(payload)
	s.sseMu.Lock()
	defer s.sseMu.Unlock()
	if s.sseWriter == nil || s.sseFlush == nil {
		s.t.Fatal("expected live SSE stream")
	}
	fmt.Fprintf(s.sseWriter, "event: message\ndata: %s\n\n", data)
	s.sseFlush.Flush()
}

func (s *upstreamHTTPTestServer) emitStreamableNotification(method string, params map[string]any) {
	<-s.streamReady
	payload := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	}
	data, _ := json.Marshal(payload)
	eventID := s.eventSeq.Add(1)
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	if s.streamWriter == nil || s.streamFlush == nil {
		s.t.Fatal("expected live streamable HTTP event stream")
	}
	fmt.Fprintf(s.streamWriter, "id: %d\nevent: message\ndata: %s\n\n", eventID, data)
	s.streamFlush.Flush()
}

func (s *upstreamHTTPTestServer) enableExtraToolAndNotify() {
	s.extraTool.Store(true)
	s.emitStreamableNotification("notifications/tools/list_changed", map[string]any{})
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

const retailAllowBundle = `{"version":"v1","rules":[{"id":"allow-refund-request","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},{"id":"allow-refund-status","action_type":"mcp.call","resource":"mcp://retail/refund.status","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`

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

func TestUpstreamLegacySSETransport(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	server := newHTTPUpstreamNomosServer(t, retailAllowBundle, UpstreamServerConfig{
		Name:        "retail",
		Transport:   "sse",
		Endpoint:    upstream.endpoint(),
		TLSInsecure: true,
	}, nil)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleRequest(Request{
		ID:     "legacy-sse",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "damaged"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected error: %+v", resp)
	}
	result := resp.Result.(action.Response)
	if result.Decision != "ALLOW" || !strings.Contains(result.Output, "refund accepted for ORD-1001") {
		t.Fatalf("unexpected legacy sse response: %+v", result)
	}
	if upstream.callCount.Load() == 0 {
		t.Fatal("expected legacy sse upstream tools/call to be invoked")
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

func TestUpstreamStreamableHTTPSendsProtocolVersionAndClosesSession(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	server := newHTTPUpstreamNomosServer(t, retailAllowBundle, UpstreamServerConfig{
		Name:        "retail",
		Transport:   "streamable_http",
		Endpoint:    upstream.endpoint(),
		TLSInsecure: true,
	}, nil)

	resp := server.handleRequest(Request{
		ID:     "headers",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "damaged"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected error: %+v", resp)
	}
	if upstream.protoCalls.Load() == 0 {
		t.Fatal("expected MCP-Protocol-Version header on upstream HTTP requests")
	}
	if err := server.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if upstream.deleteSeen.Load() == 0 {
		t.Fatal("expected streamable_http session close to send DELETE with MCP-Session-Id")
	}
}

func TestUpstreamStreamableHTTPBackgroundNotificationsRefreshTools(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	server := newHTTPUpstreamNomosServer(t, retailAllowBundle, UpstreamServerConfig{
		Name:        "retail",
		Transport:   "streamable_http",
		Endpoint:    upstream.endpoint(),
		TLSInsecure: true,
	}, nil)
	t.Cleanup(func() { _ = server.Close() })

	priming := server.handleRequest(Request{
		ID:     "prime",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "damaged"}),
	})
	if priming.Error != "" {
		t.Fatalf("prime: %+v", priming)
	}
	if containsForwardedTool(server.toolsList(), "upstream_retail_refund_status") {
		t.Fatal("did not expect status tool before notification refresh")
	}

	refreshed := make(chan string, 1)
	server.upstream.setRefreshHookForTest(func(serverName string) {
		select {
		case refreshed <- serverName:
		default:
		}
	})

	upstream.enableExtraToolAndNotify()

	select {
	case got := <-refreshed:
		if got != "retail" {
			t.Fatalf("expected retail refresh, got %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("refresh hook did not fire for streamable_http notification")
	}

	if !containsForwardedTool(server.toolsList(), "upstream_retail_refund_status") {
		t.Fatalf("expected refreshed tool list, got %+v", server.toolsList())
	}
}

func TestUpstreamStreamableHTTPSlowStreamTimesOut(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, true, "plaintext")
	upstream.hangStreamResponse = true
	server := newHTTPUpstreamNomosServer(t, retailAllowBundle, UpstreamServerConfig{
		Name:          "retail",
		Transport:     "streamable_http",
		Endpoint:      upstream.endpoint(),
		TLSInsecure:   true,
		CallTimeout:   50 * time.Millisecond,
		StreamTimeout: 50 * time.Millisecond,
	}, nil)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleRequest(Request{
		ID:     "slow-stream",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "delayed"}),
	})
	if resp.Error != "UPSTREAM_TIMEOUT" {
		t.Fatalf("expected upstream timeout on slow stream, got %+v", resp)
	}
	if upstream.callCount.Load() == 0 {
		t.Fatal("expected upstream tools/call to be invoked")
	}
}

func TestUpstreamStreamableHTTPMutualTLS(t *testing.T) {
	fixture := newMTLSFixture(t)
	server := newHTTPUpstreamNomosServer(t, retailAllowBundle, UpstreamServerConfig{
		Name:        "retail",
		Transport:   "streamable_http",
		Endpoint:    fixture.server.URL + "/mcp",
		TLSCAFile:   fixture.caPath,
		TLSCertFile: fixture.clientCertPath,
		TLSKeyFile:  fixture.clientKeyPath,
	}, nil)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleRequest(Request{
		ID:     "mtls",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "damaged"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected mTLS error: %+v", resp)
	}
	result := resp.Result.(action.Response)
	if result.Decision != "ALLOW" || !strings.Contains(result.Output, "refund accepted for ORD-1001") {
		t.Fatalf("unexpected mTLS response: %+v", result)
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
	raw := "id: 7\nretry: 1500\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{}}\n\n"
	evt, err := readSSEEvent(newBufReader(raw))
	if err != nil {
		t.Fatalf("read sse event: %v", err)
	}
	if evt.event != "message" || evt.id != "7" || evt.retry != 1500*time.Millisecond || !strings.Contains(evt.data, "\"result\"") {
		t.Fatalf("unexpected event: %+v", evt)
	}
}

func newBufReader(s string) *bufio.Reader { return bufio.NewReader(bytes.NewBufferString(s)) }

type mtlsFixture struct {
	server         *httptest.Server
	caPath         string
	clientCertPath string
	clientKeyPath  string
}

func newMTLSFixture(t *testing.T) mtlsFixture {
	t.Helper()
	caCert, caKey, caPEM := mustCreateCertificateAuthority(t)
	serverCert, serverPEM, serverKeyPEM := mustCreateSignedCertificate(t, caCert, caKey, false, "127.0.0.1")
	_, clientPEM, clientKeyPEM := mustCreateSignedCertificate(t, caCert, caKey, true, "nomos-upstream-client")

	serverTLSCert, err := tls.X509KeyPair(serverPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("server key pair: %v", err)
	}
	clientPool := x509.NewCertPool()
	clientPool.AddCert(caCert)
	mux := http.NewServeMux()
	testServer := newUpstreamHTTPTestServer(t, false, "plaintext")
	mux.HandleFunc("/mcp", testServer.handle)
	mux.HandleFunc("/sse/messages", testServer.handleLegacySSEPost)
	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverTLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientPool,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	clientCertPath := filepath.Join(dir, "client.pem")
	clientKeyPath := filepath.Join(dir, "client-key.pem")
	for _, file := range []struct {
		path string
		data []byte
	}{
		{caPath, caPEM},
		{clientCertPath, clientPEM},
		{clientKeyPath, clientKeyPEM},
	} {
		if err := os.WriteFile(file.path, file.data, 0o600); err != nil {
			t.Fatalf("write %s: %v", file.path, err)
		}
	}
	_ = serverCert
	return mtlsFixture{
		server:         server,
		caPath:         caPath,
		clientCertPath: clientCertPath,
		clientKeyPath:  clientKeyPath,
	}
}

func mustCreateCertificateAuthority(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "nomos-test-ca",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mustCreateSignedCertificate(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, client bool, commonName string) (*x509.Certificate, []byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signed key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if client {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
		template.DNSNames = append(template.DNSNames, "localhost")
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create signed cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse signed cert: %v", err)
	}
	return cert,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}
