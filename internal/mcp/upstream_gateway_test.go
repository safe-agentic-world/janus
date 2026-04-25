package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/service"
)

func TestUpstreamGatewayToolsListIncludesForwardedTools(t *testing.T) {
	dir := t.TempDir()
	server := newUpstreamGatewayTestServer(t, dir, `{"version":"v1","rules":[{"id":"allow-refund","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`, false)
	t.Cleanup(func() { _ = server.Close() })

	tools := server.toolsList()
	found := false
	for _, tool := range tools {
		if tool["name"] == "upstream_retail_refund_request" {
			found = true
			if !strings.Contains(tool["description"].(string), "Governed by Nomos before forwarding") {
				t.Fatalf("expected forwarded tool description marker, got %+v", tool)
			}
		}
	}
	if !found {
		t.Fatalf("expected forwarded tool in tools list, got %+v", tools)
	}

	resp := server.handleCapabilities(Request{ID: "caps", Method: "nomos.capabilities"})
	payload, ok := resp.Result.(service.CapabilityEnvelope)
	if !ok {
		t.Fatalf("expected capability envelope with forwarded tools, got %+T", resp.Result)
	}
	if len(payload.ForwardedTools) != 1 {
		t.Fatalf("expected one forwarded tool, got %+v", payload.ForwardedTools)
	}
	if payload.ForwardedTools[0]["name"] != "upstream_retail_refund_request" || payload.ForwardedTools[0]["resource"] != "mcp://retail/refund.request" {
		t.Fatalf("unexpected forwarded tool descriptor: %+v", payload.ForwardedTools[0])
	}
	if payload.MCPSurfaces["sample"].State != service.ToolStateUnavailable {
		t.Fatalf("expected sampling to default unavailable without explicit rule, got %+v", payload.MCPSurfaces["sample"])
	}
}

func TestHandleForwardedToolAllow(t *testing.T) {
	dir := t.TempDir()
	server := newUpstreamGatewayTestServer(t, dir, `{"version":"v1","rules":[{"id":"allow-refund","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"],"obligations":{"output_max_lines":1}}]}`, false)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleRequest(Request{
		ID:     "allow",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "damaged"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected error: %+v", resp)
	}
	result, ok := resp.Result.(action.Response)
	if !ok {
		t.Fatalf("expected action response, got %+T", resp.Result)
	}
	if result.Decision != "ALLOW" || result.ExecutionMode != "mcp_forwarded" {
		t.Fatalf("expected forwarded ALLOW response, got %+v", result)
	}
	if !strings.Contains(result.Output, "refund accepted for ORD-1001") {
		t.Fatalf("expected forwarded output, got %+v", result)
	}
	if !result.Truncated {
		t.Fatalf("expected forwarded output to honor line limits, got %+v", result)
	}
}

func TestHandleForwardedToolDenySkipsUpstreamExecution(t *testing.T) {
	dir := t.TempDir()
	server := newUpstreamGatewayTestServer(t, dir, `{"version":"v1","rules":[{"id":"deny-refund","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"DENY","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`, false)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleRequest(Request{
		ID:     "deny",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "damaged"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected error: %+v", resp)
	}
	result := resp.Result.(action.Response)
	if result.Decision != "DENY" || result.Output != "" || result.ExecutionMode != "" {
		t.Fatalf("expected policy deny before upstream call, got %+v", result)
	}
}

func TestHandleForwardedToolSupportsApprovalResume(t *testing.T) {
	dir := t.TempDir()
	server := newUpstreamGatewayTestServer(t, dir, `{"version":"v1","rules":[{"id":"approval-refund","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"REQUIRE_APPROVAL","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`, true)
	t.Cleanup(func() { _ = server.Close() })

	first := server.handleRequest(Request{
		ID:     "first",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "damaged"}),
	})
	if first.Error != "" {
		t.Fatalf("unexpected first-call error: %+v", first)
	}
	firstResp := first.Result.(action.Response)
	if firstResp.Decision != "REQUIRE_APPROVAL" || firstResp.ApprovalID == "" {
		t.Fatalf("expected pending approval, got %+v", firstResp)
	}
	if _, err := server.approvals.Decide(context.Background(), firstResp.ApprovalID, "APPROVE"); err != nil {
		t.Fatalf("approve pending action: %v", err)
	}

	second := server.handleRequest(Request{
		ID:     "second",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "damaged", "approval_id": firstResp.ApprovalID}),
	})
	if second.Error != "" {
		t.Fatalf("unexpected second-call error: %+v", second)
	}
	secondResp := second.Result.(action.Response)
	if secondResp.Decision != "ALLOW" || secondResp.Reason != "allow_by_approval" || secondResp.ExecutionMode != "mcp_forwarded" {
		t.Fatalf("expected approved forwarded allow, got %+v", secondResp)
	}
	if !strings.Contains(secondResp.Output, "refund accepted for ORD-1001") {
		t.Fatalf("expected resumed forwarded output, got %+v", secondResp)
	}
}

func TestResourcesReadAllowRedactsContent(t *testing.T) {
	dir := t.TempDir()
	server := newUpstreamGatewayTestServer(t, dir, `{"version":"v1","rules":[{"id":"allow-resource","action_type":"mcp.resource_read","resource":"mcp://retail/resource/note://retail/customer-42","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`, false)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleResourcesReadRPC(rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`"res-1"`),
		Method:  "resources/read",
		Params:  mustJSONBytes(map[string]any{"uri": downstreamResourceURI("retail", "note://retail/customer-42")}),
	}, nil)
	if resp.Error != nil {
		t.Fatalf("unexpected resources/read error: %+v", resp.Error)
	}
	body, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("marshal resource result: %v", err)
	}
	if strings.Contains(string(body), "super-secret-token") {
		t.Fatalf("expected redacted resource payload, got %s", string(body))
	}
	if !strings.Contains(string(body), "[REDACTED]") {
		t.Fatalf("expected redaction marker in %s", string(body))
	}
}

func TestResourcesReadDenyReturnsStructuredPolicyError(t *testing.T) {
	dir := t.TempDir()
	server := newUpstreamGatewayTestServer(t, dir, `{"version":"v1","rules":[{"id":"deny-resource","action_type":"mcp.resource_read","resource":"mcp://retail/resource/note://retail/customer-42","decision":"DENY","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`, false)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleResourcesReadRPC(rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`"res-2"`),
		Method:  "resources/read",
		Params:  mustJSONBytes(map[string]any{"uri": downstreamResourceURI("retail", "note://retail/customer-42")}),
	}, nil)
	if resp.Error == nil || resp.Error.Message != "denied_policy" {
		t.Fatalf("expected denied_policy error, got %+v", resp)
	}
}

func TestPromptGetAllowAndDenyPaths(t *testing.T) {
	dir := t.TempDir()
	allowServer := newUpstreamGatewayTestServer(t, dir, `{"version":"v1","rules":[{"id":"allow-prompt","action_type":"mcp.prompt_get","resource":"mcp://retail/prompt/incident.summary","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`, false)
	t.Cleanup(func() { _ = allowServer.Close() })

	allowResp := allowServer.handlePromptsGetRPC(rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`"prompt-1"`),
		Method:  "prompts/get",
		Params:  mustJSONBytes(map[string]any{"name": downstreamPromptName("retail", "incident.summary")}),
	}, nil)
	if allowResp.Error != nil {
		t.Fatalf("unexpected prompts/get error: %+v", allowResp.Error)
	}
	body, err := json.Marshal(allowResp.Result)
	if err != nil {
		t.Fatalf("marshal prompt result: %v", err)
	}
	if !strings.Contains(string(body), "Summarize the last incident.") {
		t.Fatalf("expected prompt payload, got %s", string(body))
	}

	denyDir := t.TempDir()
	denyServer := newUpstreamGatewayTestServer(t, denyDir, `{"version":"v1","rules":[{"id":"deny-prompt","action_type":"mcp.prompt_get","resource":"mcp://retail/prompt/incident.summary","decision":"DENY","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`, false)
	t.Cleanup(func() { _ = denyServer.Close() })
	denyResp := denyServer.handlePromptsGetRPC(rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`"prompt-2"`),
		Method:  "prompts/get",
		Params:  mustJSONBytes(map[string]any{"name": downstreamPromptName("retail", "incident.summary")}),
	}, nil)
	if denyResp.Error == nil || denyResp.Error.Message != "denied_policy" {
		t.Fatalf("expected denied prompt_get, got %+v", denyResp)
	}
}

func TestCompletionCompleteAllowPath(t *testing.T) {
	dir := t.TempDir()
	server := newUpstreamGatewayTestServer(t, dir, `{"version":"v1","rules":[{"id":"allow-completion","action_type":"mcp.completion","resource":"mcp://retail/completion/ref/prompt/incident.summary","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`, false)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleCompletionRPC(rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`"complete-1"`),
		Method:  "completion/complete",
		Params: mustJSONBytes(map[string]any{
			"ref": map[string]any{
				"type": "ref/prompt",
				"name": downstreamPromptName("retail", "incident.summary"),
			},
			"argument": map[string]any{"name": "refund"},
		}),
	}, nil)
	if resp.Error != nil {
		t.Fatalf("unexpected completion error: %+v", resp.Error)
	}
	body, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatalf("marshal completion result: %v", err)
	}
	if !strings.Contains(string(body), "refund.status") {
		t.Fatalf("expected completion values, got %s", string(body))
	}
}

func TestSamplingDefaultDenyWithoutExplicitRule(t *testing.T) {
	dir := t.TempDir()
	server := newSamplingTestServer(t, dir, `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`, false)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleSamplingRPC(newSamplingRPCRequest("sample-1"), newSamplingClientSession(t, server, "ignored"), "retail", "")
	if resp.Error == nil || resp.Error.Message != "denied_policy" {
		t.Fatalf("expected default deny for sampling, got %+v", resp)
	}
}

func TestSamplingApprovalFlow(t *testing.T) {
	dir := t.TempDir()
	server := newSamplingTestServer(t, dir, `{"version":"v1","rules":[{"id":"approval-sample","action_type":"mcp.sample","resource":"mcp://retail/sample","decision":"REQUIRE_APPROVAL","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`, true)
	t.Cleanup(func() { _ = server.Close() })

	first := server.handleSamplingRPC(newSamplingRPCRequest("sample-2"), newSamplingClientSession(t, server, "approved summary"), "retail", "")
	if first.Error == nil || first.Error.Message != "approval_required" {
		t.Fatalf("expected approval_required, got %+v", first)
	}
	data, _ := first.Error.Data.(map[string]any)
	approvalID, _ := data["approval_id"].(string)
	if approvalID == "" {
		t.Fatalf("expected approval id in %+v", first.Error)
	}
	if _, err := server.approvals.Decide(context.Background(), approvalID, "APPROVE"); err != nil {
		t.Fatalf("approve sampling action: %v", err)
	}

	second := server.handleSamplingRPC(newSamplingRPCRequest("sample-3"), newSamplingClientSession(t, server, "approved summary"), "retail", approvalID)
	if second.Error != nil {
		t.Fatalf("expected approved sampling response, got %+v", second.Error)
	}
	body, err := json.Marshal(second.Result)
	if err != nil {
		t.Fatalf("marshal sampling result: %v", err)
	}
	if !strings.Contains(string(body), "approved summary") {
		t.Fatalf("expected downstream sampling content, got %s", string(body))
	}
}

func TestNewServerFailsClosedWhenUpstreamRegistryCannotLoad(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	_, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		UpstreamServers: []UpstreamServerConfig{{
			Name:      "broken",
			Transport: "stdio",
			Command:   filepath.Join(dir, "does-not-exist.exe"),
		}},
	})
	if err == nil {
		t.Fatal("expected upstream registry load failure")
	}
	if !strings.Contains(err.Error(), `upstream mcp server "broken"`) {
		t.Fatalf("expected upstream server name in error, got %v", err)
	}
	if !strings.Contains(err.Error(), "load upstream mcp server") {
		t.Fatalf("expected stage-aware upstream load failure, got %v", err)
	}
}

func TestUpstreamGatewaySupportsFramedServerResponses(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-refund","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "error",
		LogFormat: "text",
		ErrWriter: io.Discard,
		UpstreamServers: []UpstreamServerConfig{{
			Name:      "retail",
			Transport: "stdio",
			Command:   os.Args[0],
			Args:      []string{"-test.run=TestUpstreamMCPHelperProcess", "--", "framed-retail"},
			Env: map[string]string{
				"GO_WANT_UPSTREAM_MCP_HELPER": "1",
			},
			Workdir: dir,
		}},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleRequest(Request{
		ID:     "allow-framed",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001", "reason": "damaged"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected error: %+v", resp)
	}
	result := resp.Result.(action.Response)
	if result.Decision != "ALLOW" || result.ExecutionMode != "mcp_forwarded" {
		t.Fatalf("expected framed forwarded ALLOW response, got %+v", result)
	}
}

func TestDownstreamToolNameUsesCrossVendorSafeCharacters(t *testing.T) {
	got := downstreamToolName("retail.api", "refund.request/v2")
	if got != "upstream_retail_api_refund_request_v2" {
		t.Fatalf("unexpected downstream tool name: %q", got)
	}
	for _, r := range got {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			t.Fatalf("unexpected unsafe character %q in %q", r, got)
		}
	}
}

func newUpstreamGatewayTestServer(t *testing.T, dir, bundle string, approvals bool) *Server {
	t.Helper()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	runtimeOptions := RuntimeOptions{
		LogLevel:  "error",
		LogFormat: "text",
		ErrWriter: io.Discard,
		UpstreamServers: []UpstreamServerConfig{{
			Name:      "retail",
			Transport: "stdio",
			Command:   os.Args[0],
			Args:      []string{"-test.run=TestUpstreamMCPHelperProcess", "--", "retail"},
			Env: map[string]string{
				"GO_WANT_UPSTREAM_MCP_HELPER": "1",
			},
			Workdir: dir,
		}},
	}
	if approvals {
		runtimeOptions.ApprovalStorePath = filepath.Join(dir, "approvals.db")
		runtimeOptions.ApprovalTTLSeconds = 600
	}
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, approvals, false, "local", runtimeOptions)
	if err != nil {
		t.Fatalf("new upstream gateway server: %v", err)
	}
	return server
}

func newSamplingTestServer(t *testing.T, dir, bundle string, approvals bool) *Server {
	t.Helper()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	runtimeOptions := RuntimeOptions{
		LogLevel:  "error",
		LogFormat: "text",
		ErrWriter: io.Discard,
	}
	if approvals {
		runtimeOptions.ApprovalStorePath = filepath.Join(dir, "approvals.db")
		runtimeOptions.ApprovalTTLSeconds = 600
	}
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, approvals, false, "local", runtimeOptions)
	if err != nil {
		t.Fatalf("new sampling server: %v", err)
	}
	return server
}

func newSamplingRPCRequest(id string) rpcRequest {
	return rpcRequest{
		JSONRPC: "2.0",
		ID:      mustJSONBytes(id),
		Method:  "sampling/createMessage",
		Params: mustJSONBytes(map[string]any{
			"messages": []map[string]any{{
				"role": "user",
				"content": map[string]any{
					"type": "text",
					"text": "Summarize the incident.",
				},
			}},
			"modelPreferences": map[string]any{
				"hints": []map[string]any{{"name": "gpt-5-mini"}},
			},
			"maxTokens":     32,
			"stopSequences": []string{"END"},
		}),
	}
}

func newSamplingClientSession(t *testing.T, server *Server, sampledText string) *downstreamSession {
	t.Helper()
	reader, writer := io.Pipe()
	session := newDownstreamSession(server, bytes.NewReader(nil), writer)
	session.clientSampling = true
	session.setMode(stdioModeLine)
	go func() {
		wire := bufio.NewReader(reader)
		body, err := wire.ReadBytes('\n')
		if err != nil {
			return
		}
		var req rpcRequest
		if err := json.Unmarshal(bytes.TrimSpace(body), &req); err != nil {
			return
		}
		resp := &rpcResponse{
			JSONRPC: "2.0",
			ID:      parseRPCID(req.ID),
			Result: map[string]any{
				"role": "assistant",
				"content": map[string]any{
					"type": "text",
					"text": sampledText,
				},
			},
		}
		data, _ := json.Marshal(resp)
		_ = session.handleRPCResponse(data)
	}()
	return session
}

func TestUpstreamMCPHelperProcess(t *testing.T) {
	if len(os.Args) < 4 {
		return
	}
	mode := os.Args[3]
	switch mode {
	case "retail", "framed-retail", "stateful-retail", "env-inspect", "hang-init", "hang-call":
	default:
		return
	}
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	listVersion := 0
	for {
		body, err := readMCPPayload(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			os.Exit(2)
		}
		var req map[string]any
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if err := dec.Decode(&req); err != nil {
			os.Exit(2)
		}
		method, _ := req["method"].(string)
		switch method {
		case "initialize":
			if mode == "hang-init" {
				time.Sleep(time.Hour)
				return
			}
			writeUpstreamHelperResponse(writer, mode, req["id"], map[string]any{
				"protocolVersion": SupportedProtocolVersion,
				"capabilities": map[string]any{
					"tools": map[string]any{"listChanged": false},
				},
				"serverInfo": map[string]any{
					"name":    "retail-upstream",
					"version": "test",
				},
			}, nil)
		case "notifications/initialized":
			continue
		case "env.inspect":
			writeUpstreamHelperResponse(writer, mode, req["id"], map[string]any{
				"env": map[string]any{
					"PATH":            os.Getenv("PATH"),
					"ALLOWLISTED_VAR": os.Getenv("ALLOWLISTED_VAR"),
					"OVERRIDE_VAR":    os.Getenv("OVERRIDE_VAR"),
					"SECRET_TOKEN":    os.Getenv("SECRET_TOKEN"),
				},
			}, nil)
		case "tools/list":
			tools := []map[string]any{{
				"name":        "refund.request",
				"description": "Submit a retail refund request.",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"order_id": map[string]any{"type": "string"},
						"reason":   map[string]any{"type": "string"},
					},
					"required":             []string{"order_id", "reason"},
					"additionalProperties": true,
				},
			}}
			if mode == "stateful-retail" && listVersion >= 1 {
				tools = append(tools, map[string]any{
					"name":        "refund.status",
					"description": "Fetch refund status.",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"order_id": map[string]any{"type": "string"},
						},
						"required":             []string{"order_id"},
						"additionalProperties": true,
					},
				})
			}
			writeUpstreamHelperResponse(writer, mode, req["id"], map[string]any{
				"tools": tools,
			}, nil)
		case "resources/list":
			writeUpstreamHelperResponse(writer, mode, req["id"], map[string]any{
				"resources": []map[string]any{{
					"uri":         "note://retail/customer-42",
					"name":        "customer-42",
					"description": "Customer resource with secrets in body.",
					"mimeType":    "text/plain",
				}},
			}, nil)
		case "resources/read":
			params, _ := req["params"].(map[string]any)
			uri, _ := params["uri"].(string)
			if uri != "note://retail/customer-42" {
				writeUpstreamHelperResponse(writer, mode, req["id"], nil, &rpcError{Code: -32602, Message: "unknown resource"})
				continue
			}
			writeUpstreamHelperResponse(writer, mode, req["id"], map[string]any{
				"contents": []map[string]any{{
					"uri":      uri,
					"mimeType": "text/plain",
					"text":     "Authorization: Bearer super-secret-token\ncustomer=42",
				}},
			}, nil)
		case "prompts/list":
			writeUpstreamHelperResponse(writer, mode, req["id"], map[string]any{
				"prompts": []map[string]any{
					{
						"name":        "incident.summary",
						"description": "Return a static summary prompt.",
					},
					{
						"name":        "llm.summary",
						"description": "Trigger downstream sampling.",
					},
				},
			}, nil)
		case "prompts/get":
			params, _ := req["params"].(map[string]any)
			promptName, _ := params["name"].(string)
			switch promptName {
			case "incident.summary":
				writeUpstreamHelperResponse(writer, mode, req["id"], map[string]any{
					"description": "Incident summary prompt.",
					"messages": []map[string]any{{
						"role": "user",
						"content": map[string]any{
							"type": "text",
							"text": "Summarize the last incident.",
						},
					}},
				}, nil)
			case "llm.summary":
				samplingResp, err := helperSamplingRoundTrip(reader, writer, mode, map[string]any{
					"messages": []map[string]any{{
						"role": "user",
						"content": map[string]any{
							"type": "text",
							"text": "Summarize incident INC-42.",
						},
					}},
					"modelPreferences": map[string]any{
						"hints": []map[string]any{{"name": "gpt-5-mini"}},
					},
					"maxTokens":     64,
					"stopSequences": []string{"END"},
				})
				if err != nil {
					writeUpstreamHelperResponse(writer, mode, req["id"], nil, &rpcError{Code: -32603, Message: err.Error()})
					continue
				}
				writeUpstreamHelperResponse(writer, mode, req["id"], map[string]any{
					"description": "LLM-generated summary prompt.",
					"messages": []map[string]any{{
						"role":    "assistant",
						"content": samplingResp,
					}},
				}, nil)
			default:
				writeUpstreamHelperResponse(writer, mode, req["id"], nil, &rpcError{Code: -32602, Message: "unknown prompt"})
			}
		case "completion/complete":
			writeUpstreamHelperResponse(writer, mode, req["id"], map[string]any{
				"completion": map[string]any{
					"values": []string{"refund.status", "refund.summary"},
				},
			}, nil)
		case "tools/call":
			if mode == "hang-call" {
				continue
			}
			params, _ := req["params"].(map[string]any)
			callName, _ := params["name"].(string)
			args, _ := params["arguments"].(map[string]any)
			orderID, _ := args["order_id"].(string)
			reason, _ := args["reason"].(string)
			if mode == "stateful-retail" {
				switch {
				case callName == "refund.request" && orderID == "KILL":
					os.Exit(0)
				case callName == "refund.request" && orderID == "LIST_CHANGED":
					listVersion++
					writeUpstreamHelperNotification(writer, mode, "notifications/tools/list_changed", map[string]any{})
					writeUpstreamHelperResponse(writer, mode, req["id"], map[string]any{
						"content": []map[string]any{{
							"type": "text",
							"text": "list_changed emitted",
						}},
						"isError": false,
					}, nil)
					continue
				case callName == "refund.status":
					writeUpstreamHelperResponse(writer, mode, req["id"], map[string]any{
						"content": []map[string]any{{
							"type": "text",
							"text": fmt.Sprintf("status pending for %s", orderID),
						}},
						"isError": false,
					}, nil)
					continue
				}
			}
			writeUpstreamHelperResponse(writer, mode, req["id"], map[string]any{
				"content": []map[string]any{{
					"type": "text",
					"text": fmt.Sprintf("refund accepted for %s\nreason: %s", orderID, reason),
				}},
				"isError": false,
			}, nil)
		default:
			writeUpstreamHelperResponse(writer, mode, req["id"], nil, &rpcError{Code: -32601, Message: "method not found"})
		}
	}
}

func helperSamplingRoundTrip(reader *bufio.Reader, writer *bufio.Writer, mode string, params map[string]any) (map[string]any, error) {
	requestID := "sample-1"
	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      requestID,
		"method":  "sampling/createMessage",
		"params":  params,
	}
	data, _ := json.Marshal(msg)
	if mode == "framed-retail" {
		_, _ = fmt.Fprintf(writer, "Content-Length: %d\r\n\r\n", len(data))
		_, _ = writer.Write(data)
	} else {
		_, _ = writer.Write(data)
		_ = writer.WriteByte('\n')
	}
	_ = writer.Flush()

	body, err := readMCPPayload(reader)
	if err != nil {
		return nil, err
	}
	resp, err := decodeRPCResponse(body)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		encoded, _ := json.Marshal(resp.Error.Data)
		return nil, fmt.Errorf("%s:%s", resp.Error.Message, strings.TrimSpace(string(encoded)))
	}
	result, _ := resp.Result.(map[string]any)
	content, _ := result["content"].(map[string]any)
	if len(content) == 0 {
		return nil, errors.New("sampling result missing content")
	}
	return content, nil
}

func writeUpstreamHelperResponse(writer *bufio.Writer, mode string, id any, result any, rpcErr *rpcError) {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
	}
	if rpcErr != nil {
		resp["error"] = rpcErr
	} else {
		resp["result"] = result
	}
	data, _ := json.Marshal(resp)
	if mode == "framed-retail" {
		_, _ = fmt.Fprintf(writer, "Content-Length: %d\r\n\r\n", len(data))
		_, _ = writer.Write(data)
	} else {
		_, _ = writer.Write(data)
		_ = writer.WriteByte('\n')
	}
	_ = writer.Flush()
}

func writeUpstreamHelperNotification(writer *bufio.Writer, mode string, method string, params map[string]any) {
	msg := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	}
	data, _ := json.Marshal(msg)
	if mode == "framed-retail" {
		_, _ = fmt.Fprintf(writer, "Content-Length: %d\r\n\r\n", len(data))
		_, _ = writer.Write(data)
	} else {
		_, _ = writer.Write(data)
		_ = writer.WriteByte('\n')
	}
	_ = writer.Flush()
}

func TestHelperCommandCanStart(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestUpstreamMCPHelperProcess", "--", "retail")
	cmd.Env = append(os.Environ(), "GO_WANT_UPSTREAM_MCP_HELPER=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper command: %v", err)
	}
	defer func() {
		_ = stdin.Close()
		_ = stdout.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}()
	writer := bufio.NewWriter(stdin)
	reader := bufio.NewReader(stdout)
	if err := writeUpstreamRPCRequest(writer, "initialize", "1", map[string]any{
		"protocolVersion": SupportedProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "test", "version": "v1"},
	}); err != nil {
		t.Fatalf("write initialize: %v", err)
	}
	resp, err := readUpstreamRPCResponse(reader)
	if err != nil {
		t.Fatalf("read initialize: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected helper initialize error: %+v", resp.Error)
	}
}
