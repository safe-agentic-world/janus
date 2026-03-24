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

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/identity"
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
	payload, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected map capabilities result with forwarded tools, got %+T", resp.Result)
	}
	forwarded, ok := payload["forwarded_tools"].([]map[string]any)
	if !ok || len(forwarded) != 1 {
		t.Fatalf("expected one forwarded tool, got %+v", payload["forwarded_tools"])
	}
	if forwarded[0]["name"] != "upstream_retail_refund_request" || forwarded[0]["resource"] != "mcp://retail/refund.request" {
		t.Fatalf("unexpected forwarded tool descriptor: %+v", forwarded[0])
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

func TestUpstreamMCPHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_UPSTREAM_MCP_HELPER") != "1" {
		return
	}
	if len(os.Args) < 4 {
		os.Exit(2)
	}
	mode := os.Args[3]
	if mode != "retail" && mode != "framed-retail" {
		os.Exit(2)
	}
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
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
		case "tools/list":
			writeUpstreamHelperResponse(writer, mode, req["id"], map[string]any{
				"tools": []map[string]any{{
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
				}},
			}, nil)
		case "tools/call":
			params, _ := req["params"].(map[string]any)
			args, _ := params["arguments"].(map[string]any)
			orderID, _ := args["order_id"].(string)
			reason, _ := args["reason"].(string)
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
