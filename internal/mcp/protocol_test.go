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
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/service"
)

func TestFramedInitializeAndToolsList(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	var stderr bytes.Buffer
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "info",
		LogFormat: "text",
		ErrWriter: &stderr,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	var in bytes.Buffer
	writeFramedRequest(t, &in, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params":  map[string]any{},
	})
	writeFramedRequest(t, &in, map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]any{},
	})
	var out bytes.Buffer
	if err := server.ServeStdio(&in, &out); err != nil {
		t.Fatalf("serve stdio: %v", err)
	}

	reader := bufio.NewReader(bytes.NewReader(out.Bytes()))
	resp1 := readFramedResponse(t, reader)
	if resp1["error"] != nil {
		t.Fatalf("unexpected initialize error: %v", resp1["error"])
	}
	result1 := resp1["result"].(map[string]any)
	if result1["protocolVersion"] == "" {
		t.Fatalf("missing protocolVersion: %+v", result1)
	}
	capabilities := result1["capabilities"].(map[string]any)
	toolsCapability := capabilities["tools"].(map[string]any)
	if listChanged, ok := toolsCapability["listChanged"].(bool); !ok || listChanged {
		t.Fatalf("expected static MCP tools/list contract, got %+v", toolsCapability)
	}
	serverInfo := result1["serverInfo"].(map[string]any)
	if serverInfo["name"] != "nomos" {
		t.Fatalf("unexpected server name: %+v", serverInfo)
	}

	resp2 := readFramedResponse(t, reader)
	if resp2["error"] != nil {
		t.Fatalf("unexpected tools/list error: %v", resp2["error"])
	}
	result2 := resp2["result"].(map[string]any)
	tools := result2["tools"].([]any)
	if len(tools) == 0 {
		t.Fatal("expected tools from tools/list")
	}
}

func TestToolsListRemainsStaticWhenPolicyDoesNotEnableAListedTool(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	tools := server.toolsList()
	foundHTTP := false
	for _, tool := range tools {
		if tool["name"] == "nomos.http_request" {
			foundHTTP = true
			break
		}
	}
	if !foundHTTP {
		t.Fatalf("expected static tools/list to advertise nomos.http_request, got %+v", tools)
	}

	resp := server.handleCapabilities(Request{ID: "1", Method: "nomos.capabilities"})
	caps, ok := resp.Result.(service.CapabilityEnvelope)
	if !ok {
		t.Fatalf("expected typed capability envelope, got %+T", resp.Result)
	}
	if caps.ToolStates["nomos.http_request"].State != service.ToolStateUnavailable {
		t.Fatalf("expected http_request unavailable in capability contract, got %+v", caps.ToolStates["nomos.http_request"])
	}
}

func TestLineDelimitedRPCInitialize(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	var stderr bytes.Buffer
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "info",
		LogFormat: "text",
		ErrWriter: &stderr,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	in := bytes.NewBufferString("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n")
	var out bytes.Buffer
	if err := server.ServeStdio(in, &out); err != nil {
		t.Fatalf("serve stdio: %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("decode line-delimited response: %v body=%q", err, out.String())
	}
	if resp["error"] != nil {
		t.Fatalf("unexpected initialize error: %+v", resp["error"])
	}
	if resp["jsonrpc"] != "2.0" {
		t.Fatalf("missing jsonrpc envelope: %+v", resp)
	}
	result := resp["result"].(map[string]any)
	if result["protocolVersion"] == "" {
		t.Fatalf("missing protocolVersion: %+v", result)
	}
}

func TestLineDelimitedLegacyRequestStillUsesLegacyEnvelope(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	in := bytes.NewBufferString("{\"id\":\"1\",\"method\":\"nomos.capabilities\",\"params\":{}}\n")
	var out bytes.Buffer
	if err := server.ServeStdio(in, &out); err != nil {
		t.Fatalf("serve stdio: %v", err)
	}

	var resp map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("decode legacy response: %v body=%q", err, out.String())
	}
	if _, ok := resp["jsonrpc"]; ok {
		t.Fatalf("expected legacy line response without jsonrpc envelope: %+v", resp)
	}
	if resp["error"] != nil {
		t.Fatalf("unexpected legacy error: %+v", resp["error"])
	}
}

func TestFramedToolsCallFsRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	var stderr bytes.Buffer
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "info",
		LogFormat: "text",
		ErrWriter: &stderr,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	var in bytes.Buffer
	writeFramedRequest(t, &in, map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "nomos.fs_read",
			"arguments": map[string]any{"resource": "file://workspace/README.md"},
		},
	})
	var out bytes.Buffer
	if err := server.ServeStdio(&in, &out); err != nil {
		t.Fatalf("serve stdio: %v", err)
	}
	reader := bufio.NewReader(bytes.NewReader(out.Bytes()))
	resp := readFramedResponse(t, reader)
	result := resp["result"].(map[string]any)
	if result["isError"].(bool) {
		t.Fatalf("expected successful tools/call response: %+v", result)
	}
	content := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("expected tools/call content: %+v", result)
	}
	text := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "ALLOW") || !strings.Contains(text, "fs.read") || !strings.Contains(text, "hello") {
		t.Fatalf("expected formatted ALLOW action response in tools/call content: %s", text)
	}
}

func TestFramedToolsCallFsReadWithInputField(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	var stderr bytes.Buffer
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "info",
		LogFormat: "text",
		ErrWriter: &stderr,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	var in bytes.Buffer
	writeFramedRequest(t, &in, map[string]any{
		"jsonrpc": "2.0",
		"id":      4,
		"method":  "tools/call",
		"params": map[string]any{
			"name":  "nomos.fs_read",
			"input": map[string]any{"resource": "file://workspace/README.md"},
		},
	})
	var out bytes.Buffer
	if err := server.ServeStdio(&in, &out); err != nil {
		t.Fatalf("serve stdio: %v", err)
	}
	reader := bufio.NewReader(bytes.NewReader(out.Bytes()))
	resp := readFramedResponse(t, reader)
	result := resp["result"].(map[string]any)
	if result["isError"].(bool) {
		t.Fatalf("expected successful tools/call response: %+v", result)
	}
	content := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("expected tools/call content: %+v", result)
	}
	text := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "ALLOW") || !strings.Contains(text, "fs.read") || !strings.Contains(text, "hello") {
		t.Fatalf("expected formatted ALLOW action response in tools/call content: %s", text)
	}
}

func TestFramedToolsCallIgnoresExtraWrapperFields(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	var in bytes.Buffer
	writeFramedRequest(t, &in, map[string]any{
		"jsonrpc": "2.0",
		"id":      5,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "nomos.fs_read",
			"arguments": map[string]any{"resource": "file://workspace/README.md"},
			"_meta":     map[string]any{"source": "claude"},
		},
	})
	var out bytes.Buffer
	if err := server.ServeStdio(&in, &out); err != nil {
		t.Fatalf("serve stdio: %v", err)
	}
	reader := bufio.NewReader(bytes.NewReader(out.Bytes()))
	resp := readFramedResponse(t, reader)
	result := resp["result"].(map[string]any)
	if result["isError"].(bool) {
		t.Fatalf("expected successful tools/call response: %+v", result)
	}
}

func TestHandleRequestMapsTraversalToNormalizationError(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	resp := server.handleRequest(Request{
		ID:     "1",
		Method: "nomos.fs_read",
		Params: mustJSONBytes(map[string]any{"resource": "file://workspace/../.env"}),
	})
	if resp.Error != "normalization_error" {
		t.Fatalf("expected normalization_error, got %+v", resp)
	}
}

func TestHandleRequestAdaptsRelativeFsReadPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	resp := server.handleRequest(Request{
		ID:     "1",
		Method: "nomos.fs_read",
		Params: mustJSONBytes(map[string]any{"resource": "README.md"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected error: %+v", resp)
	}
	result := resp.Result.(action.Response)
	if result.Decision != "ALLOW" || !strings.Contains(result.Output, "hello") {
		t.Fatalf("expected shorthand read to allow, got %+v", result)
	}
}

func TestHandleRequestAdaptsRelativeFsWritePath(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-write","action_type":"fs.write","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"],"obligations":{"sandbox_mode":"local"}}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	resp := server.handleRequest(Request{
		ID:     "1",
		Method: "nomos.fs_write",
		Params: mustJSONBytes(map[string]any{"resource": "./notes.txt", "content": "hello"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected error: %+v", resp)
	}
	result := resp.Result.(action.Response)
	if result.Decision != "ALLOW" || result.BytesWritten != len("hello") {
		t.Fatalf("expected shorthand write to allow, got %+v", result)
	}
	data, err := os.ReadFile(filepath.Join(dir, "notes.txt"))
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("unexpected file content %q", string(data))
	}
}

func TestHandleRequestShorthandDotEnvStillHitsPolicyDeny(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"deny-env","action_type":"fs.read","resource":"file://workspace/.env","decision":"DENY","principals":["system"],"agents":["nomos"],"environments":["dev"]},{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	resp := server.handleRequest(Request{
		ID:     "1",
		Method: "nomos.fs_read",
		Params: mustJSONBytes(map[string]any{"resource": ".env"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected error: %+v", resp)
	}
	result := resp.Result.(action.Response)
	if result.Decision != "DENY" {
		t.Fatalf("expected policy deny for shorthand .env, got %+v", result)
	}
}

func TestHandleRequestMapsMissingFilesToNotFound(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	resp := server.handleRequest(Request{
		ID:     "1",
		Method: "nomos.fs_read",
		Params: mustJSONBytes(map[string]any{"resource": "file://workspace/does-not-exist.txt"}),
	})
	if resp.Error != "not_found" {
		t.Fatalf("expected not_found, got %+v", resp)
	}
}

func TestHandleRequestRejectsAbsoluteHostPathForFsRead(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	resp := server.handleRequest(Request{
		ID:     "1",
		Method: "nomos.fs_read",
		Params: mustJSONBytes(map[string]any{"resource": `C:\Users\name\secret.txt`}),
	})
	if resp.Error != "normalization_error" {
		t.Fatalf("expected normalization_error, got %+v", resp)
	}
}

func TestClassifyToolErrorKeepsUnknownFailuresAsExecutionError(t *testing.T) {
	if got := classifyToolError(errors.New("boom")); got != "execution_error" {
		t.Fatalf("expected execution_error, got %q", got)
	}
}

func TestFramedToolsCallRequireApprovalIncludesApprovalMetadata(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"approval-write","action_type":"fs.write","resource":"file://workspace/**","decision":"REQUIRE_APPROVAL","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, true, false, "local", RuntimeOptions{
		ApprovalStorePath:  filepath.Join(dir, "approvals.db"),
		ApprovalTTLSeconds: 600,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	var in bytes.Buffer
	writeFramedRequest(t, &in, map[string]any{
		"jsonrpc": "2.0",
		"id":      6,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "nomos.fs_write",
			"arguments": map[string]any{"resource": "file://workspace/out.txt", "content": "hello"},
		},
	})
	var out bytes.Buffer
	if err := server.ServeStdio(&in, &out); err != nil {
		t.Fatalf("serve stdio: %v", err)
	}
	reader := bufio.NewReader(bytes.NewReader(out.Bytes()))
	resp := readFramedResponse(t, reader)
	result := resp["result"].(map[string]any)
	if result["isError"].(bool) {
		t.Fatalf("expected successful tools/call response: %+v", result)
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "APPROVAL") || !strings.Contains(text, "approval_id:") || !strings.Contains(text, "approval_fingerprint:") || !strings.Contains(text, "approval_expires_at:") {
		t.Fatalf("expected approval metadata in tools/call content, got %s", text)
	}
}

func TestFramedToolsCallNormalizationErrorIncludesShorthandHint(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	var in bytes.Buffer
	writeFramedRequest(t, &in, map[string]any{
		"jsonrpc": "2.0",
		"id":      9,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "nomos.fs_read",
			"arguments": map[string]any{"resource": `/etc/passwd`},
		},
	})
	var out bytes.Buffer
	if err := server.ServeStdio(&in, &out); err != nil {
		t.Fatalf("serve stdio: %v", err)
	}
	reader := bufio.NewReader(bytes.NewReader(out.Bytes()))
	resp := readFramedResponse(t, reader)
	result := resp["result"].(map[string]any)
	if !result["isError"].(bool) {
		t.Fatalf("expected error result, got %+v", result)
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "workspace-relative path") || !strings.Contains(text, "file://workspace/README.md") {
		t.Fatalf("expected shorthand hint in error text, got %q", text)
	}
}

func TestHandleRequestCanResumeApprovedActionViaApprovalID(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"approval-write","action_type":"fs.write","resource":"file://workspace/**","decision":"REQUIRE_APPROVAL","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, true, false, "local", RuntimeOptions{
		ApprovalStorePath:  filepath.Join(dir, "approvals.db"),
		ApprovalTTLSeconds: 600,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	first := server.handleRequest(Request{
		ID:     "7",
		Method: "nomos.fs_write",
		Params: mustJSONBytes(map[string]any{"resource": "file://workspace/out.txt", "content": "hello"}),
	})
	if first.Error != "" {
		t.Fatalf("unexpected first call error: %+v", first)
	}
	firstResp, ok := first.Result.(action.Response)
	if !ok {
		t.Fatalf("expected action response, got %+T", first.Result)
	}
	if firstResp.Decision != "REQUIRE_APPROVAL" || firstResp.ApprovalID == "" {
		t.Fatalf("expected pending approval response, got %+v", firstResp)
	}
	if _, err := server.approvals.Decide(context.Background(), firstResp.ApprovalID, "APPROVE"); err != nil {
		t.Fatalf("approve pending action: %v", err)
	}

	second := server.handleRequest(Request{
		ID:     "8",
		Method: "nomos.fs_write",
		Params: mustJSONBytes(map[string]any{"resource": "file://workspace/out.txt", "content": "hello", "approval_id": firstResp.ApprovalID}),
	})
	if second.Error != "" {
		t.Fatalf("unexpected second call error: %+v", second)
	}
	secondResp := second.Result.(action.Response)
	if secondResp.Decision != "ALLOW" || secondResp.Reason != "allow_by_approval" {
		t.Fatalf("expected approved retry to allow, got %+v", secondResp)
	}
	data, err := os.ReadFile(filepath.Join(dir, "out.txt"))
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("unexpected file content %q", string(data))
	}
}

func writeFramedRequest(t *testing.T, out *bytes.Buffer, payload map[string]any) {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal framed request: %v", err)
	}
	if _, err := fmt.Fprintf(out, "Content-Length: %d\r\n\r\n", len(data)); err != nil {
		t.Fatalf("write framed header: %v", err)
	}
	if _, err := out.Write(data); err != nil {
		t.Fatalf("write framed body: %v", err)
	}
}

func readFramedResponse(t *testing.T, reader *bufio.Reader) map[string]any {
	t.Helper()
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read framed response header: %v", err)
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "content-length:") {
		t.Fatalf("missing content-length header: %q", line)
	}
	parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
	if len(parts) != 2 {
		t.Fatalf("invalid content-length header: %q", line)
	}
	n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || n < 0 {
		t.Fatalf("invalid content-length value: %q", line)
	}
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read framed separator: %v", err)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(reader, body); err != nil {
		t.Fatalf("read framed body: %v", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode framed response: %v body=%q", err, string(body))
	}
	return resp
}
