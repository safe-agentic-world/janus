package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/identity"
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
	if !strings.Contains(text, "\"decision\":\"ALLOW\"") {
		t.Fatalf("expected ALLOW action response in tools/call content: %s", text)
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
