package mcp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/telemetry"
)

func TestForwardedContentBlocksTextOnlyBehaviorUnchanged(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	upstream.toolOutput = "plain upstream output"
	recorder := &recordingSink{}
	server := newContentBlockServer(t, contentBlockBundle(nil, nil), upstream, recorder, nil)
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleRequest(Request{
		ID:     "content-text",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001"}),
	})
	result := contentBlockActionResponse(t, resp)
	if result.Output != upstream.toolOutput {
		t.Fatalf("expected text output unchanged, got %q", result.Output)
	}
	if len(result.MCPContentBlocks) != 0 {
		t.Fatalf("did not expect structured side blocks for text-only output, got %+v", result.MCPContentBlocks)
	}

	content := callContentBlockToolRPC(t, server)
	if len(content) != 1 {
		t.Fatalf("expected one formatted text block, got %+v", content)
	}
	if content[0]["type"] != "text" || !strings.Contains(stringValue(content[0]["text"]), upstream.toolOutput) {
		t.Fatalf("expected existing formatted text result, got %+v", content)
	}
}

func TestForwardedImageContentBlockAllowed(t *testing.T) {
	imageBytes := []byte{0, 1, 2, 3, 4, 5}
	imageData := base64.StdEncoding.EncodeToString(imageBytes)
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	upstream.toolContent = []map[string]any{
		{"type": "text", "text": "receipt ready"},
		{"type": "image", "mimeType": "image/png", "data": imageData},
	}
	recorder := &recordingSink{}
	telemetrySink := &responseScanTelemetrySink{}
	server := newContentBlockServer(t, contentBlockBundle([]string{"text", "image"}, nil), upstream, recorder, telemetry.NewEmitter(telemetrySink))
	t.Cleanup(func() { _ = server.Close() })

	content := callContentBlockToolRPC(t, server)
	if len(content) != 2 {
		t.Fatalf("expected formatted text plus image block, got %+v", content)
	}
	imageBlock := content[1]
	if imageBlock["type"] != "image" || imageBlock["data"] != imageData {
		t.Fatalf("expected image block to flow through, got %+v", imageBlock)
	}
	event := contentBlocksAuditEvent(t, recorder.snapshot())
	assertAuditDoesNotContain(t, event, imageData)
	imageAudit := findContentBlockAudit(t, event, "image", false)
	if imageAudit.SizeBytes != len(imageBytes) {
		t.Fatalf("expected image size %d, got %+v", len(imageBytes), imageAudit)
	}
	if imageAudit.Digest != canonicaljson.HashSHA256(imageBytes) {
		t.Fatalf("expected deterministic binary digest, got %+v", imageAudit)
	}
	if !hasContentBlockMetric(telemetrySink.metrics, "image", "delivered") {
		t.Fatalf("expected image content block telemetry, got %+v", telemetrySink.metrics)
	}
}

func TestForwardedImageContentBlockDeniedByDefault(t *testing.T) {
	imageData := base64.StdEncoding.EncodeToString([]byte{9, 8, 7, 6})
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	upstream.toolContent = []map[string]any{{"type": "image", "mimeType": "image/png", "data": imageData}}
	recorder := &recordingSink{}
	server := newContentBlockServer(t, contentBlockBundle(nil, nil), upstream, recorder, nil)
	t.Cleanup(func() { _ = server.Close() })

	content := callContentBlockToolRPC(t, server)
	if len(content) != 2 {
		t.Fatalf("expected formatted status plus placeholder, got %+v", content)
	}
	placeholder := content[1]
	if placeholder["type"] != "text" || !strings.Contains(stringValue(placeholder["text"]), "Nomos blocked MCP content block") {
		t.Fatalf("expected structured placeholder, got %+v", placeholder)
	}
	event := contentBlocksAuditEvent(t, recorder.snapshot())
	assertAuditDoesNotContain(t, event, imageData)
	blockedImage := findContentBlockAudit(t, event, "image", true)
	if blockedImage.BlockedKind != "image" {
		t.Fatalf("expected blocked image metadata, got %+v", blockedImage)
	}
}

func TestForwardedContentBlockInvalidAllowanceFailsClosed(t *testing.T) {
	imageData := base64.StdEncoding.EncodeToString([]byte{4, 3, 2, 1})
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	upstream.toolContent = []map[string]any{{"type": "image", "mimeType": "image/png", "data": imageData}}
	recorder := &recordingSink{}
	server := newContentBlockServer(t, contentBlockBundle([]string{"image", "bogus"}, nil), upstream, recorder, nil)
	t.Cleanup(func() { _ = server.Close() })

	content := callContentBlockToolRPC(t, server)
	if len(content) != 2 || !strings.Contains(stringValue(content[1]["text"]), "kind=image") {
		t.Fatalf("expected invalid allowance to fail closed to image placeholder, got %+v", content)
	}
	event := contentBlocksAuditEvent(t, recorder.snapshot())
	if event.ExecutorMetadata["mcp_content_block_policy_misconfigured"] != true {
		t.Fatalf("expected content block policy misconfiguration metadata, got %+v", event.ExecutorMetadata)
	}
	allowed, ok := event.ExecutorMetadata["mcp_content_allowed_block_kinds"].([]string)
	if !ok || len(allowed) != 1 || allowed[0] != "text" {
		t.Fatalf("expected text-only fallback, got %+v", event.ExecutorMetadata["mcp_content_allowed_block_kinds"])
	}
}

func TestForwardedAudioContentBlockAllowedAndCapped(t *testing.T) {
	audioBytes := []byte{1, 2, 3, 4, 5}
	audioData := base64.StdEncoding.EncodeToString(audioBytes)
	cappedData := base64.StdEncoding.EncodeToString(audioBytes[:3])
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	upstream.toolContent = []map[string]any{{"type": "audio", "mimeType": "audio/wav", "data": audioData}}
	recorder := &recordingSink{}
	server := newContentBlockServer(t, contentBlockBundle([]string{"text", "audio"}, map[string]any{"output_max_bytes": 3}), upstream, recorder, nil)
	t.Cleanup(func() { _ = server.Close() })

	content := callContentBlockToolRPC(t, server)
	if len(content) != 2 {
		t.Fatalf("expected formatted status plus audio block, got %+v", content)
	}
	audioBlock := content[1]
	if audioBlock["type"] != "audio" || audioBlock["data"] != cappedData || audioBlock["mimeType"] != "audio/wav" {
		t.Fatalf("expected capped audio block with metadata preserved, got %+v", audioBlock)
	}
	event := contentBlocksAuditEvent(t, recorder.snapshot())
	audioAudit := findContentBlockAudit(t, event, "audio", false)
	if audioAudit.SizeBytes != 3 || !audioAudit.Truncated {
		t.Fatalf("expected capped audio audit metadata, got %+v", audioAudit)
	}
}

func TestForwardedResourceContentBlockAllowedAndRedacted(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	upstream.toolContent = []map[string]any{{
		"type": "resource",
		"resource": map[string]any{
			"uri":      "note://retail/customer-42",
			"mimeType": "text/plain",
			"text":     "Authorization: Bearer very-secret-token\ncustomer=42",
		},
	}}
	recorder := &recordingSink{}
	server := newContentBlockServer(t, contentBlockBundle([]string{"text", "resource"}, nil), upstream, recorder, nil)
	t.Cleanup(func() { _ = server.Close() })

	content := callContentBlockToolRPC(t, server)
	if len(content) != 2 {
		t.Fatalf("expected formatted status plus resource block, got %+v", content)
	}
	resourceBlock := content[1]
	resource, _ := resourceBlock["resource"].(map[string]any)
	if resourceBlock["type"] != "resource" || len(resource) == 0 {
		t.Fatalf("expected resource content block, got %+v", resourceBlock)
	}
	text := stringValue(resource["text"])
	if strings.Contains(text, "very-secret-token") || !strings.Contains(text, "[REDACTED]") {
		t.Fatalf("expected redacted resource text, got %q", text)
	}
	event := contentBlocksAuditEvent(t, recorder.snapshot())
	assertAuditDoesNotContain(t, event, "very-secret-token")
	_ = findContentBlockAudit(t, event, "resource", false)
}

func TestForwardedResourceContentBlockDeniedByDefault(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	upstream.toolContent = []map[string]any{{
		"type": "resource",
		"resource": map[string]any{
			"uri":  "note://retail/customer-42",
			"text": "customer=42",
		},
	}}
	recorder := &recordingSink{}
	server := newContentBlockServer(t, contentBlockBundle(nil, nil), upstream, recorder, nil)
	t.Cleanup(func() { _ = server.Close() })

	content := callContentBlockToolRPC(t, server)
	if len(content) != 2 {
		t.Fatalf("expected formatted status plus resource placeholder, got %+v", content)
	}
	if !strings.Contains(stringValue(content[1]["text"]), "kind=resource") {
		t.Fatalf("expected resource placeholder, got %+v", content[1])
	}
	event := contentBlocksAuditEvent(t, recorder.snapshot())
	_ = findContentBlockAudit(t, event, "resource", true)
}

func TestSamplingResponseContentBlocksUseGovernancePipeline(t *testing.T) {
	imageBytes := []byte{7, 7, 7}
	imageData := base64.StdEncoding.EncodeToString(imageBytes)
	recorder := &recordingSink{}
	server := newSamplingContentBlockServer(t, contentBlockSamplingBundle([]string{"text", "image"}), recorder)
	t.Cleanup(func() { _ = server.Close() })
	session := newSamplingContentBlockClientSession(t, server, map[string]any{
		"type":     "image",
		"mimeType": "image/png",
		"data":     imageData,
	})

	resp := server.handleSamplingRPC(newSamplingRPCRequest("sample-content-block"), session, "retail", "")
	if resp.Error != nil {
		t.Fatalf("unexpected sampling error: %+v", resp.Error)
	}
	result := resp.Result.(map[string]any)
	content := result["content"].(map[string]any)
	if content["type"] != "image" || content["data"] != imageData {
		t.Fatalf("expected governed image sampling response, got %+v", content)
	}
	event := contentBlocksAuditEvent(t, recorder.snapshot())
	imageAudit := findContentBlockAudit(t, event, "image", false)
	if imageAudit.SizeBytes != len(imageBytes) || imageAudit.Digest != canonicaljson.HashSHA256(imageBytes) {
		t.Fatalf("expected deterministic sampling image audit, got %+v", imageAudit)
	}
}

func newContentBlockServer(t *testing.T, bundle string, upstream *upstreamHTTPTestServer, recorder audit.Recorder, emitter *telemetry.Emitter) *Server {
	t.Helper()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServerWithRuntimeOptionsAndRecorder(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "error",
		LogFormat: "text",
		ErrWriter: io.Discard,
		UpstreamServers: []UpstreamServerConfig{{
			Name:        "retail",
			Transport:   "streamable_http",
			Endpoint:    upstream.endpoint(),
			TLSInsecure: true,
		}},
		Telemetry: emitter,
	}, recorder)
	if err != nil {
		t.Fatalf("new content block server: %v", err)
	}
	return server
}

func newSamplingContentBlockServer(t *testing.T, bundle string, recorder audit.Recorder) *Server {
	t.Helper()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServerWithRuntimeOptionsAndRecorder(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "error",
		LogFormat: "text",
		ErrWriter: io.Discard,
	}, recorder)
	if err != nil {
		t.Fatalf("new sampling content block server: %v", err)
	}
	return server
}

func contentBlockBundle(kinds []string, extraObligations map[string]any) string {
	obligations := map[string]any{}
	for key, value := range extraObligations {
		obligations[key] = value
	}
	if kinds != nil {
		obligations[mcpAllowedContentBlockKindsObligation] = kinds
	}
	rule := map[string]any{
		"id":           "allow-refund",
		"action_type":  "mcp.call",
		"resource":     "mcp://retail/refund.request",
		"decision":     "ALLOW",
		"principals":   []string{"system"},
		"agents":       []string{"nomos"},
		"environments": []string{"dev"},
	}
	if len(obligations) > 0 {
		rule["obligations"] = obligations
	}
	data, _ := json.Marshal(map[string]any{"version": "v1", "rules": []any{rule}})
	return string(data)
}

func contentBlockSamplingBundle(kinds []string) string {
	obligations := map[string]any{}
	if kinds != nil {
		obligations[mcpAllowedContentBlockKindsObligation] = kinds
	}
	rule := map[string]any{
		"id":           "allow-sampling",
		"action_type":  "mcp.sample",
		"resource":     "mcp://retail/sample",
		"decision":     "ALLOW",
		"principals":   []string{"system"},
		"agents":       []string{"nomos"},
		"environments": []string{"dev"},
	}
	if len(obligations) > 0 {
		rule["obligations"] = obligations
	}
	data, _ := json.Marshal(map[string]any{"version": "v1", "rules": []any{rule}})
	return string(data)
}

func newSamplingContentBlockClientSession(t *testing.T, server *Server, content map[string]any) *downstreamSession {
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
				"role":    "assistant",
				"content": content,
			},
		}
		data, _ := json.Marshal(resp)
		_ = session.handleRPCResponse(data)
	}()
	return session
}

func callContentBlockToolRPC(t *testing.T, server *Server) []map[string]any {
	t.Helper()
	var in bytes.Buffer
	writeFramedRequest(t, &in, map[string]any{
		"jsonrpc": "2.0",
		"id":      "init",
		"method":  "initialize",
		"params":  map[string]any{},
	})
	writeFramedRequest(t, &in, map[string]any{
		"jsonrpc": "2.0",
		"id":      "call",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "upstream_retail_refund_request",
			"arguments": map[string]any{"order_id": "ORD-1001"},
		},
	})
	var out bytes.Buffer
	if err := server.ServeStdio(&in, &out); err != nil {
		t.Fatalf("serve stdio: %v", err)
	}
	reader := bufio.NewReader(bytes.NewReader(out.Bytes()))
	initResp := readFramedResponse(t, reader)
	if initResp["error"] != nil {
		t.Fatalf("unexpected initialize error: %+v", initResp["error"])
	}
	callResp := readFramedResponse(t, reader)
	if callResp["error"] != nil {
		t.Fatalf("unexpected call error: %+v", callResp["error"])
	}
	result := callResp["result"].(map[string]any)
	rawContent := result["content"].([]any)
	content := make([]map[string]any, 0, len(rawContent))
	for _, item := range rawContent {
		block, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("expected content block map, got %+v", item)
		}
		content = append(content, block)
	}
	return content
}

func contentBlockActionResponse(t *testing.T, resp Response) action.Response {
	t.Helper()
	if resp.Error != "" {
		t.Fatalf("unexpected response error: %+v", resp)
	}
	result, ok := resp.Result.(action.Response)
	if !ok {
		t.Fatalf("expected action response, got %+T", resp.Result)
	}
	return result
}

func contentBlocksAuditEvent(t *testing.T, events []audit.Event) audit.Event {
	t.Helper()
	for _, event := range events {
		if event.EventType == "mcp.content_blocks" {
			return event
		}
	}
	t.Fatalf("missing mcp.content_blocks event in %+v", events)
	return audit.Event{}
}

func findContentBlockAudit(t *testing.T, event audit.Event, kind string, blocked bool) mcpContentBlockAudit {
	t.Helper()
	blocks, ok := event.ExecutorMetadata["mcp_content_blocks"].([]mcpContentBlockAudit)
	if !ok {
		t.Fatalf("expected typed content block audit metadata, got %+v", event.ExecutorMetadata["mcp_content_blocks"])
	}
	for _, block := range blocks {
		if block.Kind == kind && block.Blocked == blocked {
			return block
		}
	}
	t.Fatalf("missing content block audit kind=%s blocked=%v in %+v", kind, blocked, blocks)
	return mcpContentBlockAudit{}
}

func assertAuditDoesNotContain(t *testing.T, event audit.Event, raw string) {
	t.Helper()
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal audit event: %v", err)
	}
	if strings.Contains(string(data), raw) {
		t.Fatalf("audit leaked raw content %q in %s", raw, data)
	}
}

func hasContentBlockMetric(metrics []telemetry.Metric, kind, status string) bool {
	for _, metric := range metrics {
		if metric.Name == mcpContentBlockMetricName && metric.Attributes["kind"] == kind && metric.Attributes["status"] == status {
			return true
		}
	}
	return false
}
