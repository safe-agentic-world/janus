package mcp

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
	"github.com/safe-agentic-world/nomos/internal/telemetry"
)

const (
	mcpAllowedContentBlockKindsObligation = "mcp_allowed_content_block_kinds"
	mcpContentBlockMetricName             = "nomos.mcp_content_blocks"
)

var mcpContentBlockKindObligationAliases = []string{
	mcpAllowedContentBlockKindsObligation,
	"mcp_content_block_kinds",
	"allowed_content_block_kinds",
	"response_content_block_kinds",
}

type governedMCPContent struct {
	Text                     string
	Blocks                   []map[string]any
	Truncated                bool
	Denied                   bool
	BlockPolicyMisconfigured bool
	AllowedKinds             []string
}

type mcpContentBlockAudit struct {
	Index       int    `json:"index"`
	Kind        string `json:"kind"`
	Type        string `json:"type"`
	SizeBytes   int    `json:"size_bytes"`
	Digest      string `json:"digest"`
	Blocked     bool   `json:"blocked,omitempty"`
	BlockedKind string `json:"blocked_kind,omitempty"`
	Truncated   bool   `json:"truncated,omitempty"`
}

func (s *Server) governForwardedContent(result upstreamToolCallResult, obligations map[string]any, actionReq action.Request, tool upstreamTool) governedMCPContent {
	allowedKinds, policyOK := allowedMCPContentBlockKinds(obligations)
	governed := governedMCPContent{
		BlockPolicyMisconfigured: !policyOK,
		AllowedKinds:             sortedAllowedMCPContentKinds(allowedKinds),
	}
	textParts := make([]string, 0)
	maxBinaryBytes := forwardedContentBinaryMaxBytes(obligations, s.outputMaxBytes)
	for _, raw := range result.Blocks {
		kind := raw.Kind
		if kind == "" {
			kind = canonicalMCPContentKind(raw.Type)
		}
		if kind == "" {
			kind = "unknown"
		}
		if raw.Malformed || raw.Payload == nil {
			governed.Blocks = append(governed.Blocks, blockedMCPContentPlaceholder(kind, "malformed_block"))
			continue
		}
		if !allowedKinds[kind] {
			governed.Blocks = append(governed.Blocks, blockedMCPContentPlaceholder(kind, "block_kind_not_allowed"))
			continue
		}
		switch kind {
		case "text":
			text, ok := raw.Payload["text"].(string)
			if !ok {
				governed.Blocks = append(governed.Blocks, blockedMCPContentPlaceholder(kind, "malformed_text_block"))
				continue
			}
			textParts = append(textParts, redactForwardedOutput(s.logger.redactor, text))
		case "image", "audio":
			block, truncated, denied, ok := s.governBinaryMCPContentBlock(raw.Payload, kind, maxBinaryBytes, obligations, actionReq, tool)
			if denied {
				governed.Denied = true
				return governed
			}
			if !ok {
				governed.Blocks = append(governed.Blocks, blockedMCPContentPlaceholder(kind, "malformed_binary_block"))
				continue
			}
			governed.Blocks = append(governed.Blocks, block)
			governed.Truncated = governed.Truncated || truncated
		case "resource":
			block, truncated, denied, ok := s.governResourceMCPContentBlock(raw.Payload, maxBinaryBytes, obligations, actionReq, tool)
			if denied {
				governed.Denied = true
				return governed
			}
			if !ok {
				governed.Blocks = append(governed.Blocks, blockedMCPContentPlaceholder(kind, "malformed_resource_block"))
				continue
			}
			governed.Blocks = append(governed.Blocks, block)
			governed.Truncated = governed.Truncated || truncated
		case "tool_result":
			block, truncated, denied := s.governGenericMCPContentBlock(raw.Payload, obligations, actionReq, tool)
			if denied {
				governed.Denied = true
				return governed
			}
			governed.Blocks = append(governed.Blocks, block)
			governed.Truncated = governed.Truncated || truncated
		default:
			governed.Blocks = append(governed.Blocks, blockedMCPContentPlaceholder(kind, "unknown_block_kind"))
		}
	}
	scanned := s.scanForwardedResponse(strings.Join(textParts, "\n"), obligations, actionReq, tool)
	if scanned.Denied {
		governed.Denied = true
		return governed
	}
	text, textTruncated := limitForwardedOutput(scanned.Text, obligations)
	governed.Text = text
	governed.Truncated = governed.Truncated || textTruncated
	return governed
}

func (s *Server) governBinaryMCPContentBlock(block map[string]any, kind string, maxBytes int, obligations map[string]any, actionReq action.Request, tool upstreamTool) (map[string]any, bool, bool, bool) {
	out := make(map[string]any, len(block))
	truncated := false
	sawData := false
	for key, value := range block {
		if key == "data" {
			data, ok := value.(string)
			if !ok {
				return nil, false, false, false
			}
			decoded, err := decodeMCPBase64(data)
			if err != nil {
				return nil, false, false, false
			}
			if maxBytes >= 0 && len(decoded) > maxBytes {
				decoded = decoded[:maxBytes]
				data = base64.StdEncoding.EncodeToString(decoded)
				truncated = true
			}
			out[key] = data
			sawData = true
			continue
		}
		governed, denied := s.governMCPMetadataValue(value, obligations, actionReq, tool)
		if denied {
			return nil, false, true, false
		}
		out[key] = governed
	}
	if !sawData {
		return nil, false, false, false
	}
	out["type"] = kind
	if truncated {
		addMCPBlockMeta(out, "nomos_truncated", true)
	}
	return out, truncated, false, true
}

func (s *Server) governResourceMCPContentBlock(block map[string]any, maxBytes int, obligations map[string]any, actionReq action.Request, tool upstreamTool) (map[string]any, bool, bool, bool) {
	out := make(map[string]any, len(block))
	truncated := false
	resourceValue, hasResource := block["resource"]
	if hasResource {
		governed, valueTruncated, denied, ok := s.governResourceValue(resourceValue, maxBytes, obligations, actionReq, tool)
		if denied {
			return nil, false, true, false
		}
		if !ok {
			return nil, false, false, false
		}
		out["resource"] = governed
		truncated = truncated || valueTruncated
	} else {
		resource := map[string]any{}
		for key, value := range block {
			if key == "type" {
				continue
			}
			resource[key] = value
		}
		if len(resource) == 0 {
			return nil, false, false, false
		}
		governed, valueTruncated, denied, ok := s.governResourceValue(resource, maxBytes, obligations, actionReq, tool)
		if denied {
			return nil, false, true, false
		}
		if !ok {
			return nil, false, false, false
		}
		out["resource"] = governed
		truncated = truncated || valueTruncated
	}
	for key, value := range block {
		if key == "resource" || key == "type" {
			continue
		}
		governed, valueTruncated, denied := s.governMCPStringValue(value, obligations, actionReq, tool)
		if denied {
			return nil, false, true, false
		}
		out[key] = governed
		truncated = truncated || valueTruncated
	}
	out["type"] = "resource"
	if truncated {
		addMCPBlockMeta(out, "nomos_truncated", true)
	}
	return out, truncated, false, true
}

func (s *Server) governGenericMCPContentBlock(block map[string]any, obligations map[string]any, actionReq action.Request, tool upstreamTool) (map[string]any, bool, bool) {
	out := make(map[string]any, len(block))
	truncated := false
	for key, value := range block {
		governed, valueTruncated, denied := s.governMCPStringValue(value, obligations, actionReq, tool)
		if denied {
			return nil, false, true
		}
		out[key] = governed
		truncated = truncated || valueTruncated
	}
	if _, ok := out["type"].(string); !ok {
		out["type"] = "tool_result"
	}
	if truncated {
		addMCPBlockMeta(out, "nomos_truncated", true)
	}
	return out, truncated, false
}

func (s *Server) governResourceValue(value any, maxBytes int, obligations map[string]any, actionReq action.Request, tool upstreamTool) (any, bool, bool, bool) {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		truncated := false
		for key, child := range typed {
			if key == "blob" {
				blob, ok := child.(string)
				if !ok {
					return nil, false, false, false
				}
				decoded, err := decodeMCPBase64(blob)
				if err != nil {
					return nil, false, false, false
				}
				if maxBytes >= 0 && len(decoded) > maxBytes {
					decoded = decoded[:maxBytes]
					blob = base64.StdEncoding.EncodeToString(decoded)
					truncated = true
				}
				out[key] = blob
				continue
			}
			governed, valueTruncated, denied := s.governMCPStringValue(child, obligations, actionReq, tool)
			if denied {
				return nil, false, true, false
			}
			out[key] = governed
			truncated = truncated || valueTruncated
		}
		return out, truncated, false, true
	case []any:
		out := make([]any, 0, len(typed))
		truncated := false
		for _, child := range typed {
			governed, valueTruncated, denied, ok := s.governResourceValue(child, maxBytes, obligations, actionReq, tool)
			if denied {
				return nil, false, true, false
			}
			if !ok {
				return nil, false, false, false
			}
			out = append(out, governed)
			truncated = truncated || valueTruncated
		}
		return out, truncated, false, true
	default:
		governed, truncated, denied := s.governMCPStringValue(value, obligations, actionReq, tool)
		return governed, truncated, denied, true
	}
}

func (s *Server) governMCPStringValue(value any, obligations map[string]any, actionReq action.Request, tool upstreamTool) (any, bool, bool) {
	switch typed := value.(type) {
	case string:
		redacted := redactForwardedOutput(s.logger.redactor, typed)
		scanned := s.scanForwardedResponse(redacted, obligations, actionReq, tool)
		if scanned.Denied {
			return nil, false, true
		}
		limited, truncated := limitForwardedOutput(scanned.Text, obligations)
		return limited, truncated, false
	case map[string]any:
		out := make(map[string]any, len(typed))
		truncated := false
		for key, child := range typed {
			governed, valueTruncated, denied := s.governMCPStringValue(child, obligations, actionReq, tool)
			if denied {
				return nil, false, true
			}
			out[key] = governed
			truncated = truncated || valueTruncated
		}
		return out, truncated, false
	case []any:
		out := make([]any, 0, len(typed))
		truncated := false
		for _, child := range typed {
			governed, valueTruncated, denied := s.governMCPStringValue(child, obligations, actionReq, tool)
			if denied {
				return nil, false, true
			}
			out = append(out, governed)
			truncated = truncated || valueTruncated
		}
		return out, truncated, false
	default:
		return typed, false, false
	}
}

func (s *Server) governMCPMetadataValue(value any, obligations map[string]any, actionReq action.Request, tool upstreamTool) (any, bool) {
	switch typed := value.(type) {
	case string:
		redacted := redactForwardedOutput(s.logger.redactor, typed)
		scanned := s.scanForwardedResponse(redacted, obligations, actionReq, tool)
		if scanned.Denied {
			return nil, true
		}
		return scanned.Text, false
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			governed, denied := s.governMCPMetadataValue(child, obligations, actionReq, tool)
			if denied {
				return nil, true
			}
			out[key] = governed
		}
		return out, false
	case []any:
		out := make([]any, 0, len(typed))
		for _, child := range typed {
			governed, denied := s.governMCPMetadataValue(child, obligations, actionReq, tool)
			if denied {
				return nil, true
			}
			out = append(out, governed)
		}
		return out, false
	default:
		return typed, false
	}
}

func allowedMCPContentBlockKinds(obligations map[string]any) (map[string]bool, bool) {
	value, exists := firstMCPContentKindObligation(obligations)
	if !exists {
		return map[string]bool{"text": true}, true
	}
	kinds := map[string]bool{}
	for _, item := range obligationStringList(value) {
		kind := canonicalMCPContentKind(item)
		if !recognizedMCPContentKind(kind) {
			return map[string]bool{"text": true}, false
		}
		kinds[kind] = true
	}
	if len(kinds) == 0 {
		return map[string]bool{"text": true}, false
	}
	return kinds, true
}

func firstMCPContentKindObligation(obligations map[string]any) (any, bool) {
	for _, key := range mcpContentBlockKindObligationAliases {
		if value, ok := obligations[key]; ok {
			return value, true
		}
	}
	return nil, false
}

func obligationStringList(value any) []string {
	switch typed := value.(type) {
	case string:
		return strings.FieldsFunc(typed, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
		})
	case []string:
		return append([]string{}, typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil
			}
			out = append(out, text)
		}
		return out
	default:
		return nil
	}
}

func sortedAllowedMCPContentKinds(kinds map[string]bool) []string {
	order := []string{"text", "image", "audio", "resource", "tool_result"}
	out := make([]string, 0, len(kinds))
	for _, kind := range order {
		if kinds[kind] {
			out = append(out, kind)
		}
	}
	return out
}

func canonicalMCPContentKind(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	switch normalized {
	case "text":
		return "text"
	case "image":
		return "image"
	case "audio":
		return "audio"
	case "resource", "resource_embed", "resource_embedded", "embedded_resource", "resource_link":
		return "resource"
	case "tool_result", "tool_result_ref", "tool_result_reference", "tool_reference":
		return "tool_result"
	default:
		return "unknown"
	}
}

func recognizedMCPContentKind(kind string) bool {
	switch kind {
	case "text", "image", "audio", "resource", "tool_result":
		return true
	default:
		return false
	}
}

func forwardedContentBinaryMaxBytes(obligations map[string]any, fallback int) int {
	if maxBytes, ok := forwardedIntObligation(obligations["output_max_bytes"]); ok && maxBytes >= 0 {
		return maxBytes
	}
	if fallback >= 0 {
		return fallback
	}
	return -1
}

func blockedMCPContentPlaceholder(kind, reason string) map[string]any {
	if kind == "" {
		kind = "unknown"
	}
	if reason == "" {
		reason = "blocked"
	}
	return map[string]any{
		"type": "text",
		"text": "[Nomos blocked MCP content block: kind=" + kind + " reason=" + reason + "]",
		"_meta": map[string]any{
			"nomos_blocked_content_block": true,
			"blocked_kind":                kind,
			"reason":                      reason,
		},
	}
}

func addMCPBlockMeta(block map[string]any, key string, value any) {
	meta, _ := block["_meta"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	meta[key] = value
	block["_meta"] = meta
}

func cloneContentBlock(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = cloneContentValue(value)
	}
	return out
}

func cloneContentValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneContentBlock(typed)
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, cloneContentValue(item))
		}
		return out
	default:
		return typed
	}
}

func decodeMCPBase64(value string) ([]byte, error) {
	decoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, decoder := range decoders {
		decoded, err := decoder.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (s *Server) recordMCPContentBlocks(actionReq action.Request, tool upstreamTool, resp action.Response, governed governedMCPContent) {
	s.recordMCPContentBlockDelivery(actionReq, tool, actionResponseContentBlocks(tool.DownstreamName, resp), governed)
}

func (s *Server) recordMCPContentBlockDelivery(actionReq action.Request, tool upstreamTool, blocks []map[string]any, governed governedMCPContent) {
	if s == nil || s.service == nil {
		return
	}
	auditBlocks := auditMCPContentBlocks(blocks)
	metadata := map[string]any{
		"upstream_server":                        tool.ServerName,
		"upstream_tool":                          tool.ToolName,
		"mcp_content_block_count":                len(auditBlocks),
		"mcp_content_blocks":                     auditBlocks,
		"mcp_content_allowed_block_kinds":        governed.AllowedKinds,
		"mcp_content_block_policy_misconfigured": governed.BlockPolicyMisconfigured,
		"mcp_content_truncated":                  governed.Truncated,
		"mcp_content_downstream_tool_name":       tool.DownstreamName,
	}
	_ = s.service.RecordAuditEvent(audit.Event{
		SchemaVersion:        "v1",
		Timestamp:            time.Now().UTC(),
		EventType:            "mcp.content_blocks",
		TraceID:              actionReq.TraceID,
		ActionID:             actionReq.ActionID,
		Principal:            s.identity.Principal,
		Agent:                s.identity.Agent,
		Environment:          s.identity.Environment,
		ActionType:           actionReq.ActionType,
		Resource:             actionReq.Resource,
		ResultClassification: "MCP_CONTENT_BLOCKS_DELIVERED",
		ExecutorMetadata:     metadata,
	})
	s.emitMCPContentBlockTelemetry(actionReq.TraceID, auditBlocks)
}

func (s *Server) governSamplingResponseContent(resp *rpcResponse, actionResp action.Response, serverName string) (bool, *rpcResponse) {
	if resp == nil {
		return false, nil
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		return false, nil
	}
	content, ok := result["content"]
	if !ok {
		return false, nil
	}
	actionReq := action.Request{
		ActionID:   actionResp.ActionID,
		ActionType: "mcp.sample",
		Resource:   downstreamSamplingActionResource(serverName),
		TraceID:    actionResp.TraceID,
	}
	tool := upstreamTool{
		ServerName:     serverName,
		ToolName:       "sampling/createMessage",
		DownstreamName: "sampling/createMessage",
	}
	governed := s.governForwardedContent(upstreamToolCallResult{Blocks: parseRawMCPContentBlocks(content)}, actionResp.Obligations, actionReq, tool)
	if governed.Denied {
		return true, &rpcResponse{
			JSONRPC: "2.0",
			ID:      resp.ID,
			Error:   &rpcError{Code: -32603, Message: responseScanDeniedError},
		}
	}
	delivered := samplingContentBlocks(governed)
	if len(delivered) == 0 {
		delivered = []map[string]any{{"type": "text", "text": ""}}
	}
	result["content"] = cloneContentBlock(delivered[0])
	resp.Result = result
	s.recordMCPContentBlockDelivery(actionReq, tool, delivered[:1], governed)
	return false, resp
}

func samplingContentBlocks(governed governedMCPContent) []map[string]any {
	blocks := make([]map[string]any, 0, 1+len(governed.Blocks))
	if governed.Text != "" {
		blocks = append(blocks, map[string]any{"type": "text", "text": governed.Text})
	}
	for _, block := range governed.Blocks {
		blocks = append(blocks, cloneContentBlock(block))
	}
	return blocks
}

func auditMCPContentBlocks(blocks []map[string]any) []mcpContentBlockAudit {
	out := make([]mcpContentBlockAudit, 0, len(blocks))
	for idx, block := range blocks {
		kind := canonicalMCPContentKind(stringValue(block["type"]))
		if kind == "" {
			kind = "unknown"
		}
		blockedKind := blockedMCPContentKind(block)
		blocked := blockedKind != ""
		if blocked {
			kind = blockedKind
		}
		size, digest := mcpContentBlockSizeDigest(block)
		out = append(out, mcpContentBlockAudit{
			Index:       idx,
			Kind:        kind,
			Type:        stringValue(block["type"]),
			SizeBytes:   size,
			Digest:      digest,
			Blocked:     blocked,
			BlockedKind: blockedKind,
			Truncated:   boolMetaValue(block, "nomos_truncated"),
		})
	}
	return out
}

func mcpContentBlockSizeDigest(block map[string]any) (int, string) {
	switch canonicalMCPContentKind(stringValue(block["type"])) {
	case "text":
		text := stringValue(block["text"])
		return len([]byte(text)), canonicaljson.HashSHA256([]byte(text))
	case "image", "audio":
		decoded, err := decodeMCPBase64(stringValue(block["data"]))
		if err == nil {
			return len(decoded), canonicaljson.HashSHA256(decoded)
		}
	}
	payload, err := json.Marshal(block)
	if err != nil {
		return 0, ""
	}
	canonical, err := canonicaljson.Canonicalize(payload)
	if err != nil {
		return len(payload), canonicaljson.HashSHA256(payload)
	}
	return len(canonical), canonicaljson.HashSHA256(canonical)
}

func blockedMCPContentKind(block map[string]any) string {
	meta, _ := block["_meta"].(map[string]any)
	if meta == nil {
		return ""
	}
	blocked, _ := meta["nomos_blocked_content_block"].(bool)
	if !blocked {
		return ""
	}
	return canonicalMCPContentKind(stringValue(meta["blocked_kind"]))
}

func boolMetaValue(block map[string]any, key string) bool {
	meta, _ := block["_meta"].(map[string]any)
	if meta == nil {
		return false
	}
	value, _ := meta[key].(bool)
	return value
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func (s *Server) emitMCPContentBlockTelemetry(traceID string, blocks []mcpContentBlockAudit) {
	if s == nil || s.telemetry == nil || !s.telemetry.Enabled() {
		return
	}
	for _, block := range blocks {
		status := "delivered"
		if block.Blocked {
			status = "blocked"
		}
		s.telemetry.Metric(telemetry.Metric{
			SignalType: "metric",
			Name:       mcpContentBlockMetricName,
			Kind:       "counter",
			Value:      1,
			TraceID:    traceID,
			Attributes: map[string]string{
				"kind":   block.Kind,
				"status": status,
			},
		})
	}
}
