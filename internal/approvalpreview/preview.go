package approvalpreview

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

const (
	MaxPreviewBytes       = 4096
	maxPreviewStringBytes = 512
	maxPreviewNodes       = 4096
)

const redactionMarker = "[REDACTED]"

type previewBudget struct {
	nodes     int
	truncated bool
}

// FromNormalized returns the bounded, redacted argument preview for MCP call
// approvals. The preview is derived from NormalizedAction.Params, which is the
// same canonical params blob used by the action fingerprint.
func FromNormalized(redactor *redact.Redactor, normalized normalize.NormalizedAction) (json.RawMessage, bool) {
	if normalized.ActionType != "mcp.call" {
		return nil, false
	}
	params, err := decodeObject(normalized.Params)
	if err != nil {
		return nil, false
	}
	args, ok := params["tool_arguments"]
	if !ok {
		return nil, false
	}
	if redactor == nil {
		redactor = redact.DefaultRedactor()
	}
	budget := &previewBudget{}
	redactedArgs := redactPreviewValue(redactor, "tool_arguments", args, budget)
	preview := map[string]any{
		"canonical":           true,
		"kind":                "mcp_call_arguments",
		"params_hash":         normalized.ParamsHash,
		"redacted":            true,
		"tool_arguments":      redactedArgs,
		"tool_arguments_hash": stringValue(params["tool_arguments_hash"]),
		"truncated":           budget.truncated,
		"upstream_server":     stringValue(params["upstream_server"]),
		"upstream_tool":       stringValue(params["upstream_tool"]),
	}
	payload, err := canonicalPreview(preview)
	if err != nil {
		return nil, false
	}
	if len(payload) <= MaxPreviewBytes {
		return json.RawMessage(payload), true
	}
	preview["tool_arguments"] = map[string]any{
		"_nomos_preview_truncated": true,
		"reason":                   "canonical argument preview exceeded size cap",
	}
	preview["truncated"] = true
	payload, err = canonicalPreview(preview)
	if err != nil {
		return nil, false
	}
	if len(payload) > MaxPreviewBytes {
		preview = map[string]any{
			"canonical":   true,
			"kind":        "mcp_call_arguments",
			"params_hash": normalized.ParamsHash,
			"redacted":    true,
			"tool_arguments": map[string]any{
				"_nomos_preview_truncated": true,
				"reason":                   "canonical argument preview exceeded size cap",
			},
			"truncated": true,
		}
		payload, err = canonicalPreview(preview)
		if err != nil {
			return nil, false
		}
	}
	return json.RawMessage(payload), true
}

func Decode(raw string) (any, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, false
	}
	return value, true
}

func decodeObject(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, io.ErrUnexpectedEOF
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, io.ErrUnexpectedEOF
	}
	return obj, nil
}

func canonicalPreview(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonicalize(payload)
}

func redactPreviewValue(redactor *redact.Redactor, key string, value any, budget *previewBudget) any {
	budget.nodes++
	if budget.nodes > maxPreviewNodes {
		budget.truncated = true
		return map[string]any{"_nomos_preview_truncated": true}
	}
	if isSensitiveFieldName(key) {
		return redactionMarker
	}
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		keys := make([]string, 0, len(typed))
		for k := range typed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, childKey := range keys {
			out[childKey] = redactPreviewValue(redactor, childKey, typed[childKey], budget)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, redactPreviewValue(redactor, key, item, budget))
		}
		return out
	case string:
		return capString(redactor.RedactText(typed), budget)
	default:
		return typed
	}
}

func capString(value string, budget *previewBudget) string {
	if len(value) <= maxPreviewStringBytes {
		return value
	}
	budget.truncated = true
	capped := value[:maxPreviewStringBytes]
	for !utf8.ValidString(capped) && len(capped) > 0 {
		capped = capped[:len(capped)-1]
	}
	return capped + "...[truncated]"
}

func stringValue(value any) string {
	if typed, ok := value.(string); ok {
		return typed
	}
	return ""
}

func isSensitiveFieldName(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(key, "-", "_")))
	switch normalized {
	case "authorization", "proxy_authorization", "cookie", "set_cookie", "x_api_key", "x_auth_token",
		"api_key", "apikey", "access_token", "refresh_token", "token", "tokens", "secret", "secrets",
		"password", "passwords", "passwd", "credential", "credentials", "private_key":
		return true
	default:
		return strings.HasSuffix(normalized, "_token") ||
			strings.HasSuffix(normalized, "_secret") ||
			strings.HasSuffix(normalized, "_password") ||
			strings.HasSuffix(normalized, "_api_key")
	}
}
