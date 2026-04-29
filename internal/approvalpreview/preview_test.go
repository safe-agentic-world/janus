package approvalpreview

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

func TestFromNormalizedBuildsRedactedCanonicalMCPPreview(t *testing.T) {
	args := []byte(`{"authorization":"Bearer very-secret-token","order_id":"ORD-1001","reason":"damaged"}`)
	canonicalArgs, err := canonicaljson.Canonicalize(args)
	if err != nil {
		t.Fatalf("canonicalize args: %v", err)
	}
	hash := canonicaljson.HashSHA256(canonicalArgs)
	params := []byte(`{"tool_schema_validated":true,"tool_arguments_hash":"` + hash + `","upstream_tool":"refund.request","tool_arguments":{"reason":"damaged","authorization":"Bearer very-secret-token","order_id":"ORD-1001"},"upstream_server":"retail"}`)
	canonicalParams, err := canonicaljson.Canonicalize(params)
	if err != nil {
		t.Fatalf("canonicalize params: %v", err)
	}

	preview, ok := FromNormalized(redact.DefaultRedactor(), normalize.NormalizedAction{
		ActionType:  "mcp.call",
		Params:      canonicalParams,
		ParamsHash:  canonicaljson.HashSHA256(canonicalParams),
		Resource:    "mcp://retail/refund.request",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if !ok {
		t.Fatal("expected preview")
	}
	text := string(preview)
	if strings.Contains(text, "very-secret-token") {
		t.Fatalf("preview leaked secret: %s", text)
	}
	if !strings.Contains(text, redactionMarker) || !strings.Contains(text, `"order_id":"ORD-1001"`) || !strings.Contains(text, hash) {
		t.Fatalf("unexpected preview: %s", text)
	}
	if len(preview) > MaxPreviewBytes {
		t.Fatalf("preview exceeded cap: %d", len(preview))
	}
	var parsed map[string]any
	if err := json.Unmarshal(preview, &parsed); err != nil {
		t.Fatalf("preview is not valid json: %v", err)
	}
	if parsed["params_hash"] != canonicaljson.HashSHA256(canonicalParams) {
		t.Fatalf("expected params_hash parity, got %+v", parsed)
	}
}

func TestFromNormalizedCapsOversizedPreview(t *testing.T) {
	params := []byte(`{"tool_arguments":{"note":"` + strings.Repeat("x", 10000) + `"},"tool_arguments_hash":"hash","upstream_server":"retail","upstream_tool":"refund.request"}`)
	canonicalParams, err := canonicaljson.Canonicalize(params)
	if err != nil {
		t.Fatalf("canonicalize params: %v", err)
	}
	preview, ok := FromNormalized(redact.DefaultRedactor(), normalize.NormalizedAction{
		ActionType: "mcp.call",
		Params:     canonicalParams,
		ParamsHash: canonicaljson.HashSHA256(canonicalParams),
	})
	if !ok {
		t.Fatal("expected preview")
	}
	if len(preview) > MaxPreviewBytes {
		t.Fatalf("preview exceeded cap: %d", len(preview))
	}
	if !strings.Contains(string(preview), `"truncated":true`) {
		t.Fatalf("expected truncated preview, got %s", preview)
	}
}
