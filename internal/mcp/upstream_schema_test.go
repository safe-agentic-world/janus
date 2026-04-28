package mcp

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateUpstreamToolArgumentsValidCanonicalized(t *testing.T) {
	tool := upstreamTool{
		ServerName:  "retail",
		ToolName:    "refund.request",
		InputSchema: refundRequestTestSchema(),
	}
	got, err := validateUpstreamToolArguments(tool, []byte(`{"reason":"damaged","order_id":"ORD-1001"}`))
	if err != nil {
		t.Fatalf("validate arguments: %v", err)
	}
	if string(got.CanonicalBytes) != `{"order_id":"ORD-1001","reason":"damaged"}` {
		t.Fatalf("unexpected canonical arguments: %s", got.CanonicalBytes)
	}
	if got.Hash == "" {
		t.Fatal("expected canonical argument hash")
	}
}

func TestValidateUpstreamToolArgumentsInvalidStructuredNoRawValues(t *testing.T) {
	tool := upstreamTool{InputSchema: refundRequestTestSchema()}
	_, err := validateUpstreamToolArguments(tool, []byte(`{"order_id":"ORD-1001","reason":42}`))
	if err == nil {
		t.Fatal("expected validation error")
	}
	var failure *upstreamArgumentValidationFailure
	if !errors.As(err, &failure) {
		t.Fatalf("expected structured validation failure, got %T %v", err, err)
	}
	if len(failure.Details) != 1 {
		t.Fatalf("expected one validation detail, got %+v", failure.Details)
	}
	detail := failure.Details[0]
	if detail.Path != "$.reason" || detail.Expected != "string" || detail.Actual != "number" {
		t.Fatalf("unexpected validation detail: %+v", detail)
	}
	if strings.Contains(err.Error(), "ORD-1001") || strings.Contains(err.Error(), "42") {
		t.Fatalf("validation error must not echo raw values: %v", err)
	}
}

func TestValidateUpstreamToolArgumentsDoSBounds(t *testing.T) {
	tool := upstreamTool{InputSchema: map[string]any{
		"type":                 "object",
		"additionalProperties": true,
	}}
	var b strings.Builder
	for i := 0; i < maxForwardedArgumentDepth+2; i++ {
		b.WriteString(`{"x":`)
	}
	b.WriteString(`"leaf"`)
	for i := 0; i < maxForwardedArgumentDepth+2; i++ {
		b.WriteByte('}')
	}
	_, err := validateUpstreamToolArguments(tool, []byte(b.String()))
	if err == nil {
		t.Fatal("expected depth-bounded validation failure")
	}
	var failure *upstreamArgumentValidationFailure
	if !errors.As(err, &failure) {
		t.Fatalf("expected structured validation failure, got %T %v", err, err)
	}
	if !strings.Contains(failure.Details[0].Expected, "depth<=") {
		t.Fatalf("expected depth validation detail, got %+v", failure.Details)
	}

	large := []byte(`{"x":"` + strings.Repeat("a", maxForwardedArgumentBytes) + `"}`)
	if _, err := validateUpstreamToolArguments(tool, large); err == nil {
		t.Fatal("expected byte-bounded validation failure")
	}
}

func refundRequestTestSchema() map[string]any {
	return map[string]any{
		"$schema": upstreamToolSchemaDialect,
		"type":    "object",
		"properties": map[string]any{
			"order_id": map[string]any{"type": "string"},
			"reason":   map[string]any{"type": "string"},
		},
		"required":             []any{"order_id", "reason"},
		"additionalProperties": false,
	}
}
