package quickstart

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/schema"
	"gopkg.in/yaml.v3"
)

func TestHTTPContractArtifactsExistAndParse(t *testing.T) {
	root := repoRoot(t)
	required := []string{
		"docs/http-integration-kit.md",
		"docs/openapi/nomos-http-v1.yaml",
		"docs/schemas/action-request.v1.json",
		"docs/schemas/action-response.v1.json",
		"docs/schemas/approval-decision-request.v1.json",
		"docs/schemas/explain-response.v1.json",
		"docs/schemas/external-report-request.v1.json",
		"docs/schemas/external-report-response.v1.json",
		"examples/http-contract/action-fs-read.request.json",
		"examples/http-contract/action-custom-refund.request.json",
		"examples/http-contract/approval-decision.request.json",
		"examples/http-contract/action-allow.response.json",
		"examples/http-contract/action-approval.response.json",
		"examples/http-contract/action-custom-allow.response.json",
		"examples/http-contract/explain.response.json",
		"examples/http-contract/external-report.request.json",
		"examples/http-contract/external-report.response.json",
	}
	for _, rel := range required {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("missing contract artifact %s: %v", rel, err)
		}
	}

	var openapi struct {
		OpenAPI string                    `yaml:"openapi"`
		Info    map[string]any            `yaml:"info"`
		Paths   map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal([]byte(mustReadFile(t, filepath.Join(root, "docs", "openapi", "nomos-http-v1.yaml"))), &openapi); err != nil {
		t.Fatalf("parse openapi: %v", err)
	}
	if openapi.OpenAPI == "" || openapi.Info["version"] != "v1" {
		t.Fatalf("unexpected openapi header: %+v", openapi)
	}
	for _, p := range []string{"/action", "/run", "/approvals/decide", "/explain", "/actions/report"} {
		if _, ok := openapi.Paths[p]; !ok {
			t.Fatalf("openapi missing path %s", p)
		}
	}
}

func TestHTTPContractExamplesValidateAgainstSchemas(t *testing.T) {
	root := repoRoot(t)
	validateSchemaExample(t,
		filepath.Join(root, "docs", "schemas", "action-request.v1.json"),
		filepath.Join(root, "examples", "http-contract", "action-fs-read.request.json"),
	)
	validateSchemaExample(t,
		filepath.Join(root, "docs", "schemas", "action-request.v1.json"),
		filepath.Join(root, "examples", "http-contract", "action-custom-refund.request.json"),
	)
	validateSchemaExample(t,
		filepath.Join(root, "docs", "schemas", "approval-decision-request.v1.json"),
		filepath.Join(root, "examples", "http-contract", "approval-decision.request.json"),
	)
	validateSchemaExample(t,
		filepath.Join(root, "docs", "schemas", "action-response.v1.json"),
		filepath.Join(root, "examples", "http-contract", "action-allow.response.json"),
	)
	validateSchemaExample(t,
		filepath.Join(root, "docs", "schemas", "action-response.v1.json"),
		filepath.Join(root, "examples", "http-contract", "action-approval.response.json"),
	)
	validateSchemaExample(t,
		filepath.Join(root, "docs", "schemas", "action-response.v1.json"),
		filepath.Join(root, "examples", "http-contract", "action-custom-allow.response.json"),
	)
	validateSchemaExample(t,
		filepath.Join(root, "docs", "schemas", "explain-response.v1.json"),
		filepath.Join(root, "examples", "http-contract", "explain.response.json"),
	)
	validateSchemaExample(t,
		filepath.Join(root, "docs", "schemas", "external-report-request.v1.json"),
		filepath.Join(root, "examples", "http-contract", "external-report.request.json"),
	)
	validateSchemaExample(t,
		filepath.Join(root, "docs", "schemas", "external-report-response.v1.json"),
		filepath.Join(root, "examples", "http-contract", "external-report.response.json"),
	)

	if _, err := action.DecodeActionRequestBytes([]byte(mustReadFile(t, filepath.Join(root, "examples", "http-contract", "action-fs-read.request.json")))); err != nil {
		t.Fatalf("decode fs.read action request example: %v", err)
	}
	if _, err := action.DecodeActionRequestBytes([]byte(mustReadFile(t, filepath.Join(root, "examples", "http-contract", "action-custom-refund.request.json")))); err != nil {
		t.Fatalf("decode custom action request example: %v", err)
	}
}

func validateSchemaExample(t *testing.T, schemaPath, examplePath string) {
	t.Helper()
	s, err := schema.ParseSchema([]byte(mustReadFile(t, schemaPath)))
	if err != nil {
		t.Fatalf("parse schema %s: %v", schemaPath, err)
	}
	payload := []byte(mustReadFile(t, examplePath))
	if err := schema.Validate(s, payload); err != nil {
		t.Fatalf("validate example %s against %s: %v", examplePath, schemaPath, err)
	}
	var generic map[string]any
	if err := json.Unmarshal(payload, &generic); err != nil {
		t.Fatalf("json parse example %s: %v", examplePath, err)
	}
}
