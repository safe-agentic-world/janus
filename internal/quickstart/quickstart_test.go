package quickstart

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/gateway"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

func TestQuickstartDocsReferenceExistingFilesAndCurrentFlags(t *testing.T) {
	root := repoRoot(t)
	quickstartPath := filepath.Join(root, "docs", "quickstart.md")
	integrationPath := filepath.Join(root, "docs", "integration-kit.md")
	httpContractPath := filepath.Join(root, "docs", "http-integration-kit.md")
	quickstart := mustReadFile(t, quickstartPath)
	integration := mustReadFile(t, integrationPath)
	httpContract := mustReadFile(t, httpContractPath)

	requiredFiles := []string{
		"examples/quickstart/config.quickstart.json",
		"examples/quickstart/actions/allow-readme.json",
		"examples/quickstart/actions/deny-env.json",
		"examples/openai-compatible/nomos_http_loop.py",
		"examples/http-sdk/go/main.go",
		"examples/http-sdk/go/guarded-http-tool/main.go",
		"examples/http-sdk/python/quickstart.py",
		"examples/http-sdk/python/guarded_langchain_tool.py",
		"examples/http-sdk/python/custom_action_external.py",
		"examples/http-sdk/typescript/quickstart.ts",
		"examples/http-sdk/typescript/guarded_cli_tool.ts",
		"sdk/python/nomos_sdk.py",
		"sdk/typescript/nomos_sdk.ts",
		"docs/http-sdk.md",
		"docs/http-integration-kit.md",
		"docs/integration-patterns.md",
		"docs/custom-actions.md",
		"docs/openapi/nomos-http-v1.yaml",
		"docs/schemas/action-request.v1.json",
		"docs/schemas/action-response.v1.json",
		"examples/local-tooling/codex.mcp.json",
		"examples/local-tooling/claude-code-mcp.json",
	}
	for _, rel := range requiredFiles {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("expected referenced file %s to exist: %v", rel, err)
		}
	}

	requiredQuickstartCommands := []string{
		`nomos doctor -c .\examples\quickstart\config.quickstart.json --format json`,
		`nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\examples\policies\safe.yaml`,
		`nomos policy test --action .\examples\quickstart\actions\deny-env.json --bundle .\examples\policies\safe.yaml`,
		`nomos serve -c .\examples\quickstart\config.quickstart.json`,
	}
	for _, snippet := range requiredQuickstartCommands {
		if !strings.Contains(quickstart, snippet) {
			t.Fatalf("quickstart missing command %q", snippet)
		}
	}

	requiredIntegrationCommands := []string{
		`nomos mcp -c .\examples\quickstart\config.quickstart.json`,
		`nomos doctor -c .\examples\quickstart\config.quickstart.json --format json`,
		`nomos serve -c .\examples\quickstart\config.quickstart.json`,
	}
	for _, snippet := range requiredIntegrationCommands {
		if !strings.Contains(integration, snippet) {
			t.Fatalf("integration kit missing command %q", snippet)
		}
	}
	requiredHTTPContractSnippets := []string{
		"`POST /action`",
		"`POST /approvals/decide`",
		"`POST /explain`",
		"`POST /actions/report`",
		"`Authorization: Bearer <principal token>`",
	}
	for _, snippet := range requiredHTTPContractSnippets {
		if !strings.Contains(httpContract, snippet) {
			t.Fatalf("http integration kit missing snippet %q", snippet)
		}
	}
}

func TestQuickstartExamplesLoadAndProduceDeterministicAllowAndDeny(t *testing.T) {
	root := repoRoot(t)
	configPath := filepath.Join(root, "examples", "quickstart", "config.quickstart.json")
	cfg, err := gateway.LoadConfig(configPath, func(string) string { return "" }, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Policy.BundlePath == "" {
		t.Fatal("expected policy bundle path")
	}
	bundle, err := policy.LoadBundle(cfg.Policy.BundlePath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	engine := policy.NewEngine(bundle)

	allowActionPath := filepath.Join(root, "examples", "quickstart", "actions", "allow-readme.json")
	denyActionPath := filepath.Join(root, "examples", "quickstart", "actions", "deny-env.json")
	allowAction, err := action.DecodeAction([]byte(mustReadFile(t, allowActionPath)))
	if err != nil {
		t.Fatalf("decode allow action: %v", err)
	}
	denyAction, err := action.DecodeAction([]byte(mustReadFile(t, denyActionPath)))
	if err != nil {
		t.Fatalf("decode deny action: %v", err)
	}

	allowNorm, err := normalize.Action(allowAction)
	if err != nil {
		t.Fatalf("normalize allow action: %v", err)
	}
	denyNorm, err := normalize.Action(denyAction)
	if err != nil {
		t.Fatalf("normalize deny action: %v", err)
	}

	allowDecision := engine.Evaluate(allowNorm)
	denyDecision := engine.Evaluate(denyNorm)
	if allowDecision.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow action to allow, got %+v", allowDecision)
	}
	if denyDecision.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny action to deny, got %+v", denyDecision)
	}

	allowReqPath := filepath.Join(root, "examples", "quickstart", "requests", "allow-readme.json")
	denyReqPath := filepath.Join(root, "examples", "quickstart", "requests", "deny-env.json")
	if _, err := action.DecodeActionRequestBytes([]byte(mustReadFile(t, allowReqPath))); err != nil {
		t.Fatalf("decode allow request: %v", err)
	}
	if _, err := action.DecodeActionRequestBytes([]byte(mustReadFile(t, denyReqPath))); err != nil {
		t.Fatalf("decode deny request: %v", err)
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Clean(filepath.Join(dir, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

func TestExampleJSONFilesStayValid(t *testing.T) {
	root := repoRoot(t)
	paths := []string{
		filepath.Join(root, "examples", "local-tooling", "codex.mcp.json"),
		filepath.Join(root, "examples", "local-tooling", "claude-code-mcp.json"),
	}
	for _, path := range paths {
		var data map[string]any
		if err := json.Unmarshal([]byte(mustReadFile(t, path)), &data); err != nil {
			t.Fatalf("parse json %s: %v", path, err)
		}
	}
}
