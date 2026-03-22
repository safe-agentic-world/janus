package quickstart

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/gateway"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"gopkg.in/yaml.v3"
)

func TestQuickstartDocsReferenceExistingFilesAndCurrentFlags(t *testing.T) {
	root := repoRoot(t)
	quickstartPath := filepath.Join(root, "docs", "quickstart.md")
	integrationPath := filepath.Join(root, "docs", "integration-kit.md")
	quickstart := mustReadFile(t, quickstartPath)
	integration := mustReadFile(t, integrationPath)

	requiredFiles := []string{
		"examples/quickstart/config.quickstart.json",
		"examples/quickstart/actions/allow-readme.json",
		"examples/quickstart/actions/deny-env.json",
		"examples/openai-compatible/nomos_http_loop.py",
		"examples/http-sdk/go/main.go",
		"examples/http-sdk/python/quickstart.py",
		"examples/http-sdk/typescript/quickstart.ts",
		"sdk/python/nomos_sdk.py",
		"sdk/typescript/nomos_sdk.ts",
		"docs/http-sdk.md",
		"examples/local-tooling/codex.mcp.json",
		"examples/local-tooling/claude-code-mcp.json",
		"deploy/docker-compose/docker-compose.yml",
		"deploy/helm/nomos/README.md",
	}
	for _, rel := range requiredFiles {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("expected referenced file %s to exist: %v", rel, err)
		}
	}

	requiredQuickstartCommands := []string{
		`nomos.exe doctor -c .\examples\quickstart\config.quickstart.json --format json`,
		`nomos.exe policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\examples\policies\safe.yaml`,
		`nomos.exe policy test --action .\examples\quickstart\actions\deny-env.json --bundle .\examples\policies\safe.yaml`,
		`nomos.exe serve -c .\examples\quickstart\config.quickstart.json`,
	}
	for _, snippet := range requiredQuickstartCommands {
		if !strings.Contains(quickstart, snippet) {
			t.Fatalf("quickstart missing command %q", snippet)
		}
	}

	requiredIntegrationCommands := []string{
		`nomos.exe mcp -c .\examples\quickstart\config.quickstart.json`,
		`nomos.exe doctor -c .\examples\quickstart\config.quickstart.json --format json`,
		`nomos.exe serve -c .\examples\quickstart\config.quickstart.json`,
	}
	for _, snippet := range requiredIntegrationCommands {
		if !strings.Contains(integration, snippet) {
			t.Fatalf("integration kit missing command %q", snippet)
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

func TestDockerComposeAndCIArtifactsValidate(t *testing.T) {
	root := repoRoot(t)

	var compose struct {
		Services map[string]struct {
			Build struct {
				Context    string `yaml:"context"`
				Dockerfile string `yaml:"dockerfile"`
			} `yaml:"build"`
			Command []string `yaml:"command"`
			Ports   []string `yaml:"ports"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(mustReadFile(t, filepath.Join(root, "deploy", "docker-compose", "docker-compose.yml"))), &compose); err != nil {
		t.Fatalf("parse docker compose: %v", err)
	}
	nomosService, ok := compose.Services["nomos"]
	if !ok {
		t.Fatal("expected docker compose nomos service")
	}
	if nomosService.Build.Context != "../.." || nomosService.Build.Dockerfile != "deploy/docker-compose/Dockerfile" {
		t.Fatalf("unexpected compose build config: %+v", nomosService.Build)
	}
	if len(nomosService.Ports) != 1 || nomosService.Ports[0] != "8080:8080" {
		t.Fatalf("unexpected compose ports: %+v", nomosService.Ports)
	}
	if strings.Join(nomosService.Command, " ") != "nomos serve -c /demo/examples/quickstart/config.quickstart.json" {
		t.Fatalf("unexpected compose command: %+v", nomosService.Command)
	}

	if _, err := os.Stat(filepath.Join(root, "deploy", "docker-compose", "Dockerfile")); err != nil {
		t.Fatalf("missing compose Dockerfile: %v", err)
	}

	var githubWorkflow map[string]any
	if err := yaml.Unmarshal([]byte(mustReadFile(t, filepath.Join(root, "deploy", "ci", "github-actions-quickstart.yml"))), &githubWorkflow); err != nil {
		t.Fatalf("parse github workflow: %v", err)
	}
	if _, ok := githubWorkflow["jobs"]; !ok {
		t.Fatal("expected github workflow jobs")
	}

	genericCI := mustReadFile(t, filepath.Join(root, "deploy", "ci", "generic-ci.sh"))
	requiredShellSnippets := []string{
		"#!/usr/bin/env sh",
		"set -eu",
		"./bin/nomos doctor -c ./examples/quickstart/config.quickstart.json --format json",
		"./bin/nomos policy test --action ./examples/quickstart/actions/allow-readme.json --bundle ./examples/policies/safe.yaml",
		"./bin/nomos policy test --action ./examples/quickstart/actions/deny-env.json --bundle ./examples/policies/safe.yaml",
	}
	for _, snippet := range requiredShellSnippets {
		if !strings.Contains(genericCI, snippet) {
			t.Fatalf("generic CI missing %q", snippet)
		}
	}
}

func TestHelmChartRendersDefaultsExampleAndWarnings(t *testing.T) {
	root := repoRoot(t)
	chartDir := filepath.Join(root, "deploy", "helm", "nomos")

	defaultValues := mustYAMLMap(t, filepath.Join(chartDir, "values.yaml"))
	defaultRendered := renderChart(t, chartDir, defaultValues)
	if !strings.Contains(defaultRendered, "kind: Deployment") || !strings.Contains(defaultRendered, "kind: ConfigMap") {
		t.Fatalf("expected default render to include workload resources, got:\n%s", defaultRendered)
	}

	exampleValues := mustYAMLMap(t, filepath.Join(chartDir, "values.example.yaml"))
	exampleRendered := renderChart(t, chartDir, exampleValues)
	if !strings.Contains(exampleRendered, "kind: Deployment") {
		t.Fatalf("expected example render to include deployment, got:\n%s", exampleRendered)
	}

	warningValues := mustYAMLMap(t, filepath.Join(chartDir, "values.yaml"))
	identity := warningValues["identity"].(map[string]any)
	identity["useDemoCredentials"] = false
	identity["apiKey"] = ""
	identity["agentSecret"] = ""
	config := warningValues["config"].(map[string]any)
	config["useStarterBundle"] = false
	config["policyBundlePath"] = ""

	warningRendered := renderChart(t, chartDir, warningValues)
	if strings.Contains(warningRendered, "kind: Deployment") {
		t.Fatalf("expected warning render to fail closed by omitting deployment, got:\n%s", warningRendered)
	}
	if !strings.Contains(warningRendered, "warning-policy") || !strings.Contains(warningRendered, "warning-identity") {
		t.Fatalf("expected warning render to include warning configmaps, got:\n%s", warningRendered)
	}
}

func renderChart(t *testing.T, chartDir string, values map[string]any) string {
	t.Helper()
	templateDir := filepath.Join(chartDir, "templates")
	entries, err := os.ReadDir(templateDir)
	if err != nil {
		t.Fatalf("read templates dir: %v", err)
	}
	var out bytes.Buffer
	data := map[string]any{
		"Values": values,
		"Release": map[string]any{
			"Name":      "nomos",
			"Namespace": "default",
		},
		"Chart": map[string]any{
			"Name":    "nomos",
			"Version": "0.1.0",
		},
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		source := mustReadFile(t, filepath.Join(templateDir, entry.Name()))
		tmpl, err := template.New(entry.Name()).Option("missingkey=zero").Parse(source)
		if err != nil {
			t.Fatalf("parse template %s: %v", entry.Name(), err)
		}
		var rendered bytes.Buffer
		if err := tmpl.Execute(&rendered, data); err != nil {
			t.Fatalf("execute template %s: %v", entry.Name(), err)
		}
		text := strings.TrimSpace(rendered.String())
		if text == "" {
			continue
		}
		out.WriteString(text)
		out.WriteString("\n---\n")
	}
	return out.String()
}

func mustYAMLMap(t *testing.T, path string) map[string]any {
	t.Helper()
	var data map[string]any
	if err := yaml.Unmarshal([]byte(mustReadFile(t, path)), &data); err != nil {
		t.Fatalf("parse yaml %s: %v", path, err)
	}
	return data
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
