package launcher

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestRunDryRunCodexUsesDefaultSafeDevProfile(t *testing.T) {
	workspace := t.TempDir()
	var out bytes.Buffer
	result, err := Run(Options{
		Agent:         AgentCodex,
		WorkspaceRoot: workspace,
		DryRun:        true,
		PrintConfig:   true,
		NomosCommand:  "nomos",
		Stdout:        &out,
		Getenv:        emptyEnv,
		Now:           fixedTime,
	})
	if err != nil {
		t.Fatalf("run launcher: %v", err)
	}
	if result.Profile != "safe-dev" || result.AssuranceLevel != "BEST_EFFORT" {
		t.Fatalf("unexpected result: %+v", result)
	}
	got := out.String()
	for _, want := range []string{
		"No policy provided — using default profile: safe-dev",
		"safe-dev summary:",
		"Nomos workspace active",
		"read_file      -> fs.read",
		"run_command    -> process.exec",
		"Local machine mode is BEST_EFFORT",
		"Dual-tool ambiguity",
		`"--tool-surface"`,
		`"friendly"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
	if _, err := os.Stat(filepath.Join(workspace, ".nomos")); !os.IsNotExist(err) {
		t.Fatalf("dry-run should not write .nomos directory, stat err=%v", err)
	}
}

func TestRunClaudeNoLaunchWritesGeneratedConfigAndAudit(t *testing.T) {
	workspace := t.TempDir()
	var out bytes.Buffer
	result, err := Run(Options{
		Agent:         AgentClaude,
		WorkspaceRoot: workspace,
		Profile:       "ci-strict",
		NoLaunch:      true,
		NomosCommand:  "nomos",
		Stdout:        &out,
		Getenv:        emptyEnv,
		Now:           fixedTime,
	})
	if err != nil {
		t.Fatalf("run launcher: %v", err)
	}
	if result.GeneratedConfig != true {
		t.Fatalf("expected generated Nomos config: %+v", result)
	}
	for _, path := range []string{result.ConfigPath, result.MCPConfigPath, filepath.Join(workspace, ".nomos", "agent", "audit.db")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected generated file %s: %v", path, err)
		}
	}
	if runtime.GOOS != "windows" {
		for _, path := range []string{result.ConfigPath, result.MCPConfigPath} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat %s: %v", path, err)
			}
			if info.Mode().Perm()&0o077 != 0 {
				t.Fatalf("expected owner-only permissions for %s, got %v", path, info.Mode().Perm())
			}
		}
	}
	assertLauncherAuditEvent(t, filepath.Join(workspace, ".nomos", "agent", "audit.db"))
	var cfg mcpClientConfig
	if err := json.Unmarshal(result.MCPConfigJSON, &cfg); err != nil {
		t.Fatalf("decode generated mcp config: %v", err)
	}
	nomos := cfg.MCPServers["nomos"]
	if nomos.Command != "nomos" {
		t.Fatalf("unexpected command: %+v", nomos)
	}
	args := strings.Join(nomos.Args, "\x00")
	for _, want := range []string{"mcp", "-c", result.ConfigPath, "-p", result.PolicyBundlePath, "--tool-surface", "friendly", "--quiet"} {
		if !strings.Contains(args, want) {
			t.Fatalf("generated args missing %q: %+v", want, nomos.Args)
		}
	}
	if !strings.Contains(out.String(), "Profile:       ci-strict") {
		t.Fatalf("expected ci-strict summary, got:\n%s", out.String())
	}
}

func TestPolicyBundleAndProfileAreMutuallyExclusive(t *testing.T) {
	_, err := Run(Options{
		Agent:            AgentCodex,
		WorkspaceRoot:    t.TempDir(),
		PolicyBundlePath: "bundle.yaml",
		Profile:          "safe-dev",
		DryRun:           true,
		Getenv:           emptyEnv,
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive error, got %v", err)
	}
}

func TestLauncherFailsClosedOnInvalidPolicyBundle(t *testing.T) {
	workspace := t.TempDir()
	bundlePath := filepath.Join(workspace, "bad.yaml")
	if err := os.WriteFile(bundlePath, []byte("version: v1\nrules:\n  - id: bad\n    action_type: fs.read\n    resource: file://workspace/**\n    decision: MAYBE\n"), 0o600); err != nil {
		t.Fatalf("write invalid policy: %v", err)
	}
	_, err := Run(Options{
		Agent:            AgentCodex,
		WorkspaceRoot:    workspace,
		PolicyBundlePath: bundlePath,
		DryRun:           true,
		Getenv:           emptyEnv,
	})
	if err == nil || !strings.Contains(err.Error(), "load policy profile") {
		t.Fatalf("expected invalid policy failure, got %v", err)
	}
}

func TestRunWarnsWhenExistingMCPConfigContainsRawServers(t *testing.T) {
	workspace := t.TempDir()
	existing := filepath.Join(workspace, "client.mcp.json")
	data := []byte(`{"mcpServers":{"nomos":{"command":"nomos"},"filesystem":{"command":"fs"},"github":{"command":"gh"}}}`)
	if err := os.WriteFile(existing, data, 0o600); err != nil {
		t.Fatalf("write existing mcp config: %v", err)
	}
	var out bytes.Buffer
	if _, err := Run(Options{
		Agent:                 AgentCodex,
		WorkspaceRoot:         workspace,
		DryRun:                true,
		ExistingMCPConfigPath: existing,
		Stdout:                &out,
		Getenv:                emptyEnv,
		Now:                   fixedTime,
	}); err != nil {
		t.Fatalf("run launcher: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "Possible bypass paths detected") || !strings.Contains(got, "filesystem, github") {
		t.Fatalf("expected raw MCP warning, got:\n%s", got)
	}
}

func TestInstructionFilesMentionBypassAvoidance(t *testing.T) {
	workspace := t.TempDir()
	paths, err := writeInstructionFiles(workspace)
	if err != nil {
		t.Fatalf("write instructions: %v", err)
	}
	if len(paths) != 3 {
		t.Fatalf("expected three instruction files, got %+v", paths)
	}
	data, err := os.ReadFile(filepath.Join(workspace, "AGENTS.md"))
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	text := string(data)
	for _, want := range []string{"read_file", "run_command", "Do not use native shell", "raw upstream MCP servers", "bypass risk"} {
		if !strings.Contains(text, want) {
			t.Fatalf("instruction text missing %q:\n%s", want, text)
		}
	}
}

func TestResolveAgentLaunchPlanClaudePassesMCPConfigFlag(t *testing.T) {
	plan, err := resolveAgentLaunchPlan(AgentClaude, "/tmp/x/claude.mcp.json", []string{"--resume"})
	if err != nil {
		t.Fatalf("resolve plan: %v", err)
	}
	if plan.WiringMethod != mcpWiringMCPConfigFlag {
		t.Fatalf("expected wiring method %q, got %q", mcpWiringMCPConfigFlag, plan.WiringMethod)
	}
	if len(plan.Argv) < 3 || plan.Argv[0] != "--mcp-config" || plan.Argv[1] != "/tmp/x/claude.mcp.json" || plan.Argv[2] != "--resume" {
		t.Fatalf("expected argv to start with --mcp-config <path> then user args, got %+v", plan.Argv)
	}
	wantEnv := map[string]bool{
		"NOMOS_MCP_CONFIG=/tmp/x/claude.mcp.json":       false,
		"NOMOS_AGENT_MCP_CONFIG=/tmp/x/claude.mcp.json": false,
		"CLAUDE_MCP_CONFIG=/tmp/x/claude.mcp.json":      false,
	}
	for _, e := range plan.Env {
		if _, ok := wantEnv[e]; ok {
			wantEnv[e] = true
		}
	}
	for k, present := range wantEnv {
		if !present {
			t.Fatalf("expected env entry %q in plan.Env=%+v", k, plan.Env)
		}
	}
}

func TestResolveAgentLaunchPlanCodexIsOperatorManaged(t *testing.T) {
	plan, err := resolveAgentLaunchPlan(AgentCodex, "/tmp/x/codex.mcp.json", []string{"some-arg"})
	if err != nil {
		t.Fatalf("resolve plan: %v", err)
	}
	if plan.WiringMethod != mcpWiringOperatorManaged {
		t.Fatalf("expected wiring method %q, got %q", mcpWiringOperatorManaged, plan.WiringMethod)
	}
	if len(plan.Argv) != 1 || plan.Argv[0] != "some-arg" {
		t.Fatalf("expected argv to be user args only, got %+v", plan.Argv)
	}
	for _, e := range plan.Env {
		if strings.HasPrefix(e, "CODEX_MCP_CONFIG=") {
			t.Fatalf("launcher must not set unverified CODEX_MCP_CONFIG env var: %q", e)
		}
	}
}

func TestResolveAgentLaunchPlanRejectsEmptyMCPConfig(t *testing.T) {
	if _, err := resolveAgentLaunchPlan(AgentClaude, "", nil); err == nil {
		t.Fatal("expected error for empty mcp config path")
	}
}

func TestResolveAgentLaunchPlanRejectsUnknownAgent(t *testing.T) {
	if _, err := resolveAgentLaunchPlan("not-a-real-agent", "/tmp/x.json", nil); err == nil {
		t.Fatal("expected error for unknown agent")
	}
}

func TestRunClaudePopulatesWiringMethodAndArgv(t *testing.T) {
	workspace := t.TempDir()
	var out bytes.Buffer
	result, err := Run(Options{
		Agent:         AgentClaude,
		WorkspaceRoot: workspace,
		NoLaunch:      true,
		NomosCommand:  "nomos",
		Stdout:        &out,
		Getenv:        emptyEnv,
		Now:           fixedTime,
	})
	if err != nil {
		t.Fatalf("run launcher: %v", err)
	}
	if result.MCPWiringMethod != mcpWiringMCPConfigFlag {
		t.Fatalf("expected MCPWiringMethod %q, got %q", mcpWiringMCPConfigFlag, result.MCPWiringMethod)
	}
	if len(result.AgentLaunchArgv) < 2 || result.AgentLaunchArgv[0] != "--mcp-config" || result.AgentLaunchArgv[1] != result.MCPConfigPath {
		t.Fatalf("expected AgentLaunchArgv to start with --mcp-config <generated mcp config>, got %+v", result.AgentLaunchArgv)
	}
	got := out.String()
	for _, want := range []string{
		"MCP wiring:    launcher passes --mcp-config to the agent",
		"Verify after launch:",
		"In Claude Code, run `/mcp`",
		"read_file, write_file, apply_patch, run_command, http_request",
		"the session is NOT governed",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunCodexRecordsOperatorManagedAndPrintsManualSetup(t *testing.T) {
	workspace := t.TempDir()
	var out bytes.Buffer
	result, err := Run(Options{
		Agent:         AgentCodex,
		WorkspaceRoot: workspace,
		NoLaunch:      true,
		NomosCommand:  "nomos",
		Stdout:        &out,
		Getenv:        emptyEnv,
		Now:           fixedTime,
	})
	if err != nil {
		t.Fatalf("run launcher: %v", err)
	}
	if result.MCPWiringMethod != mcpWiringOperatorManaged {
		t.Fatalf("expected MCPWiringMethod %q, got %q", mcpWiringOperatorManaged, result.MCPWiringMethod)
	}
	got := out.String()
	for _, want := range []string{
		"MCP wiring:    operator-managed",
		"Verify after launch:",
		"launcher does NOT auto-wire MCP for codex",
		"~/.codex/config.toml",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunDryRunOmitsVerifyAfterLaunchBlock(t *testing.T) {
	workspace := t.TempDir()
	var out bytes.Buffer
	if _, err := Run(Options{
		Agent:         AgentClaude,
		WorkspaceRoot: workspace,
		DryRun:        true,
		NomosCommand:  "nomos",
		Stdout:        &out,
		Getenv:        emptyEnv,
		Now:           fixedTime,
	}); err != nil {
		t.Fatalf("run launcher: %v", err)
	}
	got := out.String()
	if strings.Contains(got, "Verify after launch:") {
		t.Fatalf("dry-run output should not include the verify block:\n%s", got)
	}
	if !strings.Contains(got, "MCP wiring:    <dry-run>") {
		t.Fatalf("dry-run summary should mark MCP wiring as <dry-run>:\n%s", got)
	}
}

func TestLauncherAuditMetadataReflectsWiringTruthfully(t *testing.T) {
	workspace := t.TempDir()
	if _, err := Run(Options{
		Agent:         AgentClaude,
		WorkspaceRoot: workspace,
		NoLaunch:      true,
		NomosCommand:  "nomos",
		Stdout:        &bytes.Buffer{},
		Getenv:        emptyEnv,
		Now:           fixedTime,
	}); err != nil {
		t.Fatalf("run launcher: %v", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(workspace, ".nomos", "agent", "audit.db"))
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer func() { _ = db.Close() }()
	var payloadJSON string
	if err := db.QueryRow(`SELECT payload_json FROM audit_events WHERE event_type='agent.launcher.session' LIMIT 1`).Scan(&payloadJSON); err != nil {
		t.Fatalf("query audit payload: %v", err)
	}
	var payload struct {
		ExecutorMetadata map[string]any `json:"executor_metadata"`
	}
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		t.Fatalf("decode audit payload: %v", err)
	}
	meta := payload.ExecutorMetadata
	if meta == nil {
		t.Fatalf("audit payload missing executor_metadata: %s", payloadJSON)
	}
	// Truthful claims that MUST be present.
	if got := meta["mcp_wiring_method"]; got != mcpWiringMCPConfigFlag {
		t.Fatalf("expected mcp_wiring_method=%q, got %v", mcpWiringMCPConfigFlag, got)
	}
	argv, ok := meta["agent_launch_argv"].([]any)
	if !ok || len(argv) < 2 || argv[0] != "--mcp-config" {
		t.Fatalf("expected agent_launch_argv to start with --mcp-config, got %v", meta["agent_launch_argv"])
	}
	// False claim that MUST NOT be present after the integrity fix.
	if _, present := meta["default_boundary"]; present {
		t.Fatalf("audit metadata must not record the un-verifiable `default_boundary` claim; got %v", meta)
	}
}

func emptyEnv(string) string {
	return ""
}

func fixedTime() time.Time {
	return time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
}

func assertLauncherAuditEvent(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer func() { _ = db.Close() }()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type = 'agent.launcher.session'`).Scan(&count); err != nil {
		t.Fatalf("query launcher audit event: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one launcher audit event, got %d", count)
	}
}
