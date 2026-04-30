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
