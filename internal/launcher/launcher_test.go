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
	if !result.ApprovalsEnabled || result.ApprovalStorePath != filepath.Join(workspace, ".nomos", "approvals.json") {
		t.Fatalf("expected generated launcher config to enable local approvals: %+v", result)
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
	if !strings.Contains(out.String(), "Profile:       ci-strict") ||
		!strings.Contains(out.String(), "Approvals:     enabled") ||
		!strings.Contains(out.String(), "nomos approvals approve --store") ||
		!strings.Contains(out.String(), "nomos approvals deny --store") ||
		!strings.Contains(out.String(), "run_command    -> process.exec") {
		t.Fatalf("expected ci-strict summary, got:\n%s", out.String())
	}
	generatedConfig, err := os.ReadFile(result.ConfigPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	if !strings.Contains(string(generatedConfig), `"enabled": true`) || !strings.Contains(string(generatedConfig), `approvals.json`) {
		t.Fatalf("expected generated config to enable file approvals, got:\n%s", string(generatedConfig))
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
	for _, want := range []string{"read_file", "run_command", "Do not use native shell", "raw upstream MCP servers", "bypass risk", "Native client approvals are not Nomos approvals", "do not retry the same action through a native tool"} {
		if !strings.Contains(text, want) {
			t.Fatalf("instruction text missing %q:\n%s", want, text)
		}
	}
}

func TestResolveAgentLaunchPlanClaudePassesMCPConfigFlag(t *testing.T) {
	plan, err := resolveAgentLaunchPlan(AgentClaude, "/tmp/x/claude.mcp.json", mcpClientServer{}, []string{"--resume"})
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

func TestResolveAgentLaunchPlanCodexPassesMCPConfigOverrides(t *testing.T) {
	server := mcpClientServer{
		Command: "nomos",
		Args:    []string{"mcp", "-c", `C:\tmp\nomos.json`, "-p", `C:\tmp\policy.yaml`, "--tool-surface", "friendly", "--quiet"},
	}
	plan, err := resolveAgentLaunchPlan(AgentCodex, "/tmp/x/codex.mcp.json", server, []string{"some-arg"})
	if err != nil {
		t.Fatalf("resolve plan: %v", err)
	}
	if plan.WiringMethod != mcpWiringCodexConfigOverride {
		t.Fatalf("expected wiring method %q, got %q", mcpWiringCodexConfigOverride, plan.WiringMethod)
	}
	got := strings.Join(plan.Argv, "\x00")
	for _, want := range []string{
		"-c\x00mcp_servers.nomos.command=\"nomos\"",
		"-c\x00mcp_servers.nomos.args=[\"mcp\",\"-c\",\"C:\\\\tmp\\\\nomos.json\",\"-p\",\"C:\\\\tmp\\\\policy.yaml\",\"--tool-surface\",\"friendly\",\"--quiet\"]",
		"some-arg",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected argv to contain %q, got %+v", want, plan.Argv)
		}
	}
	for _, e := range plan.Env {
		if strings.HasPrefix(e, "CODEX_MCP_CONFIG=") {
			t.Fatalf("launcher must not set unverified CODEX_MCP_CONFIG env var: %q", e)
		}
	}
}

func TestResolveAgentLaunchPlanRejectsEmptyMCPConfig(t *testing.T) {
	if _, err := resolveAgentLaunchPlan(AgentClaude, "", mcpClientServer{}, nil); err == nil {
		t.Fatal("expected error for empty mcp config path")
	}
}

func TestResolveAgentLaunchPlanRejectsUnknownAgent(t *testing.T) {
	if _, err := resolveAgentLaunchPlan("not-a-real-agent", "/tmp/x.json", mcpClientServer{}, nil); err == nil {
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
		"run_command    -> process.exec",
		"the session is NOT governed",
		"Native client approvals are outside Nomos policy",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func TestRunCodexPassesConfigOverridesAndPrintsVerification(t *testing.T) {
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
	if result.MCPWiringMethod != mcpWiringCodexConfigOverride {
		t.Fatalf("expected MCPWiringMethod %q, got %q", mcpWiringCodexConfigOverride, result.MCPWiringMethod)
	}
	gotArgv := strings.Join(result.AgentLaunchArgv, "\x00")
	for _, want := range []string{"mcp_servers.nomos.command", "mcp_servers.nomos.args"} {
		if !strings.Contains(gotArgv, want) {
			t.Fatalf("expected codex argv override %q, got %+v", want, result.AgentLaunchArgv)
		}
	}
	got := out.String()
	for _, want := range []string{
		"MCP wiring:    launcher passes Codex MCP config overrides",
		"Verify after launch:",
		"In codex, run `/mcp`",
		"read_file, write_file, apply_patch, run_command, http_request",
		"run_command    -> process.exec",
		"Do NOT approve native client shell",
		"Native client approvals are outside Nomos policy",
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

// TestEmbeddedProfilesGeneratedFromCanonicalProfiles keeps the generated
// embedded launcher profiles byte-identical to the canonical bundles in
// /profiles. If this fails, run `make pin-profile-hashes`.
func TestEmbeddedProfilesGeneratedFromCanonicalProfiles(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	for _, name := range []string{"safe-dev", "ci-strict", "prod-locked"} {
		repoBytes, err := os.ReadFile(filepath.Join(repoRoot, "profiles", name+".yaml"))
		if err != nil {
			t.Fatalf("read repo profile %s: %v", name, err)
		}
		embedBytes, err := embeddedProfiles.ReadFile("embedded_profiles/" + name + ".yaml")
		if err != nil {
			t.Fatalf("read embedded profile %s: %v", name, err)
		}
		if !bytes.Equal(repoBytes, embedBytes) {
			t.Fatalf("embedded profile %s.yaml has drifted from profiles/%s.yaml; run `make pin-profile-hashes`", name, name)
		}
	}
}

func TestMaterializeEmbeddedProfileWritesToHomeAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	getenv := func(key string) string {
		if key == "NOMOS_HOME_OVERRIDE" {
			return home
		}
		return ""
	}
	path1, err := materializeEmbeddedProfile("safe-dev", getenv)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if want := filepath.Join(home, ".nomos", "profiles", "safe-dev.yaml"); path1 != want {
		t.Fatalf("expected materialized path %s, got %s", want, path1)
	}
	if _, err := os.Stat(path1); err != nil {
		t.Fatalf("materialized file missing: %v", err)
	}
	embedBytes, err := embeddedProfiles.ReadFile("embedded_profiles/safe-dev.yaml")
	if err != nil {
		t.Fatalf("read embed: %v", err)
	}
	gotBytes, err := os.ReadFile(path1)
	if err != nil {
		t.Fatalf("read materialized: %v", err)
	}
	if !bytes.Equal(embedBytes, gotBytes) {
		t.Fatalf("materialized YAML differs from embedded source")
	}
	stat1, err := os.Stat(path1)
	if err != nil {
		t.Fatalf("stat materialized: %v", err)
	}
	// Second call must be a no-op when content already matches; the file's
	// inode timestamp must not change. This protects against race-y rewrites
	// when multiple `nomos run` invocations execute concurrently.
	path2, err := materializeEmbeddedProfile("safe-dev", getenv)
	if err != nil {
		t.Fatalf("materialize idempotent: %v", err)
	}
	if path2 != path1 {
		t.Fatalf("expected stable materialized path, got %s then %s", path1, path2)
	}
	stat2, err := os.Stat(path1)
	if err != nil {
		t.Fatalf("stat second pass: %v", err)
	}
	if !stat1.ModTime().Equal(stat2.ModTime()) {
		t.Fatalf("idempotent materialize must not rewrite when content matches")
	}
}

func TestMaterializeEmbeddedProfileRejectsUnknownName(t *testing.T) {
	getenv := func(key string) string {
		if key == "NOMOS_HOME_OVERRIDE" {
			return t.TempDir()
		}
		return ""
	}
	if _, err := materializeEmbeddedProfile("not-a-real-profile", getenv); err == nil {
		t.Fatal("expected error for unknown embedded profile name")
	}
}

// TestRunFallsBackToEmbeddedProfileWhenNotOnDisk simulates the enterprise
// install path: a workspace without profiles/ and a
// process working directory whose git root also has no profiles. Before the
// embed fix, this scenario produced the operator's reported error
// (`policy bundle path invalid: GetFileAttributesEx ...`). After the fix,
// the launcher must materialize the profile from the binary, load it
// successfully, and report PolicyBundleSource == "embedded".
func TestRunFallsBackToEmbeddedProfileWhenNotOnDisk(t *testing.T) {
	home := t.TempDir()
	workspace := t.TempDir()
	// Force tier 2 to fail so the embed fallback is exercised; restore the
	// real provider after the test so we don't leak state to other tests.
	saved := repoRootForProfileLookup
	repoRootForProfileLookup = func() string { return "" }
	t.Cleanup(func() { repoRootForProfileLookup = saved })
	getenv := func(key string) string {
		if key == "NOMOS_HOME_OVERRIDE" {
			return home
		}
		return ""
	}
	var out bytes.Buffer
	result, err := Run(Options{
		Agent:         AgentClaude,
		WorkspaceRoot: workspace,
		Profile:       "safe-dev",
		NoLaunch:      true,
		NomosCommand:  "nomos",
		Stdout:        &out,
		Getenv:        getenv,
		Now:           fixedTime,
	})
	if err != nil {
		t.Fatalf("run launcher with embed fallback: %v", err)
	}
	if result.PolicyBundleSource != profileSourceEmbedded {
		t.Fatalf("expected PolicyBundleSource=%q, got %q (path=%s)", profileSourceEmbedded, result.PolicyBundleSource, result.PolicyBundlePath)
	}
	wantPath := filepath.Join(home, ".nomos", "profiles", "safe-dev.yaml")
	if result.PolicyBundlePath != wantPath {
		t.Fatalf("expected materialized path %s, got %s", wantPath, result.PolicyBundlePath)
	}
	// The materialized bundle must produce the canonical hash pinned in
	// testdata/policy-profiles/hashes.json. If this assertion ever fails,
	// the generated embedded YAML drifted from the canonical profile.
	const safeDevPinnedHash = "4d39231248c1f4887034b63745c7b8ec5ad3a3e78ccab4dffb3d31c7f9eaf93d"
	if result.PolicyBundleHash != safeDevPinnedHash {
		t.Fatalf("embedded safe-dev hash drift: got %s want %s", result.PolicyBundleHash, safeDevPinnedHash)
	}
	if !strings.Contains(out.String(), "Bundle source: embedded") {
		t.Fatalf("expected printed summary to disclose embedded source:\n%s", out.String())
	}
}

func TestRunPrefersWorkspaceProfileWhenPresent(t *testing.T) {
	home := t.TempDir()
	workspace := t.TempDir()
	// Drop a workspace-local profile that shadows the embedded one. The
	// launcher must prefer the on-disk file (tier 1) so nomos developers
	// can iterate on profile YAML without rebuilding the binary.
	profilesDir := filepath.Join(workspace, "profiles")
	if err := os.MkdirAll(profilesDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	embedBytes, err := embeddedProfiles.ReadFile("embedded_profiles/safe-dev.yaml")
	if err != nil {
		t.Fatalf("read embed: %v", err)
	}
	target := filepath.Join(profilesDir, "safe-dev.yaml")
	if err := os.WriteFile(target, embedBytes, 0o644); err != nil {
		t.Fatalf("write workspace profile: %v", err)
	}
	saved := repoRootForProfileLookup
	repoRootForProfileLookup = func() string { return "" }
	t.Cleanup(func() { repoRootForProfileLookup = saved })
	getenv := func(key string) string {
		if key == "NOMOS_HOME_OVERRIDE" {
			return home
		}
		return ""
	}
	result, err := Run(Options{
		Agent:         AgentClaude,
		WorkspaceRoot: workspace,
		Profile:       "safe-dev",
		NoLaunch:      true,
		NomosCommand:  "nomos",
		Stdout:        &bytes.Buffer{},
		Getenv:        getenv,
		Now:           fixedTime,
	})
	if err != nil {
		t.Fatalf("run launcher: %v", err)
	}
	if result.PolicyBundleSource != profileSourceWorkspace {
		t.Fatalf("expected PolicyBundleSource=%q, got %q", profileSourceWorkspace, result.PolicyBundleSource)
	}
	wantAbs, _ := filepath.Abs(target)
	if result.PolicyBundlePath != wantAbs {
		t.Fatalf("expected workspace-local path %s, got %s", wantAbs, result.PolicyBundlePath)
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
