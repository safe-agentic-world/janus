package launcher

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/gateway"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/version"
)

// embeddedProfiles ships the canonical default profile bundles inside the
// binary so `nomos run` works for operators who installed nomos via Homebrew,
// Scoop, the installer script, or `go install` and run it from any project
// directory. The byte-for-byte equivalence with examples/policies/profiles/
// is enforced by a unit test in this package; if the source profiles change,
// the embedded copies must be updated in lockstep (and the hashes pinned in
// testdata/policy-profiles/hashes.json updated through the policy test).
//
//go:embed embedded_profiles/*.yaml
var embeddedProfiles embed.FS

// repoRootForProfileLookup is the function used by resolvePolicySelection to
// find a checkout of the nomos source repository when looking for on-disk
// profile YAMLs. Production code uses repoRootFromPackage (current working
// directory's git root), which preserves the developer experience inside a
// nomos checkout. Tests override this to simulate running from outside the
// nomos repo (the path enterprise users hit) so we exercise the embedded
// fallback. Not safe for parallel tests — the launcher tests do not use
// t.Parallel.
var repoRootForProfileLookup = repoRootFromPackage

const (
	AgentCodex  = "codex"
	AgentClaude = "claude"
)

type Options struct {
	Agent                 string
	ConfigPath            string
	PolicyBundlePath      string
	Profile               string
	DryRun                bool
	PrintConfig           bool
	NoLaunch              bool
	WriteInstructions     bool
	ExistingMCPConfigPath string
	WorkspaceRoot         string
	NomosCommand          string
	Stdout                io.Writer
	Stderr                io.Writer
	Getenv                func(string) string
	Args                  []string
	Now                   func() time.Time
}

type Result struct {
	Agent               string
	WorkspaceRoot       string
	ConfigPath          string
	GeneratedConfig     bool
	PolicyBundlePath    string
	PolicyBundleSource  string // "custom", "workspace", "repo", or "embedded"
	Profile             string
	ProfileSummary      string
	PolicyBundleHash    string
	AssuranceLevel      string
	MCPConfigPath       string
	MCPConfigJSON       []byte
	MCPWiringMethod     string
	AgentLaunchArgv     []string
	InstructionsWritten []string
	Warnings            []string
	Launched            bool
}

// MCP wiring methods recorded in audit and printed in the launcher summary.
// They describe how the launcher attached (or did not attach) Nomos as the
// MCP boundary for the launched agent. The values are stable strings; do not
// rename them without an audit-schema review.
const (
	// mcpWiringMCPConfigFlag indicates Nomos passed --mcp-config <path> to the
	// agent CLI and the agent is expected to load the generated MCP config on
	// startup. Used for Claude Code.
	mcpWiringMCPConfigFlag = "mcp_config_flag"
	// mcpWiringOperatorManaged indicates the launcher cannot auto-wire MCP for
	// this agent and the operator is responsible for registering the generated
	// MCP config in the agent's persistent configuration. Used for Codex.
	mcpWiringOperatorManaged = "operator_managed"
	// mcpWiringSkipped indicates dry-run or no-launch: no wiring was attempted
	// because no agent process was started.
	mcpWiringSkipped = "skipped"
)

type mcpClientConfig struct {
	MCPServers map[string]mcpClientServer `json:"mcpServers"`
}

type mcpClientServer struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

var governedToolMappings = []struct {
	Friendly  string
	Canonical string
}{
	{"read_file", "fs.read"},
	{"write_file", "fs.write"},
	{"apply_patch", "repo.apply_patch"},
	{"run_command", "process.exec"},
	{"http_request", "net.http_request"},
}

func Run(opts Options) (Result, error) {
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	if opts.Getenv == nil {
		opts.Getenv = os.Getenv
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	agent := normalizeAgent(opts.Agent)
	if agent == "" {
		return Result{}, errors.New("agent must be codex or claude")
	}
	if strings.TrimSpace(opts.PolicyBundlePath) != "" && strings.TrimSpace(opts.Profile) != "" {
		return Result{}, errors.New("--policy-bundle and --profile are mutually exclusive")
	}
	workspaceRoot, err := resolveWorkspaceRoot(opts.WorkspaceRoot)
	if err != nil {
		return Result{}, err
	}
	policySelection, err := resolvePolicySelection(workspaceRoot, opts.PolicyBundlePath, opts.Profile, opts)
	if err != nil {
		return Result{}, err
	}
	configPath, generatedConfig, configJSON, err := resolveNomosConfig(workspaceRoot, opts.ConfigPath, policySelection.BundlePath, opts)
	if err != nil {
		return Result{}, err
	}
	if generatedConfig && !opts.DryRun {
		if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
			return Result{}, fmt.Errorf("create generated Nomos config directory: %w", err)
		}
		if err := os.WriteFile(configPath, configJSON, 0o600); err != nil {
			return Result{}, fmt.Errorf("write generated Nomos config: %w", err)
		}
	}
	var cfg gateway.Config
	if generatedConfig && opts.DryRun {
		cfg = dryRunGeneratedConfig()
	} else {
		cfg, err = gateway.LoadConfig(configPath, opts.Getenv, policySelection.BundlePath)
		if err != nil {
			return Result{}, err
		}
	}
	bundle, err := policy.LoadBundle(policySelection.BundlePath)
	if err != nil {
		return Result{}, fmt.Errorf("load policy profile: %w", err)
	}
	mcpConfigJSON, err := buildMCPConfigJSON(nomosCommand(opts.NomosCommand), configPath, policySelection.BundlePath)
	if err != nil {
		return Result{}, err
	}
	mcpConfigPath := ""
	if !opts.DryRun {
		dir, err := ensureAgentTempDir(workspaceRoot)
		if err != nil {
			return Result{}, err
		}
		path := filepath.Join(dir, agent+".mcp.json")
		if err := os.WriteFile(path, mcpConfigJSON, 0o600); err != nil {
			return Result{}, fmt.Errorf("write mcp client config: %w", err)
		}
		mcpConfigPath = path
	}
	warnings := launcherWarnings(opts, cfg)
	if extra := rawMCPWarnings(opts.ExistingMCPConfigPath); len(extra) > 0 {
		warnings = append(warnings, extra...)
	}
	wiringMethod := mcpWiringSkipped
	var plannedArgv []string
	if mcpConfigPath != "" {
		plan, err := resolveAgentLaunchPlan(agent, mcpConfigPath, opts.Args)
		if err != nil {
			return Result{}, err
		}
		wiringMethod = plan.WiringMethod
		plannedArgv = plan.Argv
	}
	result := Result{
		Agent:              agent,
		WorkspaceRoot:      workspaceRoot,
		ConfigPath:         configPath,
		GeneratedConfig:    generatedConfig,
		PolicyBundlePath:   policySelection.BundlePath,
		PolicyBundleSource: policySelection.Source,
		Profile:            policySelection.Profile,
		ProfileSummary:     policySelection.Summary,
		PolicyBundleHash:   bundle.Hash,
		AssuranceLevel:     "BEST_EFFORT",
		MCPConfigPath:      mcpConfigPath,
		MCPConfigJSON:      mcpConfigJSON,
		MCPWiringMethod:    wiringMethod,
		AgentLaunchArgv:    plannedArgv,
		Warnings:           warnings,
	}
	if opts.WriteInstructions {
		written, err := writeInstructionFiles(workspaceRoot)
		if err != nil {
			return Result{}, err
		}
		result.InstructionsWritten = written
	}
	recordLauncherSession(cfg, result, opts.Now)
	writeSummary(opts.Stdout, result, opts, policySelection.Defaulted)
	if opts.PrintConfig {
		_, _ = fmt.Fprintln(opts.Stdout)
		_, _ = fmt.Fprintln(opts.Stdout, "Generated MCP config:")
		_, _ = opts.Stdout.Write(mcpConfigJSON)
		_, _ = fmt.Fprintln(opts.Stdout)
	}
	if opts.DryRun || opts.NoLaunch {
		return result, nil
	}
	if err := launchAgent(agent, mcpConfigPath, opts.Args); err != nil {
		return result, err
	}
	result.Launched = true
	return result, nil
}

type policySelection struct {
	BundlePath string
	Profile    string
	Summary    string
	Source     string // "custom", "workspace", "repo", or "embedded"
	Defaulted  bool
}

// Profile bundle source labels recorded in audit and printed in the launcher
// summary. The labels are stable strings; do not rename them without an
// audit-schema review.
const (
	profileSourceCustom    = "custom"
	profileSourceWorkspace = "workspace"
	profileSourceRepo      = "repo"
	profileSourceEmbedded  = "embedded"
)

func resolvePolicySelection(workspaceRoot, policyBundlePath, profile string, opts Options) (policySelection, error) {
	policyBundlePath = strings.TrimSpace(policyBundlePath)
	profile = strings.TrimSpace(profile)
	if policyBundlePath != "" {
		abs, err := filepath.Abs(policyBundlePath)
		if err != nil {
			return policySelection{}, err
		}
		return policySelection{BundlePath: abs, Profile: "custom", Summary: "custom policy bundle", Source: profileSourceCustom}, nil
	}
	defaulted := false
	if profile == "" {
		profile = "safe-dev"
		defaulted = true
	}
	summary, ok := profileSummaries()[profile]
	if !ok {
		return policySelection{}, fmt.Errorf("unknown profile %q: expected safe-dev, ci-strict, or prod-locked", profile)
	}
	bundlePath, source, err := locateOrMaterializeProfile(profile, workspaceRoot, opts)
	if err != nil {
		return policySelection{}, err
	}
	return policySelection{BundlePath: bundlePath, Profile: profile, Summary: summary, Source: source, Defaulted: defaulted}, nil
}

// locateOrMaterializeProfile resolves a profile name to an absolute filesystem
// path that exists when the function returns.
//
// Lookup tiers, in order:
//
//  1. Workspace checkout: <workspaceRoot>/examples/policies/profiles/<name>.yaml.
//     This lets a nomos developer iterate on a profile YAML inside their own
//     checkout without rebuilding the binary.
//
//  2. Calling-process git root: <repoRootForProfileLookup()>/examples/policies/
//     profiles/<name>.yaml. Covers `go run ./cmd/nomos run claude` from a
//     subdirectory of a nomos checkout where the workspace root is not the
//     repo root.
//
//  3. Embedded: materialize the profile baked into the binary to
//     ~/.nomos/profiles/<name>.yaml. This is the path enterprise users hit:
//     they install nomos via Homebrew/installer/`go install` and run from
//     their own project directory which has no examples/policies/profiles/
//     anywhere on disk. Without this tier, `nomos run` is broken outside a
//     nomos source checkout.
//
// Tier 3 is the integrity-critical path. The embedded YAML is byte-for-byte
// identical to the repo-shipped source — guarded by
// TestEmbeddedProfilesMatchRepoSourceByteForByte — and the resulting bundle
// hash matches the value pinned in testdata/policy-profiles/hashes.json.
func locateOrMaterializeProfile(profile, workspaceRoot string, opts Options) (string, string, error) {
	candidate := filepath.Join(workspaceRoot, "examples", "policies", "profiles", profile+".yaml")
	if _, err := os.Stat(candidate); err == nil {
		abs, err := filepath.Abs(candidate)
		if err != nil {
			return "", "", err
		}
		return abs, profileSourceWorkspace, nil
	}
	if root := strings.TrimSpace(repoRootForProfileLookup()); root != "" {
		candidate := filepath.Join(root, "examples", "policies", "profiles", profile+".yaml")
		if _, err := os.Stat(candidate); err == nil {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				return "", "", err
			}
			return abs, profileSourceRepo, nil
		}
	}
	path, err := materializeEmbeddedProfile(profile, opts.Getenv)
	if err != nil {
		return "", "", fmt.Errorf("materialize embedded profile %q: %w", profile, err)
	}
	return path, profileSourceEmbedded, nil
}

// materializeEmbeddedProfile writes the embedded profile bundle to a stable
// per-user path so the on-disk file outlives the launcher process and can be
// referenced by a persistent agent MCP config (e.g. ~/.codex/config.toml).
//
// Path: <home>/.nomos/profiles/<name>.yaml.
//
// The function is idempotent and safe under concurrent launchers: if the
// destination already matches the embedded bytes, it is left untouched;
// otherwise it is rewritten atomically via a tempfile-and-rename, which is a
// single inode replacement on POSIX and a best-effort replacement on Windows.
// File permissions are tightened to 0o600 where the platform supports it so
// the cached profile is not world-readable.
//
// This function is the integrity-critical materialization path for the embed
// fallback; the byte-equivalence test in this package guarantees the embed
// content equals the canonical YAML in examples/policies/profiles/.
func materializeEmbeddedProfile(name string, getenv func(string) string) (string, error) {
	data, err := embeddedProfiles.ReadFile("embedded_profiles/" + name + ".yaml")
	if err != nil {
		return "", fmt.Errorf("read embedded profile: %w", err)
	}
	home, err := launcherHomeDir(getenv)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".nomos", "profiles")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create profile cache dir: %w", err)
	}
	target := filepath.Join(dir, name+".yaml")
	if existing, err := os.ReadFile(target); err == nil && bytes.Equal(existing, data) {
		return target, nil
	}
	tmp, err := os.CreateTemp(dir, name+".*.yaml")
	if err != nil {
		return "", fmt.Errorf("stage profile cache file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return "", fmt.Errorf("write profile cache file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", fmt.Errorf("close profile cache file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil && runtime.GOOS != "windows" {
		cleanup()
		return "", fmt.Errorf("chmod profile cache file: %w", err)
	}
	if err := os.Rename(tmpPath, target); err != nil {
		cleanup()
		return "", fmt.Errorf("install profile cache file: %w", err)
	}
	return target, nil
}

// launcherHomeDir resolves the per-user home directory used to cache embedded
// profiles. It prefers the explicit HOME / USERPROFILE env vars (so tests can
// inject a tempdir via Options.Getenv) and falls back to os.UserHomeDir. A
// missing home is a fatal launcher error: the launcher cannot honestly claim
// it materialized the profile if it has no place to put the file.
func launcherHomeDir(getenv func(string) string) (string, error) {
	if getenv != nil {
		for _, key := range []string{"NOMOS_HOME_OVERRIDE", "USERPROFILE", "HOME"} {
			if value := strings.TrimSpace(getenv(key)); value != "" {
				return value, nil
			}
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate user home directory: %w", err)
	}
	return home, nil
}

func profileSummaries() map[string]string {
	return map[string]string{
		"safe-dev":    "developer profile: workspace reads/writes allowed, secrets denied, risky publish/infra actions require approval, unknown egress denied",
		"ci-strict":   "CI profile: validation and structured artifact publishing allowed, package installs and mutations denied, unknown egress denied",
		"prod-locked": "production profile: read-only inspection allowed, writes/patches/mutations denied except narrow break-glass approval",
	}
}

func resolveNomosConfig(workspaceRoot, configPath, policyBundlePath string, opts Options) (string, bool, []byte, error) {
	if strings.TrimSpace(configPath) != "" {
		abs, err := filepath.Abs(configPath)
		return abs, false, nil, err
	}
	if envPath := strings.TrimSpace(opts.Getenv("NOMOS_CONFIG")); envPath != "" {
		abs, err := filepath.Abs(envPath)
		return abs, false, nil, err
	}
	for _, candidate := range configCandidates(workspaceRoot) {
		if _, err := os.Stat(candidate); err == nil {
			abs, err := filepath.Abs(candidate)
			return abs, false, nil, err
		}
	}
	configPath = filepath.Join(workspaceRoot, ".nomos", "agent", "nomos.generated.json")
	data, err := json.MarshalIndent(minimalConfig(workspaceRoot, policyBundlePath), "", "  ")
	if err != nil {
		return "", false, nil, err
	}
	data = append(data, '\n')
	return configPath, true, data, nil
}

func configCandidates(workspaceRoot string) []string {
	return []string{
		filepath.Join(workspaceRoot, "nomos", "config.json"),
		filepath.Join(workspaceRoot, ".nomos", "config.json"),
	}
}

func minimalConfig(workspaceRoot, policyBundlePath string) map[string]any {
	return map[string]any{
		"gateway": map[string]any{
			"listen":                           ":8080",
			"transport":                        "http",
			"concurrency_limit":                32,
			"rate_limit_per_minute":            120,
			"circuit_breaker_failures":         5,
			"circuit_breaker_cooldown_seconds": 60,
			"tls":                              map[string]any{"enabled": false, "cert_file": "", "key_file": "", "client_ca_file": "", "require_mtls": false},
		},
		"runtime": map[string]any{"deployment_mode": "unmanaged", "strong_guarantee": false, "stateless_mode": false},
		"policy": map[string]any{
			"policy_bundle_path":      policyBundlePath,
			"verify_signatures":       false,
			"signature_path":          "",
			"public_key_path":         "",
			"exec_compatibility_mode": "strict",
			"explain_suggestions":     true,
			"opa":                     map[string]any{"enabled": false, "binary_path": "", "policy_path": "", "query": "", "timeout_ms": 2000},
		},
		"executor":    map[string]any{"sandbox_enabled": true, "sandbox_profile": "local", "workspace_root": workspaceRoot, "max_output_bytes": 65536, "max_output_lines": 200},
		"credentials": map[string]any{"enabled": false, "secrets": []any{}},
		"audit":       map[string]any{"sink": "sqlite:" + filepath.Join(workspaceRoot, ".nomos", "agent", "audit.db")},
		"telemetry":   map[string]any{"enabled": false, "sink": "stderr"},
		"rate_limits": map[string]any{"enabled": false},
		"mcp":         map[string]any{"enabled": true},
		"upstream":    map[string]any{"routes": []any{}},
		"approvals":   map[string]any{"enabled": false, "backend": "file", "store_path": filepath.Join(workspaceRoot, ".nomos", "approvals.json"), "ttl_seconds": 900, "webhook_token": "", "slack_token": "", "teams_token": ""},
		"identity": map[string]any{
			"principal":       "system",
			"agent":           "nomos",
			"environment":     "dev",
			"api_keys":        map[string]string{"local-agent": "system"},
			"agent_secrets":   map[string]string{"nomos": "local-agent-secret"},
			"service_secrets": map[string]string{},
			"oidc":            map[string]any{"enabled": false, "issuer": "", "audience": "", "public_key_path": ""},
			"spiffe":          map[string]any{"enabled": false, "trust_domain": ""},
		},
		"redaction": map[string]any{"patterns": []any{}},
	}
}

func dryRunGeneratedConfig() gateway.Config {
	return gateway.Config{
		Audit: gateway.AuditConfig{Sink: ""},
		Identity: gateway.IdentityConfig{
			Principal:   "system",
			Agent:       "nomos",
			Environment: "dev",
		},
	}
}

func buildMCPConfigJSON(command, configPath, policyBundlePath string) ([]byte, error) {
	cfg := mcpClientConfig{MCPServers: map[string]mcpClientServer{
		"nomos": {
			Command: command,
			Args: []string{
				"mcp",
				"-c", configPath,
				"-p", policyBundlePath,
				"--tool-surface", "friendly",
				"--quiet",
			},
		},
	}}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func launcherWarnings(opts Options, cfg gateway.Config) []string {
	warnings := []string{
		"Local machine mode is BEST_EFFORT: Nomos cannot prevent deliberate bypass while native file, shell, HTTP, or patch tools remain enabled.",
		"Dual-tool ambiguity: if native tools or raw MCP servers expose the same capabilities beside Nomos, actions may bypass governance.",
		"Do not register raw filesystem, shell, GitHub, Kubernetes, or other upstream MCP servers directly beside Nomos in workspace profile mode.",
		"Future enforcement mode will be able to exclude non-Nomos MCP servers from generated configs.",
	}
	if len(cfg.MCP.UpstreamServers) > 0 {
		warnings = append(warnings, "Nomos upstream MCP proxy is configured; clients should still register only the Nomos MCP server.")
	}
	return warnings
}

func rawMCPWarnings(path string) []string {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("Could not inspect existing MCP config %s for bypass paths: %v", path, err)}
	}
	raw, err := RawMCPServerNames(data)
	if err != nil {
		return []string{fmt.Sprintf("Could not parse existing MCP config %s for bypass paths: %v", path, err)}
	}
	if len(raw) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("Possible bypass paths detected: existing MCP config also registers raw server(s): %s", strings.Join(raw, ", "))}
}

func RawMCPServerNames(data []byte) ([]string, error) {
	var cfg struct {
		MCPServers map[string]any `json:"mcpServers"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(cfg.MCPServers))
	for name := range cfg.MCPServers {
		if strings.EqualFold(strings.TrimSpace(name), "nomos") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func writeSummary(out io.Writer, result Result, opts Options, defaulted bool) {
	if defaulted {
		_, _ = fmt.Fprintln(out, "No policy provided — using default profile: safe-dev")
		_, _ = fmt.Fprintf(out, "safe-dev summary: %s\n\n", result.ProfileSummary)
	}
	_, _ = fmt.Fprintln(out, "Nomos workspace active")
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "Agent:         %s\n", result.Agent)
	_, _ = fmt.Fprintf(out, "Workspace:     %s\n", result.WorkspaceRoot)
	_, _ = fmt.Fprintf(out, "Config:        %s\n", displayGeneratedPath(result.ConfigPath, result.GeneratedConfig, opts.DryRun))
	_, _ = fmt.Fprintf(out, "Profile:       %s\n", result.Profile)
	_, _ = fmt.Fprintf(out, "Policy bundle: %s\n", result.PolicyBundlePath)
	_, _ = fmt.Fprintf(out, "Bundle source: %s\n", displayPolicyBundleSource(result.PolicyBundleSource))
	_, _ = fmt.Fprintf(out, "Policy hash:   %s\n", result.PolicyBundleHash)
	_, _ = fmt.Fprintf(out, "Assurance:     %s\n", result.AssuranceLevel)
	if opts.DryRun {
		_, _ = fmt.Fprintln(out, "MCP config:    <dry-run>")
	} else {
		_, _ = fmt.Fprintf(out, "MCP config:    %s\n", result.MCPConfigPath)
	}
	_, _ = fmt.Fprintf(out, "MCP wiring:    %s\n", displayMCPWiringMethod(result.MCPWiringMethod, opts.DryRun))
	_, _ = fmt.Fprintln(out, "Governed tools:")
	for _, mapping := range governedToolMappings {
		_, _ = fmt.Fprintf(out, "  %-14s -> %s\n", mapping.Friendly, mapping.Canonical)
	}
	writeVerifyAfterLaunch(out, result, opts)
	if len(result.InstructionsWritten) > 0 {
		_, _ = fmt.Fprintln(out, "Instructions:")
		for _, path := range result.InstructionsWritten {
			_, _ = fmt.Fprintf(out, "  wrote %s\n", path)
		}
	}
	if len(result.Warnings) > 0 {
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, "Warning:")
		for _, warning := range result.Warnings {
			_, _ = fmt.Fprintf(out, "  %s\n", warning)
		}
	}
}

func displayGeneratedPath(path string, generated, dryRun bool) string {
	if generated && dryRun {
		return "<generated-nomos-config>"
	}
	return path
}

func displayPolicyBundleSource(source string) string {
	switch source {
	case profileSourceCustom:
		return "custom (--policy-bundle path provided by operator)"
	case profileSourceWorkspace:
		return "workspace (./examples/policies/profiles/)"
	case profileSourceRepo:
		return "nomos repo checkout"
	case profileSourceEmbedded:
		return "embedded (materialized to ~/.nomos/profiles/)"
	default:
		if strings.TrimSpace(source) == "" {
			return "unknown"
		}
		return source
	}
}

func displayMCPWiringMethod(method string, dryRun bool) string {
	if dryRun {
		return "<dry-run>"
	}
	switch method {
	case mcpWiringMCPConfigFlag:
		return "launcher passes --mcp-config to the agent (verified path)"
	case mcpWiringOperatorManaged:
		return "operator-managed (launcher cannot auto-wire MCP for this agent)"
	case mcpWiringSkipped, "":
		return "skipped (no agent process started)"
	default:
		return method
	}
}

// writeVerifyAfterLaunch prints the post-launch verification checklist. The
// launcher cannot prove the agent loaded the MCP config (the agent is a
// separate process the launcher does not control), so we tell the operator
// exactly what to confirm before trusting the session.
func writeVerifyAfterLaunch(out io.Writer, result Result, opts Options) {
	if opts.DryRun {
		return
	}
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Verify after launch:")
	switch result.Agent {
	case AgentClaude:
		_, _ = fmt.Fprintln(out, "  - In Claude Code, run `/mcp` and confirm `nomos` appears as a connected server.")
		_, _ = fmt.Fprintln(out, "  - Confirm the MCP tool list includes read_file, write_file, apply_patch, run_command, http_request.")
	case AgentCodex:
		_, _ = fmt.Fprintln(out, "  - The launcher does NOT auto-wire MCP for codex. Register the generated MCP config")
		_, _ = fmt.Fprintf(out, "    (%s) in ~/.codex/config.toml before trusting this session.\n", result.MCPConfigPath)
		_, _ = fmt.Fprintln(out, "  - In codex, list MCP servers and confirm `nomos` is connected and exposes read_file,")
		_, _ = fmt.Fprintln(out, "    write_file, apply_patch, run_command, http_request.")
	}
	_, _ = fmt.Fprintln(out, "  - If `nomos` is missing or those tools are absent, the session is NOT governed —")
	_, _ = fmt.Fprintln(out, "    exit and reconfigure before issuing prompts.")
}

func writeInstructionFiles(workspaceRoot string) ([]string, error) {
	files := map[string]string{
		filepath.Join(workspaceRoot, "AGENTS.md"):                 instructionText("AGENTS.md"),
		filepath.Join(workspaceRoot, "CLAUDE.md"):                 instructionText("CLAUDE.md"),
		filepath.Join(workspaceRoot, ".codex", "instructions.md"): instructionText(".codex/instructions.md"),
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return nil, fmt.Errorf("instruction file already exists: %s", path)
		}
	}
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(files[path]), 0o600); err != nil {
			return nil, err
		}
	}
	return paths, nil
}

func instructionText(target string) string {
	return fmt.Sprintf(`# Nomos-Governed Workspace

This workspace is intended to route filesystem, patch, shell, git, and HTTP actions through Nomos.

Use the governed default tools:
- read_file for local file reads
- write_file for local file writes
- apply_patch for repository patches
- run_command for shell, git, build, test, and deployment commands
- http_request for outbound HTTP

Do not use native shell, native file, native patch, native internet, or raw upstream MCP servers directly for governed capabilities when Nomos equivalents are available.

If both native tools and Nomos tools are visible, treat the native path as a bypass risk and prefer the Nomos tool.

Source: generated for %s by nomos run.
`, target)
}

func recordLauncherSession(cfg gateway.Config, result Result, now func() time.Time) {
	if strings.TrimSpace(result.MCPConfigPath) == "" {
		return
	}
	sink := launcherAuditSink(cfg.Audit.Sink)
	if strings.TrimSpace(sink) == "" {
		return
	}
	writer, err := audit.NewWriter(sink, redact.DefaultRedactor())
	if err != nil {
		return
	}
	defer func() { _ = writer.Close() }()
	metadata := map[string]any{
		"workspace_root":       result.WorkspaceRoot,
		"profile":              result.Profile,
		"profile_source":       result.PolicyBundleSource,
		"mcp_tool_surface":     "friendly",
		"mcp_config_path":      result.MCPConfigPath,
		"nomos_config_path":    result.ConfigPath,
		"nomos_version":        version.Version,
		"dual_tool_warning":    true,
		"mcp_wiring_method":    result.MCPWiringMethod,
		"generated_config":     result.GeneratedConfig,
		"governed_tool_count":  len(governedToolMappings),
	}
	if len(result.AgentLaunchArgv) > 0 {
		metadata["agent_launch_argv"] = append([]string(nil), result.AgentLaunchArgv...)
	}
	_ = writer.WriteEvent(audit.Event{
		SchemaVersion:    "v1",
		Timestamp:        now().UTC(),
		EventType:        "agent.launcher.session",
		TraceID:          "agent_launcher",
		ActionID:         "agent_launcher",
		Principal:        cfg.Identity.Principal,
		Agent:            result.Agent,
		Environment:      cfg.Identity.Environment,
		PolicyBundleHash: result.PolicyBundleHash,
		AssuranceLevel:   result.AssuranceLevel,
		ExecutorMetadata: metadata,
	})
}

func launcherAuditSink(sink string) string {
	parts := strings.Split(strings.TrimSpace(sink), ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if part == "stdout" {
			part = "stderr"
		}
		out = append(out, part)
	}
	return strings.Join(out, ",")
}

// agentLaunchPlan is the deterministic set of arguments and environment
// variables the launcher will use to start an agent process. It is produced
// independently of os.Exec so it can be unit-tested.
type agentLaunchPlan struct {
	Argv         []string
	Env          []string
	WiringMethod string
}

// resolveAgentLaunchPlan returns the argv and env required to start the named
// agent with Nomos as its MCP boundary. The plan is pure — it does not start
// any process — so the launcher's wiring contract is verifiable in tests.
//
// Threat-model invariant: the launcher MUST NOT print or audit integrity
// claims it has not enforced. Each agent has a different MCP wiring story:
//
//   - Claude Code (`claude --mcp-config <path>`) accepts a per-invocation MCP
//     config file. The launcher passes its generated config via that flag, so
//     the launched session is governed by Nomos by construction. WiringMethod
//     is "mcp_config_flag".
//
//   - The OpenAI Codex CLI loads MCP servers from ~/.codex/config.toml; it has
//     no documented one-shot equivalent of --mcp-config, and the previous
//     CODEX_MCP_CONFIG environment variable was unverified and silently
//     ignored. Rather than ship a false integrity claim, the launcher records
//     "operator_managed": the operator is responsible for registering the
//     generated MCP config in their codex configuration. The launched agent
//     still runs, but the launcher is honest that it did not attach Nomos.
func resolveAgentLaunchPlan(agent, mcpConfigPath string, userArgs []string) (agentLaunchPlan, error) {
	if strings.TrimSpace(mcpConfigPath) == "" {
		return agentLaunchPlan{}, errors.New("mcp config path required")
	}
	plan := agentLaunchPlan{
		Env: []string{
			"NOMOS_MCP_CONFIG=" + mcpConfigPath,
			"NOMOS_AGENT_MCP_CONFIG=" + mcpConfigPath,
		},
	}
	switch agent {
	case AgentClaude:
		plan.Argv = append([]string{"--mcp-config", mcpConfigPath}, userArgs...)
		plan.Env = append(plan.Env, "CLAUDE_MCP_CONFIG="+mcpConfigPath)
		plan.WiringMethod = mcpWiringMCPConfigFlag
	case AgentCodex:
		plan.Argv = append([]string(nil), userArgs...)
		plan.WiringMethod = mcpWiringOperatorManaged
	default:
		return agentLaunchPlan{}, fmt.Errorf("unknown agent %q", agent)
	}
	return plan, nil
}

func launchAgent(agent, mcpConfigPath string, args []string) error {
	bin, err := exec.LookPath(agent)
	if err != nil {
		return fmt.Errorf("%s executable not found; rerun with --no-launch or configure the client with %s: %w", agent, mcpConfigPath, err)
	}
	plan, err := resolveAgentLaunchPlan(agent, mcpConfigPath, args)
	if err != nil {
		return err
	}
	cmd := exec.Command(bin, plan.Argv...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), plan.Env...)
	return cmd.Run()
}

func ensureAgentTempDir(workspaceRoot string) (string, error) {
	root := filepath.Join(workspaceRoot, ".nomos", "agent")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	return os.MkdirTemp(root, "session-*")
}

func normalizeAgent(agent string) string {
	switch strings.ToLower(strings.TrimSpace(agent)) {
	case AgentCodex:
		return AgentCodex
	case AgentClaude:
		return AgentClaude
	default:
		return ""
	}
}

func resolveWorkspaceRoot(raw string) (string, error) {
	if strings.TrimSpace(raw) != "" {
		return filepath.Abs(raw)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if root := findGitRoot(cwd); root != "" {
		return root, nil
	}
	return cwd, nil
}

func findGitRoot(start string) string {
	dir := start
	for {
		if info, err := os.Stat(filepath.Join(dir, ".git")); err == nil && info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func repoRootFromPackage() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}
	if root := findGitRoot(cwd); root != "" {
		return root
	}
	return cwd
}

func nomosCommand(value string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return "nomos"
}
