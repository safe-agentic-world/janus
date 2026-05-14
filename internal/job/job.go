package job

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/safe-agentic-world/nomos/internal/launcher"
	"github.com/safe-agentic-world/nomos/internal/version"
)

const (
	MaxTaskBytes = 64 * 1024

	ExitSuccess         = 0
	ExitInternalError   = 1
	ExitInvalidConfig   = 2
	ExitPolicyDenied    = 10
	ExitApprovalPending = 11
	ExitAgentFailure    = 12
)

const (
	ReasonSuccess         = "success"
	ReasonDryRun          = "dry_run"
	ReasonNoLaunch        = "no_launch"
	ReasonInvalidConfig   = "invalid_config"
	ReasonPolicyDenied    = "policy_denied"
	ReasonApprovalPending = "approval_pending"
	ReasonAgentFailure    = "agent_failure"
	ReasonInternalError   = "internal_error"
)

type Options struct {
	Agent            string
	TaskPath         string
	ConfigPath       string
	PolicyBundlePath string
	Profile          string
	WorkspaceRoot    string
	ArtifactDir      string
	DryRun           bool
	NoLaunch         bool
	NomosCommand     string
	Stdout           io.Writer
	Stderr           io.Writer
	Getenv           func(string) string
	Now              func() time.Time
	Launch           func(launcher.Options) (launcher.Result, error)
}

type Result struct {
	JobID              string
	Agent              string
	TaskPath           string
	WorkspaceRoot      string
	ArtifactDir        string
	MetadataPath       string
	MCPConfigPath      string
	AuditPath          string
	ChangedFilesPath   string
	PolicySummaryPath  string
	AgentTranscript    string
	Profile            string
	PolicyBundlePath   string
	PolicyBundleHash   string
	AssuranceLevel     string
	MCPWiringMethod    string
	ApprovalStorePath  string
	LauncherConfigPath string
	StartTime          time.Time
	EndTime            time.Time
	ExitReason         string
	ExitCode           int
	LauncherError      string
}

type metadata struct {
	JobID                     string    `json:"job_id"`
	NomosVersion              string    `json:"nomos_version"`
	Agent                     string    `json:"agent"`
	TaskPath                  string    `json:"task_path"`
	WorkspaceRoot             string    `json:"workspace_root"`
	ArtifactDir               string    `json:"artifact_dir"`
	Profile                   string    `json:"profile"`
	PolicyBundlePath          string    `json:"policy_bundle_path"`
	PolicyBundleHash          string    `json:"policy_bundle_hash"`
	AssuranceLevel            string    `json:"assurance_level"`
	MCPWiringMethod           string    `json:"mcp_wiring_method"`
	MCPConfigArtifactPath     string    `json:"mcp_config_artifact_path"`
	LauncherMCPConfigPath     string    `json:"launcher_mcp_config_path,omitempty"`
	LauncherConfigPath        string    `json:"launcher_config_path,omitempty"`
	ApprovalStorePath         string    `json:"approval_store_path,omitempty"`
	AgentTranscriptPath       string    `json:"agent_transcript_path,omitempty"`
	AuditArtifactPath         string    `json:"audit_artifact_path"`
	ChangedFilesArtifactPath  string    `json:"changed_files_artifact_path"`
	PolicySummaryArtifactPath string    `json:"policy_summary_artifact_path"`
	DryRun                    bool      `json:"dry_run"`
	NoLaunch                  bool      `json:"no_launch"`
	StartTime                 time.Time `json:"start_time"`
	EndTime                   time.Time `json:"end_time"`
	ExitReason                string    `json:"exit_reason"`
	ExitCode                  int       `json:"exit_code"`
	LauncherError             string    `json:"launcher_error,omitempty"`
}

type policySummary struct {
	ExitReason      string `json:"exit_reason"`
	PolicyDenied    int    `json:"policy_denied"`
	ApprovalPending int    `json:"approval_pending"`
	AgentFailure    int    `json:"agent_failure"`
}

type auditEvent struct {
	SchemaVersion string    `json:"schema_version"`
	Timestamp     time.Time `json:"timestamp"`
	EventType     string    `json:"event_type"`
	JobID         string    `json:"job_id"`
	Agent         string    `json:"agent"`
	TaskPath      string    `json:"task_path"`
	ExitReason    string    `json:"exit_reason"`
	ExitCode      int       `json:"exit_code"`
	Error         string    `json:"error,omitempty"`
}

type changedFilesSummary struct {
	Available bool          `json:"available"`
	Error     string        `json:"error,omitempty"`
	Before    []changedFile `json:"before,omitempty"`
	After     []changedFile `json:"after,omitempty"`
	Changed   []changedFile `json:"changed,omitempty"`
}

type changedFile struct {
	Status string `json:"status"`
	Path   string `json:"path"`
}

type validationError struct {
	msg string
}

func (e validationError) Error() string {
	return e.msg
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
	if opts.Launch == nil {
		opts.Launch = launcher.Run
	}

	start := opts.Now().UTC()
	result := Result{
		Agent:      strings.ToLower(strings.TrimSpace(opts.Agent)),
		StartTime:  start,
		ExitCode:   ExitInvalidConfig,
		ExitReason: ReasonInvalidConfig,
	}

	workspace, err := resolveWorkspace(opts.WorkspaceRoot)
	if err != nil {
		return result, validationError{msg: err.Error()}
	}
	result.WorkspaceRoot = workspace

	taskPath, taskText, err := readTaskFile(workspace, opts.TaskPath)
	if err != nil {
		return result, validationError{msg: err.Error()}
	}
	result.TaskPath = taskPath

	if strings.TrimSpace(opts.PolicyBundlePath) != "" && strings.TrimSpace(opts.Profile) != "" {
		return result, validationError{msg: "--policy-bundle and --profile are mutually exclusive"}
	}
	if result.Agent != launcher.AgentCodex && result.Agent != launcher.AgentClaude {
		return result, validationError{msg: "--agent must be codex or claude"}
	}

	result.JobID = jobID(start, result.Agent, workspace, taskPath)
	artifactDir, err := resolveArtifactDir(workspace, opts.ArtifactDir, result.JobID)
	if err != nil {
		result.ExitCode = ExitInternalError
		result.ExitReason = ReasonInternalError
		return result, err
	}
	result.ArtifactDir = artifactDir
	result.MCPConfigPath = filepath.Join(artifactDir, "mcp-config.json")
	result.AuditPath = filepath.Join(artifactDir, "audit.jsonl")
	result.ChangedFilesPath = filepath.Join(artifactDir, "changed-files.json")
	result.PolicySummaryPath = filepath.Join(artifactDir, "policy-summary.json")
	result.MetadataPath = filepath.Join(artifactDir, "job-metadata.json")
	if !opts.DryRun && !opts.NoLaunch && (result.Agent == launcher.AgentCodex || result.Agent == launcher.AgentClaude) {
		result.AgentTranscript = filepath.Join(artifactDir, "agent-final-message.txt")
	}
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		result.ExitCode = ExitInternalError
		result.ExitReason = ReasonInternalError
		return result, fmt.Errorf("create artifact dir: %w", err)
	}

	before := gitStatus(workspace)
	var agentStdout io.Writer
	var transcriptFile *os.File
	if result.Agent == launcher.AgentClaude && result.AgentTranscript != "" {
		transcriptFile, err = os.Create(result.AgentTranscript)
		if err != nil {
			result.ExitCode = ExitInternalError
			result.ExitReason = ReasonInternalError
			return result, fmt.Errorf("create agent transcript artifact: %w", err)
		}
		agentStdout = transcriptFile
	}
	launcherResult, launchErr := opts.Launch(launcher.Options{
		Agent:            result.Agent,
		ConfigPath:       opts.ConfigPath,
		PolicyBundlePath: opts.PolicyBundlePath,
		Profile:          opts.Profile,
		DryRun:           opts.DryRun,
		NoLaunch:         opts.NoLaunch,
		WorkspaceRoot:    workspace,
		NomosCommand:     opts.NomosCommand,
		Stdout:           io.Discard,
		Stderr:           opts.Stderr,
		AgentStdout:      agentStdout,
		AgentStderr:      opts.Stderr,
		Getenv:           opts.Getenv,
		Args:             agentArgs(result.Agent, workspace, taskPath, taskText, result.AgentTranscript),
		Now:              opts.Now,
	})
	if transcriptFile != nil {
		if err := transcriptFile.Close(); err != nil && launchErr == nil {
			launchErr = fmt.Errorf("close agent transcript artifact: %w", err)
		}
	}

	result.Profile = launcherResult.Profile
	result.PolicyBundlePath = launcherResult.PolicyBundlePath
	result.PolicyBundleHash = launcherResult.PolicyBundleHash
	result.AssuranceLevel = launcherResult.AssuranceLevel
	result.MCPWiringMethod = launcherResult.MCPWiringMethod
	result.ApprovalStorePath = launcherResult.ApprovalStorePath
	result.LauncherConfigPath = launcherResult.ConfigPath

	if len(launcherResult.MCPConfigJSON) > 0 {
		if err := os.WriteFile(result.MCPConfigPath, launcherResult.MCPConfigJSON, 0o600); err != nil {
			result.ExitCode = ExitInternalError
			result.ExitReason = ReasonInternalError
			return result, fmt.Errorf("write mcp config artifact: %w", err)
		}
	}

	agentTranscript, agentTranscriptFound := readOptionalText(result.AgentTranscript)
	result.ExitCode, result.ExitReason = classifyLaunchOutcome(opts, launchErr, result.AgentTranscript != "", agentTranscriptFound, agentTranscript)
	if launchErr != nil {
		result.LauncherError = launchErr.Error()
	}
	result.EndTime = opts.Now().UTC()

	after := gitStatus(workspace)
	if err := writeArtifacts(result, opts, launcherResult, before, after); err != nil {
		result.ExitCode = ExitInternalError
		result.ExitReason = ReasonInternalError
		return result, err
	}
	writeSummary(opts.Stdout, result)
	return result, nil
}

func readTaskFile(workspace, raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("--task is required")
	}
	path := raw
	if !filepath.IsAbs(path) {
		path = filepath.Join(workspace, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", fmt.Errorf("resolve task path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", "", fmt.Errorf("read task file: %w", err)
	}
	if info.IsDir() {
		return "", "", fmt.Errorf("task path is a directory: %s", abs)
	}
	if info.Size() > MaxTaskBytes {
		return "", "", fmt.Errorf("task file exceeds %d bytes: %s", MaxTaskBytes, abs)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", "", fmt.Errorf("read task file: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return "", "", fmt.Errorf("task file is empty: %s", abs)
	}
	if !utf8.Valid(data) {
		return "", "", fmt.Errorf("task file must be valid UTF-8: %s", abs)
	}
	return abs, string(data), nil
}

func resolveWorkspace(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return os.Getwd()
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("resolve workspace: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("workspace does not exist: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("workspace is not a directory: %s", abs)
	}
	return abs, nil
}

func resolveArtifactDir(workspace, raw, id string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return filepath.Join(workspace, ".nomos", "job", id), nil
	}
	if filepath.IsAbs(raw) {
		return raw, nil
	}
	return filepath.Abs(filepath.Join(workspace, raw))
}

func jobID(start time.Time, agent, workspace, taskPath string) string {
	sum := sha256.Sum256([]byte(agent + "\x00" + workspace + "\x00" + taskPath + "\x00" + start.Format(time.RFC3339Nano)))
	return "job-" + start.Format("20060102T150405Z") + "-" + hex.EncodeToString(sum[:])[:12]
}

func agentArgs(agent, workspace, taskPath, taskText, transcriptPath string) []string {
	prompt := "Run this Nomos-governed CI job in workspace " + workspace + ".\n" +
		"Use only Nomos MCP tools for governed file, patch, shell, git, and HTTP actions.\n" +
		"Task file: " + taskPath + "\n\n" + taskText
	switch agent {
	case launcher.AgentCodex:
		args := []string{"-C", workspace, "--ask-for-approval", "never", "--sandbox", "read-only", "exec"}
		if strings.TrimSpace(transcriptPath) != "" {
			args = append(args, "-o", transcriptPath)
		}
		return append(args, prompt)
	case launcher.AgentClaude:
		return []string{"--strict-mcp-config", "--tools", "", "--permission-mode", "dontAsk", "--print", prompt}
	default:
		return []string{prompt}
	}
}

func classifyLaunchOutcome(opts Options, err error, agentTranscriptExpected, agentTranscriptFound bool, agentTranscript string) (int, string) {
	if err == nil {
		if opts.DryRun {
			return ExitSuccess, ReasonDryRun
		}
		if opts.NoLaunch {
			return ExitSuccess, ReasonNoLaunch
		}
		if agentTranscriptExpected && (!agentTranscriptFound || strings.TrimSpace(agentTranscript) == "") {
			return ExitAgentFailure, ReasonAgentFailure
		}
		if agentTranscriptIndicatesFailure(agentTranscript) {
			return ExitAgentFailure, ReasonAgentFailure
		}
		return ExitSuccess, ReasonSuccess
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "approval") && (strings.Contains(msg, "pending") || strings.Contains(msg, "requires approval") || strings.Contains(msg, "require_approval")):
		return ExitApprovalPending, ReasonApprovalPending
	case strings.Contains(msg, "policy denied") || strings.Contains(msg, "denied by policy") || strings.Contains(msg, "deny "):
		return ExitPolicyDenied, ReasonPolicyDenied
	case strings.Contains(msg, "executable not found") || strings.Contains(msg, "exit status"):
		return ExitAgentFailure, ReasonAgentFailure
	case strings.Contains(msg, "config") || strings.Contains(msg, "policy bundle") || strings.Contains(msg, "profile"):
		return ExitInvalidConfig, ReasonInvalidConfig
	default:
		return ExitInternalError, ReasonInternalError
	}
}

func readOptionalText(path string) (string, bool) {
	if strings.TrimSpace(path) == "" {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(data), true
}

func agentTranscriptIndicatesFailure(text string) bool {
	normalized := strings.ToLower(strings.TrimSpace(text))
	normalized = strings.NewReplacer("\u2019", "'", "\u2018", "'", "\u201c", "\"", "\u201d", "\"").Replace(normalized)
	if normalized == "" {
		return false
	}
	markers := []string{
		"user cancelled mcp tool call",
		"user canceled mcp tool call",
		"mcp tool call was cancelled",
		"mcp tool call was canceled",
		"nomos `read_file` call was cancelled",
		"nomos `read_file` call was canceled",
		"i can't proceed",
		"i cannot proceed",
		"required nomos mcp",
		"required nomos tool",
		"allow the nomos mcp",
		"allow the nomos tool",
		"switch the sandbox",
	}
	for _, marker := range markers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func writeArtifacts(result Result, opts Options, launcherResult launcher.Result, before, after changedFilesSummary) error {
	changed := changedFilesSummary{Available: before.Available && after.Available, Before: before.After, After: after.After}
	if !before.Available {
		changed.Available = false
		changed.Error = before.Error
	} else if !after.Available {
		changed.Available = false
		changed.Error = after.Error
	} else {
		changed.Changed = diffChangedFiles(before.After, after.After)
	}
	if err := writeJSON(result.ChangedFilesPath, changed); err != nil {
		return fmt.Errorf("write changed files artifact: %w", err)
	}
	summary := policySummary{ExitReason: result.ExitReason}
	if result.ExitReason == ReasonPolicyDenied {
		summary.PolicyDenied = 1
	}
	if result.ExitReason == ReasonApprovalPending {
		summary.ApprovalPending = 1
	}
	if result.ExitReason == ReasonAgentFailure {
		summary.AgentFailure = 1
	}
	if err := writeJSON(result.PolicySummaryPath, summary); err != nil {
		return fmt.Errorf("write policy summary artifact: %w", err)
	}
	audit := auditEvent{
		SchemaVersion: "v1",
		Timestamp:     result.EndTime,
		EventType:     "job.run",
		JobID:         result.JobID,
		Agent:         result.Agent,
		TaskPath:      result.TaskPath,
		ExitReason:    result.ExitReason,
		ExitCode:      result.ExitCode,
		Error:         result.LauncherError,
	}
	if err := appendJSONL(result.AuditPath, audit); err != nil {
		return fmt.Errorf("write audit artifact: %w", err)
	}
	meta := metadata{
		JobID:                     result.JobID,
		NomosVersion:              version.Version,
		Agent:                     result.Agent,
		TaskPath:                  result.TaskPath,
		WorkspaceRoot:             result.WorkspaceRoot,
		ArtifactDir:               result.ArtifactDir,
		Profile:                   result.Profile,
		PolicyBundlePath:          result.PolicyBundlePath,
		PolicyBundleHash:          result.PolicyBundleHash,
		AssuranceLevel:            result.AssuranceLevel,
		MCPWiringMethod:           result.MCPWiringMethod,
		MCPConfigArtifactPath:     result.MCPConfigPath,
		LauncherMCPConfigPath:     launcherResult.MCPConfigPath,
		LauncherConfigPath:        result.LauncherConfigPath,
		ApprovalStorePath:         result.ApprovalStorePath,
		AgentTranscriptPath:       result.AgentTranscript,
		AuditArtifactPath:         result.AuditPath,
		ChangedFilesArtifactPath:  result.ChangedFilesPath,
		PolicySummaryArtifactPath: result.PolicySummaryPath,
		DryRun:                    opts.DryRun,
		NoLaunch:                  opts.NoLaunch,
		StartTime:                 result.StartTime,
		EndTime:                   result.EndTime,
		ExitReason:                result.ExitReason,
		ExitCode:                  result.ExitCode,
		LauncherError:             result.LauncherError,
	}
	if err := writeJSON(result.MetadataPath, meta); err != nil {
		return fmt.Errorf("write job metadata: %w", err)
	}
	return nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func appendJSONL(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func gitStatus(workspace string) changedFilesSummary {
	cmd := exec.Command("git", "-C", workspace, "status", "--porcelain=v1")
	out, err := cmd.Output()
	if err != nil {
		return changedFilesSummary{Available: false, Error: err.Error()}
	}
	return changedFilesSummary{Available: true, After: parsePorcelain(out)}
}

func parsePorcelain(data []byte) []changedFile {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
		return nil
	}
	out := make([]changedFile, 0, len(lines))
	for _, line := range lines {
		if len(line) < 4 {
			continue
		}
		out = append(out, changedFile{Status: strings.TrimSpace(line[:2]), Path: strings.TrimSpace(line[3:])})
	}
	return out
}

func diffChangedFiles(before, after []changedFile) []changedFile {
	beforeSet := map[string]string{}
	for _, file := range before {
		beforeSet[file.Path] = file.Status
	}
	out := make([]changedFile, 0, len(after))
	for _, file := range after {
		if beforeSet[file.Path] != file.Status {
			out = append(out, file)
		}
	}
	return out
}

func writeSummary(out io.Writer, result Result) {
	_, _ = fmt.Fprintln(out, "Nomos job complete")
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintf(out, "Job:           %s\n", result.JobID)
	_, _ = fmt.Fprintf(out, "Agent:         %s\n", result.Agent)
	_, _ = fmt.Fprintf(out, "Task:          %s\n", result.TaskPath)
	_, _ = fmt.Fprintf(out, "Workspace:     %s\n", result.WorkspaceRoot)
	_, _ = fmt.Fprintf(out, "Artifacts:     %s\n", result.ArtifactDir)
	_, _ = fmt.Fprintf(out, "Profile:       %s\n", result.Profile)
	_, _ = fmt.Fprintf(out, "Policy hash:   %s\n", result.PolicyBundleHash)
	_, _ = fmt.Fprintf(out, "Assurance:     %s\n", result.AssuranceLevel)
	_, _ = fmt.Fprintf(out, "MCP wiring:    %s\n", result.MCPWiringMethod)
	_, _ = fmt.Fprintf(out, "Exit reason:   %s\n", result.ExitReason)
	_, _ = fmt.Fprintf(out, "Exit code:     %d\n", result.ExitCode)
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Artifacts written:")
	_, _ = fmt.Fprintf(out, "  metadata:       %s\n", result.MetadataPath)
	_, _ = fmt.Fprintf(out, "  mcp_config:     %s\n", result.MCPConfigPath)
	_, _ = fmt.Fprintf(out, "  audit:          %s\n", result.AuditPath)
	_, _ = fmt.Fprintf(out, "  changed_files:  %s\n", result.ChangedFilesPath)
	_, _ = fmt.Fprintf(out, "  policy_summary: %s\n", result.PolicySummaryPath)
	if result.AgentTranscript != "" {
		_, _ = fmt.Fprintf(out, "  agent_message:  %s\n", result.AgentTranscript)
	}
	if result.ApprovalStorePath != "" {
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintln(out, "Approval commands:")
		_, _ = fmt.Fprintf(out, "  nomos approvals list --store %s\n", result.ApprovalStorePath)
		_, _ = fmt.Fprintf(out, "  nomos approvals approve --store %s <approval_id>\n", result.ApprovalStorePath)
		_, _ = fmt.Fprintf(out, "  nomos approvals deny --store %s <approval_id>\n", result.ApprovalStorePath)
	}
}
