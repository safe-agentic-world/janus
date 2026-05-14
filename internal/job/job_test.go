package job

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/launcher"
)

func TestDryRunJobCodexWritesArtifacts(t *testing.T) {
	workspace, task := writeJobTask(t, "Inspect the repository and do nothing.")
	var out bytes.Buffer

	result, err := Run(Options{
		Agent:         launcher.AgentCodex,
		TaskPath:      task,
		Profile:       "ci-strict",
		WorkspaceRoot: workspace,
		DryRun:        true,
		NomosCommand:  "nomos",
		Stdout:        &out,
		Getenv:        testEnv(t.TempDir()),
		Now:           fixedJobTime,
	})
	if err != nil {
		t.Fatalf("job dry-run: %v", err)
	}
	if result.ExitCode != ExitSuccess || result.ExitReason != ReasonDryRun {
		t.Fatalf("unexpected exit: %+v", result)
	}
	for _, path := range []string{result.MetadataPath, result.MCPConfigPath, result.AuditPath, result.ChangedFilesPath, result.PolicySummaryPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}
	assertMetadata(t, result.MetadataPath, map[string]any{
		"agent":              launcher.AgentCodex,
		"profile":            "ci-strict",
		"exit_reason":        ReasonDryRun,
		"policy_bundle_hash": result.PolicyBundleHash,
		"assurance_level":    "BEST_EFFORT",
	})
	if !strings.Contains(out.String(), "Nomos job complete") || !strings.Contains(out.String(), "Approval commands:") {
		t.Fatalf("unexpected summary:\n%s", out.String())
	}
}

func TestDryRunJobClaudeWritesArtifacts(t *testing.T) {
	workspace, task := writeJobTask(t, "Inspect the repository and do nothing.")
	result, err := Run(Options{
		Agent:         launcher.AgentClaude,
		TaskPath:      task,
		Profile:       "ci-strict",
		WorkspaceRoot: workspace,
		DryRun:        true,
		NomosCommand:  "nomos",
		Getenv:        testEnv(t.TempDir()),
		Now:           fixedJobTime,
	})
	if err != nil {
		t.Fatalf("job dry-run: %v", err)
	}
	if result.ExitCode != ExitSuccess || result.ExitReason != ReasonDryRun {
		t.Fatalf("unexpected exit: %+v", result)
	}
	if result.Agent != launcher.AgentClaude || result.MCPWiringMethod != "skipped" {
		t.Fatalf("unexpected launcher metadata: %+v", result)
	}
}

func TestJobRunUsesLauncherForRealAgentInvocation(t *testing.T) {
	for _, tc := range []struct {
		agent string
		want  []string
	}{
		{agent: launcher.AgentCodex, want: []string{"-C", "-o", "exec", "Use only Nomos MCP tools"}},
		{agent: launcher.AgentClaude, want: []string{"--strict-mcp-config", "--print", "Use only Nomos MCP tools"}},
	} {
		t.Run(tc.agent, func(t *testing.T) {
			workspace, task := writeJobTask(t, "Fix tests.")
			var got launcher.Options
			_, err := Run(Options{
				Agent:         tc.agent,
				TaskPath:      task,
				Profile:       "ci-strict",
				WorkspaceRoot: workspace,
				Now:           fixedJobTime,
				Launch: func(opts launcher.Options) (launcher.Result, error) {
					got = opts
					writeAgentTranscriptIfRequested(t, opts, "Completed.\n")
					return fakeLauncherResult(opts), nil
				},
			})
			if err != nil {
				t.Fatalf("job run: %v", err)
			}
			if got.NoLaunch || got.DryRun || got.WorkspaceRoot != workspace {
				t.Fatalf("unexpected launcher options: %+v", got)
			}
			joined := strings.Join(got.Args, "\x00")
			for _, want := range tc.want {
				if !strings.Contains(joined, want) {
					t.Fatalf("launcher args missing %q: %+v", want, got.Args)
				}
			}
		})
	}
}

func TestJobRunFailsClosedWhenAgentFinalMessageCannotProceed(t *testing.T) {
	workspace, task := writeJobTask(t, "Fix tests.")
	result, err := Run(Options{
		Agent:         launcher.AgentCodex,
		TaskPath:      task,
		Profile:       "ci-strict",
		WorkspaceRoot: workspace,
		Now:           fixedJobTime,
		Launch: func(opts launcher.Options) (launcher.Result, error) {
			transcriptPath := codexTranscriptPath(opts)
			if transcriptPath == "" {
				t.Fatalf("codex launcher args missing final message output path: %+v", opts.Args)
			}
			text := "I can't proceed because the required Nomos `read_file` call was canceled twice.\n"
			if err := os.WriteFile(transcriptPath, []byte(text), 0o600); err != nil {
				t.Fatalf("write agent transcript: %v", err)
			}
			return fakeLauncherResult(opts), nil
		},
	})
	if err != nil {
		t.Fatalf("job run: %v", err)
	}
	if result.ExitCode != ExitAgentFailure || result.ExitReason != ReasonAgentFailure {
		t.Fatalf("got code=%d reason=%s, want code=%d reason=%s", result.ExitCode, result.ExitReason, ExitAgentFailure, ReasonAgentFailure)
	}
	if result.AgentTranscript == "" {
		t.Fatalf("expected agent transcript path in result")
	}
	assertMetadata(t, result.MetadataPath, map[string]any{
		"agent_transcript_path": result.AgentTranscript,
		"exit_reason":           ReasonAgentFailure,
		"exit_code":             float64(ExitAgentFailure),
	})
	var summary policySummary
	readJSON(t, result.PolicySummaryPath, &summary)
	if summary.ExitReason != ReasonAgentFailure || summary.AgentFailure != 1 {
		t.Fatalf("unexpected policy summary: %+v", summary)
	}
}

func TestJobRunFailsClosedWhenCodexFinalMessageIsMissing(t *testing.T) {
	workspace, task := writeJobTask(t, "Fix tests.")
	result, err := Run(Options{
		Agent:         launcher.AgentCodex,
		TaskPath:      task,
		Profile:       "ci-strict",
		WorkspaceRoot: workspace,
		Now:           fixedJobTime,
		Launch: func(opts launcher.Options) (launcher.Result, error) {
			if codexTranscriptPath(opts) == "" {
				t.Fatalf("codex launcher args missing final message output path: %+v", opts.Args)
			}
			return fakeLauncherResult(opts), nil
		},
	})
	if err != nil {
		t.Fatalf("job run: %v", err)
	}
	if result.ExitCode != ExitAgentFailure || result.ExitReason != ReasonAgentFailure {
		t.Fatalf("got code=%d reason=%s, want code=%d reason=%s", result.ExitCode, result.ExitReason, ExitAgentFailure, ReasonAgentFailure)
	}
}

func TestJobRunFailsClosedWhenClaudePrintOutputCannotProceed(t *testing.T) {
	workspace, task := writeJobTask(t, "Fix tests.")
	result, err := Run(Options{
		Agent:         launcher.AgentClaude,
		TaskPath:      task,
		Profile:       "ci-strict",
		WorkspaceRoot: workspace,
		Now:           fixedJobTime,
		Launch: func(opts launcher.Options) (launcher.Result, error) {
			if opts.AgentStdout == nil {
				t.Fatalf("expected claude agent stdout capture")
			}
			if _, err := opts.AgentStdout.Write([]byte("I cannot proceed because the required Nomos MCP tool call was cancelled.\n")); err != nil {
				t.Fatalf("write claude transcript: %v", err)
			}
			return fakeLauncherResult(opts), nil
		},
	})
	if err != nil {
		t.Fatalf("job run: %v", err)
	}
	if result.ExitCode != ExitAgentFailure || result.ExitReason != ReasonAgentFailure {
		t.Fatalf("got code=%d reason=%s, want code=%d reason=%s", result.ExitCode, result.ExitReason, ExitAgentFailure, ReasonAgentFailure)
	}
	assertMetadata(t, result.MetadataPath, map[string]any{
		"agent_transcript_path": result.AgentTranscript,
		"exit_reason":           ReasonAgentFailure,
	})
}

func TestJobRunFailsClosedWhenClaudePrintOutputIsEmpty(t *testing.T) {
	workspace, task := writeJobTask(t, "Fix tests.")
	result, err := Run(Options{
		Agent:         launcher.AgentClaude,
		TaskPath:      task,
		Profile:       "ci-strict",
		WorkspaceRoot: workspace,
		Now:           fixedJobTime,
		Launch: func(opts launcher.Options) (launcher.Result, error) {
			if opts.AgentStdout == nil {
				t.Fatalf("expected claude agent stdout capture")
			}
			return fakeLauncherResult(opts), nil
		},
	})
	if err != nil {
		t.Fatalf("job run: %v", err)
	}
	if result.ExitCode != ExitAgentFailure || result.ExitReason != ReasonAgentFailure {
		t.Fatalf("got code=%d reason=%s, want code=%d reason=%s", result.ExitCode, result.ExitReason, ExitAgentFailure, ReasonAgentFailure)
	}
}

func TestTaskFileValidation(t *testing.T) {
	workspace := t.TempDir()
	empty := filepath.Join(workspace, "empty.md")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatalf("write empty task: %v", err)
	}
	large := filepath.Join(workspace, "large.md")
	if err := os.WriteFile(large, bytes.Repeat([]byte("x"), MaxTaskBytes+1), 0o600); err != nil {
		t.Fatalf("write large task: %v", err)
	}
	invalid := filepath.Join(workspace, "invalid.md")
	if err := os.WriteFile(invalid, []byte{0xff, 0xfe}, 0o600); err != nil {
		t.Fatalf("write invalid task: %v", err)
	}
	tests := []struct {
		name string
		task string
		want string
	}{
		{name: "missing", task: "", want: "--task is required"},
		{name: "empty", task: empty, want: "task file is empty"},
		{name: "too large", task: large, want: "task file exceeds"},
		{name: "invalid utf8", task: invalid, want: "valid UTF-8"},
		{name: "directory", task: workspace, want: "task path is a directory"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Run(Options{Agent: launcher.AgentCodex, TaskPath: tc.task, WorkspaceRoot: workspace})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q error, got result=%+v err=%v", tc.want, result, err)
			}
			if result.ExitCode != ExitInvalidConfig || result.ExitReason != ReasonInvalidConfig {
				t.Fatalf("unexpected exit classification: %+v", result)
			}
		})
	}
}

func TestArtifactDirCreationAndNoLaunchMetadata(t *testing.T) {
	workspace, task := writeJobTask(t, "Prepare a plan.")
	artifactDir := filepath.Join(workspace, "artifacts", "job")
	result, err := Run(Options{
		Agent:         launcher.AgentClaude,
		TaskPath:      task,
		Profile:       "ci-strict",
		WorkspaceRoot: workspace,
		ArtifactDir:   artifactDir,
		NoLaunch:      true,
		NomosCommand:  "nomos",
		Getenv:        testEnv(t.TempDir()),
		Now:           fixedJobTime,
	})
	if err != nil {
		t.Fatalf("job no-launch: %v", err)
	}
	if result.ArtifactDir != artifactDir || result.ExitReason != ReasonNoLaunch {
		t.Fatalf("unexpected result: %+v", result)
	}
	assertMetadata(t, result.MetadataPath, map[string]any{
		"artifact_dir":      artifactDir,
		"exit_reason":       ReasonNoLaunch,
		"mcp_wiring_method": "mcp_config_flag",
	})
}

func TestPolicyBundleAndProfileAreMutuallyExclusive(t *testing.T) {
	workspace, task := writeJobTask(t, "Do nothing.")
	result, err := Run(Options{
		Agent:            launcher.AgentCodex,
		TaskPath:         task,
		WorkspaceRoot:    workspace,
		Profile:          "ci-strict",
		PolicyBundlePath: "policy.yaml",
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual exclusion error, got result=%+v err=%v", result, err)
	}
	if result.ExitCode != ExitInvalidConfig {
		t.Fatalf("unexpected exit code: %+v", result)
	}
}

func TestExitCodeClassification(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantCode   int
		wantReason string
	}{
		{name: "policy denied", err: errors.New("DENY process.exec denied by policy"), wantCode: ExitPolicyDenied, wantReason: ReasonPolicyDenied},
		{name: "approval pending", err: errors.New("Nomos requires approval for git push"), wantCode: ExitApprovalPending, wantReason: ReasonApprovalPending},
		{name: "agent launch failure", err: errors.New("codex executable not found"), wantCode: ExitAgentFailure, wantReason: ReasonAgentFailure},
		{name: "invalid config", err: errors.New("load config: policy bundle missing"), wantCode: ExitInvalidConfig, wantReason: ReasonInvalidConfig},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			workspace, task := writeJobTask(t, "Do work.")
			result, err := Run(Options{
				Agent:         launcher.AgentCodex,
				TaskPath:      task,
				WorkspaceRoot: workspace,
				Now:           fixedJobTime,
				Launch: func(opts launcher.Options) (launcher.Result, error) {
					return fakeLauncherResult(opts), tc.err
				},
			})
			if err != nil {
				t.Fatalf("job run: %v", err)
			}
			if result.ExitCode != tc.wantCode || result.ExitReason != tc.wantReason {
				t.Fatalf("got code=%d reason=%s, want code=%d reason=%s", result.ExitCode, result.ExitReason, tc.wantCode, tc.wantReason)
			}
			var summary policySummary
			readJSON(t, result.PolicySummaryPath, &summary)
			if summary.ExitReason != tc.wantReason {
				t.Fatalf("unexpected policy summary: %+v", summary)
			}
		})
	}
}

func TestAuditAndSessionMetadataForJobRun(t *testing.T) {
	workspace, task := writeJobTask(t, "Do work.")
	result, err := Run(Options{
		Agent:         launcher.AgentCodex,
		TaskPath:      task,
		WorkspaceRoot: workspace,
		Now:           fixedJobTime,
		Launch: func(opts launcher.Options) (launcher.Result, error) {
			writeAgentTranscriptIfRequested(t, opts, "Completed the requested work.\n")
			return fakeLauncherResult(opts), nil
		},
	})
	if err != nil {
		t.Fatalf("job run: %v", err)
	}
	auditData, err := os.ReadFile(result.AuditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !strings.Contains(string(auditData), `"event_type":"job.run"`) || !strings.Contains(string(auditData), `"exit_reason":"success"`) {
		t.Fatalf("unexpected audit artifact:\n%s", auditData)
	}
	assertMetadata(t, result.MetadataPath, map[string]any{
		"job_id":             result.JobID,
		"policy_bundle_hash": "hash-test",
		"assurance_level":    "BEST_EFFORT",
		"mcp_wiring_method":  "codex_config_override",
		"exit_reason":        ReasonSuccess,
	})
}

func writeJobTask(t *testing.T, text string) (string, string) {
	t.Helper()
	workspace := t.TempDir()
	task := filepath.Join(workspace, "task.md")
	if err := os.WriteFile(task, []byte(text), 0o600); err != nil {
		t.Fatalf("write task: %v", err)
	}
	return workspace, task
}

func fakeLauncherResult(opts launcher.Options) launcher.Result {
	method := "codex_config_override"
	if opts.Agent == launcher.AgentClaude {
		method = "mcp_config_flag"
	}
	return launcher.Result{
		Agent:             opts.Agent,
		WorkspaceRoot:     opts.WorkspaceRoot,
		ConfigPath:        filepath.Join(opts.WorkspaceRoot, ".nomos", "agent", "nomos.generated.json"),
		PolicyBundlePath:  filepath.Join(opts.WorkspaceRoot, "profiles", "ci-strict.yaml"),
		Profile:           "ci-strict",
		PolicyBundleHash:  "hash-test",
		AssuranceLevel:    "BEST_EFFORT",
		ApprovalStorePath: filepath.Join(opts.WorkspaceRoot, ".nomos", "approvals.json"),
		MCPWiringMethod:   method,
		MCPConfigJSON:     []byte(`{"mcpServers":{"nomos":{"command":"nomos","args":["mcp"]}}}` + "\n"),
	}
}

func codexTranscriptPath(opts launcher.Options) string {
	for i, arg := range opts.Args {
		if arg == "-o" && i+1 < len(opts.Args) {
			return opts.Args[i+1]
		}
	}
	return ""
}

func writeAgentTranscriptIfRequested(t *testing.T, opts launcher.Options, text string) {
	t.Helper()
	path := codexTranscriptPath(opts)
	if path != "" {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatalf("write codex transcript: %v", err)
		}
	}
	if opts.AgentStdout != nil {
		if _, err := opts.AgentStdout.Write([]byte(text)); err != nil {
			t.Fatalf("write agent stdout transcript: %v", err)
		}
	}
}

func fixedJobTime() time.Time {
	return time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
}

func testEnv(home string) func(string) string {
	return func(key string) string {
		switch key {
		case "NOMOS_HOME_OVERRIDE", "HOME", "USERPROFILE":
			return home
		default:
			return ""
		}
	}
}

func assertMetadata(t *testing.T, path string, expected map[string]any) {
	t.Helper()
	var got map[string]any
	readJSON(t, path, &got)
	for key, want := range expected {
		if got[key] != want {
			t.Fatalf("metadata[%s] = %#v, want %#v\nmetadata=%+v", key, got[key], want, got)
		}
	}
}

func readJSON(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read json %s: %v", path, err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode json %s: %v\n%s", path, err, data)
	}
}
