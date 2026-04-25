package bypasssuite

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/credentials"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/sandbox"
	"github.com/safe-agentic-world/nomos/internal/service"
)

type corpusCase struct {
	ID                 string          `json:"id"`
	Category           string          `json:"category"`
	ActionAttempted    string          `json:"action_attempted"`
	ExpectedControlled caseExpectation `json:"expected_controlled"`
	ExpectedUnmanaged  caseExpectation `json:"expected_unmanaged"`
}

type caseExpectation struct {
	Decision            string `json:"decision"`
	ExecutorBehavior    string `json:"executor_behavior"`
	AuditClassification string `json:"audit_classification"`
	RedactionBehavior   string `json:"redaction_behavior"`
}

type recordSink struct {
	events []audit.Event
}

func (r *recordSink) WriteEvent(event audit.Event) error {
	r.events = append(r.events, event)
	return nil
}

func TestBypassSuiteControlledRuntime(t *testing.T) {
	runBypassSuite(t, "controlled")
}

func TestBypassSuiteUnmanagedMode(t *testing.T) {
	runBypassSuite(t, "unmanaged")
}

func runBypassSuite(t *testing.T, mode string) {
	t.Helper()
	cases := loadBypassCases(t)
	if len(cases) == 0 {
		t.Fatal("expected bypass cases")
	}
	for _, tc := range cases {
		t.Run(mode+"_"+tc.ID, func(t *testing.T) {
			expectation := tc.ExpectedControlled
			if mode == "unmanaged" {
				expectation = tc.ExpectedUnmanaged
			}
			runCase(t, mode, tc, expectation)
		})
	}
}

func runCase(t *testing.T, mode string, tc corpusCase, expected caseExpectation) {
	t.Helper()
	dir := t.TempDir()
	outside := t.TempDir()
	secretValue := "bypass-secret-123"
	reader := executor.NewFSReader(dir, 64*1024, 200)
	writer := executor.NewFSWriter(dir, 64*1024)
	patcher := executor.NewPatchApplier(dir, 64*1024)
	execRunner := executor.NewExecRunner(dir, 64*1024)
	httpRunner := executor.NewHTTPRunner(64 * 1024)
	recorder := &recordSink{}
	redactor := redact.DefaultRedactor()
	var broker *credentials.Broker
	sandboxProfile := "container"
	if mode == "unmanaged" {
		sandboxProfile = "none"
	}

	if tc.ID == "env_leakage_exec" {
		var err error
		broker, err = credentials.NewBroker([]credentials.Secret{
			{ID: "leak", EnvKey: "API_TOKEN", Value: secretValue, TTLSeconds: 60},
		}, func() time.Time { return time.Unix(0, 0) })
		if err != nil {
			t.Fatalf("new broker: %v", err)
		}
	}

	if tc.ID == "redirect_to_disallowed_host" {
		httpRunner.SetClient(&http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusFound,
					Header:     http.Header{"Location": []string{"https://evil.com/blocked?token=secret"}},
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    req,
				}, nil
			}),
		})
	}

	engine := policy.NewEngine(policy.Bundle{
		Version: "v1",
		Hash:    "bypass-bundle",
		Rules:   rulesForCase(tc.ID),
	})
	svc := service.New(
		engine,
		reader,
		writer,
		patcher,
		execRunner,
		httpRunner,
		recorder,
		redactor,
		nil,
		broker,
		sandboxProfile,
		func() time.Time { return time.Unix(0, 0) },
	)
	if mode == "controlled" {
		svc.SetSandboxEvidence(sandbox.Evidence{
			ContainerBackendReady: true,
			Rootless:              true,
			ReadOnlyFS:            true,
			NoNewPrivileges:       true,
			NetworkDefaultDeny:    true,
		}, []string{dir})
	}

	var resp action.Response
	var err error
	switch tc.ID {
	case "path_traversal_read":
		resp, err = svc.Process(mustAction(t, "act-"+tc.ID, "fs.read", "file://workspace/../secret.txt", `{}`, "dev"))
	case "symlink_escape_read":
		if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside"), 0o600); err != nil {
			t.Fatalf("write outside secret: %v", err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		resp, err = svc.Process(mustAction(t, "act-"+tc.ID, "fs.read", "file://workspace/link/secret.txt", `{}`, "dev"))
	case "redirect_to_disallowed_host":
		resp, err = svc.Process(mustAction(t, "act-"+tc.ID, "net.http_request", "url://example.com/start", `{"method":"GET"}`, "dev"))
	case "env_leakage_exec":
		traceID := "trace-" + tc.ID
		leaseResp, leaseErr := svc.Process(mustActionWithTrace(t, "act-"+tc.ID+"-lease", "secrets.checkout", "secret://vault/leak", `{"secret_id":"leak"}`, "dev", traceID))
		if leaseErr != nil {
			t.Fatalf("lease process: %v", leaseErr)
		}
		argv, allowPrefix := secretEchoCommand()
		t.Setenv("GO_WANT_EXEC_HELPER_PROCESS", "1")
		t.Setenv("NOMOS_EXEC_HELPER_MODE", "secret")
		engine = policy.NewEngine(policy.Bundle{
			Version: "v1",
			Hash:    "bypass-bundle",
			Rules: append(rulesForCase(tc.ID), policy.Rule{
				ID:           "allow-exec",
				ActionType:   "process.exec",
				Resource:     "file://workspace/",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
				Obligations: map[string]any{
					"sandbox_mode":   "local",
					"exec_allowlist": []any{allowPrefix},
				},
			}),
		})
		svc = service.New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redactor, nil, broker, "local", func() time.Time { return time.Unix(0, 0) })
		params, marshalErr := json.Marshal(map[string]any{
			"argv":                 argv,
			"cwd":                  "",
			"env_allowlist_keys":   []string{"API_TOKEN", "GO_WANT_EXEC_HELPER_PROCESS", "NOMOS_EXEC_HELPER_MODE"},
			"credential_lease_ids": []string{leaseResp.CredentialLeaseID},
		})
		if marshalErr != nil {
			t.Fatalf("marshal exec params: %v", marshalErr)
		}
		resp, err = svc.Process(mustActionWithTrace(t, "act-"+tc.ID, "process.exec", "file://workspace/", string(params), "dev", traceID))
	case "subprocess_escape_probe":
		argv, allowPrefix := benignExecCommand()
		t.Setenv("GO_WANT_EXEC_HELPER_PROCESS", "1")
		t.Setenv("NOMOS_EXEC_HELPER_MODE", "echo")
		engine = policy.NewEngine(policy.Bundle{
			Version: "v1",
			Hash:    "bypass-bundle",
			Rules: []policy.Rule{
				{
					ID:           "allow-exec-probe",
					ActionType:   "process.exec",
					Resource:     "file://workspace/",
					Decision:     policy.DecisionAllow,
					Principals:   []string{"system"},
					Agents:       []string{"nomos"},
					Environments: []string{"dev"},
					Obligations: map[string]any{
						"sandbox_mode":   "container",
						"exec_allowlist": []any{allowPrefix},
					},
				},
			},
		})
		svc = service.New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redactor, nil, nil, sandboxProfile, func() time.Time { return time.Unix(0, 0) })
		if mode == "controlled" {
			svc.SetSandboxEvidence(sandbox.Evidence{
				ContainerBackendReady: true,
				Rootless:              true,
				ReadOnlyFS:            true,
				NoNewPrivileges:       true,
				NetworkDefaultDeny:    true,
			}, []string{dir})
		}
		resp, err = svc.Process(mustAction(t, "act-"+tc.ID, "process.exec", "file://workspace/", mustJSON(map[string]any{
			"argv":               argv,
			"cwd":                "",
			"env_allowlist_keys": []string{},
		}), "dev"))
	case "workspace_race_probe":
		if err := os.Symlink(outside, filepath.Join(dir, "race")); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		resp, err = svc.Process(mustAction(t, "act-"+tc.ID, "fs.write", "file://workspace/race/probe.txt", `{"content":"payload"}`, "dev"))
	default:
		t.Fatalf("unhandled case %s", tc.ID)
	}

	completed := findCompletedEvent(t, recorder.events, "act-"+tc.ID)
	effectiveDecision := completed.Decision
	if resp.Decision != "" {
		effectiveDecision = resp.Decision
	}
	if effectiveDecision != expected.Decision {
		t.Fatalf("%s: expected decision %s, got %s", tc.ID, expected.Decision, effectiveDecision)
	}
	if completed.ResultClassification != expected.AuditClassification {
		t.Fatalf("%s: expected audit classification %s, got %s", tc.ID, expected.AuditClassification, completed.ResultClassification)
	}
	validateExecutorBehavior(t, tc.ID, expected.ExecutorBehavior, resp, err, completed)
	validateRedactionBehavior(t, tc.ID, expected.RedactionBehavior, resp, completed, secretValue)
}

func rulesForCase(id string) []policy.Rule {
	switch id {
	case "path_traversal_read":
		return []policy.Rule{{ID: "allow-read", ActionType: "fs.read", Resource: "file://workspace/**", Decision: policy.DecisionAllow, Principals: []string{"system"}, Agents: []string{"nomos"}, Environments: []string{"dev"}}}
	case "symlink_escape_read":
		return []policy.Rule{{ID: "allow-read", ActionType: "fs.read", Resource: "file://workspace/**", Decision: policy.DecisionAllow, Principals: []string{"system"}, Agents: []string{"nomos"}, Environments: []string{"dev"}}}
	case "redirect_to_disallowed_host":
		return []policy.Rule{{
			ID:           "allow-http",
			ActionType:   "net.http_request",
			Resource:     "url://example.com/**",
			Decision:     policy.DecisionAllow,
			Principals:   []string{"system"},
			Agents:       []string{"nomos"},
			Environments: []string{"dev"},
			Obligations: map[string]any{
				"net_allowlist":           []any{"example.com"},
				"http_redirects":          true,
				"http_redirect_hop_limit": 2,
			},
		}}
	case "env_leakage_exec":
		return []policy.Rule{{
			ID:           "allow-secret",
			ActionType:   "secrets.checkout",
			Resource:     "secret://vault/leak",
			Decision:     policy.DecisionAllow,
			Principals:   []string{"system"},
			Agents:       []string{"nomos"},
			Environments: []string{"dev"},
		}}
	case "workspace_race_probe":
		return []policy.Rule{{
			ID:           "allow-write",
			ActionType:   "fs.write",
			Resource:     "file://workspace/**",
			Decision:     policy.DecisionAllow,
			Principals:   []string{"system"},
			Agents:       []string{"nomos"},
			Environments: []string{"dev"},
			Obligations:  map[string]any{"sandbox_mode": "local"},
		}}
	default:
		return nil
	}
}

func validateExecutorBehavior(t *testing.T, caseID, behavior string, resp action.Response, processErr error, completed audit.Event) {
	t.Helper()
	switch behavior {
	case "normalization_rejects_before_execution":
		if processErr == nil || !strings.Contains(strings.ToLower(processErr.Error()), "traversal") {
			t.Fatalf("%s: expected traversal error, got %v", caseID, processErr)
		}
	case "path_escape_detected":
		if processErr == nil || !strings.Contains(strings.ToLower(processErr.Error()), "path escape") {
			t.Fatalf("%s: expected path escape error, got %v", caseID, processErr)
		}
	case "redirect_blocked_by_allowlist":
		if processErr == nil || !strings.Contains(strings.ToLower(processErr.Error()), "allowlisted") {
			t.Fatalf("%s: expected redirect allowlist error, got %v", caseID, processErr)
		}
	case "exec_output_redacted":
		if processErr != nil {
			t.Fatalf("%s: unexpected process error: %v", caseID, processErr)
		}
		if !strings.Contains(resp.Stdout, "[REDACTED]") {
			t.Fatalf("%s: expected redacted stdout, got %q", caseID, resp.Stdout)
		}
	case "exec_runs_in_configured_sandbox":
		if processErr != nil {
			t.Fatalf("%s: unexpected process error: %v", caseID, processErr)
		}
		if completed.SandboxMode != "container" {
			t.Fatalf("%s: expected container sandbox, got %s", caseID, completed.SandboxMode)
		}
	case "sandbox_required":
		if processErr != nil {
			t.Fatalf("%s: unexpected process error: %v", caseID, processErr)
		}
		if resp.Reason != "sandbox_required" {
			t.Fatalf("%s: expected sandbox_required, got %s", caseID, resp.Reason)
		}
	default:
		t.Fatalf("unknown executor behavior %s", behavior)
	}
}

func validateRedactionBehavior(t *testing.T, caseID, behavior string, resp action.Response, completed audit.Event, secretValue string) {
	t.Helper()
	switch behavior {
	case "no_output":
		if resp.Output != "" || resp.Stdout != "" || resp.Stderr != "" {
			t.Fatalf("%s: expected no output, got %+v", caseID, resp)
		}
	case "audit_no_final_resource":
		if completed.ExecutorMetadata == nil {
			return
		}
		if _, ok := completed.ExecutorMetadata["final_resource"]; ok {
			t.Fatalf("%s: expected no final_resource in audit metadata, got %+v", caseID, completed.ExecutorMetadata)
		}
	case "response_and_audit_redacted":
		if strings.Contains(resp.Stdout, secretValue) || strings.Contains(resp.Stderr, secretValue) {
			t.Fatalf("%s: secret leaked in response", caseID)
		}
		data, err := json.Marshal(completed)
		if err != nil {
			t.Fatalf("%s: marshal audit: %v", caseID, err)
		}
		if strings.Contains(string(data), secretValue) {
			t.Fatalf("%s: secret leaked in audit", caseID)
		}
	case "no_secret_output":
		if strings.Contains(resp.Stdout, "secret") || strings.Contains(resp.Stderr, "secret") {
			t.Fatalf("%s: unexpected secret-like output", caseID)
		}
	default:
		t.Fatalf("unknown redaction behavior %s", behavior)
	}
}

func findCompletedEvent(t *testing.T, events []audit.Event, actionID string) audit.Event {
	t.Helper()
	for _, event := range events {
		if event.EventType == "action.completed" && event.ActionID == actionID {
			return event
		}
	}
	t.Fatalf("missing completed event for %s", actionID)
	return audit.Event{}
}

func mustAction(t *testing.T, id, actionType, resource, params, env string) action.Action {
	t.Helper()
	return mustActionWithTrace(t, id, actionType, resource, params, env, "trace-"+id)
}

func mustActionWithTrace(t *testing.T, id, actionType, resource, params, env, traceID string) action.Action {
	t.Helper()
	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      id,
		ActionType:    actionType,
		Resource:      resource,
		Params:        []byte(params),
		TraceID:       traceID,
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: env,
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	return act
}

func mustJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func benignExecCommand() ([]string, []any) {
	return []string{os.Args[0], "-test.run=TestExecHelperProcess"}, []any{os.Args[0], "-test.run=TestExecHelperProcess"}
}

func secretEchoCommand() ([]string, []any) {
	return []string{os.Args[0], "-test.run=TestExecHelperProcess"}, []any{os.Args[0], "-test.run=TestExecHelperProcess"}
}

func TestExecHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_EXEC_HELPER_PROCESS") != "1" {
		return
	}
	switch os.Getenv("NOMOS_EXEC_HELPER_MODE") {
	case "echo":
		fmt.Fprint(os.Stdout, "ok")
	case "secret":
		fmt.Fprint(os.Stdout, os.Getenv("API_TOKEN"))
	default:
		fmt.Fprint(os.Stdout, "unexpected helper mode")
		os.Exit(2)
	}
	os.Exit(0)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func loadBypassCases(t *testing.T) []corpusCase {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "bypass", "cases.jsonl")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open bypass cases: %v", err)
	}
	defer file.Close()
	var cases []corpusCase
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var tc corpusCase
		if err := json.Unmarshal([]byte(line), &tc); err != nil {
			t.Fatalf("parse bypass case: %v", err)
		}
		if tc.ID == "" || tc.ActionAttempted == "" {
			t.Fatalf("invalid bypass case: %+v", tc)
		}
		cases = append(cases, tc)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan bypass cases: %v", err)
	}
	return cases
}
