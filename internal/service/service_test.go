package service

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

type recordSink struct {
	events []audit.Event
}

func (r *recordSink) WriteEvent(event audit.Event) error {
	r.events = append(r.events, event)
	return nil
}

func TestServiceAllowsReadAndRedacts(t *testing.T) {
	dir := t.TempDir()
	readmePath := filepath.Join(dir, "README.md")
	content := "Authorization: secret\n" + strings.Repeat("x", 100) + "\n"
	if err := os.WriteFile(readmePath, []byte(content), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{ID: "allow-readme", ActionType: "fs.read", Resource: "file://workspace/README.md", Decision: policy.DecisionAllow},
		},
		Hash: "test",
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(dir, 32, 10)
	recorder := &recordSink{}
	writer := executor.NewFSWriter(dir, 32)
	patcher := executor.NewPatchApplier(dir, 32)
	execRunner := executor.NewExecRunner(dir, 32)
	httpRunner := executor.NewHTTPRunner(32)
	httpRunner.SetClient(newTestHTTPClient("ok"))
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), nil, nil, "local", func() time.Time { return time.Unix(0, 0) })

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "fs.read",
		Resource:      "file://workspace/README.md",
		Params:        []byte(`{}`),
		TraceID:       "trace1",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	resp, err := svc.Process(act)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if resp.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow, got %s", resp.Decision)
	}
	if resp.Output == "" {
		t.Fatal("expected output")
	}
	if strings.Contains(resp.Output, "Authorization: secret") {
		t.Fatal("expected redaction")
	}
	if !resp.Truncated {
		t.Fatal("expected truncated output")
	}
	if len(resp.Output) > 32 {
		t.Fatalf("expected output <= 32 bytes, got %d", len(resp.Output))
	}
	if len(recorder.events) < 3 {
		t.Fatalf("expected at least 3 events, got %d", len(recorder.events))
	}
	decisionEvent := recorder.events[1]
	if decisionEvent.Principal != "system" || decisionEvent.Agent != "nomos" || decisionEvent.Environment != "dev" {
		t.Fatalf("expected identity in audit event, got principal=%s agent=%s env=%s", decisionEvent.Principal, decisionEvent.Agent, decisionEvent.Environment)
	}
}

func TestServiceDeniesRead(t *testing.T) {
	dir := t.TempDir()
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{ID: "allow-readme", ActionType: "fs.read", Resource: "file://workspace/README.md", Decision: policy.DecisionAllow},
		},
		Hash: "test",
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(dir, 32, 10)
	recorder := &recordSink{}
	writer := executor.NewFSWriter(dir, 32)
	patcher := executor.NewPatchApplier(dir, 32)
	execRunner := executor.NewExecRunner(dir, 32)
	httpRunner := executor.NewHTTPRunner(32)
	httpRunner.SetClient(newTestHTTPClient("ok"))
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), nil, nil, "local", func() time.Time { return time.Unix(0, 0) })

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act2",
		ActionType:    "fs.read",
		Resource:      "file://workspace/other.md",
		Params:        []byte(`{}`),
		TraceID:       "trace2",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	resp, err := svc.Process(act)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if resp.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s", resp.Decision)
	}
	if resp.Output != "" {
		t.Fatal("expected no output on deny")
	}
	if len(recorder.events) < 3 {
		t.Fatalf("expected at least 3 events, got %d", len(recorder.events))
	}
}

func TestServiceHTTPAllowlist(t *testing.T) {
	dir := t.TempDir()
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{
				ID:           "allow-http",
				ActionType:   "net.http_request",
				Resource:     "url://example.com/**",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
				Obligations: map[string]any{
					"net_allowlist": []any{"example.com"},
				},
			},
		},
		Hash: "test",
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(dir, 32, 10)
	writer := executor.NewFSWriter(dir, 32)
	patcher := executor.NewPatchApplier(dir, 32)
	execRunner := executor.NewExecRunner(dir, 32)
	httpRunner := executor.NewHTTPRunner(32)
	httpRunner.SetClient(newTestHTTPClient("hello"))
	recorder := &recordSink{}
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), nil, nil, "local", func() time.Time { return time.Unix(0, 0) })

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act3",
		ActionType:    "net.http_request",
		Resource:      "url://example.com/path",
		Params:        []byte(`{"method":"GET"}`),
		TraceID:       "trace3",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	resp, err := svc.Process(act)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if resp.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow, got %s", resp.Decision)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if resp.Output == "" {
		t.Fatal("expected body output")
	}
}

func TestServiceExecRequiresAllowlist(t *testing.T) {
	dir := t.TempDir()
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{
				ID:           "allow-exec",
				ActionType:   "process.exec",
				Resource:     "file://workspace/**",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
			},
		},
		Hash: "test",
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(dir, 32, 10)
	writer := executor.NewFSWriter(dir, 32)
	patcher := executor.NewPatchApplier(dir, 32)
	execRunner := executor.NewExecRunner(dir, 32)
	httpRunner := executor.NewHTTPRunner(32)
	recorder := &recordSink{}
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), nil, nil, "local", func() time.Time { return time.Unix(0, 0) })

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act4",
		ActionType:    "process.exec",
		Resource:      "file://workspace/",
		Params:        []byte(`{"argv":["cmd","/c","echo","hi"],"cwd":"","env_allowlist_keys":[]}`),
		TraceID:       "trace4",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	resp, err := svc.Process(act)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if resp.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s", resp.Decision)
	}
	if resp.Reason != "exec_not_allowlisted" {
		t.Fatalf("expected exec_not_allowlisted, got %s", resp.Reason)
	}
}

func TestServiceSandboxRequired(t *testing.T) {
	dir := t.TempDir()
	bundle := policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{
			{
				ID:           "allow-write",
				ActionType:   "fs.write",
				Resource:     "file://workspace/**",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
				Obligations: map[string]any{
					"sandbox_mode": "container",
				},
			},
		},
		Hash: "test",
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(dir, 32, 10)
	writer := executor.NewFSWriter(dir, 32)
	patcher := executor.NewPatchApplier(dir, 32)
	execRunner := executor.NewExecRunner(dir, 32)
	httpRunner := executor.NewHTTPRunner(32)
	recorder := &recordSink{}
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), nil, nil, "local", func() time.Time { return time.Unix(0, 0) })

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act5",
		ActionType:    "fs.write",
		Resource:      "file://workspace/output.txt",
		Params:        []byte(`{"content":"data"}`),
		TraceID:       "trace5",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	resp, err := svc.Process(act)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if resp.Decision != policy.DecisionDeny {
		t.Fatalf("expected deny, got %s", resp.Decision)
	}
	if resp.Reason != "sandbox_required" {
		t.Fatalf("expected sandbox_required, got %s", resp.Reason)
	}
}

func TestServiceAuditIncludesAssuranceLevel(t *testing.T) {
	dir := t.TempDir()
	readmePath := filepath.Join(dir, "README.md")
	if err := os.WriteFile(readmePath, []byte("ok"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	bundle := policy.Bundle{
		Version: "v1",
		Hash:    "test",
		Rules: []policy.Rule{
			{ID: "allow-readme", ActionType: "fs.read", Resource: "file://workspace/README.md", Decision: policy.DecisionAllow},
		},
	}
	engine := policy.NewEngine(bundle)
	recorder := &recordSink{}
	svc := New(
		engine,
		executor.NewFSReader(dir, 32, 10),
		executor.NewFSWriter(dir, 32),
		executor.NewPatchApplier(dir, 32),
		executor.NewExecRunner(dir, 32),
		executor.NewHTTPRunner(32),
		recorder,
		redact.DefaultRedactor(),
		nil,
		nil,
		"local",
		func() time.Time { return time.Unix(0, 0) },
	)
	svc.SetAssuranceLevel("GUARDED")

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act6",
		ActionType:    "fs.read",
		Resource:      "file://workspace/README.md",
		Params:        []byte(`{}`),
		TraceID:       "trace6",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	if _, err := svc.Process(act); err != nil {
		t.Fatalf("process: %v", err)
	}
	foundDecision := false
	foundCompleted := false
	for _, event := range recorder.events {
		if event.AssuranceLevel != "GUARDED" {
			t.Fatalf("expected assurance level on event %s, got %q", event.EventType, event.AssuranceLevel)
		}
		if event.EventType == "action.decision" {
			foundDecision = true
		}
		if event.EventType == "action.completed" {
			foundCompleted = true
		}
	}
	if !foundDecision || !foundCompleted {
		t.Fatalf("expected decision and completed events, got %+v", recorder.events)
	}
}

func TestServiceAuditRecordsFinalRedirectResource(t *testing.T) {
	dir := t.TempDir()
	bundle := policy.Bundle{
		Version: "v1",
		Hash:    "test",
		Rules: []policy.Rule{
			{
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
			},
		},
	}
	engine := policy.NewEngine(bundle)
	recorder := &recordSink{}
	httpRunner := executor.NewHTTPRunner(32)
	httpRunner.SetClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Path {
			case "/start":
				return &http.Response{
					StatusCode: http.StatusFound,
					Header:     http.Header{"Location": []string{"https://example.com/final?token=secret"}},
					Body:       io.NopCloser(strings.NewReader("")),
					Request:    req,
				}, nil
			default:
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("ok")),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}
		}),
		CheckRedirect: nil,
	})
	svc := New(
		engine,
		executor.NewFSReader(dir, 32, 10),
		executor.NewFSWriter(dir, 32),
		executor.NewPatchApplier(dir, 32),
		executor.NewExecRunner(dir, 32),
		httpRunner,
		recorder,
		redact.DefaultRedactor(),
		nil,
		nil,
		"local",
		func() time.Time { return time.Unix(0, 0) },
	)

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "act7",
		ActionType:    "net.http_request",
		Resource:      "url://example.com/start",
		Params:        []byte(`{"method":"GET"}`),
		TraceID:       "trace7",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	if _, err := svc.Process(act); err != nil {
		t.Fatalf("process: %v", err)
	}
	found := false
	for _, event := range recorder.events {
		if event.EventType != "action.completed" {
			continue
		}
		found = true
		if event.ExecutorMetadata["final_resource"] != "url://example.com/final" {
			t.Fatalf("expected final_resource in executor metadata, got %+v", event.ExecutorMetadata)
		}
		if event.ExecutorMetadata["redirect_hops"] != 1 {
			t.Fatalf("expected redirect_hops=1, got %+v", event.ExecutorMetadata)
		}
	}
	if !found {
		t.Fatal("expected action.completed audit event")
	}
}

func TestServiceReadHonorsPerRuleOutputCaps(t *testing.T) {
	dir := t.TempDir()
	readmePath := filepath.Join(dir, "README.md")
	content := "line1\nline2\nline3\n"
	if err := os.WriteFile(readmePath, []byte(content), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	bundle := policy.Bundle{
		Version: "v1",
		Hash:    "test",
		Rules: []policy.Rule{
			{
				ID:         "allow-readme",
				ActionType: "fs.read",
				Resource:   "file://workspace/README.md",
				Decision:   policy.DecisionAllow,
				Obligations: map[string]any{
					"output_max_bytes": 5,
					"output_max_lines": 1,
				},
			},
		},
	}
	svc := New(
		policy.NewEngine(bundle),
		executor.NewFSReader(dir, 1024, 100),
		executor.NewFSWriter(dir, 1024),
		executor.NewPatchApplier(dir, 1024),
		executor.NewExecRunner(dir, 1024),
		executor.NewHTTPRunner(1024),
		&recordSink{},
		redact.DefaultRedactor(),
		nil,
		nil,
		"local",
		func() time.Time { return time.Unix(0, 0) },
	)

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "cap-read",
		ActionType:    "fs.read",
		Resource:      "file://workspace/README.md",
		Params:        []byte(`{}`),
		TraceID:       "trace-cap-read",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	resp, err := svc.Process(act)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if resp.Output != "line1" {
		t.Fatalf("expected capped output %q, got %q", "line1", resp.Output)
	}
	if !resp.Truncated {
		t.Fatal("expected truncation due to output caps")
	}
}

func TestServiceHTTPHonorsPerRuleOutputLineCaps(t *testing.T) {
	dir := t.TempDir()
	bundle := policy.Bundle{
		Version: "v1",
		Hash:    "test",
		Rules: []policy.Rule{
			{
				ID:           "allow-http",
				ActionType:   "net.http_request",
				Resource:     "url://example.com/**",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"dev"},
				Obligations: map[string]any{
					"net_allowlist":    []any{"example.com"},
					"output_max_lines": 1,
				},
			},
		},
	}
	httpRunner := executor.NewHTTPRunner(1024)
	httpRunner.SetClient(newTestHTTPClient("alpha\nbeta\ngamma"))
	svc := New(
		policy.NewEngine(bundle),
		executor.NewFSReader(dir, 1024, 100),
		executor.NewFSWriter(dir, 1024),
		executor.NewPatchApplier(dir, 1024),
		executor.NewExecRunner(dir, 1024),
		httpRunner,
		&recordSink{},
		redact.DefaultRedactor(),
		nil,
		nil,
		"local",
		func() time.Time { return time.Unix(0, 0) },
	)

	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "cap-http",
		ActionType:    "net.http_request",
		Resource:      "url://example.com/path",
		Params:        []byte(`{"method":"GET"}`),
		TraceID:       "trace-cap-http",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	resp, err := svc.Process(act)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if resp.Output != "alpha\n" {
		t.Fatalf("expected capped output %q, got %q", "alpha\n", resp.Output)
	}
	if !resp.Truncated {
		t.Fatal("expected truncation due to output caps")
	}
}

func TestApplyOutputObligationsCapsEachSurface(t *testing.T) {
	text, truncated := applyOutputObligations("abcdef\nsecond\n", map[string]any{
		"output_max_bytes": 6,
		"output_max_lines": 1,
	}, false)
	if text != "abcdef" {
		t.Fatalf("expected capped text %q, got %q", "abcdef", text)
	}
	if !truncated {
		t.Fatal("expected truncation")
	}
}

func newTestHTTPClient(body string) *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
