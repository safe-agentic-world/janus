package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/ratelimit"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/telemetry"
)

type mutableClock struct {
	now time.Time
}

func (c *mutableClock) Now() time.Time {
	return c.now
}

func (c *mutableClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

type rateLimitTelemetrySink struct {
	events  []telemetry.Event
	metrics []telemetry.Metric
}

func (s *rateLimitTelemetrySink) ExportEvent(event telemetry.Event) error {
	s.events = append(s.events, event)
	return nil
}

func (s *rateLimitTelemetrySink) ExportMetric(metric telemetry.Metric) error {
	s.metrics = append(s.metrics, metric)
	return nil
}

func TestServiceRateLimitBurstExactlyAtLimitAllows(t *testing.T) {
	clock := &mutableClock{now: time.Unix(100, 0)}
	svc, _, _ := newRateLimitTestService(t, clock, []ratelimit.Rule{{
		ID:              "limit-read-by-action",
		Scope:           ratelimit.ScopePrincipalAction,
		ActionType:      "fs.read",
		Burst:           2,
		RefillPerMinute: 60,
	}})

	for i := 0; i < 2; i++ {
		resp, err := svc.Process(rateLimitReadAction(t, "system", "act-burst-"+string(rune('a'+i))))
		if err != nil {
			t.Fatalf("process %d: %v", i, err)
		}
		if resp.Decision != policy.DecisionAllow {
			t.Fatalf("expected request %d to allow, got %+v", i, resp)
		}
	}
}

func TestServiceRateLimitAboveBurstDeniesWithAuditAndTelemetry(t *testing.T) {
	clock := &mutableClock{now: time.Unix(100, 0)}
	svc, recorder, telemetryRecorder := newRateLimitTestService(t, clock, []ratelimit.Rule{{
		ID:              "limit-read-by-action",
		Scope:           ratelimit.ScopePrincipalAction,
		ActionType:      "fs.read",
		Burst:           1,
		RefillPerMinute: 60,
	}})

	if resp, err := svc.Process(rateLimitReadAction(t, "system", "act-first")); err != nil || resp.Decision != policy.DecisionAllow {
		t.Fatalf("expected first request allow, got resp=%+v err=%v", resp, err)
	}
	resp, err := svc.Process(rateLimitReadAction(t, "system", "act-second"))
	if err != nil {
		t.Fatalf("rate-limited request returned error: %v", err)
	}
	if resp.Decision != policy.DecisionDeny || resp.Reason != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("expected structured rate limit deny, got %+v", resp)
	}
	completed := lastCompletedEvent(t, recorder.events)
	if completed.ResultClassification != "RATE_LIMIT_EXCEEDED" || completed.Decision != policy.DecisionDeny || completed.Reason != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("expected rate limit completed audit, got %+v", completed)
	}
	if got := completed.ExecutorMetadata["rate_limit_rule_id"]; got != "limit-read-by-action" {
		t.Fatalf("expected rate limit rule metadata, got %+v", completed.ExecutorMetadata)
	}
	if !hasRateLimitMetric(telemetryRecorder.metrics, "exceeded", "limit-read-by-action") {
		t.Fatalf("expected exceeded rate limit telemetry metric, got %+v", telemetryRecorder.metrics)
	}
}

func TestServiceRateLimitRefillsWithInjectedClock(t *testing.T) {
	clock := &mutableClock{now: time.Unix(100, 0)}
	svc, _, _ := newRateLimitTestService(t, clock, []ratelimit.Rule{{
		ID:              "limit-read-by-resource",
		Scope:           ratelimit.ScopePrincipalResource,
		Resource:        "file://workspace/README.md",
		Burst:           1,
		RefillPerMinute: 60,
	}})

	if resp, err := svc.Process(rateLimitReadAction(t, "system", "act-first")); err != nil || resp.Decision != policy.DecisionAllow {
		t.Fatalf("expected first request allow, got resp=%+v err=%v", resp, err)
	}
	if resp, err := svc.Process(rateLimitReadAction(t, "system", "act-denied")); err != nil || resp.Reason != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("expected second request deny, got resp=%+v err=%v", resp, err)
	}
	clock.Advance(time.Second)
	resp, err := svc.Process(rateLimitReadAction(t, "system", "act-refill"))
	if err != nil {
		t.Fatalf("process after refill: %v", err)
	}
	if resp.Decision != policy.DecisionAllow {
		t.Fatalf("expected refill to allow, got %+v", resp)
	}
}

func TestServiceRateLimitPerPrincipalIsolation(t *testing.T) {
	clock := &mutableClock{now: time.Unix(100, 0)}
	svc, _, _ := newRateLimitTestService(t, clock, []ratelimit.Rule{{
		ID:              "limit-read-by-principal-resource",
		Scope:           ratelimit.ScopePrincipalResource,
		Resource:        "file://workspace/README.md",
		Burst:           1,
		RefillPerMinute: 60,
	}})

	if resp, err := svc.Process(rateLimitReadAction(t, "alice", "act-alice-1")); err != nil || resp.Decision != policy.DecisionAllow {
		t.Fatalf("expected alice first request allow, got resp=%+v err=%v", resp, err)
	}
	if resp, err := svc.Process(rateLimitReadAction(t, "alice", "act-alice-2")); err != nil || resp.Reason != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("expected alice second request deny, got resp=%+v err=%v", resp, err)
	}
	resp, err := svc.Process(rateLimitReadAction(t, "bob", "act-bob-1"))
	if err != nil {
		t.Fatalf("bob request: %v", err)
	}
	if resp.Decision != policy.DecisionAllow {
		t.Fatalf("expected bob to have isolated bucket, got %+v", resp)
	}
}

func TestServiceRateLimitDeterminismAcrossRuns(t *testing.T) {
	run := func() []string {
		clock := &mutableClock{now: time.Unix(100, 0)}
		svc, _, _ := newRateLimitTestService(t, clock, []ratelimit.Rule{{
			ID:              "global-read-limit",
			Scope:           ratelimit.ScopeGlobalTool,
			ActionType:      "fs.read",
			Burst:           2,
			RefillPerMinute: 60,
		}})
		out := make([]string, 0, 4)
		for i := 0; i < 4; i++ {
			if i == 3 {
				clock.Advance(time.Second)
			}
			resp, err := svc.Process(rateLimitReadAction(t, "system", "act-determinism-"+string(rune('a'+i))))
			if err != nil {
				t.Fatalf("process determinism request %d: %v", i, err)
			}
			out = append(out, resp.Decision+":"+resp.Reason)
		}
		return out
	}
	first := run()
	second := run()
	if len(first) != len(second) {
		t.Fatalf("unexpected lengths: %v vs %v", first, second)
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("expected deterministic decisions, got %v vs %v", first, second)
		}
	}
}

func newRateLimitTestService(t *testing.T, clock *mutableClock, rules []ratelimit.Rule) (*Service, *recordSink, *rateLimitTelemetrySink) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	engine := policy.NewEngine(policy.Bundle{
		Version: "v1",
		Rules: []policy.Rule{{
			ID:         "allow-readme",
			ActionType: "fs.read",
			Resource:   "file://workspace/README.md",
			Decision:   policy.DecisionAllow,
		}},
		Hash: "bundle-rate-limit-test",
	})
	recorder := &recordSink{}
	telemetryRecorder := &rateLimitTelemetrySink{}
	limiter, err := ratelimit.New(ratelimit.Config{
		Enabled:    true,
		EvictAfter: time.Hour,
		Rules:      rules,
		Now:        clock.Now,
	})
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	reader := executor.NewFSReader(dir, 1024, 20)
	writer := executor.NewFSWriter(dir, 1024)
	patcher := executor.NewPatchApplier(dir, 1024)
	execRunner := executor.NewExecRunner(dir, 1024)
	httpRunner := executor.NewHTTPRunner(1024)
	svc := New(engine, reader, writer, patcher, execRunner, httpRunner, recorder, redact.DefaultRedactor(), nil, nil, "local", clock.Now)
	svc.SetRateLimiter(limiter)
	svc.SetTelemetry(telemetry.NewEmitter(telemetryRecorder))
	return svc, recorder, telemetryRecorder
}

func rateLimitReadAction(t *testing.T, principal, actionID string) action.Action {
	t.Helper()
	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      actionID,
		ActionType:    "fs.read",
		Resource:      "file://workspace/README.md",
		Params:        []byte(`{}`),
		TraceID:       "trace-" + actionID,
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   principal,
		Agent:       "nomos",
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	return act
}

func lastCompletedEvent(t *testing.T, events []audit.Event) audit.Event {
	t.Helper()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].EventType == "action.completed" {
			return events[i]
		}
	}
	t.Fatalf("missing action.completed event in %+v", events)
	return audit.Event{}
}

func hasRateLimitMetric(metrics []telemetry.Metric, result, ruleID string) bool {
	for _, metric := range metrics {
		if metric.Name != "nomos.rate_limits" {
			continue
		}
		if metric.Attributes["result"] == result && metric.Attributes["rule_id"] == ruleID {
			return true
		}
	}
	return false
}
