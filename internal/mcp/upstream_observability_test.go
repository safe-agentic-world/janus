package mcp

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/telemetry"
)

type upstreamObservabilitySink struct {
	events  []telemetry.Event
	metrics []telemetry.Metric
}

func (s *upstreamObservabilitySink) ExportEvent(event telemetry.Event) error {
	s.events = append(s.events, event)
	return nil
}

func (s *upstreamObservabilitySink) ExportMetric(metric telemetry.Metric) error {
	s.metrics = append(s.metrics, metric)
	return nil
}

type fakeUpstreamTransport struct {
	result any
	err    error
	done   chan struct{}
}

func newFakeUpstreamTransport(result any, err error) *fakeUpstreamTransport {
	return &fakeUpstreamTransport{result: result, err: err, done: make(chan struct{})}
}

func (f *fakeUpstreamTransport) callMethod(context.Context, time.Duration, string, map[string]any) (any, error) {
	return f.result, f.err
}

func (f *fakeUpstreamTransport) setRequestHandler(upstreamRequestHandler) {}

func (f *fakeUpstreamTransport) isClosed() bool { return false }

func (f *fakeUpstreamTransport) close() {
	select {
	case <-f.done:
	default:
		close(f.done)
	}
}

func (f *fakeUpstreamTransport) doneCh() <-chan struct{} { return f.done }

func (f *fakeUpstreamTransport) envShapeHash() string { return "shape" }

func TestUpstreamObservabilityEmitsMetricsPerOutcomeClass(t *testing.T) {
	sink := &upstreamObservabilitySink{}
	session := newObservableTestSession(t, sink, nil)
	session.conn = newFakeUpstreamTransport(map[string]any{"tools": []any{}}, nil)

	if _, err := session.callWithRequests(context.Background(), "tools/list", map[string]any{}, nil); err != nil {
		t.Fatalf("success call: %v", err)
	}
	session.conn = newFakeUpstreamTransport(nil, errUpstreamTimeout)
	if _, err := session.callWithRequests(context.Background(), "tools/list", map[string]any{}, nil); !errors.Is(err, errUpstreamTimeout) {
		t.Fatalf("expected timeout error, got %v", err)
	}

	if !hasUpstreamMetric(sink.metrics, upstreamMetricRequests, "success", upstreamFailureNone) {
		t.Fatalf("missing success request metric: %+v", sink.metrics)
	}
	if !hasUpstreamMetric(sink.metrics, upstreamMetricRequests, "error", upstreamFailureTimeout) {
		t.Fatalf("missing timeout request metric: %+v", sink.metrics)
	}
	if !hasUpstreamMetricKind(sink.metrics, upstreamMetricLatencyMS, "histogram") {
		t.Fatalf("missing latency histogram metric: %+v", sink.metrics)
	}
}

func TestUpstreamObservabilityBoundsLabelCardinality(t *testing.T) {
	labels := upstreamTelemetryLabels(UpstreamServerConfig{
		Name:      strings.Repeat("A", 200) + " !@#$",
		Transport: "streamable_http",
	}, "unbounded/custom/method/"+strings.Repeat("x", 200), errors.New("raw transport failure"))
	if got := labels["method"]; got != "other" {
		t.Fatalf("expected unrecognized method to collapse to other, got %q", got)
	}
	for key, value := range labels {
		if len(value) > maxUpstreamTelemetryLabelLen {
			t.Fatalf("label %s exceeds cap: len=%d value=%q", key, len(value), value)
		}
	}
	if got := boundedTelemetryLabel(strings.Repeat("字", 80)); len(got) > maxUpstreamTelemetryLabelLen {
		t.Fatalf("unicode label exceeds cap: len=%d value=%q", len(got), got)
	}
	sessionID := nextUpstreamSessionID(strings.Repeat("retail", 40))
	if len(sessionID) > maxUpstreamTelemetryLabelLen {
		t.Fatalf("session id exceeds cap: len=%d value=%q", len(sessionID), sessionID)
	}
	if !strings.HasPrefix(sessionID, "upstream-retail") {
		t.Fatalf("session id lost bounded server prefix: %q", sessionID)
	}
}

func TestUpstreamBreakerStateGaugeIsEmitted(t *testing.T) {
	sink := &upstreamObservabilitySink{}
	breaker := newUpstreamBreaker("retail", testBreakerConfig(), time.Now, telemetry.NewEmitter(sink))
	if !hasGaugeState(sink.metrics, upstreamBreakerClosed) {
		t.Fatalf("expected initial closed breaker gauge, got %+v", sink.metrics)
	}
	for i := 0; i < 2; i++ {
		permit, err := breaker.beforeCall()
		if err != nil {
			t.Fatalf("before call: %v", err)
		}
		breaker.afterCall(permit, errors.New("transport reset"))
	}
	if !hasGaugeState(sink.metrics, upstreamBreakerOpen) {
		t.Fatalf("expected open breaker gauge, got %+v", sink.metrics)
	}
}

func TestUpstreamStructuredLogsExcludeRawPayloads(t *testing.T) {
	var logs bytes.Buffer
	sink := &upstreamObservabilitySink{}
	logger, err := newRuntimeLogger(RuntimeOptions{
		LogLevel:  "debug",
		LogFormat: "json",
		ErrWriter: &logs,
	})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	session := newObservableTestSession(t, sink, logger)
	session.conn = newFakeUpstreamTransport(map[string]any{"content": []any{}, "isError": false}, nil)
	_, err = session.callWithRequests(context.Background(), "tools/call", map[string]any{
		"authorization": "secret-raw-argument",
	}, nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	got := logs.String()
	if strings.Contains(got, "secret-raw-argument") {
		t.Fatalf("structured logs leaked raw payload: %s", got)
	}
	for _, want := range []string{`"event":"mcp.upstream.request"`, `"upstream_server":"retail"`, `"action_type":"mcp.call"`, `"outcome":"success"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("structured log missing %s: %s", want, got)
		}
	}
}

func newObservableTestSession(t *testing.T, sink *upstreamObservabilitySink, logger *runtimeLogger) *upstreamSession {
	t.Helper()
	return newUpstreamSession(UpstreamServerConfig{
		Name:             "retail",
		Transport:        "stdio",
		BreakerEnabled:   true,
		BreakerThreshold: 2,
		BreakerWindow:    time.Minute,
		BreakerOpenTime:  time.Minute,
	}, logger, nil, time.Now, telemetry.NewEmitter(sink), identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, nil, nil)
}

func hasUpstreamMetric(metrics []telemetry.Metric, name, outcome, errorClass string) bool {
	for _, metric := range metrics {
		if metric.Name != name {
			continue
		}
		if metric.Attributes["outcome"] == outcome && metric.Attributes["error_class"] == errorClass {
			return true
		}
	}
	return false
}

func hasUpstreamMetricKind(metrics []telemetry.Metric, name, kind string) bool {
	for _, metric := range metrics {
		if metric.Name == name && metric.Kind == kind {
			return true
		}
	}
	return false
}

func hasGaugeState(metrics []telemetry.Metric, state string) bool {
	for _, metric := range metrics {
		if metric.Name == upstreamMetricBreakerState && metric.Attributes["state"] == state {
			return true
		}
	}
	return false
}
