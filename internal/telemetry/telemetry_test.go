package telemetry

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/redact"
)

func TestParseAndPropagateTraceContext(t *testing.T) {
	headers := make(http.Header)
	headers.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	headers.Set("tracestate", "vendor=value")
	tc := ParseTraceContext(headers)
	if tc.Traceparent == "" || tc.Tracestate == "" {
		t.Fatalf("expected valid trace context, got %+v", tc)
	}

	w := httptest.NewRecorder()
	PropagateTraceContext(w, tc)
	if got := w.Header().Get("Traceparent"); got != tc.Traceparent {
		t.Fatalf("expected propagated traceparent, got %q", got)
	}
	if got := w.Header().Get("Tracestate"); got != tc.Tracestate {
		t.Fatalf("expected propagated tracestate, got %q", got)
	}
}

func TestParseTraceContextRejectsInvalidTraceparent(t *testing.T) {
	headers := make(http.Header)
	headers.Set("traceparent", "invalid")
	headers.Set("tracestate", "vendor=value")
	tc := ParseTraceContext(headers)
	if tc.Traceparent != "" || tc.Tracestate != "" {
		t.Fatalf("expected invalid trace context to be dropped, got %+v", tc)
	}
}

func TestWriterExporterRedactsSecrets(t *testing.T) {
	var out bytes.Buffer
	exporter := &writerExporter{out: &out, redactor: redact.DefaultRedactor()}
	err := exporter.ExportEvent(Event{
		SignalType:  "trace",
		EventName:   "request.lifecycle",
		TraceID:     "trace1",
		Correlation: "trace1",
		Attributes: map[string]any{
			"authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNTE2MjM5MDIyfQ.sgnaturetoken",
		},
	})
	if err != nil {
		t.Fatalf("export event: %v", err)
	}
	got := out.String()
	if strings.Contains(got, "eyJhbGciOiJIUzI1Ni") {
		t.Fatalf("expected redacted telemetry output, got %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected redaction marker, got %q", got)
	}
}

func TestOTLPExporterPostsRedactedSignals(t *testing.T) {
	requests := map[string][]map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		requests[r.URL.Path] = append(requests[r.URL.Path], body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	exporter, err := NewExporter(Config{
		Enabled: true,
		Sink:    "otlp:" + server.URL,
	}, redact.DefaultRedactor())
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}

	err = exporter.ExportEvent(Event{
		SignalType:  "trace",
		EventName:   "request.lifecycle",
		TraceID:     "trace1",
		Correlation: "trace1",
		Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		Attributes: map[string]any{
			"authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNTE2MjM5MDIyfQ.sgnaturetoken",
		},
	})
	if err != nil {
		t.Fatalf("export event: %v", err)
	}
	err = exporter.ExportMetric(Metric{
		SignalType: "metric",
		Name:       "nomos.decisions",
		Kind:       "counter",
		Value:      1,
		TraceID:    "trace1",
		Attributes: map[string]string{"result": "allow"},
	})
	if err != nil {
		t.Fatalf("export metric: %v", err)
	}

	if len(requests["/v1/traces"]) != 1 {
		t.Fatalf("expected 1 trace export, got %d", len(requests["/v1/traces"]))
	}
	if len(requests["/v1/logs"]) != 1 {
		t.Fatalf("expected 1 log export, got %d", len(requests["/v1/logs"]))
	}
	if len(requests["/v1/metrics"]) != 1 {
		t.Fatalf("expected 1 metric export, got %d", len(requests["/v1/metrics"]))
	}
	tracePayload := requests["/v1/traces"][0]
	traceJSON, err := json.Marshal(tracePayload)
	if err != nil {
		t.Fatalf("marshal trace payload: %v", err)
	}
	if strings.Contains(string(traceJSON), "eyJhbGciOiJIUzI1Ni") {
		t.Fatalf("expected redacted otlp payload, got %s", string(traceJSON))
	}
	if !strings.Contains(string(traceJSON), "[REDACTED]") {
		t.Fatalf("expected redaction marker in otlp payload, got %s", string(traceJSON))
	}
}

func TestOTLPExporterPostsHistogramMetrics(t *testing.T) {
	requests := map[string][]map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		requests[r.URL.Path] = append(requests[r.URL.Path], body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	exporter, err := NewExporter(Config{
		Enabled: true,
		Sink:    "otlp:" + server.URL,
	}, redact.DefaultRedactor())
	if err != nil {
		t.Fatalf("new exporter: %v", err)
	}

	err = exporter.ExportMetric(Metric{
		SignalType: "metric",
		Name:       "nomos.mcp.upstream.latency_ms",
		Kind:       "histogram",
		Value:      42,
		TraceID:    "trace-histogram",
		Attributes: map[string]string{"upstream_server": "retail"},
	})
	if err != nil {
		t.Fatalf("export histogram metric: %v", err)
	}
	if len(requests["/v1/metrics"]) != 1 {
		t.Fatalf("expected 1 metric export, got %d", len(requests["/v1/metrics"]))
	}
	body, err := json.Marshal(requests["/v1/metrics"][0])
	if err != nil {
		t.Fatalf("marshal metric body: %v", err)
	}
	if !strings.Contains(string(body), `"histogram"`) {
		t.Fatalf("expected histogram OTLP payload, got %s", string(body))
	}
	if !strings.Contains(string(body), `"sum":42`) {
		t.Fatalf("expected histogram sample sum, got %s", string(body))
	}
}
