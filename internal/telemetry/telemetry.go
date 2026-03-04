package telemetry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/safe-agentic-world/nomos/internal/redact"
)

type Config struct {
	Enabled bool   `json:"enabled"`
	Sink    string `json:"sink"`
}

type TraceContext struct {
	Traceparent string
	Tracestate  string
}

type Event struct {
	SignalType  string         `json:"signal_type"`
	EventName   string         `json:"event_name"`
	TraceID     string         `json:"trace_id"`
	Correlation string         `json:"correlation_id"`
	Traceparent string         `json:"traceparent,omitempty"`
	Tracestate  string         `json:"tracestate,omitempty"`
	Status      string         `json:"status,omitempty"`
	Attributes  map[string]any `json:"attributes,omitempty"`
}

type Metric struct {
	SignalType string            `json:"signal_type"`
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	Value      int64             `json:"value"`
	TraceID    string            `json:"trace_id,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type Exporter interface {
	ExportEvent(Event) error
	ExportMetric(Metric) error
}

type Emitter struct {
	exporter Exporter
}

func NewEmitter(exporter Exporter) *Emitter {
	return &Emitter{exporter: exporter}
}

func (e *Emitter) Enabled() bool {
	return e != nil && e.exporter != nil
}

func (e *Emitter) Event(event Event) {
	if e == nil || e.exporter == nil {
		return
	}
	_ = e.exporter.ExportEvent(event)
}

func (e *Emitter) Metric(metric Metric) {
	if e == nil || e.exporter == nil {
		return
	}
	_ = e.exporter.ExportMetric(metric)
}

func ParseTraceContext(header http.Header) TraceContext {
	if header == nil {
		return TraceContext{}
	}
	traceparent := strings.TrimSpace(header.Get("traceparent"))
	if !validTraceparent(traceparent) {
		traceparent = ""
	}
	tracestate := strings.TrimSpace(header.Get("tracestate"))
	if traceparent == "" {
		tracestate = ""
	}
	return TraceContext{
		Traceparent: traceparent,
		Tracestate:  tracestate,
	}
}

func PropagateTraceContext(w http.ResponseWriter, tc TraceContext) {
	if w == nil {
		return
	}
	if tc.Traceparent != "" {
		w.Header().Set("Traceparent", tc.Traceparent)
	}
	if tc.Tracestate != "" {
		w.Header().Set("Tracestate", tc.Tracestate)
	}
}

func NewExporter(cfg Config, redactor *redact.Redactor) (Exporter, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if redactor == nil {
		return nil, errors.New("telemetry redactor is required")
	}
	sink := strings.TrimSpace(cfg.Sink)
	if sink == "" {
		sink = "stdout"
	}
	switch sink {
	case "stdout":
		return &writerExporter{out: os.Stdout, redactor: redactor}, nil
	case "stderr":
		return &writerExporter{out: os.Stderr, redactor: redactor}, nil
	}
	if strings.HasPrefix(sink, "otlp:") {
		baseURL := strings.TrimSpace(strings.TrimPrefix(sink, "otlp:"))
		if baseURL == "" {
			return nil, errors.New("telemetry otlp endpoint is required")
		}
		return &otlpHTTPExporter{
			baseURL:  strings.TrimRight(baseURL, "/"),
			client:   &http.Client{Timeout: 2 * time.Second},
			redactor: redactor,
		}, nil
	}
	return nil, errors.New("unsupported telemetry sink")
}

type writerExporter struct {
	out      io.Writer
	redactor *redact.Redactor
	mu       sync.Mutex
}

func (w *writerExporter) ExportEvent(event Event) error {
	return w.writeJSON(event)
}

func (w *writerExporter) ExportMetric(metric Metric) error {
	return w.writeJSON(metric)
}

func (w *writerExporter) writeJSON(value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	redacted := w.redactor.RedactBytes(data)
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err = w.out.Write(append(redacted, '\n'))
	return err
}

type otlpHTTPExporter struct {
	baseURL  string
	client   *http.Client
	redactor *redact.Redactor
}

func (o *otlpHTTPExporter) ExportEvent(event Event) error {
	safe := sanitizeEvent(o.redactor, event)
	if err := o.post("/v1/traces", otlpTracePayload(safe)); err != nil {
		return err
	}
	return o.post("/v1/logs", otlpLogPayload(safe))
}

func (o *otlpHTTPExporter) ExportMetric(metric Metric) error {
	return o.post("/v1/metrics", otlpMetricPayload(sanitizeMetric(o.redactor, metric)))
}

func (o *otlpHTTPExporter) post(path string, payload map[string]any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, o.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("otlp exporter request failed")
	}
	return nil
}

func sanitizeEvent(redactor *redact.Redactor, event Event) Event {
	event.SignalType = redactor.RedactText(event.SignalType)
	event.EventName = redactor.RedactText(event.EventName)
	event.TraceID = redactor.RedactText(event.TraceID)
	event.Correlation = redactor.RedactText(event.Correlation)
	event.Traceparent = redactor.RedactText(event.Traceparent)
	event.Tracestate = redactor.RedactText(event.Tracestate)
	event.Status = redactor.RedactText(event.Status)
	if event.Attributes != nil {
		event.Attributes = sanitizeMap(redactor, event.Attributes)
	}
	return event
}

func sanitizeMetric(redactor *redact.Redactor, metric Metric) Metric {
	metric.SignalType = redactor.RedactText(metric.SignalType)
	metric.Name = redactor.RedactText(metric.Name)
	metric.Kind = redactor.RedactText(metric.Kind)
	metric.TraceID = redactor.RedactText(metric.TraceID)
	if metric.Attributes != nil {
		safe := make(map[string]string, len(metric.Attributes))
		for key, value := range metric.Attributes {
			safe[key] = redactor.RedactText(value)
		}
		metric.Attributes = safe
	}
	return metric
}

func sanitizeMap(redactor *redact.Redactor, input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = sanitizeValue(redactor, value)
	}
	return out
}

func sanitizeValue(redactor *redact.Redactor, value any) any {
	switch typed := value.(type) {
	case string:
		return redactor.RedactText(typed)
	case []string:
		out := make([]string, len(typed))
		for i, v := range typed {
			out[i] = redactor.RedactText(v)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, v := range typed {
			out[i] = sanitizeValue(redactor, v)
		}
		return out
	case map[string]any:
		return sanitizeMap(redactor, typed)
	default:
		return value
	}
}

func otlpTracePayload(event Event) map[string]any {
	traceID := stableTraceID(event.TraceID)
	spanID := stableSpanID(event.TraceID, event.EventName)
	start := time.Now().UTC().UnixNano()
	attrs := otlpAttributes(event.Attributes)
	attrs = append(attrs, otlpStringAttr("nomos.signal_type", event.SignalType))
	attrs = append(attrs, otlpStringAttr("nomos.correlation_id", event.Correlation))
	if event.Traceparent != "" {
		attrs = append(attrs, otlpStringAttr("w3c.traceparent", event.Traceparent))
	}
	if event.Tracestate != "" {
		attrs = append(attrs, otlpStringAttr("w3c.tracestate", event.Tracestate))
	}
	return map[string]any{
		"resourceSpans": []any{
			map[string]any{
				"resource": map[string]any{
					"attributes": []any{otlpStringAttr("service.name", "nomos")},
				},
				"scopeSpans": []any{
					map[string]any{
						"scope": map[string]any{"name": "nomos.telemetry"},
						"spans": []any{
							map[string]any{
								"traceId":           traceID,
								"spanId":            spanID,
								"name":              event.EventName,
								"startTimeUnixNano": start,
								"endTimeUnixNano":   start,
								"attributes":        attrs,
								"status": map[string]any{
									"message": event.Status,
								},
							},
						},
					},
				},
			},
		},
	}
}

func otlpLogPayload(event Event) map[string]any {
	record := map[string]any{
		"timeUnixNano": uint64(time.Now().UTC().UnixNano()),
		"body": map[string]any{
			"stringValue": event.EventName,
		},
		"attributes": append(otlpAttributes(event.Attributes),
			otlpStringAttr("nomos.trace_id", event.TraceID),
			otlpStringAttr("nomos.correlation_id", event.Correlation),
		),
	}
	return map[string]any{
		"resourceLogs": []any{
			map[string]any{
				"resource": map[string]any{
					"attributes": []any{otlpStringAttr("service.name", "nomos")},
				},
				"scopeLogs": []any{
					map[string]any{
						"scope":      map[string]any{"name": "nomos.telemetry"},
						"logRecords": []any{record},
					},
				},
			},
		},
	}
}

func otlpMetricPayload(metric Metric) map[string]any {
	dataPoint := map[string]any{
		"asInt":             metric.Value,
		"timeUnixNano":      uint64(time.Now().UTC().UnixNano()),
		"attributes":        otlpStringMapAttributes(metric.Attributes),
		"startTimeUnixNano": uint64(time.Now().UTC().UnixNano()),
	}
	metricBody := map[string]any{
		"name": metric.Name,
	}
	switch strings.TrimSpace(metric.Kind) {
	case "counter":
		metricBody["sum"] = map[string]any{
			"aggregationTemporality": 2,
			"isMonotonic":            true,
			"dataPoints":             []any{dataPoint},
		}
	default:
		metricBody["gauge"] = map[string]any{
			"dataPoints": []any{dataPoint},
		}
	}
	return map[string]any{
		"resourceMetrics": []any{
			map[string]any{
				"resource": map[string]any{
					"attributes": []any{otlpStringAttr("service.name", "nomos")},
				},
				"scopeMetrics": []any{
					map[string]any{
						"scope":   map[string]any{"name": "nomos.telemetry"},
						"metrics": []any{metricBody},
					},
				},
			},
		},
	}
}

func otlpAttributes(input map[string]any) []any {
	if len(input) == 0 {
		return []any{}
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sortStrings(keys)
	out := make([]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, map[string]any{
			"key": key,
			"value": map[string]any{
				"stringValue": stringifyOTLPValue(input[key]),
			},
		})
	}
	return out
}

func otlpStringMapAttributes(input map[string]string) []any {
	if len(input) == 0 {
		return []any{}
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sortStrings(keys)
	out := make([]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, otlpStringAttr(key, input[key]))
	}
	return out
}

func otlpStringAttr(key, value string) map[string]any {
	return map[string]any{
		"key": key,
		"value": map[string]any{
			"stringValue": value,
		},
	}
}

func stringifyOTLPValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []string:
		return strings.Join(typed, ",")
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(data)
	}
}

func stableTraceID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:16])
}

func stableSpanID(traceID, eventName string) string {
	sum := sha256.Sum256([]byte(traceID + ":" + eventName))
	return hex.EncodeToString(sum[:8])
}

func sortStrings(values []string) {
	for i := 0; i < len(values); i++ {
		for j := i + 1; j < len(values); j++ {
			if values[j] < values[i] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
}

func validTraceparent(value string) bool {
	if len(value) != 55 {
		return false
	}
	for _, idx := range []int{2, 35, 52} {
		if value[idx] != '-' {
			return false
		}
	}
	for i, r := range value {
		if i == 2 || i == 35 || i == 52 {
			continue
		}
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}
