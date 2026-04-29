package mcp

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/safe-agentic-world/nomos/internal/telemetry"
)

const (
	upstreamMetricRequests     = "nomos.mcp.upstream.requests"
	upstreamMetricLatencyMS    = "nomos.mcp.upstream.latency_ms"
	upstreamMetricBreakerState = "nomos.mcp.upstream.breaker_state"

	upstreamEventRequest          = "mcp.upstream.request"
	upstreamEventSessionLifecycle = "mcp.upstream.session.lifecycle"

	maxUpstreamTelemetryLabelLen = 64
)

var upstreamSessionSeq atomic.Uint64

func nextUpstreamSessionID(server string) string {
	n := upstreamSessionSeq.Add(1)
	suffix := fmt.Sprintf("-%d", n)
	prefix := "upstream-"
	serverLabel := boundedTelemetryLabel(server)
	available := maxUpstreamTelemetryLabelLen - len(prefix) - len(suffix)
	if available < 1 {
		available = 1
	}
	if len(serverLabel) > available {
		serverLabel = strings.Trim(serverLabel[:available], "._-/")
		if serverLabel == "" {
			serverLabel = "unknown"
		}
	}
	return prefix + serverLabel + suffix
}

func boundedTelemetryLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range value {
		if b.Len() >= maxUpstreamTelemetryLabelLen {
			break
		}
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteByte(byte(r + ('a' - 'A')))
		case r >= 'a' && r <= 'z':
			b.WriteByte(byte(r))
		case r >= '0' && r <= '9':
			b.WriteByte(byte(r))
		case r == '-', r == '_', r == '.', r == '/':
			b.WriteByte(byte(r))
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "._-/")
	if out == "" {
		return "unknown"
	}
	return out
}

func upstreamTelemetryMethod(method string) string {
	switch strings.TrimSpace(method) {
	case "initialize":
		return "initialize"
	case "tools/list":
		return "tools.list"
	case "tools/call":
		return "tools.call"
	case "resources/list":
		return "resources.list"
	case "resources/read":
		return "resources.read"
	case "prompts/list":
		return "prompts.list"
	case "prompts/get":
		return "prompts.get"
	case "completion/complete":
		return "completion.complete"
	case "sampling/createMessage":
		return "sampling.create_message"
	default:
		return "other"
	}
}

func upstreamTelemetryActionType(method string) string {
	switch upstreamTelemetryMethod(method) {
	case "tools.call":
		return "mcp.call"
	case "resources.list", "resources.read":
		return "mcp.resource_read"
	case "prompts.list", "prompts.get":
		return "mcp.prompt_get"
	case "completion.complete":
		return "mcp.completion"
	case "sampling.create_message":
		return "mcp.sample"
	default:
		return "mcp.upstream_rpc"
	}
}

func upstreamTelemetryOutcome(err error) string {
	if err == nil {
		return "success"
	}
	if errors.Is(err, errUpstreamUnavailable) {
		return "blocked"
	}
	return "error"
}

func upstreamTelemetryErrorClass(err error) string {
	if err == nil {
		return upstreamFailureNone
	}
	if errors.Is(err, errUpstreamUnavailable) {
		return "breaker_open"
	}
	kind, _ := classifyUpstreamBreakerFailure(err)
	return kind
}

func upstreamBreakerStateValue(state string) int64 {
	switch state {
	case upstreamBreakerClosed:
		return 1
	case upstreamBreakerHalfOpen:
		return 2
	case upstreamBreakerOpen:
		return 3
	default:
		return 0
	}
}

func upstreamTelemetryLabels(config UpstreamServerConfig, method string, err error) map[string]string {
	return map[string]string{
		"upstream_server": boundedTelemetryLabel(config.Name),
		"transport":       boundedTelemetryLabel(config.Transport),
		"method":          upstreamTelemetryMethod(method),
		"action_type":     upstreamTelemetryActionType(method),
		"outcome":         upstreamTelemetryOutcome(err),
		"error_class":     upstreamTelemetryErrorClass(err),
	}
}

func emitUpstreamRequestObservability(emitter *telemetry.Emitter, logger *runtimeLogger, config UpstreamServerConfig, sessionID string, method string, elapsed time.Duration, err error) {
	labels := upstreamTelemetryLabels(config, method, err)
	traceID := "mcp_upstream_" + labels["upstream_server"]
	latencyMS := maxInt64(0, elapsed.Milliseconds())
	if emitter != nil && emitter.Enabled() {
		emitter.Metric(telemetry.Metric{
			SignalType: "metric",
			Name:       upstreamMetricRequests,
			Kind:       "counter",
			Value:      1,
			TraceID:    traceID,
			Attributes: labels,
		})
		emitter.Metric(telemetry.Metric{
			SignalType: "metric",
			Name:       upstreamMetricLatencyMS,
			Kind:       "histogram",
			Value:      latencyMS,
			TraceID:    traceID,
			Attributes: labels,
		})
		emitter.Event(telemetry.Event{
			SignalType:  "trace",
			EventName:   upstreamEventRequest,
			TraceID:     traceID,
			Correlation: traceID,
			Status:      labels["outcome"],
			Attributes: map[string]any{
				"upstream_server":     labels["upstream_server"],
				"upstream_session_id": boundedTelemetryLabel(sessionID),
				"transport":           labels["transport"],
				"method":              labels["method"],
				"action_type":         labels["action_type"],
				"outcome":             labels["outcome"],
				"error_class":         labels["error_class"],
				"latency_ms":          latencyMS,
			},
		})
	}
	level := logLevelDebug
	if err != nil {
		level = logLevelWarn
	}
	if logger != nil {
		logger.Structured(level, upstreamEventRequest, map[string]any{
			"upstream_server":     labels["upstream_server"],
			"upstream_session_id": boundedTelemetryLabel(sessionID),
			"transport":           labels["transport"],
			"stage":               "request",
			"method":              labels["method"],
			"action_type":         labels["action_type"],
			"outcome":             labels["outcome"],
			"error_class":         labels["error_class"],
			"latency_ms":          latencyMS,
		})
	}
}

func emitUpstreamLifecycleObservability(emitter *telemetry.Emitter, logger *runtimeLogger, config UpstreamServerConfig, sessionID, stage, outcome string, err error) {
	attrs := map[string]any{
		"upstream_server":     boundedTelemetryLabel(config.Name),
		"upstream_session_id": boundedTelemetryLabel(sessionID),
		"transport":           boundedTelemetryLabel(config.Transport),
		"stage":               boundedTelemetryLabel(stage),
		"outcome":             boundedTelemetryLabel(outcome),
		"error_class":         upstreamTelemetryErrorClass(err),
	}
	traceID := "mcp_upstream_" + attrs["upstream_server"].(string)
	if emitter != nil && emitter.Enabled() {
		emitter.Event(telemetry.Event{
			SignalType:  "trace",
			EventName:   upstreamEventSessionLifecycle,
			TraceID:     traceID,
			Correlation: traceID,
			Status:      attrs["outcome"].(string),
			Attributes:  attrs,
		})
	}
	level := logLevelInfo
	if err != nil {
		level = logLevelWarn
	}
	if logger != nil {
		logger.Structured(level, upstreamEventSessionLifecycle, attrs)
	}
}

func emitUpstreamBreakerGauge(emitter *telemetry.Emitter, server, state string, enabled bool) {
	if emitter == nil || !emitter.Enabled() {
		return
	}
	labels := map[string]string{
		"upstream_server": boundedTelemetryLabel(server),
		"state":           boundedTelemetryLabel(state),
		"enabled":         fmt.Sprintf("%t", enabled),
	}
	emitter.Metric(telemetry.Metric{
		SignalType: "metric",
		Name:       upstreamMetricBreakerState,
		Kind:       "gauge",
		Value:      upstreamBreakerStateValue(state),
		TraceID:    "mcp_upstream_" + labels["upstream_server"],
		Attributes: labels,
	})
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}
