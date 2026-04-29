# Observability

Nomos emits two complementary observability surfaces:

- audit events for durable security evidence
- OpenTelemetry-compatible telemetry records for execution tracing and counters

## Telemetry Export

Telemetry is optional and disabled by default.

When enabled, Nomos emits a fail-safe structured telemetry stream to:

- `stdout`
- `stderr`
- `otlp:<base_url>` over OTLP/HTTP JSON (`/v1/traces`, `/v1/logs`, `/v1/metrics`)

Telemetry export failures are ignored and MUST NOT change authorization or execution decisions.

## Stable Fields

Telemetry records use stable field names:

- `signal_type`
- `event_name`
- `trace_id`
- `correlation_id`
- `traceparent` (when accepted from HTTP ingress)
- `tracestate` (when accepted from HTTP ingress)
- `status`
- `attributes`

Metrics use:

- `signal_type`
- `name`
- `kind`
- `value`
- `trace_id`
- `attributes`

Metric kinds currently exported by Nomos:

- `counter`
- `gauge`
- `histogram`

## Emitted Signals

The current implementation emits:

- request lifecycle events
- policy evaluation events
- executor run events
- counters for decisions, rate limits, approvals, retries, and failures
- upstream MCP request counters and latency histograms
- upstream MCP breaker transition events and breaker-state gauges
- upstream MCP session lifecycle events

`nomos.rate_limits` counters include stable `result`, `rule_id`, `scope`, `action_type`, and `principal` attributes. `result=allowed` means a matching bucket was consumed; `result=exceeded` means the action was denied with `RATE_LIMIT_EXCEEDED`.

`mcp.upstream_breaker.transition` events include stable `upstream_server`, `from_state`, `to_state`, and `failure_kind` attributes. These events are emitted only on state transitions and do not change policy or execution decisions.

## Per-Upstream MCP Telemetry

Nomos emits per-upstream telemetry for configured MCP upstream servers.

Stable metric names:

- `nomos.mcp.upstream.requests`
- `nomos.mcp.upstream.latency_ms`
- `nomos.mcp.upstream.breaker_state`

`nomos.mcp.upstream.requests` is a counter emitted once per upstream RPC attempt, including fast-fail outcomes.

Stable labels:

- `upstream_server`
- `transport`
- `method`
- `action_type`
- `outcome`
- `error_class`

`nomos.mcp.upstream.latency_ms` is a histogram sample emitted with the same labels. It measures elapsed upstream RPC time in milliseconds. When a connection must be established first, Nomos also emits an `initialize` latency sample for the connection/handshake stage.

`nomos.mcp.upstream.breaker_state` is a gauge. Values are:

- `0` disabled
- `1` closed
- `2` half-open
- `3` open

Stable labels:

- `upstream_server`
- `state`
- `enabled`

Per-upstream events:

- `mcp.upstream.request`
- `mcp.upstream.session.lifecycle`
- `mcp.upstream_breaker.transition`

Structured MCP runtime logs use the same stable field names as the events where applicable:

- `event`
- `upstream_server`
- `upstream_session_id`
- `transport`
- `stage`
- `method`
- `action_type`
- `outcome`
- `error_class`
- `latency_ms`

These logs never include raw tool arguments, upstream responses, request bodies, headers, or credential values.

## Cardinality Guidance

Per-upstream labels are intentionally bounded:

- `method` is normalized to a fixed set such as `tools.call`, `resources.read`, `prompts.get`, or `other`.
- `action_type` is normalized to canonical Nomos action classes such as `mcp.call`, `mcp.resource_read`, or `mcp.upstream_rpc`.
- `outcome` is limited to `success`, `error`, or `blocked`.
- `error_class` is limited to stable classes such as `none`, `transport`, `protocol`, `timeout`, `credential`, `canceled`, or `breaker_open`.
- free-form values such as `upstream_server` are sanitized and length-capped before export.

Do not encode tenant ids, user ids, request ids, tool arguments, or resource URIs into upstream server names. Use audit records for high-cardinality forensic detail.

## W3C Trace Context

For HTTP ingress, Nomos accepts:

- `traceparent`
- `tracestate`

If `traceparent` is valid, Nomos propagates the accepted trace context back on the HTTP response headers.

Telemetry trace records use Nomos `trace_id` as the deterministic correlation key so telemetry and audit can be joined reliably.

## Redaction And Safety

- telemetry is redacted before export
- secret material must not appear in emitted telemetry
- upstream telemetry must not include raw MCP payloads, arguments, headers, responses, or credentials
- telemetry is additive and does not replace audit evidence

## Configuration

Example:

```json
{
  "telemetry": {
    "enabled": true,
    "sink": "otlp:http://otel-collector:4318"
  }
}
```

Supported sinks:

- `stdout`
- `stderr`
- `otlp:<base_url>`
