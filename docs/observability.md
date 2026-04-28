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

## Emitted Signals

The current implementation emits:

- request lifecycle events
- policy evaluation events
- executor run events
- counters for decisions, rate limits, approvals, retries, and failures
- upstream MCP breaker transition events

`nomos.rate_limits` counters include stable `result`, `rule_id`, `scope`, `action_type`, and `principal` attributes. `result=allowed` means a matching bucket was consumed; `result=exceeded` means the action was denied with `RATE_LIMIT_EXCEEDED`.

`mcp.upstream_breaker.transition` events include stable `upstream_server`, `from_state`, `to_state`, and `failure_kind` attributes. These events are emitted only on state transitions and do not change policy or execution decisions.

## W3C Trace Context

For HTTP ingress, Nomos accepts:

- `traceparent`
- `tracestate`

If `traceparent` is valid, Nomos propagates the accepted trace context back on the HTTP response headers.

Telemetry trace records use Nomos `trace_id` as the deterministic correlation key so telemetry and audit can be joined reliably.

## Redaction And Safety

- telemetry is redacted before export
- secret material must not appear in emitted telemetry
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
