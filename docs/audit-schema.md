# Audit Schema v1

This document defines `AuditEvent` for replay level 1 (reconstructable).

## Replay Level 1 Guarantees

- Full timeline events are emitted (for example `trace.start`, `action.decision`, `action.completed`, `trace.end`).
- Normalized action identity is captured via `resource_normalized` and `params_hash`.
- `policy_bundle_hash` and `engine_version` are recorded on completion events.
- Executor outcome metadata is recorded in minimized, redacted form.

## AuditEvent v1 Fields

Required for `action.completed`:
- `schema_version` (`"v1"`)
- `timestamp`
- `trace_id`
- `action_id`
- `principal`
- `agent`
- `environment`
- `action_type`
- `resource_normalized`
- `params_hash`
- `decision`
- `matched_rule_ids`
- `obligations`
- `duration_ms`
- `result_classification`
- `retryable`
- `policy_bundle_hash`
- `engine_version`

Optional replay/safety fields:
- `params_redacted_summary`
- `result_redacted_summary`
- `executor_metadata`
- `reason`
- `approval_id`
- `action_fingerprint`
- `risk_level`
- `risk_flags`
- `sandbox_mode`
- `network_mode`
- `credential_lease_ids` (IDs only, never raw credentials)
- `action_summary`
- `prev_event_hash`
- `event_hash`

## Result Classification

Current set:
- `SUCCESS`
- `DENIED_POLICY`
- `APPROVAL_REQUIRED`
- `VALIDATION_ERROR`
- `NORMALIZATION_ERROR`
- `SANDBOX_VIOLATION`
- `EXEC_TIMEOUT`
- `OUTPUT_LIMIT`
- `UPSTREAM_ERROR`
- `INTERNAL_ERROR`

## Storage Rules

- Always store `params_hash`.
- `params_redacted_summary` and `result_redacted_summary` are optional and size-capped.
- Never store raw secrets or auth headers; events are redacted before storage/transmission.
- `executor_metadata` must remain minimal and redacted.

## Sinks

Configured via `audit.sink`:
- `stdout` (JSONL)
- `sqlite:<path>` or `sqlite://<path>`
- `webhook:<url>` (optional)

Multiple sinks can be combined as a comma-separated list.

## Tamper Evidence

Nomos supports per-stream hash chaining:

`event_hash_i = sha256(canonical_json(event_i_without_event_hash) || event_hash_{i-1})`

- `prev_event_hash` stores `event_hash_{i-1}` for linkage.
- `event_hash` stores `event_hash_i`.
- The first event in a stream has empty `prev_event_hash`.
- Audit-stream signing is separate from release artifact signing and is not part of the current event-chain verification model.

## Example

```json
{
  "schema_version": "v1",
  "timestamp": "2026-02-26T12:00:00Z",
  "event_type": "action.completed",
  "trace_id": "trace_123",
  "action_id": "act_123",
  "principal": "system",
  "agent": "nomos",
  "environment": "dev",
  "action_type": "fs.read",
  "resource_normalized": "file://workspace/README.md",
  "params_hash": "...",
  "decision": "ALLOW",
  "matched_rule_ids": ["allow-readme"],
  "obligations": {},
  "duration_ms": 12,
  "result_classification": "SUCCESS",
  "retryable": false,
  "policy_bundle_hash": "...",
  "engine_version": "0.0.0"
}
```
