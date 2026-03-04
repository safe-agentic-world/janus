# OPA Interop

Nomos provides a fail-closed OPA interoperability path through:

- a stable bridge contract for external evaluation
- an optional runtime backend that invokes `opa eval`

The built-in Nomos policy engine remains available, but controlled deployments can configure the OPA backend as the active decision source.

## Stable External Input

The bridge converts a normalized Nomos action into a stable JSON object containing:

- `schema_version`
- `action_id`
- `action_type`
- `resource`
- `params`
- `params_hash`
- `principal`
- `agent`
- `environment`
- `trace_id`

The normalized Nomos action remains the source of truth.

## Supported External Output

The bridge and runtime backend accept only:

```json
{
  "decision": "ALLOW | DENY | REQUIRE_APPROVAL",
  "reason_code": "optional",
  "obligations": {}
}
```

## Fail-Closed Behavior

The bridge/backend fails closed when:

- the external evaluator is unavailable
- the external evaluator returns malformed output
- the external evaluator returns an ambiguous decision

Nomos never treats an unavailable or ambiguous external evaluator as allow.

## Determinism

Determinism depends on:

- stable normalized input
- deterministic external policy logic
- stable obligations translation

Nomos preserves its own deny-by-default and decision-class semantics at the bridge boundary.

## Runtime Backend Configuration

Example:

```json
{
  "policy": {
    "policy_bundle_path": "./policies/minimal/policy.bundle.json",
    "opa": {
      "enabled": true,
      "binary_path": "opa",
      "policy_path": "./policy.rego",
      "query": "data.nomos.decision",
      "timeout_ms": 2000
    }
  }
}
```

Nomos executes:

- `opa eval --format=json --stdin-input --data <policy_path> <query>`

The configured query must evaluate to exactly one object that matches the supported external output schema above.
