# Custom Actions

Nomos built-in executors are intentionally narrow:

- `fs.read`
- `fs.write`
- `repo.apply_patch`
- `process.exec`
- `net.http_request`
- `secrets.checkout`

M39 adds support for **custom action types** so applications do not need to mislabel business actions as `net.http_request`.

Examples:

- `payments.refund`
- `ticket.update`
- `crm.contact_export`
- `support.issue_credit`

These are examples only. Nomos does not hard-code them.

## What Custom Actions Mean

Custom actions use the same core path as built-in actions:

1. authenticate
2. validate
3. normalize
4. evaluate policy
5. return `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`
6. record audit evidence

The difference is execution semantics:

- built-in actions may be executed by Nomos executors
- custom actions are **authorized by Nomos** and then executed by the caller or application

Nomos does not claim it executed a custom business action.

## Action Type Rules

Action types must use a stable dotted identifier shape:

- lowercase segments
- letters, digits, and `_`
- one or more `.` separators

Examples:

- valid: `payments.refund`
- valid: `crm.contact_export`
- invalid: `RefundPayment`

## Resource Rules

Custom actions may use custom resource schemes such as:

- `payment://shop.example.com/orders/ORD-1001`
- `ticket://jira/INC-42`
- `crm://salesforce/contacts/segment-a`

Custom resource normalization is deterministic:

- scheme is lowercased
- host is lowercased
- path is cleaned
- traversal is rejected
- query strings, fragments, and userinfo are rejected

## HTTP Authorization Flow

Submit a custom action through the normal `POST /action` path.

Example:

```json
{
  "schema_version": "v1",
  "action_id": "act_refund_1",
  "action_type": "payments.refund",
  "resource": "payment://shop.example.com/orders/ORD-1001",
  "params": {
    "amount": "249.00",
    "currency": "USD",
    "reason": "damaged_on_arrival"
  },
  "trace_id": "trace_refund_1",
  "context": {
    "extensions": {}
  }
}
```

On allow, Nomos returns an additive response shape such as:

```json
{
  "decision": "ALLOW",
  "reason": "allow_by_rule",
  "action_id": "act_refund_1",
  "trace_id": "trace_refund_1",
  "approval_fingerprint": "…",
  "execution_mode": "external_authorized",
  "report_path": "/actions/report"
}
```

`execution_mode: external_authorized` means:

- Nomos authorized the action
- Nomos did not execute the business side effect itself
- the caller may execute it and optionally report the outcome

## Approval Behavior

Custom actions use the normal approval model.

If policy returns `REQUIRE_APPROVAL`:

- Nomos returns `approval_id` and `approval_fingerprint`
- the caller retries the same action with the approval binding in `context.extensions.approval`
- on success, Nomos returns `ALLOW` with `execution_mode: external_authorized`

## Optional Outcome Reporting

Applications may report caller-executed outcomes through `POST /actions/report`.

Example:

```json
{
  "schema_version": "v1",
  "action_id": "act_refund_1",
  "trace_id": "trace_refund_1",
  "action_type": "payments.refund",
  "resource": "payment://shop.example.com/orders/ORD-1001",
  "outcome": "SUCCEEDED",
  "external_reference": "refund_123"
}
```

This records a caller-attested audit event:

- `action.external_reported`

That event is explicitly different from Nomos executor evidence.

## SDK Support

The SDKs now expose:

- response fields for `execution_mode` and `report_path`
- outcome reporting helpers:
  - Go: `ReportExternalOutcome`
  - Python: `report_external_outcome`
  - TypeScript: `reportExternalOutcome`

For wrapper-based integrations, the SDKs also expose:

- Go: `InvokeAndReport`
- Python: `invoke_and_report`
- TypeScript: `invokeAndReport`
