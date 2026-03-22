# HTTP Integration Kit

This is the canonical raw HTTP integration guide for Nomos.

Use this when:

- your runtime does not support MCP
- you do not want to adopt an official SDK yet
- you need a machine-consumable contract for generated or hand-written clients

Preferred order remains:

1. MCP when available
2. official SDKs when HTTP is needed
3. raw HTTP using the published contract below

## Published Contract

Artifacts:

- OpenAPI: [`docs/openapi/nomos-http-v1.yaml`](./openapi/nomos-http-v1.yaml)
- request schema: [`docs/schemas/action-request.v1.json`](./schemas/action-request.v1.json)
- action response schema: [`docs/schemas/action-response.v1.json`](./schemas/action-response.v1.json)
- approval request schema: [`docs/schemas/approval-decision-request.v1.json`](./schemas/approval-decision-request.v1.json)
- explain response schema: [`docs/schemas/explain-response.v1.json`](./schemas/explain-response.v1.json)
- external report request schema: [`docs/schemas/external-report-request.v1.json`](./schemas/external-report-request.v1.json)
- external report response schema: [`docs/schemas/external-report-response.v1.json`](./schemas/external-report-response.v1.json)

Supported endpoints:

- `POST /action`
- `POST /run`
- `POST /approvals/decide`
- `POST /explain`
- `POST /actions/report`

## Auth

Raw HTTP requests use:

- `Authorization: Bearer <principal token>`
- `X-Nomos-Agent-Id: <verified agent id>`
- `X-Nomos-Agent-Signature: <hmac sha256 of raw request body>`

Optional contract hint:

- `X-Nomos-SDK-Contract: v1`

Requests fail closed on missing or invalid auth.

## Core Execution Flow

1. build an action request
2. sign the exact JSON request body
3. `POST /action`
4. branch on `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`
5. execute side effects only when Nomos authorizes them

Examples:

- [`examples/http-contract/action-fs-read.request.json`](../examples/http-contract/action-fs-read.request.json)
- [`examples/http-contract/action-custom-refund.request.json`](../examples/http-contract/action-custom-refund.request.json)
- [`examples/http-contract/action-allow.response.json`](../examples/http-contract/action-allow.response.json)
- [`examples/http-contract/action-approval.response.json`](../examples/http-contract/action-approval.response.json)
- [`examples/http-contract/action-custom-allow.response.json`](../examples/http-contract/action-custom-allow.response.json)

## Approval Flow

If Nomos returns `REQUIRE_APPROVAL`:

- the side effect must not run
- the response contains approval metadata
- a human or operator records approval through `POST /approvals/decide`
- the caller retries the same action with the approval binding

Request example:

- [`examples/http-contract/approval-decision.request.json`](../examples/http-contract/approval-decision.request.json)

## Explain-Only Flow

`POST /explain` uses the same request envelope as `POST /action`, but:

- does not execute side effects
- does not create execution audit events

Response example:

- [`examples/http-contract/explain.response.json`](../examples/http-contract/explain.response.json)

## Custom External Actions

Custom action types use the same request path:

- `POST /action`

If a custom action is allowed, Nomos returns:

- `decision: ALLOW`
- `execution_mode: external_authorized`
- `report_path: /actions/report`

The caller may then execute the business action and optionally report the outcome with:

- [`examples/http-contract/external-report.request.json`](../examples/http-contract/external-report.request.json)
- [`examples/http-contract/external-report.response.json`](../examples/http-contract/external-report.response.json)

For semantics and examples, see [`docs/custom-actions.md`](./custom-actions.md).

## Compatibility Guidance

The HTTP contract is additive.

Safe client assumptions:

- unknown response fields may appear and should be ignored safely
- existing required request fields remain stable for `v1`
- `POST /run` remains an alias of `POST /action`
- built-in and custom action flows share the same decision contract

Do not assume:

- Nomos executed a custom external action just because it returned `ALLOW`
- `REQUIRE_APPROVAL` is equivalent to success
- future additive fields imply a breaking contract change
