# Operator UI

Nomos includes a small operator-facing UI at `/ui/`.

The operator UI now includes two additive layers:

- readiness / doctor view
- approval inbox
- action detail
- trace list and trace detail
- explain-only policy inspection

The UI is a thin surface over existing Nomos state and endpoints. It does not introduce a second control plane and it does not create a new execution path.

## What It Is For

Use the operator UI when you want to:

- review pending approvals without handcrafting approval requests
- inspect the current decision state for a governed action
- confirm readiness posture, policy bundle hash, assurance level, and deployment mode

## What It Is Not

The UI still does not provide:

- policy authoring
- file browsing or mutation
- generic admin analytics
- a new execution path outside the existing Nomos control flow

## Routes

- UI shell: `GET /ui/`
- readiness API: `GET /api/ui/readiness`
- approvals API: `GET /api/ui/approvals`
- action detail API: `GET /api/ui/actions/{action_id}`
- trace list API: `GET /api/ui/traces`
- trace detail API: `GET /api/ui/traces/{trace_id}`
- explain-only API: `POST /api/ui/explain`
- authenticated approval wrapper: `POST /api/ui/approvals/decide`

## Authentication

The static UI shell may be served without authentication, but operator data APIs are authenticated.

Current operator authentication uses principal auth only:

- bearer API key, or
- OIDC bearer token, or
- SPIFFE-derived principal when that transport identity is available

The UI does not require an agent signature because it is an operator/admin surface, not an agent execution surface.

If authentication fails, the UI data APIs return `401`.

## Security Notes

- approval decisions made through the UI are still recorded through the existing approval decision flow
- UI responses are redacted before they are returned
- the UI never receives brokered secret values
- the UI does not change Nomos authorization semantics

## Audit And Storage Notes

Approval inbox data comes from the configured approval store.

Action detail and trace inspection currently depend on a sqlite audit sink because the UI reads existing audit evidence rather than inventing a parallel action state store.

If the audit sink is not sqlite-backed, readiness and approvals still work, but action detail will not have stored audit evidence to query.

## Deep Inspection Notes

Trace inspection is read-only:

- trace list supports filtering by trace id, action type, decision, principal, agent, and environment
- trace detail shows the ordered timeline of major audit events already recorded by Nomos

Explain is also read-only:

- the UI accepts a full action JSON payload for explain-only evaluation
- the explain endpoint does not execute the action
- the explain endpoint does not write execution audit events

Use the same internal action shape you would pass to `action.DecodeAction`, including:

- `schema_version`
- `action_id`
- `action_type`
- `resource`
- `params`
- `principal`
- `agent`
- `environment`
- `context`
- `trace_id`

## Minimal Local Use

1. Start Nomos with a config that has:
   - `approvals.enabled: true` if you want the approval inbox
   - `audit.sink: sqlite:<path>` if you want action detail from stored audit evidence
2. Open `http://127.0.0.1:8080/ui/`
3. Enter a valid bearer token for a configured principal

## Deployment Guidance

- treat `/ui/` as an operator surface, not a public app surface
- prefer serving the UI only on trusted internal networks
- use stronger operator identity such as OIDC or mTLS-backed identity where available
- do not confuse the UI with strong-guarantee evidence; assurance still comes from runtime evidence and deployment controls
