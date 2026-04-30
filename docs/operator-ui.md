# Operator UI

Nomos includes an operator-facing console at `/ui/`.

The console is a thin presentation layer over existing Nomos gateway APIs. It does not introduce a second control plane, a new execution path, or a separate approval mechanism.

## Console Layout

The operator console uses persistent primary navigation:

- Overview
- Approvals
- Investigations
- Upstreams
- Policy Explain

Each section has a stable hash route such as `#/approvals` or `#/upstreams`. Operators can move from summary to queue to detail without losing queue context because approval, trace, and upstream pages use split-pane work surfaces.

## Workflows

### Overview

The overview page summarizes readiness, pending approvals, recent investigation count, and upstream health. It shows operational hotspots only when they map to an action an operator can take.

### Approvals

The approvals page is an enterprise data grid for pending decisions.

Supported interactions:

- search across principal, action, resource, approval id, and trace id
- active / expired filtering
- sortable columns
- local column visibility persistence
- stable row selection
- split-pane action detail
- approve / deny buttons routed through `POST /api/ui/approvals/decide`

Approval decisions still use the existing approval flow and audit behavior.

### Investigations

The investigations page lists audit trace summaries and keeps detail in a split pane.

Supported interactions:

- filters for trace id, action type, decision, principal, agent, and environment
- local saved trace filters
- sortable trace table
- bounded rendering for large result sets
- detail timeline from existing audit events

Trace inspection is read-only.

### Upstreams

The upstreams page combines configured MCP upstreams with sqlite audit evidence when available.

It surfaces:

- health classification
- request count
- error count and error rate
- average and p95 action latency
- breaker posture from configuration
- recent failure evidence

The upstream view intentionally does not expose credentials, auth headers, env values, raw MCP payloads, or upstream responses.

### Policy Explain

Policy Explain accepts a full action JSON payload and calls the explain-only endpoint. It does not execute the action and does not write execution audit events.

## Routes

- UI shell: `GET /ui/`
- readiness API: `GET /api/ui/readiness`
- approvals API: `GET /api/ui/approvals`
- action detail API: `GET /api/ui/actions/{action_id}`
- trace list API: `GET /api/ui/traces`
- trace detail API: `GET /api/ui/traces/{trace_id}`
- upstream summary API: `GET /api/ui/upstreams`
- explain-only API: `POST /api/ui/explain`
- authenticated approval wrapper: `POST /api/ui/approvals/decide`

## Authentication

The static UI shell may be served without authentication, but operator data APIs are authenticated.

Current operator authentication uses principal auth only:

- bearer API key
- OIDC bearer token
- SPIFFE-derived principal when that transport identity is available

The UI does not require an agent signature because it is an operator/admin surface, not an agent execution surface.

If authentication fails, the UI data APIs return `401`.

## Security Notes

- approval decisions made through the UI are still recorded through the existing approval decision flow
- UI responses are redacted before they are returned
- the UI never receives brokered secret values
- richer detail views remain subject to existing auth and redaction rules
- upstream summaries intentionally omit auth material and raw payload data
- visual status badges describe evidence already available to Nomos and must not imply stronger runtime guarantees
- the UI does not change Nomos authorization semantics

## Audit And Storage Notes

Approval inbox data comes from the configured approval store.

Action detail, trace inspection, and upstream evidence depend on a sqlite audit sink because the UI reads existing audit evidence rather than inventing a parallel action state store.

If the audit sink is not sqlite-backed, readiness, approvals, and configured upstream inventory still work, but action detail, trace timelines, and audit-derived upstream metrics may be unavailable or config-only.

## Keyboard And Responsiveness

Core navigation supports keyboard shortcuts:

- `Alt+1`: Overview
- `Alt+2`: Approvals
- `Alt+3`: Investigations
- `Alt+4`: Upstreams
- `Alt+5`: Policy Explain
- `/`: focus the primary filter/editor for the current route

All table decisions remain available through explicit buttons, not hover-only controls.

The layout is responsive for laptop-width and large-monitor operator use. At narrower widths, split panes stack while preserving the same route and detail state.

## Minimal Local Use

1. Start Nomos with a config that has `approvals.enabled: true` if you want the approval inbox.
2. Use `audit.sink: sqlite:<path>` if you want action detail, trace timelines, and audit-derived upstream evidence.
3. Open `http://127.0.0.1:8080/ui/`.
4. Enter a valid bearer token for a configured principal.

## Deployment Guidance

- treat `/ui/` as an operator surface, not a public app surface
- prefer serving the UI only on trusted internal networks
- use stronger operator identity such as OIDC or mTLS-backed identity where available
- do not confuse the UI with strong-guarantee evidence; assurance still comes from runtime evidence and deployment controls

See [UI System](ui-system.md) for component, visual, and interaction rules.
