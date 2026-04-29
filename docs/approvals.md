# Approval Binding Model

Nomos binds approvals to deterministic targets so an approval for one normalized input is not valid for a different normalized input.

## Fingerprint

`action_fingerprint = sha256(canonical_json({normalized_action, principal, agent, environment}))`

`normalized_action` includes:
- `schema_version`
- `action_type`
- `resource`
- canonicalized `params`

Any change to normalized inputs (including params) produces a new fingerprint and requires a new approval.

## MCP Argument Preview

For approval-gated `mcp.call` actions, approval records include an `argument_preview_json` payload.

The preview is derived from the normalized canonical `params.tool_arguments` field, the same canonical params blob used for `action_fingerprint` and `params_hash`.

Preview guarantees:

- only `mcp.call` approvals include argument previews; non-MCP approvals are unchanged
- secrets are redacted before storage and rendering
- known sensitive argument fields such as authorization, cookies, tokens, API keys, passwords, credentials, and private keys are replaced with `[REDACTED]`
- previews are size-capped and mark `truncated: true` when Nomos cannot safely render the full argument shape
- `tool_arguments_hash` and `params_hash` remain visible so operators can bind what they see to the canonical action that will execute

Approval previews are presentation data only. Operator UI, CLI, and explain rendering do not re-evaluate policy and do not provide an alternate execution path.

## Scope

Nomos supports two narrowly scoped bindings:
- `fingerprint` (default): a single normalized action.
- `class` (optional): bounded class key currently limited to `action_type_resource`, derived as `<action_type>|<resource>`.

Approvals are never global.

## Resume Flow

1. Policy returns `REQUIRE_APPROVAL`.
2. Nomos persists a pending approval with TTL in sqlite, including a redacted MCP argument preview when the action is `mcp.call`.
3. External approver records `APPROVE` or `DENY` via approval endpoint/webhook.
4. Agent retries the same action with `context.extensions.approval = {"approval_id":"..."}`.
5. Nomos recomputes normalized action and fingerprint and only resumes when approval binding matches and TTL is valid.

## Integrations

Nomos provides integration endpoints:
- Generic webhook: `POST /webhooks/approvals` using header `X-Nomos-Webhook-Token` when configured.
- Slack webhook: `POST /webhooks/slack/approvals` using header `X-Nomos-Slack-Token` when configured.
- Teams webhook: `POST /webhooks/teams/approvals` using header `X-Nomos-Teams-Token` when configured.

Slack payload schema:
- `approval_id` (string, required)
- `decision` (string, required)
- `user_id` (string, required)
- `channel_id` (string, required)
- `comment` (string, optional)

Teams payload schema:
- `approval_id` (string, required)
- `decision` (string, required)
- `user_aad_id` (string, required)
- `conversation_id` (string, required)
- `comment` (string, optional)

Unknown fields are rejected for deterministic validation behavior.

## Approval CLI

Operators can inspect pending approvals with:

```bash
nomos approvals list --store ./nomos-approvals.db
```

The JSON output includes `argument_preview` for `mcp.call` approvals and omits it for non-MCP approvals.

## Params Patch (Future)

Approvals may optionally provide a params patch in a future revision. If applied, it creates a new normalized action and fingerprint, which requires approval against that new target.
