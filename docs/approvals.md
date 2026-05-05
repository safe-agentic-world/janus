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
2. Nomos durably persists a pending approval with TTL, including a redacted MCP argument preview when the action is `mcp.call`.
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

## Durable Store

Approvals are persisted before Nomos returns a pending, approved, or denied state to a client or operator.

Configured gateway deployments use the file-backed store by default:

```json
{
  "approvals": {
    "enabled": true,
    "backend": "file",
    "store_path": "nomos-approvals.json",
    "ttl_seconds": 900
  }
}
```

Supported backends:

- `file`: default durable JSON store with checksum validation and atomic writes.
- `sqlite`: optional SQLite store for operators that prefer a database file.

SQLite configuration:

```json
{
  "approvals": {
    "enabled": true,
    "backend": "sqlite",
    "store_path": "nomos-approvals.db",
    "ttl_seconds": 900
  }
}
```

Durability semantics:

- startup verifies persisted store integrity before serving approvals
- expired approvals are purged deterministically on startup and pending-list reads
- TTL checks survive process restarts because `expires_at` is persisted
- partial file-store writes are isolated in a temporary file and do not replace the last committed store
- existing approval ids, fingerprints, scopes, and approval resume behavior are stable across file and SQLite backends

Migration from older deployments:

1. If approvals were disabled or no durable store path was configured, enable approvals and set `approvals.store_path`.
2. For the default backend, use `backend: "file"` and a path such as `nomos-approvals.json`.
3. To keep an existing SQLite approval database, set `backend: "sqlite"` and point `store_path` at the existing `.db` file.
4. Keep `ttl_seconds` at least as long as the previous approval TTL window.
5. Restart Nomos and verify `nomos approvals list --store <path> --backend <file|sqlite>` and a non-production `approve` / `deny` decision before routing approval-gated actions.

## Approval CLI

Operators can inspect pending approvals with:

```bash
nomos approvals list --store ./nomos-approvals.json --backend file
nomos approvals list --store ./nomos-approvals.db --backend sqlite
```

The JSON output includes `argument_preview` for `mcp.call` approvals and omits it for non-MCP approvals.

Operators can decide a pending approval from the same durable store:

```bash
nomos approvals approve --store ./nomos-approvals.json --backend file <approval_id>
nomos approvals deny --store ./nomos-approvals.json --backend file <approval_id>
```

`approve` and `deny` accept `--format text|json`. The `approval_id` may appear before or after the flags.

## Params Patch (Future)

Approvals may optionally provide a params patch in a future revision. If applied, it creates a new normalized action and fingerprint, which requires approval against that new target.
