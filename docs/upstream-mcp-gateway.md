# Upstream MCP Gateway

Nomos can now run as an additive MCP governance gateway in front of one or more configured upstream MCP servers.

In this mode:

- the downstream agent still sees an MCP server
- Nomos remains the decision point
- governed upstream tools are surfaced as forwarded downstream tools
- successful calls are forwarded only after policy and approval checks pass

This is the 2026 MCP-native architecture path where:

- the agent is an MCP client
- business tools live on external MCP servers
- governance sits between the agent and those upstream MCP servers

## What v1 Supports

- configured upstream MCP servers over `stdio`, `streamable_http`, and legacy `sse`
- long-lived upstream MCP sessions: each upstream server is spawned once, initialized once, and reused for every forwarded call (no per-call process launch)
- id-keyed JSON-RPC response multiplexer so many concurrent forwarded calls share one upstream session
- `notifications/tools/list_changed` propagation so a refreshed upstream tool list is re-enumerated and re-advertised downstream without restarting Nomos
- deterministic restart-on-crash with bounded exponential backoff, fail-closed while restarting
- graceful shutdown: upstream child processes are terminated when the Nomos gateway exits
- standards-compatible upstream stdio interoperability with common newline-delimited JSON MCP server implementations
- compatibility fallback for framed upstream MCP responses when encountered
- deterministic downstream naming using a conservative cross-vendor-safe character set:
  - `upstream_<server>_<tool>`
- policy-visible forwarded action identity:
  - `action_type`: `mcp.call`
  - `resource`: `mcp://<server>/<tool>`
- approval-gated forwarded calls using the same `approval_id` retry model as direct Nomos tools

Out of scope for this first gateway mode:

- dynamic discovery or registry integration
- multi-hop MCP routing
- WebSocket upstream transport

## Config Example

Use the checked-in example:

- [examples/configs/config.mcp-gateway.example.json](../examples/configs/config.mcp-gateway.example.json)
- [examples/configs/config.mcp-gateway.remote-http.example.json](../examples/configs/config.mcp-gateway.remote-http.example.json)
- [examples/policies/mcp-gateway.example.yaml](../examples/policies/mcp-gateway.example.yaml)

Config shape:

```json
{
  "mcp": {
    "enabled": true,
    "upstream_servers": [
      {
        "name": "retail",
        "transport": "stdio",
        "command": "python",
        "args": ["../local-tooling/retail_mcp_server.py"]
      }
    ]
  }
}
```

Replace `path/to/your/retail_mcp_server.py` with the upstream MCP server command you actually want Nomos to govern.

## Remote Upstream MCP Transports

Nomos can also front remote, managed, or containerized MCP servers over HTTP. Two transport kinds are supported:

- `streamable_http` — the current MCP Streamable HTTP transport. Nomos POSTs JSON-RPC messages to the configured endpoint and accepts either an `application/json` single response or a `text/event-stream` server-sent stream of JSON-RPC messages.
- `sse` — the legacy two-endpoint SSE transport. Nomos opens a `GET` SSE channel, receives the `endpoint` event, and POSTs subsequent messages to the advertised URL. Responses arrive back on the open SSE stream.

For `streamable_http`, Nomos speaks the current MCP HTTP transport version (`MCP-Protocol-Version: 2025-11-25`), carries forward `MCP-Session-Id` when assigned by the upstream, listens on the optional GET event stream for server-initiated notifications, and sends a best-effort `DELETE` when closing a stateful HTTP session.

Both transports plug into the same long-lived session supervisor as `stdio`, so policy identity, approval semantics, forwarded tool naming, and audit records are identical across transports. A bundle that governs `mcp://retail/refund.request` does not need to change when the upstream `retail` server migrates from `stdio` to `streamable_http`.

### HTTP Upstream Config Shape

The remote HTTP example above is a working template for `streamable_http` upstreams. The minimal shape is:

```json
{
  "mcp": {
    "enabled": true,
    "upstream_servers": [
      {
        "name": "retail",
        "transport": "streamable_http",
        "endpoint": "https://retail.mcp.example.com/mcp",
        "allowed_hosts": ["retail.mcp.example.com"],
        "auth": {
          "type": "bearer",
          "token": "${NOMOS_UPSTREAM_RETAIL_TOKEN}"
        }
      }
    ]
  }
}
```

- `endpoint` is required for `streamable_http` and `sse`. It must use `https` unless `tls_insecure` is set to `true`. `tls_insecure` is a dev-only escape hatch and MUST NOT be used in controlled runtimes.
- `allowed_hosts` is an optional host allowlist. When set, the upstream endpoint host (and, for legacy SSE, the advertised POST URL host) MUST match one of the listed hosts or startup fails closed before any RPC is sent.
- `tls_ca_file` is optional and adds a custom CA bundle for upstream TLS verification.
- `tls_cert_file` and `tls_key_file` are optional and enable mutual TLS to the upstream MCP server. They must be configured together.
- `auth` is an optional static auth injection hook. Supported shapes:
  - `{ "type": "bearer", "token": "..." }` → adds `Authorization: Bearer <token>`.
  - `{ "type": "header", "header": "X-Api-Key", "value": "..." }` → adds a single static header.
  - `{ "type": "header", "values": { "X-Api-Key": "...", "X-Tenant": "..." } }` → adds multiple static headers.

Auth material passed through the config is injected only into upstream HTTP requests. It is NEVER written to audit records, explain output, or logs.

### Security Expectations

- TLS verification is on by default and uses the host's system root store. TLS verification failures during handshake, session startup, or call time cause the upstream session to fail closed — forwarded calls return `upstream_unavailable` rather than silently downgrading.
- When `tls_ca_file` is set, Nomos extends the trust store with that CA bundle rather than disabling verification. When `tls_cert_file` and `tls_key_file` are set, Nomos presents that client certificate to upstream servers requiring mTLS.
- Upstream host allowlists are enforced **before** any JSON-RPC payload is sent. An allowlist violation prevents the upstream request entirely.
- Upstream auth failures (HTTP `401`/`403`) surface as deterministic `upstream_unavailable` errors. Nomos does NOT retry with alternate credentials.
- Streamed responses are read through the normal redaction and per-rule `output_max_bytes` / `output_max_lines` caps before they leave Nomos to the agent, logs, or audit sinks. A streamed secret in a tool result is redacted the same as a buffered secret.

### Operator Guidance

- Prefer `https` endpoints with a trusted certificate chain. Reserve `tls_insecure` for local smoke tests against development servers.
- Prefer a private CA plus `tls_ca_file` over `tls_insecure` for internal upstreams, and use `tls_cert_file` plus `tls_key_file` only for upstreams that require client-authenticated TLS.
- Set `allowed_hosts` to the exact hostnames you intend to forward to. This is a transport-layer allowlist, not a substitute for a policy rule — the policy bundle is still the only authorization source.
- Store upstream auth tokens outside the config file when possible (templated in at deploy time, or brokered via the M54 credential flow in future revisions). The v1 `auth` block is a stable injection point for that integration.
- Policy bundles do not need any changes to move an upstream from `stdio` to `streamable_http`: `mcp.call` resource identity is `mcp://<server>/<tool>` regardless of transport.


Policy shape:

```yaml
rules:
  - id: require-approval-upstream-refund
    action_type: mcp.call
    resource: mcp://retail/request_refund
    decision: REQUIRE_APPROVAL
```

## Forwarded Tool Naming

If the upstream server is named `retail` and it exposes a tool named `request_refund`, Nomos advertises:

- `upstream_retail_request_refund`

That tool maps deterministically to:

- `action_type`: `mcp.call`
- `resource`: `mcp://retail/request_refund`

Only the client-facing forwarded tool name is adapted for broad MCP client and model-provider compatibility. Policy, approvals, explain, and audit continue to key off the canonical `mcp://<server>/<tool>` resource identity.

## How Forwarding Works

1. the downstream agent calls a forwarded MCP tool exposed by Nomos
2. Nomos constructs a governed `mcp.call` action
3. normalization, policy, approvals, redaction, and audit run on the Nomos path
4. only an `ALLOW` result causes the upstream MCP tool call to be forwarded over the long-lived upstream session
5. the upstream tool result is returned through the governed response path as `execution_mode: mcp_forwarded`

## Upstream Session Lifecycle

Nomos runs one long-lived supervisor per configured upstream MCP server. At startup:

1. the supervisor spawns the upstream child process
2. it runs `initialize` and `notifications/initialized` exactly once
3. it calls `tools/list` to populate the forwarded tool registry
4. it begins accepting forwarded calls over the same session

Every subsequent forwarded call reuses the same upstream session, so latency is dominated by policy evaluation and upstream tool execution — not by process startup. JSON-RPC request ids are allocated deterministically per session and multiplexed by a single reader goroutine, so many concurrent forwarded calls are routed back to their original callers without cross-talk.

When the upstream server emits `notifications/tools/list_changed`, the supervisor re-enumerates the upstream tool list and refreshes the downstream forwarded tool set. No Nomos restart is required. Unknown or unsupported upstream notifications are logged deterministically and dropped without affecting policy decisions already in flight.

## Upstream Unavailable Behavior

If the upstream process crashes, closes stdin/stdout, or sends an unframable response, the session is marked unavailable. All in-flight forwarded calls bound to that session return a structured `upstream_unavailable` error to the caller. Policy decisions already recorded in audit are not re-executed.

The next forwarded call triggers a lazy session restart with bounded exponential backoff. While a restart is pending, additional forwarded calls return `upstream_unavailable` rather than hanging, so failures stay deterministic and fail-closed.

You will see `upstream_unavailable` surface in:

- the downstream MCP response `error` field for the failing forwarded tool call
- audit and explain output when the forwarded call reaches the supervisor after policy has allowed it

This is distinct from a policy `DENY`: `upstream_unavailable` means policy allowed the forwarded call but the upstream transport was not in a usable state at the moment of execution. Retry by the client, not a policy change, is the appropriate operator response.

## Approval Retry

Forwarded tools use the same approval pattern as other Nomos-mediated actions:

1. first call returns `REQUIRE_APPROVAL` with `approval_id`
2. operator records approval
3. client retries the same forwarded tool with:

```json
{
  "approval_id": "apr_..."
}
```

Nomos then re-evaluates and only forwards on a valid approved retry.

## Notes

- Upstream tool enumeration fails closed. If Nomos cannot initialize an upstream server or list its tools, startup fails.
- Upstream stdio compatibility failures are reported with stage-aware errors such as launch, initialize, tool enumeration, or tool invocation.
- Nomos expects real upstream MCP stdio servers to follow ecosystem-standard newline-delimited JSON messaging. Framed upstream responses are also accepted for compatibility.
- Direct Nomos MCP tools still work unchanged. Upstream gateway mode is additive.
- Stateful upstream MCP servers that rely on session-scoped state (auth tokens, cached resources, progress streams) work correctly because the upstream session is long-lived rather than re-initialized per call.
- Upstream child processes are terminated on Nomos shutdown. Supervised deployments should additionally parent the Nomos process to a process manager that reaps orphans on a host crash.
- Upstream stderr is continuously drained; the tail of stderr is attached to stage-aware error messages when an upstream process fails to launch or handshake.
- `nomos.capabilities` includes a `forwarded_tools` section when upstream MCP servers are configured.
