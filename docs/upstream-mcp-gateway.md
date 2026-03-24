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

- configured upstream MCP servers over `stdio`
- standards-compatible upstream stdio interoperability with common newline-delimited JSON MCP server implementations
- compatibility fallback for framed upstream MCP responses when encountered
- deterministic downstream naming using a conservative cross-vendor-safe character set:
  - `upstream_<server>_<tool>`
- policy-visible forwarded action identity:
  - `action_type`: `mcp.call`
  - `resource`: `mcp://<server>/<tool>`
- approval-gated forwarded calls using the same `approval_id` retry model as direct Nomos tools

Out of scope for this first gateway mode:

- remote upstream MCP transport
- dynamic discovery or registry integration
- multi-hop MCP routing

## Config Example

Use the checked-in example:

- [examples/configs/config.mcp-gateway.example.json](../examples/configs/config.mcp-gateway.example.json)
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
4. only an `ALLOW` result causes the upstream MCP tool call to be forwarded
5. the upstream tool result is returned through the governed response path as `execution_mode: mcp_forwarded`

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
- `nomos.capabilities` includes a `forwarded_tools` section when upstream MCP servers are configured.
