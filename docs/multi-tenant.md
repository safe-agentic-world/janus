# Multi-Tenant

Nomos can run one gateway for multiple teams by deriving a tenant id from the verified principal, then using that tenant id for policy selection, upstream MCP visibility, and audit partitioning.

## Tenant Model

Tenant ids are stable lowercase identifiers. Configure them under `tenancy.tenants` and map each tenant to one or more verified principals:

```json
{
  "tenancy": {
    "enabled": true,
    "tenants": [
      {
        "id": "retail",
        "principals": ["alice@example.com"],
        "policy_bundle_path": "policies/retail.json",
        "upstream_servers": ["retail-tools"]
      },
      {
        "id": "orders",
        "principals": ["bob@example.com"],
        "policy_bundle_path": "policies/orders.json",
        "upstream_servers": ["orders-tools"]
      }
    ]
  }
}
```

When tenancy is configured, Nomos resolves the tenant from the authenticated principal. If no tenant can be derived and no `default_tenant` is configured, the request fails closed.

`default_tenant` is an explicit compatibility fallback for principals that are authenticated but not listed in a tenant definition. Use it only when the default policy and upstream visibility are safe for every unmatched principal.

## Policy Selection

The global `policy.policy_bundle_path` or `policy.policy_bundle_paths` remains the baseline. Tenant policy bundles are appended after the baseline in deterministic order:

```text
global bundle 1
global bundle 2
tenant bundle 1
tenant bundle 2
```

This means every tenant gets the shared baseline plus its own tenant-specific rules. Bundle roles and signatures follow the same order when configured.

If a tenant has no `policy_bundle_path` or `policy_bundle_paths`, it uses only the global policy bundle set.

## Upstream Scoping

Upstream MCP visibility can be scoped in two ways.

Tenant-owned list:

```json
{
  "tenancy": {
    "tenants": [
      {
        "id": "retail",
        "principals": ["alice@example.com"],
        "upstream_servers": ["retail-tools"]
      }
    ]
  }
}
```

Server tags:

```json
{
  "mcp": {
    "upstream_servers": [
      {
        "name": "retail-tools",
        "transport": "stdio",
        "command": "retail-mcp",
        "tenants": ["retail"]
      }
    ]
  }
}
```

If a tenant defines `upstream_servers`, that explicit list takes precedence. Otherwise Nomos uses `mcp.upstream_servers[].tenants`. Untagged upstream servers remain visible to all tenants, so tag sensitive upstreams.

Tool listings, forwarded tool calls, resource listing, prompt listing, completions, sampling, and capability envelopes use the tenant-scoped upstream view.

## Audit Partitioning

Audit events include `tenant_id` when tenancy is active. Operator UI trace and action detail endpoints filter by the operator tenant, and audit query helpers can replay a single tenant partition.

Tenant partitioning is an audit and visibility boundary. It is not separate-process isolation; per-tenant process isolation and tenant-specific credential broker backends are future work.

## Migration

Existing single-tenant deployments do not need a `tenancy` block and continue to behave unchanged.

To migrate safely:

1. Add `tenancy.enabled: true` in a staging config.
2. Define tenant ids and principal mappings for known users or agents.
3. Keep the current global policy bundle as the baseline.
4. Add tenant policy bundles only for tenant-specific exceptions or stricter rules.
5. Tag sensitive upstream MCP servers with `tenants`.
6. Avoid `default_tenant` until every unmatched principal has been reviewed.
7. Verify `/explain`, MCP `tools/list`, `nomos.capabilities`, and audit traces for each tenant before production rollout.
