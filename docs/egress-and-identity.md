# Egress And Identity

This document explains how the reference architecture combines environment controls and Nomos controls.

## Egress Enforcement

The reference architecture assumes:

- agent workloads have default-deny egress
- only Nomos is allowed to reach approved upstream destinations
- Nomos still applies per-action network allowlists before execution

This creates a layered model:

1. Environment blocks direct agent egress.
2. Nomos blocks disallowed governed requests.

## Identity Enforcement

The reference architecture uses workload identity to bind the runtime to an operator-controlled identity source.

For the strong-guarantee posture, the readiness signal is OIDC enabled in Nomos config:

- environment asserts identity
- Nomos verifies identity material
- audit records principal, agent, and environment

## Credential Boundaries

- Agents do not receive raw enterprise credentials directly.
- Nomos brokers short-lived lease IDs.
- Credential materialization happens only inside executors and remains subject to redaction before output/logging/audit.

## Upstream MCP Credentials

Upstream MCP servers can authenticate through brokered leases instead of static tokens in config.

Operators provision a broker profile under `credentials.secrets`, then reference that profile from the upstream server:

```json
{
  "credentials": {
    "enabled": true,
    "secrets": [
      {
        "id": "retail_mcp_token",
        "env_key": "RETAIL_MCP_TOKEN",
        "value": "<loaded from the operator secret store>",
        "ttl_seconds": 900
      }
    ]
  },
  "mcp": {
    "upstream_servers": [
      {
        "name": "retail",
        "transport": "streamable_http",
        "endpoint": "https://retail.example.com/mcp",
        "credentials": {
          "profile": "retail_mcp_token",
          "mode": "bearer",
          "refresh_before_expiry_ms": 30000
        }
      }
    ]
  }
}
```

Do not commit real secret values. In production, populate broker profiles from the operator-controlled secret store or deployment secret injection path.

Supported injection modes:

- `bearer` injects `Authorization: Bearer <leased-secret>` for HTTP MCP transports.
- `header` injects a configured header name for HTTP MCP transports.
- `env` injects one explicit environment variable into a stdio upstream, without inheriting the parent environment.
- `file` writes the leased secret to a Nomos-managed temporary file and injects the file path through the configured environment variable.

Each upstream lease is bound to the Nomos principal, agent, environment, upstream server, and upstream session id. Nomos refreshes leases before expiry using the session clock, audits only lease IDs, and releases active leases on upstream shutdown when the broker supports release.

If lease acquisition or refresh fails, the upstream session fails closed with `UPSTREAM_CREDENTIAL_UNAVAILABLE`. Refresh failure opens the upstream circuit breaker rather than retrying with alternate credentials.

## Why Both Layers Matter

Nomos alone cannot stop an untrusted workload from bypassing mediation if the environment allows unrestricted egress, direct credential access, or unrestricted process escape.

The reference architecture is therefore explicitly a combined control plane:

- environment enforces the outer boundary
- Nomos enforces the inner deterministic authorization boundary

## Explicit Out-Of-Scope Bypass Conditions

The current strong-guarantee posture does **not** claim protection if:

- the Kubernetes cluster does not actually enforce `NetworkPolicy`
- the runtime allows privileged pods or host-level escape paths outside the required constraints
- the operator injects direct credentials into the agent workload
- the deployment diverges from the required hardening constraints without equivalent replacements
- the host or cluster control plane itself is already compromised

In those cases, Nomos should be treated as a deterministic authorization layer running inside a weaker outer boundary, not as a complete strong-guarantee deployment.
