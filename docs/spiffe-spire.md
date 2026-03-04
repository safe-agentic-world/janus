# SPIFFE And SPIRE

Nomos supports an additive SPIFFE-based workload identity path for controlled runtimes.

## Trust Model

The current SPIFFE integration assumes:

- the gateway is already protected by mTLS
- the client certificate presented to the gateway contains a SPIFFE URI SAN
- the configured trust domain is operator-controlled

Nomos verifies the SPIFFE ID from the presented client certificate and binds that verified identity into authorization and audit inputs as the authenticated principal.

## Configuration

Example:

```json
{
  "identity": {
    "principal": "system",
    "agent": "nomos",
    "environment": "prod",
    "api_keys": {},
    "service_secrets": {},
    "agent_secrets": {
      "nomos": "replace-me"
    },
    "spiffe": {
      "enabled": true,
      "trust_domain": "example.org"
    }
  }
}
```

When `identity.spiffe.enabled=true`, Nomos requires:

- `identity.spiffe.trust_domain`

## What Is Verified

Nomos accepts a workload identity only when:

- a peer certificate is present
- the leaf certificate contains a URI SAN with the form `spiffe://<trust-domain>/...`
- the URI SAN trust domain matches the configured trust domain

If verification fails, Nomos falls back to the other configured principal auth modes only if those are enabled.

## Deployment Guidance

For controlled runtimes:

- prefer SPIFFE/SPIRE or other workload identity over shared API keys
- keep shared API keys disabled in strong-guarantee deployments
- combine SPIFFE with mTLS so the presented certificate is part of the transport trust boundary

## Scope

The current implementation validates SPIFFE IDs from mTLS peer certificates. It does not embed a full SPIRE control-plane integration in the Nomos binary.

