# Threat Model

This is the canonical security posture document for Nomos.

## Scope

Current hardening scope covers:
- OIDC principal authentication
- mTLS channel/client authentication
- per principal/agent/environment rate limiting and circuit breakers
- policy bundle signature verification
- audit redaction and tamper-evidence chain integrity

For a control-by-control security review mapped to the OWASP Agentic Top 10, see `docs/owasp-agentic-mapping.md`.

## Adversaries

1. Compromised or malicious agent process attempting unauthorized side effects.
2. Prompt-driven abuse attempting credential escalation or policy bypass.
3. Network attacker attempting MITM or endpoint spoofing.
4. Malicious actor tampering with policy bundles before load.
5. Abusive high-volume callers attempting resource exhaustion.
6. Insider or process attempting to exfiltrate secrets through logs.
7. Upstream tool or service returning adversarial instructions to steer the downstream agent.

## Trusted Computing Base (TCB)

- Nomos gateway binaries and loaded configuration.
- Host TLS stack and kernel networking.
- Signature verification keys provisioned by operators.
- Identity provider key material configured for OIDC verification.

## Security Controls And Mitigations

- `deny-by-default` policy with deny-wins precedence.
- No agent-supplied identity/environment: identity is verified server-side and environment is config-bound.
- OIDC token verification (`iss`, `aud`, signature) using configured public key.
- Optional mTLS requiring verified client certificates.
- Per principal/agent/environment rate limiting to bound request volume.
- Per principal/agent/environment circuit breaker to cut repeated execution failures.
- Optional policy bundle signature verification before policy activation.
- Redaction before returning/logging and audit storage rules disallowing raw secrets.
- Response-side scanning for forwarded upstream MCP content before downstream delivery.
- Audit hash chaining (`prev_event_hash`, `event_hash`) for tamper evidence.

## Response-Side Trust Boundary

Upstream MCP responses are untrusted input even after the upstream call itself is policy-authorized. Nomos treats returned text as a separate trust boundary: content is redacted, scanned for known injection/exfiltration patterns, sanitized according to `response_scan_mode`, and then delivered to the downstream agent.

Audit and telemetry record rule IDs and locations only. Raw matched response content is not stored in audit metadata, explain output, logs, or telemetry.

## Residual Risks

- OIDC key rotation/discovery automation is operator-managed rather than built into the runtime (Nomos uses a statically configured public key).
- In-memory rate-limit and breaker state is process-local; distributed coordination is out of scope.
- mTLS protects transport path but does not replace application-level authorization.
- Signature verification protects bundle integrity only if operator key management is strong.
- Pattern-based response scanning does not claim ML-grade detection; operators should treat it as deterministic mitigation for known classes of adversarial text.

## Non-Goals

- Full host compromise resistance.
- Hardware-backed key attestation.
- Cross-region distributed breaker/rate limiter consensus.

## Security Review Checklist

Use this checklist before release.

### Identity And Transport

- [ ] OIDC enabled where required with correct `issuer`, `audience`, and trusted public key path.
- [ ] API key/service HMAC credentials rotated and least-privilege scoped.
- [ ] mTLS enabled for sensitive deployments.
- [ ] mTLS client CA bundle validated and current.

### Policy Integrity

- [ ] `policy.verify_signatures` enabled in production.
- [ ] Policy signature and public key files are provisioned read-only.
- [ ] Policy bundle hash and engine version visible in audit logs.

### Abuse Controls

- [ ] `gateway.rate_limit_per_minute` set per environment capacity.
- [ ] `gateway.circuit_breaker_failures` and cooldown tuned to prevent cascade failures.
- [ ] `gateway.concurrency_limit` set to safe service capacity.

### Secrets And Logging

- [ ] Audit sinks configured with redaction-safe destinations.
- [ ] No raw credentials in outputs/logs; only credential lease IDs are surfaced.
- [ ] Response scan mode set appropriately for high-risk upstream MCP servers.
- [ ] Audit tamper-evidence chain fields present (`prev_event_hash`, `event_hash`).

### Operational

- [ ] Graceful shutdown behavior validated.
- [ ] Stateless mode used for horizontally scaled deployments.
- [ ] Runbook includes key rotation and incident response contacts.
