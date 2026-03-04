# Threat Model

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
- Audit hash chaining (`prev_event_hash`, `event_hash`) for tamper evidence.

## Residual Risks

- OIDC key rotation/discovery automation is operator-managed rather than built into the runtime (Nomos uses a statically configured public key).
- In-memory rate-limit and breaker state is process-local; distributed coordination is out of scope.
- mTLS protects transport path but does not replace application-level authorization.
- Signature verification protects bundle integrity only if operator key management is strong.

## Non-Goals

- Full host compromise resistance.
- Hardware-backed key attestation.
- Cross-region distributed breaker/rate limiter consensus.
