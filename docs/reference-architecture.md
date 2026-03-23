# Controlled Runtime Reference Architecture

This document defines the reference architecture for a strong-guarantee deployment of Nomos.

## Threat Assumptions

- Agent code may be prompt-influenced, compromised, or actively malicious.
- Agent processes must be treated as untrusted with respect to filesystem, network, process spawning, and credential access.
- The platform operator controls the runtime boundary (CI runner or Kubernetes cluster) and can enforce network, identity, and process isolation outside the Nomos process itself.

## Reference Layout

```text
+---------------------------+        +---------------------------+
| Sample Agent Workload     |        | Operator-Controlled Infra |
|                           |        |                           |
| - no direct secrets       |        | - workload identity       |
| - no direct egress        |        | - network policy / egress |
| - bounded workspace       |        | - service routing / mTLS  |
+-------------+-------------+        +-------------+-------------+
              |                                        |
              | governed action request                |
              v                                        |
        +-----+----------------------------------------+-----+
        |                  Nomos Gateway                     |
        |                                                    |
        | validate -> normalize -> policy -> execute ->      |
        | redact -> audit                                    |
        +-----+------------------------------+---------------+
              |                              |
              | allowed, policy-bound        | audit events
              v                              v
        +-----+------+                +------+------+
        | Executors  |                | Audit Sink  |
        |            |                | (durable)   |
        +------------+                +-------------+
```

## Enforcement Points

1. Runtime isolation:
   The agent workload runs in a separate container or runner boundary with direct network egress denied by default.
   In Kubernetes, this normally means an isolated agent workload plus operator-managed egress controls.
2. Identity:
   Workload identity is asserted by the runtime environment, not by agent input.
3. Mediation:
   Governed side effects are routed through Nomos only.
4. Policy:
   Nomos remains deny-by-default and deny-wins.
5. Redaction:
   Nomos redacts before returning output, logging, or auditing.
6. Audit:
   Denied and allowed actions are written to a durable audit sink.

## Trust Assumptions vs. Enforced Properties

### Environment-Enforced Properties

These must be enforced by the runtime platform, not by Nomos alone:

- direct agent egress is blocked except to approved destinations
- agent workloads run as non-root
- agent workloads do not receive direct secret mounts
- agent workloads cannot use privileged container features to escape the boundary

### Nomos-Enforced Properties

These are enforced by Nomos once a request reaches the gateway:

- deterministic normalization
- deterministic policy evaluation
- deny-by-default authorization
- obligation enforcement inside the supported executor surfaces
- output redaction
- audit recording

### Current Proof Boundary

The current strong-guarantee validation surface in this repository is intentionally conservative:

- `nomos doctor` validates strong-guarantee readiness signals
- integration tests validate Nomos-mediated behavior and the readiness logic itself

This is stronger than a documentation-only claim, but it is still scoped to the current runtime checks and tests rather than a shipped deployment bundle.

## Verifiable Signals

The `nomos doctor` strong-guarantee mode validates conservative proxy signals for this architecture:

- container sandbox profile
- gateway mTLS
- workload identity verification (OIDC or SPIFFE, depending on deployment)
- durable audit sink
- deployment-bound environment (`ci`, `staging`, or `prod`)

These are intentionally fail-closed readiness checks rather than a full proof of cluster policy correctness.
