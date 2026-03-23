# Strong-Guarantee Deployment

This document describes the runtime conditions Nomos needs before `STRONG` is a defensible claim. It no longer assumes checked-in manifests or deployment templates.

## Prerequisites

You need:

- a Kubernetes cluster that enforces `NetworkPolicy`
- a TLS secret named `nomos-tls`
- an operator-built Nomos image available to the cluster
- a runtime where the operator controls network, identity, and pod security settings

If the cluster does not enforce `NetworkPolicy`, this deployment does **not** provide a strong guarantee.

## Kubernetes Golden Path

1. Build the Nomos binary or produce the container image through your own packaging pipeline.

2. Deploy operator-managed workloads for:

- the Nomos gateway
- the locked-down agent workload
- a Nomos-only egress policy for that agent
- a restricted Nomos egress policy for approved upstream access

3. Confirm health and outer-boundary posture using your platform tooling. At minimum, verify:

- the Nomos workload is healthy
- the agent workload is healthy
- direct agent egress is blocked by default
- only Nomos can reach approved upstream destinations

4. Run doctor against the strong-guarantee config:

```bash
go run ./cmd/nomos doctor -c ./examples/configs/config.example.json --format json
```

The strong-guarantee readiness signal is intentionally conservative. For a deployment to be READY, the config should indicate:

- `runtime.strong_guarantee=true`
- `runtime.deployment_mode=k8s` (or `ci` in CI environments)
- `executor.sandbox_profile=container`
- `runtime.evidence.container_backend_ready=true`
- `runtime.evidence.rootless_or_non_privileged=true`
- `runtime.evidence.read_only_fs=true`
- `runtime.evidence.no_new_privileges=true`
- `runtime.evidence.network_default_deny=true`
- `runtime.evidence.workload_identity_verified=true`
- `runtime.evidence.durable_audit_verified=true`
- gateway mTLS enabled
- workload identity verification enabled
- shared API keys disabled
- durable audit sink configured

5. Verify the outer boundary from the agent workload:

Expected checks:

- direct egress to arbitrary hosts fails
- access to the Nomos service remains possible
- the agent workload does not receive an automounted service account token unless explicitly required
- the agent workload runs as non-root

## CI Golden Path

Use your CI platform's hardened workflow as the baseline:

- Nomos is the policy gate for governed actions
- `nomos doctor` runs in strong-guarantee mode before agent tasks begin
- workload identity should come from the CI platform identity provider rather than long-lived shared keys

It is the operator's job to ensure the CI runtime enforces the outer network and credential boundary.

The evidence block is explicit by design. It exists so `STRONG` remains an earned claim backed by verifiable runtime conditions, not by config intent alone.

## Operational Expectations

- Direct agent egress is blocked by runtime network policy.
- The agent workload can only egress to the Nomos gateway and approved downstream destinations.
- Enterprise identity is asserted by the platform.
- Agent-visible effects occur only through Nomos-mediated actions.
- Denied bypass attempts are auditable.

## Scope

This provides a runtime contract and conservative readiness checks.

It does not claim:

- a full proof for every Kubernetes distribution
- enforcement on unmanaged developer machines
- complete mediation outside operator-controlled runtimes

Treat this document as the source of truth for the current strong-guarantee requirements, not as a promise of shipped deployment assets.
