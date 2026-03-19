# Strong-Guarantee Deployment

This is the golden path for a reproducible strong-guarantee deployment of Nomos.

## Prerequisites

You need:

- a Kubernetes cluster that enforces `NetworkPolicy`
- a TLS secret named `nomos-tls`
- a Nomos image available as `nomos:local` or an equivalent image override
- a runtime where the operator controls network, identity, and pod security settings

If the cluster does not enforce `NetworkPolicy`, this deployment does **not** provide a strong guarantee.

## Kubernetes Golden Path

1. Build the image:

```bash
go build -o ./bin/nomos ./cmd/nomos
docker build -t nomos:local .
```

2. Apply the single reference manifest:

```bash
kubectl apply -f deploy/k8s/strong-guarantee.yaml
```

The manifest deploys:

- the Nomos gateway
- a locked-down `sample-agent` pod
- a Nomos-only egress policy for the sample agent
- a restricted Nomos egress policy for approved upstream access

3. Confirm health:

```bash
kubectl get pods -l app=nomos
kubectl get pods -l app=sample-agent
kubectl get networkpolicy nomos-egress
kubectl get networkpolicy sample-agent-egress
```

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

5. Verify the outer boundary from the sample agent:

Direct egress to arbitrary hosts should fail:

```bash
kubectl exec deploy/sample-agent -- wget -T 5 -qO- https://example.com || true
```

Access to the Nomos service should remain possible:

```bash
kubectl exec deploy/sample-agent -- wget -T 5 -qO- http://nomos:8080/healthz
```

The sample agent should not have an automounted service account token:

```bash
kubectl exec deploy/sample-agent -- sh -c 'test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token'
```

The sample agent should run as non-root:

```bash
kubectl exec deploy/sample-agent -- id -u
```

The expected result is a non-zero UID.

## CI Golden Path

Use the reference workflow in `deploy/ci/github-actions-hardened.yml` as the hardened baseline:

- Nomos is the policy gate for governed actions
- `nomos doctor` runs in strong-guarantee mode before agent tasks begin
- workload identity should come from the CI platform identity provider rather than long-lived shared keys

The checked-in CI example validates the strong-guarantee config shape and readiness signals. It is still the operator's job to ensure the CI runtime enforces the outer network and credential boundary.

The evidence block is explicit by design. It exists so `STRONG` remains an earned claim backed by verifiable runtime conditions, not by config intent alone.

## Operational Expectations

- Direct agent egress is blocked by runtime network policy.
- The sample agent can only egress to the Nomos gateway on TCP 8080.
- Enterprise identity is asserted by the platform.
- Agent-visible effects occur only through Nomos-mediated actions.
- Denied bypass attempts are auditable.

## Scope

This provides a reference deployment, a reusable validation harness, and conservative readiness checks.

It does not claim:

- a full proof for every Kubernetes distribution
- enforcement on unmanaged developer machines
- complete mediation outside operator-controlled runtimes

Treat this document as the source of truth for what the current strong-guarantee reference actually enforces.
