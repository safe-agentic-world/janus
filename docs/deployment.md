# Deployment Readiness

This document describes the base deployment posture.

For higher-assurance deployment guidance, also see:

- `docs/strong-guarantee-deployment.md`
- `docs/reference-architecture.md`
- `docs/egress-and-identity.md`
- `docs/ci-k8s.md`

## Stateless Mode

Set `runtime.stateless_mode: true` for stateless deployments.

Behavior in stateless mode:
- approvals are disabled (no local sqlite approval state)
- sqlite audit sink is disallowed
- suitable sinks are `stdout` and/or `webhook:<url>`

Example:

```json
{
  "runtime": {
    "stateless_mode": true
  },
  "audit": {
    "sink": "stdout,webhook:https://audit.example.internal/events"
  },
  "approvals": {
    "enabled": false
  }
}
```

## HTTP Run API

Nomos exposes an HTTP run endpoint:
- `POST /run`

`/run` uses the same request schema and auth model as `POST /action`.

## Container Image

A production-oriented container build is provided via `Dockerfile`:
- multi-stage build
- distroless runtime image
- non-root user

Build:

```powershell
docker build -t nomos:local .
```

Run:

```powershell
docker run --rm -p 8080:8080 -v ${PWD}:/workspace nomos:local serve -c /workspace/config.example.json -p /workspace/policies/your-policy-bundle.json
```

## Graceful Shutdown

`nomos serve` now waits for `SIGINT`/`SIGTERM` and performs graceful HTTP shutdown with a bounded timeout.

## Concurrency Limits

Set `gateway.concurrency_limit` to bound simultaneous action processing.

When limit is reached:
- request is rejected with HTTP `429`
- response reason code is `rate_limited`

## Horizontal Scaling Notes

For horizontal scaling:
1. Use stateless mode (`runtime.stateless_mode: true`).
2. Route audit to shared downstream systems (`webhook` and/or log collector from stdout).
3. Keep policy bundles identical across replicas.
4. Use external load balancing in front of `/run`.
5. Keep deny-by-default policy packs and approvals disabled or externalized.
