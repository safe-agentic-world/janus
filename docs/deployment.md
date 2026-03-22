# Deployment Readiness

This is the canonical deployment guide for Nomos.

This guide covers deployment shapes and operational readiness. It does not, by itself, imply `STRONG` assurance. Stronger claims depend on the runtime evidence and outer-boundary controls described in the assurance and strong-guarantee docs.

For higher-assurance deployment guidance, also see:

- `docs/strong-guarantee-deployment.md`
- `docs/reference-architecture.md`
- `docs/egress-and-identity.md`

## Stateless Mode

Set `runtime.stateless_mode: true` for stateless deployments.

Stateless mode is an operational mode, not a guarantee level.

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
- `POST /action`
- `POST /approvals/decide`
- `POST /explain`

`/run` uses the same request schema and auth model as `POST /action`.
`/explain` uses the same request schema and auth model as `POST /action`, but it does not execute side effects.

## Operator UI

Nomos serves a small operator UI at:

- `GET /ui/`

The UI is intentionally narrow:

- readiness / doctor posture
- approval inbox
- action detail

Security notes:

- treat `/ui/` as an operator surface
- UI data APIs require authenticated principal access
- approval decisions from the UI still flow through the existing approval machinery
- action detail currently depends on a sqlite audit sink for stored audit evidence
- the UI does not imply stronger assurance than the runtime evidence already supports

For details, see:

- `docs/operator-ui.md`

## Container Image

A production-oriented container build is provided via `Dockerfile`:
- multi-stage build
- distroless runtime image
- non-root user

Build:

```powershell
docker build -t nomos:local .
```

Multi-arch build example (`docker buildx`):

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t nomos:local .
```

OPA-enabled variant:

```bash
docker build --target runtime-opa -t nomos:opa-local .
```

This variant includes the OPA binary at `/opa` so `policy.opa.enabled=true` can run inside the container.

Run:

```powershell
docker run --rm -p 8080:8080 -v ${PWD}:/workspace nomos:local serve -c /workspace/examples/configs/config.example.json
```

If you want to override the checked-in example policy set, add:

```powershell
docker run --rm -p 8080:8080 -v ${PWD}:/workspace nomos:local serve -c /workspace/examples/configs/config.example.json -p /workspace/examples/policies/your-policy-bundle.json
```

Validate OPA binary presence in the OPA-enabled image:

```bash
docker run --rm --entrypoint /opa nomos:opa-local version
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

## CI Readiness

Primary workflows:

- `.github/workflows/ci.yml` (`Enterprise CI`)
- `.github/workflows/codeql.yml` (`CodeQL`)
- `.github/workflows/auto-tag-release.yml` (`Auto Tag Release`)
- `.github/workflows/release.yml` (`Release`)

Checks:

- workflow lint (`actionlint`)
- formatting, `go vet`, and `go build`
- `go test ./...`
- normalization corpus matrix (Linux/macOS/Windows)
- bypass suite
- race tests + `nomos doctor` smoke
- `govulncheck`
- container image build (`docker buildx`)
- release dry-run build on pull requests
- CodeQL analysis on `main` and pull requests

## Kubernetes Readiness

Reference manifests in `deploy/k8s/`:

- `configmap.yaml`
- `deployment.yaml`
- `service.yaml`
- `networkpolicy.yaml`
- `serviceaccount.yaml`
- `strong-guarantee.yaml`

Apply:

```powershell
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/deployment.yaml
kubectl apply -f deploy/k8s/service.yaml
```

For the stronger reference posture:

```powershell
kubectl apply -f deploy/k8s/strong-guarantee.yaml
```

Design notes:

- stateless mode enabled in sample config
- readiness/liveness probes on `/healthz`
- resource requests/limits set
- multiple replicas for horizontal scaling
- graceful termination via deployment `terminationGracePeriodSeconds`
- release path is workflow-managed: successful `main` CI can tag, publish a GitHub Release, and update Homebrew (`safe-agentic-world/homebrew-nomos`) and Scoop (`safe-agentic-world/scoop-nomos`) manifests
