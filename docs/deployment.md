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
- `POST /actions/report`

`/run` uses the same request schema and auth model as `POST /action`.
`/explain` uses the same request schema and auth model as `POST /action`, but it does not execute side effects.
`/actions/report` records caller-reported outcomes for custom actions that Nomos authorized but did not execute itself.

For the published contract, schemas, and OpenAPI artifact, see:

- `docs/http-integration-kit.md`
- `docs/openapi/nomos-http-v1.yaml`

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

## Remote MCP Gateway

Nomos can expose its downstream MCP surface over Streamable HTTP for shared remote-agent deployments:

```text
nomos mcp serve --http --listen 127.0.0.1:8090 -c ./examples/configs/config.mcp-serve-http.example.json
```

This mode leaves `nomos mcp` stdio unchanged and adds a separate authenticated HTTP listener for remote MCP clients.

Operator notes:

- put `nomos mcp serve --http` behind a reverse proxy or ingress that terminates TLS
- prefer mTLS from the proxy to Nomos, or an internal network hop with strict source controls
- if a proxy injects identity headers, only do so on an authenticated non-spoofable hop
- direct client access should keep TLS termination on Nomos or on an mTLS-enforcing edge
- resumed MCP requests must keep sending the same authenticated principal and `MCP-Session-Id`

Security notes:

- authentication happens before `initialize`, `tools/list`, or `tools/call`
- failed auth returns a stable HTTP JSON error shape and never reaches policy evaluation
- governed MCP audit events include `executor_metadata.downstream_transport` and `executor_metadata.downstream_session_id`

Related references:

- `docs/integration-kit.md`
- `docs/upstream-mcp-gateway.md`
- `examples/configs/config.mcp-serve-http.example.json`

## Upstream Env Isolation

For upstream stdio servers, Nomos now starts child processes from an empty-by-default environment. If an upstream server needs specific parent variables, add them explicitly with `mcp.upstream_servers[].env_allowlist` and `mcp.upstream_servers[].env`.

This is a migration change for older configs that implicitly depended on `os.Environ()` inheritance. The safe path is:

1. list the exact parent env names you need in `env_allowlist`
2. add fixed values in `env`
3. prefer absolute command paths for stdio upstreams if `PATH` is no longer available to the child

## Container Packaging

Nomos does not currently publish or maintain an official container image path.

If you deploy Nomos in Kubernetes or another containerized environment today, treat image packaging as an operator-managed concern and build or supply your own image out of band.

## Graceful Shutdown

`nomos serve` now waits for `SIGINT`/`SIGTERM` and performs graceful HTTP shutdown with a bounded timeout.

## Concurrency Limits

Set `gateway.concurrency_limit` to bound simultaneous action processing.

When limit is reached:
- request is rejected with HTTP `429`
- response reason code is `rate_limited`

## Service-Stage Rate Limits

Use `rate_limits` for deterministic action quotas after normalization and before policy evaluation. These limits are separate from the legacy `gateway.rate_limit_per_minute` transport guard.

Supported buckets:

- `principal_action`: one bucket per `(principal, action_type)`.
- `principal_resource`: one bucket per `(principal, normalized_resource)`.
- `global_tool`: one shared bucket per `action_type`.

All matching buckets are enforced. If any bucket is empty, Nomos denies the action with `RATE_LIMIT_EXCEEDED`, writes that classification to audit, and exports `nomos.rate_limits` telemetry counters. Keep bursts large enough for normal automation spikes and use `evict_after_seconds` to bound idle in-memory bucket state.

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
- release dry-run build on pull requests
- CodeQL analysis on `main` and pull requests

## Kubernetes Readiness

Nomos can be deployed in Kubernetes, but this repository does not currently ship checked-in manifests or Helm packaging.

If you deploy Nomos in Kubernetes today, treat the manifests, image packaging, workload identity wiring, and network boundary controls as operator-managed concerns.

Design notes:

- stateless mode is the preferred scale-out posture
- readiness/liveness should target `/healthz`
- multiple replicas and graceful termination belong at the workload layer
- strong-guarantee claims depend on real runtime controls, not config intent alone
- release path is workflow-managed: successful `main` CI can tag, publish a GitHub Release, and update Homebrew (`safe-agentic-world/homebrew-nomos`) and Scoop (`safe-agentic-world/scoop-nomos`) manifests
