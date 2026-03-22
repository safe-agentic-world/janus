# Quickstart

This is the canonical first run for Nomos. It uses only checked-in files and should get a new user to one deterministic allow and one deterministic deny in under 10 minutes.

This quickstart demonstrates Nomos on the mediated path only. It is a local evaluation flow, not a claim of full mediation or strong-guarantee deployment.

## Prerequisites

- Go 1.25+ on `PATH`
- a clean checkout of this repository

No Docker, Kubernetes, or external services are required for the first success path.

## 1. Install Nomos CLI

```powershell
go install ./cmd/nomos
```

## 2. Run Deterministic Preflight

```powershell
nomos.exe doctor -c .\examples\quickstart\config.quickstart.json --format json
```

Expected result:

- exit code `0`
- `overall_status` is `READY`

Audit output for the quickstart uses `stdout`, so the same terminal shows readiness output and later action evidence.

## 3. Verify One Allowed Action

```powershell
nomos.exe policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\examples\policies\safe.yaml
```

Expected result:

- `decision` is `ALLOW`

## 4. Verify One Denied Action

```powershell
nomos.exe policy test --action .\examples\quickstart\actions\deny-env.json --bundle .\examples\policies\safe.yaml
```

Expected result:

- `decision` is `DENY`

## 5. Start The HTTP Gateway

```powershell
nomos.exe serve -c .\examples\quickstart\config.quickstart.json
```

The gateway listens on `http://127.0.0.1:8080`.

## 6. Run The HTTP SDK Example

In a second terminal:

```powershell
python .\examples\openai-compatible\nomos_http_loop.py
```

Expected result:

- the first request reads `README.md` and returns `ALLOW`
- the second request targets `.env` and returns `DENY`

The example prints both responses so you can see the policy-gated behavior directly.

If you want the official Go SDK path instead of the raw Python loop:

```powershell
go run .\examples\http-sdk\go
```

## 7. Optional: Open The Operator UI

Nomos now serves a small operator UI at:

```text
http://127.0.0.1:8080/ui/
```

The UI shell is static, but the data APIs require authenticated operator access.

For the quickstart config:

- use bearer token `dev-api-key`
- readiness works immediately
- approval inbox is disabled because `approvals.enabled` is `false`
- action detail and trace inspection are limited because the quickstart audit sink is `stdout`, not sqlite
- explain-only inspection works if you paste a full action JSON payload

If you want the full M36a UI path locally, use a config with:

- `approvals.enabled: true`
- `audit.sink: sqlite:<path>`

See [operator-ui.md](./operator-ui.md).

## Troubleshooting

- `load config:`:
  Confirm [config.quickstart.json](../examples/quickstart/config.quickstart.json) is being used from the repository root.
- `policy bundle path invalid`:
  Use the checked-in bundle [safe.yaml](../examples/policies/safe.yaml).
- `connection refused` from the Python example:
  Start `nomos serve` first and keep that terminal open.
- `python` not found:
  Any Python 3.9+ interpreter works; the example uses only the standard library.

## Next Paths

- Codex and Claude Code MCP setup: [integration-kit.md](./integration-kit.md)
- HTTP SDK reference: [http-sdk.md](./http-sdk.md)
- Operator UI details: [operator-ui.md](./operator-ui.md)
- Docker demo: `docker compose -f .\deploy\docker-compose\docker-compose.yml up --build`
- Kubernetes install: [deploy/helm/nomos/README.md](../deploy/helm/nomos/README.md)

