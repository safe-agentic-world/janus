# Quickstart

This is the canonical first run for Nomos. It uses only checked-in files and should get a new user to one deterministic allow and one deterministic deny in under 10 minutes.

## Prerequisites

- Go 1.24+ on `PATH`
- a clean checkout of this repository

No Docker, Kubernetes, or external services are required for the first success path.

## 1. Build Nomos

```powershell
go build -o .\bin\nomos.exe .\cmd\nomos
```

## 2. Run Deterministic Preflight

```powershell
.\bin\nomos.exe doctor -c .\examples\quickstart\config.quickstart.json --format json
```

Expected result:

- exit code `0`
- `overall_status` is `READY`

Audit output for the quickstart uses `stdout`, so the same terminal shows readiness output and later action evidence.

## 3. Verify One Allowed Action

```powershell
.\bin\nomos.exe policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\policies\safe-dev-hardened.yaml
```

Expected result:

- `decision` is `ALLOW`

## 4. Verify One Denied Action

```powershell
.\bin\nomos.exe policy test --action .\examples\quickstart\actions\deny-env.json --bundle .\policies\safe-dev-hardened.yaml
```

Expected result:

- `decision` is `DENY`

## 5. Start The HTTP Gateway

```powershell
.\bin\nomos.exe serve -c .\examples\quickstart\config.quickstart.json -p .\policies\safe-dev-hardened.yaml
```

The gateway listens on `http://127.0.0.1:8080`.

## 6. Run The SDK Example

In a second terminal:

```powershell
python .\examples\openai-compatible\nomos_http_loop.py
```

Expected result:

- the first request reads `README.md` and returns `ALLOW`
- the second request targets `.env` and returns `DENY`

The example prints both responses so you can see the policy-gated behavior directly.

## Troubleshooting

- `load config:`:
  Confirm [config.quickstart.json](../examples/quickstart/config.quickstart.json) is being used from the repository root.
- `policy bundle path invalid`:
  Use the checked-in bundle [safe-dev-hardened.yaml](../policies/safe-dev-hardened.yaml).
- `connection refused` from the Python example:
  Start `nomos serve` first and keep that terminal open.
- `python` not found:
  Any Python 3.9+ interpreter works; the example uses only the standard library.

## Next Paths

- Codex and Claude Code MCP setup: [integration-kit.md](/C:/Users/prudh/repos/safe-agentic-world/nomos/docs/integration-kit.md)
- Codex and Claude Code MCP setup: [integration-kit.md](./integration-kit.md)
- Docker demo: `docker compose -f .\deploy\docker-compose\docker-compose.yml up --build`
- Kubernetes install: [deploy/helm/nomos/README.md](../deploy/helm/nomos/README.md)
