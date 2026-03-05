<img src="docs/assets/nomos-logo.png" alt="Nomos logo" width="220">

# Nomos

##

**Nomos helps you run AI agents safely without giving them full system trust.**

It sits between your agent and real side effects (files, shell, network, credentials), then:

- checks policy before execution
- blocks unsafe actions by default
- redacts sensitive output
- writes an audit trail

If you use Codex, Claude Code, OpenClaw, or custom agents, Nomos gives you a practical control layer.

---

## What Nomos Is (And Isn't)

Nomos **is**:

- a policy gate for agent actions
- a deterministic execution boundary
- an audit and redaction layer

Nomos **is not**:

- a model or agent framework
- a replacement for runtime hardening (network policy, identity, container controls)
- a prompt-only safety system

---

## Install

### Go (all platforms)

```bash
go install github.com/safe-agentic-world/nomos/cmd/nomos@latest
```

Windows note:

- `nomos.exe` is usually installed to `%USERPROFILE%\go\bin`

### macOS / Linux quick install

```bash
curl -fsSL https://raw.githubusercontent.com/safe-agentic-world/nomos/main/install.sh | sh
```

Optional:

- `NOMOS_VERSION=vX.Y.Z` to pin a version
- `INSTALL_DIR=$HOME/.local/bin` to avoid sudo

### Direct release downloads

Use GitHub Releases if you prefer manual install. Verify with `nomos-checksums.txt`.

---

## 5-Minute Local Check

From repo root:

1. Build:

```powershell
go build -o .\bin\nomos.exe .\cmd\nomos
```

2. Run readiness check:

```powershell
.\bin\nomos.exe doctor -c .\examples\quickstart\config.quickstart.json --format json
```

3. Verify one allow:

```powershell
.\bin\nomos.exe policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\policies\safe-dev-hardened.yaml
```

4. Verify one deny:

```powershell
.\bin\nomos.exe policy test --action .\examples\quickstart\actions\deny-env.json --bundle .\policies\safe-dev-hardened.yaml
```

If this works, your Nomos setup is healthy.

---

## Start Nomos

### HTTP gateway mode

```powershell
.\bin\nomos.exe serve -c .\examples\quickstart\config.quickstart.json -p .\policies\safe-dev-hardened.yaml
```

### MCP mode (for coding assistants)

```powershell
.\bin\nomos.exe mcp -c .\examples\quickstart\config.quickstart.json -p .\policies\safe-dev-hardened.yaml
```

---

## Common Commands

```powershell
.\bin\nomos.exe version
.\bin\nomos.exe doctor -c .\config.example.json
.\bin\nomos.exe policy test --action .\action.json --bundle .\policies\safe-dev.yaml
.\bin\nomos.exe policy explain --action .\action.json --bundle .\policies\safe-dev.yaml
```

---

## Starter Policies

- `policies/minimal.json`: smallest demo policy
- `policies/safe-dev.yaml`: safer local dev baseline
- `policies/safe-dev-hardened.yaml`: stricter local baseline
- `policies/guarded-prod.yaml`: production-oriented posture
- `policies/unsafe.yaml`: intentionally permissive (testing only)

---

## Where To Go Next

- Quickstart: `docs/quickstart.md`
- Agent integrations (Codex, Claude Code, OpenClaw, SDK): `docs/integration-kit.md`
- Deployment guide (includes CI/K8s readiness): `docs/deployment.md`
- Strong-guarantee reference deployment: `docs/strong-guarantee-deployment.md`
- Policy language: `docs/policy-language.md`
- Threat model + security checklist: `docs/threat-model.md`
- Release verification: `docs/release-verification.md`

---

## Container Images

- Standard image: `docker build -t nomos:local .`
- OPA-enabled image: `docker build --target runtime-opa -t nomos:opa-local .`

---

## Project Governance

- Contributing: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Changelog: `CHANGELOG.md`
- License: `LICENSE`
