<img src="docs/assets/nomos-logo.png" alt="Nomos logo" width="220">

# Nomos

**Ship agentic workflows without giving agents root trust.**

Nomos is a zero-trust gateway that sits between AI agents and real side effects (files, shell, network, credentials).

It enforces deterministic policy before execution, then redacts and audits results.

If you use Codex, OpenClaw, or custom agents, Nomos gives you guardrails without killing speed.

---

## Why This Matters

Most agent setups are still "tool access by prompt."

Nomos adds an actual policy boundary:

- Deny-by-default, deny-wins authorization
- Deterministic evaluation and normalization
- Approval gates for risky actions
- Redaction before outputs leave Nomos
- Replayable audit trail with trace linkage

---

## What You Get

- **Fast wedge:** works in minutes with MCP (`nomos.fs_read` demo)
- **Real control:** policy-gated `fs`, `exec`, `http`, patch/write paths
- **Safer ops:** rate limits, circuit breakers, TLS/mTLS options
- **Auditability:** bundle hash, risk metadata, tamper-evident chain support
- **Portability:** MCP stdio and HTTP gateway (`/action`, `/run`)

---

## Install

### Go users

```bash
go install github.com/safe-agentic-world/nomos/cmd/nomos@latest
```

On Windows, `go install` places `nomos.exe` in `%USERPROFILE%\\go\\bin` unless `GOBIN` is set. Add that directory to your `PATH`, or run it directly:

```powershell
& "$env:USERPROFILE\go\bin\nomos.exe"
```

To use `nomos` in the current PowerShell session immediately:

```powershell
$env:Path += ";$env:USERPROFILE\go\bin"
```

### macOS and Linux quick install

```bash
curl -fsSL https://raw.githubusercontent.com/safe-agentic-world/nomos/main/install.sh | sh
```

Optional:

- set `NOMOS_VERSION=vX.Y.Z` to pin a version
- set `INSTALL_DIR=$HOME/.local/bin` to install without sudo

### Direct download

GitHub Releases publish these archives for each release:

- `nomos-linux-amd64.tar.gz`
- `nomos-linux-arm64.tar.gz`
- `nomos-darwin-amd64.tar.gz`
- `nomos-darwin-arm64.tar.gz`
- `nomos-windows-amd64.zip`
- `nomos-windows-arm64.zip`
- `nomos-checksums.txt`

Verify the archive with `nomos-checksums.txt`, then extract `nomos` (or `nomos.exe`) into your `PATH`.

---

## 2-Minute Demo

### 1) Build

```powershell
go build -o .\bin\nomos.exe .\cmd\nomos
```

### 2) Start Nomos in MCP mode

```powershell
.\bin\nomos.exe mcp `
  -c .\config.example.json `
  -p .\policies\minimal.json
```

### 3) Register in Codex

```powershell
codex mcp add nomos -- `
  .\bin\nomos.exe mcp `
  -c .\config.example.json `
  -p .\policies\minimal.json
```

### 4) Prove policy is real

In Codex, run:

- Allowed: `Use nomos.fs_read to read file://workspace/README.md`
- Denied: `Use nomos.fs_read to read file://workspace/TASKS.md`

You should see:

- `README.md` allowed (capped output)
- `TASKS.md` denied under the minimal bundle (structured deny response)
- audit events emitted for both
- redaction path executed before returning output

---

## Architecture In One Screen

1. Agent sends action request.
2. Nomos validates shape and identity.
3. Nomos normalizes resource/params deterministically.
4. Policy engine returns `ALLOW` / `DENY` / `REQUIRE_APPROVAL`.
5. Executor runs only if authorized.
6. Output is redacted and audited.

---

## Current Feature Set

- Strict validation with unknown-field rejection (except `context.extensions`)
- Identity verification (API key, service HMAC, OIDC, SPIFFE, and agent HMAC)
- Deterministic policy engine (`deny wins`) + `policy test` / `policy explain`
- Executors: `fs.read`, `fs.write`, `repo.apply_patch`, `process.exec`, `net.http_request`
- Approval workflow (sqlite + TTL + webhook/Slack/Teams endpoints)
- Audit sinks (`stdout`, `sqlite`, `webhook`) + tamper-evident chain hashes
- Safety visibility metadata (risk level, sandbox/network mode, lease IDs, bundle hash)
- Gateway protections (concurrency/rate/circuit limits, optional TLS/mTLS)
- Strong-guarantee deployment checks and reference manifests for CI/K8s
- Deterministic assurance labeling (`STRONG`, `GUARDED`, `BEST_EFFORT`, `NONE`) in audit, `policy explain`, and `nomos.capabilities`
- Golden normalization corpus, redirect policy controls, and bypass-suite coverage
- Corpus-backed redaction guarantees plus no-leak harness coverage
- Actionable `policy explain` denial context (`why_denied`, `minimal_allowing_change`, `obligations_preview`)
- Workflow-managed releases with GitHub Release assets and checksums
- Starter policy bundles include `safe-dev`, `safe-dev-hardened`, `guarded-prod`, and `unsafe`

---

## Quick Commands

```powershell
go test ./...
.\bin\nomos.exe version
.\bin\nomos.exe policy test --action .\action.json --bundle .\policies\your-policy-bundle.json
.\bin\nomos.exe policy explain --action .\action.json --bundle .\policies\your-policy-bundle.json
.\bin\nomos.exe serve -c .\config.example.json -p .\policies\your-policy-bundle.json
```

Release metadata build example:

```powershell
go build -ldflags "-X github.com/safe-agentic-world/nomos/internal/version.Version=vX.Y.Z -X github.com/safe-agentic-world/nomos/internal/version.Commit=$(git rev-parse --short HEAD) -X github.com/safe-agentic-world/nomos/internal/version.BuildDate=$(Get-Date -AsUTC -Format o)" -o .\bin\nomos.exe .\cmd\nomos
.\bin\nomos.exe version
```

HTTP endpoints in `serve` mode:

- `GET /healthz`
- `GET /version`
- `POST /action`
- `POST /run`
- `POST /approvals/decide`
- `POST /webhooks/approvals`
- `POST /webhooks/slack/approvals`
- `POST /webhooks/teams/approvals`

---

## Integrations

- Quickstart path: `docs/quickstart.md`
- Codex + OpenClaw setup: `docs/integration-kit.md`
- MCP capability model and workflow notes: `docs/integration-kit.md`
- Unmanaged laptop limitations and safer workflows: `docs/integration-kit.md`
- Assurance and mediation contract: `docs/assurance-levels.md`, `docs/guarantees.md`
- Policy troubleshooting: `docs/policy-explain.md`

---

## Security And Design Docs

- Threat model: `docs/threat-model.md`
- OWASP Agentic Top 10 mapping: `docs/owasp-agentic-mapping.md`
- Security checklist: `docs/security-checklist.md`
- Policy language: `docs/policy-language.md`
- Canonical JSON and hashing: `docs/canonical-json.md`
- Normalization rules: `docs/normalization.md`
- Approval binding model: `docs/approvals.md`
- Audit schema and replay notes: `docs/audit-schema.md`
- Redaction guarantees and source coverage: `docs/redaction-guarantees.md`, `docs/redaction-sources.md`
- Normalization vectors and redirect rules: `docs/normalization-test-vectors.md`, `docs/http-redirects.md`
- Bypass coverage model: `docs/bypass-playbook.md`
- Release verification and supply-chain trust: `docs/release-verification.md`, `docs/supply-chain-security.md`

---

## Deployment

- Base deployment guide: `docs/deployment.md`
- CI/K8s readiness and release automation: `docs/ci-k8s.md`
- Strong-guarantee deployment reference: `docs/strong-guarantee-deployment.md`, `docs/reference-architecture.md`, `docs/egress-and-identity.md`
- Container image: `Dockerfile`
- K8s manifests: `deploy/k8s/`

---

## Project Governance

- Contribution guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Release history: `CHANGELOG.md`

---

## License

`LICENSE`
