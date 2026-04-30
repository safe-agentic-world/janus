# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Go 1.25+. Use Makefile targets or `go` directly.

- Build CLI: `go build ./cmd/nomos` (or `make build`)
- Release build with version metadata: `make release-build` (sets ldflags into `internal/version`)
- Full test suite: `go test ./...`
- Race suite (release gate): `go test -race ./...` — requires `CGO_ENABLED=1` (default on Linux/macOS, must be set explicitly on Windows checkouts without a C toolchain)
- Static checks: `go vet ./...` (aliased as `make lint`)
- Format: `gofmt -w .` (aliased as `make fmt`)
- Single package: `go test ./internal/policy`
- Single test: `go test ./internal/policy -run TestName`
- Focused MCP compat: `go test ./internal/mcp`
- Fast iteration set: `go test ./cmd/nomos ./internal/policy ./internal/service ./internal/gateway ./internal/mcp`

Smoke checks using the built binary (run after `make build` / `go build`):

- `nomos doctor -c ./examples/quickstart/config.quickstart.json --format json`
- `nomos policy test --action ./examples/quickstart/actions/allow-readme.json --bundle ./examples/policies/safe.yaml`
- `nomos policy test --action ./examples/quickstart/actions/deny-env.json --bundle ./examples/policies/safe.yaml`
- `nomos policy explain ...` for deny/approval diagnostics

CLI flag precedence is `flag > env > fail`. Relevant env vars: `NOMOS_CONFIG`, `NOMOS_POLICY_BUNDLE`, `NOMOS_LOG_LEVEL`. `--config/-c` and `--policy-bundle/-p` are resolved to absolute paths at parse time.

## Architecture

Nomos is an execution firewall for AI agents: an agent-agnostic control plane that sits at the execution boundary and returns `ALLOW` / `DENY` / `REQUIRE_APPROVAL` on normalized actions. The same pipeline backs both the MCP server and HTTP gateway surfaces — understanding that pipeline is the big picture.

**Request pipeline** (same shape whether the caller is MCP or HTTP):

1. **Boundary** (`internal/mcp` or `internal/gateway`) accepts the request. Identity is never read from the request body — it is injected from config and verified via bearer/HMAC/OIDC. The MCP path derives `action_id`/`trace_id` from the MCP request id (`mcp_<id>`) to stay deterministic.
2. **Normalize** (`internal/normalize`, `internal/action`) canonicalizes resources (e.g., `file://workspace/...`, `url://host/path`), rejects traversal (`..`), and yields a stable action fingerprint. Agent-supplied principal/environment claims are rejected.
3. **Policy evaluation** (`internal/policy`) is **deny-wins** and rule order is irrelevant. Bundles load from JSON or YAML; YAML is validated strictly (duplicate-key and unknown-field rejection) and `policy_bundle_hash` is always computed from canonical JSON of the typed bundle so equivalent inputs stay deterministic. Matching supports glob patterns and optional identity/risk filters.
4. **Obligations**: redaction patterns, output caps (`output_max_bytes`/`output_max_lines`), sandbox profile (`sandbox_mode`), approval scope. Sandbox selection is obligation-driven and fails closed when the configured profile is weaker than required.
5. **Approvals** (`internal/approval`) bind to exact action fingerprints by default; class-scoped approvals require explicit `approval_scope_class` obligation and are limited to `action_type_resource`.
6. **Execute** (`internal/executor`, `internal/sandbox`) runs only ALLOW decisions. `repo.apply_patch` is implemented as deterministic `path` + `content` replacement (not diff application) and rejects writes outside the workspace root. `net.http_request` maps normalized `url://` to `https://`, enforces host allowlists, and denies redirects unless the matched policy sets `http_redirects`.
7. **Credentials** (`internal/credentials`) are brokered as short-lived lease IDs bound to `(principal, agent, environment, trace_id)`. Raw secrets never return to the agent; only lease IDs surface in visibility.
8. **Redact + cap** (`internal/redact`) applies before any output leaves Nomos — to the agent, logs, and audit sinks. Per-rule caps are enforced post-redaction so policy caps cannot be bypassed by larger executor defaults.
9. **Audit + telemetry** (`internal/audit`, `internal/telemetry`): `action.completed` is the canonical replay-level `AuditEvent v1` record. Hash chaining runs over canonicalized payloads with `prev_event_hash` attached for cross-platform-deterministic verification. Telemetry is additive (OTLP/HTTP) — audit remains the authoritative evidence surface.

**Assurance levels** (`internal/assurance`): `STRONG` / `GUARDED` / `BEST_EFFORT` are derived strictly from operator-controlled `runtime.deployment_mode` + `runtime.strong_guarantee` and propagate into explain/audit output only. They never alter policy decisions. `nomos doctor` uses conservative proxy checks (container sandbox, mTLS, OIDC workload identity, durable audit sink, deployment-bound environment) and fails closed when signals are absent.

**Config path resolution**: filesystem-backed fields in config (policy bundles, workspace roots, approval store, TLS files, OIDC public keys, sqlite audit sinks) resolve relative to the **config file directory**, not the process CWD. Absolute paths still win.

**Upstream routes** (`upstream.routes`) act as a fail-closed transport allowlist for `net.http_request` when configured. They constrain host/path/method **before** execution but do not participate in policy authorization — deny-wins remains the only authorization source.

**HTTP `/run`** maps to the same strict action handler as `/action` — there is no parallel execution path. Keep it that way when adding endpoints.

**MCP stdout is protocol-pure**: operator UX (ready banner, logs, errors) goes to stderr; MCP runtime uses a non-emitting in-process audit recorder so stdout carries only MCP protocol frames.

## Package map

- `cmd/nomos` — CLI entrypoint (commands: `doctor`, `policy test|explain`, `mcp`, `serve`, `version`, …)
- `internal/policy` — bundle loading, matching, deny-wins evaluation, explain
- `internal/service`, `internal/gateway` — HTTP boundary + shared action handler
- `internal/mcp` — MCP server and upstream MCP gateway (stdio newline-delimited JSON, framed responses accepted for compat)
- `internal/identity` — bearer/HMAC/OIDC verification feeding the boundary
- `internal/normalize`, `internal/action`, `internal/canonicaljson`, `internal/schema` — determinism layer + JSON schemas
- `internal/executor`, `internal/sandbox` — execution + obligation-driven isolation
- `internal/credentials` — lease broker
- `internal/redact`, `internal/responsescan` — output guardrails (textual redaction + upstream-response injection scanning)
- `internal/audit`, `internal/telemetry` — evidence and metrics
- `internal/approval`, `internal/approvalpreview` — fingerprint-bound approvals + preview surface
- `internal/assurance`, `internal/doctor`, `internal/quickstart` — deployment guarantee modeling, preflight, and quickstart helpers
- `internal/tenant`, `internal/ratelimit`, `internal/opabridge` — tenancy scoping, rate limits, OPA/Rego interop
- `internal/bypasssuite`, `internal/owaspmapping`, `internal/supplychain` — standards/bypass verification
- `pkg/sdk` — public Go SDK for HTTP integrations
- `examples/` — configs, policies, quickstart actions (used by smoke tests — keep working)
- `testdata/` — checked-in fixtures; prefer relative paths

## Conventions to preserve

- **Fail closed** on policy/config errors. Never introduce permissive fallbacks.
- **Reject unknown fields** on typed decoders unless the API explicitly supports extensions.
- Use **stable, descriptive rule IDs** in policy bundles.
- Never accept identity or environment from the agent/action body.
- Never log raw secrets or return them to agents; broker via lease IDs.
- Redact before any output leaves Nomos.
- Keep example configs and quickstart commands green — they are smoke-tested by CI and documented in README.

## Adjacent docs

- `AGENTS.md` — commit/PR conventions, testing approach, security/config notes.
- `DESIGN_NOTES.md` — deeper rationale on redirect handling, redaction scope, explain remediation.
- `TASKS.md` — the living milestone spec (Mxx milestones). **Gitignored**, so a fresh checkout will not have it; treat it as a developer-local source of truth when present.
