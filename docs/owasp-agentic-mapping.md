# OWASP Agentic Top 10 Mapping

This document maps Nomos to the OWASP Top 10 for Agentic Applications.

Mapped release:

- `OWASP Top 10 for Agentic Applications`
- initial public release published December 9, 2025
- stable category identifiers `ASI01` through `ASI10`

Coverage labels used here:

- `FULL`: Nomos implements direct, evidence-backed controls for the category within the stated environment bounds
- `PARTIAL`: Nomos mitigates meaningful parts of the category, but coverage depends on deployment mode, operator hardening, or adjacent controls
- `OUT_OF_SCOPE`: the category primarily targets behavior Nomos does not claim to govern directly in v1

Environment note:

- controlled runtimes (`ci` and `k8s`) can provide stronger guarantees
- unmanaged laptops remain best-effort for mediation-dependent controls
- see `docs/assurance-levels.md` and `docs/strong-guarantee-deployment.md`

## ASI01 — Agent Goal Hijack

Coverage: `PARTIAL`

Why it matters:

- goal hijack tries to steer an agent into unsafe side effects even when the user intent was benign

Relevant Nomos controls:

- deny-by-default policy with deny-wins evaluation
- explicit approvals for risky actions
- per-action normalization before authorization
- publish-boundary validation for repo changes

Relevant code and runtime surfaces:

- `internal/policy/policy.go`
- `internal/normalize/normalize.go`
- `internal/approval/store.go`
- `cmd/nomos/main.go`

Evidence:

- `internal/policy/policy_test.go`
- `docs/policy-explain.md`
- `docs/bypass-playbook.md`

Guarantee by environment:

- `ci` / `k8s`: stronger control over mediated side effects
- unmanaged laptop: best-effort only; the agent can still attempt side effects outside Nomos if the surrounding tooling allows it

Residual risk / bypass conditions:

- Nomos governs execution authority, not internal reasoning
- if an agent retains direct tools outside Nomos, goal hijack can still succeed outside the mediation boundary

## ASI02 — Tool Misuse & Exploitation

Coverage: `FULL`

Why it matters:

- agent tools are the main side-effect path, so unsafe tool invocation is the core attack surface Nomos is designed to mediate

Relevant Nomos controls:

- strict action schema validation
- deterministic policy gating for `fs`, `exec`, `http`, patch, and secrets actions
- output caps, allowlists, approvals, and circuit breakers
- redaction before outputs leave Nomos

Relevant code and runtime surfaces:

- `internal/action/action.go`
- `internal/service/service.go`
- `internal/executor/exec.go`
- `internal/executor/http.go`

Evidence:

- `internal/service/service_test.go`
- `internal/bypasssuite/bypasssuite_test.go`
- `docs/integration-kit.md`

Guarantee by environment:

- `ci` / `k8s`: strong or guarded for mediated actions
- unmanaged laptop: mediated actions remain governed, but direct non-Nomos tools remain outside scope

Residual risk / bypass conditions:

- coverage applies only to actions routed through Nomos
- direct shell/editor/browser access outside Nomos bypasses this control

## ASI03 — Identity & Privilege Abuse

Coverage: `PARTIAL`

Why it matters:

- if an agent can impersonate a stronger principal or hold broader credentials, every downstream policy decision becomes untrustworthy

Relevant Nomos controls:

- server-side identity verification
- no agent-supplied principal or environment claims
- API key, service HMAC, OIDC, and SPIFFE verification
- brokered credentials with lease IDs instead of raw secret return

Relevant code and runtime surfaces:

- `internal/identity/auth.go`
- `internal/credentials/broker.go`
- `internal/gateway/gateway.go`
- `internal/service/service.go`

Evidence:

- `internal/identity/auth_test.go`
- `internal/credentials/broker_test.go`
- `docs/egress-and-identity.md`
- `docs/spiffe-spire.md`

Guarantee by environment:

- controlled runtimes, especially `k8s`, are stronger when workload identity and no direct secret injection are enforced
- unmanaged laptop: best-effort because local credentials can still exist outside Nomos

Residual risk / bypass conditions:

- requires operator hardening to remove alternate credential paths
- shared keys remain weaker than workload identity

## ASI04 — Agentic Supply Chain Vulnerabilities

Coverage: `PARTIAL`

Why it matters:

- compromised policy bundles, MCP components, configs, or example integrations can shift the trust boundary underneath the operator

Relevant Nomos controls:

- optional policy bundle signature verification
- strict config decoding with unknown-field rejection
- MCP compatibility documentation and protocol constraints

Relevant code and runtime surfaces:

- `internal/policy/bundle.go`
- `internal/gateway/config.go`
- `internal/mcp/server.go`

Evidence:

- `internal/policy/bundle_signature_test.go`
- `internal/mcp/compatibility_test.go`
- `docs/mcp-compatibility.md`

Guarantee by environment:

- independent of runtime for config/policy verification
- release provenance, signing, and SBOM coverage are documented separately in the release verification and supply-chain security docs

Residual risk / bypass conditions:

- release verification helps establish trust in the shipped artifact, but operators still need to verify the policy bundle loaded by that runtime
- optional signature verification must be enabled and managed by operators

## ASI05 — Unexpected Code Execution (RCE)

Coverage: `PARTIAL`

Why it matters:

- agent-mediated code execution can turn prompt or tool misuse into direct host compromise if execution boundaries are weak

Relevant Nomos controls:

- explicit `process.exec` allowlists
- sandbox profile enforcement
- fail-closed denial when stronger sandbox is required but unavailable
- controlled-runtime hardening guidance

Relevant code and runtime surfaces:

- `internal/executor/exec.go`
- `internal/sandbox/sandbox.go`
- `internal/doctor/doctor.go`

Evidence:

- `internal/service/service_test.go`
- `internal/doctor/doctor_test.go`
- `docs/strong-guarantee-deployment.md`

Guarantee by environment:

- `k8s`: strongest current coverage when the surrounding runtime enforces container isolation
- unmanaged laptop: best-effort only

Residual risk / bypass conditions:

- requires operator hardening and real runtime isolation
- Nomos does not claim host-compromise resistance on unmanaged machines

## ASI06 — Memory & Context Poisoning

Coverage: `PARTIAL`

Why it matters:

- poisoned memory, prompts, or context can bias later actions even if the current request looks plausible

Relevant Nomos controls:

- strict request schema
- deterministic normalization
- no trust in agent-supplied principal or environment
- policy explanation and audit traceability for post-incident review

Relevant code and runtime surfaces:

- `internal/action/action.go`
- `internal/normalize/normalize.go`
- `internal/audit/audit.go`

Evidence:

- `internal/action/action_test.go`
- `internal/normalize/normalize_test.go`
- `docs/audit-schema.md`

Guarantee by environment:

- largely environment-independent for request validation
- stronger operational containment in controlled runtimes

Residual risk / bypass conditions:

- Nomos does not inspect or sanitize the agent's internal memory store
- protection is at the side-effect boundary, not the reasoning layer

## ASI07 — Insecure Inter-Agent Communication

Coverage: `PARTIAL`

Why it matters:

- spoofed or unsafe inter-agent messages can route harmful actions through a trusted execution boundary

Relevant Nomos controls:

- authenticated HTTP and MCP ingress
- verified principal and agent binding
- strict request schema with no hidden authority fields
- audit trace linkage for cross-system review

Relevant code and runtime surfaces:

- `internal/gateway/gateway.go`
- `internal/mcp/server.go`
- `internal/identity/auth.go`

Evidence:

- `internal/gateway/gateway_test.go`
- `internal/mcp/protocol_test.go`
- `docs/mcp-compatibility.md`

Guarantee by environment:

- stronger in controlled deployments with TLS, mTLS, OIDC, or SPIFFE
- weaker when clients share local trust surfaces or unaudited side channels

Residual risk / bypass conditions:

- Nomos does not secure non-Nomos inter-agent channels
- message authenticity depends on configured auth mode

## ASI08 — Cascading Failures

Coverage: `FULL`

Why it matters:

- unchecked retries, repeated failing actions, or broad fan-out can amplify small errors into system-wide impact

Relevant Nomos controls:

- rate limiting
- circuit breakers
- approvals for risky actions
- deterministic deny and fail-closed behavior when config is invalid

Relevant code and runtime surfaces:

- `internal/gateway/limits.go`
- `internal/gateway/gateway.go`
- `internal/doctor/doctor.go`

Evidence:

- `internal/gateway/gateway_test.go`
- `cmd/nomos/main_test.go`
- `docs/deployment.md`
- `docs/strong-guarantee-deployment.md`

Guarantee by environment:

- applies consistently at the Nomos boundary
- broader distributed coordination remains outside current scope

Residual risk / bypass conditions:

- in-memory limit state is process-local
- direct parallel side effects outside Nomos bypass these controls

## ASI09 — Human-Agent Trust Exploitation

Coverage: `PARTIAL`

Why it matters:

- polished agent output can cause a human operator to approve or trust a harmful action

Relevant Nomos controls:

- structured deny reasons
- `policy explain` with `why_denied` and remediation hints
- approvals tied to action fingerprints or bounded classes
- audit evidence for review

Relevant code and runtime surfaces:

- `cmd/nomos/main.go`
- `internal/approval/store.go`
- `internal/service/service.go`

Evidence:

- `cmd/nomos/main_test.go`
- `internal/approval/store_test.go`
- `docs/policy-explain.md`
- `docs/approvals.md`

Guarantee by environment:

- environment-independent for approval binding and explain surfaces
- stronger when organizations require Nomos-mediated approvals instead of ad hoc human review

Residual risk / bypass conditions:

- humans can still override policy outside Nomos
- Nomos reduces blind trust but cannot eliminate human judgment failures

## ASI10 — Rogue Agents

Coverage: `OUT_OF_SCOPE`

Why it matters:

- truly rogue or self-directed agents can pursue goals outside operator intent across time and channels

Relevant Nomos controls:

- deny-by-default execution boundary
- deterministic audit trail
- explicit assurance labeling to avoid overclaiming control

Relevant code and runtime surfaces:

- `internal/policy/policy.go`
- `internal/audit/audit.go`
- `internal/assurance/assurance.go`

Evidence:

- `internal/policy/policy_test.go`
- `internal/audit/audit_test.go`
- `docs/assurance-levels.md`

Guarantee by environment:

- Nomos can constrain mediated actions
- Nomos does not claim to govern internal long-horizon autonomy, self-modification, or off-platform behavior

Residual risk / bypass conditions:

- control is limited to the mediated side-effect boundary
- rogue planning or deception outside that boundary is out of scope for v1

## Reviewer Notes

- This mapping is intentionally conservative.
- `PARTIAL` does not mean "weak"; it means the control depends on deployment mode, operator hardening, or adjacent systems.
- See `docs/threat-model.md` for the threat assumptions that inform these ratings.
