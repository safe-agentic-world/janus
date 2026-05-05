# Launch Checklist

This checklist is optimized for shipping Nomos publicly to Hacker News and Reddit with strong technical credibility.

## T-7 Days

- run full release gate from `TESTING.md`
- confirm `docs/quickstart.md` works from clean checkout
- verify one deterministic allow and one deterministic deny flow
- validate `docs/release-verification.md` and supply-chain artifacts are current
- record a short terminal demo showing allow, deny, and doctor output

## T-1 Day

- freeze launch branch and avoid late behavioral changes
- rerun release gate (`go test`, `-race`, `go vet`, `doctor`)
- ensure README top section reflects exact current commands
- ensure README docs map points to the current primary path: quickstart, agent launcher, integration kit, local validation, policy language, approvals, MCP gateway
- verify policy starter bundles and config examples load cleanly
- verify `examples/README.md` matches the current examples tree
- verify launcher/profile/MCP changes updated `docs/agent-launcher.md`, `docs/integration-kit.md`, `docs/local-validation-plan.md`, and `docs/decisions/`
- prepare post drafts and screenshots

## Launch Day

### Release Hygiene

- tag release and publish changelog entry
- ensure install paths and release assets are available
- verify links in README and docs are not broken

### Proof Pack

- include exact terminal transcript for:
  - `nomos version`
  - `doctor --format json`
  - `policy test` allow
  - `policy test` deny
- include one architecture image or diagram
- include one threat model or guarantee reference link

### HN Post

- title should lead with concrete problem solved, not marketing
- first comment should include:
  - what Nomos does
  - what Nomos does not claim
  - quickstart commands
  - security model links

### Reddit Posts

- `r/opensource`: focus on implementation quality, tests, and docs
- `r/LocalLLaMA` or adjacent agent communities: focus on safe side-effect control for agent tooling
- avoid hype language, use reproducible commands and concrete outputs

## T+1 Day

- respond quickly to issue reports and setup failures
- capture recurring confusion and patch README within 24 hours
- convert repeated questions into FAQ or troubleshooting updates
- publish a short retrospective with what worked and what failed

## Post Templates

## HN Draft (Short)

`Show HN: Nomos, a zero-trust control plane for AI agent side effects`

Core points:

- deterministic policy gate for file, exec, network, and secret actions
- deny-by-default with auditable traces and output redaction
- works with MCP and HTTP, model-agnostic by design
- quick local proof with one ALLOW and one DENY in under 2 minutes

## Reddit Draft (Short)

`Open-source: Nomos for policy-gated AI agent execution (MCP + HTTP)`

Core points:

- practical boundary for agent side effects
- strict action schema, normalization, and policy evaluation
- redaction plus audit trail built in
- docs include threat model, assurance levels, and release verification

## Success Metrics

- first-hour stars, issues, and fork velocity
- quickstart completion feedback rate
- ratio of technical discussion to setup failure reports
- inbound integration interest from agent framework communities
