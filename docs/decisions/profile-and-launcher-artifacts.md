# Profile And Launcher Artifacts

Status: accepted

## Context

Nomos ships default policy profiles, local agent launcher wiring, and examples for multiple integration surfaces. Earlier layouts had two sources of confusion:

- default profile YAML existed in more than one place
- static MCP client snippets could drift from the launcher behavior

Both patterns made local validation and release review harder than necessary.

## Decision

Default profiles are canonical under repo-root `profiles/`.

The launcher embeds generated profile copies under `internal/launcher/embedded_profiles/` so installed binaries work outside a Nomos source checkout. These embedded copies are generated artifacts, not a second hand-edited source.

`nomos run` is the primary local path for Claude Code and Codex:

- Claude Code receives the generated MCP config through `--mcp-config`.
- Codex receives per-invocation `mcp_servers.nomos.*` config overrides.
- Generated launcher configs enable a local file-backed approval store at `.nomos/approvals.json`.

Static MCP client examples under `examples/local-tooling/` were removed. Generic MCP config shape remains documented in `docs/integration-kit.md`, but Claude/Codex local testing should use `nomos run`.

## Consequences

Profile edits must update:

- `profiles/<name>.yaml`
- generated embedded copies via `make pin-profile-hashes`
- `testdata/policy-profiles/hashes.json`
- any release notes or validation docs affected by behavior changes

Docs and examples should not reintroduce duplicate default profile YAML or static Claude/Codex MCP config snippets.

When launcher behavior changes, update these docs in the same PR:

- `README.md`
- `docs/agent-launcher.md`
- `docs/integration-kit.md`
- `docs/local-validation-plan.md`
- `examples/README.md`

