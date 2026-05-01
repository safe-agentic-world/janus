# Agent Launcher

`nomos run` creates a Nomos-wrapped workspace profile for local Codex and Claude workflows.

## Problem Statement

Today, connecting Nomos as an MCP server is not sufficient to guarantee that agent actions are governed.

Agents may:

- select native tools over Nomos tools
- use raw upstream MCP servers directly
- bypass governance unintentionally

This makes Nomos feel optional and weakens both security guarantees and product adoption.

This feature makes Nomos the default execution boundary, not an optional tool the user must remember to mention.

## Commands

```bash
nomos run codex
nomos run claude
```

Useful setup modes:

```bash
nomos run codex --dry-run --print-config
nomos run claude --profile ci-strict --no-launch
nomos run codex --write-instructions --no-launch
```

Policy selection:

- `--policy-bundle, -p` uses a custom bundle.
- `--profile` selects `safe-dev`, `ci-strict`, or `prod-locked`.
- if neither is provided, Nomos prints `No policy provided — using default profile: safe-dev` and uses `safe-dev`.
- `--policy-bundle` and `--profile` are mutually exclusive.

## How The Launcher Wires MCP

The launcher writes a generated MCP client config at `.nomos/agent/session-*/<agent>.mcp.json` with the friendly tool surface and `--quiet`. How that config reaches the agent depends on the agent CLI:

- **Claude Code** — the launcher passes `--mcp-config <generated path>` directly to the `claude` invocation, so Nomos is attached for the launched session by construction. The summary prints `MCP wiring: launcher passes --mcp-config to the agent (verified path)` and the `agent.launcher.session` audit event records `mcp_wiring_method: "mcp_config_flag"` along with the resolved `agent_launch_argv`.
- **OpenAI Codex CLI** — Codex loads MCP servers from `~/.codex/config.toml` and has no documented one-shot equivalent of `--mcp-config`. The launcher does NOT silently set unverified env vars (the previous `CODEX_MCP_CONFIG` approach was a no-op). Instead the summary prints `MCP wiring: operator-managed (launcher cannot auto-wire MCP for this agent)` and instructs the operator to register the generated MCP config in `~/.codex/config.toml` before trusting the session. The audit event records `mcp_wiring_method: "operator_managed"`.

After the agent starts, run `/mcp` (Claude Code) or the equivalent in your codex session and confirm `nomos` is listed as a connected server and the friendly tools are visible. If `nomos` is missing or those tools are absent, the session is NOT governed — exit and reconfigure before issuing prompts. The launcher cannot verify the agent loaded the MCP config (the agent is a separate process); the post-launch checklist is the operator's verification step.

## Tool Surface

The launcher configures MCP with the friendly tool surface:

- `read_file` -> `fs.read`
- `write_file` -> `fs.write`
- `apply_patch` -> `repo.apply_patch`
- `run_command` -> `process.exec`
- `http_request` -> `net.http_request`

Audit, policy, explain, and approvals still use canonical action types. Existing compatibility names such as `nomos_fs_read` remain available outside friendly-only profile mode.

## Tool Surface Clarity

In workspace profile mode, Nomos should be the only exposed path for governed capabilities where possible.

If native or upstream tools remain available, the launcher warns explicitly. Dual-tool ambiguity, where both native and Nomos tools expose the same capability, is a bypass risk and must be surfaced to the user.

Do not register raw filesystem, shell, GitHub, Kubernetes, or other upstream MCP servers directly beside Nomos in the client. If an existing MCP config contains both Nomos and raw MCP servers, run:

```bash
nomos run codex --dry-run --existing-mcp-config path/to/client.mcp.json
```

Nomos will emit a possible-bypass warning for the extra server names.

Future enforcement mode can exclude non-Nomos MCP servers from generated configs.

## Threat Model Note

This improves default tool routing and reduces accidental bypass.

It does not provide:

- hard isolation on unmanaged laptops
- protection against deliberate user bypass
- guarantees when native tools remain enabled

Stronger guarantees require controlled runtimes such as containers, CI, or remote workspaces.

## Default Profiles

The launcher ships three standalone profiles under `examples/policies/profiles/`:

- `safe-dev`: local development, workspace edits allowed, secrets denied, risky publish/infra actions require approval, unknown egress denied.
- `ci-strict`: deterministic validation and structured artifact publishing allowed, package installs and mutations denied, unknown egress denied.
- `prod-locked`: read-only production inspection, writes/patches/mutations denied, narrow break-glass rollout approval.

Profile hashes are pinned in `testdata/policy-profiles/hashes.json` and mentioned in `CHANGELOG.md`. If a profile changes, update both intentionally.

## Generated Instructions

With `--write-instructions`, Nomos emits:

- `AGENTS.md`
- `CLAUDE.md`
- `.codex/instructions.md`

The generated instructions tell agents to use the governed tools and avoid native shell, native file, native patch, native internet, and raw upstream MCP paths when Nomos equivalents are available.
