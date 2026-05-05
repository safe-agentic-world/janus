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
- **OpenAI Codex CLI** — current Codex accepts per-invocation config overrides with `-c mcp_servers.nomos.command=...` and `-c mcp_servers.nomos.args=[...]`. The launcher passes those overrides directly, so Nomos is attached for the launched session without mutating `~/.codex/config.toml`. The summary prints `MCP wiring: launcher passes Codex MCP config overrides (verified path)` and the `agent.launcher.session` audit event records `mcp_wiring_method: "codex_config_override"` along with the resolved `agent_launch_argv`.

After the agent starts, run `/mcp` (Claude Code) or the equivalent in your codex session and confirm `nomos` is listed as a connected server and the friendly tools are visible. If `nomos` is missing or those tools are absent, the session is NOT governed — exit and reconfigure before issuing prompts. The launcher cannot verify the agent loaded the MCP config (the agent is a separate process); the post-launch checklist is the operator's verification step.

For Codex specifically, `/mcp` remains the proof point. If `nomos run codex` opens Codex and `/mcp` reports no Nomos tools, the session is ungoverned and the launcher has a wiring bug or the local Codex CLI no longer honors the config override. Do not issue file, shell, HTTP, git, or upstream MCP prompts until `/mcp` confirms `nomos` is connected.

## Local Approvals

When the launcher generates a Nomos config, it enables a local file-backed approval store at `.nomos/approvals.json`. The launcher summary prints the resolved store path and the exact commands to inspect or approve pending requests:

```bash
nomos approvals list --store <workspace>/.nomos/approvals.json
nomos approvals approve --store <workspace>/.nomos/approvals.json <approval_id>
nomos approvals deny --store <workspace>/.nomos/approvals.json <approval_id>
```

Custom configs keep their own `approvals` settings. If a custom config disables approvals, `REQUIRE_APPROVAL` policy decisions remain visible as policy outcomes, but there may be no pending approval record to decide from the CLI.

Native client approvals are separate from Nomos approvals. If Codex or Claude asks you to approve a native shell, file, patch, HTTP, or git action after Nomos returned `DENY` or `REQUIRE_APPROVAL`, approving that native request leaves the Nomos boundary. Decide the pending request with `nomos approvals ...`, change policy, or stop the session; do not retry the same action through a native tool and call it governed.

## Tool Surface

The launcher configures MCP with the friendly tool surface:

- `read_file` -> `fs.read`
- `write_file` -> `fs.write`
- `apply_patch` -> `repo.apply_patch`
- `run_command` -> `process.exec`
- `http_request` -> `net.http_request`

Audit, policy, explain, and approvals still use canonical action types. Existing compatibility names such as `nomos_fs_read` remain available outside friendly-only profile mode.

## Tool Visibility Contract (M63 > M31 Precedence)

Direct governed tools (`read_file`, `write_file`, `apply_patch`, `run_command`, `http_request`, and their `nomos.*` canonical equivalents) are advertised in MCP `tools/list` whenever the active policy bundle has at least one `ALLOW` or `REQUIRE_APPROVAL` rule whose `action_type`, `principals`, `agents`, and `environments` fields match the calling identity. Resource pattern, params, and `exec_match` are deliberately ignored at advertisement time.

This is M63's "Nomos becomes the default execution boundary" precedence over M31's earlier probe-based hiding. The earlier behavior synthesized a stand-in action (e.g. `argv=["echo","sample"]` for `process.exec`, `url://example.com/status` for `net.http_request`) and ran it through full policy evaluation; if the probe hit default-deny, the tool was hidden from `tools/list`. Under realistic profiles like `safe-dev` whose exec allowlist excludes `echo` and whose HTTP allowlist excludes `example.com`, that behavior silently dropped governed tools the policy was perfectly willing to allow for legitimate inputs — and the agent escaped to native shell or HTTP to do the work, defeating the default-boundary promise.

The current behavior keeps the tool advertised so the agent uses the governed path, and policy still adjudicates each real call at execute time. Tools advertised under a profile whose only matching rule is `REQUIRE_APPROVAL` are surfaced with `_meta.approval_required: true`; the agent calls the tool normally and Nomos returns the approval gate.

Resource-aware hiding still applies to upstream MCP fanout (`mcp.call`), where each forwarded tool maps to a distinct `mcp://<server>/<tool>` resource and the per-tool resource pattern is the right granularity for visibility.

External-policy backend health is independent of this contract and remains fail-closed: when a configured external policy backend (e.g. an unreachable OPA) returns `deny_by_external_policy_error` on the discovery probe, the tool is hidden regardless of local capability scan, because the gateway cannot trust a future allow decision when the policy authority is unhealthy.

## Tool Surface Clarity

In workspace profile mode, Nomos should be the only exposed path for governed capabilities where possible.

If native or upstream tools remain available, the launcher warns explicitly. Dual-tool ambiguity, where both native and Nomos tools expose the same capability, is a bypass risk and must be surfaced to the user.

Native Codex/Claude approval prompts are part of that ambiguity. A native client approval is not cryptographically or semantically bound to the Nomos action fingerprint, so it cannot satisfy a Nomos approval gate and must be treated as an explicit bypass path.

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

The launcher ships three standalone profiles. The canonical YAML is at `profiles/<name>.yaml`; generated copies are embedded in the binary so the launcher works without a nomos source checkout on disk:

- `safe-dev`: local development, workspace edits allowed, secrets denied, risky publish/infra actions require approval, unknown egress denied.
- `ci-strict`: deterministic validation and structured artifact publishing allowed, package installs and mutations denied, unknown egress denied.
- `prod-locked`: read-only production inspection, writes/patches/mutations denied, narrow break-glass rollout approval.

Profile hashes are pinned in `testdata/policy-profiles/hashes.json`. If a profile changes, run `make pin-profile-hashes`; this regenerates the embedded copies at `internal/launcher/embedded_profiles/<name>.yaml` and refreshes the hash pins. `TestEmbeddedProfilesGeneratedFromCanonicalProfiles` fails if generated embedded YAMLs drift from `profiles/`.

Operators can inspect the profile set embedded in the running binary:

```bash
nomos profiles list
nomos profiles show safe-dev
nomos profiles verify
```

### Profile Bundle Source Resolution

When the launcher needs to load `<name>.yaml`, it tries three sources in order and prints the result as `Bundle source:` in its summary (and `profile_source` in the `agent.launcher.session` audit event):

1. **`workspace`** — `<workspaceRoot>/profiles/<name>.yaml`. Lets a nomos developer iterate on a profile YAML without rebuilding.
2. **`repo`** — the same path under the calling process's git root. Covers `go run ./cmd/nomos run claude` from a subdirectory.
3. **`embedded`** — materialized from the binary to `~/.nomos/profiles/<name>.yaml`. This is the path enterprise users hit: install via Homebrew/Scoop/installer, run `nomos run claude` from any project. The file is written atomically (tempfile + rename), with mode `0o600` where the platform supports it, and rewritten only when the on-disk content does not already match the embedded bytes.

The materialized path is stable across launcher invocations, so per-invocation Codex overrides or a persistent agent MCP config can reference `~/.nomos/profiles/<name>.yaml` and continue to point at the right file after the session-scoped artifacts under `.nomos/agent/session-*/` are cleaned up. When you upgrade the nomos binary, the next invocation rewrites the materialized file to match the new embedded YAML; verify the printed `Policy hash:` matches the value pinned in `testdata/policy-profiles/hashes.json` for the version you intend to run.

## Generated Instructions

With `--write-instructions`, Nomos emits:

- `AGENTS.md`
- `CLAUDE.md`
- `.codex/instructions.md`

The generated instructions tell agents to use the governed tools and avoid native shell, native file, native patch, native internet, and raw upstream MCP paths when Nomos equivalents are available.

They also instruct agents not to retry a Nomos `DENY` or `REQUIRE_APPROVAL` through native tools. This is a local `BEST_EFFORT` control: it improves default behavior, but hard prevention requires an environment where native tools are unavailable or separately blocked.
