# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and semantic versioning.

## [Unreleased]

### Security

- agent launcher now passes `--mcp-config <generated>` to `claude` so the launched Claude Code session is actually governed by Nomos. Previously the launcher set `CLAUDE_MCP_CONFIG` and `CODEX_MCP_CONFIG` environment variables that neither CLI honors, producing sessions that printed `Nomos workspace active` and recorded `default_boundary: true` in the audit log without any MCP server attached. The launcher now records `mcp_wiring_method` (`mcp_config_flag` for Claude, `operator_managed` for Codex) and the resolved `agent_launch_argv`, drops the un-verifiable `default_boundary` claim, and prints a `Verify after launch` block instructing operators to confirm `nomos` shows in `/mcp` before trusting the session.
- agent launcher default profiles now have a single public canonical source under `profiles/`. The embedded launcher copies are generated from that source by `make pin-profile-hashes`, and `testdata/policy-profiles/hashes.json` is the authoritative checked-in hash pin file.
- agent launcher now embeds the three default profile bundles (`safe-dev`, `ci-strict`, `prod-locked`) into the binary and materializes them to `~/.nomos/profiles/<name>.yaml` on demand. Previously the launcher only resolved profiles via `<workspaceRoot>/profiles/` or the calling process's git root, so `nomos run` failed closed for every enterprise install path (Homebrew, Scoop, installer script, `go install`) when run from any project directory that was not a checkout of the nomos source repo. The new `Bundle source:` line in the launcher summary and the `profile_source` audit field disclose which tier (`workspace`, `repo`, or `embedded`) was used.
- MCP `tools/list` now advertises any direct governed tool (`read_file`, `write_file`, `apply_patch`, `run_command`, `http_request` and the canonical `nomos.*` aliases) whose action_type has at least one matching `ALLOW` or `REQUIRE_APPROVAL` rule for the calling identity, replacing the prior synthetic-probe approach that hid governed tools whenever the placeholder probe (e.g. `argv=["echo","sample"]` for exec, `url://example.com/status` for HTTP) hit a default-deny rule under realistic profiles like `safe-dev`. Under the previous behavior, an agent running with `nomos run claude --profile safe-dev` saw only `read_file`, `write_file`, `apply_patch`, and `nomos_capabilities` in its tool list — `run_command` and `http_request` silently disappeared and the agent escaped to native shell to perform governed actions, defeating M63's "Nomos becomes the default execution boundary" promise. The new rule-based capability scan in `internal/mcp/tool_discovery.go` decides direct-tool visibility from action_type + identity only (ignoring resource pattern, params, and exec_match), establishing M63 precedence over M31's resource-aware probe-based hiding for direct tools. Resource-aware hiding still applies to upstream MCP fanout (`mcp.call`) where each forwarded tool maps to a distinct `mcp://` resource. External-policy backend health is still fail-closed: if a configured external policy (e.g. an unreachable OPA) returns `deny_by_external_policy_error` on the discovery probe, the tool is hidden regardless of local capability scan.

### Added

- strong-guarantee deployment guidance and conservative readiness checks (`runtime.strong_guarantee`)
- deterministic `assurance_level` derivation in audit and `nomos policy explain`
- `assurance_level` and `mediation_notice` in `nomos.capabilities`
- normalization corpus, redirect controls, and bypass-suite validation coverage
- corpus-backed redaction harness and secret no-leak integration coverage
- actionable `policy explain` denial context and remediation hints
- workflow-managed release publishing with multi-arch archives, checksums, Homebrew tap updates, and Scoop manifest updates
- `safe` starter policy bundle for safer local file mediation defaults
- default workspace profiles `safe-dev`, `ci-strict`, and `prod-locked`; current hashes are pinned in `testdata/policy-profiles/hashes.json`
- `nomos profiles list|show|verify` for inspecting the default profiles embedded in the running binary

### Changed

- MCP runtime output isolation to keep stdout protocol-safe
- MCP tool-call adapter compatibility for current Claude Code wrapper shapes (`input` and extra wrapper metadata)
- MCP file-tool error mapping now distinguishes `normalization_error`, `not_found`, and `execution_error`
- release build metadata injection support for `Version`, `Commit`, `BuildDate`
- release assets now publish archives (`.tar.gz` / `.zip`) instead of raw binaries
- install guidance now centers on `go install`, GitHub Releases, Homebrew tap, Scoop, and the provided installer script
