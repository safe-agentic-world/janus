# Integration Kit

This guide covers local agent integration for Nomos using checked-in quickstart files and MCP stdio mode.

If you are starting from a fresh machine, install or build Nomos first:

```powershell
go build -o .\bin\nomos.exe .\cmd\nomos
```

Shared quickstart assets used below:

- [config.quickstart.json](../examples/quickstart/config.quickstart.json)
- [safe-dev-hardened.yaml](../policies/safe-dev-hardened.yaml)
- [allow-readme.json](../examples/quickstart/actions/allow-readme.json)
- [deny-env.json](../examples/quickstart/actions/deny-env.json)

## Codex Setup

1. Run a preflight check:

```powershell
.\bin\nomos.exe doctor -c .\examples\quickstart\config.quickstart.json --format json
```

2. Start the MCP server:

```powershell
.\bin\nomos.exe mcp -c .\examples\quickstart\config.quickstart.json -p .\policies\safe-dev-hardened.yaml
```

3. Register Nomos in Codex MCP configuration with the checked-in example:

- [codex.mcp.json](../examples/local-tooling/codex.mcp.json)

4. In Codex, issue one allowed and one denied request:

- allowed: ask to read `README.md` from the quickstart workspace
- denied: ask to read `.env` from the quickstart workspace

Expected behavior:

- `README.md` succeeds under `allow-root-markdown`
- `.env` is denied under `deny-root-env`

Troubleshooting:

- if MCP registration fails, confirm the command uses `mcp -c ... -p ...` and not stale flags
- if actions are denied unexpectedly, confirm Codex is targeting `examples/quickstart/workspace`
- if you see no startup banner, check whether `--quiet` is set

## Claude Code Setup

1. Run the same preflight:

```powershell
.\bin\nomos.exe doctor -c .\examples\quickstart\config.quickstart.json --format json
```

2. Start the MCP server:

```powershell
.\bin\nomos.exe mcp -c .\examples\quickstart\config.quickstart.json -p .\policies\safe-dev-hardened.yaml
```

3. Register Nomos using the checked-in example:

- [claude-code-mcp.json](../examples/local-tooling/claude-code-mcp.json)

4. In Claude Code, run the same two requests:

- allowed: read `README.md`
- denied: read `.env`

Troubleshooting:

- if Claude Code cannot connect, verify the MCP command path points to `.\bin\nomos.exe`
- if the wrong workspace is used, confirm the config file is [config.quickstart.json](../examples/quickstart/config.quickstart.json)
- in unmanaged local sessions, disable direct built-in file tools if you want Nomos to be the practical side-effect boundary

## OpenAI-Compatible Agent SDK Setup

Use the runnable local HTTP example:

- [nomos_http_loop.py](../examples/openai-compatible/nomos_http_loop.py)

1. Start Nomos:

```powershell
.\bin\nomos.exe serve -c .\examples\quickstart\config.quickstart.json -p .\policies\safe-dev-hardened.yaml
```

2. In a second terminal, run:

```powershell
python .\examples\openai-compatible\nomos_http_loop.py
```

What it demonstrates:

- a tool loop sending one governed action that returns `ALLOW`
- a second governed action that returns `DENY`
- deterministic handling of both responses over the HTTP API

Troubleshooting:

- if the script returns `401`, use the default checked-in key `dev-api-key`
- if the script returns `connection refused`, start `nomos serve` first
- if you want to point the example at a different host, set `NOMOS_BASE_URL`

## OpenClaw Setup

OpenClaw uses the same MCP stdio contract.

1. Start Nomos with:

```powershell
.\bin\nomos.exe mcp -c .\config.example.json -p .\policies\your-policy-bundle.json
```

2. Register Nomos in OpenClaw MCP server config with command `.\bin\nomos.exe` and args:
- `mcp`
- `-c`
- `.\config.example.json`
- `-p`
- `.\policies\your-policy-bundle.json`

## MCP Runtime UX

MCP mode keeps stdout protocol-only. Human-readable status/logs are written to stderr.

New flags:
- `--log-level error|warn|info|debug` (default `info`)
- `--log-format text|json` (default `text`)
- `--quiet` (equivalent to error-only; suppresses startup banner)

Default MCP runtime output behavior:
- one ready banner line on stderr after startup
- errors on stderr
- no non-protocol text on stdout

## CLI Ergonomics

`nomos mcp` now supports short aliases and env fallbacks with deterministic precedence.

Short flags:
- `-c` for `--config`
- `-p` for `--policy-bundle`
- `-l` for `--log-level`
- `-q` for `--quiet`

Env fallbacks:
- `NOMOS_CONFIG`
- `NOMOS_POLICY_BUNDLE`
- `NOMOS_LOG_LEVEL`

Precedence:
1. explicit CLI flag
2. environment variable
3. fail closed

Example:

```powershell
nomos mcp -c .\config.example.json -p .\policies\your-policy-bundle.json -l info
```

## Doctor Preflight

Use `nomos doctor` before connecting MCP clients to validate configuration and runtime readiness.

Examples:

```powershell
nomos doctor -c .\config.example.json
nomos doctor -c .\config.example.json --format json
```

Exit codes:
- `0` READY
- `1` NOT_READY
- `2` INTERNAL_ERROR

## MCP Config Examples

### Example: Generic MCP client JSON

```json
{
  "mcpServers": {
    "nomos": {
      "command": ".\\bin\\nomos.exe",
      "args": [
        "mcp",
        "-c",
        ".\\config.example.json",
        "-p",
        ".\\policies\\your-policy-bundle.json"
      ]
    }
  }
}
```

### Example: Strict approvals-enabled config fragment

```json
{
  "approvals": {
    "enabled": true,
    "store_path": ".\\nomos-approvals.db",
    "ttl_seconds": 900,
    "webhook_token": "replace-me"
  }
}
```

## Capabilities Explanation

Use `nomos.capabilities` to discover what tools are currently available for a principal/agent/environment under loaded policy.

Response fields:
- `enabled_tools`: policy-allowed tools (for example `nomos.fs_read`, `nomos.exec`).
- `sandbox_modes`: available sandbox mode envelope (`none` or `sandboxed` in current implementation).
- `network_mode`: `deny` or `allowlist` depending on policy-derived capability.
- `output_max_bytes`, `output_max_lines`: output caps returned to the client.
- `approvals_enabled`: whether approval workflow is configured.
- `assurance_level`: runtime-derived assurance label for the current mediation environment.
- `mediation_notice`: human-readable warning when the current runtime is not strong mediation.

The capability envelope is advisory; final authorization is still performed per action with deny-wins semantics.

## Unmanaged Laptop Limitations And Safe Workflows

In unmanaged developer laptops, mediation is best-effort. Nomos cannot guarantee that all side effects are forced through the gateway.

Safe workflow recommendations:
1. Keep policy deny-by-default and only allow required actions.
2. Require approvals for high-risk actions (`process.exec`, `net.http_request`, writes/patches in sensitive paths).
3. Use publish-boundary validation (`repo.validate_change_set`) before creating PRs.
4. Keep audit enabled (`stdout` + `sqlite`) and review `action.completed` events.
5. Avoid local direct credentials; pass only lease IDs in policy/executor metadata.

Operational note:
- Stronger enforcement guarantees are expected in controlled runtimes (`ci`, containers, and `k8s` runners).
- In local Claude Code or similar unmanaged setups, disable direct built-in file/shell tools if you want Nomos to be the only practical side-effect path.
- See `docs/assurance-levels.md` and `docs/guarantees.md` for the current assurance labels exposed in audit and `nomos policy explain`.
