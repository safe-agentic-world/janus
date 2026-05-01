# Local Test Plan

## Purpose

This is the canonical end-to-end local validation plan for Nomos on Windows with PowerShell.

It is designed for an operator who is new to MCP and agent tooling and wants one holistic path that proves:

- the CLI works
- policy decisions are deterministic
- `doctor` reports the right readiness state
- the M63 agent launcher generates a Nomos-governed workspace for Claude Code and Codex
- the three default safe profiles (`safe-dev`, `ci-strict`, `prod-locked`) produce stable, hand-authored decisions
- Claude Code can use Nomos over MCP using either the launcher or manual registration
- friendly aliases (`read_file`, `write_file`, `apply_patch`, `run_command`, `http_request`) route to the canonical Nomos action types
- allowed actions succeed
- denied actions fail closed
- approvals (durable store), credentials, redaction, and gateway auth work as intended

This plan uses checked-in files wherever possible and calls out when a temporary local file is created.

## Scope

This plan covers:

- CLI commands: `version`, `policy test`, `policy explain`, `doctor`, `serve`, `mcp`, `run`, `approvals list`
- policy bundles: JSON and YAML; the three default profiles under `examples/policies/profiles/`
- transports: MCP stdio and HTTP
- action types: `fs.read`, `fs.write`, `repo.apply_patch`, `process.exec`, `net.http_request`, `secrets.checkout`
- friendly MCP tool surface: `read_file`, `write_file`, `apply_patch`, `run_command`, `http_request`
- M63 agent launcher: `nomos run codex` and `nomos run claude` with `--profile`, `--dry-run`, `--print-config`, `--no-launch`, `--write-instructions`, `--existing-mcp-config`
- auth modes: default bearer API key plus agent HMAC, with optional advanced checks
- approvals flow plus durable store inspection via `nomos approvals list`
- credential lease flow and no-leak behavior
- local best-effort mediation with Claude Code as the agent

## Claude Code Note

This plan follows the current Claude Code MCP workflow where MCP servers are added with `claude mcp add ...`.

If your local Claude Code build differs, check the current Claude Code MCP docs first and adapt only the registration command. The Nomos-side commands in this document remain the same.

## Preconditions

- Windows PowerShell
- `nomos` installed and on `PATH` (verify with `nomos version`)
- Claude Code installed and on `PATH` for the launcher and MCP scenarios
- Codex CLI on `PATH` only if you want to test `nomos run codex` end to end
- Python 3 available for the OpenAI-compatible example
- You are in the repo root:

```powershell
C:\Users\prudh\repos\safe-agentic-world\nomos
```

## Release Compatibility Note

The example policy set uses `exec_match` for generic `process.exec` policy matching, the example config uses ordered multi-bundle loading, and the launcher resolves default profiles from `examples/policies/profiles/`.

That means:

- the installed `nomos` binary must include at least M29 (generic exec matching), M30 (multi-bundle loading), M61 (durable approval store), M62 (MCP contract suite), and M63 (launcher + default profiles)
- older releases that do not understand `exec_match`, multi-bundle loading, or the launcher will fail `doctor`, `serve`, `mcp`, or `run` startup with the current example set

Quick compatibility check:

```powershell
nomos doctor -c .\examples\configs\config.example.json --format json
nomos run claude --no-launch --dry-run
```

Expected:

- `doctor` returns `policy.bundle_parses` and `policy.bundle_hash` passing
- `run claude --no-launch --dry-run` exits `0` and prints a workspace summary including a `Profile:` and `Policy hash:` line

## Test Philosophy

Run the scenarios in order.

The first half proves the product without relying on agent tooling. The middle proves the M63 launcher, default profiles, and the friendly tool surface. The second half proves the same boundary through Claude Code, then through the HTTP gateway, then through approvals and credentials.

If a scenario fails:

1. stop
2. capture the exact command, output, and file involved
3. do not skip ahead until the failure is understood

## Important Shell Note

Several later scenarios use PowerShell variables such as `$TmpDir`, `$ConfigAll`, `$ProfilesDir`, and `$CredsBundle`.

Those variables exist only in the PowerShell session where you ran the `One-Time Setup` block.

If you open a new terminal before running a later phase, run the `One-Time Setup` block again first.

For the early CLI and Claude Code phases, this document uses literal checked-in paths where possible so they work even if you did not keep the original shell session.

## 30-Minute Smoke Test

Use this when you want one fast, high-signal local proof before running the full plan.

### Smoke Test Goals

This smoke test proves:

- the installed CLI works
- the policy engine produces one deterministic allow and one deterministic deny against the safe quickstart bundle
- each of the three default M63 profiles parses and produces a stable bundle hash
- `doctor` is ready
- the M63 launcher generates a usable Claude Code workspace in `--dry-run`
- friendly MCP aliases are advertised under `--tool-surface friendly`
- a safe read succeeds through Nomos
- a sensitive read is denied through Nomos

### Smoke Test Steps

1. Verify the installed CLI:

```powershell
$Repo = (Resolve-Path .).Path
nomos version
```

2. Run deterministic CLI proof:

```powershell
nomos doctor -c .\examples\quickstart\config.quickstart.json --format json
nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\examples\policies\safe.yaml
nomos policy test --action .\examples\quickstart\actions\deny-env.json --bundle .\examples\policies\safe.yaml
```

3. Confirm the three M63 default profiles parse and emit a stable bundle hash:

```powershell
nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\examples\policies\profiles\safe-dev.yaml
nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\examples\policies\profiles\ci-strict.yaml
nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\examples\policies\profiles\prod-locked.yaml
```

Expected:

- each command prints `policy_bundle_hash` and the value is stable across re-runs
- `safe-dev` returns `ALLOW`, `ci-strict` returns `ALLOW`, `prod-locked` returns `ALLOW` for the README read

4. Dry-run the M63 Claude Code launcher (no agent process is started):

```powershell
nomos run claude --no-launch --dry-run --print-config
```

Expected:

- output begins with `No policy provided — using default profile: safe-dev`
- a `Nomos workspace active` block is printed with `Profile: safe-dev`, `Policy hash: <hash>`, `Assurance: BEST_EFFORT`
- the `Governed tools:` section maps `read_file -> fs.read`, `write_file -> fs.write`, `apply_patch -> repo.apply_patch`, `run_command -> process.exec`, `http_request -> net.http_request`
- `Generated MCP config:` block shows `nomos mcp -c <config> -p <profile> --tool-surface friendly --quiet`

5. Optional: register Nomos directly without the launcher (manual MCP path):

```powershell
$Repo = (Resolve-Path .).Path
$TmpDir = Join-Path $Repo ".tmp\manual-tests"
$ConfigExample = Join-Path $Repo "examples\configs\config.example.json"
$ConfigLocalAgent = Join-Path $TmpDir "config-local-agent.json"
New-Item -ItemType Directory -Force $TmpDir | Out-Null
$json = Get-Content -Raw $ConfigExample | ConvertFrom-Json
$json.executor.workspace_root = "C:\Users\prudh\repos\safe-agentic-world\implementation"
$json | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $ConfigLocalAgent
nomos doctor -c $ConfigLocalAgent

claude mcp add --transport stdio --scope local nomos-local -- "nomos" mcp -c "C:\Users\prudh\repos\safe-agentic-world\nomos\.tmp\manual-tests\config-local-agent.json" --tool-surface friendly
```

6. Verify the registration:

```powershell
claude mcp list
claude mcp get nomos-local
```

7. Start Claude Code:

```powershell
claude
```

8. In Claude Code, run these prompts in order:

```text
Use the nomos capabilities tool and show me the raw JSON result.
```

```text
Use the read_file tool from nomos to read file://workspace/README.md and show only the first 5 lines.
```

```text
Use the read_file tool from nomos to read file://workspace/.env
```

9. Remove the MCP server when done:

```powershell
claude mcp remove nomos-local
```

### Smoke Test Pass Criteria

The smoke test passes when:

- `doctor` returns `READY`
- the allow action returns `ALLOW` and the deny action returns `DENY`
- each default profile prints a stable `policy_bundle_hash`
- `nomos run claude --no-launch --dry-run` prints a complete workspace summary defaulting to `safe-dev`
- generated MCP config invokes `nomos mcp ... --tool-surface friendly --quiet`
- Claude Code shows a Nomos capability envelope
- `README.md` is readable via the friendly `read_file` alias
- `.env` is denied via `read_file`

## One-Time Setup

Run this once in PowerShell from the repo root:

```powershell
$Repo = (Resolve-Path .).Path
$TmpDir = Join-Path $Repo ".tmp\manual-tests"
$ConfigQuickstart = Join-Path $Repo "examples\quickstart\config.quickstart.json"
$ConfigExample = Join-Path $Repo "examples\configs\config.example.json"
$ConfigAll = Join-Path $Repo "examples\configs\config.all-fields.example.json"
$SafeYaml = Join-Path $Repo "examples\policies\safe.yaml"
$SafeJson = Join-Path $Repo "examples\policies\safe.json"
$AllFieldsYaml = Join-Path $Repo "examples\policies\all-fields.example.yaml"
$ProfilesDir = Join-Path $Repo "examples\policies\profiles"
$SafeDevYaml = Join-Path $ProfilesDir "safe-dev.yaml"
$CIStrictYaml = Join-Path $ProfilesDir "ci-strict.yaml"
$ProdLockedYaml = Join-Path $ProfilesDir "prod-locked.yaml"
$ConfigLocalAgent = Join-Path $TmpDir "config-local-agent.json"
New-Item -ItemType Directory -Force $TmpDir | Out-Null

$json = Get-Content -Raw $ConfigExample | ConvertFrom-Json
$json.executor.workspace_root = "C:\\Users\\prudh\\repos\\safe-agentic-world\\implementation"
$json | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $ConfigLocalAgent
```

## Phase 1: Install And Baseline

### Scenario 1: Verify the installed Nomos version

```powershell
nomos version
```

Expected:

- output contains `version=`
- output contains `go=`

### Scenario 2: Check root help

```powershell
nomos
```

Expected:

- exits non-zero
- lists `serve`, `mcp`, `policy`, `run`, `approvals`, and `doctor`

### Scenario 3: Optional repo validation

```powershell
go test ./...
```

Expected:

- all packages pass

## Phase 2: Deterministic CLI Proof

### Scenario 4: Run doctor against the quickstart config

```powershell
nomos doctor -c .\examples\quickstart\config.quickstart.json --format json
```

Expected:

- exit code `0`
- JSON contains `"overall_status":"READY"`

### Scenario 5: Verify one deterministic allow

```powershell
nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\examples\policies\safe.yaml
```

Expected:

- `decision` is `ALLOW`

### Scenario 6: Verify one deterministic deny

```powershell
nomos policy test --action .\examples\quickstart\actions\deny-env.json --bundle .\examples\policies\safe.yaml
```

Expected:

- `decision` is `DENY`

### Scenario 7: Verify YAML and JSON bundle parity

```powershell
nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\examples\policies\safe.yaml
nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\examples\policies\safe.json
```

Expected:

- both runs return `ALLOW`
- both runs return the same `policy_bundle_hash`

### Scenario 8: Explain a deny

```powershell
nomos policy explain --action .\examples\quickstart\actions\deny-env.json --bundle .\examples\policies\safe.yaml
```

Expected:

- output contains `why_denied`
- output contains `assurance_level`
- output contains a remediation hint

### Scenario 9: Missing bundle fails closed

```powershell
nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\.tmp\manual-tests\missing.yaml
```

Expected:

- exits non-zero
- reports `VALIDATION_ERROR`

### Scenario 10: Traversal is rejected before execution

If you are in a new PowerShell session, run `One-Time Setup` first so `$TmpDir` exists.

```powershell
$TraversalAction = Join-Path $TmpDir "action-traversal.json"
@'
{
  "schema_version": "v1",
  "action_id": "manual_traversal_1",
  "action_type": "fs.read",
  "resource": "file://workspace/../.env",
  "params": {},
  "principal": "system",
  "agent": "nomos",
  "environment": "dev",
  "context": { "extensions": {} },
  "trace_id": "manual_traversal_trace_1"
}
'@ | Set-Content -Encoding UTF8 $TraversalAction
nomos policy test --action $TraversalAction --bundle $SafeYaml
```

Expected:

- exits non-zero
- reports `NORMALIZATION_ERROR`

## Phase 3: M63 Default Safe Policy Profiles

The M63 launcher ships three hand-authored, enterprise-grade YAML profiles under `examples/policies/profiles/`. They are additive-only across releases — rule IDs and decisions must not silently drift. This phase exercises each profile against checked-in actions and a few inline ad-hoc actions.

### Scenario 11: All three profiles parse and emit a stable bundle hash

```powershell
nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle $SafeDevYaml
nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle $CIStrictYaml
nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle $ProdLockedYaml
```

Expected:

- each command prints a `policy_bundle_hash`
- re-running any command returns the same hash byte-for-byte

### Scenario 12: Secret read is DENY in every profile

```powershell
nomos policy test --action .\examples\quickstart\actions\deny-env.json --bundle $SafeDevYaml
nomos policy test --action .\examples\quickstart\actions\deny-env.json --bundle $CIStrictYaml
nomos policy test --action .\examples\quickstart\actions\deny-env.json --bundle $ProdLockedYaml
```

Expected:

- all three runs return `DENY`
- the matched rule ID is namespaced by profile (for example `safe-dev-deny-root-env-read`, `ci-strict-deny-root-env-read`, `prod-locked-deny-root-env-read`)

### Scenario 13: `safe-dev` golden decisions

Build a small set of inline action fixtures and run them through `safe-dev`:

```powershell
$ActSafeDevGitStatus = Join-Path $TmpDir "action-safe-dev-git-status.json"
@'
{
  "schema_version": "v1",
  "action_id": "act_safe_dev_git_status",
  "action_type": "process.exec",
  "resource": "file://workspace/",
  "params": { "argv": ["git", "status"] },
  "trace_id": "trace_safe_dev_git_status",
  "context": { "extensions": {} }
}
'@ | Set-Content -Encoding UTF8 $ActSafeDevGitStatus

$ActSafeDevGitPush = Join-Path $TmpDir "action-safe-dev-git-push.json"
@'
{
  "schema_version": "v1",
  "action_id": "act_safe_dev_git_push",
  "action_type": "process.exec",
  "resource": "file://workspace/",
  "params": { "argv": ["git", "push", "origin", "main"] },
  "trace_id": "trace_safe_dev_git_push",
  "context": { "extensions": {} }
}
'@ | Set-Content -Encoding UTF8 $ActSafeDevGitPush

nomos policy test --action $ActSafeDevGitStatus --bundle $SafeDevYaml
nomos policy test --action $ActSafeDevGitPush   --bundle $SafeDevYaml
```

Expected:

- `git status` returns `ALLOW` (matched by `safe-dev-allow-git-readonly`)
- `git push origin main` returns `REQUIRE_APPROVAL` (matched by `safe-dev-approve-git-push`)

### Scenario 14: `ci-strict` golden decisions

```powershell
$ActCIStrictTfDestroy = Join-Path $TmpDir "action-ci-strict-tf-destroy.json"
@'
{
  "schema_version": "v1",
  "action_id": "act_ci_strict_tf_destroy",
  "action_type": "process.exec",
  "resource": "file://workspace/",
  "params": { "argv": ["terraform", "destroy", "-auto-approve"] },
  "trace_id": "trace_ci_strict_tf_destroy",
  "context": { "extensions": {} }
}
'@ | Set-Content -Encoding UTF8 $ActCIStrictTfDestroy

nomos policy test --action $ActCIStrictTfDestroy --bundle $CIStrictYaml
```

Expected:

- `terraform destroy` returns `DENY`
- a CI-strict rule ID like `ci-strict-deny-tf-destroy` is reported

### Scenario 15: `prod-locked` golden decisions (writes are denied by default)

```powershell
$ActProdWrite = Join-Path $TmpDir "action-prod-locked-fs-write.json"
@'
{
  "schema_version": "v1",
  "action_id": "act_prod_locked_fs_write",
  "action_type": "fs.write",
  "resource": "file://workspace/notes.txt",
  "params": { "content": "hello" },
  "trace_id": "trace_prod_locked_fs_write",
  "context": { "extensions": {} }
}
'@ | Set-Content -Encoding UTF8 $ActProdWrite

nomos policy test --action $ActProdWrite                                 --bundle $ProdLockedYaml
nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle $ProdLockedYaml
```

Expected:

- the write returns `DENY` (matched by `prod-locked-deny-workspace-write`)
- the README read returns `ALLOW` (read-only inspection is allowed)

### Scenario 16: Profile bundles reject unknown fields

Create a deliberately broken copy of `safe-dev` and confirm it fails closed:

```powershell
$BadProfile = Join-Path $TmpDir "policy-bad-profile.yaml"
@'
version: v1
not_a_real_field: true
rules:
  - id: bad-allow
    action_type: fs.read
    resource: file://workspace/**
    decision: ALLOW
'@ | Set-Content -Encoding UTF8 $BadProfile

nomos policy test --action .\examples\quickstart\actions\allow-readme.json --bundle $BadProfile
```

Expected:

- exits non-zero
- error indicates an unknown field / strict YAML validation failure

### Scenario 17: Explain a `prod-locked` deny

```powershell
nomos policy explain --action $ActProdWrite --bundle $ProdLockedYaml
```

Expected:

- output contains `why_denied`
- the matched rule ID is `prod-locked-deny-workspace-write` (or another `prod-locked-*` deny)
- a remediation hint suggests the safe alternative

## Phase 4: M63 Agent Launcher

The launcher generates an MCP client config for Codex or Claude Code, loads a default profile when none is provided, prints a deterministic startup summary, and writes session metadata to the audit sink. It is the recommended path for "use Nomos as the default boundary" UX.

### Scenario 18: Default profile dry-run for Claude Code

```powershell
nomos run claude --no-launch --dry-run --print-config
```

Expected:

- first line: `No policy provided — using default profile: safe-dev`
- a `Nomos workspace active` block follows with:
  - `Agent: claude`
  - `Workspace: <repo root>`
  - `Profile: safe-dev`
  - `Policy bundle: ...\examples\policies\profiles\safe-dev.yaml`
  - `Policy hash: <hash>` (matches Phase 3 Scenario 11)
  - `Assurance: BEST_EFFORT`
  - `MCP config: <dry-run>`
- `Governed tools:` lists the five friendly aliases mapped to their canonical action types
- `Generated MCP config:` block contains `--tool-surface friendly` and `--quiet`
- a `Warning:` block explains best-effort and dual-tool ambiguity
- exit code `0`

### Scenario 19: Default profile dry-run for Codex

```powershell
nomos run codex --no-launch --dry-run --print-config
```

Expected:

- same shape as Scenario 18, but with `Agent: codex`

### Scenario 20: Explicit `--profile` selection

```powershell
nomos run claude --no-launch --dry-run --profile ci-strict
nomos run claude --no-launch --dry-run --profile prod-locked
```

Expected:

- each run prints `Profile: <name>` and the corresponding profile path
- `Policy hash` value matches the hash recorded in Phase 3 Scenario 11
- the no-policy-provided line does NOT appear when `--profile` is set

### Scenario 21: `-p <path>` and `--profile <name>` are mutually exclusive

```powershell
nomos run claude --no-launch --dry-run --profile safe-dev -p $SafeYaml
```

Expected:

- exits non-zero
- error message contains `--policy-bundle and --profile are mutually exclusive`

### Scenario 22: Unknown profile fails closed

```powershell
nomos run claude --no-launch --dry-run --profile does-not-exist
```

Expected:

- exits non-zero
- error indicates `unknown profile` and lists `safe-dev`, `ci-strict`, `prod-locked`

### Scenario 23: `--no-launch` writes a real MCP client config and a generated Nomos config

```powershell
nomos run claude --no-launch
```

Expected:

- Generated MCP client config exists at `.\.nomos\agent\session-*\claude.mcp.json`
- Generated Nomos config exists at `.\.nomos\agent\nomos.generated.json` (created when the workspace has no checked-in `nomos/config.json` or `.nomos/config.json`)
- Both files have owner-only / restrictive permissions on platforms that support them
- The MCP client config invokes `nomos mcp -c <generated config> -p <profile> --tool-surface friendly --quiet`
- An `agent.launcher.session` audit event is appended to the audit sink configured in the generated Nomos config

Inspect the files:

```powershell
Get-ChildItem .\.nomos\agent -Recurse -Force
Get-Content (Get-ChildItem .\.nomos\agent\session-* -Filter claude.mcp.json -Recurse | Select-Object -First 1).FullName
```

### Scenario 24: Bypass-path detection via `--existing-mcp-config`

Create a fake MCP client config that registers a non-Nomos shell server beside Nomos:

```powershell
$BypassMCP = Join-Path $TmpDir "existing.mcp.json"
@'
{
  "mcpServers": {
    "nomos":   { "command": "nomos", "args": ["mcp"] },
    "shell":   { "command": "some-shell-mcp", "args": [] },
    "github":  { "command": "some-github-mcp", "args": [] }
  }
}
'@ | Set-Content -Encoding UTF8 $BypassMCP

nomos run claude --no-launch --dry-run --existing-mcp-config $BypassMCP
```

Expected:

- output includes a warning of the form: `Possible bypass paths detected: existing MCP config also registers raw server(s): github, shell`
- exit code `0` (the launcher warns; it does not fail closed on dual-tool ambiguity in v1)

### Scenario 25: `--write-instructions` is fail-closed when target files already exist

In this repo `AGENTS.md` and `CLAUDE.md` are checked in, so this MUST fail closed:

```powershell
nomos run claude --no-launch --dry-run --write-instructions
```

Expected:

- exits non-zero
- error indicates `instruction file already exists` for `AGENTS.md` or `CLAUDE.md`
- no instruction files are mutated

To exercise the success path, run the launcher in a temp directory:

```powershell
$EmptyWS = Join-Path $TmpDir "empty-ws"
New-Item -ItemType Directory -Force $EmptyWS | Out-Null
Push-Location $EmptyWS
try {
  nomos run claude --no-launch --write-instructions
  Get-ChildItem -Recurse $EmptyWS
} finally {
  Pop-Location
}
```

Expected:

- `AGENTS.md`, `CLAUDE.md`, and `.codex/instructions.md` are created under `$EmptyWS`
- each file references `read_file`, `write_file`, `apply_patch`, `run_command`, `http_request`

### Scenario 25a: Default profile resolves from the embedded binary outside the nomos repo

This is the integrity check that the launcher's profile resolver is not coupled to a checkout of the nomos source repo. Enterprise installs (Homebrew, Scoop, installer, `go install`) ship the binary alone; the launcher must materialize the embedded profile to `~/.nomos/profiles/<name>.yaml` and use it.

```powershell
$DemoDir = Join-Path $TmpDir "demo-not-a-nomos-repo"
New-Item -ItemType Directory -Force $DemoDir | Out-Null
Push-Location $DemoDir
try {
  nomos run claude --no-launch --profile safe-dev 2>&1 | Select-String "Policy bundle:|Bundle source:|Policy hash:"
} finally {
  Pop-Location
}
```

Expected:

- `Bundle source: embedded (materialized to ~/.nomos/profiles/)`
- `Policy bundle:` points at `~/.nomos/profiles/safe-dev.yaml` (`$env:USERPROFILE\.nomos\profiles\safe-dev.yaml` on Windows)
- `Policy hash:` matches the safe-dev value pinned in `CHANGELOG.md` (currently `4d39231248c1f4887034b63745c7b8ec5ad3a3e78ccab4dffb3d31c7f9eaf93d`)

Verify the materialized file persisted:

```powershell
Get-Item "$env:USERPROFILE\.nomos\profiles\safe-dev.yaml" | Format-List FullName,Length,LastWriteTime
```

Expected:

- file exists and is non-empty
- a second invocation of `nomos run claude --no-launch --profile safe-dev` does NOT update `LastWriteTime` (idempotent rewrite)

### Scenario 25b: Verify `--mcp-config` is passed to Claude Code

This is the integrity check that the launcher actually attaches Nomos to the launched session. The launcher prints `MCP wiring: launcher passes --mcp-config to the agent (verified path)` for Claude. Confirm the resolved argv:

```powershell
nomos run claude --no-launch --print-config 2>&1 | Select-String "MCP wiring:"
```

Expected:

- output line: `MCP wiring:    launcher passes --mcp-config to the agent (verified path)`

Inspect the audit event written by the launcher:

```powershell
$Db = Join-Path $Repo ".nomos\agent\audit.db"
sqlite3 $Db "SELECT json_extract(payload_json, '$.executor_metadata.mcp_wiring_method'), json_extract(payload_json, '$.executor_metadata.agent_launch_argv') FROM audit_events WHERE event_type = 'agent.launcher.session' ORDER BY id DESC LIMIT 1;"
```

Expected:

- first column: `mcp_config_flag`
- second column: a JSON array starting with `"--mcp-config"` followed by the absolute path to `claude.mcp.json`
- the `default_boundary` field is NOT present (the launcher must not record un-verifiable integrity claims)

Then start Claude Code under the launcher (this DOES launch the agent — drop `--no-launch`):

```powershell
nomos run claude
```

Inside Claude, run:

```text
/mcp
```

Expected:

- the `nomos` server appears under the connected-servers list
- listing MCP tools (for example `What MCP tools are available?`) returns `read_file`, `write_file`, `apply_patch`, `run_command`, `http_request`

If `nomos` is missing from `/mcp`, the launcher's MCP wiring is broken — stop and capture: the launcher's printed `MCP wiring:` line, the resolved `agent_launch_argv` from audit, and the running `claude` argv (`Get-Process claude | Select CommandLine`). Do NOT issue prompts in this state — the session is ungoverned and any `git push`, `fs.write`, or shell command will bypass policy entirely.

### Scenario 25c: Codex is `operator-managed`, not auto-wired

```powershell
nomos run codex --no-launch 2>&1 | Select-String "MCP wiring:|launcher does NOT auto-wire"
```

Expected:

- `MCP wiring: operator-managed (launcher cannot auto-wire MCP for this agent)`
- a `Verify after launch:` block tells the operator to register the generated MCP config in `~/.codex/config.toml` before trusting the session
- the audit event records `mcp_wiring_method: "operator_managed"`

This is the staff-engineering correction for the prior CLI version, which set an unverified `CODEX_MCP_CONFIG` env var that Codex ignored — silently launching an ungoverned session while printing integrity claims.

### Scenario 26: Launcher generated config drives a real `nomos mcp` process

Use the artifact written by Scenario 23 to launch `nomos mcp` directly:

```powershell
$Generated = Get-ChildItem .\.nomos\agent\session-* -Filter claude.mcp.json -Recurse | Select-Object -First 1
$Cfg = Get-Content -Raw $Generated.FullName | ConvertFrom-Json
$Cfg.mcpServers.nomos.command
$Cfg.mcpServers.nomos.args -join " "
& $Cfg.mcpServers.nomos.command @($Cfg.mcpServers.nomos.args)
```

Expected:

- the printed command is `nomos`
- the printed args include `mcp`, `-c`, `-p`, `--tool-surface`, `friendly`, `--quiet`
- the spawned process starts and writes only its ready banner to stderr (stdout stays protocol-pure)

Stop the process with `Ctrl+C` before moving on.

## Phase 5: OpenAI-Compatible HTTP Example

### Scenario 27: Start Nomos in HTTP mode

In terminal 1:

```powershell
nomos serve -c .\examples\quickstart\config.quickstart.json
```

Expected:

- startup log shows `gateway listening on :8080 (http)`
- the usable local URL is `http://127.0.0.1:8080`

### Scenario 28: Run the checked-in Python example

In terminal 2:

```powershell
python .\examples\openai-compatible\nomos_http_loop.py
```

Expected:

- first request returns `ALLOW`
- second request returns `DENY`

Stop the server in terminal 1 with `Ctrl+C` before moving on.

## Phase 6: Claude Code As The Agent Over MCP

This is the main manual proof for agent mediation. The recommended flow is to use the launcher from Phase 4 to register Nomos as the only MCP server. A manual `claude mcp add` path is included as a fallback.

### Scenario 29: Run doctor for the manual Claude Code config

```powershell
nomos doctor -c .\.tmp\manual-tests\config-local-agent.json --format json
```

Expected:

- `READY`

### Scenario 30 (Recommended): Register Nomos with the M63 launcher

```powershell
nomos run claude --no-launch
$Generated = Get-ChildItem .\.nomos\agent\session-* -Filter claude.mcp.json -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
claude mcp add --transport stdio --scope local nomos-local -- @((Get-Content -Raw $Generated.FullName | ConvertFrom-Json).mcpServers.nomos.command, (Get-Content -Raw $Generated.FullName | ConvertFrom-Json).mcpServers.nomos.args) | Out-Null
```

If your shell makes the inline read awkward, use the simpler manual path in Scenario 31 instead.

Expected:

- `claude mcp list` shows `nomos-local`
- the registered command includes `--tool-surface friendly --quiet`

### Scenario 31 (Fallback): Register Nomos manually

Use absolute paths:

```powershell
claude mcp add --transport stdio --scope local nomos-local -- "nomos" mcp -c "C:\Users\prudh\repos\safe-agentic-world\nomos\.tmp\manual-tests\config-local-agent.json" --tool-surface friendly
```

Expected:

- the command succeeds without error
- this works because `config-local-agent.json` is generated from `examples/configs/config.example.json` and already sets `policy.policy_bundle_paths`

### Scenario 32: Verify the MCP registration

```powershell
claude mcp list
claude mcp get nomos-local
```

Expected:

- `nomos-local` is listed
- the command points to `nomos mcp -c ...`
- the args include `--tool-surface friendly`

### Scenario 33: Start Claude Code in the repo

```powershell
claude
```

Expected:

- Claude Code starts in the current workspace
- Nomos starts automatically as the configured MCP server

### Scenario 34: Inspect the capability envelope

In Claude Code, send this prompt:

```text
Use the nomos capabilities tool and show me the raw JSON result.
```

Expected:

- `enabled_tools` includes the Nomos MCP tool surface
- `tool_advertisement_mode` is `mcp_tools_list_static`
- approval-gated tools (for example `nomos.http_request` under `safe.yaml`, or `nomos.exec` for git push under `safe-dev`) appear under `approval_gated_tools` and `tool_states.<tool>.state == require_approval`
- response includes `assurance_level`
- on a local unmanaged machine, response includes a mediation notice

### Scenario 35: Friendly aliases are advertised

If you registered Nomos with `--tool-surface friendly`, the model-facing tool list should expose the M63 friendly aliases:

```text
List the MCP tools nomos exposes and show their names.
```

Expected:

- `read_file`, `write_file`, `apply_patch`, `run_command`, `http_request` appear
- the canonical `nomos_*` tool names are NOT advertised in friendly mode
- (with `--tool-surface both`, both forms appear)

### Scenario 36: Allowed read through Nomos

```text
Use the read_file tool to read file://workspace/README.md and show only the first 5 lines.
```

Expected:

- allowed
- content is returned

### Scenario 37: Denied secret file read through Nomos

```text
Use the read_file tool to read file://workspace/.env
```

Expected:

- denied
- no `.env` contents leak

### Scenario 38: Traversal attempt through Nomos

```text
Use the read_file tool to read file://workspace/../.env
```

Expected:

- denied with a normalization-style error
- no file contents leak

### Scenario 39: Allowed write through Nomos

```text
Use the write_file tool to write "manual test" into file://workspace/.tmp/manual-tests/mcp-write.txt
```

Expected:

- allowed
- file is created under `.tmp/manual-tests`

### Scenario 40: Allowed deterministic patch through Nomos

Before the prompt, create a file:

```powershell
"before patch" | Set-Content -Encoding UTF8 (Join-Path $TmpDir "mcp-patch.txt")
```

Then in Claude Code:

```text
Use the apply_patch tool to replace the contents of .tmp/manual-tests/mcp-patch.txt with "patched by nomos"
```

Expected:

- allowed
- file content is replaced (path + content replacement, not diff application)

### Scenario 41: Git read-only exec is allowed

```text
Use the run_command tool to run ["git","status"] in the workspace.
```

Expected:

- allowed
- `git status` output is returned
- under `safe.yaml` the allow comes from `safe-allow-git-exec`; under `safe-dev` the allow comes from `safe-dev-allow-git-readonly`

### Scenario 42: HTTP denied or approval-gated

```text
Use the http_request tool to fetch resource url://example.com/
```

Expected:

- under `safe.yaml`: denied by policy
- under `safe-dev`: `example.com` is not on the allowlist, so denied
- under `prod-locked`: denied unless explicitly allowlisted

### Scenario 43: Publish-boundary style check

```text
Use repo.validate_change_set for these paths: ["README.md",".tmp/manual-tests/mcp-write.txt"]
```

Expected:

- command returns a structured allow/block result
- if any path is blocked, record the exact blocked list

### Scenario 44: Practical mediation check

```text
Do not use built-in file tools. Use only Nomos tools. Read README.md, create .tmp/manual-tests/agent-note.txt, then tell me which Nomos tools you used.
```

Expected:

- Claude Code uses `read_file` and `write_file`
- the file is created
- no direct non-Nomos tool use is needed for the task

### Scenario 45: Git push to `main` is denied or approval-gated through Nomos

This is a higher-signal local demo because it shows a realistic dangerous action:

- safe repo inspection is allowed
- `git push origin main` is denied or approval-gated depending on the active profile

In Claude Code, run:

```text
Use only Nomos tools. Run run_command with ["git","status"] in the workspace and show me the result.
```

Expected:

- allowed
- Claude Code shows repo status through Nomos

Then run:

```text
Use only Nomos tools. Run run_command with ["git","push","origin","main"] in the workspace.
```

Expected:

- under `safe.yaml`: denied by `deny_by_rule` (git push deny rule)
- under `safe-dev`: returns `REQUIRE_APPROVAL` (matched by `safe-dev-approve-git-push`) — this is the M63 default, and demonstrates the approval-gated escalation flow
- under `ci-strict`: denied for non-allowlisted branches
- under `prod-locked`: denied (`prod-locked-deny-git-push`)

For a cleaner one-shot demo, you can also use:

```text
Use only Nomos tools. First run ["git","status"], then try ["git","push","origin","main"], and explain which action Nomos allowed and which it denied or approval-gated.
```

### Scenario 46: Remove the MCP server when you are done

Exit Claude Code, then run:

```powershell
claude mcp remove nomos-local
```

Expected:

- `nomos-local` is removed

## Phase 7: Standalone MCP Process Check

This validates Nomos MCP behavior directly, without Claude Code in the loop.

### Scenario 47: Start Nomos MCP directly

```powershell
nomos mcp -c .\.tmp\manual-tests\config-local-agent.json
```

Expected:

- process starts
- startup banner goes to stderr
- stdout remains reserved for MCP protocol bytes
- this works because `config-local-agent.json` already sets `policy.policy_bundle_paths`

Stop it with `Ctrl+C`.

### Scenario 48: Quiet mode

```powershell
nomos mcp -c .\.tmp\manual-tests\config-local-agent.json --quiet
```

Expected:

- no startup banner
- only errors are written to stderr

### Scenario 49: Friendly tool surface flag

```powershell
nomos mcp -c .\.tmp\manual-tests\config-local-agent.json --tool-surface friendly --quiet
```

Expected:

- starts cleanly (stderr is silent except on errors)
- a connected MCP client (Claude Code, MCP Inspector, etc.) sees `read_file`, `write_file`, `apply_patch`, `run_command`, `http_request` rather than the canonical `nomos_*` names

Stop it with `Ctrl+C`.

## Phase 8: Direct HTTP Gateway Validation

### Scenario 50: Start the HTTP gateway

In terminal 1:

```powershell
nomos serve -c .\.tmp\manual-tests\config-local-agent.json
```

### Scenario 51: Check health and version endpoints

In terminal 2:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/healthz
Invoke-RestMethod http://127.0.0.1:8080/version
```

Expected:

- `/healthz` returns `200`
- `/version` returns JSON

### Scenario 52: Create a helper to sign agent requests

Run this once in terminal 2:

```powershell
function New-NomosAgentSignature {
  param(
    [Parameter(Mandatory = $true)][string]$Body,
    [Parameter(Mandatory = $true)][string]$Secret
  )
  $hmac = [System.Security.Cryptography.HMACSHA256]::new([System.Text.Encoding]::UTF8.GetBytes($Secret))
  try {
    $hash = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Body))
    return ([System.BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
  } finally {
    $hmac.Dispose()
  }
}
```

### Scenario 53: Allowed HTTP `fs.read`

```powershell
$Body = @'
{
  "schema_version": "v1",
  "action_id": "http_read_1",
  "action_type": "fs.read",
  "resource": "file://workspace/README.md",
  "params": {},
  "trace_id": "http_read_trace_1",
  "context": { "extensions": {} }
}
'@
$Sig = New-NomosAgentSignature -Body $Body -Secret "dev-agent-secret"

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/action `
  -ContentType "application/json" `
  -Headers @{
    Authorization = "Bearer dev-api-key"
    "X-Nomos-Agent-Id" = "nomos"
    "X-Nomos-Agent-Signature" = $Sig
  } `
  -Body $Body
```

Expected:

- `decision` is `ALLOW`
- content is returned

### Scenario 54: Allowed HTTP `fs.write`

```powershell
$Body = @'
{
  "schema_version": "v1",
  "action_id": "http_write_1",
  "action_type": "fs.write",
  "resource": "file://workspace/.tmp/manual-tests/http-write.txt",
  "params": { "content": "written through gateway" },
  "trace_id": "http_write_trace_1",
  "context": { "extensions": {} }
}
'@
$Sig = New-NomosAgentSignature -Body $Body -Secret "dev-agent-secret"

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/action `
  -ContentType "application/json" `
  -Headers @{
    Authorization = "Bearer dev-api-key"
    "X-Nomos-Agent-Id" = "nomos"
    "X-Nomos-Agent-Signature" = $Sig
  } `
  -Body $Body
```

Expected:

- `decision` is `ALLOW`
- `bytes_written` is present

### Scenario 55: Missing auth is rejected

```powershell
Invoke-WebRequest `
  -Method Post `
  -Uri http://127.0.0.1:8080/action `
  -ContentType "application/json" `
  -Body $Body
```

Expected:

- HTTP `401`

### Scenario 56: Bad agent signature is rejected

Repeat Scenario 53, but set:

```powershell
$Sig = "deadbeef"
```

Expected:

- HTTP `401`

### Scenario 57: `/run` behaves like `/action`

Repeat Scenario 53 and post to:

```powershell
http://127.0.0.1:8080/run
```

Expected:

- same result as `/action`

Stop the gateway with `Ctrl+C` before moving on.

## Phase 9: Approval Flow (Durable Store)

The M61 durable approval store survives gateway restarts. This phase exercises the create -> decide -> replay flow plus the `nomos approvals list` inspection command.

### Scenario 58: Create an approvals-enabled config

```powershell
$ApprovalsConfig = Join-Path $TmpDir "config-approvals.json"
$ApprovalsStore = Join-Path $TmpDir "nomos-approvals.json"
$json = Get-Content -Raw $ConfigAll | ConvertFrom-Json
$json.approvals.enabled = $true
$json.approvals.backend = "file"
$json.approvals.store_path = $ApprovalsStore
$json.audit.sink = "stdout"
$json | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $ApprovalsConfig
```

### Scenario 59: Run doctor on the approvals config

```powershell
nomos doctor -c $ApprovalsConfig
```

Expected:

- `READY`

### Scenario 60: Start the approvals-enabled gateway

```powershell
nomos serve -c $ApprovalsConfig -p $AllFieldsYaml
```

### Scenario 61: Submit a request that requires approval

In a second terminal:

```powershell
$Body = @'
{
  "schema_version": "v1",
  "action_id": "approval_http_1",
  "action_type": "net.http_request",
  "resource": "url://api.example.com/v1/test",
  "params": { "method": "GET", "headers": {} },
  "trace_id": "approval_http_trace_1",
  "context": { "extensions": {} }
}
'@
$Sig = New-NomosAgentSignature -Body $Body -Secret "dev-agent-secret"
$Resp = Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/action `
  -ContentType "application/json" `
  -Headers @{
    Authorization = "Bearer dev-api-key"
    "X-Nomos-Agent-Id" = "nomos"
    "X-Nomos-Agent-Signature" = $Sig
  } `
  -Body $Body
$Resp
```

Expected:

- `decision` is `REQUIRE_APPROVAL`
- `approval_id` is present
- `approval_fingerprint` is present

### Scenario 62: List pending approvals via the durable store

```powershell
nomos approvals list --store $ApprovalsStore --backend file --format json
```

Expected:

- the response contains the `approval_id` from Scenario 61
- `status` is `pending`
- `expires_at` is in the future
- `principal`, `agent`, `environment`, and `action_type` (`net.http_request`) are populated

### Scenario 63: Approve the pending request

```powershell
$ApprovalId = $Resp.approval_id
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/approvals/decide `
  -ContentType "application/json" `
  -Body (@{ approval_id = $ApprovalId; decision = "approve" } | ConvertTo-Json)
```

Expected:

- response reason is `approval_recorded`

### Scenario 64: Approval persists across gateway restart

In terminal 1, stop the gateway with `Ctrl+C`, then restart it:

```powershell
nomos serve -c $ApprovalsConfig -p $AllFieldsYaml
```

In terminal 2, list approvals again:

```powershell
nomos approvals list --store $ApprovalsStore --backend file --format json
```

Expected:

- the previously approved entry is still recorded (M61 durable behavior)
- pending approvals from prior runs are still visible until they expire

### Scenario 65: Replay the same request with the approval ID

```powershell
$BodyReplay = @"
{
  "schema_version": "v1",
  "action_id": "approval_http_2",
  "action_type": "net.http_request",
  "resource": "url://api.example.com/v1/test",
  "params": { "method": "GET", "headers": {} },
  "trace_id": "approval_http_trace_2",
  "context": { "extensions": { "approval": { "approval_id": "$ApprovalId" } } }
}
"@
$SigReplay = New-NomosAgentSignature -Body $BodyReplay -Secret "dev-agent-secret"

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/action `
  -ContentType "application/json" `
  -Headers @{
    Authorization = "Bearer dev-api-key"
    "X-Nomos-Agent-Id" = "nomos"
    "X-Nomos-Agent-Signature" = $SigReplay
  } `
  -Body $BodyReplay
```

Expected:

- approval gate is satisfied
- the request is no longer blocked at `REQUIRE_APPROVAL`

### Scenario 66: Deny flow

Repeat Scenario 61 to get a fresh approval, then:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/approvals/decide `
  -ContentType "application/json" `
  -Body (@{ approval_id = $Resp.approval_id; decision = "deny" } | ConvertTo-Json)
```

Expected:

- denial is recorded
- subsequent `nomos approvals list` no longer shows that approval as pending

Stop the gateway before moving on.

## Phase 10: Credentials And Redaction

### Scenario 67: Create a temporary credentials policy and config

```powershell
$CredsBundle = Join-Path $TmpDir "policy-creds.yaml"
@'
version: v1
rules:
  - id: allow-secret-checkout
    action_type: secrets.checkout
    resource: secret://vault/github_token
    decision: ALLOW
  - id: allow-exec-with-secret
    action_type: process.exec
    resource: file://workspace/
    decision: ALLOW
    obligations:
      sandbox_mode: local
      exec_allowlist:
        - ["cmd", "/c", "echo", "%GITHUB_TOKEN%"]
'@ | Set-Content -Encoding UTF8 $CredsBundle

$CredsConfig = Join-Path $TmpDir "config-creds.json"
$json = Get-Content -Raw $ConfigLocalAgent | ConvertFrom-Json
$json.credentials.enabled = $true
$json.credentials.secrets = @(
  @{
    id = "github_token"
    env_key = "GITHUB_TOKEN"
    value = "manual-secret-token"
    ttl_seconds = 300
  }
)
$json.policy.policy_bundle_path = $CredsBundle
$json | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $CredsConfig
```

### Scenario 68: Start the gateway with the credentials config

```powershell
nomos serve -c $CredsConfig -p $CredsBundle
```

### Scenario 69: Checkout a secret lease

```powershell
$Body = @'
{
  "schema_version": "v1",
  "action_id": "secret_checkout_1",
  "action_type": "secrets.checkout",
  "resource": "secret://vault/github_token",
  "params": { "secret_id": "github_token" },
  "trace_id": "secret_checkout_trace_1",
  "context": { "extensions": {} }
}
'@
$Sig = New-NomosAgentSignature -Body $Body -Secret "dev-agent-secret"
$LeaseResp = Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/action `
  -ContentType "application/json" `
  -Headers @{
    Authorization = "Bearer dev-api-key"
    "X-Nomos-Agent-Id" = "nomos"
    "X-Nomos-Agent-Signature" = $Sig
  } `
  -Body $Body
$LeaseResp
```

Expected:

- `credential_lease_id` is returned
- the secret value is not returned

### Scenario 70: Use the lease in exec and verify redaction

```powershell
$LeaseId = $LeaseResp.credential_lease_id
$Body = @"
{
  "schema_version": "v1",
  "action_id": "secret_exec_1",
  "action_type": "process.exec",
  "resource": "file://workspace/",
  "params": {
    "argv": ["cmd", "/c", "echo", "%GITHUB_TOKEN%"],
    "env_allowlist_keys": ["GITHUB_TOKEN"],
    "credential_lease_ids": ["$LeaseId"]
  },
  "trace_id": "secret_exec_trace_1",
  "context": { "extensions": {} }
}
"@
$Sig = New-NomosAgentSignature -Body $Body -Secret "dev-agent-secret"

Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/action `
  -ContentType "application/json" `
  -Headers @{
    Authorization = "Bearer dev-api-key"
    "X-Nomos-Agent-Id" = "nomos"
    "X-Nomos-Agent-Signature" = $Sig
  } `
  -Body $Body
```

Expected:

- exec is allowed
- output does not contain `manual-secret-token`
- output contains a redacted replacement instead

### Scenario 71: Invalid lease binding fails

Repeat Scenario 70, but change only `trace_id` to a new value.

Expected:

- request fails
- error indicates lease binding mismatch or invalid lease use

Stop the gateway before moving on.

## Phase 11: Optional Hardened Checks

These are useful, but not required for the basic local proof.

### Scenario 72: OIDC auth path

Set up a local RSA keypair, configure `identity.oidc.enabled = true`, mint a valid RS256 JWT, and verify:

- invalid token is rejected
- valid token is accepted

### Scenario 73: mTLS gateway path

Create local TLS materials, enable:

- `gateway.tls.enabled = true`
- `gateway.tls.require_mtls = true`

Then verify:

- request without client cert is rejected
- request with valid client cert is accepted

### Scenario 74: Redirect policy

Use a policy that allows `net.http_request` with:

- `http_redirects: true`
- `http_redirect_hop_limit: 1`
- a matching `net_allowlist`

Then verify:

- redirects are denied by default without the obligation
- one allowed hop succeeds when the obligation is present
- the second hop is blocked by hop limit

## Cleanup

Stop any running `nomos` processes with `Ctrl+C`, then remove the Claude Code server if it still exists:

```powershell
claude mcp remove nomos-local
```

Optional cleanup of temp files and launcher artifacts:

```powershell
Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .\.nomos\agent -ErrorAction SilentlyContinue
```

Do NOT remove `.nomos/` if it contains a checked-in `config.json`.

## Pass Criteria

Nomos is locally validated when all of the following are true:

- the installed `nomos` CLI works and reports version info
- optional repo validation via `go test ./...` passes if you run it
- `doctor` reports `READY` for valid configs
- `policy test` returns one deterministic `ALLOW` and one deterministic `DENY` against `safe.yaml`
- each of `safe-dev.yaml`, `ci-strict.yaml`, `prod-locked.yaml` parses, has a stable `policy_bundle_hash`, denies secret reads, and matches its profile-namespaced rule IDs
- `policy explain` gives safe denial context including the matching profile rule ID
- `nomos run claude --no-launch --dry-run` and `nomos run codex --no-launch --dry-run` succeed and default to `safe-dev`
- `--profile` and `-p` are mutually exclusive and unknown profiles fail closed
- `--existing-mcp-config` warns when a non-Nomos MCP server is registered alongside Nomos
- `--write-instructions` fails closed when target files exist and succeeds in an empty workspace
- the OpenAI-compatible example works end to end
- Claude Code can use Nomos over MCP using either the launcher-generated config or manual registration
- friendly aliases (`read_file`, `write_file`, `apply_patch`, `run_command`, `http_request`) appear in `tools/list` under `--tool-surface friendly`
- allowed Nomos actions succeed in Claude Code
- denied Nomos actions fail closed in Claude Code
- direct HTTP gateway requests require auth and enforce policy
- approvals create, decide, and replay correctly, persist across gateway restarts (M61), and are inspectable via `nomos approvals list`
- credential leases never return raw secret values
- secret-bearing exec output is redacted before return

## If You Want One Minimal Proof Only

If you want the shortest high-signal proof, run only:

1. Phase 1
2. Phase 2
3. Phase 3 Scenarios 11 through 13 (default profiles + safe-dev golden decisions)
4. Phase 4 Scenarios 18 through 23 (launcher dry-run, profile selection, generated config)
5. Phase 6 Scenarios 30 through 37 (Claude Code over MCP using the launcher-generated config)
6. Phase 9 Scenarios 61 through 65 (approval create -> list -> approve -> replay)
7. Phase 10 Scenarios 69 through 70 (lease + redaction)

That gives you the quickest full story: CLI proof, profile proof, M63 launcher proof, agent mediation proof, durable approval proof, and secret redaction proof.
