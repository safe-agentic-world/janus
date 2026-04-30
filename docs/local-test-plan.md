# Local Test Plan

## Purpose

This is the canonical end-to-end local validation plan for Nomos on Windows with PowerShell.

It is designed for an operator who is new to MCP and agent tooling and wants one holistic path that proves:

- the CLI works
- policy decisions are deterministic
- `doctor` reports the right readiness state
- Claude Code can use Nomos over MCP
- allowed actions succeed
- denied actions fail closed
- approvals, credentials, redaction, and gateway auth work as intended

This plan uses checked-in files wherever possible and calls out when a temporary local file is created.

## Scope

This plan covers:

- CLI commands: `version`, `policy test`, `policy explain`, `doctor`, `serve`, `mcp`
- policy bundles: JSON and YAML
- transports: MCP stdio and HTTP
- action types: `fs.read`, `fs.write`, `repo.apply_patch`, `process.exec`, `net.http_request`, `secrets.checkout`
- auth modes: default bearer API key plus agent HMAC, with optional advanced checks
- approvals and replay
- credential lease flow and no-leak behavior
- local best-effort mediation with Claude Code as the agent

## Claude Code Note

This plan follows the current Claude Code MCP workflow where MCP servers are added with `claude mcp add ...`.

If your local Claude Code build differs, check the current Claude Code MCP docs first and adapt only the registration command. The Nomos-side commands in this document remain the same.

## Preconditions

- Windows PowerShell
- `nomos` installed from GitHub Releases and available on `PATH`
- Claude Code installed and on `PATH`
- Python 3 available for the OpenAI-compatible example
- You are in the repo root:

```powershell
C:\Users\prudh\repos\safe-agentic-world\nomos
```

## Release Compatibility Note

The current example policy set uses `exec_match` for generic `process.exec` policy matching and the usable example config uses ordered multi-bundle loading.

That means:

- the installed `nomos` binary must include the M29 and M30 implementations
- older releases that do not understand `exec_match` or multi-bundle loading will fail `doctor`, `serve`, or `mcp` startup with the current example config set

Quick compatibility check:

```powershell
nomos doctor -c .\examples\configs\config.example.json --format json
```

Expected result:

- `policy.bundle_parses` passes
- `policy.bundle_hash` passes

## Test Philosophy

Run the scenarios in order.

The first half proves the product without relying on agent tooling. The second half proves the same boundary through Claude Code, then through the HTTP gateway, then through approvals and credentials.

If a scenario fails:

1. stop
2. capture the exact command, output, and file involved
3. do not skip ahead until the failure is understood

## Important Shell Note

Several later scenarios use PowerShell variables such as `$TmpDir`, `$ConfigAll`, and `$CredsBundle`.

Those variables exist only in the PowerShell session where you ran the `One-Time Setup` block.

If you open a new terminal before running a later phase, run the `One-Time Setup` block again first.

For the early CLI and Claude Code phases, this document now uses literal checked-in paths where possible so they work even if you did not keep the original shell session.

## 30-Minute Smoke Test

Use this when you want one fast, high-signal local proof before running the full plan.

### Smoke Test Goals

This smoke test proves:

- the installed CLI works
- the policy engine produces one deterministic allow and one deterministic deny
- `doctor` is ready
- Claude Code can call Nomos over MCP
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

3. Create the local agent config used for Claude Code:

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
```

4. Register Nomos in Claude Code:

```powershell
claude mcp add --transport stdio --scope local nomos-local -- "nomos" mcp -c "C:\Users\prudh\repos\safe-agentic-world\nomos\.tmp\manual-tests\config-local-agent.json"
```

5. Verify the registration:

```powershell
claude mcp list
claude mcp get nomos-local
```

6. Start Claude Code:

```powershell
claude
```

7. In Claude Code, run these prompts in order:

```text
Use nomos.capabilities and show me the raw JSON result.
```

```text
Use nomos.fs_read to read file://workspace/README.md and show only the first 5 lines.
```

```text
Use nomos.fs_read to read file://workspace/.env
```

8. Remove the MCP server when done:

```powershell
claude mcp remove nomos-local
```

### Smoke Test Pass Criteria

The smoke test passes when:

- `doctor` returns `READY`
- the allow action returns `ALLOW`
- the deny action returns `DENY`
- Claude Code shows a Nomos capability envelope
- `README.md` is readable via `nomos.fs_read`
- `.env` is denied via `nomos.fs_read`

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
- lists `serve`, `mcp`, `policy`, and `doctor`

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

Create a temporary action:

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

## Phase 3: OpenAI-Compatible HTTP Example

### Scenario 11: Start Nomos in HTTP mode

In terminal 1:

```powershell
nomos serve -c .\examples\quickstart\config.quickstart.json
```

Expected:

- startup log shows `gateway listening on :8080 (http)`
- the usable local URL is `http://127.0.0.1:8080`

### Scenario 12: Run the checked-in Python example

In terminal 2:

```powershell
python .\examples\openai-compatible\nomos_http_loop.py
```

Expected:

- first request returns `ALLOW`
- second request returns `DENY`

Stop the server in terminal 1 with `Ctrl+C` before moving on.

## Phase 4: Claude Code As The Agent Over MCP

This is the main manual proof for agent mediation.

### Scenario 13: Run doctor for the Claude Code config

```powershell
nomos doctor -c .\.tmp\manual-tests\config-local-agent.json --format json
```

Expected:

- `READY`

### Scenario 14: Register Nomos as a Claude Code MCP server

Use absolute paths:

```powershell
claude mcp add --transport stdio --scope local nomos-local -- "nomos" mcp -c "C:\Users\prudh\repos\safe-agentic-world\nomos\.tmp\manual-tests\config-local-agent.json"
```

Expected:

- the command succeeds without error
- this works because `config-local-agent.json` is generated from `examples/configs/config.example.json` and already sets `policy.policy_bundle_paths`

### Scenario 15: Verify the MCP registration

```powershell
claude mcp list
claude mcp get nomos-local
```

Expected:

- `nomos-local` is listed
- the command points to `nomos.exe mcp -c ...`

### Scenario 16: Start Claude Code in the repo

```powershell
claude
```

Expected:

- Claude Code starts in the current workspace
- Nomos starts automatically as the configured MCP server

### Scenario 17: Inspect the capability envelope

In Claude Code, send this prompt:

```text
Use nomos.capabilities and show me the raw JSON result.
```

Expected:

- `enabled_tools` includes `nomos.fs_read`, `nomos.fs_write`, `nomos.apply_patch`, `nomos.exec`, and `nomos.http_request`
- `tool_advertisement_mode` is `mcp_tools_list_static`
- `immediate_tools` includes `nomos.fs_read`, `nomos.fs_write`, `nomos.apply_patch`, and `nomos.exec`
- `approval_gated_tools` includes `nomos.http_request`
- `tool_states.nomos.http_request.state` is `require_approval`
- response includes `assurance_level`
- on a local unmanaged machine, response should include a mediation notice

### Scenario 18: Allowed read through Nomos

Prompt:

```text
Use nomos.fs_read to read file://workspace/README.md and show only the first 5 lines.
```

Expected:

- allowed
- content is returned

### Scenario 19: Denied secret file read through Nomos

Prompt:

```text
Use nomos.fs_read to read file://workspace/.env
```

Expected:

- denied
- no `.env` contents leak

### Scenario 20: Traversal attempt through Nomos

Prompt:

```text
Use nomos.fs_read to read file://workspace/../.env
```

Expected:

- denied with a normalization-style error
- no file contents leak

### Scenario 21: Allowed write through Nomos

Prompt:

```text
Use nomos.fs_write to write "manual test" into file://workspace/.tmp/manual-tests/mcp-write.txt
```

Expected:

- allowed
- file is created under `.tmp/manual-tests`

### Scenario 22: Allowed deterministic patch through Nomos

Before the prompt, create a file:

```powershell
"before patch" | Set-Content -Encoding UTF8 (Join-Path $TmpDir "mcp-patch.txt")
```

Then in Claude Code:

```text
Use nomos.apply_patch to replace the contents of .tmp/manual-tests/mcp-patch.txt with "patched by nomos"
```

Expected:

- allowed
- file content is replaced

### Scenario 23: Git exec allowed under `safe`

Prompt:

```text
Use nomos.exec to run ["git","status"] in the workspace.
```

Expected:

- allowed
- `git status` output is returned
- the allow comes from the `safe-allow-git-exec` rule

### Scenario 24: HTTP denied under `safe`

Prompt:

```text
Use nomos.http_request to fetch resource url://example.com/
```

Expected:

- denied by policy

### Scenario 25: Publish-boundary style check

Prompt:

```text
Use repo.validate_change_set for these paths: ["README.md",".tmp/manual-tests/mcp-write.txt"]
```

Expected:

- command returns a structured allow/block result
- if any path is blocked, record the exact blocked list

### Scenario 26: Practical mediation check

Prompt:

```text
Do not use built-in file tools. Use only Nomos tools. Read README.md, create .tmp/manual-tests/agent-note.txt, then tell me which Nomos tools you used.
```

Expected:

- Claude Code uses `nomos.fs_read` and `nomos.fs_write`
- the file is created
- no direct non-Nomos tool use is needed for the task

### Scenario 27: Git push to `main` is denied through Nomos

This is a higher-signal local demo because it shows a realistic dangerous action:

- safe repo inspection is allowed
- `git push origin main` is denied

The shipped `safe` bundle now allows general git usage through Nomos, but it has an explicit deny rule for `git push`.

Start Claude Code again if needed:

```powershell
claude
```

In Claude Code, using your existing `nomos-local` MCP server, run this prompt first:

```text
Use only Nomos tools. Run nomos.exec with ["git","status"] in the workspace and show me the result.
```

Expected:

- allowed
- Claude Code shows repo status through Nomos
- the allow comes from the `safe-allow-git-exec` rule

Then run this prompt:

```text
Use only Nomos tools. Run nomos.exec with ["git","push","origin","main"] in the workspace.
```

Expected:

- denied by Nomos
- the effective reason should be `deny_by_rule`
- this demonstrates that general git usage can be allowed while pushes remain blocked by policy

For a cleaner one-shot demo, you can also use:

```text
Use only Nomos tools. First run ["git","status"], then try ["git","push","origin","main"], and explain which action Nomos allowed and which it denied.
```

### Scenario 28: Remove the MCP server when you are done

Exit Claude Code, then run:

```powershell
claude mcp remove nomos-local
```

Expected:

- `nomos-local` is removed

## Phase 5: Standalone MCP Process Check

This validates Nomos MCP behavior directly, without Claude Code in the loop.

### Scenario 29: Start Nomos MCP directly

```powershell
nomos mcp -c .\.tmp\manual-tests\config-local-agent.json
```

Expected:

- process starts
- startup banner goes to stderr
- stdout remains reserved for MCP protocol bytes
- this works because `config-local-agent.json` already sets `policy.policy_bundle_paths`

Stop it with `Ctrl+C`.

### Scenario 30: Quiet mode

```powershell
nomos mcp -c .\.tmp\manual-tests\config-local-agent.json --quiet
```

Expected:

- no startup banner
- only errors are written to stderr

## Phase 6: Direct HTTP Gateway Validation

### Scenario 31: Start the HTTP gateway

In terminal 1:

```powershell
nomos serve -c .\.tmp\manual-tests\config-local-agent.json
```

### Scenario 32: Check health and version endpoints

In terminal 2:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/healthz
Invoke-RestMethod http://127.0.0.1:8080/version
```

Expected:

- `/healthz` returns `200`
- `/version` returns JSON

### Scenario 33: Create a helper to sign agent requests

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

### Scenario 34: Allowed HTTP `fs.read`

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

### Scenario 35: Allowed HTTP `fs.write`

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

### Scenario 36: Missing auth is rejected

```powershell
Invoke-WebRequest `
  -Method Post `
  -Uri http://127.0.0.1:8080/action `
  -ContentType "application/json" `
  -Body $Body
```

Expected:

- HTTP `401`

### Scenario 37: Bad agent signature is rejected

Repeat Scenario 34, but set:

```powershell
$Sig = "deadbeef"
```

Expected:

- HTTP `401`

### Scenario 38: `/run` behaves like `/action`

Repeat Scenario 34 and post to:

```powershell
http://127.0.0.1:8080/run
```

Expected:

- same result as `/action`

Stop the gateway with `Ctrl+C` before moving on.

## Phase 7: Approval Flow

### Scenario 39: Create an approvals-enabled config

```powershell
$ApprovalsConfig = Join-Path $TmpDir "config-approvals.json"
$json = Get-Content -Raw $ConfigAll | ConvertFrom-Json
$json.approvals.enabled = $true
$json.approvals.backend = "file"
$json.approvals.store_path = ".\.tmp\manual-tests\nomos-approvals.json"
$json.audit.sink = "stdout"
$json | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $ApprovalsConfig
```

### Scenario 40: Run doctor on the approvals config

```powershell
nomos doctor -c $ApprovalsConfig
```

Expected:

- `READY`

### Scenario 41: Start the approvals-enabled gateway

```powershell
nomos serve -c $ApprovalsConfig -p $AllFieldsYaml
```

### Scenario 42: Submit a request that requires approval

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

### Scenario 43: Approve the pending request

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

### Scenario 44: Replay the same request with the approval ID

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

### Scenario 45: Deny flow

Repeat Scenario 42 to get a fresh approval, then:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/approvals/decide `
  -ContentType "application/json" `
  -Body (@{ approval_id = $Resp.approval_id; decision = "deny" } | ConvertTo-Json)
```

Expected:

- denial is recorded

Stop the gateway before moving on.

## Phase 8: Credentials And Redaction

### Scenario 46: Create a temporary credentials policy and config

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

### Scenario 47: Start the gateway with the credentials config

```powershell
nomos serve -c $CredsConfig -p $CredsBundle
```

### Scenario 48: Checkout a secret lease

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

### Scenario 49: Use the lease in exec and verify redaction

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

### Scenario 50: Invalid lease binding fails

Repeat Scenario 49, but change only `trace_id` to a new value.

Expected:

- request fails
- error indicates lease binding mismatch or invalid lease use

Stop the gateway before moving on.

## Phase 9: Optional Hardened Checks

These are useful, but not required for the basic local proof.

### Scenario 51: OIDC auth path

Set up a local RSA keypair, configure `identity.oidc.enabled = true`, mint a valid RS256 JWT, and verify:

- invalid token is rejected
- valid token is accepted

### Scenario 52: mTLS gateway path

Create local TLS materials, enable:

- `gateway.tls.enabled = true`
- `gateway.tls.require_mtls = true`

Then verify:

- request without client cert is rejected
- request with valid client cert is accepted

### Scenario 53: Redirect policy

Use a policy that allows `net.http_request` with:

- `http_redirects: true`
- `http_redirect_hop_limit: 1`
- a matching `net_allowlist`

Then verify:

- redirects are denied by default without the obligation
- one allowed hop succeeds when the obligation is present
- the second hop is blocked by hop limit

## Cleanup

Stop any running `nomos.exe` processes with `Ctrl+C`, then remove the Claude Code server if it still exists:

```powershell
claude mcp remove nomos-local
```

Optional cleanup of temp files:

```powershell
Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
```

## Pass Criteria

Nomos is locally validated when all of the following are true:

- the installed `nomos` CLI works and reports version info
- optional repo validation via `go test ./...` passes if you run it
- `doctor` reports `READY` for valid configs
- `policy test` returns one deterministic `ALLOW` and one deterministic `DENY`
- `policy explain` gives safe denial context
- the OpenAI-compatible example works end to end
- Claude Code can use Nomos over MCP
- allowed Nomos actions succeed in Claude Code
- denied Nomos actions fail closed in Claude Code
- direct HTTP gateway requests require auth and enforce policy
- approvals create, decide, and replay correctly
- credential leases never return raw secret values
- secret-bearing exec output is redacted before return

## If You Want One Minimal Proof Only

If you want the shortest high-signal proof, run only:

1. Phase 1
2. Phase 2
3. Phase 4 Scenarios 14 through 26
4. Phase 7 Scenarios 38 through 43
5. Phase 8 Scenarios 45 through 48

That gives you the quickest full story: CLI proof, agent mediation proof, approval proof, and secret redaction proof.
