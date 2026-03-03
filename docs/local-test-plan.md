# Local Test Plan

## Purpose

This plan is a full local validation pass for Nomos on Windows with PowerShell, covering:

- local build and unit tests
- CLI behavior
- policy engine behavior
- `doctor` readiness checks
- MCP integration with Claude Code
- HTTP gateway behavior
- approvals
- credentials and redaction
- security and failure cases

This plan is written against the current repository state on disk. It uses the existing sample configs and policies where possible, and temporary copies where feature toggles are required.

## Scope

This plan covers every implemented product surface in the current codebase:

- CLI commands: `version`, `serve`, `mcp`, `policy test`, `policy explain`, `doctor`
- transports: MCP stdio and HTTP
- action types: `fs.read`, `fs.write`, `repo.apply_patch`, `process.exec`, `net.http_request`, `secrets.checkout`
- policy bundle formats: JSON and YAML
- auth modes: API key + agent HMAC by default, plus optional service HMAC and OIDC
- approvals: pending, approve, deny, replay with approval ID
- audit sinks: stdout/stderr, optional sqlite
- enforcement edges: deny-by-default, path traversal, sandbox requirement, allowlists, redirect policy, output caps, redaction

## Preconditions

- Windows PowerShell
- Go installed and on `PATH`
- Claude Code installed and on `PATH`
- You are in the repo root: `C:\Users\prudh\repos\safe-agentic-world\nomos`

## One-Time Setup

Run these first in PowerShell from the repo root:

```powershell
$Repo = (Resolve-Path .).Path
$BinDir = Join-Path $Repo "bin"
$TmpDir = Join-Path $Repo ".tmp\manual-tests"
$NomosExe = Join-Path $BinDir "nomos.exe"
$ConfigCodex = Join-Path $Repo "config.codex.json"
$ConfigAll = Join-Path $Repo "config.all-fields.example.json"
$SafeDevYaml = Join-Path $Repo "policies\safe-dev.yaml"
$SafeDevJson = Join-Path $Repo "policies\safe-dev.json"
$MinimalJson = Join-Path $Repo "policies\minimal.json"
$AllFieldsYaml = Join-Path $Repo "policies\all-fields.example.yaml"
New-Item -ItemType Directory -Force $BinDir | Out-Null
New-Item -ItemType Directory -Force $TmpDir | Out-Null
```

## Build And Baseline

### Scenario 1: Run the automated test suite

```powershell
go test ./...
```

Expected:

- all packages pass
- no failing tests

### Scenario 2: Build Nomos locally

```powershell
go build -o $NomosExe .\cmd\nomos
```

Expected:

- `bin\nomos.exe` exists

### Scenario 3: Check build metadata

```powershell
& $NomosExe version
```

Expected:

- output contains `version=...`
- output contains `go=...`

### Scenario 4: Check root help

```powershell
& $NomosExe
```

Expected:

- exits non-zero
- prints command list including `serve`, `mcp`, `policy`, `doctor`

## CLI And Policy Engine

### Scenario 5: `policy test` with JSON bundle, allowed action

Create an allowed action file:

```powershell
$ActionAllow = Join-Path $TmpDir "action-allow-readme.json"
@'
{
  "schema_version": "v1",
  "action_id": "manual_policy_allow_1",
  "action_type": "fs.read",
  "resource": "file://workspace/README.md",
  "params": {},
  "principal": "system",
  "agent": "nomos",
  "environment": "dev",
  "context": { "extensions": {} },
  "trace_id": "manual_policy_allow_trace_1"
}
'@ | Set-Content -Encoding UTF8 $ActionAllow

& $NomosExe policy test --action $ActionAllow --bundle $MinimalJson
```

Expected:

- JSON output
- `decision` is `ALLOW`
- `policy_bundle_hash` is present

### Scenario 6: `policy test` with JSON bundle, denied action

```powershell
$ActionDeny = Join-Path $TmpDir "action-deny-other-file.json"
@'
{
  "schema_version": "v1",
  "action_id": "manual_policy_deny_1",
  "action_type": "fs.read",
  "resource": "file://workspace/TASKS.md",
  "params": {},
  "principal": "system",
  "agent": "nomos",
  "environment": "dev",
  "context": { "extensions": {} },
  "trace_id": "manual_policy_deny_trace_1"
}
'@ | Set-Content -Encoding UTF8 $ActionDeny

& $NomosExe policy test --action $ActionDeny --bundle $MinimalJson
```

Expected:

- `decision` is `DENY`
- `reason_code` reflects default deny or rule deny

### Scenario 7: `policy test` with YAML bundle

```powershell
& $NomosExe policy test --action $ActionAllow --bundle $SafeDevYaml
& $NomosExe policy test --action $ActionAllow --bundle $SafeDevJson
```

Expected:

- both commands succeed
- both decisions are `ALLOW`
- both return the same `policy_bundle_hash`

### Scenario 8: `policy explain` with denied action

```powershell
& $NomosExe policy explain --action $ActionDeny --bundle $MinimalJson
```

Expected:

- JSON output
- includes `assurance_level`
- includes `why_denied`
- includes `remediation_hint`

### Scenario 9: Missing bundle fails closed

```powershell
& $NomosExe policy test --action $ActionAllow --bundle (Join-Path $TmpDir "missing.json")
```

Expected:

- exits non-zero
- reports `VALIDATION_ERROR`

### Scenario 10: Invalid action shape is rejected

```powershell
$BadAction = Join-Path $TmpDir "action-invalid.json"
@'
{
  "schema_version": "v1",
  "action_id": "bad",
  "action_type": "fs.read",
  "resource": "file://workspace/README.md",
  "params": [],
  "principal": "system",
  "agent": "nomos",
  "environment": "dev",
  "context": { "extensions": {} },
  "trace_id": "bad_trace"
}
'@ | Set-Content -Encoding UTF8 $BadAction

& $NomosExe policy test --action $BadAction --bundle $SafeDevYaml
```

Expected:

- exits non-zero
- reports `VALIDATION_ERROR`

### Scenario 11: Path traversal normalization is rejected

```powershell
$TraversalAction = Join-Path $TmpDir "action-traversal.json"
@'
{
  "schema_version": "v1",
  "action_id": "traversal_1",
  "action_type": "fs.read",
  "resource": "file://workspace/../.env",
  "params": {},
  "principal": "system",
  "agent": "nomos",
  "environment": "dev",
  "context": { "extensions": {} },
  "trace_id": "traversal_trace_1"
}
'@ | Set-Content -Encoding UTF8 $TraversalAction

& $NomosExe policy test --action $TraversalAction --bundle $SafeDevYaml
```

Expected:

- exits non-zero
- reports `NORMALIZATION_ERROR`

## Doctor

### Scenario 12: `doctor` ready state

```powershell
& $NomosExe doctor -c $ConfigCodex
```

Expected:

- exits `0`
- shows `Result: READY`

### Scenario 13: `doctor` JSON mode

```powershell
& $NomosExe doctor -c $ConfigCodex --format json
```

Expected:

- JSON output
- includes `overall_status`
- includes `checks`
- includes `policy_bundle_hash`

### Scenario 14: `doctor` not-ready on missing bundle

Create a temporary broken config:

```powershell
$DoctorBadConfig = Join-Path $TmpDir "config-doctor-missing-bundle.json"
(Get-Content -Raw $ConfigCodex).Replace("policies\\safe-dev.yaml", "policies\\missing.yaml") | Set-Content -Encoding UTF8 $DoctorBadConfig
& $NomosExe doctor -c $DoctorBadConfig
```

Expected:

- exits `1`
- shows `NOT_READY`
- failing checks mention bundle path / parsing

### Scenario 15: Invalid format returns internal/usage error

```powershell
& $NomosExe doctor -c $ConfigCodex --format yaml
```

Expected:

- exits `2`
- prints invalid format message

## MCP With Claude Code

The commands below use the current Claude Code MCP syntax from the Claude Code MCP docs:

- local stdio syntax: `claude mcp add --transport stdio [options] <name> -- <command> [args...]`
- use `--scope project` if you want the server definition written to the project `.mcp.json`

Important Windows note:

- on native Windows, the `cmd /c` wrapper is required for local MCP servers launched through `npx`
- Nomos does not need that wrapper here because you are launching `nomos.exe` directly, not `npx`

Use absolute paths so the MCP registration works from any directory.

### Scenario 16: Register Nomos as a Claude Code MCP server

```powershell
claude mcp add --transport stdio --scope project nomos-local -- $NomosExe mcp -c $ConfigCodex -p $SafeDevYaml
```

Expected:

- server is added without error

If you want to verify the Windows `npx` rule separately, this is the correct pattern for native Windows:

```powershell
claude mcp add --transport stdio sample-npx-server -- cmd /c npx -y @some/package
```

Do not use that wrapper for the Nomos binary itself.

### Scenario 17: Verify the MCP registration

```powershell
claude mcp list
claude mcp get nomos-local
```

Expected:

- `nomos-local` is listed
- config shows a stdio command invoking Nomos

### Scenario 18: Start Claude Code and inspect capability envelope

Start Claude Code in the repo:

```powershell
claude
```

In the Claude Code session, run:

```text
Use nomos.capabilities and show me the JSON result.
```

Expected:

- enabled tools should include `nomos.fs_read`, `nomos.fs_write`, and `nomos.apply_patch`
- `nomos.exec` and `nomos.http_request` should not be enabled under `safe-dev`

### Scenario 19: MCP read allowed

In Claude Code:

```text
Use nomos.fs_read to read file://workspace/README.md and show only the first few lines.
```

Expected:

- allowed
- content returned
- output is capped if large

### Scenario 20: MCP read of a different workspace file allowed under `safe-dev`

In Claude Code:

```text
Use nomos.fs_read to read file://workspace/TASKS.md and summarize the first section.
```

Expected:

- allowed

### Scenario 21: MCP traversal attempt denied

In Claude Code:

```text
Use nomos.fs_read to read file://workspace/../.env
```

Expected:

- denied
- no file content leaks

### Scenario 22: MCP write allowed

In Claude Code:

```text
Use nomos.fs_write to write "manual test" into file://workspace/.tmp/manual-tests/mcp-write.txt
```

Expected:

- allowed
- file is created

### Scenario 23: MCP patch allowed

In Claude Code:

```text
Use nomos.apply_patch to replace the contents of .tmp/manual-tests/mcp-patch.txt with "patched by nomos"
```

Before running that prompt, create the file:

```powershell
"before patch" | Set-Content -Encoding UTF8 (Join-Path $TmpDir "mcp-patch.txt")
```

Expected:

- allowed
- file contents are replaced

### Scenario 24: MCP exec denied under `safe-dev`

In Claude Code:

```text
Use nomos.exec to run ["git","status"] in the workspace.
```

Expected:

- denied by policy

### Scenario 25: MCP HTTP denied under `safe-dev`

In Claude Code:

```text
Use nomos.http_request to fetch https://example.com
```

Expected:

- denied by policy

### Scenario 26: Current `repo.validate_change_set` behavior

In Claude Code:

```text
Use repo.validate_change_set for these paths: ["README.md",".tmp/manual-tests/mcp-write.txt"]
```

Expected:

- record the actual result returned by the current build
- under the current `safe-dev` policy, this may conservatively block paths because `ValidateChangeSet` evaluates `repo.apply_patch` against `file://workspace/...`

This scenario is a behavioral verification, not a policy expectation test.

### Scenario 27: Remove the MCP server when done

```powershell
claude mcp remove nomos-local
```

Expected:

- `nomos-local` is removed

## Standalone MCP Process

### Scenario 28: Start Nomos MCP directly

```powershell
& $NomosExe mcp -c $ConfigCodex -p $SafeDevYaml
```

Expected:

- process starts
- startup banner/logs go to stderr
- stdout remains protocol output only once a client connects

Stop it with `Ctrl+C`.

### Scenario 29: Quiet mode

```powershell
& $NomosExe mcp -c $ConfigCodex -p $SafeDevYaml --quiet
```

Expected:

- no startup banner
- only errors are emitted to stderr

## HTTP Gateway

### Scenario 30: Start the gateway

```powershell
& $NomosExe serve -c $ConfigCodex -p $SafeDevYaml
```

Expected:

- gateway starts on `:8080`

Leave it running in one terminal for the HTTP scenarios below.

### Scenario 31: Health endpoint

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8080/healthz
```

Expected:

- status `200`
- body `ok`

### Scenario 32: Version endpoint

```powershell
Invoke-RestMethod http://127.0.0.1:8080/version
```

Expected:

- JSON object with version fields

### Scenario 33: Prepare a helper to sign agent requests

Nomos requires principal auth and agent auth. With `config.codex.json`, principal auth is bearer API key and agent auth is HMAC over the raw request body.

Run this helper once:

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

### Scenario 34: HTTP `fs.read` allowed

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
- content is returned in `output`

### Scenario 35: HTTP `fs.write` allowed

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

### Scenario 36: HTTP `process.exec` denied by policy

```powershell
$Body = @'
{
  "schema_version": "v1",
  "action_id": "http_exec_1",
  "action_type": "process.exec",
  "resource": "file://workspace/",
  "params": { "argv": ["git", "status"] },
  "trace_id": "http_exec_trace_1",
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

- `decision` is `DENY`

### Scenario 37: Missing auth is rejected

```powershell
Invoke-WebRequest `
  -Method Post `
  -Uri http://127.0.0.1:8080/action `
  -ContentType "application/json" `
  -Body $Body
```

Expected:

- status `401`

### Scenario 38: Bad agent signature is rejected

Repeat Scenario 34 but set:

```powershell
$Sig = "deadbeef"
```

Expected:

- status `401`

### Scenario 39: Validation error on malformed request

```powershell
Invoke-WebRequest `
  -Method Post `
  -Uri http://127.0.0.1:8080/action `
  -ContentType "application/json" `
  -Headers @{
    Authorization = "Bearer dev-api-key"
    "X-Nomos-Agent-Id" = "nomos"
    "X-Nomos-Agent-Signature" = (New-NomosAgentSignature -Body '{"bad":true}' -Secret "dev-agent-secret")
  } `
  -Body '{"bad":true}'
```

Expected:

- status `400`

### Scenario 40: `/run` uses the same action path

Repeat Scenario 34 but post to:

```powershell
http://127.0.0.1:8080/run
```

Expected:

- same behavior as `/action`

## Approvals

Use a temporary config with approvals enabled and the existing `all-fields.example.yaml` bundle.

### Scenario 41: Create an approvals-enabled config

```powershell
$ApprovalsConfig = Join-Path $TmpDir "config-approvals.json"
$json = Get-Content -Raw $ConfigAll | ConvertFrom-Json
$json.approvals.enabled = $true
$json.approvals.store_path = ".\.tmp\manual-tests\nomos-approvals.db"
$json.audit.sink = "stdout"
$json | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $ApprovalsConfig
```

### Scenario 42: `doctor` on approvals config

```powershell
& $NomosExe doctor -c $ApprovalsConfig
```

Expected:

- ready if the config is valid

### Scenario 43: Start approvals-enabled gateway

```powershell
& $NomosExe serve -c $ApprovalsConfig -p $AllFieldsYaml
```

Expected:

- gateway starts on `:8080`

### Scenario 44: HTTP request that requires approval

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

### Scenario 45: Approve the pending request

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

### Scenario 46: Replay the action with the approval ID

```powershell
$BodyReplay = @"
{
  "schema_version": "v1",
  "action_id": "approval_http_2",
  "action_type": "net.http_request",
  "resource": "url://api.example.com/v1/test",
  "params": { "method": "GET", "headers": {} },
  "trace_id": "approval_http_trace_2",
  "context": { "extensions": { "approval_id": "$ApprovalId" } }
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

- approval is applied
- final outcome may still fail later with upstream/network error if the remote host is unreachable
- the important part is that the request is no longer blocked at the approval gate

### Scenario 47: Deny flow

Repeat Scenario 44 to get a fresh `approval_id`, then:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8080/approvals/decide `
  -ContentType "application/json" `
  -Body (@{ approval_id = $Resp.approval_id; decision = "deny" } | ConvertTo-Json)
```

Expected:

- approval is recorded as denied

## Credentials, Redaction, And Secret Handling

There is no shipped policy that allows `secrets.checkout`, so use a temporary bundle.

### Scenario 48: Create a temporary credentials bundle and config

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
$json = Get-Content -Raw $ConfigCodex | ConvertFrom-Json
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
$json | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $CredsConfig
```

### Scenario 49: Checkout a secret lease

Start the gateway with `$CredsConfig`, then send:

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
- secret value is not returned

### Scenario 50: Use the lease in exec, verify output redaction

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
- secret-like value is replaced/redacted

### Scenario 51: Invalid lease binding fails

Re-use the lease ID but change `trace_id` to a different value.

Expected:

- execution fails
- error indicates lease binding mismatch or invalid lease use

## Optional Advanced Auth Scenarios

These are implemented, but require extra local setup.

### Scenario 52: Service HMAC principal authentication

- create a temporary config from `config.all-fields.example.json`
- set `identity.service_secrets` to a real local value
- omit bearer API key
- send `X-Nomos-Service-Id` and `X-Nomos-Service-Signature` over the raw body

Expected:

- request authenticates as the service ID

### Scenario 53: OIDC principal authentication

- create a local RSA keypair
- configure `identity.oidc.enabled = true`
- point `identity.oidc.public_key_path` at the public key
- mint a valid RS256 JWT with matching issuer/audience/sub
- send it as `Authorization: Bearer <jwt>`

Expected:

- request authenticates

### Scenario 54: mTLS gateway requirement

- create local server cert, key, CA, and client cert
- enable `gateway.tls.enabled = true`
- enable `gateway.tls.require_mtls = true`
- call the gateway with and without the client certificate

Expected:

- without client cert: rejected
- with valid client cert: accepted

## Failure And Security Regression Scenarios

### Scenario 55: Oversized request body is rejected

- send a request larger than `64 KiB`

Expected:

- HTTP `400`

### Scenario 56: Unknown fields are rejected

- add an extra top-level field to the HTTP action request

Expected:

- HTTP `400`

### Scenario 57: Unsupported resource scheme is rejected

- use `resource: "ftp://example.com/file"`

Expected:

- normalization / validation failure

### Scenario 58: Encoded path separators are rejected

- use `file://workspace/%2e%2e%2fsecret.txt`

Expected:

- normalization failure

### Scenario 59: Exec cwd escape is rejected

- send `process.exec` with `"cwd": ".."`

Expected:

- denied or execution failure before command runs

### Scenario 60: Gateway rate-limits and breaker protections

This is easiest with a temporary config:

- set `gateway.rate_limit_per_minute` to `1`
- send two valid requests quickly

Expected:

- second request returns `429`

Then:

- set `gateway.circuit_breaker_failures` to `1`
- repeatedly trigger execution errors

Expected:

- later requests return `429` with circuit-open behavior

### Scenario 61: Redirects denied by default

Use a policy allowing `net.http_request` without `http_redirects: true`, then target a URL that returns a redirect.

Expected:

- redirect is denied

### Scenario 62: Redirects allowed only when explicitly enabled

Use a policy allowing `net.http_request` with:

- `http_redirects: true`
- `http_redirect_hop_limit: 1`
- matching `net_allowlist`

Expected:

- one allowed hop succeeds
- second hop is blocked by hop limit

### Scenario 63: Redaction of auth headers

- include `Authorization`, `Cookie`, or `X-Api-Key` values in HTTP action params or command output

Expected:

- returned output and audit output show `[REDACTED]`

## Cleanup

Stop any running `nomos.exe` process with `Ctrl+C`, then:

```powershell
claude mcp remove nomos-local
```

Optional cleanup of manual test artifacts:

```powershell
Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
```

## Suggested Execution Order

Run the plan in this order:

1. Build and baseline
2. CLI and policy engine
3. Doctor
4. MCP with Claude Code
5. Standalone MCP process
6. HTTP gateway
7. Approvals
8. Credentials and redaction
9. Optional advanced auth
10. Failure and security regression cases

## Pass Criteria

Nomos is locally validated when all of the following are true:

- the binary builds and the test suite passes
- `doctor` reports `READY` for valid configs and `NOT_READY` for broken ones
- `policy test` and `policy explain` behave deterministically for JSON and YAML bundles
- Claude Code can invoke Nomos over MCP
- allowed actions succeed and denied actions fail closed
- approvals create, decide, and replay correctly
- leases are issued and secrets do not leak in output
- gateway auth checks reject unsigned or malformed requests
- traversal, unsupported schemes, and redirect edge cases fail closed
