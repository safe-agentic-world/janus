# Local Rebuild, MCP Registration, And Demo Capture Plan

This is the local demo runbook for rebuilding `nomos.exe`, re-registering it as an MCP server, and capturing screenshots or screen recordings for README and launch posts.

The goal is to produce a short set of proof assets that show:

- Nomos is the MCP boundary for local agent actions
- safe actions are allowed without friction
- risky actions are denied or approval-gated
- the behavior is visible in structured capability and result payloads

---

## Demo Assets To Capture

Capture these as either separate screenshots or one short recording:

1. `nomos version` and `nomos doctor` proving the local binary and config are active
2. `nomos.capabilities` raw JSON showing:
   - `tool_advertisement_mode: "mcp_tools_list_static"`
   - `tool_states.nomos.exec.state`
   - `tool_states.nomos.http_request.state`
   - `approval_gated_tools`
   - `approvals_enabled`
3. allowed write demo:
   - agent writes `file://workspace/dummy.txt`
4. allowed exec demo:
   - agent runs `git status`
5. denied exec demo:
   - agent tries `git push origin main`
6. approval-gated HTTP demo:
   - agent tries a purchase POST to `url://shop.example.com/checkout/cart-123`
7. denied order-placement demo:
   - agent tries a purchase POST to `url://payments.example.com/orders/cart-123`
8. denied OpenClaw purchase demo:
   - OpenClaw attempts a direct order placement and Nomos denies it

Recommended README order:

1. capabilities screenshot
2. denied `git push` screenshot
3. approval-required purchase screenshot
4. denied order-placement screenshot
5. denied OpenClaw purchase screenshot
6. optional short GIF/video of the full flow

---

## Pre-Conditions

Use:

- this repo checked out locally
- Claude Code installed
- Go installed and on `PATH`
- the Nomos example config at:
  - `C:\Users\prudh\repos\safe-agentic-world\nomos\examples\configs\config.example.json`

Important:

- the config path below is absolute on purpose
- `executor.workspace_root` is left empty in `config.example.json`
- that means Nomos will govern the current working directory of the launched Claude session
- start Claude in the repo or workspace you want Nomos to govern

---

## Step 1. Remove The Previous Local Build

```powershell
if (Test-Path "$env:USERPROFILE\go\bin\nomos.exe") { Remove-Item -Force "$env:USERPROFILE\go\bin\nomos.exe" }
```

---

## Step 2. Rebuild Local `nomos.exe`

Run from the Nomos repo root:

```powershell
& "C:\Program Files\PowerShell\7\pwsh.exe" -Command "go build -o '$env:USERPROFILE\go\bin\nomos.exe' ./cmd/nomos"
```

---

## Step 3. Verify The Local Binary

```powershell
Get-Command nomos | Format-List Source
nomos version
nomos doctor -c C:\Users\prudh\repos\safe-agentic-world\nomos\examples\configs\config.example.json
```

Expected:

- `Source` points to `C:\Users\prudh\go\bin\nomos.exe`
- `nomos version` shows the local build metadata, often including `+dirty` during development
- `nomos doctor` succeeds against the example config
- `policy.bundle_parses` and `policy.bundle_hash` pass

Capture:

- one terminal screenshot showing `Source`, `version`, and the successful doctor result

---

## Step 4. Re-Register Claude Code MCP

```powershell
claude mcp remove nomos-local
claude mcp add --transport stdio --scope local nomos-local -- "$env:USERPROFILE\\go\\bin\\nomos.exe" mcp -c "C:\Users\prudh\repos\safe-agentic-world\nomos\examples\configs\config.example.json"
claude mcp list
claude mcp get nomos-local
```

Expected:

- `nomos-local` exists as a local stdio MCP server
- the command points to your freshly rebuilt `nomos.exe`
- the config path is the absolute Nomos example config path

Capture:

- optional screenshot of `claude mcp get nomos-local`

---

## Step 5. Start Claude In The Governed Workspace

Start Claude from the repo or target workspace you want Nomos to govern:

```powershell
claude
```

For Nomos screenshots, the cleanest choice is to launch Claude from a test repo or from this repo root.

---

## Step 6. Run The Demo Prompts

Run these prompts one by one.

### 6.1 Capabilities Probe

```text
Use nomos.capabilities and show me the raw JSON result.
```

Expected:

- `nomos.exec` appears in the surfaced tools
- `nomos.http_request` appears in the surfaced tools
- `tool_advertisement_mode` is `mcp_tools_list_static`
- `tool_states.nomos.exec.state` is `allow` or `mixed`
- `tool_states.nomos.http_request.state` is `require_approval`
- `approval_gated_tools` includes `nomos.http_request`
- `approvals_enabled` is `true`

Capture:

- screenshot of the raw JSON result

This is the best “setup proof” screenshot for the README because it shows that Nomos is exposing a policy-aware contract instead of naive unrestricted tools.

### 6.2 Allowed File Write

```text
Use nomos.fs_write to write "This is a dummy text file." into file://workspace/dummy.txt
```

Expected:

- the action succeeds
- `dummy.txt` is created in the governed workspace

Capture:

- screenshot of the successful response

This is your “Nomos does not block everything” proof.

### 6.3 Allowed Exec

```text
Use only Nomos tools. Run nomos.exec with ["git","status"] in the workspace.
```

Expected:

- the action is allowed
- the result includes the `git status` output

Capture:

- screenshot of the successful `git status` response

### 6.4 Denied Exec

```text
Use only Nomos tools. Run nomos.exec with ["git","push","origin","main"] in the workspace.
```

Expected:

- the action is denied by policy
- the response shows a deny result rather than a shell result

Capture:

- screenshot of the denied `git push origin main` result

This should be one of the headline README assets.

### 6.5 Approval-Gated HTTP Purchase Attempt

```text
Use only Nomos tools. Send a POST request to resource url://shop.example.com/checkout/cart-123 to purchase the item. Show me the raw Nomos result, including any approval_id or approval_fingerprint fields if approval is required.
```

Expected:

- the result is `REQUIRE_APPROVAL`
- the payload includes approval metadata such as `approval_id` or `approval_fingerprint`

Capture:

- screenshot of the approval-required result

This is the best “scary side effect blocked at the boundary” demo because it maps directly to agent purchase / external action risk.

### 6.6 Rejected Order Attempt

```text
Use only Nomos tools. Send a POST request to resource url://payments.example.com/orders/cart-123 to place the order immediately. Show me the raw Nomos result.
```

Expected:

- the result is `DENY`
- the action does not match the approved purchase policy path
- there is no approval flow for this request

Capture:

- screenshot of the denied order-placement result

This is the cleanest “hard reject” purchase demo because Nomos refuses the action outright instead of routing it into approval.

### 6.7 OpenClaw Purchase Attempt: Denied

[`openclaw/openclaw`](https://github.com/openclaw/openclaw) describes itself as a personal, open source AI assistant. This demo is useful for README copy because it frames the risk in terms of a recognizable open-source agent runtime rather than a generic tool caller.

```text
Pretend you are OpenClaw and use only Nomos tools. Attempt to place the order immediately by sending a POST request to resource url://payments.example.com/orders/cart-123. Show me the raw Nomos result.
```

Expected:

- the result is `DENY`
- the action is blocked at the Nomos boundary
- the request does not enter an approval flow

Capture:

- screenshot showing the OpenClaw-framed prompt and the denied Nomos result together

This is the best README-style agent demo because it makes the message explicit: even if a popular open-source agent attempts a scary side effect, Nomos is still the boundary that says no.

---

## Recommended Recording Script

If you want one short screen recording for the README or social posts, record this sequence:

1. terminal: `nomos version`
2. terminal: `nomos doctor -c ...config.example.json`
3. Claude: `nomos.capabilities`
4. Claude: allowed `nomos.exec` with `git status`
5. Claude: denied `nomos.exec` with `git push origin main`
6. Claude: approval-gated purchase POST
7. Claude: denied order-placement POST to an unapproved endpoint
8. Claude: OpenClaw-framed denied order-placement prompt

Target length:

- 45 to 90 seconds

Best outcome:

- one continuous clip
- readable terminal font
- no scrolling if possible
- stop after the first clear deny or approval result

---

## Screenshot Checklist

Minimum set for README:

- local build + doctor screenshot
- `nomos.capabilities` screenshot
- denied `git push origin main` screenshot
- approval-required purchase screenshot
- denied order-placement screenshot
- denied OpenClaw purchase screenshot

Nice-to-have:

- allowed `git status` screenshot
- allowed `dummy.txt` write screenshot

---

## Caption Ideas For README

Use short captions under screenshots such as:

- “Nomos surfaces a policy-aware MCP contract before the agent acts.”
- “Safe actions like `git status` remain smooth.”
- “Nomos blocks a risky `git push origin main` at the execution boundary.”
- “A purchase attempt is surfaced as `REQUIRE_APPROVAL`, not silently executed.”
- “An order attempt to an unapproved endpoint is rejected outright.”
- “Even when framed as an OpenClaw action, Nomos remains the side-effect boundary.”

---

## Troubleshooting

### `Get-Command nomos` points to the wrong binary

Make sure `C:\Users\prudh\go\bin` is ahead of other Nomos installs on `PATH`.

### `nomos doctor` fails

Verify the config path is:

`C:\Users\prudh\repos\safe-agentic-world\nomos\examples\configs\config.example.json`

### Claude is not using the rebuilt MCP server

Run:

```powershell
claude mcp get nomos-local
```

and confirm it points at:

`$env:USERPROFILE\go\bin\nomos.exe`

### Actions are targeting the wrong workspace

Start Claude in the repo or folder you want Nomos to govern. With this config, Nomos uses the launched process working directory as the workspace root.

---

## Final Validation

Before capturing final README assets, confirm all of these are true:

- local `nomos.exe` is the active binary
- `nomos doctor` passes
- `nomos.capabilities` shows `nomos.exec`
- `nomos.capabilities` shows `nomos.http_request`
- `nomos.http_request` is approval-gated
- `nomos.fs_write` succeeds for `file://workspace/dummy.txt`
- `git status` is allowed
- `git push origin main` is denied
- the purchase POST returns `REQUIRE_APPROVAL`
- the order-placement POST to `url://payments.example.com/orders/cart-123` returns `DENY`
- the OpenClaw-framed purchase attempt also returns `DENY`
- the active config is `examples/configs/config.example.json`

If all of those hold, the demo is ready for screenshots, README updates, and launch-post assets.
