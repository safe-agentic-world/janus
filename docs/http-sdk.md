# HTTP SDKs

Nomos now ships a small official HTTP adoption layer for runtimes that do not speak MCP directly.

This surface is intentionally narrow. It is not a second control plane and it does not change the gateway contract. It removes repetitive client glue while preserving the existing execution boundary:

- `ALLOW`
- `DENY`
- `REQUIRE_APPROVAL`

## Current SDK Surfaces

- Go: [`pkg/sdk`](../pkg/sdk)
- Python: [`sdk/python/nomos_sdk.py`](../sdk/python/nomos_sdk.py)
- TypeScript: [`sdk/typescript/nomos_sdk.ts`](../sdk/typescript/nomos_sdk.ts)

The supported HTTP contract remains additive and backward-compatible:

- `POST /action`
- `POST /approvals/decide`
- `POST /explain`

All SDKs use:

- bearer principal auth
- `X-Nomos-Agent-Id`
- `X-Nomos-Agent-Signature`

## Security Defaults

The SDKs are opinionated in a few ways:

- auth and signing are mandatory
- request envelopes are generated for you, but callers may override `action_id` and `trace_id`
- missing auth configuration fails closed
- `REQUIRE_APPROVAL` is surfaced explicitly and is not treated as success-with-side-effects
- debug logging excludes bearer tokens, signing secrets, and request payload bodies
- the SDK layer does not bypass the raw HTTP path; handwritten integrations continue to work

The first client surfaces intentionally do not retry side-effecting `POST /action` calls automatically. If a caller wants replay semantics, it should make that decision explicitly at the application layer.

## Explain Semantics

`POST /explain` is explain-only. It uses the same request envelope and auth model as `POST /action`, but it does not execute side effects and it does not write execution audit events.

Use it for:

- integration testing
- safer operator or developer previews
- policy troubleshooting inside application code

Do not confuse `POST /explain` with authorization to execute. Live execution still happens only through `POST /action`.

## Go Quickstart

```go
package main

import (
  "context"
  "fmt"
  "log"

  "github.com/safe-agentic-world/nomos/pkg/sdk"
)

func main() {
  client, err := sdk.NewClient(sdk.Config{
    BaseURL:     "http://127.0.0.1:8080",
    BearerToken: "dev-api-key",
    AgentID:     "demo-agent",
    AgentSecret: "demo-agent-secret",
  })
  if err != nil {
    log.Fatal(err)
  }

  req := sdk.NewActionRequest("fs.read", "file://workspace/README.md", map[string]any{})
  resp, err := client.RunAction(context.Background(), req)
  if err != nil {
    log.Fatal(err)
  }
  fmt.Printf("decision=%s action_id=%s trace_id=%s\n", resp.Decision, resp.ActionID, resp.TraceID)
}
```

Runnable example:

- [`examples/http-sdk/go/main.go`](../examples/http-sdk/go/main.go)

## Python Quickstart

```python
from sdk.python.nomos_sdk import NomosClient, ActionRequest

client = NomosClient(
    base_url="http://127.0.0.1:8080",
    bearer_token="dev-api-key",
    agent_id="demo-agent",
    agent_secret="demo-agent-secret",
)

response = client.run_action(
    ActionRequest(
        action_type="fs.read",
        resource="file://workspace/README.md",
        params={},
    )
)
print(response["decision"])
```

Runnable example:

- [`examples/http-sdk/python/quickstart.py`](../examples/http-sdk/python/quickstart.py)

## TypeScript Quickstart

```ts
import { NomosClient, createActionRequest } from "../sdk/typescript/nomos_sdk";

const client = new NomosClient({
  baseUrl: "http://127.0.0.1:8080",
  bearerToken: "dev-api-key",
  agentId: "demo-agent",
  agentSecret: "demo-agent-secret",
});

const response = await client.runAction(
  createActionRequest("fs.read", "file://workspace/README.md", {}),
);
console.log(response.decision);
```

Runnable example:

- [`examples/http-sdk/typescript/quickstart.ts`](../examples/http-sdk/typescript/quickstart.ts)

## Migration From Handwritten HTTP

Replace handwritten integration code that currently owns:

- action envelope construction
- id generation
- auth header assembly
- HMAC signing
- raw decision parsing

with:

- `RunAction` / `run_action`
- `DecideApproval` / `decide_approval`
- `ExplainAction` / `explain_action`

This is an adoption convenience layer only. It does not change Nomos authorization semantics.
