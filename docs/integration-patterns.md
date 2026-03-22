# Integration Patterns

Nomos integration should stay boring and explicit.

Preferred order:

1. use **MCP** when the agent runtime already supports MCP tool calling
2. use the **HTTP SDK wrapper layer** when the runtime has its own tool loop
3. use **raw HTTP** only when an SDK is unavailable for the stack

The wrapper layer exists so teams can keep their own tools and business logic while moving Nomos request construction, signing, and decision handling into a small shared SDK surface.

## Wrapper Model

The generic wrapper flow is:

1. map application input into a Nomos `ActionRequest`
2. call Nomos over HTTP
3. branch on `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`
4. execute the underlying side effect only on `ALLOW`
5. return the decision outcome plus the wrapped result to the caller

Wrapper helpers fail closed on Nomos transport or auth errors. They do not silently fall back to unsafe direct execution.

## Common Wrapper Shapes

The SDKs now provide small helper constructors for:

- guarded callable / function wrappers
- guarded HTTP tool wrappers
- guarded subprocess wrappers
- guarded file read wrappers
- guarded file write wrappers

These helpers stay framework-neutral. They do not depend on LangChain, MCP clients, browser runtimes, or application-specific business types.

## Go Example

See:

- [`examples/http-sdk/go/guarded-http-tool/main.go`](../examples/http-sdk/go/guarded-http-tool/main.go)

This wraps an existing refund-style HTTP action with `sdk.NewGuardedHTTPTool(...)` and returns both the Nomos decision and whether the underlying side effect actually ran.

## Python Example

See:

- [`examples/http-sdk/python/guarded_langchain_tool.py`](../examples/http-sdk/python/guarded_langchain_tool.py)

This shows the same pattern for a LangChain-style tool function without coupling the SDK itself to LangChain.

## TypeScript Example

See:

- [`examples/http-sdk/typescript/guarded_cli_tool.ts`](../examples/http-sdk/typescript/guarded_cli_tool.ts)

This shows a CLI-style subprocess wrapper using the same decision flow.

## Approval Semantics

Wrappers do not auto-resume approval-gated actions.

When Nomos returns `REQUIRE_APPROVAL`:

- the wrapped side effect does not run
- the caller receives the approval metadata
- the application or orchestrator decides how and when to retry with the approval binding

This keeps Nomos agent-agnostic and workflow-agnostic.

## MCP Or HTTP

If a runtime already speaks MCP well, use MCP.

If it does not, use the HTTP SDK wrapper layer around the runtime's existing tools. That keeps the application code small while preserving Nomos as the execution decision authority.

For domain-specific actions that Nomos should authorize but not execute itself, see [`docs/custom-actions.md`](./custom-actions.md).
