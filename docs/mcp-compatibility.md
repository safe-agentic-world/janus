# MCP Compatibility

This document defines the MCP compatibility contract implemented by Nomos.

## Supported Protocol Version

- `2024-11-05`

Nomos returns this version from the `initialize` response.

The `initialize` response currently advertises:

- `capabilities.tools.listChanged = false`

Nomos therefore treats MCP `tools/list` as a static advertised surface for the life of a server session.

## Supported Transports

- stdio
- Streamable HTTP for remote MCP clients and upstream MCP servers

Legacy SSE upstream MCP servers are supported as a compatibility path.

## Supported Request / Response Envelopes

Nomos currently supports:

- framed JSON-RPC 2.0 requests using `Content-Length`
- line-delimited JSON-RPC 2.0 requests
- legacy line-delimited Nomos request envelopes for backward compatibility

Nomos emits:

- framed JSON-RPC 2.0 responses for framed JSON-RPC requests
- line-delimited JSON-RPC 2.0 responses for line-delimited JSON-RPC requests
- legacy line-delimited responses for legacy line requests

## Tool Compatibility Guarantees

Nomos supports:

- `initialize`
- `notifications/initialized`
- `tools/list`
- `tools/call`
- `resources/list`
- `resources/read`
- `prompts/list`
- `prompts/get`
- `completion/complete`
- governed upstream `sampling/createMessage` when the downstream client advertises sampling support

Exposed tools:

- `nomos_capabilities`
- `nomos_fs_read`
- `nomos_fs_write`
- `nomos_apply_patch`
- `nomos_exec`
- `nomos_http_request`
- `repo_validate_change_set`

Nomos advertises MCP tool names using a conservative cross-vendor-safe character set. Legacy dotted names such as `nomos.fs_read` remain accepted for backward compatibility, but new clients should use the advertised names from `tools/list`.

Launcher/workspace-profile mode can request `--tool-surface friendly`, which advertises natural aliases for the five primary governed capabilities:

- `read_file` -> `fs.read`
- `write_file` -> `fs.write`
- `apply_patch` -> `repo.apply_patch`
- `run_command` -> `process.exec`
- `http_request` -> `net.http_request`

`--tool-surface canonical` preserves the compatibility-safe names above. `--tool-surface both` advertises both sets. Incoming calls through any supported alias are canonicalized before policy, approval, and audit evaluation.

Tool surfacing semantics:

- `tools/list` is static and returns the full advertised Nomos MCP surface
- current policy state is exposed through `nomos_capabilities`
- clients should use `nomos_capabilities` to distinguish:
  - tools callable now
  - tools available only with approval
  - tools currently unavailable for the active identity/environment
- `nomos_capabilities` is advisory only; every action is still evaluated live
- capability evolution is additive and versioned through `contract_version`
- clients may watch `capability_set_hash` to detect deterministic contract changes within the current runtime
- `tool_states[*].constraints` exposes bounded safe summaries only; Nomos does not expose raw policy internals or sensitive resource names by default

For `tools/call`:

- action tools return text content with a concise decision line (`ALLOW`, `APPROVAL`, or `DENY`) and relevant output details when present
- non-action utility responses such as `nomos_capabilities` and `repo_validate_change_set` remain JSON text payloads

## Stdout / Stderr Guarantees

- stdout is reserved for MCP protocol bytes only
- the startup banner is written to stderr only
- runtime logs are written to stderr only
- `--quiet` suppresses banner and non-error logs

## Unsupported Or Narrowly Supported Features

- optional protocol features not explicitly listed above
- arbitrary non-protocol stdout output

## Reference Contract Suite

The `MCP Reference Contract` CI job is the authoritative interop gate for upstream MCP gateway claims.

Pinned references are recorded in `testdata/mcp-contract/reference-servers.json` with package versions and `sha512` integrity hashes:

- `@modelcontextprotocol/server-everything@2026.1.26`
- `@modelcontextprotocol/server-filesystem@2026.1.14`
- `@modelcontextprotocol/server-memory@2026.1.26`

The CI suite runs offline deterministic contract fixtures for those references instead of downloading package payloads during test execution. Coverage includes:

- `initialize` and `tools/list`
- representative `tools/call` success for each reference
- invalid `tools/call` arguments returning structured tool errors
- `resources/list` and `resources/read`
- `prompts/list` and `prompts/get`
- upstream-requested sampling for the Everything reference surface
- stdio and Streamable HTTP upstream transport parity
- unsupported method errors
- early upstream exit fail-closed behavior
- stable canonical action fingerprints across equivalent argument ordering
- least-privilege stdio upstream environment defaults

Failures in `MCP Reference Contract` are release blockers and must not be treated as optional unit-test flakes.
