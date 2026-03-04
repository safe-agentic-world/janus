# MCP Compatibility

This document defines the MCP compatibility contract implemented by Nomos.

## Supported Protocol Version

- `2024-11-05`

Nomos returns this version from the `initialize` response.

## Supported Transports

- stdio

HTTP transport for MCP is not currently implemented.

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

Exposed tools:

- `nomos.capabilities`
- `nomos.fs_read`
- `nomos.fs_write`
- `nomos.apply_patch`
- `nomos.exec`
- `nomos.http_request`
- `repo.validate_change_set`

## Stdout / Stderr Guarantees

- stdout is reserved for MCP protocol bytes only
- the startup banner is written to stderr only
- runtime logs are written to stderr only
- `--quiet` suppresses banner and non-error logs

## Unsupported Or Narrowly Supported Features

- MCP over HTTP transport
- optional protocol features not explicitly listed above
- arbitrary non-protocol stdout output

