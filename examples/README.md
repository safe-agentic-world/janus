# Examples

The `examples/` tree contains runnable fixtures and integration references. These files are part of the validation surface, not scratch space.

## Directory Map

- `quickstart/` contains the deterministic local allow/deny workspace used by quickstart docs and smoke tests.
- `policies/` contains starter and reference policy bundles used by docs, CI, and policy compatibility tests.
- `configs/` contains gateway, MCP, layered-policy, and upstream gateway config examples.
- `http-contract/` contains request and response examples validated against the HTTP contract schemas.
- `http-sdk/` contains minimal Go, Python, and TypeScript SDK usage examples.
- `openai-compatible/` contains the small HTTP loop used by the quickstart gateway demo.

## Maintenance Rules

- Keep examples deterministic and runnable from the repository root.
- Prefer relative paths in checked-in configs.
- Do not add generated caches, local binaries, session files, or copied workspace state.
- Do not add duplicate default profile YAML under `examples/`; default profiles live in `../profiles/`.
- Do not add static Claude or Codex MCP client snippets. Use `nomos run claude` and `nomos run codex` for local agent launcher workflows.
- If a doc references an example path, add or keep a test that proves the path exists.

Before removing an example, search for references in `README.md`, `docs/`, `cmd/`, `internal/`, `.github/`, and `testdata/`, then run `go test ./...`.

