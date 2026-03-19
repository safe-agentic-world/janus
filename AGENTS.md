# Repository Guidelines

## Project Structure & Module Organization
Nomos is a Go codebase for a policy-enforced execution control plane. The CLI entrypoint lives in `cmd/nomos`. Core implementation packages live under `internal/` and include areas such as `policy`, `service`, `gateway`, `mcp`, `doctor`, and `executor`. Example configs and quickstarts live in `examples/`. Starter policy bundles are in `policies/`, deployment artifacts in `deploy/`, docs in `docs/`, and reusable fixtures in `testdata/`.

## Build, Test, and Development Commands
Use standard Go tooling from the repository root:

- `go build ./cmd/nomos` builds the CLI.
- `go test ./...` runs the full test suite.
- `go vet ./...` runs static checks.
- `go test ./internal/mcp` runs focused MCP compatibility tests.
- `go run ./cmd/nomos doctor -c ./examples/quickstart/config.quickstart.json --format json` performs a deterministic readiness check.

For quick local validation, keep the example configs and policy bundles working as checked in.

## Coding Style & Naming Conventions
Format Go code with `gofmt` and follow standard Go naming. Keep behavior deterministic and fail closed. Reject unknown fields unless an API explicitly supports extensions. Use stable, descriptive rule IDs in policy bundles. Keep Markdown headings short and in Title Case. Prefer relative paths in checked-in sample configs.

## Testing Guidelines
Add or update targeted unit tests in the package you change. Run focused tests first, then `go test ./...` before opening a PR. Preserve smoke coverage for CLI, policy, doctor, and MCP flows. When changing examples or workflows, verify the quickstart commands still work and keep `.github/workflows/ci.yml` green.

## Commit & Pull Request Guidelines
Recent history uses short, imperative subjects, often with prefixes such as `feat:`, `fix:`, and `chore:`. Keep commits focused and descriptive, for example `feat: add argv-aware exec policy matching`. Pull requests should include a concise summary, linked issue or task, tests run, and any docs updates required by the change.

## Security & Configuration Notes
Do not commit secrets. Keep developer-local config separate from CI fixtures. Use portable checked-in fixtures under `testdata/` for automation. Preserve least-privilege defaults in workflows and avoid introducing secret logging or permissive policy fallbacks.
