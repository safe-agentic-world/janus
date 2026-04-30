# Testing

This document defines practical local testing and a release-quality gate for Nomos.

## Prerequisites

- Go 1.25+
- Repository checked out locally
- `nomos` built at least once for CLI checks

## Fast Validation

Use this when iterating quickly:

```powershell
go test ./cmd/nomos ./internal/policy ./internal/service ./internal/gateway ./internal/mcp
.\bin\nomos.exe doctor -c .\examples\quickstart\config.quickstart.json --format json
.\bin\nomos.exe policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\policies\safe-dev-hardened.yaml
.\bin\nomos.exe policy test --action .\examples\quickstart\actions\deny-env.json --bundle .\policies\safe-dev-hardened.yaml
```

## Full Validation

Use this before opening a pull request:

```powershell
go test ./...
go vet ./...
```

## Release Gate

Use this before tagging and public launch posts:

```powershell
go test ./...
go test -race ./...
go vet ./...
$env:NOMOS_MCP_CONTRACT_TESTS = "1"; go test ./internal/mcp -run "TestReferenceMCPContract|TestReferenceContractManifest" -count=1 -v; Remove-Item Env:\NOMOS_MCP_CONTRACT_TESTS
.\bin\nomos.exe doctor -c .\examples\quickstart\config.quickstart.json --format json
.\bin\nomos.exe policy explain --action .\examples\quickstart\actions\deny-env.json --bundle .\policies\safe-dev-hardened.yaml
```

The `MCP Reference Contract` CI job is mandatory for releases. Treat failures in that job as release blockers because it proves Nomos can govern pinned reference MCP upstreams through stdio and Streamable HTTP.

## Docs and Artifact Consistency

These are already enforced by existing tests and should stay green:

- quickstart commands and paths
- integration artifacts and examples
- Helm and Docker Compose demo validity
- OWASP and supply-chain documentation consistency checks

## Launch Smoke Proof

Capture this output for launch credibility:

1. `doctor` ready status in JSON mode
2. one deterministic `ALLOW` policy result
3. one deterministic `DENY` policy result
4. `version` output with build metadata

Recommended command:

```powershell
.\bin\nomos.exe version
.\bin\nomos.exe doctor -c .\examples\quickstart\config.quickstart.json --format json
.\bin\nomos.exe policy test --action .\examples\quickstart\actions\allow-readme.json --bundle .\policies\safe-dev-hardened.yaml
.\bin\nomos.exe policy test --action .\examples\quickstart\actions\deny-env.json --bundle .\policies\safe-dev-hardened.yaml
```
