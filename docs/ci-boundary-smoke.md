# CI Boundary Smoke

This smoke path proves Nomos can run in CI as a policy boundary before real Claude or Codex credentials are introduced.

It does not launch an AI agent. It validates the deterministic pieces first:

- CI runtime config loads with `runtime.deployment_mode=ci`
- `nomos doctor` reports the configured CI posture
- `ci-strict` allows read-only repository inspection
- `ci-strict` denies ad hoc publishing and secret reads
- workflow artifacts capture the doctor and policy-test outputs

## Local Run

From the repository root:

```bash
go build -o ./bin/nomos ./cmd/nomos
mkdir -p artifacts/nomos-ci-smoke

./bin/nomos doctor \
  -c ./examples/ci/github/config.ci.json \
  --format json > artifacts/nomos-ci-smoke/doctor.json

./bin/nomos policy test \
  --bundle ./profiles/ci-strict.yaml \
  --action ./examples/ci/github/actions/allow-git-status.json

./bin/nomos policy test \
  --bundle ./profiles/ci-strict.yaml \
  --action ./examples/ci/github/actions/deny-git-push.json

./bin/nomos policy test \
  --bundle ./profiles/ci-strict.yaml \
  --action ./examples/ci/github/actions/deny-secret-read.json
```

Expected decisions:

- `allow-git-status.json` -> `ALLOW`
- `deny-git-push.json` -> `DENY`
- `deny-secret-read.json` -> `DENY`

## GitHub Actions

The checked-in workflow is `.github/workflows/nomos-ci-smoke.yml`.

It builds `nomos`, runs doctor, evaluates the three CI action fixtures, runs a focused MCP/process smoke test, and uploads `artifacts/nomos-ci-smoke/`.

The workflow intentionally does not require:

- Claude credentials
- Codex credentials
- OpenAI or Anthropic API keys
- GitHub write permissions

## GitLab CI

Use `examples/ci/gitlab/.gitlab-ci.yml` as the equivalent GitLab job.

It runs the same commands as the GitHub smoke workflow and stores the same artifact directory.

## Boundary

This is a boundary smoke, not a full governed agent runner.

It proves the policy and runtime checks that the later job runner will depend on. It does not prove that Claude or Codex native tools are disabled. That stronger claim requires a controlled CI/container runtime where direct shell, direct egress, and direct credentials are blocked outside Nomos.
