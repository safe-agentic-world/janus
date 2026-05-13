# CI Boundary Smoke

This smoke path proves Nomos can run in CI as a policy boundary before real Claude or Codex credentials are introduced.

It does not launch an AI agent. It validates the deterministic pieces first:

- CI runtime config loads with `runtime.deployment_mode=ci`
- `nomos doctor` reports the configured CI posture
- `ci-strict` allows read-only repository inspection
- `ci-strict` denies ad hoc publishing and secret reads
- Claude and Codex launcher configs can be generated without agent credentials
- `nomos job run` can validate a governed task and write job artifacts without agent credentials
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

./bin/nomos run codex \
  --profile ci-strict \
  --no-launch \
  --print-config > artifacts/nomos-ci-smoke/codex-launcher.txt

./bin/nomos run claude \
  --profile ci-strict \
  --no-launch \
  --print-config > artifacts/nomos-ci-smoke/claude-launcher.txt

./bin/nomos job run \
  --agent codex \
  --profile ci-strict \
  --task ./examples/ci/tasks/noop.md \
  --dry-run \
  --artifact-dir artifacts/nomos-ci-smoke/job-codex-dry-run

./bin/nomos job run \
  --agent claude \
  --profile ci-strict \
  --task ./examples/ci/tasks/noop.md \
  --dry-run \
  --artifact-dir artifacts/nomos-ci-smoke/job-claude-dry-run
```

Expected decisions:

- `allow-git-status.json` -> `ALLOW`
- `deny-git-push.json` -> `DENY`
- `deny-secret-read.json` -> `DENY`

## GitHub Actions

The checked-in workflow is `.github/workflows/nomos-ci-smoke.yml`.

It builds `nomos`, runs doctor, evaluates the three CI action fixtures, runs a focused MCP/process smoke test, and uploads `artifacts/nomos-ci-smoke/`.

It also runs launcher preflight for Codex and Claude with `--no-launch --print-config`. The workflow asserts that each generated config references only Nomos MCP wiring, includes the governed tool mappings, and prints the native bypass warning.

Finally, it runs `nomos job run` for Codex and Claude in `--dry-run` mode against `examples/ci/tasks/noop.md`. This validates the production job surface without requiring Claude or Codex credentials and writes the same artifact shape a real job will use:

- `job-metadata.json`
- `mcp-config.json`
- `audit.jsonl`
- `changed-files.json`
- `policy-summary.json`

The workflow intentionally does not require:

- Claude credentials
- Codex credentials
- OpenAI or Anthropic API keys
- GitHub write permissions

## GitLab CI

Use `examples/ci/gitlab/.gitlab-ci.yml` as the equivalent GitLab job.

It runs the same commands as the GitHub smoke workflow and stores the same artifact directory.

## Boundary

This is a boundary smoke. The `nomos job run --dry-run` step proves the governed agent job contract up to the launch boundary.

It proves the policy and runtime checks that a real job runner depends on. It does not prove that Claude or Codex native tools are disabled during a live model run. That stronger claim requires a controlled CI/container runtime where direct shell, direct egress, and direct credentials are blocked outside Nomos.

The launcher preflight output is intentionally inspectable. Operators should review it before adding model credentials or starting an agent process in CI.
