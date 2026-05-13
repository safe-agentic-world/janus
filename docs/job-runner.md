# Job Runner

`nomos job run` is the CI/production entrypoint for running Codex or Claude behind a Nomos policy boundary.

Nomos remains the control plane. The selected agent still does the reasoning and code work, but Nomos owns the workspace boundary, MCP wiring, policy profile, approvals store, and job artifacts.

## Command

```bash
nomos job run --agent codex --profile ci-strict --task .nomos/tasks/fix-tests.md
nomos job run --agent claude --policy nomos/policy.yaml --task .nomos/tasks/update-docs.md
```

Useful preflight mode:

```bash
nomos job run \
  --agent codex \
  --profile ci-strict \
  --task examples/ci/tasks/noop.md \
  --dry-run
```

## Inputs

- `--agent codex|claude` selects the agent CLI Nomos will launch.
- `--task <path>` points at a UTF-8 task file. The first version limits task files to 64 KiB.
- `--profile <name>` selects `safe-dev`, `ci-strict`, or `prod-locked`.
- `--policy-bundle <path>` or `--policy <path>` selects an explicit policy bundle.
- `--profile` and `--policy-bundle` are mutually exclusive.
- `--workspace <path>` defaults to the current directory.
- `--artifact-dir <path>` defaults to `.nomos/job/<job-id>/`.
- `--dry-run` validates, generates config, and writes artifacts without launching an agent.
- `--no-launch` writes generated config and artifacts, then stops before launching.

## Artifacts

Each job writes:

- `job-metadata.json`: agent, workspace, profile, policy hash, assurance level, MCP wiring method, start/end time, and exit reason.
- `mcp-config.json`: generated client config that registers only Nomos MCP.
- `audit.jsonl`: job-level audit event.
- `changed-files.json`: best-effort git status summary before and after the job.
- `policy-summary.json`: deterministic counters for Nomos-observed policy denied, approval pending, and agent failure outcomes.

Live agent jobs also write `agent-final-message.txt` and expose it through `agent_transcript_path` in `job-metadata.json`. For Codex, Nomos asks the CLI to write the final message artifact. For Claude Code, Nomos captures `--print` stdout into the same artifact. Nomos uses that final message to fail closed when the agent exits successfully but reports that required Nomos MCP calls were cancelled, produces no final message, or says it could not proceed.

## Exit Codes

- `0`: success, dry-run, or no-launch preflight completed.
- `2`: invalid job input, invalid config, invalid profile, or invalid policy bundle.
- `10`: Nomos-observed policy denial.
- `11`: Nomos-observed approval pending.
- `12`: agent launch failure, agent process failure, or agent-reported inability to complete the governed task.
- `1`: internal Nomos job runner error.

Policy denials and approval-pending outcomes are deterministic when Nomos observes the failure at the boundary. A fully external agent process can still fail without structured policy detail; that is reported as agent failure unless the error is clearly classifiable. For live Codex and Claude Code jobs, Nomos also captures the final agent message and treats missing output, explicit MCP cancellation, or cannot-proceed messages as agent failure instead of successful completion.

## GitHub Actions

Run dry-run first, then add credentials only after the artifacts look right:

```yaml
- name: Nomos job preflight
  run: |
    nomos job run \
      --agent codex \
      --profile ci-strict \
      --task examples/ci/tasks/noop.md \
      --dry-run \
      --artifact-dir artifacts/nomos-job-preflight
```

The checked-in `.github/workflows/nomos-ci-smoke.yml` runs this pattern for both Codex and Claude.

## GitLab CI

Use the same dry-run gate in a GitLab job:

```yaml
script:
  - nomos job run --agent codex --profile ci-strict --task examples/ci/tasks/noop.md --dry-run --artifact-dir artifacts/nomos-job-preflight
artifacts:
  when: always
  paths:
    - artifacts/nomos-job-preflight/
```

The checked-in `examples/ci/gitlab/.gitlab-ci.yml` includes the equivalent Codex and Claude dry-runs.

## Enforcement Boundary

Hard enforcement requires CI or container controls that prevent native tools, direct network egress, and direct credentials from bypassing Nomos. The job runner configures the selected agent for the safest supported non-interactive mode, but the strong claim comes from the outer runtime controls plus Nomos policy decisions and audit artifacts.
