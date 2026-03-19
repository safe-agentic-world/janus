# Obligations

Obligations are the typed constraints Nomos applies after a policy decision matches an action.

They are part of the authorization result and MUST remain deterministic for the same normalized action, verified identity, policy bundle, and engine version.

## Core Rules

- obligations are evaluated only after normalization and policy matching
- obligations MUST be side-effect free to compute
- when multiple matching rules contribute obligations, Nomos resolves conflicts deterministically
- deny-wins semantics remain authoritative; obligations do not override a `DENY`

## Supported Obligation Types

- `sandbox_mode`
- `net_allowlist`
- `exec_allowlist`
- `http_redirects`
- `http_redirect_hop_limit`
- `output_max_bytes`
- `output_max_lines`
- `approval_scope_class`
- `credential_lease_ids`

## Exec Match vs Exec Allowlist

`exec_match` is not an obligation.

It is a rule-level policy matcher described in [policy-language.md](./policy-language.md) for `process.exec`.

For new policy authoring:

- `exec_match` decides which exec requests a rule applies to
- Nomos derives typed exec constraints from matched `exec_match` rules and enforces them at execution time as defense-in-depth

Legacy `exec_allowlist` remains supported only as a compatibility path for older bundles that do not yet use `exec_match`.

Rules:

- do not declare both `exec_match` and `exec_allowlist` in the same rule
- prefer `exec_match` for all new `process.exec` policy rules
- treat legacy `exec_allowlist` as migration-only compatibility, not the preferred long-term model
- use `policy.exec_compatibility_mode: strict` when you want runtime startup to reject legacy exec allowlist policies
- if matched allow / approval exec rules mix legacy and argv-aware models for the same action evaluation, Nomos fails closed

This lets operators express:

- broad allow for a command family
- narrower deny or approval rules for dangerous subcommands
- executor-side fail-closed validation of the matched exec shape

## Deterministic Merge Rules

- LIMITS choose the most restrictive numeric value
- SANDBOX chooses the most restrictive profile by explicit ordering
- NET chooses the most restrictive mode (`deny > allowlist > open`)
- RATE limits choose the lowest limit
- TAGS form a union
- REDACTION rules form a union
- OUTPUT caps choose the smallest cap
- derived exec constraints are the deterministic union of matched rule-level argv patterns for the selected decision class
- EXEC allowlists are intersected or otherwise reduced to the stricter effective set
- NET allowlists are intersected or otherwise reduced to the stricter effective set

## Execution Contract

- the policy engine returns obligations as data
- the service layer merges and exposes obligations with the decision
- executors enforce only the obligations relevant to their action type
- if the configured runtime cannot satisfy a required obligation, Nomos fails closed

## Testing Guidance

- add merge-behavior tests for any new obligation type
- keep obligation outputs stable for the same inputs
- avoid obligation logic that depends on wall-clock state, host state, or external services
