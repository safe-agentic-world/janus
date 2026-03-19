# Policy Language (v1)

Nomos policy bundles may be authored in JSON or YAML, but Nomos evaluates them through the same deterministic typed representation with deny-wins semantics.

## Bundle Format

JSON:

```json
{
  "version": "v1",
  "rules": [
    {
      "id": "allow-readme",
      "action_type": "fs.read",
      "resource": "file://workspace/README.md",
      "decision": "ALLOW",
      "principals": ["system"],
      "agents": ["nomos"],
      "environments": ["dev"],
      "risk_flags": ["risk.net"],
      "obligations": {}
    }
  ]
}
```

YAML (equivalent):

```yaml
version: v1
rules:
  - id: allow-readme
    action_type: fs.read
    resource: file://workspace/README.md
    decision: ALLOW
    principals: [system]
    agents: [nomos]
    environments: [dev]
    risk_flags: [risk.net]
    obligations: {}
```

## YAML Support

- `.json` bundles keep the existing typed JSON decode path.
- `.yaml` and `.yml` bundles are convenience input formats only.
- YAML is decoded into the same typed Go structs used by JSON decoding.
- Unknown YAML fields are rejected.
- Duplicate YAML keys are rejected deterministically.
- YAML source bytes are not hashed directly.
- Bundle identity is computed after the typed bundle is converted into canonical JSON, so equivalent JSON and YAML bundles produce the same `policy_bundle_hash`.

## Matching Semantics

- `action_type` is an exact string match or `*` for any.
- `resource` uses deterministic glob patterns:
  - `*` matches a single segment.
  - `**` matches multiple segments.
  - `/` is the only separator; backslashes are rejected.
- `principals`, `agents`, `environments` are optional lists:
  - empty list means “any”.
  - `*` matches any.
- `risk_flags` is an optional list of required flags; all must be present.
- `exec_match` is an optional `process.exec` matcher over normalized `argv` tokens:
  - it applies only to `action_type: process.exec` or `action_type: *`
  - `argv_patterns` is an array of token patterns; any matching pattern is sufficient
  - tokens match exactly unless the token is `*` or `**`
  - `*` matches exactly one argv token
  - `**` matches zero or more argv tokens
- `id` is required and must be stable across bundle versions.

## Determinism

- All inputs are normalized before policy evaluation.
- All matching occurs on normalized inputs only.
- Rule order does not affect decisions; deny-wins is always enforced.

## Decision Order (Deny Wins)

1. If any matching rule returns `DENY` → **DENY**
2. Else if any matching rule returns `REQUIRE_APPROVAL` → **REQUIRE_APPROVAL**
3. Else if any matching rule returns `ALLOW` → **ALLOW**
4. Else → **DENY** (default)

## Pattern Examples

1. `file://workspace/README.md`
2. `file://workspace/docs/**`
3. `file://workspace/src/*/main.go`
4. `repo://org/service`
5. `repo://org/*` (single segment wildcard)
6. `url://api.example.com/v1/**`
7. `url://example.com/*/status`
8. `file://workspace/**/config.json`
9. `file://workspace/.github/*`
10. `file://workspace/**/secrets/*`
11. `file://workspace/assets/**`
12. `repo://org/infra`
13. `url://example.com/health`
14. `file://workspace/scripts/*.sh`
15. `file://workspace/logs/**`

## Policy Pack Merge Order (Explicit)

When multiple bundles are loaded, they should be merged in this explicit order:

1. built-in baseline pack (deny-biased)
2. org/global packs (ordered list)
3. repo pack (optional)
4. environment pack (dev/ci/prod)
5. local overrides (dev only, loud warnings)

Current starter bundles shipped in-repo:
- `examples/policies/safe.{json,yaml}` (secure local development starter with deny-by-rule secret/code file protections)
- `examples/policies/all-fields.example.{json,yaml}` (schema and obligation surface reference bundle)

These shipped bundles are examples and starter packs only.

Nomos does not depend on any specific checked-in bundle at runtime. Operators can provide their own policy bundles and Nomos evaluates them through the same deterministic policy model.

## Multi-Bundle Loading

Nomos now supports loading multiple policy bundles from a single config with deterministic ordered merge.

Config shape:

```json
{
  "policy": {
    "policy_bundle_paths": [
      "./examples/policies/base.yaml",
      "./examples/policies/repo.yaml",
      "./examples/policies/dev.yaml"
    ],
    "policy_bundle_roles": [
      "baseline",
      "repo",
      "env"
    ],
    "verify_signatures": false,
    "signature_paths": [],
    "public_key_path": ""
  }
}
```

Rules:

- use either `policy_bundle_path` or `policy_bundle_paths`, never both
- bundle order is significant and operator-controlled
- `policy_bundle_roles` is optional but recommended for layered configs
- valid `policy_bundle_roles` values are `baseline`, `org`, `repo`, `env`, and `local_override`
- every configured bundle must load successfully or Nomos fails closed
- duplicate rule IDs across bundles are rejected
- the effective merged policy state gets its own deterministic `policy_bundle_hash`
- for multi-bundle loads, explain, doctor, audit, and startup logs expose ordered bundle provenance

Recommended layered profile:

1. `baseline`
2. `org`
3. `repo`
4. `env`
5. `local_override`

`local_override` is intentionally narrow:

- it is only allowed when `identity.environment` is `dev` or `local`
- it is only allowed when `runtime.deployment_mode` is `unmanaged`
- Nomos fails closed if a `local_override` bundle is configured outside those bounds

If signature verification is enabled for multi-bundle configs:

- `signature_paths` must align one-for-one with `policy_bundle_paths`
- each bundle is verified independently before merge

Checked-in examples:

- `examples/configs/config.layered.example.json`
- `examples/configs/config.layered.local-override.example.json`
- `examples/policies/local-override.yaml`

## Process Exec Matching

Nomos now supports rule-level argv matching for `process.exec` without introducing tool-specific action types.

Rule-level `exec_match` is part of authorization matching.

For rules that use `exec_match`, Nomos derives a typed internal exec constraint surface from the matched policy rules and enforces that surface at execution time as defense-in-depth.

This keeps policy as the only authorization source while still letting the executor fail closed if the matched exec shape is not preserved.

Legacy `exec_allowlist` remains supported as a compatibility path for older bundles that do not use `exec_match`.

Rules:

- prefer `exec_match` for all new `process.exec` policy authoring
- Nomos MUST NOT parse shell command strings for policy matching
- Nomos MUST match only normalized argv arrays
- a single rule MUST NOT declare both `exec_match` and `exec_allowlist`
- if matched allow / approval rules mix `exec_match` and legacy `exec_allowlist` models for the same action evaluation, Nomos fails closed with `deny_by_exec_model_conflict`
- if `exec_match` is present on matched allow or approval rules, the derived exec constraints are the primary runtime defense check
- if no `exec_match`-derived constraints exist, legacy `exec_allowlist` may still constrain execution for compatibility

Runtime compatibility mode:

- `policy.exec_compatibility_mode: legacy_allowlist_fallback` keeps legacy `exec_allowlist` bundles working during migration
- `policy.exec_compatibility_mode: strict` rejects runtime startup if allow / approval exec rules still depend on legacy `exec_allowlist`

Example:

```yaml
version: v1
rules:
  - id: allow-git
    action_type: process.exec
    resource: file://workspace/
    decision: ALLOW
    exec_match:
      argv_patterns:
        - ["git", "**"]
    obligations:
      sandbox_mode: local

  - id: deny-push-main
    action_type: process.exec
    resource: file://workspace/
    decision: DENY
    exec_match:
      argv_patterns:
        - ["git", "push", "**", "main"]
        - ["git", "push", "**", "master"]
```

With deny-wins semantics:

- `git status` matches `allow-git` and can proceed if the obligations permit it
- `git push origin main` matches both rules, but the narrower `DENY` wins

Legacy compatibility example:

```yaml
version: v1
rules:
  - id: allow-legacy-echo
    action_type: process.exec
    resource: file://workspace/
    decision: ALLOW
    obligations:
      sandbox_mode: local
      exec_allowlist:
        - ["cmd", "/c", "echo"]
```

This matching model remains generic and works for any CLI with normalized argv tokens.
