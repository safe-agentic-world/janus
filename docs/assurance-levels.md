# Assurance Levels

This is the canonical assurance and mediation coverage contract for Nomos.

It defines:

- assurance labels used by audit events, `nomos policy explain`, and `nomos.capabilities`
- mediation coverage expectations by deployment environment

## Levels

- `STRONG`: The runtime supplies independent enforcement for mediation boundaries, and Nomos is operating in a strong-guarantee deployment mode.
- `GUARDED`: Nomos is the primary enforcement point, with meaningful runtime controls, but the deployment is not asserting the full strong-guarantee posture.
- `BEST_EFFORT`: Nomos mediates only the actions routed through it; the surrounding environment may still permit bypass.
- `NONE`: Deployment mode is unknown or unsupported, so Nomos intentionally makes no stronger assurance claim.

## Deterministic Derivation

Nomos derives `assurance_level` from runtime config plus explicit runtime evidence signals.

Current mapping:

- deployment mode `k8s` or `ci` with `strong_guarantee=true` and verified runtime isolation, workload identity, and durable audit evidence -> `STRONG`
- deployment mode `k8s` or `ci` with `strong_guarantee=true` but missing or unverifiable evidence -> `GUARDED`
- deployment mode `k8s` or `ci` with `strong_guarantee=false` -> `GUARDED`
- deployment mode `remote_dev` -> `BEST_EFFORT`
- deployment mode `unmanaged` -> `BEST_EFFORT`
- unknown/invalid mode -> `NONE`

This derivation is:

- side-effect free
- deterministic
- independent of agent input

The current evidence inputs are:

- hardened container sandbox evidence
- workload identity verification evidence
- durable audit delivery evidence

Nomos fails closed for hardened sandbox selection when container backend evidence is missing, and it degrades assurance when strong-guarantee intent is not backed by evidence.

## What Can Go Wrong

- `STRONG` is only emitted when the required runtime evidence is present and verified.
- `GUARDED` does not imply complete bypass resistance.
- `BEST_EFFORT` means local or adjacent tooling may bypass Nomos entirely.
- `NONE` should be treated as a configuration gap until deployment mode is made explicit.

## Scope

This document only defines the assurance label and its documentation contract. It does not change policy decisions or broaden executor capabilities. In unmanaged environments, the label should be read together with the `mediation_notice` surfaced by `nomos.capabilities`.

## Mediation Coverage Matrix

### CI

| Action Class | Guarantee Level | Enforcement Mechanism(s) | Bypass Conditions | Required Operator Hardening |
| --- | --- | --- | --- | --- |
| filesystem reads/writes | GUARDED | workspace root constraints, policy gate, CI workspace isolation | direct runner filesystem access outside Nomos tooling | isolated workspace, no privileged host mounts |
| process exec | GUARDED | policy allowlists, sandbox profile, CI job boundary | direct shell steps outside Nomos | route side effects through Nomos, restrict privileged job steps |
| network requests | GUARDED | policy allowlists, CI egress controls | unrestricted egress from non-Nomos steps | default-deny egress, Nomos-only side-effecting steps |
| secrets checkout | GUARDED | brokered leases, executor-only materialization | direct CI secret injection to agent steps | keep secrets out of agent steps, use workload identity |
| repo publishing / PR boundary validation | GUARDED | policy + publish-boundary checks | direct git credentials outside Nomos | block direct push credentials, require Nomos mediation |

### K8s

| Action Class | Guarantee Level | Enforcement Mechanism(s) | Bypass Conditions | Required Operator Hardening |
| --- | --- | --- | --- | --- |
| filesystem reads/writes | STRONG | workspace scoping, container boundary, policy gate | privileged mounts or hostPath escapes | read-only roots where possible, no hostPath for agents |
| process exec | STRONG | container sandbox, policy allowlists, pod isolation | privileged containers or escape-capable runtime | non-privileged pods, no privilege escalation |
| network requests | STRONG | network policy + Nomos allowlists | permissive cluster egress or sidecar bypass | default-deny egress, explicit allowlists |
| secrets checkout | STRONG | workload identity + brokered leases | direct secret mounts into agent pod | no direct secret mounts, executor-only materialization |
| repo publishing / PR boundary validation | STRONG | policy gate + isolated service identity | alternate credentials bypass Nomos | isolate credentials to Nomos path only |

### Remote Dev

| Action Class | Guarantee Level | Enforcement Mechanism(s) | Bypass Conditions | Required Operator Hardening |
| --- | --- | --- | --- | --- |
| filesystem reads/writes | BEST_EFFORT | policy gate, workspace scoping | local user can bypass local process controls | narrow workspace roots, avoid sensitive co-location |
| process exec | BEST_EFFORT | allowlists, sandbox profile when available | local host process access outside Nomos | run in containerized remote dev where possible |
| network requests | BEST_EFFORT | policy allowlists | direct host egress outside Nomos | prefer tunneled/dev-container environments |
| secrets checkout | BEST_EFFORT | brokered leases | host-level secret stores accessible directly | avoid long-lived local secrets |
| repo publishing / PR boundary validation | BEST_EFFORT | policy and validation tools | local git credentials bypass Nomos | require PR checks before merge |

### Unmanaged Laptop

| Action Class | Guarantee Level | Enforcement Mechanism(s) | Bypass Conditions | Required Operator Hardening |
| --- | --- | --- | --- | --- |
| filesystem reads/writes | BEST_EFFORT | policy gate for mediated actions only | local user/process can bypass Nomos entirely | keep sensitive repos isolated, deny by default |
| process exec | BEST_EFFORT | allowlists for mediated exec only | direct shell access outside Nomos | avoid trusting local mediation as sole control |
| network requests | BEST_EFFORT | policy allowlists for mediated requests | direct browser/CLI egress outside Nomos | treat as advisory control, not strong isolation |
| secrets checkout | BEST_EFFORT | short-lived lease IDs | local environment may still hold direct creds | do not inject raw secrets into local agent context |
| repo publishing / PR boundary validation | BEST_EFFORT | validation checks before publish | direct push from local credentials | enforce server-side branch protections |

## Notes

- `NONE` is reserved for unsupported or unspecified deployment modes where Nomos cannot safely make a stronger claim.
- These assurance levels describe mediation coverage, not whether a specific action is allowed. Authorization remains policy-driven and deny-by-default.
