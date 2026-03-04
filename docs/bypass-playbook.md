# Bypass Playbook

This document defines the bypass regression suite.

## Purpose

The bypass suite codifies known evasion attempts into deterministic fixtures and tests so Nomos cannot silently regress.

## Included Attempt Classes

- symlink escape sequences
- path traversal
- redirect-to-disallowed-host
- env leakage attempts
- subprocess escape attempts
- workspace race / TOCTOU probes

## Per-Case Contract

Each case in `testdata/bypass/cases.jsonl` specifies:

- action attempted
- expected decision
- expected executor behavior
- expected audit classification
- expected redaction behavior

The corpus also includes explicit expectations for:

- controlled-runtime reference mode
- best-effort / unmanaged mode

## Expected Outcomes

- bypasses must be blocked when Nomos can enforce them directly
- if the surrounding runtime is weaker, Nomos must fail closed or otherwise safely degrade
- all outcomes must be auditable with stable classification
- secret-bearing outputs must remain redacted

## CI And Release Gating

The bypass suite is intended to run in CI and is part of release gating. A release should not ship if the bypass suite fails.
