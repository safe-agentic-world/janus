# Response Scanning

Nomos scans forwarded upstream MCP tool responses after redaction and before delivery to the downstream agent. This protects the return path from prompt-injection and exfiltration instructions embedded in upstream content.

## Policy Obligation

Use `response_scan_mode` on `mcp.call` policy rules:

- `strip` removes matched spans from the response.
- `fence` wraps matched spans in an annotated fenced block.
- `deny` blocks the response and returns `RESPONSE_SCAN_DENIED`.

If the obligation is omitted, Nomos uses the conservative default `fence`. Invalid values fail closed as `deny`.

Example:

```yaml
rules:
  - id: allow-retail-refund
    action_type: mcp.call
    resource: mcp://retail/refund.request
    decision: ALLOW
    obligations:
      response_scan_mode: strip
```

## Rule Pack

Rule pack version: `response-scan-rules/v1`

| Rule ID | Severity | Purpose |
| --- | --- | --- |
| `prompt_injection.instruction_override` | high | Detects phrases such as requests to ignore previous instructions. |
| `prompt_injection.role_override` | medium | Detects attempts to redefine system or developer role context. |
| `exfiltration.secret_request` | high | Detects attempts to leak or send secrets, tokens, credentials, or API keys. |
| `obfuscation.hidden_unicode` | medium | Detects repeated zero-width or hidden Unicode characters. |
| `exfiltration.suspicious_url` | medium | Detects links to common paste, webhook, tunnel, or URL-shortener endpoints. |

The rule pack is checked in and does not download runtime detector updates.

Scanning is bounded to 1 MiB of response text, 128 findings, and depth 1 for the current text-only content pipeline. Full structured content depth handling is reserved for the full-fidelity content-block pipeline.

## Audit And Telemetry

Findings are recorded in `mcp.response_scan` audit events under `executor_metadata`:

- `response_scan_rule_pack_version`
- `response_scan_mode`
- `response_scan_finding_count`
- `response_scan_findings`
- `response_scan_input_truncated`
- `response_scan_max_depth`
- `response_scan_misconfigured`

Each finding contains only `rule_id`, `location`, and `severity`. Raw matched content is never written to audit, explain output, logs, or telemetry.

Telemetry emits `nomos.response_scan_findings` counters by `rule_id`, `severity`, `mode`, and rule-pack version.

## Operator Guidance

- Prefer `fence` for general upstream content where availability matters and operators want agents to see context as untrusted.
- Use `strip` for high-volume upstreams where known injection phrases should be removed from otherwise useful text.
- Use `deny` for high-risk upstreams where any injection-like content must block delivery.
- Keep output byte and line limits in place; scanning is bounded and deterministic, not a substitute for response size controls.
