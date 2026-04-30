# UI System

This document defines the operator-console rules for Nomos UI work.

## Principles

- Optimize for time-to-triage, not decorative simplicity.
- Keep the UI a thin layer over existing Nomos control paths.
- Prefer dense, scannable tables with split-pane detail over disconnected dashboards.
- Preserve context when moving from overview to queue to detail.
- Never expose secrets, raw MCP payloads, raw upstream responses, or credentials in UI views.
- Never imply stronger guarantees than runtime evidence supports.

## Information Architecture

Primary operator sections are stable:

- Overview
- Approvals
- Investigations
- Upstreams
- Policy Explain

Use stable hash routes for local UI state and deep links. New sections should only be added when they represent a durable operator workflow, not a one-off dashboard.

## Visual Tokens

Typography:

- Display: serif headings for strong hierarchy.
- Body: readable sans-serif for dense operational text.
- Monospace: JSON, traces, and policy payloads.

Spacing:

- Panels use large radius containers with internal spacing.
- Dense data grids use compact row spacing and sticky headers.
- Split-pane pages keep queue and detail visible together on wide screens.

Color semantics:

- Good: healthy, ready, allow, success.
- Warning: pending, watch, configured but not live-confirmed.
- Bad: degraded, denied, expired, not ready.

Color must never be the sole carrier of status meaning. Badges must include explicit text.

## Components

### Navigation

Navigation is persistent and reflects the operational hierarchy. It must expose `aria-current="page"` for the active route and remain keyboard accessible.

### Data Grids

Data grids should support the workflow before adding ornamentation.

Expected behavior:

- sortable columns where ordering affects triage
- route-local filtering
- row selection that preserves surrounding context
- bounded rendering for large result sets
- clear empty states
- sticky headers where useful

### Detail Panes

Detail panes should progressively disclose evidence. Prefer summarized fields, status, and timelines before raw JSON. Raw JSON is acceptable when it is already redacted and is the most faithful evidence view.

### Saved Views

Saved filters and column preferences are local UI conveniences. They must fail safe: invalid saved state is ignored and defaults are used.

### Status Badges

Badges must combine text and semantic color. Do not invent new assurance levels or status words without documenting them.

### Empty And Error States

Empty states should explain what is missing and which configuration enables the view. Error states should not leak tokens, headers, raw arguments, or upstream payloads.

## Accessibility

- Core workflows must work with keyboard only.
- Focus states must be visible.
- Tables, drawers, timelines, and status components must expose accessible labels or roles.
- Hover-only actions are not allowed for critical workflows.
- Responsive stacking must preserve the same actions and detail access.

## Performance

- Use bounded rendering or virtualization for large queues.
- Keep local filtering deterministic.
- Avoid rendering thousands of rows at once.
- Keep API limits explicit and bounded.

## Security

The UI must not create alternate execution or approval paths.

All new operator data must come from existing authenticated APIs or existing audit/readiness evidence. If a view cannot be supported without exposing sensitive material, the view should show a safe summary instead of raw data.
