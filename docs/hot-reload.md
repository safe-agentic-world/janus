# Hot Reload

Nomos can reload policy bundles and MCP upstream server registration while the process stays running.

Hot reload is intended for operator-driven configuration changes. Startup validation remains authoritative: the same policy bundle parsing and exec-compatibility validation used at startup is run before a reload is applied.

## Triggers

Use `SIGHUP` for local process-manager driven reloads:

```bash
kill -HUP <nomos-pid>
```

Use the authenticated admin endpoint for HTTP deployments:

```bash
curl -X POST \
  -H "Authorization: Bearer $NOMOS_API_KEY" \
  http://127.0.0.1:8080/admin/reload
```

For downstream MCP-over-HTTP deployments, the same endpoint is available on the MCP HTTP listener:

```bash
curl -X POST \
  -H "Authorization: Bearer $NOMOS_API_KEY" \
  http://127.0.0.1:9090/admin/reload
```

The admin endpoint uses the existing gateway principal authentication path. If the gateway requires mTLS, the reload request must also present a valid client certificate.

## Safety Model

Policy reload is fail-closed and all-or-nothing:

- The replacement bundle is loaded, canonical-hashed, and validated before it is published.
- A malformed or incompatible bundle leaves the previous policy engine active.
- Successful reload swaps the active typed policy state atomically for new evaluations.
- Existing downstream MCP sessions are not disconnected by policy reload.

MCP upstream registry reload is also all-or-nothing:

- New upstream servers are initialized and their tools are enumerated before they are shown to clients.
- Removed upstream servers are removed from lookup tables first, so new calls cannot use them.
- In-flight calls to removed upstream servers are allowed to drain, then the old upstream session is closed.
- Unchanged upstream server configs keep their existing session.

## Audit Events

Every reload attempt emits a `runtime.reload` audit event. The event includes:

- `policy_bundle_hash`
- `policy_bundle_sources`
- `executor_metadata.trigger`
- `executor_metadata.outcome`
- `executor_metadata.registry_version`
- `executor_metadata.added_upstreams` and `executor_metadata.removed_upstreams` when applicable
- `executor_metadata.error` for failed reloads

Audit events are written through the configured audit writer, so file and sqlite sinks keep the same deterministic chain hashing semantics as action events.

## Validation Guidance

Validate changes before triggering reload:

```bash
go run ./cmd/nomos doctor -c ./examples/quickstart/config.quickstart.json --format json
```

For policy-only changes, run policy explain/test against the candidate bundle before replacing the configured bundle path. For MCP upstream changes, verify each new upstream server can initialize and respond to `tools/list` from the target environment.

After reload, confirm the active state:

```bash
curl -X POST -H "Authorization: Bearer $NOMOS_API_KEY" http://127.0.0.1:8080/admin/reload
```

A successful response reports `outcome: "success"` with the active `policy_bundle_hash` and `registry_version`. A failed response reports `outcome: "failure"` and leaves the previous state active.
