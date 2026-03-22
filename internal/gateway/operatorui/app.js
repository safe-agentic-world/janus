const readinessEl = document.getElementById("readiness");
const approvalsEl = document.getElementById("approvals");
const actionEl = document.getElementById("action-detail");
const authStatusEl = document.getElementById("auth-status");
const tokenEl = document.getElementById("token");
const connectEl = document.getElementById("connect");
const refreshEl = document.getElementById("refresh");
const approveEl = document.getElementById("approve");
const denyEl = document.getElementById("deny");
const tracesEl = document.getElementById("traces");
const traceDetailEl = document.getElementById("trace-detail");
const refreshTracesEl = document.getElementById("refresh-traces");
const applyTraceFilterEl = document.getElementById("apply-trace-filter");
const traceIdFilterEl = document.getElementById("trace-id-filter");
const traceActionFilterEl = document.getElementById("trace-action-filter");
const traceDecisionFilterEl = document.getElementById("trace-decision-filter");
const explainInputEl = document.getElementById("explain-input");
const explainOutputEl = document.getElementById("explain-output");
const runExplainEl = document.getElementById("run-explain");

let selectedApproval = null;
let selectedActionId = null;
let selectedTraceId = null;

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function authHeaders() {
  const token = tokenEl.value.trim();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function api(path, options = {}) {
  const headers = { ...authHeaders(), ...(options.headers || {}) };
  const response = await fetch(path, { ...options, headers });
  const text = await response.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = { raw: text };
  }
  if (!response.ok) {
    throw new Error(payload.reason || payload.raw || `${response.status}`);
  }
  return payload;
}

function renderApprovals(items) {
  if (!items.length) {
    approvalsEl.className = "list empty";
    approvalsEl.textContent = "No pending approvals.";
    approveEl.disabled = true;
    denyEl.disabled = true;
    return;
  }
  approvalsEl.className = "list";
  approvalsEl.innerHTML = "";
  for (const item of items) {
    const node = document.createElement("div");
    node.className = "approval-item";
    const expiredBadge = item.expired ? '<span class="badge warn">Expired</span>' : '<span class="badge">Pending</span>';
    node.innerHTML = `
      <div class="approval-copy">
        <strong>${item.action_type} ${item.resource}</strong>
        <div>${item.principal} / ${item.agent} / ${item.environment}</div>
        <div>approval_id: ${item.approval_id}</div>
        <div>scope: ${item.scope_type}</div>
        <div>expires: ${item.expires_at}</div>
        ${expiredBadge}
      </div>
      <button type="button">Inspect</button>
    `;
    node.querySelector("button").addEventListener("click", async () => {
      selectedApproval = item;
      selectedActionId = item.action_id;
      approveEl.disabled = item.expired;
      denyEl.disabled = item.expired;
      await loadActionDetail(item.action_id);
    });
    approvalsEl.appendChild(node);
  }
}

async function loadReadiness() {
  const data = await api("/api/ui/readiness");
  readinessEl.className = "json";
  readinessEl.textContent = pretty(data);
}

async function loadApprovals() {
  const data = await api("/api/ui/approvals");
  renderApprovals(data.approvals || []);
}

async function loadActionDetail(actionId) {
  const data = await api(`/api/ui/actions/${encodeURIComponent(actionId)}`);
  actionEl.className = "json";
  actionEl.textContent = pretty(data);
}

function traceQuery() {
  const params = new URLSearchParams();
  if (traceIdFilterEl.value.trim()) params.set("trace_id", traceIdFilterEl.value.trim());
  if (traceActionFilterEl.value.trim()) params.set("action_type", traceActionFilterEl.value.trim());
  if (traceDecisionFilterEl.value.trim()) params.set("decision", traceDecisionFilterEl.value.trim());
  return params.toString();
}

function renderTraces(items) {
  if (!items.length) {
    tracesEl.className = "list empty";
    tracesEl.textContent = "No traces matched the current filter.";
    return;
  }
  tracesEl.className = "list";
  tracesEl.innerHTML = "";
  for (const item of items) {
    const node = document.createElement("div");
    node.className = "approval-item";
    node.innerHTML = `
      <div class="approval-copy">
        <strong>${item.trace_id}</strong>
        <div>${item.action_type || "unknown"} / ${item.decision || "none"}</div>
        <div>${item.principal || "-"} / ${item.agent || "-"} / ${item.environment || "-"}</div>
        <div>last event: ${item.last_event_type}</div>
        <div>events: ${item.event_count}</div>
      </div>
      <button type="button">Timeline</button>
    `;
    node.querySelector("button").addEventListener("click", async () => {
      selectedTraceId = item.trace_id;
      await loadTraceDetail(item.trace_id);
    });
    tracesEl.appendChild(node);
  }
}

async function loadTraces() {
  const suffix = traceQuery();
  const data = await api(`/api/ui/traces${suffix ? `?${suffix}` : ""}`);
  renderTraces(data.traces || []);
}

async function loadTraceDetail(traceId) {
  const data = await api(`/api/ui/traces/${encodeURIComponent(traceId)}`);
  traceDetailEl.className = "json";
  traceDetailEl.textContent = pretty(data);
}

async function runExplain() {
  const payload = explainInputEl.value;
  const data = await api("/api/ui/explain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: payload
  });
  explainOutputEl.className = "json";
  explainOutputEl.textContent = pretty(data);
}

async function refreshAll() {
  await loadReadiness();
  await loadApprovals();
  await loadTraces();
  if (selectedActionId) {
    await loadActionDetail(selectedActionId);
  }
  if (selectedTraceId) {
    await loadTraceDetail(selectedTraceId);
  }
}

async function decide(decision) {
  if (!selectedApproval) {
    return;
  }
  const payload = await api("/api/ui/approvals/decide", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ approval_id: selectedApproval.approval_id, decision })
  });
  actionEl.className = "json";
  actionEl.textContent = pretty(payload);
  await loadApprovals();
}

connectEl.addEventListener("click", async () => {
  try {
    await refreshAll();
    authStatusEl.textContent = "Authenticated operator data loaded.";
  } catch (error) {
    authStatusEl.textContent = `Authentication or data load failed: ${error.message}`;
  }
});

refreshEl.addEventListener("click", async () => {
  try {
    await refreshAll();
  } catch (error) {
    authStatusEl.textContent = `Refresh failed: ${error.message}`;
  }
});

approveEl.addEventListener("click", async () => {
  try {
    await decide("approve");
  } catch (error) {
    authStatusEl.textContent = `Approve failed: ${error.message}`;
  }
});

denyEl.addEventListener("click", async () => {
  try {
    await decide("deny");
  } catch (error) {
    authStatusEl.textContent = `Deny failed: ${error.message}`;
  }
});

refreshTracesEl.addEventListener("click", async () => {
  try {
    await loadTraces();
  } catch (error) {
    authStatusEl.textContent = `Trace refresh failed: ${error.message}`;
  }
});

applyTraceFilterEl.addEventListener("click", async () => {
  try {
    await loadTraces();
  } catch (error) {
    authStatusEl.textContent = `Trace filter failed: ${error.message}`;
  }
});

runExplainEl.addEventListener("click", async () => {
  try {
    await runExplain();
  } catch (error) {
    authStatusEl.textContent = `Explain failed: ${error.message}`;
  }
});
