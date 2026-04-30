const MAX_VISIBLE_ROWS = 100;

const storageKeys = {
  approvalColumns: "nomos.ui.approval.columns",
  approvalView: "nomos.ui.approval.savedView",
  traceViews: "nomos.ui.trace.savedViews"
};

const routeMeta = {
  overview: "Overview",
  approvals: "Approvals",
  investigations: "Investigations",
  upstreams: "Upstreams",
  explain: "Policy Explain"
};

const els = {
  authStatus: document.getElementById("auth-status"),
  token: document.getElementById("token"),
  connect: document.getElementById("connect"),
  refresh: document.getElementById("refresh"),
  breadcrumb: document.getElementById("breadcrumb"),
  pageTitle: document.getElementById("page-title"),
  workspace: document.getElementById("workspace"),
  overviewSummary: document.getElementById("overview-summary"),
  overviewHotspots: document.getElementById("overview-hotspots"),
  readiness: document.getElementById("readiness"),
  approvals: document.getElementById("approvals"),
  approvalSearch: document.getElementById("approval-search"),
  approvalStatusFilter: document.getElementById("approval-status-filter"),
  saveApprovalView: document.getElementById("save-approval-view"),
  approve: document.getElementById("approve"),
  deny: document.getElementById("deny"),
  actionDetail: document.getElementById("action-detail"),
  traces: document.getElementById("traces"),
  traceDetail: document.getElementById("trace-detail"),
  refreshTraces: document.getElementById("refresh-traces"),
  applyTraceFilter: document.getElementById("apply-trace-filter"),
  saveTraceView: document.getElementById("save-trace-view"),
  traceSavedView: document.getElementById("trace-saved-view"),
  traceID: document.getElementById("trace-id-filter"),
  traceAction: document.getElementById("trace-action-filter"),
  traceDecision: document.getElementById("trace-decision-filter"),
  tracePrincipal: document.getElementById("trace-principal-filter"),
  traceAgent: document.getElementById("trace-agent-filter"),
  traceEnv: document.getElementById("trace-env-filter"),
  upstreams: document.getElementById("upstreams"),
  upstreamDetail: document.getElementById("upstream-detail"),
  refreshUpstreams: document.getElementById("refresh-upstreams"),
  explainInput: document.getElementById("explain-input"),
  explainOutput: document.getElementById("explain-output"),
  runExplain: document.getElementById("run-explain")
};

const state = {
  route: "overview",
  readiness: null,
  approvals: [],
  traces: [],
  upstreams: [],
  selectedApproval: null,
  selectedActionID: "",
  selectedTraceID: "",
  selectedUpstream: "",
  approvalSort: { key: "expires_at", direction: "asc" },
  traceSort: { key: "last_timestamp", direction: "desc" },
  approvalColumns: loadApprovalColumns()
};

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function text(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  return String(value);
}

function clear(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function append(parent, ...children) {
  for (const child of children) {
    if (child === null || child === undefined) {
      continue;
    }
    if (typeof child === "string") {
      parent.appendChild(document.createTextNode(child));
    } else {
      parent.appendChild(child);
    }
  }
  return parent;
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "className") {
      node.className = value;
    } else if (key === "dataset") {
      for (const [dataKey, dataValue] of Object.entries(value)) {
        node.dataset[dataKey] = dataValue;
      }
    } else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (value !== false && value !== null && value !== undefined) {
      node.setAttribute(key, value === true ? "" : value);
    }
  }
  return append(node, ...children);
}

function setStatus(message, tone = "info") {
  els.authStatus.textContent = message;
  els.authStatus.dataset.tone = tone;
}

function authHeaders() {
  const token = els.token.value.trim();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function api(path, options = {}) {
  const headers = { ...authHeaders(), ...(options.headers || {}) };
  const response = await fetch(path, { ...options, headers });
  const raw = await response.text();
  let payload = {};
  try {
    payload = raw ? JSON.parse(raw) : {};
  } catch {
    payload = { raw };
  }
  if (!response.ok) {
    throw new Error(payload.reason || payload.raw || `${response.status}`);
  }
  return payload;
}

function routeFromHash() {
  const route = (location.hash || "#/overview").replace(/^#\/?/, "").trim();
  return routeMeta[route] ? route : "overview";
}

function routeTo(route) {
  state.route = routeMeta[route] ? route : "overview";
  for (const panel of document.querySelectorAll("[data-route-panel]")) {
    panel.classList.toggle("active", panel.dataset.routePanel === state.route);
  }
  for (const link of document.querySelectorAll("[data-route]")) {
    const active = link.dataset.route === state.route;
    link.classList.toggle("active", active);
    link.setAttribute("aria-current", active ? "page" : "false");
  }
  els.pageTitle.textContent = routeMeta[state.route];
  els.breadcrumb.textContent = `Console / ${routeMeta[state.route]}`;
  document.title = `Nomos Operator Console - ${routeMeta[state.route]}`;
  if (location.hash !== `#/${state.route}`) {
    history.replaceState(null, "", `#/${state.route}`);
  }
  els.workspace.focus({ preventScroll: true });
}

function boundedRows(items) {
  return {
    rows: items.slice(0, MAX_VISIBLE_ROWS),
    truncated: items.length > MAX_VISIBLE_ROWS
  };
}

function statusBadge(value) {
  const normalized = text(value).toLowerCase();
  let tone = "neutral";
  if (["ready", "healthy", "allow", "success", "active"].includes(normalized)) tone = "good";
  if (["watch", "pending", "configured"].includes(normalized)) tone = "warn";
  if (["degraded", "deny", "denied_policy", "expired", "not_ready"].includes(normalized)) tone = "bad";
  return el("span", { className: `badge ${tone}` }, text(value));
}

function metricCard(label, value, detail, tone = "") {
  return el("article", { className: `metric-card ${tone}` },
    el("span", { className: "metric-label" }, label),
    el("strong", {}, text(value)),
    el("span", { className: "metric-detail" }, detail)
  );
}

async function loadReadiness() {
  const data = await api("/api/ui/readiness");
  state.readiness = data;
  els.readiness.className = "json";
  els.readiness.textContent = pretty(data);
  renderOverview();
}

async function loadApprovals() {
  const data = await api("/api/ui/approvals?limit=200");
  state.approvals = data.approvals || [];
  renderApprovals();
  renderOverview();
}

function filteredApprovals() {
  const query = els.approvalSearch.value.trim().toLowerCase();
  const status = els.approvalStatusFilter.value;
  let items = state.approvals.filter((item) => {
    if (status === "active" && item.expired) return false;
    if (status === "expired" && !item.expired) return false;
    if (!query) return true;
    return [item.principal, item.agent, item.environment, item.action_type, item.resource, item.approval_id, item.trace_id]
      .some((value) => text(value).toLowerCase().includes(query));
  });
  items = items.sort((a, b) => compareValues(a[state.approvalSort.key], b[state.approvalSort.key], state.approvalSort.direction));
  return items;
}

function compareValues(left, right, direction) {
  const a = text(left).toLowerCase();
  const b = text(right).toLowerCase();
  const result = a < b ? -1 : a > b ? 1 : 0;
  return direction === "desc" ? -result : result;
}

function approvalColumns() {
  return [
    { key: "principal", label: "Principal" },
    { key: "action_type", label: "Action" },
    { key: "resource", label: "Resource" },
    { key: "expires_at", label: "Expires" },
    { key: "scope_type", label: "Scope" }
  ].filter((column) => state.approvalColumns[column.key] !== false);
}

function renderApprovals() {
  const items = filteredApprovals();
  clear(els.approvals);
  if (!items.length) {
    els.approvals.className = "table-region empty";
    els.approvals.textContent = "No approvals matched the current view.";
    setApprovalButtons(false);
    return;
  }
  els.approvals.className = "table-region";
  const table = el("table", { className: "data-grid", role: "grid", "aria-label": "Approval inbox table" });
  const thead = el("thead");
  const headerRow = el("tr");
  append(headerRow, el("th", {}, "Inspect"));
  for (const column of approvalColumns()) {
    append(headerRow, sortableHeader(column.label, column.key, "approval"));
  }
  append(headerRow, el("th", {}, "Status"));
  append(thead, headerRow);
  const tbody = el("tbody");
  const { rows, truncated } = boundedRows(items);
  for (const item of rows) {
    const selected = state.selectedApproval && state.selectedApproval.approval_id === item.approval_id;
    const row = el("tr", { className: selected ? "selected" : "" });
    append(row, el("td", {}, el("button", { type: "button", className: "link-button", onclick: () => selectApproval(item) }, "Inspect")));
    for (const column of approvalColumns()) {
      const cell = el("td", { dataset: { column: column.key } }, text(item[column.key]));
      if (column.key === "resource") {
        appendArgumentPreview(cell, item.argument_preview);
      }
      append(row, cell);
    }
    append(row, el("td", {}, item.expired ? statusBadge("expired") : statusBadge("active")));
    append(tbody, row);
  }
  append(table, thead, tbody);
  append(els.approvals, table);
  if (truncated) {
    append(els.approvals, el("p", { className: "table-note" }, `Showing first ${MAX_VISIBLE_ROWS} rows. Narrow filters to inspect more.`));
  }
  applyColumnVisibility();
}

function sortableHeader(label, key, tableName) {
  const button = el("button", {
    type: "button",
    className: "sort-button",
    onclick: () => {
      const sort = tableName === "approval" ? state.approvalSort : state.traceSort;
      sort.direction = sort.key === key && sort.direction === "asc" ? "desc" : "asc";
      sort.key = key;
      tableName === "approval" ? renderApprovals() : renderTraces();
    }
  }, label);
  return el("th", {}, button);
}

function selectApproval(item) {
  state.selectedApproval = item;
  state.selectedActionID = item.action_id;
  setApprovalButtons(!item.expired);
  renderApprovals();
  loadActionDetail(item.action_id).catch((error) => setStatus(`Action detail failed: ${error.message}`, "error"));
}

function setApprovalButtons(enabled) {
  els.approve.disabled = !enabled;
  els.deny.disabled = !enabled;
}

async function loadActionDetail(actionID) {
  const data = await api(`/api/ui/actions/${encodeURIComponent(actionID)}`);
  els.actionDetail.className = "json";
  els.actionDetail.textContent = pretty(data);
}

function appendArgumentPreview(container, preview) {
  if (!preview) {
    return;
  }
  const details = el("details", { className: "argument-preview" },
    el("summary", {}, "Forwarded arguments"),
    el("pre", { className: "json compact" }, pretty(preview))
  );
  append(container, details);
}

async function decide(decision) {
  if (!state.selectedApproval) {
    return;
  }
  const payload = await api("/api/ui/approvals/decide", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ approval_id: state.selectedApproval.approval_id, decision })
  });
  els.actionDetail.className = "json";
  els.actionDetail.textContent = pretty(payload);
  setApprovalButtons(false);
  await loadApprovals();
}

function traceQuery() {
  const params = new URLSearchParams();
  const fields = [
    ["trace_id", els.traceID.value],
    ["action_type", els.traceAction.value],
    ["decision", els.traceDecision.value],
    ["principal", els.tracePrincipal.value],
    ["agent", els.traceAgent.value],
    ["environment", els.traceEnv.value]
  ];
  for (const [key, value] of fields) {
    if (value.trim()) params.set(key, value.trim());
  }
  params.set("limit", "200");
  return params.toString();
}

async function loadTraces() {
  const suffix = traceQuery();
  const data = await api(`/api/ui/traces?${suffix}`);
  state.traces = data.traces || [];
  renderTraces();
  renderOverview();
}

function renderTraces() {
  clear(els.traces);
  if (!state.traces.length) {
    els.traces.className = "table-region empty";
    els.traces.textContent = "No traces matched the current filter.";
    return;
  }
  els.traces.className = "table-region";
  const items = [...state.traces].sort((a, b) => compareValues(a[state.traceSort.key], b[state.traceSort.key], state.traceSort.direction));
  const table = el("table", { className: "data-grid", role: "grid", "aria-label": "Investigation trace table" });
  const headerRow = el("tr");
  append(headerRow,
    el("th", {}, "Timeline"),
    sortableHeader("Trace", "trace_id", "trace"),
    sortableHeader("Action", "action_type", "trace"),
    sortableHeader("Decision", "decision", "trace"),
    sortableHeader("Last Event", "last_event_type", "trace"),
    sortableHeader("Events", "event_count", "trace")
  );
  append(table, el("thead", {}, headerRow));
  const tbody = el("tbody");
  const { rows, truncated } = boundedRows(items);
  for (const item of rows) {
    const selected = state.selectedTraceID === item.trace_id;
    const row = el("tr", { className: selected ? "selected" : "" },
      el("td", {}, el("button", { type: "button", className: "link-button", onclick: () => selectTrace(item.trace_id) }, "Open")),
      el("td", {}, text(item.trace_id)),
      el("td", {}, text(item.action_type)),
      el("td", {}, statusBadge(item.decision || "none")),
      el("td", {}, text(item.last_event_type)),
      el("td", {}, text(item.event_count))
    );
    append(tbody, row);
  }
  append(table, tbody);
  append(els.traces, table);
  if (truncated) {
    append(els.traces, el("p", { className: "table-note" }, `Showing first ${MAX_VISIBLE_ROWS} rows. Narrow filters to inspect more.`));
  }
}

function selectTrace(traceID) {
  state.selectedTraceID = traceID;
  renderTraces();
  loadTraceDetail(traceID).catch((error) => setStatus(`Trace detail failed: ${error.message}`, "error"));
}

async function loadTraceDetail(traceID) {
  const data = await api(`/api/ui/traces/${encodeURIComponent(traceID)}`);
  els.traceDetail.className = "json";
  els.traceDetail.textContent = pretty(data);
}

async function loadUpstreams() {
  const data = await api("/api/ui/upstreams");
  state.upstreams = data.upstreams || [];
  renderUpstreams();
  renderOverview();
}

function renderUpstreams() {
  clear(els.upstreams);
  if (!state.upstreams.length) {
    els.upstreams.className = "table-region empty";
    els.upstreams.textContent = "No upstream MCP servers are configured or observed.";
    return;
  }
  els.upstreams.className = "table-region";
  const table = el("table", { className: "data-grid", role: "grid", "aria-label": "Upstream health table" });
  append(table, el("thead", {}, el("tr", {},
    el("th", {}, "Inspect"),
    el("th", {}, "Server"),
    el("th", {}, "Health"),
    el("th", {}, "Transport"),
    el("th", {}, "Errors"),
    el("th", {}, "Latency p95"),
    el("th", {}, "Breaker")
  )));
  const tbody = el("tbody");
  for (const item of state.upstreams) {
    const selected = state.selectedUpstream === item.name;
    append(tbody, el("tr", { className: selected ? "selected" : "" },
      el("td", {}, el("button", { type: "button", className: "link-button", onclick: () => selectUpstream(item) }, "Open")),
      el("td", {}, text(item.name)),
      el("td", {}, statusBadge(item.health)),
      el("td", {}, text(item.transport)),
      el("td", {}, `${text(item.error_count)} / ${text(item.request_count)}`),
      el("td", {}, item.p95_latency_ms ? `${item.p95_latency_ms} ms` : "-"),
      el("td", {}, statusBadge(item.breaker_state))
    ));
  }
  append(table, tbody);
  append(els.upstreams, table);
}

function selectUpstream(item) {
  state.selectedUpstream = item.name;
  els.upstreamDetail.className = "json";
  els.upstreamDetail.textContent = pretty(item);
  renderUpstreams();
}

async function runExplain() {
  const data = await api("/api/ui/explain", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: els.explainInput.value
  });
  els.explainOutput.className = "json";
  els.explainOutput.textContent = pretty(data);
}

function renderOverview() {
  clear(els.overviewSummary);
  const pending = state.approvals.filter((item) => !item.expired).length;
  const expired = state.approvals.filter((item) => item.expired).length;
  const degraded = state.upstreams.filter((item) => ["degraded", "watch"].includes(item.health)).length;
  append(els.overviewSummary,
    metricCard("Readiness", state.readiness ? state.readiness.overall_status : "not loaded", state.readiness ? state.readiness.assurance_level : "connect to inspect", state.readiness && state.readiness.overall_status === "READY" ? "good" : "warn"),
    metricCard("Approvals", pending, `${expired} expired`, expired ? "bad" : "warn"),
    metricCard("Investigations", state.traces.length, "recent traces in current filter", ""),
    metricCard("Upstreams", state.upstreams.length, `${degraded} need attention`, degraded ? "bad" : "good")
  );
  renderHotspots();
}

function renderHotspots() {
  clear(els.overviewHotspots);
  const urgentApprovals = state.approvals.filter((item) => item.expired).slice(0, 3);
  const badUpstreams = state.upstreams.filter((item) => ["degraded", "watch"].includes(item.health)).slice(0, 3);
  if (!urgentApprovals.length && !badUpstreams.length) {
    els.overviewHotspots.className = "list empty";
    els.overviewHotspots.textContent = "No loaded hotspots. Connect or refresh to inspect current posture.";
    return;
  }
  els.overviewHotspots.className = "list";
  for (const item of urgentApprovals) {
    const row = el("button", { type: "button", className: "hotspot", onclick: () => { routeTo("approvals"); selectApproval(item); } },
      el("strong", {}, "Expired approval"),
      el("span", {}, `${text(item.action_type)} ${text(item.resource)}`)
    );
    append(els.overviewHotspots, row);
  }
  for (const item of badUpstreams) {
    append(els.overviewHotspots, el("button", { type: "button", className: "hotspot", onclick: () => { routeTo("upstreams"); selectUpstream(item); } },
      el("strong", {}, `${item.health} upstream`),
      el("span", {}, `${item.name}: ${item.error_count}/${item.request_count} errors`)
    ));
  }
}

async function refreshAll() {
  const tasks = [loadReadiness(), loadApprovals(), loadTraces(), loadUpstreams()];
  const results = await Promise.allSettled(tasks);
  const failures = results.filter((result) => result.status === "rejected");
  if (failures.length) {
    setStatus(`Loaded with ${failures.length} unavailable view(s): ${failures.map((f) => f.reason.message).join("; ")}`, "warn");
  } else {
    setStatus("Authenticated operator data loaded.", "good");
  }
}

function loadApprovalColumns() {
  try {
    const raw = localStorage.getItem(storageKeys.approvalColumns);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function applyColumnVisibility() {
  for (const checkbox of document.querySelectorAll("[data-approval-column]")) {
    state.approvalColumns[checkbox.dataset.approvalColumn] = checkbox.checked;
  }
  localStorage.setItem(storageKeys.approvalColumns, JSON.stringify(state.approvalColumns));
}

function initializeColumnControls() {
  for (const checkbox of document.querySelectorAll("[data-approval-column]")) {
    const key = checkbox.dataset.approvalColumn;
    if (state.approvalColumns[key] === false) {
      checkbox.checked = false;
    }
    checkbox.addEventListener("change", () => {
      applyColumnVisibility();
      renderApprovals();
    });
  }
}

function saveApprovalView() {
  const view = {
    search: els.approvalSearch.value,
    status: els.approvalStatusFilter.value,
    columns: state.approvalColumns,
    sort: state.approvalSort
  };
  localStorage.setItem(storageKeys.approvalView, JSON.stringify(view));
  setStatus("Approval view saved locally.", "good");
}

function loadTraceSavedViews() {
  clear(els.traceSavedView);
  append(els.traceSavedView, el("option", { value: "" }, "Manual filters"));
  let views = {};
  try {
    views = JSON.parse(localStorage.getItem(storageKeys.traceViews) || "{}");
  } catch {
    views = {};
  }
  for (const name of Object.keys(views).sort()) {
    append(els.traceSavedView, el("option", { value: name }, name));
  }
  return views;
}

function saveTraceFilter() {
  const views = loadTraceSavedViews();
  const name = `view-${new Date().toISOString().replace(/[:.]/g, "-")}`;
  views[name] = {
    trace_id: els.traceID.value,
    action_type: els.traceAction.value,
    decision: els.traceDecision.value,
    principal: els.tracePrincipal.value,
    agent: els.traceAgent.value,
    environment: els.traceEnv.value
  };
  localStorage.setItem(storageKeys.traceViews, JSON.stringify(views));
  loadTraceSavedViews();
  els.traceSavedView.value = name;
  setStatus(`Trace filter saved as ${name}.`, "good");
}

function applyTraceSavedView() {
  const views = loadTraceSavedViews();
  const selected = views[els.traceSavedView.value];
  if (!selected) {
    return;
  }
  els.traceID.value = selected.trace_id || "";
  els.traceAction.value = selected.action_type || "";
  els.traceDecision.value = selected.decision || "";
  els.tracePrincipal.value = selected.principal || "";
  els.traceAgent.value = selected.agent || "";
  els.traceEnv.value = selected.environment || "";
}

function focusRouteFilter() {
  const target = {
    approvals: els.approvalSearch,
    investigations: els.traceID,
    explain: els.explainInput
  }[state.route];
  if (target) {
    target.focus();
  }
}

function handleKeyboardShortcuts(event) {
  if (event.altKey && /^[1-5]$/.test(event.key)) {
    event.preventDefault();
    routeTo(["overview", "approvals", "investigations", "upstreams", "explain"][Number(event.key) - 1]);
    return;
  }
  if (event.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName)) {
    event.preventDefault();
    focusRouteFilter();
  }
}

els.connect.addEventListener("click", () => refreshAll().catch((error) => setStatus(`Connect failed: ${error.message}`, "error")));
els.refresh.addEventListener("click", () => refreshAll().catch((error) => setStatus(`Refresh failed: ${error.message}`, "error")));
els.approvalSearch.addEventListener("input", renderApprovals);
els.approvalStatusFilter.addEventListener("change", renderApprovals);
els.saveApprovalView.addEventListener("click", saveApprovalView);
els.approve.addEventListener("click", () => decide("approve").catch((error) => setStatus(`Approve failed: ${error.message}`, "error")));
els.deny.addEventListener("click", () => decide("deny").catch((error) => setStatus(`Deny failed: ${error.message}`, "error")));
els.refreshTraces.addEventListener("click", () => loadTraces().catch((error) => setStatus(`Trace refresh failed: ${error.message}`, "error")));
els.applyTraceFilter.addEventListener("click", () => loadTraces().catch((error) => setStatus(`Trace filter failed: ${error.message}`, "error")));
els.saveTraceView.addEventListener("click", saveTraceFilter);
els.traceSavedView.addEventListener("change", () => {
  applyTraceSavedView();
  loadTraces().catch((error) => setStatus(`Trace saved view failed: ${error.message}`, "error"));
});
els.refreshUpstreams.addEventListener("click", () => loadUpstreams().catch((error) => setStatus(`Upstream refresh failed: ${error.message}`, "error")));
els.runExplain.addEventListener("click", () => runExplain().catch((error) => setStatus(`Explain failed: ${error.message}`, "error")));
window.addEventListener("hashchange", () => routeTo(routeFromHash()));
window.addEventListener("keydown", handleKeyboardShortcuts);

initializeColumnControls();
loadTraceSavedViews();
routeTo(routeFromHash());
renderOverview();
