package gateway

import (
	"database/sql"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	neturl "net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/approvalpreview"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/version"
)

//go:embed operatorui/*
var operatorUIFS embed.FS

type uiReadinessResponse struct {
	OverallStatus       string             `json:"overall_status"`
	Checks              []UIReadinessCheck `json:"checks"`
	PolicyBundleHash    string             `json:"policy_bundle_hash"`
	PolicyBundleSources []string           `json:"policy_bundle_sources,omitempty"`
	PolicyBundleInputs  []map[string]any   `json:"policy_bundle_inputs,omitempty"`
	AssuranceLevel      string             `json:"assurance_level"`
	EngineVersion       string             `json:"engine_version"`
	DeploymentMode      string             `json:"deployment_mode"`
	ApprovalsEnabled    bool               `json:"approvals_enabled"`
	ConfigPath          string             `json:"config_path,omitempty"`
	OperatorPrincipal   string             `json:"operator_principal,omitempty"`
	GuaranteeNote       string             `json:"guarantee_note,omitempty"`
}

type uiApprovalRecord struct {
	ApprovalID      string          `json:"approval_id"`
	Status          string          `json:"status"`
	ExpiresAt       string          `json:"expires_at"`
	Expired         bool            `json:"expired"`
	Principal       string          `json:"principal"`
	Agent           string          `json:"agent"`
	Environment     string          `json:"environment"`
	ActionType      string          `json:"action_type"`
	Resource        string          `json:"resource"`
	ScopeType       string          `json:"scope_type"`
	ActionID        string          `json:"action_id"`
	TraceID         string          `json:"trace_id"`
	ArgumentPreview json.RawMessage `json:"argument_preview,omitempty"`
}

type uiActionDetailResponse struct {
	ActionID              string         `json:"action_id"`
	TraceID               string         `json:"trace_id"`
	ActionType            string         `json:"action_type"`
	Resource              string         `json:"resource"`
	ResourceNormalized    string         `json:"resource_normalized"`
	ParamsHash            string         `json:"params_hash"`
	Decision              string         `json:"decision"`
	Reason                string         `json:"reason"`
	MatchedRuleIDs        []string       `json:"matched_rule_ids"`
	Obligations           map[string]any `json:"obligations"`
	RiskLevel             string         `json:"risk_level"`
	RiskFlags             []string       `json:"risk_flags"`
	SandboxMode           string         `json:"sandbox_mode"`
	NetworkMode           string         `json:"network_mode"`
	AssuranceLevel        string         `json:"assurance_level"`
	PolicyBundleHash      string         `json:"policy_bundle_hash"`
	PolicyBundleSources   []string       `json:"policy_bundle_sources,omitempty"`
	ResultClassification  string         `json:"result_classification,omitempty"`
	ParamsRedactedSummary string         `json:"params_redacted_summary,omitempty"`
	ResultRedactedSummary string         `json:"result_redacted_summary,omitempty"`
	ExecutorMetadata      map[string]any `json:"executor_metadata,omitempty"`
	Principal             string         `json:"principal,omitempty"`
	Agent                 string         `json:"agent,omitempty"`
	Environment           string         `json:"environment,omitempty"`
	Audit                 uiAuditLink    `json:"audit"`
	Approval              *uiApprovalRef `json:"approval,omitempty"`
}

type uiAuditLink struct {
	EventType     string `json:"event_type"`
	EventHash     string `json:"event_hash,omitempty"`
	PrevEventHash string `json:"prev_event_hash,omitempty"`
}

type uiApprovalRef struct {
	ApprovalID string `json:"approval_id"`
	Status     string `json:"status"`
	ExpiresAt  string `json:"expires_at"`
	Expired    bool   `json:"expired"`
	ScopeType  string `json:"scope_type"`
}

type UIReadinessCheck struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

type UIReadinessReport struct {
	OverallStatus       string             `json:"overall_status"`
	Checks              []UIReadinessCheck `json:"checks"`
	PolicyBundleHash    string             `json:"policy_bundle_hash,omitempty"`
	PolicyBundleSources []string           `json:"policy_bundle_sources,omitempty"`
	PolicyBundleInputs  []map[string]any   `json:"policy_bundle_inputs,omitempty"`
	AssuranceLevel      string             `json:"assurance_level,omitempty"`
	EngineVersion       string             `json:"engine_version,omitempty"`
}

type uiTraceListResponse struct {
	Traces []audit.TraceSummary `json:"traces"`
}

type uiTraceDetailResponse struct {
	TraceID string         `json:"trace_id"`
	Events  []uiTraceEvent `json:"events"`
}

type uiTraceEvent struct {
	Timestamp            string         `json:"timestamp"`
	EventType            string         `json:"event_type"`
	ActionID             string         `json:"action_id,omitempty"`
	ActionType           string         `json:"action_type,omitempty"`
	Decision             string         `json:"decision,omitempty"`
	Reason               string         `json:"reason,omitempty"`
	ApprovalID           string         `json:"approval_id,omitempty"`
	MatchedRuleIDs       []string       `json:"matched_rule_ids,omitempty"`
	ResultClassification string         `json:"result_classification,omitempty"`
	RiskLevel            string         `json:"risk_level,omitempty"`
	RiskFlags            []string       `json:"risk_flags,omitempty"`
	SandboxMode          string         `json:"sandbox_mode,omitempty"`
	NetworkMode          string         `json:"network_mode,omitempty"`
	AssuranceLevel       string         `json:"assurance_level,omitempty"`
	ActionSummary        string         `json:"action_summary,omitempty"`
	ExecutorMetadata     map[string]any `json:"executor_metadata,omitempty"`
}

type uiUpstreamListResponse struct {
	GeneratedAt string             `json:"generated_at"`
	DataSource  string             `json:"data_source"`
	Upstreams   []uiUpstreamRecord `json:"upstreams"`
}

type uiUpstreamRecord struct {
	Name             string              `json:"name"`
	Transport        string              `json:"transport"`
	Endpoint         string              `json:"endpoint,omitempty"`
	Command          string              `json:"command,omitempty"`
	BreakerState     string              `json:"breaker_state"`
	BreakerEnabled   bool                `json:"breaker_enabled"`
	Health           string              `json:"health"`
	RequestCount     int                 `json:"request_count"`
	ErrorCount       int                 `json:"error_count"`
	ErrorRate        float64             `json:"error_rate"`
	AvgLatencyMS     int64               `json:"avg_latency_ms"`
	P95LatencyMS     int64               `json:"p95_latency_ms"`
	LastEventAt      string              `json:"last_event_at,omitempty"`
	RecentFailures   []uiUpstreamFailure `json:"recent_failures,omitempty"`
	ConfigurationRef string              `json:"configuration_ref"`
}

type uiUpstreamFailure struct {
	Timestamp            string `json:"timestamp"`
	EventType            string `json:"event_type"`
	TraceID              string `json:"trace_id,omitempty"`
	ActionID             string `json:"action_id,omitempty"`
	ActionType           string `json:"action_type,omitempty"`
	Decision             string `json:"decision,omitempty"`
	ResultClassification string `json:"result_classification,omitempty"`
}

func (g *Gateway) handleUIRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/ui" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/ui/", http.StatusTemporaryRedirect)
}

func (g *Gateway) handleUIStatic(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(operatorUIFS, "operatorui")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	http.StripPrefix("/ui/", http.FileServer(http.FS(sub))).ServeHTTP(w, r)
}

func (g *Gateway) handleUIReadiness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	principal, ok := g.requireOperatorUIAuth(w, r)
	if !ok {
		return
	}
	report := UIReadinessReport{
		OverallStatus:  "UNKNOWN",
		Checks:         []UIReadinessCheck{},
		AssuranceLevel: g.assuranceLevel,
		EngineVersion:  version.Current().Version,
	}
	if g.uiReadinessReporter != nil {
		if next, err := g.uiReadinessReporter(); err == nil {
			report = next
		}
	}
	g.writeUIJSON(w, buildUIReadinessResponse(report, g.cfg, g.PolicyBundleHash(), g.PolicyBundleSources(), g.assuranceLevel, principal))
}

func (g *Gateway) handleUIApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, ok := g.requireOperatorUIAuth(w, r); !ok {
		return
	}
	if !g.cfg.Approvals.Enabled || g.approvals == nil {
		g.respondError(w, http.StatusNotFound, "not_enabled", "approvals are not enabled")
		return
	}
	limit := 25
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}
	records, err := g.approvals.ListPending(r.Context(), limit)
	if err != nil {
		g.respondError(w, http.StatusInternalServerError, "approval_error", err.Error())
		return
	}
	now := g.now().UTC()
	out := make([]uiApprovalRecord, 0, len(records))
	for _, rec := range records {
		item := uiApprovalRecord{
			ApprovalID:  rec.ApprovalID,
			Status:      rec.Status,
			ExpiresAt:   rec.ExpiresAt.Format(time.RFC3339Nano),
			Expired:     now.After(rec.ExpiresAt),
			Principal:   rec.Principal,
			Agent:       rec.Agent,
			Environment: rec.Environment,
			ActionType:  rec.ActionType,
			Resource:    rec.Resource,
			ScopeType:   rec.ScopeType,
			ActionID:    rec.ActionID,
			TraceID:     rec.TraceID,
		}
		if raw := strings.TrimSpace(rec.ArgumentPreviewJSON); raw != "" && json.Valid([]byte(raw)) {
			item.ArgumentPreview = json.RawMessage(raw)
		}
		out = append(out, item)
	}
	g.writeUIJSON(w, map[string]any{"approvals": out})
}

func (g *Gateway) handleUIApprovalDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, ok := g.requireOperatorUIAuth(w, r); !ok {
		return
	}
	body, err := action.ReadRequestBytes(r.Body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	req, err := decodeApprovalDecisionRequest(body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	g.applyApprovalDecision(w, r, req, "approval.decided.ui")
}

func (g *Gateway) handleUIActionDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, ok := g.requireOperatorUIAuth(w, r); !ok {
		return
	}
	actionID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/ui/actions/"))
	if actionID == "" {
		g.respondError(w, http.StatusBadRequest, "validation_error", "action_id is required")
		return
	}
	sqlitePath := audit.FirstSQLiteSinkPath(g.cfg.Audit.Sink)
	event, err := audit.LoadActionDetail(sqlitePath, actionID)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			status = http.StatusNotFound
		}
		if strings.Contains(strings.ToLower(err.Error()), "sqlite audit sink") {
			status = http.StatusNotFound
		}
		g.respondError(w, status, "audit_error", err.Error())
		return
	}
	resp := buildUIActionDetailResponse(event)
	if g.approvals != nil {
		if records, err := g.approvals.ListPending(r.Context(), 200); err == nil {
			now := g.now().UTC()
			for _, rec := range records {
				if rec.ActionID == actionID {
					resp.Approval = &uiApprovalRef{
						ApprovalID: rec.ApprovalID,
						Status:     rec.Status,
						ExpiresAt:  rec.ExpiresAt.Format(time.RFC3339Nano),
						Expired:    now.After(rec.ExpiresAt),
						ScopeType:  rec.ScopeType,
					}
					break
				}
			}
		}
	}
	g.writeUIJSON(w, resp)
}

func (g *Gateway) handleUITraceList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, ok := g.requireOperatorUIAuth(w, r); !ok {
		return
	}
	sqlitePath := audit.FirstSQLiteSinkPath(g.cfg.Audit.Sink)
	filter := audit.TraceListFilter{
		TraceID:     strings.TrimSpace(r.URL.Query().Get("trace_id")),
		ActionType:  strings.TrimSpace(r.URL.Query().Get("action_type")),
		Decision:    strings.TrimSpace(r.URL.Query().Get("decision")),
		Principal:   strings.TrimSpace(r.URL.Query().Get("principal")),
		Agent:       strings.TrimSpace(r.URL.Query().Get("agent")),
		Environment: strings.TrimSpace(r.URL.Query().Get("environment")),
		Limit:       50,
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 200 {
			filter.Limit = parsed
		}
	}
	traces, err := audit.ListTraceSummaries(sqlitePath, filter)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "sqlite audit sink") {
			status = http.StatusNotFound
		}
		g.respondError(w, status, "audit_error", err.Error())
		return
	}
	g.writeUIJSON(w, uiTraceListResponse{Traces: traces})
}

func (g *Gateway) handleUITraceDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, ok := g.requireOperatorUIAuth(w, r); !ok {
		return
	}
	traceID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/ui/traces/"))
	if traceID == "" {
		g.respondError(w, http.StatusBadRequest, "validation_error", "trace_id is required")
		return
	}
	sqlitePath := audit.FirstSQLiteSinkPath(g.cfg.Audit.Sink)
	events, err := audit.LoadTraceEvents(sqlitePath, traceID)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(strings.ToLower(err.Error()), "trace not found") || strings.Contains(strings.ToLower(err.Error()), "sqlite audit sink") {
			status = http.StatusNotFound
		}
		g.respondError(w, status, "audit_error", err.Error())
		return
	}
	audit.SortTraceEvents(events)
	out := make([]uiTraceEvent, 0, len(events))
	for _, event := range events {
		out = append(out, uiTraceEvent{
			Timestamp:            event.Timestamp.UTC().Format(time.RFC3339Nano),
			EventType:            event.EventType,
			ActionID:             event.ActionID,
			ActionType:           event.ActionType,
			Decision:             event.Decision,
			Reason:               event.Reason,
			ApprovalID:           event.ApprovalID,
			MatchedRuleIDs:       append([]string{}, event.MatchedRuleIDs...),
			ResultClassification: event.ResultClassification,
			RiskLevel:            event.RiskLevel,
			RiskFlags:            append([]string{}, event.RiskFlags...),
			SandboxMode:          event.SandboxMode,
			NetworkMode:          event.NetworkMode,
			AssuranceLevel:       event.AssuranceLevel,
			ActionSummary:        event.ActionSummary,
			ExecutorMetadata:     cloneMap(event.ExecutorMetadata),
		})
	}
	g.writeUIJSON(w, uiTraceDetailResponse{TraceID: traceID, Events: out})
}

func (g *Gateway) handleUIUpstreams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, ok := g.requireOperatorUIAuth(w, r); !ok {
		return
	}
	resp, err := buildUIUpstreamListResponse(g.cfg, audit.FirstSQLiteSinkPath(g.cfg.Audit.Sink), g.now().UTC())
	if err != nil {
		g.respondError(w, http.StatusInternalServerError, "upstream_ui_error", err.Error())
		return
	}
	g.writeUIJSON(w, resp)
}

func (g *Gateway) handleUIExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, ok := g.requireOperatorUIAuth(w, r); !ok {
		return
	}
	body, err := action.ReadRequestBytes(r.Body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	act, err := action.DecodeAction(body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	payload, err := g.explainAction(act)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "normalization_error", err.Error())
		return
	}
	g.writeUIJSON(w, payload)
}

func buildUIReadinessResponse(report UIReadinessReport, cfg Config, bundleHash string, bundleSources []string, assuranceLevel, principal string) uiReadinessResponse {
	effectiveBundleHash := report.PolicyBundleHash
	if strings.TrimSpace(effectiveBundleHash) == "" {
		effectiveBundleHash = bundleHash
	}
	effectiveBundleSources := report.PolicyBundleSources
	if len(effectiveBundleSources) == 0 {
		effectiveBundleSources = append([]string{}, bundleSources...)
	}
	effectiveAssurance := report.AssuranceLevel
	if strings.TrimSpace(effectiveAssurance) == "" {
		effectiveAssurance = assuranceLevel
	}
	guaranteeNote := "Operator note: unmanaged and remote_dev deployments remain best-effort for full mediation."
	switch strings.ToLower(strings.TrimSpace(cfg.Runtime.DeploymentMode)) {
	case "ci", "k8s":
		guaranteeNote = "Operator note: controlled runtimes still require verified evidence before Nomos should be treated as STRONG."
	}
	return uiReadinessResponse{
		OverallStatus:       report.OverallStatus,
		Checks:              append([]UIReadinessCheck{}, report.Checks...),
		PolicyBundleHash:    effectiveBundleHash,
		PolicyBundleSources: effectiveBundleSources,
		PolicyBundleInputs:  append([]map[string]any{}, report.PolicyBundleInputs...),
		AssuranceLevel:      effectiveAssurance,
		EngineVersion:       version.Current().Version,
		DeploymentMode:      cfg.Runtime.DeploymentMode,
		ApprovalsEnabled:    cfg.Approvals.Enabled,
		ConfigPath:          cfg.SourcePath,
		OperatorPrincipal:   principal,
		GuaranteeNote:       guaranteeNote,
	}
}

func buildUIUpstreamListResponse(cfg Config, sqlitePath string, now time.Time) (uiUpstreamListResponse, error) {
	evidence, dataSource, err := loadUIUpstreamEvidence(sqlitePath, 1200)
	if err != nil {
		return uiUpstreamListResponse{}, err
	}
	records := make([]uiUpstreamRecord, 0, len(cfg.MCP.UpstreamServers)+len(evidence))
	seen := map[string]struct{}{}
	for idx, server := range cfg.MCP.UpstreamServers {
		name := strings.TrimSpace(server.Name)
		if name == "" {
			name = "upstream-" + strconv.Itoa(idx+1)
		}
		key := strings.ToLower(name)
		seen[key] = struct{}{}
		stats := evidence[key]
		records = append(records, buildUIUpstreamRecord(name, server, cfg.MCP.Breaker, stats, idx+1))
	}
	for key, stats := range evidence {
		if _, ok := seen[key]; ok {
			continue
		}
		records = append(records, buildUIUpstreamRecord(stats.name, MCPUpstreamServerConfig{
			Name:      stats.name,
			Transport: "unknown",
		}, cfg.MCP.Breaker, stats, len(records)+1))
	}
	sort.SliceStable(records, func(i, j int) bool {
		return strings.ToLower(records[i].Name) < strings.ToLower(records[j].Name)
	})
	return uiUpstreamListResponse{
		GeneratedAt: now.UTC().Format(time.RFC3339Nano),
		DataSource:  dataSource,
		Upstreams:   records,
	}, nil
}

type uiUpstreamEvidence struct {
	name          string
	requests      map[string]struct{}
	errorCount    int
	latencyMS     []int64
	lastEventAt   time.Time
	recentFailure []uiUpstreamFailure
}

func loadUIUpstreamEvidence(sqlitePath string, limit int) (map[string]*uiUpstreamEvidence, string, error) {
	out := map[string]*uiUpstreamEvidence{}
	if strings.TrimSpace(sqlitePath) == "" {
		return out, "config_only", nil
	}
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		return nil, "", err
	}
	defer db.Close()
	if limit <= 0 {
		limit = 1200
	}
	rows, err := db.Query(`SELECT payload_json FROM audit_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, "", err
		}
		var event audit.Event
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			return nil, "", err
		}
		server := uiUpstreamServerFromAuditEvent(event)
		if server == "" {
			continue
		}
		key := strings.ToLower(server)
		stats := out[key]
		if stats == nil {
			stats = &uiUpstreamEvidence{name: server, requests: map[string]struct{}{}}
			out[key] = stats
		}
		if event.Timestamp.After(stats.lastEventAt) {
			stats.lastEventAt = event.Timestamp
		}
		if uiAuditEventContributesRequest(event) {
			stats.requests[uiAuditRequestKey(event)] = struct{}{}
		}
		if event.DurationMS > 0 && event.EventType == "action.completed" {
			stats.latencyMS = append(stats.latencyMS, event.DurationMS)
		}
		if uiAuditEventFailed(event) {
			stats.errorCount++
			if len(stats.recentFailure) < 5 {
				stats.recentFailure = append(stats.recentFailure, uiUpstreamFailure{
					Timestamp:            event.Timestamp.UTC().Format(time.RFC3339Nano),
					EventType:            event.EventType,
					TraceID:              event.TraceID,
					ActionID:             event.ActionID,
					ActionType:           event.ActionType,
					Decision:             event.Decision,
					ResultClassification: event.ResultClassification,
				})
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return out, "config_and_audit", nil
}

func buildUIUpstreamRecord(name string, server MCPUpstreamServerConfig, globalBreaker MCPBreakerConfig, stats *uiUpstreamEvidence, configOrdinal int) uiUpstreamRecord {
	breakerEnabled := effectiveUIBreakerEnabled(globalBreaker, server.Breaker)
	record := uiUpstreamRecord{
		Name:             name,
		Transport:        uiNonEmpty(server.Transport, "unknown"),
		Endpoint:         uiSafeEndpoint(server.Endpoint),
		Command:          uiCommandSummary(server.Command),
		BreakerEnabled:   breakerEnabled,
		BreakerState:     uiBreakerStateLabel(breakerEnabled),
		Health:           "unknown",
		ConfigurationRef: "mcp.upstream_servers[" + strconv.Itoa(configOrdinal-1) + "]",
	}
	if stats != nil {
		record.RequestCount = len(stats.requests)
		record.ErrorCount = stats.errorCount
		record.ErrorRate = uiErrorRate(record.ErrorCount, record.RequestCount)
		record.AvgLatencyMS = uiAverageLatency(stats.latencyMS)
		record.P95LatencyMS = uiP95Latency(stats.latencyMS)
		if !stats.lastEventAt.IsZero() {
			record.LastEventAt = stats.lastEventAt.UTC().Format(time.RFC3339Nano)
		}
		record.RecentFailures = append([]uiUpstreamFailure{}, stats.recentFailure...)
	}
	record.Health = uiUpstreamHealth(record)
	return record
}

func effectiveUIBreakerEnabled(global, server MCPBreakerConfig) bool {
	if server.Enabled != nil {
		return *server.Enabled
	}
	if global.Enabled != nil {
		return *global.Enabled
	}
	return true
}

func uiBreakerStateLabel(enabled bool) string {
	if enabled {
		return "configured"
	}
	return "disabled"
}

func uiUpstreamHealth(record uiUpstreamRecord) string {
	switch {
	case record.RequestCount == 0 && record.ErrorCount == 0:
		return "unknown"
	case record.RequestCount > 0 && record.ErrorRate >= 0.2:
		return "degraded"
	case record.ErrorCount > 0:
		return "watch"
	default:
		return "healthy"
	}
}

func uiAuditEventContributesRequest(event audit.Event) bool {
	if event.EventType == "action.completed" {
		return true
	}
	if event.EventType == "action.decision" && strings.EqualFold(event.Decision, policy.DecisionDeny) {
		return true
	}
	return strings.HasPrefix(event.EventType, "mcp.") && event.TraceID != ""
}

func uiAuditEventFailed(event audit.Event) bool {
	class := strings.ToUpper(strings.TrimSpace(event.ResultClassification))
	switch class {
	case "", "SUCCESS", "APPROVAL_REQUIRED", "OUTPUT_LIMIT":
		return false
	default:
		return true
	}
}

func uiAuditRequestKey(event audit.Event) string {
	if strings.TrimSpace(event.ActionID) != "" && event.ActionID != "-" {
		return "action:" + event.ActionID
	}
	if strings.TrimSpace(event.TraceID) != "" {
		return "trace:" + event.TraceID + ":" + event.EventType
	}
	return event.EventType + ":" + event.Timestamp.UTC().Format(time.RFC3339Nano)
}

func uiUpstreamServerFromAuditEvent(event audit.Event) string {
	if value := uiStringFromMap(event.ExecutorMetadata, "upstream_server"); value != "" {
		return value
	}
	if !strings.HasPrefix(strings.TrimSpace(event.ActionType), "mcp.") {
		return ""
	}
	return uiUpstreamFromMCPResource(event.Resource)
}

func uiUpstreamFromMCPResource(resource string) string {
	trimmed := strings.TrimSpace(resource)
	if !strings.HasPrefix(trimmed, "mcp://") {
		return ""
	}
	trimmed = strings.TrimPrefix(trimmed, "mcp://")
	if idx := strings.Index(trimmed, "/"); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	if trimmed == "" || trimmed == "tools" {
		return ""
	}
	return trimmed
}

func uiStringFromMap(input map[string]any, key string) string {
	if len(input) == 0 {
		return ""
	}
	value, ok := input[key]
	if !ok {
		return ""
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text)
	}
	return ""
}

func uiSafeEndpoint(endpoint string) string {
	trimmed := strings.TrimSpace(endpoint)
	if trimmed == "" {
		return ""
	}
	parsed, err := neturl.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func uiCommandSummary(command string) string {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return ""
	}
	trimmed = strings.ReplaceAll(trimmed, "\\", "/")
	if idx := strings.LastIndex(trimmed, "/"); idx >= 0 {
		return trimmed[idx+1:]
	}
	return trimmed
}

func uiNonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func uiErrorRate(errors, total int) float64 {
	if total <= 0 || errors <= 0 {
		return 0
	}
	return float64(errors) / float64(total)
}

func uiAverageLatency(samples []int64) int64 {
	if len(samples) == 0 {
		return 0
	}
	var total int64
	for _, sample := range samples {
		total += sample
	}
	return total / int64(len(samples))
}

func uiP95Latency(samples []int64) int64 {
	if len(samples) == 0 {
		return 0
	}
	sorted := append([]int64{}, samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := ((len(sorted) * 95) + 99) / 100
	if idx <= 0 {
		idx = 1
	}
	if idx > len(sorted) {
		idx = len(sorted)
	}
	return sorted[idx-1]
}

func buildUIActionDetailResponse(event audit.Event) uiActionDetailResponse {
	return uiActionDetailResponse{
		ActionID:              event.ActionID,
		TraceID:               event.TraceID,
		ActionType:            event.ActionType,
		Resource:              event.Resource,
		ResourceNormalized:    event.ResourceNormalized,
		ParamsHash:            event.ParamsHash,
		Decision:              event.Decision,
		Reason:                event.Reason,
		MatchedRuleIDs:        append([]string{}, event.MatchedRuleIDs...),
		Obligations:           cloneMap(event.Obligations),
		RiskLevel:             event.RiskLevel,
		RiskFlags:             append([]string{}, event.RiskFlags...),
		SandboxMode:           event.SandboxMode,
		NetworkMode:           event.NetworkMode,
		AssuranceLevel:        event.AssuranceLevel,
		PolicyBundleHash:      event.PolicyBundleHash,
		PolicyBundleSources:   append([]string{}, event.PolicyBundleSources...),
		ResultClassification:  event.ResultClassification,
		ParamsRedactedSummary: event.ParamsRedactedSummary,
		ResultRedactedSummary: event.ResultRedactedSummary,
		ExecutorMetadata:      cloneMap(event.ExecutorMetadata),
		Principal:             event.Principal,
		Agent:                 event.Agent,
		Environment:           event.Environment,
		Audit: uiAuditLink{
			EventType:     event.EventType,
			EventHash:     event.EventHash,
			PrevEventHash: event.PrevEventHash,
		},
	}
}

func buildExplainResponse(explanation policy.ExplainDetails, normalized normalize.NormalizedAction, cfg Config, assuranceLevel string) explainResponse {
	previewRedactor, err := redact.NewRedactor(cfg.Redaction.Patterns)
	if err != nil {
		previewRedactor = redact.DefaultRedactor()
	}
	resp := explainResponse{
		ActionID:           normalized.ActionID,
		TraceID:            normalized.TraceID,
		ActionType:         normalized.ActionType,
		Resource:           normalized.Resource,
		Decision:           explanation.Decision.Decision,
		ReasonCode:         explanation.Decision.ReasonCode,
		MatchedRuleIDs:     append([]string{}, explanation.Decision.MatchedRuleIDs...),
		PolicyBundleHash:   explanation.Decision.PolicyBundleHash,
		EngineVersion:      version.Current().Version,
		AssuranceLevel:     assuranceLevel,
		ObligationsPreview: cloneMap(explanation.ObligationsPreview),
	}
	if preview, ok := approvalpreview.FromNormalized(previewRedactor, normalized); ok {
		if decoded, ok := approvalpreview.Decode(string(preview)); ok {
			resp.ArgumentPreview = decoded
		}
	}
	if len(explanation.Decision.PolicyBundleInputs) > 0 {
		resp.PolicyBundleInputs = make([]any, 0, len(explanation.Decision.PolicyBundleInputs))
		for _, input := range explanation.Decision.PolicyBundleInputs {
			resp.PolicyBundleInputs = append(resp.PolicyBundleInputs, input)
		}
	}
	if len(explanation.Decision.PolicyBundleSources) > 1 {
		resp.PolicyBundleSources = append([]string{}, explanation.Decision.PolicyBundleSources...)
	}
	if len(explanation.MatchedRuleProvenance) > 0 {
		resp.MatchedRuleProvenance = make([]any, 0, len(explanation.MatchedRuleProvenance))
		for _, item := range explanation.MatchedRuleProvenance {
			resp.MatchedRuleProvenance = append(resp.MatchedRuleProvenance, item)
		}
	}
	if explanation.Decision.Decision != policy.DecisionAllow {
		resp.WhyDenied = map[string]any{
			"reason_code":        explanation.Decision.ReasonCode,
			"deny_rules":         buildUIDeniedRulePayload(explanation.DenyRules),
			"matched_conditions": buildUIOverallMatchedConditions(explanation),
			"remediation_hint":   uiRemediationHint(explanation, normalized),
		}
		if cfg.Policy.ExplainSuggestions == nil || *cfg.Policy.ExplainSuggestions {
			resp.MinimalAllowingChange = uiRemediationSuggestion(explanation, normalized)
		}
	}
	return resp
}

func buildUIDeniedRulePayload(rules []policy.DeniedRuleExplanation) []map[string]any {
	out := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		item := map[string]any{
			"rule_id":            rule.RuleID,
			"reason_code":        rule.ReasonCode,
			"matched_conditions": rule.MatchedConditions,
		}
		if rule.BundleSource != "" {
			item["bundle_source"] = rule.BundleSource
		}
		out = append(out, item)
	}
	return out
}

func buildUIOverallMatchedConditions(explanation policy.ExplainDetails) map[string]bool {
	if len(explanation.DenyRules) > 0 {
		return map[string]bool{"deny_rule_match": true}
	}
	if len(explanation.RequireApprovalRuleIDs) > 0 {
		return map[string]bool{"approval_rule_match": true}
	}
	return map[string]bool{"matching_allow_rule": false}
}

func uiRemediationHint(explanation policy.ExplainDetails, normalized normalize.NormalizedAction) string {
	switch explanation.Decision.ReasonCode {
	case "require_approval_by_rule":
		return "This action requires approval before it can proceed."
	case "deny_by_rule":
		return "A deny rule matched this action."
	default:
		switch normalized.ActionType {
		case "net.http_request":
			return "This network destination is not currently allowed."
		case "process.exec":
			return "This command is not currently allowed."
		case "fs.write", "repo.apply_patch":
			return "This write target is not currently allowed."
		case "mcp.resource_read":
			return "This MCP resource is not currently allowed."
		case "mcp.prompt_get":
			return "This MCP prompt is not currently allowed."
		case "mcp.completion":
			return "This MCP completion surface is not currently allowed."
		case "mcp.sample":
			return "This upstream-initiated sampling request is blocked unless policy explicitly allows it."
		default:
			return "No matching allow rule was found for this action."
		}
	}
}

func uiRemediationSuggestion(explanation policy.ExplainDetails, normalized normalize.NormalizedAction) string {
	switch normalized.ActionType {
	case "net.http_request":
		host := uiHostFromNormalizedResource(normalized.Resource)
		if host != "" {
			return "This host is not currently allowed; use an allowlisted host, request approval, or update the network allowlist for " + host + "."
		}
		return "This host is not currently allowed; use an allowlisted host or request approval."
	case "process.exec":
		return "Exec is restricted; use an allowlisted command or request approval."
	case "fs.write", "repo.apply_patch":
		return "Write access is restricted for this resource; use an allowed path or request approval."
	case "mcp.resource_read":
		return "Add an allow or approval rule for this MCP resource URI if this upstream resource should be readable."
	case "mcp.prompt_get":
		return "Add an allow or approval rule for this MCP prompt if this upstream prompt should be callable."
	case "mcp.completion":
		return "Add an allow or approval rule for this MCP completion reference if this upstream completion surface should be callable."
	case "mcp.sample":
		return "Sampling defaults to deny; add an explicit allow or approval rule for this upstream server only if downstream LLM use is intended."
	default:
		if explanation.Decision.ReasonCode == "require_approval_by_rule" {
			return "Request approval for this action."
		}
		return "Adjust the requested action to match an allowlisted resource or request approval."
	}
}

func uiHostFromNormalizedResource(resource string) string {
	if !strings.HasPrefix(resource, "url://") {
		return ""
	}
	trimmed := strings.TrimPrefix(resource, "url://")
	if idx := strings.Index(trimmed, "/"); idx >= 0 {
		return trimmed[:idx]
	}
	return trimmed
}

func cloneMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func (g *Gateway) requireOperatorUIAuth(w http.ResponseWriter, r *http.Request) (string, bool) {
	if g.auth == nil {
		g.respondError(w, http.StatusUnauthorized, "auth_error", "operator auth unavailable")
		return "", false
	}
	principal, err := g.auth.VerifyPrincipalOnly(r)
	if err != nil {
		g.respondError(w, http.StatusUnauthorized, "auth_error", err.Error())
		return "", false
	}
	return principal, true
}

func (g *Gateway) writeUIJSON(w http.ResponseWriter, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		g.respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	redactor := g.redactor
	if redactor == nil {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(redactor.RedactBytes(payload))
}
