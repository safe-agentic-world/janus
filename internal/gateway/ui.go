package gateway

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
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
	ApprovalID  string `json:"approval_id"`
	Status      string `json:"status"`
	ExpiresAt   string `json:"expires_at"`
	Expired     bool   `json:"expired"`
	Principal   string `json:"principal"`
	Agent       string `json:"agent"`
	Environment string `json:"environment"`
	ActionType  string `json:"action_type"`
	Resource    string `json:"resource"`
	ScopeType   string `json:"scope_type"`
	ActionID    string `json:"action_id"`
	TraceID     string `json:"trace_id"`
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
	g.writeUIJSON(w, buildUIReadinessResponse(report, g.cfg, g.policyBundleHash, g.policyBundleSources, g.assuranceLevel, principal))
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
		out = append(out, uiApprovalRecord{
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
		})
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
	resp := explainResponse{
		ActionID:           normalized.ActionID,
		TraceID:            normalized.TraceID,
		Decision:           explanation.Decision.Decision,
		ReasonCode:         explanation.Decision.ReasonCode,
		MatchedRuleIDs:     append([]string{}, explanation.Decision.MatchedRuleIDs...),
		PolicyBundleHash:   explanation.Decision.PolicyBundleHash,
		EngineVersion:      version.Current().Version,
		AssuranceLevel:     assuranceLevel,
		ObligationsPreview: cloneMap(explanation.ObligationsPreview),
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
