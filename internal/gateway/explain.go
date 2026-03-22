package gateway

import (
	"net/http"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/normalize"
)

type explainResponse struct {
	ActionID              string         `json:"action_id"`
	TraceID               string         `json:"trace_id"`
	Decision              string         `json:"decision"`
	ReasonCode            string         `json:"reason_code"`
	MatchedRuleIDs        []string       `json:"matched_rule_ids"`
	PolicyBundleHash      string         `json:"policy_bundle_hash"`
	PolicyBundleSources   []string       `json:"policy_bundle_sources,omitempty"`
	PolicyBundleInputs    []any          `json:"policy_bundle_inputs,omitempty"`
	EngineVersion         string         `json:"engine_version"`
	AssuranceLevel        string         `json:"assurance_level"`
	ObligationsPreview    map[string]any `json:"obligations_preview"`
	MatchedRuleProvenance []any          `json:"matched_rule_provenance,omitempty"`
	WhyDenied             map[string]any `json:"why_denied,omitempty"`
	MinimalAllowingChange string         `json:"minimal_allowing_change,omitempty"`
}

func (g *Gateway) handleExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := action.ReadRequestBytes(r.Body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	id, err := g.auth.Verify(r, body)
	if err != nil {
		g.respondError(w, http.StatusUnauthorized, "auth_error", err.Error())
		return
	}
	req, err := action.DecodeActionRequestBytes(body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	act, err := action.ToAction(req, id)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	if err := g.validateUpstreamRoute(act); err != nil {
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

func (g *Gateway) explainAction(act action.Action) (explainResponse, error) {
	normalized, err := normalize.Action(act)
	if err != nil {
		return explainResponse{}, err
	}
	explanation := g.policy.Explain(normalized)
	return buildExplainResponse(explanation, normalized, g.cfg, g.assuranceLevel), nil
}
