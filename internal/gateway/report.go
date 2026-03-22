package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/normalize"
)

type externalReportRequest struct {
	SchemaVersion       string `json:"schema_version"`
	ActionID            string `json:"action_id"`
	TraceID             string `json:"trace_id"`
	ActionType          string `json:"action_type"`
	Resource            string `json:"resource"`
	Outcome             string `json:"outcome"`
	Message             string `json:"message,omitempty"`
	ExternalReference   string `json:"external_reference,omitempty"`
	ApprovalID          string `json:"approval_id,omitempty"`
	ApprovalFingerprint string `json:"approval_fingerprint,omitempty"`
	StatusCode          int    `json:"status_code,omitempty"`
}

type externalReportResponse struct {
	Recorded bool   `json:"recorded"`
	TraceID  string `json:"trace_id"`
	ActionID string `json:"action_id"`
	Outcome  string `json:"outcome"`
}

func (g *Gateway) handleExternalReport(w http.ResponseWriter, r *http.Request) {
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
	req, err := decodeExternalReportRequest(body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	resource, err := normalize.NormalizeCustomResource(req.Resource)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "normalization_error", err.Error())
		return
	}
	event := audit.Event{
		SchemaVersion:         "v1",
		Timestamp:             g.now().UTC(),
		EventType:             "action.external_reported",
		TraceID:               req.TraceID,
		ActionID:              req.ActionID,
		ApprovalID:            req.ApprovalID,
		Fingerprint:           req.ApprovalFingerprint,
		Principal:             id.Principal,
		Agent:                 id.Agent,
		Environment:           id.Environment,
		ActionType:            req.ActionType,
		Resource:              resource,
		ResourceNormalized:    resource,
		AssuranceLevel:        g.assuranceLevel,
		ResultClassification:  mapExternalOutcomeClass(req.Outcome),
		Retryable:             req.Outcome == "FAILED",
		Reason:                req.Outcome,
		ResultRedactedSummary: g.redactor.RedactText(strings.TrimSpace(req.Message)),
		ExecutorMetadata: map[string]any{
			"execution_mode":     "caller_reported",
			"nomos_executed":     false,
			"external_reference": strings.TrimSpace(req.ExternalReference),
			"status_code":        req.StatusCode,
			"reported_outcome":   req.Outcome,
		},
		ActionSummary: req.ActionType + " " + resource,
	}
	_ = g.writer.WriteEvent(event)
	g.writeUIJSON(w, externalReportResponse{
		Recorded: true,
		TraceID:  req.TraceID,
		ActionID: req.ActionID,
		Outcome:  req.Outcome,
	})
}

func decodeExternalReportRequest(data []byte) (externalReportRequest, error) {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var req externalReportRequest
	if err := dec.Decode(&req); err != nil {
		return externalReportRequest{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return externalReportRequest{}, errors.New("unexpected trailing data")
	}
	if strings.TrimSpace(req.SchemaVersion) != "v1" {
		return externalReportRequest{}, errors.New("schema_version must be v1")
	}
	if strings.TrimSpace(req.ActionID) == "" {
		return externalReportRequest{}, errors.New("action_id is required")
	}
	if strings.TrimSpace(req.TraceID) == "" {
		return externalReportRequest{}, errors.New("trace_id is required")
	}
	if err := action.ValidateActionType(req.ActionType); err != nil {
		return externalReportRequest{}, err
	}
	if action.IsBuiltInActionType(req.ActionType) {
		return externalReportRequest{}, errors.New("built-in action types do not support external outcome reporting")
	}
	if strings.TrimSpace(req.Resource) == "" {
		return externalReportRequest{}, errors.New("resource is required")
	}
	switch strings.TrimSpace(req.Outcome) {
	case "SUCCEEDED", "FAILED":
	default:
		return externalReportRequest{}, errors.New("outcome must be SUCCEEDED or FAILED")
	}
	return req, nil
}

func mapExternalOutcomeClass(outcome string) string {
	switch outcome {
	case "SUCCEEDED":
		return "SUCCESS"
	case "FAILED":
		return "UPSTREAM_ERROR"
	default:
		return "INTERNAL_ERROR"
	}
}
