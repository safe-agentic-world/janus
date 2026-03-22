package sdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type ActionContext struct {
	Extensions map[string]any `json:"extensions,omitempty"`
}

type ActionRequest struct {
	SchemaVersion string         `json:"schema_version"`
	ActionID      string         `json:"action_id"`
	ActionType    string         `json:"action_type"`
	Resource      string         `json:"resource"`
	Params        map[string]any `json:"params"`
	TraceID       string         `json:"trace_id"`
	Context       ActionContext  `json:"context"`
}

type ApprovalDecisionRequest struct {
	ApprovalID string `json:"approval_id"`
	Decision   string `json:"decision"`
}

type DecisionResponse struct {
	Decision            string         `json:"decision"`
	Reason              string         `json:"reason,omitempty"`
	TraceID             string         `json:"trace_id,omitempty"`
	ActionID            string         `json:"action_id,omitempty"`
	Output              string         `json:"output,omitempty"`
	Truncated           bool           `json:"truncated,omitempty"`
	BytesWritten        int            `json:"bytes_written,omitempty"`
	Stdout              string         `json:"stdout,omitempty"`
	Stderr              string         `json:"stderr,omitempty"`
	ExitCode            int            `json:"exit_code,omitempty"`
	StatusCode          int            `json:"status_code,omitempty"`
	Obligations         map[string]any `json:"obligations,omitempty"`
	ApprovalID          string         `json:"approval_id,omitempty"`
	ApprovalFingerprint string         `json:"approval_fingerprint,omitempty"`
	ApprovalExpiresAt   string         `json:"approval_expires_at,omitempty"`
	CredentialLeaseID   string         `json:"credential_lease_id,omitempty"`
	CredentialLeaseIDs  []string       `json:"credential_lease_ids,omitempty"`
}

func (r DecisionResponse) IsAllowed() bool {
	return r.Decision == "ALLOW"
}

func (r DecisionResponse) IsDenied() bool {
	return r.Decision == "DENY"
}

func (r DecisionResponse) RequiresApproval() bool {
	return r.Decision == "REQUIRE_APPROVAL"
}

type ExplainResponse struct {
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

type ErrorKind string

const (
	ErrorKindTransport  ErrorKind = "transport"
	ErrorKindTimeout    ErrorKind = "timeout"
	ErrorKindValidation ErrorKind = "validation"
	ErrorKindAuth       ErrorKind = "auth"
	ErrorKindExecution  ErrorKind = "execution"
	ErrorKindDecode     ErrorKind = "decode"
	ErrorKindGateway    ErrorKind = "gateway"
)

type Error struct {
	Kind       ErrorKind
	StatusCode int
	Message    string
	Decision   string
	Reason     string
	Retryable  bool
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	switch {
	case e.StatusCode > 0 && e.Message != "":
		return fmt.Sprintf("%s error (status=%d): %s", e.Kind, e.StatusCode, e.Message)
	case e.Message != "":
		return fmt.Sprintf("%s error: %s", e.Kind, e.Message)
	default:
		return string(e.Kind) + " error"
	}
}

func NewActionRequest(actionType, resource string, params map[string]any) ActionRequest {
	return ActionRequest{
		SchemaVersion: "v1",
		ActionType:    strings.TrimSpace(actionType),
		Resource:      strings.TrimSpace(resource),
		Params:        cloneMap(params),
		Context:       ActionContext{Extensions: map[string]any{}},
	}
}

func (r *ActionRequest) ensureDefaults() {
	if r == nil {
		return
	}
	if strings.TrimSpace(r.SchemaVersion) == "" {
		r.SchemaVersion = "v1"
	}
	if strings.TrimSpace(r.ActionID) == "" {
		r.ActionID = GenerateID(defaultActionPrefix)
	}
	if strings.TrimSpace(r.TraceID) == "" {
		r.TraceID = GenerateID(defaultTracePrefix)
	}
	if r.Params == nil {
		r.Params = map[string]any{}
	}
	if r.Context.Extensions == nil {
		r.Context.Extensions = map[string]any{}
	}
}

func (r ActionRequest) Validate() error {
	if strings.TrimSpace(r.SchemaVersion) != "v1" {
		return errors.New("schema_version must be v1")
	}
	if strings.TrimSpace(r.ActionID) == "" {
		return errors.New("action_id is required")
	}
	if strings.TrimSpace(r.TraceID) == "" {
		return errors.New("trace_id is required")
	}
	if strings.TrimSpace(r.ActionType) == "" {
		return errors.New("action_type is required")
	}
	if strings.TrimSpace(r.Resource) == "" {
		return errors.New("resource is required")
	}
	if r.Params == nil {
		return errors.New("params is required")
	}
	return nil
}

func decodeGatewayError(statusCode int, body []byte) error {
	var resp DecisionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return &Error{
			Kind:       ErrorKindGateway,
			StatusCode: statusCode,
			Message:    strings.TrimSpace(string(body)),
			Retryable:  statusCode >= 500 || statusCode == 429,
		}
	}
	return &Error{
		Kind:       classifyErrorKind(statusCode, resp.Reason),
		StatusCode: statusCode,
		Message:    strings.TrimSpace(resp.Reason),
		Decision:   resp.Decision,
		Reason:     resp.Reason,
		Retryable:  statusCode >= 500 || statusCode == 429,
	}
}

func classifyErrorKind(statusCode int, reason string) ErrorKind {
	switch {
	case strings.HasPrefix(reason, "auth_error:"):
		return ErrorKindAuth
	case strings.HasPrefix(reason, "validation_error:"), strings.HasPrefix(reason, "normalization_error:"):
		return ErrorKindValidation
	case strings.HasPrefix(reason, "execution_error:"), strings.HasPrefix(reason, "approval_error:"):
		return ErrorKindExecution
	case statusCode >= 500:
		return ErrorKindGateway
	default:
		return ErrorKindGateway
	}
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
