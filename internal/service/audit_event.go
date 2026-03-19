package service

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/version"
)

const (
	resultDeniedPolicy    = "DENIED_POLICY"
	resultApprovalNeeded  = "APPROVAL_REQUIRED"
	resultValidationError = "VALIDATION_ERROR"
	resultNormError       = "NORMALIZATION_ERROR"
	resultSandbox         = "SANDBOX_VIOLATION"
	resultExecTimeout     = "EXEC_TIMEOUT"
	resultOutputLimit     = "OUTPUT_LIMIT"
	resultUpstreamError   = "UPSTREAM_ERROR"
	resultInternalError   = "INTERNAL_ERROR"
)

type auditContext struct {
	normalized         *normalize.NormalizedAction
	decision           policy.Decision
	resultClass        string
	retryable          bool
	riskLevel          string
	riskFlags          []string
	sandboxMode        string
	networkMode        string
	credentialLeaseIDs []string
	actionSummary      string
	paramsSummary      string
	resultSummary      string
	executorMetadata   map[string]any
	fallbackAction     action.Action
	fallbackTraceID    string
	fallbackActionID   string
	fallbackPrincipal  string
	fallbackAgent      string
	fallbackEnv        string
}

func (s *Service) emitCompletedAudit(ctx auditContext, started time.Time) {
	e := audit.Event{
		SchemaVersion:        "v1",
		Timestamp:            s.now().UTC(),
		EventType:            "action.completed",
		DurationMS:           s.now().UTC().Sub(started.UTC()).Milliseconds(),
		ResultClassification: ctx.resultClass,
		Retryable:            ctx.retryable,
		EngineVersion:        version.Current().Version,
	}
	if ctx.normalized != nil {
		e.TraceID = ctx.normalized.TraceID
		e.ActionID = ctx.normalized.ActionID
		e.Principal = ctx.normalized.Principal
		e.Agent = ctx.normalized.Agent
		e.Environment = ctx.normalized.Environment
		e.ActionType = ctx.normalized.ActionType
		e.ResourceNormalized = ctx.normalized.Resource
		e.Resource = ctx.normalized.Resource
		e.ParamsHash = ctx.normalized.ParamsHash
	} else {
		e.TraceID = ctx.fallbackTraceID
		e.ActionID = ctx.fallbackActionID
		e.Principal = ctx.fallbackPrincipal
		e.Agent = ctx.fallbackAgent
		e.Environment = ctx.fallbackEnv
		e.ActionType = strings.TrimSpace(ctx.fallbackAction.ActionType)
	}
	e.Decision = ctx.decision.Decision
	if e.Decision == "" {
		e.Decision = policy.DecisionDeny
	}
	e.MatchedRuleIDs = ctx.decision.MatchedRuleIDs
	e.Obligations = ctx.decision.Obligations
	e.PolicyBundleHash = ctx.decision.PolicyBundleHash
	e.PolicyBundleSources = append([]string{}, ctx.decision.PolicyBundleSources...)
	e.PolicyBundleInputs = toAuditPolicyInputs(ctx.decision.PolicyBundleInputs)
	e.RiskLevel = ctx.riskLevel
	e.RiskFlags = ctx.riskFlags
	e.SandboxMode = ctx.sandboxMode
	e.NetworkMode = ctx.networkMode
	e.CredentialLeaseIDs = ctx.credentialLeaseIDs
	e.AssuranceLevel = s.assuranceLevel
	e.ActionSummary = ctx.actionSummary
	e.ParamsRedactedSummary = ctx.paramsSummary
	e.ResultRedactedSummary = ctx.resultSummary
	e.ExecutorMetadata = ctx.executorMetadata
	_ = s.recorder.WriteEvent(e)
}

func toAuditPolicyInputs(inputs []policy.BundleSource) []audit.PolicyInput {
	if len(inputs) == 0 {
		return nil
	}
	out := make([]audit.PolicyInput, 0, len(inputs))
	for _, input := range inputs {
		out = append(out, audit.PolicyInput{
			Path:              input.Path,
			Hash:              input.Hash,
			Role:              input.Role,
			SignatureVerified: input.SignatureVerified,
		})
	}
	return out
}

func summarizeParams(redactor *redact.Redactor, params []byte) string {
	if len(params) == 0 {
		return ""
	}
	v := string(params)
	if len(v) > 256 {
		v = v[:256]
	}
	return redactor.RedactText(v)
}

func summarizeResponse(redactor *redact.Redactor, resp action.Response) string {
	summary := map[string]any{
		"decision":      resp.Decision,
		"reason":        resp.Reason,
		"truncated":     resp.Truncated,
		"bytes_written": resp.BytesWritten,
		"status_code":   resp.StatusCode,
		"exit_code":     resp.ExitCode,
	}
	payload, err := json.Marshal(summary)
	if err != nil {
		return ""
	}
	text := string(payload)
	if len(text) > 256 {
		text = text[:256]
	}
	return redactor.RedactText(text)
}

func classifyError(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "path escape") || strings.Contains(msg, "cwd escape"):
		return resultSandbox, false
	case strings.Contains(msg, "redirect") && (strings.Contains(msg, "allowlisted") || strings.Contains(msg, "not allowed") || strings.Contains(msg, "hop limit")):
		return resultDeniedPolicy, false
	case strings.Contains(msg, "timeout"):
		return resultExecTimeout, true
	case strings.Contains(msg, "normalize"):
		return resultNormError, false
	case strings.Contains(msg, "validation") || strings.Contains(msg, "invalid"):
		return resultValidationError, false
	case strings.Contains(msg, "http") || strings.Contains(msg, "upstream"):
		return resultUpstreamError, true
	default:
		return resultInternalError, true
	}
}

func classifyDecision(decision policy.Decision, response action.Response) (string, bool) {
	effective := response.Decision
	if effective == "" {
		effective = decision.Decision
	}
	switch effective {
	case policy.DecisionRequireApproval:
		return resultApprovalNeeded, true
	case policy.DecisionDeny:
		if response.Reason == "sandbox_required" {
			return resultSandbox, false
		}
		return resultDeniedPolicy, false
	case policy.DecisionAllow:
		if response.Truncated {
			return resultOutputLimit, false
		}
		return "SUCCESS", false
	default:
		return resultInternalError, true
	}
}
