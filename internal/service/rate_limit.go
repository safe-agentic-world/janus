package service

import (
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/ratelimit"
)

func (s *Service) emitRateLimitAuditDecision(normalized normalize.NormalizedAction, decision policy.Decision, ctx auditContext, result ratelimit.Result) {
	metadata := mergeExecutorMetadata(ctx.executorMetadata, map[string]any{
		"rate_limit_rule_id":           result.RuleID,
		"rate_limit_scope":             result.Scope,
		"rate_limit_bucket_key":        result.BucketKey,
		"rate_limit_remaining_tokens":  result.RemainingTokens,
		"rate_limit_refill_per_minute": result.RefillPerMinute,
	})
	_ = s.recorder.WriteEvent(audit.Event{
		SchemaVersion:       "v1",
		Timestamp:           s.now().UTC(),
		EventType:           "action.decision",
		TraceID:             normalized.TraceID,
		ActionID:            normalized.ActionID,
		ActionType:          normalized.ActionType,
		Resource:            normalized.Resource,
		ResourceNormalized:  normalized.Resource,
		ParamsHash:          normalized.ParamsHash,
		MatchedRuleIDs:      decision.MatchedRuleIDs,
		Obligations:         decision.Obligations,
		PolicyBundleHash:    decision.PolicyBundleHash,
		PolicyBundleSources: append([]string{}, decision.PolicyBundleSources...),
		PolicyBundleInputs:  toAuditPolicyInputs(decision.PolicyBundleInputs),
		RiskLevel:           ctx.riskLevel,
		RiskFlags:           ctx.riskFlags,
		SandboxMode:         ctx.sandboxMode,
		NetworkMode:         ctx.networkMode,
		AssuranceLevel:      s.assuranceLevel,
		ActionSummary:       ctx.actionSummary,
		Principal:           normalized.Principal,
		Agent:               normalized.Agent,
		Environment:         normalized.Environment,
		TenantID:            normalized.TenantID,
		Decision:            decision.Decision,
		Reason:              decision.ReasonCode,
		ExecutorMetadata:    metadata,
	})
}

func (s *Service) emitRateLimitTelemetry(normalized normalize.NormalizedAction, result ratelimit.Result) {
	if !result.Applied {
		return
	}
	for _, hit := range result.Hits {
		outcome := "allowed"
		if !result.Allowed && hit.RuleID == result.RuleID && hit.BucketKey == result.BucketKey {
			outcome = "exceeded"
		}
		s.emitTelemetryMetric("nomos.rate_limits", normalized.TraceID, "counter", 1, map[string]string{
			"result":      outcome,
			"rule_id":     hit.RuleID,
			"scope":       hit.Scope,
			"action_type": normalized.ActionType,
			"principal":   normalized.Principal,
		})
	}
}
