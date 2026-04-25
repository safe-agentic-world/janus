package service

import (
	"errors"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

func (s *Service) EvaluateAction(actionInput action.Action) (normalize.NormalizedAction, policy.Decision, error) {
	if s == nil || s.policy == nil {
		return normalize.NormalizedAction{}, policy.Decision{}, errors.New("service not initialized")
	}
	normalized, err := normalize.Action(actionInput)
	if err != nil {
		return normalize.NormalizedAction{}, policy.Decision{}, err
	}
	decision := s.policy.Evaluate(normalized)
	if s.externalPolicy != nil {
		externalDecision, err := s.externalPolicy.Evaluate(normalized)
		if err != nil {
			return normalized, policy.Decision{
				Decision:         policy.DecisionDeny,
				ReasonCode:       "deny_by_external_policy_error",
				MatchedRuleIDs:   []string{},
				Obligations:      map[string]any{},
				PolicyBundleHash: "opa:error",
			}, nil
		}
		decision = externalDecision
		if decision.MatchedRuleIDs == nil {
			decision.MatchedRuleIDs = []string{}
		}
		if decision.Obligations == nil {
			decision.Obligations = map[string]any{}
		}
	}
	return normalized, decision, nil
}
