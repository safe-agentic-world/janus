package policy

type ExecAuthorizationSummary struct {
	ConditionClass         string
	RuntimeEnforcementHint string
	Conflict               bool
}

func summarizeExecAuthorization(matched []Rule, decisionObligations map[string]any) ExecAuthorizationSummary {
	summary := ExecAuthorizationSummary{
		ConditionClass:         "none",
		RuntimeEnforcementHint: "policy_only",
	}
	hasExecMatch := false
	hasLegacyAllowlist := false
	for _, rule := range matched {
		if rule.Decision != DecisionAllow && rule.Decision != DecisionRequireApproval {
			continue
		}
		if rule.ExecMatch != nil {
			hasExecMatch = true
		}
		if _, ok := rule.Obligations[obligationExecAllowlist]; ok {
			hasLegacyAllowlist = true
		}
	}
	switch {
	case hasExecMatch && hasLegacyAllowlist:
		summary.ConditionClass = "mixed_exec_models"
		summary.RuntimeEnforcementHint = "conflict"
		summary.Conflict = true
	case hasExecMatch:
		summary.ConditionClass = "argv_pattern_match"
		summary.RuntimeEnforcementHint = "derived_exec_constraints"
	case hasLegacyAllowlist:
		summary.ConditionClass = "legacy_prefix_allowlist"
		summary.RuntimeEnforcementHint = "legacy_exec_allowlist_fallback"
	case decisionObligations != nil:
		if _, ok := decisionObligations[obligationExecConstraints]; ok {
			summary.ConditionClass = "argv_pattern_match"
			summary.RuntimeEnforcementHint = "derived_exec_constraints"
		} else if _, ok := decisionObligations[obligationExecAllowlist]; ok {
			summary.ConditionClass = "legacy_prefix_allowlist"
			summary.RuntimeEnforcementHint = "legacy_exec_allowlist_fallback"
		}
	}
	return summary
}

func hasLegacyExecAllowlist(rule Rule) bool {
	_, ok := rule.Obligations[obligationExecAllowlist]
	return ok
}
