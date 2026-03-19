package policy

import (
	"sort"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/normalize"
)

const (
	DecisionAllow           = "ALLOW"
	DecisionDeny            = "DENY"
	DecisionRequireApproval = "REQUIRE_APPROVAL"
)

type Decision struct {
	Decision            string
	ReasonCode          string
	Message             string
	MatchedRuleIDs      []string
	Obligations         map[string]any
	PolicyBundleHash    string
	PolicyBundleSources []string
	PolicyBundleInputs  []BundleSource
}

type ExplainDetails struct {
	Decision               Decision
	DenyRules              []DeniedRuleExplanation
	AllowRuleIDs           []string
	RequireApprovalRuleIDs []string
	ObligationsPreview     map[string]any
	ExecAuthorization      ExecAuthorizationSummary
	MatchedRuleProvenance  []MatchedRuleProvenance
}

type DeniedRuleExplanation struct {
	RuleID            string
	ReasonCode        string
	MatchedConditions map[string]bool
	BundleSource      string
}

type MatchedRuleProvenance struct {
	RuleID       string
	Decision     string
	BundleSource string
}

type ActionCapability struct {
	Allow           bool
	RequireApproval bool
	ResourceClasses []string
	HostClasses     []string
	ExecClasses     []string
	ApprovalScopes  []string
}

type Engine struct {
	bundle Bundle
}

func NewEngine(bundle Bundle) *Engine {
	return &Engine{bundle: bundle}
}

func (c ActionCapability) Available() bool {
	return c.Allow || c.RequireApproval
}

func (c ActionCapability) State() string {
	switch {
	case c.Allow && c.RequireApproval:
		return "mixed"
	case c.Allow:
		return "allow"
	case c.RequireApproval:
		return "require_approval"
	default:
		return "unavailable"
	}
}

func (e *Engine) CapabilityForActionType(actionType, principal, agent, environment string) ActionCapability {
	capability := ActionCapability{}
	for _, rule := range e.bundle.Rules {
		if rule.Decision != DecisionAllow && rule.Decision != DecisionRequireApproval {
			continue
		}
		if !matchField(rule.ActionType, actionType) {
			continue
		}
		if !matchList(rule.Principals, principal) {
			continue
		}
		if !matchList(rule.Agents, agent) {
			continue
		}
		if !matchList(rule.Environments, environment) {
			continue
		}
		if rule.Decision == DecisionAllow {
			capability.Allow = true
		}
		if rule.Decision == DecisionRequireApproval {
			capability.RequireApproval = true
		}
		capability.ResourceClasses = appendUniqueString(capability.ResourceClasses, summarizeCapabilityResourceClass(actionType, rule.Resource))
		capability.HostClasses = appendUniqueString(capability.HostClasses, summarizeCapabilityHostClass(actionType, rule.Resource))
		capability.ExecClasses = appendUniqueString(capability.ExecClasses, summarizeCapabilityExecClass(actionType, rule))
		capability.ApprovalScopes = appendUniqueString(capability.ApprovalScopes, summarizeCapabilityApprovalScope(rule))
	}
	sort.Strings(capability.ResourceClasses)
	sort.Strings(capability.HostClasses)
	sort.Strings(capability.ExecClasses)
	sort.Strings(capability.ApprovalScopes)
	return capability
}

func (e *Engine) SupportsActionType(actionType, principal, agent, environment string) bool {
	return e.CapabilityForActionType(actionType, principal, agent, environment).Available()
}

func (e *Engine) Evaluate(action normalize.NormalizedAction) Decision {
	return e.Explain(action).Decision
}

func (e *Engine) Explain(action normalize.NormalizedAction) ExplainDetails {
	risk := ComputeRiskFlags(action)
	matched := make([]Rule, 0)
	for _, rule := range e.bundle.Rules {
		if !matchField(rule.ActionType, action.ActionType) {
			continue
		}
		ok, err := normalize.MatchPattern(rule.Resource, action.Resource)
		if err != nil || !ok {
			continue
		}
		if !matchList(rule.Principals, action.Principal) {
			continue
		}
		if !matchList(rule.Agents, action.Agent) {
			continue
		}
		if !matchList(rule.Environments, action.Environment) {
			continue
		}
		if !matchRisk(rule.RiskFlags, risk) {
			continue
		}
		if !matchExec(rule, action) {
			continue
		}
		matched = append(matched, rule)
	}
	denyIDs := make([]string, 0)
	requireIDs := make([]string, 0)
	allowIDs := make([]string, 0)
	denyExplanations := make([]DeniedRuleExplanation, 0)
	denyObligations := mergeObligations(matched, DecisionDeny)
	requireObligations := withDerivedExecConstraints(mergeObligations(matched, DecisionRequireApproval), matched, DecisionRequireApproval)
	allowObligations := withDerivedExecConstraints(mergeObligations(matched, DecisionAllow), matched, DecisionAllow)
	execAuthorization := summarizeExecAuthorization(matched, allowObligations)
	matchedRuleProvenance := buildMatchedRuleProvenance(matched)
	if len(matched) == 0 {
		return ExplainDetails{
			Decision: Decision{
				Decision:            DecisionDeny,
				ReasonCode:          "deny_by_default",
				MatchedRuleIDs:      []string{},
				Obligations:         map[string]any{},
				PolicyBundleHash:    e.bundle.Hash,
				PolicyBundleSources: policyBundleSources(e.bundle),
				PolicyBundleInputs:  copyBundleSources(e.bundle.SourceBundles),
			},
			DenyRules:              []DeniedRuleExplanation{},
			AllowRuleIDs:           []string{},
			RequireApprovalRuleIDs: []string{},
			ObligationsPreview:     map[string]any{},
			ExecAuthorization:      ExecAuthorizationSummary{ConditionClass: "none", RuntimeEnforcementHint: "policy_only"},
			MatchedRuleProvenance:  []MatchedRuleProvenance{},
		}
	}
	for _, rule := range matched {
		if rule.Decision == DecisionDeny {
			denyIDs = append(denyIDs, rule.ID)
			denyExplanations = append(denyExplanations, DeniedRuleExplanation{
				RuleID:       rule.ID,
				ReasonCode:   "deny_by_rule",
				BundleSource: ruleBundleSource(rule),
				MatchedConditions: map[string]bool{
					"action_type": true,
					"resource":    true,
					"principal":   true,
					"agent":       true,
					"environment": true,
					"risk_flags":  true,
					"exec_match":  true,
				},
			})
		}
		if rule.Decision == DecisionRequireApproval {
			requireIDs = append(requireIDs, rule.ID)
		}
		if rule.Decision == DecisionAllow {
			allowIDs = append(allowIDs, rule.ID)
		}
	}
	sort.Strings(denyIDs)
	sort.Strings(requireIDs)
	sort.Strings(allowIDs)
	sort.Slice(denyExplanations, func(i, j int) bool {
		return denyExplanations[i].RuleID < denyExplanations[j].RuleID
	})
	if len(denyIDs) > 0 {
		return ExplainDetails{
			Decision: Decision{
				Decision:            DecisionDeny,
				ReasonCode:          "deny_by_rule",
				MatchedRuleIDs:      denyIDs,
				Obligations:         denyObligations,
				PolicyBundleHash:    e.bundle.Hash,
				PolicyBundleSources: policyBundleSources(e.bundle),
				PolicyBundleInputs:  copyBundleSources(e.bundle.SourceBundles),
			},
			DenyRules:              denyExplanations,
			AllowRuleIDs:           append([]string{}, allowIDs...),
			RequireApprovalRuleIDs: append([]string{}, requireIDs...),
			ObligationsPreview:     copyObligations(allowObligations),
			ExecAuthorization:      execAuthorization,
			MatchedRuleProvenance:  matchedRuleProvenance,
		}
	}
	if action.ActionType == "process.exec" && execAuthorization.Conflict {
		conflictingRuleIDs := append([]string{}, allowIDs...)
		conflictingRuleIDs = append(conflictingRuleIDs, requireIDs...)
		sort.Strings(conflictingRuleIDs)
		return ExplainDetails{
			Decision: Decision{
				Decision:            DecisionDeny,
				ReasonCode:          "deny_by_exec_model_conflict",
				MatchedRuleIDs:      conflictingRuleIDs,
				Obligations:         map[string]any{},
				PolicyBundleHash:    e.bundle.Hash,
				PolicyBundleSources: policyBundleSources(e.bundle),
				PolicyBundleInputs:  copyBundleSources(e.bundle.SourceBundles),
			},
			DenyRules:              []DeniedRuleExplanation{},
			AllowRuleIDs:           append([]string{}, allowIDs...),
			RequireApprovalRuleIDs: append([]string{}, requireIDs...),
			ObligationsPreview:     copyObligations(allowObligations),
			ExecAuthorization:      execAuthorization,
			MatchedRuleProvenance:  matchedRuleProvenance,
		}
	}
	if len(requireIDs) > 0 {
		return ExplainDetails{
			Decision: Decision{
				Decision:            DecisionRequireApproval,
				ReasonCode:          "require_approval_by_rule",
				MatchedRuleIDs:      requireIDs,
				Obligations:         requireObligations,
				PolicyBundleHash:    e.bundle.Hash,
				PolicyBundleSources: policyBundleSources(e.bundle),
				PolicyBundleInputs:  copyBundleSources(e.bundle.SourceBundles),
			},
			DenyRules:              []DeniedRuleExplanation{},
			AllowRuleIDs:           append([]string{}, allowIDs...),
			RequireApprovalRuleIDs: append([]string{}, requireIDs...),
			ObligationsPreview:     copyObligations(requireObligations),
			ExecAuthorization:      summarizeExecAuthorization(matched, requireObligations),
			MatchedRuleProvenance:  matchedRuleProvenance,
		}
	}
	return ExplainDetails{
		Decision: Decision{
			Decision:            DecisionAllow,
			ReasonCode:          "allow_by_rule",
			MatchedRuleIDs:      allowIDs,
			Obligations:         allowObligations,
			PolicyBundleHash:    e.bundle.Hash,
			PolicyBundleSources: policyBundleSources(e.bundle),
			PolicyBundleInputs:  copyBundleSources(e.bundle.SourceBundles),
		},
		DenyRules:              []DeniedRuleExplanation{},
		AllowRuleIDs:           append([]string{}, allowIDs...),
		RequireApprovalRuleIDs: []string{},
		ObligationsPreview:     copyObligations(allowObligations),
		ExecAuthorization:      summarizeExecAuthorization(matched, allowObligations),
		MatchedRuleProvenance:  matchedRuleProvenance,
	}
}

func policyBundleSources(bundle Bundle) []string {
	if len(bundle.SourceBundles) <= 1 {
		return nil
	}
	out := make([]string, 0, len(bundle.SourceBundles))
	for _, source := range bundle.SourceBundles {
		out = append(out, source.Path+"#"+source.Hash)
	}
	return out
}

func ruleBundleSource(rule Rule) string {
	if rule.SourcePath == "" || rule.SourceHash == "" {
		return ""
	}
	return rule.SourcePath + "#" + rule.SourceHash
}

func copyObligations(input map[string]any) map[string]any {
	if len(input) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func copyBundleSources(input []BundleSource) []BundleSource {
	if len(input) == 0 {
		return nil
	}
	out := make([]BundleSource, len(input))
	copy(out, input)
	return out
}

func buildMatchedRuleProvenance(matched []Rule) []MatchedRuleProvenance {
	if len(matched) == 0 {
		return []MatchedRuleProvenance{}
	}
	out := make([]MatchedRuleProvenance, 0, len(matched))
	for _, rule := range matched {
		out = append(out, MatchedRuleProvenance{
			RuleID:       rule.ID,
			Decision:     rule.Decision,
			BundleSource: ruleBundleSource(rule),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID == out[j].RuleID {
			return out[i].Decision < out[j].Decision
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

func summarizeCapabilityResourceClass(actionType, resource string) string {
	switch actionType {
	case "fs.read", "fs.write":
		return summarizeWorkspaceResourceClass(resource)
	case "repo.apply_patch":
		if strings.HasPrefix(resource, "repo://") {
			return "repo_workspace"
		}
		return summarizeWorkspaceResourceClass(resource)
	default:
		return ""
	}
}

func summarizeWorkspaceResourceClass(resource string) string {
	switch {
	case resource == "file://workspace/" || resource == "file://workspace/**":
		return "workspace_tree"
	case strings.HasPrefix(resource, "file://workspace/") && !strings.ContainsAny(resource, "*"):
		return "workspace_single_path"
	case strings.HasPrefix(resource, "file://workspace/"):
		return "workspace_subtree"
	default:
		return ""
	}
}

func summarizeCapabilityHostClass(actionType, resource string) string {
	if actionType != "net.http_request" || !strings.HasPrefix(resource, "url://") {
		return ""
	}
	host := strings.TrimPrefix(resource, "url://")
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	switch {
	case host == "":
		return ""
	case strings.Contains(host, "*"):
		return "host_pattern_allowlist"
	default:
		return "host_allowlist"
	}
}

func summarizeCapabilityExecClass(actionType string, rule Rule) string {
	if actionType != "process.exec" {
		return ""
	}
	switch {
	case rule.ExecMatch != nil:
		return "argv_pattern_match"
	case hasLegacyExecAllowlist(rule):
		return "legacy_exec_allowlist"
	default:
		return "generic_exec"
	}
}

func summarizeCapabilityApprovalScope(rule Rule) string {
	if rule.Decision != DecisionRequireApproval {
		return ""
	}
	value, _ := rule.Obligations["approval_scope_class"].(string)
	switch strings.TrimSpace(value) {
	case "":
		return ""
	default:
		return value
	}
}

func appendUniqueString(in []string, value string) []string {
	if strings.TrimSpace(value) == "" {
		return in
	}
	for _, existing := range in {
		if existing == value {
			return in
		}
	}
	return append(in, value)
}
