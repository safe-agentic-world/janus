package gateway

import (
	"fmt"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/tenant"
)

func loadGatewayPolicyStateFromConfig(cfg Config) (*gatewayPolicyState, error) {
	baseBundle, err := loadPolicyBundleForConfig(cfg, cfg.Policy.EffectiveBundlePaths(), cfg.Policy.EffectiveSignaturePaths(), cfg.Policy.EffectiveBundleRoles())
	if err != nil {
		return nil, err
	}
	state := newGatewayPolicyState(baseBundle)
	if !cfg.Tenancy.Configured() {
		return state, nil
	}
	for _, tenantID := range tenant.TenantIDs(cfg.Tenancy) {
		def, _ := tenant.DefinitionByID(cfg.Tenancy, tenantID)
		tenantPaths := effectiveTenantBundlePaths(def)
		if len(tenantPaths) == 0 {
			continue
		}
		paths := append([]string{}, cfg.Policy.EffectiveBundlePaths()...)
		paths = append(paths, tenantPaths...)
		signatures := combinedTenantSignaturePaths(cfg, def, len(tenantPaths))
		roles := combinedTenantBundleRoles(cfg, def, len(tenantPaths))
		bundle, err := loadPolicyBundleForConfig(cfg, paths, signatures, roles)
		if err != nil {
			return nil, fmt.Errorf("load tenant %q policy bundles: %w", tenantID, err)
		}
		state.TenantPolicies[tenantID] = newGatewayTenantPolicyState(bundle)
	}
	return state, nil
}

func loadPolicyBundleForConfig(cfg Config, paths, signatures, roles []string) (policy.Bundle, error) {
	bundle, err := policy.LoadBundlesWithOptions(paths, policy.MultiLoadOptions{
		VerifySignatures: cfg.Policy.VerifySignatures,
		SignaturePaths:   signatures,
		PublicKeyPath:    cfg.Policy.PublicKeyPath,
		BundleRoles:      roles,
	})
	if err != nil {
		return policy.Bundle{}, err
	}
	if err := policy.ValidateExecCompatibility(bundle, cfg.Policy.ExecCompatibilityMode); err != nil {
		return policy.Bundle{}, err
	}
	return bundle, nil
}

func combinedTenantBundleRoles(cfg Config, def tenant.Definition, tenantPathCount int) []string {
	basePaths := cfg.Policy.EffectiveBundlePaths()
	baseRoles := cfg.Policy.EffectiveBundleRoles()
	tenantRoles := effectiveTenantBundleRoles(def)
	if len(baseRoles) == 0 && len(tenantRoles) == 0 {
		return nil
	}
	out := make([]string, 0, len(basePaths)+tenantPathCount)
	if len(baseRoles) > 0 {
		out = append(out, baseRoles...)
	} else {
		for range basePaths {
			out = append(out, "")
		}
	}
	if len(tenantRoles) > 0 {
		out = append(out, tenantRoles...)
	} else {
		for i := 0; i < tenantPathCount; i++ {
			out = append(out, "")
		}
	}
	return out
}

func combinedTenantSignaturePaths(cfg Config, def tenant.Definition, tenantPathCount int) []string {
	if !cfg.Policy.VerifySignatures {
		return nil
	}
	out := append([]string{}, cfg.Policy.EffectiveSignaturePaths()...)
	out = append(out, effectiveTenantSignaturePaths(def, tenantPathCount)...)
	return out
}

func (g *Gateway) tenantForIdentity(id identity.VerifiedIdentity) (tenant.Resolved, error) {
	if g == nil {
		return tenant.Resolved{}, errGatewayPolicyUnavailable
	}
	return tenant.Resolve(g.cfg.Tenancy, tenant.Identity{
		Principal:   id.Principal,
		Agent:       id.Agent,
		Environment: id.Environment,
	})
}

func (g *Gateway) tenantIDForPrincipal(principal string) (string, error) {
	resolved, err := tenant.Resolve(g.cfg.Tenancy, tenant.Identity{
		Principal:   principal,
		Agent:       g.cfg.Identity.Agent,
		Environment: g.cfg.Identity.Environment,
	})
	if err != nil || !resolved.Configured {
		return "", err
	}
	return resolved.ID, nil
}

func (g *Gateway) selectPolicyEngine(normalized normalize.NormalizedAction) (*policy.Engine, string, error) {
	state := g.currentPolicyState()
	if state == nil || state.Engine == nil {
		return nil, "", errGatewayPolicyUnavailable
	}
	resolved, err := tenant.Resolve(g.cfg.Tenancy, tenant.Identity{
		Principal:   normalized.Principal,
		Agent:       normalized.Agent,
		Environment: normalized.Environment,
	})
	if err != nil {
		return nil, "", err
	}
	if !resolved.Configured {
		return state.Engine, "", nil
	}
	if tenantState := state.TenantPolicies[resolved.ID]; tenantState != nil && tenantState.Engine != nil {
		return tenantState.Engine, resolved.ID, nil
	}
	return state.Engine, resolved.ID, nil
}

func (g *Gateway) attachTenant(act *action.Action, id identity.VerifiedIdentity) error {
	resolved, err := g.tenantForIdentity(id)
	if err != nil {
		return err
	}
	if resolved.Configured {
		act.TenantID = resolved.ID
	}
	return nil
}
