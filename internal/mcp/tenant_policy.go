package mcp

import (
	"errors"
	"fmt"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/tenant"
)

func loadServerTenantPolicyStates(basePaths []string, options RuntimeOptions) (map[string]*serverTenantPolicyState, error) {
	if !options.TenantConfig.Configured() {
		return map[string]*serverTenantPolicyState{}, nil
	}
	out := map[string]*serverTenantPolicyState{}
	for _, tenantID := range tenant.TenantIDs(options.TenantConfig) {
		def, _ := tenant.DefinitionByID(options.TenantConfig, tenantID)
		tenantPaths := tenantPolicyBundlePaths(def)
		if len(tenantPaths) == 0 {
			continue
		}
		paths := append([]string{}, basePaths...)
		paths = append(paths, tenantPaths...)
		roles := combinedMCPBundleRoles(len(basePaths), options.BundleRoles, len(tenantPaths), def.PolicyBundleRoles)
		bundle, err := policy.LoadBundlesWithOptions(paths, policy.MultiLoadOptions{BundleRoles: roles})
		if err != nil {
			return nil, fmt.Errorf("load tenant %q policy bundles: %w", tenantID, err)
		}
		if err := policy.ValidateExecCompatibility(bundle, options.ExecCompatibilityMode); err != nil {
			return nil, fmt.Errorf("tenant %q exec compatibility: %w", tenantID, err)
		}
		out[tenantID] = &serverTenantPolicyState{
			Engine:        policy.NewEngine(bundle),
			BundleHash:    bundle.Hash,
			BundleSources: policy.BundleSourceLabels(bundle),
		}
	}
	return out, nil
}

func tenantPolicyBundlePaths(def tenant.Definition) []string {
	if strings.TrimSpace(def.PolicyBundlePath) != "" {
		return []string{def.PolicyBundlePath}
	}
	out := make([]string, 0, len(def.PolicyBundlePaths))
	for _, value := range def.PolicyBundlePaths {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func combinedMCPBundleRoles(baseCount int, baseRoles []string, tenantCount int, tenantRoles []string) []string {
	if len(baseRoles) == 0 && len(tenantRoles) == 0 {
		return nil
	}
	out := make([]string, 0, baseCount+tenantCount)
	if len(baseRoles) > 0 {
		out = append(out, baseRoles...)
	} else {
		for i := 0; i < baseCount; i++ {
			out = append(out, "")
		}
	}
	if len(tenantRoles) > 0 {
		out = append(out, tenantRoles...)
	} else {
		for i := 0; i < tenantCount; i++ {
			out = append(out, "")
		}
	}
	return out
}

func (s *Server) selectPolicyEngine(normalized normalize.NormalizedAction) (*policy.Engine, string, error) {
	state := s.currentReloadState()
	if state == nil || state.Engine == nil {
		return nil, "", errors.New("mcp server policy unavailable")
	}
	resolved, err := tenant.Resolve(s.tenantConfig, tenant.Identity{
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

func (s *Server) tenantIDForIdentity(id identity.VerifiedIdentity) (string, error) {
	resolved, err := tenant.Resolve(s.tenantConfig, tenant.Identity{
		Principal:   id.Principal,
		Agent:       id.Agent,
		Environment: id.Environment,
	})
	if err != nil || !resolved.Configured {
		return "", err
	}
	return resolved.ID, nil
}

func (s *Server) policyMetadataForIdentity(id identity.VerifiedIdentity) (string, []string) {
	state := s.currentReloadState()
	if state == nil {
		return s.policyMetadata()
	}
	tenantID, err := s.tenantIDForIdentity(id)
	if err == nil && tenantID != "" {
		if tenantState := state.TenantPolicies[tenantID]; tenantState != nil {
			return tenantState.BundleHash, append([]string{}, tenantState.BundleSources...)
		}
	}
	return state.PolicyBundleHash, append([]string{}, state.PolicyBundleSources...)
}

func (s *Server) upstreamVisibleForIdentity(id identity.VerifiedIdentity, serverName string) bool {
	if !s.tenantConfig.Configured() {
		return true
	}
	tenantID, err := s.tenantIDForIdentity(id)
	if err != nil {
		return false
	}
	serverTenants := []string{}
	if s.upstream != nil {
		if cfg, ok := s.upstream.serverConfig(serverName); ok {
			serverTenants = append([]string{}, cfg.Tenants...)
		}
	}
	return tenant.VisibleUpstream(s.tenantConfig, tenantID, serverName, serverTenants)
}
