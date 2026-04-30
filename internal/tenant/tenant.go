package tenant

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var tenantIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type Config struct {
	Enabled       bool         `json:"enabled"`
	DefaultTenant string       `json:"default_tenant,omitempty"`
	Tenants       []Definition `json:"tenants,omitempty"`
}

type Definition struct {
	ID                   string   `json:"id"`
	Principals           []string `json:"principals,omitempty"`
	PolicyBundlePath     string   `json:"policy_bundle_path,omitempty"`
	PolicyBundlePaths    []string `json:"policy_bundle_paths,omitempty"`
	PolicyBundleRoles    []string `json:"policy_bundle_roles,omitempty"`
	PolicySignaturePath  string   `json:"policy_signature_path,omitempty"`
	PolicySignaturePaths []string `json:"policy_signature_paths,omitempty"`
	UpstreamServers      []string `json:"upstream_servers,omitempty"`
}

type Identity struct {
	Principal   string
	Agent       string
	Environment string
}

type Resolved struct {
	ID         string
	Configured bool
	Defaulted  bool
}

func (c Config) Configured() bool {
	return c.Enabled || strings.TrimSpace(c.DefaultTenant) != "" || len(c.Tenants) > 0
}

func NormalizeID(id string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(id))
	if normalized == "" {
		return "", errors.New("tenant id is required")
	}
	if !tenantIDPattern.MatchString(normalized) {
		return "", fmt.Errorf("tenant id %q must match [a-z0-9][a-z0-9._-]{0,127}", strings.TrimSpace(id))
	}
	return normalized, nil
}

func ValidateConfig(c Config) error {
	if !c.Configured() {
		return nil
	}
	seenIDs := map[string]struct{}{}
	principalOwners := map[string]string{}
	if strings.TrimSpace(c.DefaultTenant) != "" {
		if _, err := NormalizeID(c.DefaultTenant); err != nil {
			return fmt.Errorf("tenancy.default_tenant: %w", err)
		}
	}
	for _, def := range c.Tenants {
		id, err := NormalizeID(def.ID)
		if err != nil {
			return fmt.Errorf("tenancy.tenants.id: %w", err)
		}
		if _, exists := seenIDs[id]; exists {
			return fmt.Errorf("duplicate tenant id %q", id)
		}
		seenIDs[id] = struct{}{}
		if strings.TrimSpace(def.PolicyBundlePath) != "" && len(def.PolicyBundlePaths) > 0 {
			return fmt.Errorf("tenant %q policy_bundle_path and policy_bundle_paths are mutually exclusive", id)
		}
		if strings.TrimSpace(def.PolicySignaturePath) != "" && len(def.PolicySignaturePaths) > 0 {
			return fmt.Errorf("tenant %q policy_signature_path and policy_signature_paths are mutually exclusive", id)
		}
		for _, principal := range def.Principals {
			principal = strings.TrimSpace(principal)
			if principal == "" {
				return fmt.Errorf("tenant %q principals entries must be non-empty", id)
			}
			key := strings.ToLower(principal)
			if owner, exists := principalOwners[key]; exists && owner != id {
				return fmt.Errorf("principal %q is mapped to both tenants %q and %q", principal, owner, id)
			}
			principalOwners[key] = id
		}
		for _, upstream := range def.UpstreamServers {
			if strings.TrimSpace(upstream) == "" {
				return fmt.Errorf("tenant %q upstream_servers entries must be non-empty", id)
			}
		}
	}
	return nil
}

func Resolve(c Config, id Identity) (Resolved, error) {
	if !c.Configured() {
		return Resolved{}, nil
	}
	principal := strings.TrimSpace(id.Principal)
	if principal == "" {
		return Resolved{}, errors.New("tenant cannot be derived: principal is empty")
	}
	principalKey := strings.ToLower(principal)
	var matches []string
	for _, def := range c.Tenants {
		tenantID, err := NormalizeID(def.ID)
		if err != nil {
			return Resolved{}, err
		}
		for _, configured := range def.Principals {
			if strings.ToLower(strings.TrimSpace(configured)) == principalKey {
				matches = append(matches, tenantID)
				break
			}
		}
	}
	sort.Strings(matches)
	switch len(matches) {
	case 0:
		if strings.TrimSpace(c.DefaultTenant) == "" {
			return Resolved{}, fmt.Errorf("tenant cannot be derived for principal %q", principal)
		}
		defaultID, err := NormalizeID(c.DefaultTenant)
		if err != nil {
			return Resolved{}, err
		}
		return Resolved{ID: defaultID, Configured: true, Defaulted: true}, nil
	case 1:
		return Resolved{ID: matches[0], Configured: true}, nil
	default:
		return Resolved{}, fmt.Errorf("principal %q maps to multiple tenants: %s", principal, strings.Join(matches, ","))
	}
}

func DefinitionByID(c Config, id string) (Definition, bool) {
	normalized, err := NormalizeID(id)
	if err != nil {
		return Definition{}, false
	}
	for _, def := range c.Tenants {
		defID, err := NormalizeID(def.ID)
		if err != nil {
			continue
		}
		if defID == normalized {
			return def, true
		}
	}
	return Definition{}, false
}

func TenantIDs(c Config) []string {
	out := make([]string, 0, len(c.Tenants))
	for _, def := range c.Tenants {
		id, err := NormalizeID(def.ID)
		if err == nil {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func VisibleUpstream(c Config, tenantID, serverName string, serverTenants []string) bool {
	if !c.Configured() {
		return true
	}
	normalizedTenant, err := NormalizeID(tenantID)
	if err != nil {
		return false
	}
	serverKey := strings.ToLower(strings.TrimSpace(serverName))
	if serverKey == "" {
		return false
	}
	if def, ok := DefinitionByID(c, normalizedTenant); ok && len(def.UpstreamServers) > 0 {
		return containsFold(def.UpstreamServers, serverKey)
	}
	if len(serverTenants) > 0 {
		for _, value := range serverTenants {
			id, err := NormalizeID(value)
			if err == nil && id == normalizedTenant {
				return true
			}
		}
		return false
	}
	return true
}

func containsFold(values []string, targetLower string) bool {
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == targetLower {
			return true
		}
	}
	return false
}
