package tenant

import "testing"

func TestResolveMapsPrincipalDeterministically(t *testing.T) {
	cfg := Config{
		Tenants: []Definition{
			{ID: "team-b", Principals: []string{"bob@example.com"}},
			{ID: "Team-A", Principals: []string{"alice@example.com"}},
		},
	}
	resolved, err := Resolve(cfg, Identity{Principal: "alice@example.com"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !resolved.Configured || resolved.ID != "team-a" || resolved.Defaulted {
		t.Fatalf("unexpected tenant resolution: %+v", resolved)
	}
}

func TestResolveUsesExplicitDefaultTenant(t *testing.T) {
	cfg := Config{Enabled: true, DefaultTenant: "default"}
	resolved, err := Resolve(cfg, Identity{Principal: "unknown@example.com"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.ID != "default" || !resolved.Defaulted {
		t.Fatalf("expected default tenant, got %+v", resolved)
	}
}

func TestResolveFailsClosedWithoutDefault(t *testing.T) {
	cfg := Config{Enabled: true, Tenants: []Definition{{ID: "team-a", Principals: []string{"alice@example.com"}}}}
	if _, err := Resolve(cfg, Identity{Principal: "unknown@example.com"}); err == nil {
		t.Fatal("expected unresolved tenant to fail closed")
	}
}

func TestVisibleUpstreamUsesTenantDefinitionBeforeServerTags(t *testing.T) {
	cfg := Config{
		Tenants: []Definition{
			{ID: "team-a", UpstreamServers: []string{"retail"}},
			{ID: "team-b", UpstreamServers: []string{"orders"}},
		},
	}
	if !VisibleUpstream(cfg, "team-a", "retail", []string{"team-b"}) {
		t.Fatal("expected explicit tenant upstream list to allow retail")
	}
	if VisibleUpstream(cfg, "team-a", "orders", nil) {
		t.Fatal("expected team-a to be unable to see orders")
	}
}

func TestValidateConfigRejectsAmbiguousPrincipals(t *testing.T) {
	cfg := Config{
		Tenants: []Definition{
			{ID: "team-a", Principals: []string{"shared@example.com"}},
			{ID: "team-b", Principals: []string{"SHARED@example.com"}},
		},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected duplicate principal mapping error")
	}
}
