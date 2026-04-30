package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigAppliesEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	overridePath := filepath.Join(dir, "bundle-override.json")
	if err := os.WriteFile(overridePath, []byte(`{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write override bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"policy":  map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit":     map[string]any{"sink": "stdout"},
		"mcp":       map[string]any{"enabled": false},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":   "system",
			"agent":       "nomos",
			"environment": "dev",
			"api_keys": map[string]any{
				"key1": "system",
			},
			"agent_secrets": map[string]any{
				"nomos": "secret",
			},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	env := map[string]string{
		"NOMOS_GATEWAY_LISTEN":        "127.0.0.1:0",
		"NOMOS_MCP_ENABLED":           "true",
		"NOMOS_IDENTITY_PRINCIPAL":    "override",
		"NOMOS_IDENTITY_API_KEY":      "override-key",
		"NOMOS_IDENTITY_AGENT_SECRET": "override-agent-secret",
		"NOMOS_POLICY_BUNDLE_PATH":    overridePath,
		"NOMOS_APPROVALS_SLACK_TOKEN": "slack-token",
		"NOMOS_APPROVALS_TEAMS_TOKEN": "teams-token",
	}
	cfg, err := LoadConfig(path, func(key string) string {
		return env[key]
	}, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Gateway.Listen != "127.0.0.1:0" {
		t.Fatalf("expected listen override, got %s", cfg.Gateway.Listen)
	}
	if !cfg.MCP.Enabled {
		t.Fatal("expected mcp.enabled override")
	}
	if cfg.Identity.Principal != "override" {
		t.Fatalf("expected principal override, got %s", cfg.Identity.Principal)
	}
	if cfg.Identity.APIKeys["override-key"] != "override" {
		t.Fatal("expected api key override")
	}
	if cfg.Identity.AgentSecrets["nomos"] != "override-agent-secret" {
		t.Fatal("expected agent secret override")
	}
	if cfg.Policy.BundlePath != overridePath {
		t.Fatalf("expected bundle override, got %s", cfg.Policy.BundlePath)
	}
	if cfg.Approvals.SlackToken != "slack-token" {
		t.Fatalf("expected slack token override, got %s", cfg.Approvals.SlackToken)
	}
	if cfg.Approvals.TeamsToken != "teams-token" {
		t.Fatalf("expected teams token override, got %s", cfg.Approvals.TeamsToken)
	}
}

func TestLoadConfigRequiresPolicyBundlePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"policy":  map[string]any{},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit":     map[string]any{"sink": "stdout"},
		"mcp":       map[string]any{"enabled": false},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":   "system",
			"agent":       "nomos",
			"environment": "dev",
			"api_keys": map[string]any{
				"key1": "system",
			},
			"agent_secrets": map[string]any{
				"nomos": "secret",
			},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := LoadConfig(path, os.Getenv, "")
	if err == nil {
		t.Fatal("expected policy bundle path error")
	}
}

func TestLoadConfigSupportsPolicyBundlePaths(t *testing.T) {
	dir := t.TempDir()
	firstBundle := filepath.Join(dir, "base.json")
	secondBundle := filepath.Join(dir, "repo.json")
	for _, path := range []string{firstBundle, secondBundle} {
		if err := os.WriteFile(path, []byte(`{"version":"v1","rules":[{"id":"`+filepath.Base(path)+`","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
			t.Fatalf("write bundle %s: %v", path, err)
		}
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"policy":  map[string]any{"policy_bundle_paths": []any{firstBundle, secondBundle}},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit":     map[string]any{"sink": "stdout"},
		"mcp":       map[string]any{"enabled": false},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(path, os.Getenv, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.Policy.EffectiveBundlePaths()) != 2 {
		t.Fatalf("expected 2 effective bundle paths, got %+v", cfg.Policy.EffectiveBundlePaths())
	}
}

func TestLoadConfigRejectsAmbiguousPolicyBundleConfig(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"policy": map[string]any{
			"policy_bundle_path":  bundlePath,
			"policy_bundle_paths": []any{bundlePath},
		},
		"executor":  map[string]any{"sandbox_enabled": true},
		"audit":     map[string]any{"sink": "stdout"},
		"mcp":       map[string]any{"enabled": false},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := LoadConfig(path, os.Getenv, ""); err == nil {
		t.Fatal("expected ambiguous bundle config error")
	}
}

func TestLoadConfigSupportsPolicyBundleRoles(t *testing.T) {
	dir := t.TempDir()
	baseBundle := filepath.Join(dir, "base.json")
	repoBundle := filepath.Join(dir, "repo.json")
	for _, path := range []string{baseBundle, repoBundle} {
		if err := os.WriteFile(path, []byte(`{"version":"v1","rules":[{"id":"`+filepath.Base(path)+`","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
			t.Fatalf("write bundle %s: %v", path, err)
		}
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"runtime": map[string]any{"deployment_mode": "unmanaged"},
		"policy": map[string]any{
			"policy_bundle_paths": []any{baseBundle, repoBundle},
			"policy_bundle_roles": []any{"baseline", "repo"},
		},
		"executor":  map[string]any{"sandbox_enabled": true},
		"audit":     map[string]any{"sink": "stdout"},
		"mcp":       map[string]any{"enabled": false},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(path, os.Getenv, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if got := cfg.Policy.EffectiveBundleRoles(); len(got) != 2 || got[0] != "baseline" || got[1] != "repo" {
		t.Fatalf("unexpected effective bundle roles: %+v", got)
	}
}

func TestLoadConfigRejectsLocalOverrideOutsideApprovedContexts(t *testing.T) {
	dir := t.TempDir()
	baseBundle := filepath.Join(dir, "base.json")
	overrideBundle := filepath.Join(dir, "override.json")
	for _, path := range []string{baseBundle, overrideBundle} {
		if err := os.WriteFile(path, []byte(`{"version":"v1","rules":[{"id":"`+filepath.Base(path)+`","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
			t.Fatalf("write bundle %s: %v", path, err)
		}
	}

	devAllowedPath := filepath.Join(dir, "config-dev.json")
	devAllowedJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"runtime": map[string]any{"deployment_mode": "unmanaged"},
		"policy": map[string]any{
			"policy_bundle_paths": []any{baseBundle, overrideBundle},
			"policy_bundle_roles": []any{"baseline", "local_override"},
		},
		"executor":  map[string]any{"sandbox_enabled": true},
		"audit":     map[string]any{"sink": "stdout"},
		"mcp":       map[string]any{"enabled": false},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(devAllowedPath, devAllowedJSON, 0o600); err != nil {
		t.Fatalf("write dev config: %v", err)
	}
	if _, err := LoadConfig(devAllowedPath, os.Getenv, ""); err != nil {
		t.Fatalf("expected dev unmanaged local_override config to load, got %v", err)
	}

	ciRejectedPath := filepath.Join(dir, "config-ci.json")
	ciRejectedJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"runtime": map[string]any{"deployment_mode": "ci"},
		"policy": map[string]any{
			"policy_bundle_paths": []any{baseBundle, overrideBundle},
			"policy_bundle_roles": []any{"baseline", "local_override"},
		},
		"executor":  map[string]any{"sandbox_enabled": true},
		"audit":     map[string]any{"sink": "stdout"},
		"mcp":       map[string]any{"enabled": false},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(ciRejectedPath, ciRejectedJSON, 0o600); err != nil {
		t.Fatalf("write ci config: %v", err)
	}
	if _, err := LoadConfig(ciRejectedPath, os.Getenv, ""); err == nil {
		t.Fatal("expected local_override rejection for non-unmanaged deployment mode")
	}
}

func TestLoadConfigApprovalsValidationAndDefaults(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"policy":  map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit":    map[string]any{"sink": "stdout"},
		"mcp":      map[string]any{"enabled": false},
		"upstream": map[string]any{"routes": []any{}},
		"approvals": map[string]any{
			"enabled": true,
		},
		"identity": map[string]any{
			"principal":   "system",
			"agent":       "nomos",
			"environment": "dev",
			"api_keys": map[string]any{
				"key1": "system",
			},
			"agent_secrets": map[string]any{
				"nomos": "secret",
			},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(path, os.Getenv, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Approvals.StorePath == "" {
		t.Fatal("expected approvals.store_path default")
	}
	if cfg.Approvals.Backend != "file" {
		t.Fatalf("expected file-backed approvals default, got %q", cfg.Approvals.Backend)
	}
	if filepath.Base(cfg.Approvals.StorePath) != "nomos-approvals.json" {
		t.Fatalf("expected file-backed approvals default path, got %s", cfg.Approvals.StorePath)
	}
	if cfg.Approvals.TTLSeconds <= 0 {
		t.Fatal("expected approvals.ttl_seconds default")
	}
}

func TestLoadConfigStatelessModeRules(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http", "concurrency_limit": 4},
		"runtime": map[string]any{"stateless_mode": true},
		"policy":  map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit":    map[string]any{"sink": "stdout"},
		"mcp":      map[string]any{"enabled": false},
		"upstream": map[string]any{"routes": []any{}},
		"approvals": map[string]any{
			"enabled": false,
		},
		"identity": map[string]any{
			"principal":   "system",
			"agent":       "nomos",
			"environment": "dev",
			"api_keys": map[string]any{
				"key1": "system",
			},
			"agent_secrets": map[string]any{
				"nomos": "secret",
			},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(path, os.Getenv, "")
	if err != nil {
		t.Fatalf("expected valid stateless config, got %v", err)
	}
	if !cfg.Runtime.StatelessMode {
		t.Fatal("expected stateless mode true")
	}
	if cfg.Gateway.ConcurrencyLimit != 4 {
		t.Fatalf("expected concurrency limit 4, got %d", cfg.Gateway.ConcurrencyLimit)
	}

	badPath := filepath.Join(dir, "config-bad.json")
	badJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"runtime": map[string]any{"stateless_mode": true},
		"policy":  map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit":    map[string]any{"sink": "sqlite:./audit.db"},
		"mcp":      map[string]any{"enabled": false},
		"upstream": map[string]any{"routes": []any{}},
		"approvals": map[string]any{
			"enabled": true,
		},
		"identity": map[string]any{
			"principal":   "system",
			"agent":       "nomos",
			"environment": "dev",
			"api_keys": map[string]any{
				"key1": "system",
			},
			"agent_secrets": map[string]any{
				"nomos": "secret",
			},
		},
	})
	if err := os.WriteFile(badPath, badJSON, 0o600); err != nil {
		t.Fatalf("write bad config: %v", err)
	}
	if _, err := LoadConfig(badPath, os.Getenv, ""); err == nil {
		t.Fatal("expected stateless mode validation error")
	}
}

func TestLoadConfigM13HardeningFields(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	sigPath := filepath.Join(dir, "bundle.sig")
	pubPath := filepath.Join(dir, "bundle_pub.pem")
	oidcPub := filepath.Join(dir, "oidc_pub.pem")
	if err := os.WriteFile(sigPath, []byte("AA=="), 0o600); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA7a+x\n-----END PUBLIC KEY-----"), 0o600); err != nil {
		t.Fatalf("write policy pub: %v", err)
	}
	if err := os.WriteFile(oidcPub, []byte("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA7a+x\n-----END PUBLIC KEY-----"), 0o600); err != nil {
		t.Fatalf("write oidc pub: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{
			"listen":                           ":8080",
			"transport":                        "http",
			"concurrency_limit":                5,
			"rate_limit_per_minute":            10,
			"circuit_breaker_failures":         3,
			"circuit_breaker_cooldown_seconds": 30,
		},
		"runtime": map[string]any{"stateless_mode": false},
		"policy": map[string]any{
			"policy_bundle_path": bundlePath,
			"verify_signatures":  true,
			"signature_path":     sigPath,
			"public_key_path":    pubPath,
		},
		"executor": map[string]any{"sandbox_enabled": true},
		"audit":    map[string]any{"sink": "stdout"},
		"mcp":      map[string]any{"enabled": false},
		"upstream": map[string]any{"routes": []any{}},
		"approvals": map[string]any{
			"enabled": false,
		},
		"identity": map[string]any{
			"principal":   "system",
			"agent":       "nomos",
			"environment": "dev",
			"agent_secrets": map[string]any{
				"nomos": "secret",
			},
			"oidc": map[string]any{
				"enabled":         true,
				"issuer":          "https://issuer.example",
				"audience":        "nomos",
				"public_key_path": oidcPub,
			},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := LoadConfig(path, os.Getenv, ""); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestLoadConfigResolvesPathsRelativeToConfigDir(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "conf")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	workspaceDir := filepath.Join(configDir, "workspace")
	if err := os.MkdirAll(workspaceDir, 0o700); err != nil {
		t.Fatalf("mkdir workspace: %v", err)
	}
	bundlePath := filepath.Join(configDir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(configDir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"policy":  map[string]any{"policy_bundle_path": ".\\bundle.json"},
		"executor": map[string]any{
			"sandbox_enabled": true,
			"workspace_root":  ".\\workspace",
		},
		"audit":    map[string]any{"sink": "sqlite:./audit.db"},
		"mcp":      map[string]any{"enabled": false},
		"upstream": map[string]any{"routes": []any{}},
		"approvals": map[string]any{
			"enabled":    true,
			"store_path": ".\\approvals.db",
		},
		"identity": map[string]any{
			"principal":   "system",
			"agent":       "nomos",
			"environment": "dev",
			"api_keys": map[string]any{
				"key1": "system",
			},
			"agent_secrets": map[string]any{
				"nomos": "secret",
			},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(path, os.Getenv, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Policy.BundlePath != bundlePath {
		t.Fatalf("expected config-relative bundle path, got %s", cfg.Policy.BundlePath)
	}
	if cfg.Executor.WorkspaceRoot != workspaceDir {
		t.Fatalf("expected config-relative workspace root, got %s", cfg.Executor.WorkspaceRoot)
	}
	if cfg.Approvals.StorePath != filepath.Join(configDir, "approvals.db") {
		t.Fatalf("expected config-relative approvals store, got %s", cfg.Approvals.StorePath)
	}
	if cfg.Audit.Sink != "sqlite:"+filepath.Join(configDir, "audit.db") {
		t.Fatalf("expected config-relative sqlite sink, got %s", cfg.Audit.Sink)
	}
}

func TestLoadConfigSupportsTypedAndLegacyUpstreamRoutes(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	typedPath := filepath.Join(dir, "typed.json")
	typedJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"policy":  map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit": map[string]any{"sink": "stdout"},
		"mcp":   map[string]any{"enabled": false},
		"upstream": map[string]any{"routes": []any{
			map[string]any{"url": "https://api.example.com/base", "methods": []any{"GET", "POST"}, "path_prefix": "/base"},
		}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":   "system",
			"agent":       "nomos",
			"environment": "dev",
			"api_keys":    map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{
				"nomos": "secret",
			},
		},
	})
	if err := os.WriteFile(typedPath, typedJSON, 0o600); err != nil {
		t.Fatalf("write typed config: %v", err)
	}
	cfg, err := LoadConfig(typedPath, os.Getenv, "")
	if err != nil {
		t.Fatalf("load typed config: %v", err)
	}
	if len(cfg.Upstream.Routes) != 1 || cfg.Upstream.Routes[0].URL != "https://api.example.com/base" {
		t.Fatalf("unexpected typed routes: %+v", cfg.Upstream.Routes)
	}
	if len(cfg.Upstream.Routes[0].Methods) != 2 || cfg.Upstream.Routes[0].PathPrefix != "/base" {
		t.Fatalf("expected typed route fields, got %+v", cfg.Upstream.Routes[0])
	}

	legacyPath := filepath.Join(dir, "legacy.json")
	legacyJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"policy":  map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit": map[string]any{"sink": "stdout"},
		"mcp":   map[string]any{"enabled": false},
		"upstream": map[string]any{"routes": []any{
			"https://legacy.example.com",
		}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":   "system",
			"agent":       "nomos",
			"environment": "dev",
			"api_keys":    map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{
				"nomos": "secret",
			},
		},
	})
	if err := os.WriteFile(legacyPath, legacyJSON, 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}
	cfg, err = LoadConfig(legacyPath, os.Getenv, "")
	if err != nil {
		t.Fatalf("load legacy config: %v", err)
	}
	if len(cfg.Upstream.Routes) != 1 || cfg.Upstream.Routes[0].URL != "https://legacy.example.com" {
		t.Fatalf("unexpected legacy routes: %+v", cfg.Upstream.Routes)
	}
}

func TestLoadConfigSupportsTelemetryAndSPIFFE(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	opaPolicyPath := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(opaPolicyPath, []byte(`package nomos`), 0o600); err != nil {
		t.Fatalf("write opa policy: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"policy": map[string]any{
			"policy_bundle_path": bundlePath,
			"opa": map[string]any{
				"enabled":     true,
				"binary_path": "pwsh",
				"policy_path": opaPolicyPath,
				"query":       "data.nomos.decision",
				"timeout_ms":  500,
			},
		},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit":     map[string]any{"sink": "stdout"},
		"telemetry": map[string]any{"enabled": true, "sink": "otlp:http://127.0.0.1:4318"},
		"mcp":       map[string]any{"enabled": false},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
			"spiffe": map[string]any{
				"enabled":      true,
				"trust_domain": "example.org",
			},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(path, os.Getenv, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.Telemetry.Enabled || cfg.Telemetry.Sink != "otlp:http://127.0.0.1:4318" {
		t.Fatalf("unexpected telemetry config: %+v", cfg.Telemetry)
	}
	if !cfg.Identity.SPIFFE.Enabled || cfg.Identity.SPIFFE.TrustDomain != "example.org" {
		t.Fatalf("unexpected SPIFFE config: %+v", cfg.Identity.SPIFFE)
	}
	if !cfg.Policy.OPA.Enabled || cfg.Policy.OPA.BinaryPath != "pwsh" || cfg.Policy.OPA.PolicyPath != opaPolicyPath || cfg.Policy.OPA.Query != "data.nomos.decision" || cfg.Policy.OPA.TimeoutMS != 500 {
		t.Fatalf("unexpected OPA config: %+v", cfg.Policy.OPA)
	}
}

func TestLoadConfigExecCompatibilityModeDefaultsAndValidation(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway":   map[string]any{"listen": ":8080", "transport": "http"},
		"policy":    map[string]any{"policy_bundle_path": bundlePath},
		"executor":  map[string]any{"sandbox_enabled": true},
		"audit":     map[string]any{"sink": "stdout"},
		"mcp":       map[string]any{"enabled": false},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(path, os.Getenv, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Policy.ExecCompatibilityMode != "legacy_allowlist_fallback" {
		t.Fatalf("expected default exec compatibility mode, got %s", cfg.Policy.ExecCompatibilityMode)
	}

	env := func(key string) string {
		if key == "NOMOS_POLICY_EXEC_COMPATIBILITY_MODE" {
			return "strict"
		}
		return ""
	}
	cfg, err = LoadConfig(path, env, "")
	if err != nil {
		t.Fatalf("load config with strict env: %v", err)
	}
	if cfg.Policy.ExecCompatibilityMode != "strict" {
		t.Fatalf("expected strict mode, got %s", cfg.Policy.ExecCompatibilityMode)
	}

	badPath := filepath.Join(dir, "config-bad.json")
	badJSON := mustMarshal(map[string]any{
		"gateway":   map[string]any{"listen": ":8080", "transport": "http"},
		"policy":    map[string]any{"policy_bundle_path": bundlePath, "exec_compatibility_mode": "invalid"},
		"executor":  map[string]any{"sandbox_enabled": true},
		"audit":     map[string]any{"sink": "stdout"},
		"mcp":       map[string]any{"enabled": false},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(badPath, badJSON, 0o600); err != nil {
		t.Fatalf("write bad config: %v", err)
	}
	if _, err := LoadConfig(badPath, os.Getenv, ""); err == nil {
		t.Fatal("expected invalid exec compatibility mode error")
	}
}

func TestLoadConfigSupportsMCPUpstreamServers(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	workdir := filepath.Join(dir, "upstream")
	caPath := filepath.Join(dir, "ca.pem")
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client-key.pem")
	if err := os.MkdirAll(workdir, 0o700); err != nil {
		t.Fatalf("mkdir upstream workdir: %v", err)
	}
	for _, file := range []string{caPath, certPath, keyPath} {
		if err := os.WriteFile(file, []byte("test"), 0o600); err != nil {
			t.Fatalf("write %s: %v", file, err)
		}
	}
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"policy":  map[string]any{"policy_bundle_path": ".\\bundle.json"},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit": map[string]any{"sink": "stdout"},
		"credentials": map[string]any{
			"enabled": true,
			"secrets": []any{
				map[string]any{"id": "retail_mcp_token", "env_key": "RETAIL_MCP_TOKEN", "value": "retail-token", "ttl_seconds": 900},
			},
		},
		"mcp": map[string]any{
			"enabled": true,
			"upstream_servers": []any{
				map[string]any{
					"name":          "retail",
					"transport":     "streamable_http",
					"endpoint":      "https://retail.example.com/mcp",
					"workdir":       ".\\upstream",
					"env_allowlist": []any{"RETAIL_ENV", "PATH"},
					"env":           map[string]any{"RETAIL_ENV": "demo"},
					"tls_ca_file":   ".\\ca.pem",
					"tls_cert_file": ".\\client.pem",
					"tls_key_file":  ".\\client-key.pem",
					"credentials": map[string]any{
						"profile":                  "retail_mcp_token",
						"mode":                     "bearer",
						"refresh_before_expiry_ms": 30000,
					},
				},
			},
		},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(path, os.Getenv, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.MCP.UpstreamServers) != 1 {
		t.Fatalf("expected one upstream server, got %+v", cfg.MCP.UpstreamServers)
	}
	server := cfg.MCP.UpstreamServers[0]
	if server.Name != "retail" || server.Transport != "streamable_http" {
		t.Fatalf("unexpected upstream server config: %+v", server)
	}
	if server.Workdir != workdir {
		t.Fatalf("expected config-relative upstream workdir, got %s", server.Workdir)
	}
	if server.TLSCAFile != caPath || server.TLSCertFile != certPath || server.TLSKeyFile != keyPath {
		t.Fatalf("expected config-relative TLS files, got %+v", server)
	}
	if len(server.EnvAllowlist) != 2 || server.EnvAllowlist[0] != "RETAIL_ENV" || server.EnvAllowlist[1] != "PATH" {
		t.Fatalf("expected env allowlist, got %+v", server.EnvAllowlist)
	}
	if server.Env["RETAIL_ENV"] != "demo" {
		t.Fatalf("expected upstream env, got %+v", server.Env)
	}
	if server.Credentials == nil || server.Credentials.Profile != "retail_mcp_token" || server.Credentials.Mode != "bearer" || server.Credentials.RefreshBeforeExpiryMS != 30000 {
		t.Fatalf("expected upstream brokered credentials config, got %+v", server.Credentials)
	}
}

func TestLoadConfigAppliesMCPTimeoutDefaultsAndOverrides(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway":  map[string]any{"listen": ":8080", "transport": "http"},
		"policy":   map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{"sandbox_enabled": true},
		"audit":    map[string]any{"sink": "stdout"},
		"mcp": map[string]any{
			"enabled": true,
			"timeouts": map[string]any{
				"initialize_timeout_ms": 7000,
				"call_timeout_ms":       45000,
			},
			"upstream_servers": []any{
				map[string]any{
					"name":      "retail",
					"transport": "stdio",
					"command":   "helper",
					"timeouts": map[string]any{
						"enumerate_timeout_ms": 12000,
					},
				},
			},
		},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(path, os.Getenv, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.MCP.Timeouts.InitializeMS != 7000 || cfg.MCP.Timeouts.EnumerateMS != 5000 || cfg.MCP.Timeouts.CallMS != 45000 || cfg.MCP.Timeouts.StreamMS != 30000 {
		t.Fatalf("unexpected global mcp timeouts: %+v", cfg.MCP.Timeouts)
	}
	if len(cfg.MCP.UpstreamServers) != 1 {
		t.Fatalf("expected one upstream server, got %+v", cfg.MCP.UpstreamServers)
	}
	server := cfg.MCP.UpstreamServers[0]
	if server.Timeouts.InitializeMS != 0 || server.Timeouts.EnumerateMS != 12000 || server.Timeouts.CallMS != 0 || server.Timeouts.StreamMS != 0 {
		t.Fatalf("unexpected per-server mcp timeouts: %+v", server.Timeouts)
	}
}

func TestLoadConfigAppliesMCPBreakerDefaultsAndOverrides(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway":  map[string]any{"listen": ":8080", "transport": "http"},
		"policy":   map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{"sandbox_enabled": true},
		"audit":    map[string]any{"sink": "stdout"},
		"mcp": map[string]any{
			"enabled": true,
			"breaker": map[string]any{
				"enabled":           true,
				"failure_threshold": 4,
				"failure_window_ms": 90000,
				"open_timeout_ms":   15000,
			},
			"upstream_servers": []any{
				map[string]any{
					"name":                       "retail",
					"transport":                  "stdio",
					"command":                    "helper",
					"allow_missing_tool_schemas": true,
					"breaker": map[string]any{
						"failure_threshold": 2,
						"open_timeout_ms":   5000,
					},
				},
			},
		},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(path, os.Getenv, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.MCP.Breaker.Enabled == nil || !*cfg.MCP.Breaker.Enabled {
		t.Fatalf("expected global breaker enabled, got %+v", cfg.MCP.Breaker)
	}
	if cfg.MCP.Breaker.FailureThreshold != 4 || cfg.MCP.Breaker.FailureWindowMS != 90000 || cfg.MCP.Breaker.OpenTimeoutMS != 15000 {
		t.Fatalf("unexpected global breaker config: %+v", cfg.MCP.Breaker)
	}
	server := cfg.MCP.UpstreamServers[0]
	if server.Breaker.FailureThreshold != 2 || server.Breaker.FailureWindowMS != 0 || server.Breaker.OpenTimeoutMS != 5000 {
		t.Fatalf("unexpected per-server breaker config: %+v", server.Breaker)
	}
	if !server.AllowMissingToolSchemas {
		t.Fatalf("expected per-server missing-schema opt-in")
	}
}

func TestLoadConfigRejectsInvalidMCPBreakerConfig(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway":  map[string]any{"listen": ":8080", "transport": "http"},
		"policy":   map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{"sandbox_enabled": true},
		"audit":    map[string]any{"sink": "stdout"},
		"mcp": map[string]any{
			"enabled": true,
			"breaker": map[string]any{
				"enabled":           true,
				"failure_threshold": -1,
				"failure_window_ms": 60000,
				"open_timeout_ms":   30000,
			},
		},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := LoadConfig(path, os.Getenv, ""); err == nil || !strings.Contains(err.Error(), "mcp.breaker.failure_threshold must be > 0") {
		t.Fatalf("expected breaker validation error, got %v", err)
	}
}

func TestLoadConfigAcceptsRateLimitRules(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"runtime": map[string]any{"deployment_mode": "unmanaged"},
		"policy":  map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{
			"sandbox_enabled": false,
			"workspace_root":  dir,
		},
		"audit":     map[string]any{"sink": "stdout"},
		"telemetry": map[string]any{"enabled": true, "sink": "stderr"},
		"rate_limits": map[string]any{
			"enabled":             true,
			"evict_after_seconds": 60,
			"principal_action": []any{
				map[string]any{"id": "read-per-principal", "action_type": "fs.read", "burst": 2, "refill_per_minute": 60},
			},
			"principal_resource": []any{
				map[string]any{"id": "readme-per-principal", "resource": "file://workspace/README.md", "burst": 1, "refill_per_minute": 30},
			},
			"global_tool": []any{
				map[string]any{"id": "global-read", "action_type": "fs.read", "burst": 10, "refill_per_minute": 120},
			},
		},
		"mcp":      map[string]any{"enabled": false},
		"upstream": map[string]any{"routes": []any{}},
		"approvals": map[string]any{
			"enabled": false,
		},
		"identity": map[string]any{
			"principal":   "system",
			"agent":       "nomos",
			"environment": "dev",
			"api_keys":    map[string]any{"dev-api-key": "system"},
			"agent_secrets": map[string]any{
				"nomos": "secret",
			},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(path, os.Getenv, "")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.RateLimits.Enabled || cfg.RateLimits.EvictAfterSeconds != 60 {
		t.Fatalf("unexpected rate limits config: %+v", cfg.RateLimits)
	}
	rules, err := cfg.RateLimits.Rules()
	if err != nil {
		t.Fatalf("rate limit rules: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rate limit rules, got %+v", rules)
	}
}

func TestLoadConfigRejectsInvalidRateLimitRules(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	cases := []struct {
		name    string
		rule    map[string]any
		wantErr string
	}{
		{
			name:    "burst",
			rule:    map[string]any{"id": "bad-burst", "action_type": "fs.read", "burst": 0, "refill_per_minute": 60},
			wantErr: "burst must be > 0",
		},
		{
			name:    "refill",
			rule:    map[string]any{"id": "bad-refill", "action_type": "fs.read", "burst": 1, "refill_per_minute": 0},
			wantErr: "refill_per_minute must be > 0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "config-"+tc.name+".json")
			configJSON := mustMarshal(map[string]any{
				"gateway": map[string]any{"listen": ":8080", "transport": "http"},
				"runtime": map[string]any{"deployment_mode": "unmanaged"},
				"policy":  map[string]any{"policy_bundle_path": bundlePath},
				"executor": map[string]any{
					"sandbox_enabled": false,
					"workspace_root":  dir,
				},
				"audit":    map[string]any{"sink": "stdout"},
				"mcp":      map[string]any{"enabled": false},
				"upstream": map[string]any{"routes": []any{}},
				"approvals": map[string]any{
					"enabled": false,
				},
				"rate_limits": map[string]any{
					"enabled": true,
					"principal_action": []any{
						tc.rule,
					},
				},
				"identity": map[string]any{
					"principal":   "system",
					"agent":       "nomos",
					"environment": "dev",
					"api_keys":    map[string]any{"dev-api-key": "system"},
					"agent_secrets": map[string]any{
						"nomos": "secret",
					},
				},
			})
			if err := os.WriteFile(path, configJSON, 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			if _, err := LoadConfig(path, os.Getenv, ""); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected invalid rate limit config error %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestLoadConfigRejectsInvalidMCPUpstreamServer(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"policy":  map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit": map[string]any{"sink": "stdout"},
		"mcp": map[string]any{
			"enabled": true,
			"upstream_servers": []any{
				map[string]any{
					"name":      "retail",
					"transport": "http",
					"command":   "ignored",
				},
			},
		},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := LoadConfig(path, os.Getenv, ""); err == nil || !strings.Contains(err.Error(), "mcp.upstream_servers.transport must be stdio|streamable_http|sse") {
		t.Fatalf("expected invalid upstream transport error, got %v", err)
	}
}

func TestLoadConfigRejectsIncompleteMCPUpstreamMutualTLSConfig(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	certPath := filepath.Join(dir, "client.pem")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(certPath, []byte("test"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"policy":  map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit": map[string]any{"sink": "stdout"},
		"mcp": map[string]any{
			"enabled": true,
			"upstream_servers": []any{
				map[string]any{
					"name":          "retail",
					"transport":     "streamable_http",
					"endpoint":      "https://retail.example.com/mcp",
					"tls_cert_file": certPath,
				},
			},
		},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := LoadConfig(path, os.Getenv, ""); err == nil || !strings.Contains(err.Error(), "tls_cert_file and tls_key_file must be provided together") {
		t.Fatalf("expected incomplete mTLS config error, got %v", err)
	}
}

func TestLoadConfigRejectsWildcardMCPUpstreamEnvNames(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"allow","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	path := filepath.Join(dir, "config.json")
	configJSON := mustMarshal(map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"policy":  map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{
			"sandbox_enabled": true,
		},
		"audit": map[string]any{"sink": "stdout"},
		"mcp": map[string]any{
			"enabled": true,
			"upstream_servers": []any{
				map[string]any{
					"name":          "retail",
					"transport":     "stdio",
					"command":       "python",
					"env_allowlist": []any{"RETAIL_*"},
				},
			},
		},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"key1": "system"},
			"agent_secrets": map[string]any{"nomos": "secret"},
		},
	})
	if err := os.WriteFile(path, configJSON, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := LoadConfig(path, os.Getenv, ""); err == nil || !strings.Contains(err.Error(), "env_allowlist must use exact variable names") {
		t.Fatalf("expected invalid env allowlist error, got %v", err)
	}
}
