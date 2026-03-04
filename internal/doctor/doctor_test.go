package doctor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRunReady(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	writeConfig(t, configPath, bundlePath, true, dir, false)

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.OverallStatus != "READY" {
		t.Fatalf("expected READY, got %s", report.OverallStatus)
	}
	if report.PolicyBundleHash == "" {
		t.Fatal("expected policy bundle hash")
	}
}

func TestRunMissingBundleNotReady(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	writeConfig(t, configPath, filepath.Join(dir, "missing.json"), true, dir, false)

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.OverallStatus != "NOT_READY" {
		t.Fatalf("expected NOT_READY, got %s", report.OverallStatus)
	}
}

func TestRunMalformedBundleNotReady(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":`), 0o600); err != nil {
		t.Fatalf("write malformed bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	writeConfig(t, configPath, bundlePath, true, dir, false)

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.OverallStatus != "NOT_READY" {
		t.Fatalf("expected NOT_READY, got %s", report.OverallStatus)
	}
}

func TestReportJSONDeterministic(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	writeConfig(t, configPath, bundlePath, true, dir, false)

	r1, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run #1: %v", err)
	}
	r2, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run #2: %v", err)
	}
	j1, err := json.Marshal(r1)
	if err != nil {
		t.Fatalf("marshal #1: %v", err)
	}
	j2, err := json.Marshal(r2)
	if err != nil {
		t.Fatalf("marshal #2: %v", err)
	}
	if string(j1) != string(j2) {
		t.Fatalf("expected deterministic json output\n1=%s\n2=%s", string(j1), string(j2))
	}
}

func TestRunStrongGuaranteeMissingHardeningNotReady(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["prod"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	writeConfig(t, configPath, bundlePath, true, dir, true)

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.OverallStatus != "NOT_READY" {
		t.Fatalf("expected NOT_READY, got %s", report.OverallStatus)
	}
	assertCheckFailed(t, report, "strong.sandbox_container")
	assertCheckFailed(t, report, "strong.controlled_runtime_mode")
	assertCheckFailed(t, report, "strong.network_boundary_controlled")
	assertCheckFailed(t, report, "strong.gateway_mtls")
	assertCheckFailed(t, report, "strong.workload_identity")
	assertCheckFailed(t, report, "strong.no_shared_api_keys")
	assertCheckFailed(t, report, "strong.audit_durable")
}

func TestRunStrongGuaranteeRemoteDevNotReady(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["prod"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	oidcKeyPath := filepath.Join(dir, "oidc.pub.pem")
	if err := os.WriteFile(oidcKeyPath, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("write oidc key: %v", err)
	}
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	clientCAPath := filepath.Join(dir, "client-ca.pem")
	for _, path := range []string{certPath, keyPath, clientCAPath} {
		if err := os.WriteFile(path, []byte("placeholder"), 0o600); err != nil {
			t.Fatalf("write tls placeholder %s: %v", path, err)
		}
	}
	configPath := filepath.Join(dir, "config.json")
	writeStrongConfigForMode(t, configPath, bundlePath, dir, certPath, keyPath, clientCAPath, oidcKeyPath, "remote_dev")

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.OverallStatus != "NOT_READY" {
		t.Fatalf("expected NOT_READY, got %s", report.OverallStatus)
	}
	assertCheckFailed(t, report, "strong.controlled_runtime_mode")
	assertCheckFailed(t, report, "strong.network_boundary_controlled")
}

func TestRunStrongGuaranteeReady(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["prod"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	oidcKeyPath := filepath.Join(dir, "oidc.pub.pem")
	const oidcKey = "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAM39o9wQ8jKXu95syEHCqB6f+GO6zkRg\npmjQe7YQDdyCjTiMQuuLHfoalGoVYLRNvKcJsteVEh9UpAJZciV06P8CAwEAAQ==\n-----END PUBLIC KEY-----\n"
	if err := os.WriteFile(oidcKeyPath, []byte(oidcKey), 0o600); err != nil {
		t.Fatalf("write oidc key: %v", err)
	}
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	clientCAPath := filepath.Join(dir, "client-ca.pem")
	for _, path := range []string{certPath, keyPath, clientCAPath} {
		if err := os.WriteFile(path, []byte("placeholder"), 0o600); err != nil {
			t.Fatalf("write tls placeholder %s: %v", path, err)
		}
	}
	configPath := filepath.Join(dir, "config.json")
	writeStrongConfig(t, configPath, bundlePath, dir, certPath, keyPath, clientCAPath, oidcKeyPath)

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.OverallStatus != "READY" {
		t.Fatalf("expected READY, got %s", report.OverallStatus)
	}
}

func TestRunStrongGuaranteeRejectsSharedAPIKeys(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["prod"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	oidcKeyPath := filepath.Join(dir, "oidc.pub.pem")
	if err := os.WriteFile(oidcKeyPath, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("write oidc key: %v", err)
	}
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	clientCAPath := filepath.Join(dir, "client-ca.pem")
	for _, path := range []string{certPath, keyPath, clientCAPath} {
		if err := os.WriteFile(path, []byte("placeholder"), 0o600); err != nil {
			t.Fatalf("write tls placeholder %s: %v", path, err)
		}
	}
	configPath := filepath.Join(dir, "config.json")
	writeStrongConfig(t, configPath, bundlePath, dir, certPath, keyPath, clientCAPath, oidcKeyPath)
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	identityCfg, ok := cfg["identity"].(map[string]any)
	if !ok {
		t.Fatal("missing identity config")
	}
	identityCfg["api_keys"] = map[string]any{"prod-api-key": "system"}
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.OverallStatus != "NOT_READY" {
		t.Fatalf("expected NOT_READY, got %s", report.OverallStatus)
	}
	assertCheckFailed(t, report, "strong.no_shared_api_keys")
}

func TestM17ReferenceArtifactsExist(t *testing.T) {
	required := []string{
		filepath.Join("docs", "reference-architecture.md"),
		filepath.Join("docs", "strong-guarantee-deployment.md"),
		filepath.Join("docs", "egress-and-identity.md"),
		filepath.Join("deploy", "ci", "github-actions-hardened.yml"),
		filepath.Join("deploy", "k8s", "networkpolicy.yaml"),
		filepath.Join("deploy", "k8s", "serviceaccount.yaml"),
		filepath.Join("deploy", "k8s", "strong-guarantee.yaml"),
	}
	for _, path := range required {
		if _, err := os.Stat(filepath.Clean(filepath.Join("..", "..", path))); err != nil {
			t.Fatalf("expected reference artifact %s: %v", path, err)
		}
	}
}

func writeConfig(t *testing.T, path, bundlePath string, mcpEnabled bool, workspaceRoot string, strongGuarantee bool) {
	t.Helper()
	cfg := map[string]any{
		"gateway": map[string]any{
			"listen":    ":8080",
			"transport": "http",
		},
		"runtime": map[string]any{
			"stateless_mode":   false,
			"strong_guarantee": strongGuarantee,
		},
		"policy": map[string]any{
			"policy_bundle_path": bundlePath,
		},
		"executor": map[string]any{
			"sandbox_enabled": false,
			"workspace_root":  workspaceRoot,
		},
		"credentials": map[string]any{"enabled": false, "secrets": []any{}},
		"audit":       map[string]any{"sink": "stdout"},
		"mcp":         map[string]any{"enabled": mcpEnabled},
		"upstream":    map[string]any{"routes": []any{}},
		"approvals":   map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":       "system",
			"agent":           "nomos",
			"environment":     "dev",
			"api_keys":        map[string]any{"dev-api-key": "system"},
			"service_secrets": map[string]any{},
			"agent_secrets":   map[string]any{"nomos": "dev-agent-secret"},
			"oidc":            map[string]any{"enabled": false, "issuer": "", "audience": "", "public_key_path": ""},
		},
		"redaction": map[string]any{"patterns": []any{}},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func writeStrongConfig(t *testing.T, path, bundlePath, workspaceRoot, certPath, keyPath, clientCAPath, oidcKeyPath string) {
	writeStrongConfigForMode(t, path, bundlePath, workspaceRoot, certPath, keyPath, clientCAPath, oidcKeyPath, "k8s")
}

func writeStrongConfigForMode(t *testing.T, path, bundlePath, workspaceRoot, certPath, keyPath, clientCAPath, oidcKeyPath, deploymentMode string) {
	t.Helper()
	cfg := map[string]any{
		"gateway": map[string]any{
			"listen":    ":8080",
			"transport": "http",
			"tls": map[string]any{
				"enabled":        true,
				"cert_file":      certPath,
				"key_file":       keyPath,
				"client_ca_file": clientCAPath,
				"require_mtls":   true,
			},
		},
		"runtime": map[string]any{
			"stateless_mode":   false,
			"strong_guarantee": true,
			"deployment_mode":  deploymentMode,
		},
		"policy": map[string]any{
			"policy_bundle_path": bundlePath,
		},
		"executor": map[string]any{
			"sandbox_enabled": true,
			"sandbox_profile": "container",
			"workspace_root":  workspaceRoot,
		},
		"credentials": map[string]any{"enabled": false, "secrets": []any{}},
		"audit":       map[string]any{"sink": "sqlite:" + filepath.Join(workspaceRoot, "audit.db")},
		"mcp":         map[string]any{"enabled": true},
		"upstream":    map[string]any{"routes": []any{}},
		"approvals":   map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":       "system",
			"agent":           "nomos",
			"environment":     "prod",
			"api_keys":        map[string]any{},
			"service_secrets": map[string]any{},
			"agent_secrets":   map[string]any{"nomos": "prod-agent-secret"},
			"oidc": map[string]any{
				"enabled":         true,
				"issuer":          "https://issuer.example",
				"audience":        "nomos",
				"public_key_path": oidcKeyPath,
			},
		},
		"redaction": map[string]any{"patterns": []any{}},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func assertCheckFailed(t *testing.T, report Report, id string) {
	t.Helper()
	for _, check := range report.Checks {
		if check.ID == id {
			if check.Status != "FAIL" {
				t.Fatalf("expected %s to fail, got %s", id, check.Status)
			}
			return
		}
	}
	t.Fatalf("missing check %s", id)
}
