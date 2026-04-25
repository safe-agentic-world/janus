package doctor

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/opabridge"
	"github.com/safe-agentic-world/nomos/internal/policy"
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

func TestRunWarnsOnEmptyEnvWithRelativeUpstreamCommand(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	cfg := map[string]any{
		"gateway":     map[string]any{"listen": ":8080", "transport": "http"},
		"runtime":     map[string]any{"stateless_mode": false, "strong_guarantee": false, "deployment_mode": "unmanaged"},
		"policy":      map[string]any{"policy_bundle_path": bundlePath},
		"executor":    map[string]any{"sandbox_enabled": false, "workspace_root": dir},
		"credentials": map[string]any{"enabled": false, "secrets": []any{}},
		"audit":       map[string]any{"sink": "stdout"},
		"mcp": map[string]any{
			"enabled": true,
			"upstream_servers": []any{
				map[string]any{
					"name":      "retail",
					"transport": "stdio",
					"command":   "python",
					"args":      []any{"server.py"},
				},
			},
		},
		"upstream":  map[string]any{"routes": []any{}},
		"approvals": map[string]any{"enabled": false},
		"identity": map[string]any{
			"principal":     "system",
			"agent":         "nomos",
			"environment":   "dev",
			"api_keys":      map[string]any{"dev-api-key": "system"},
			"agent_secrets": map[string]any{"nomos": "dev-agent-secret"},
			"oidc":          map[string]any{"enabled": false, "issuer": "", "audience": "", "public_key_path": ""},
		},
		"redaction": map[string]any{"patterns": []any{}},
	}
	data, err := json.Marshal(cfg)
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
	if report.OverallStatus != "READY" {
		t.Fatalf("expected READY, got %s", report.OverallStatus)
	}
	for _, check := range report.Checks {
		if check.ID == "mcp.upstream_env_isolation.retail" {
			if check.Status != "WARN" {
				t.Fatalf("expected WARN env isolation check, got %+v", check)
			}
			if !strings.Contains(check.Message, "empty env") {
				t.Fatalf("expected env isolation warning message, got %+v", check)
			}
			return
		}
	}
	t.Fatal("missing env isolation warning check")
}

func TestRunMultiBundleReportsMergedSources(t *testing.T) {
	dir := t.TempDir()
	baseBundlePath := filepath.Join(dir, "base.json")
	repoBundlePath := filepath.Join(dir, "repo.json")
	if err := os.WriteFile(baseBundlePath, []byte(`{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write base bundle: %v", err)
	}
	if err := os.WriteFile(repoBundlePath, []byte(`{"version":"v1","rules":[{"id":"deny-env","action_type":"fs.read","resource":"file://workspace/.env","decision":"DENY","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write repo bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	cfg := map[string]any{
		"gateway":     map[string]any{"listen": ":8080", "transport": "http"},
		"runtime":     map[string]any{"stateless_mode": false, "strong_guarantee": false},
		"policy":      map[string]any{"policy_bundle_paths": []any{baseBundlePath, repoBundlePath}},
		"executor":    map[string]any{"sandbox_enabled": false, "workspace_root": dir},
		"credentials": map[string]any{"enabled": false, "secrets": []any{}},
		"audit":       map[string]any{"sink": "stdout"},
		"mcp":         map[string]any{"enabled": true},
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
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.OverallStatus != "READY" {
		t.Fatalf("expected READY, got %s", report.OverallStatus)
	}
	if len(report.PolicyBundleSources) != 2 {
		t.Fatalf("expected 2 policy bundle sources, got %+v", report.PolicyBundleSources)
	}
	if len(report.PolicyBundleInputs) != 2 {
		t.Fatalf("expected 2 policy bundle inputs, got %+v", report.PolicyBundleInputs)
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
	for _, check := range report.Checks {
		if check.ID == "policy.bundle_parses" {
			if !strings.Contains(check.Hint, bundlePath) {
				t.Fatalf("expected malformed bundle hint to include failing bundle path, got %q", check.Hint)
			}
			return
		}
	}
	t.Fatal("missing policy.bundle_parses check")
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

func TestRunOPAEnabledEvaluatorUnavailableNotReady(t *testing.T) {
	restore := stubOPAChecks(
		func(opabridge.CommandConfig) (opabridge.Evaluator, error) {
			return nil, errors.New("opa binary not found")
		},
		nil,
	)
	defer restore()

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	regoPath := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(regoPath, []byte(`package nomos`), 0o600); err != nil {
		t.Fatalf("write rego: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	writeConfigWithOPA(t, configPath, bundlePath, dir, regoPath)

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.OverallStatus != "NOT_READY" {
		t.Fatalf("expected NOT_READY, got %s", report.OverallStatus)
	}
	assertCheckFailed(t, report, "policy.opa_evaluator_ready")
	assertCheckFailed(t, report, "policy.opa_probe_evaluates")
}

func TestRunOPAEnabledProbeFailureNotReady(t *testing.T) {
	restore := stubOPAChecks(
		func(opabridge.CommandConfig) (opabridge.Evaluator, error) {
			return fakeOPAEvaluator{}, nil
		},
		func(normalize.NormalizedAction, opabridge.Evaluator) (policy.Decision, error) {
			return policy.Decision{}, errors.New("opa evaluator unavailable")
		},
	)
	defer restore()

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	regoPath := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(regoPath, []byte(`package nomos`), 0o600); err != nil {
		t.Fatalf("write rego: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	writeConfigWithOPA(t, configPath, bundlePath, dir, regoPath)

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.OverallStatus != "NOT_READY" {
		t.Fatalf("expected NOT_READY, got %s", report.OverallStatus)
	}
	assertCheckPassed(t, report, "policy.opa_evaluator_ready")
	assertCheckFailed(t, report, "policy.opa_probe_evaluates")
}

func TestRunOPAEnabledProbeSuccessReady(t *testing.T) {
	restore := stubOPAChecks(
		func(opabridge.CommandConfig) (opabridge.Evaluator, error) {
			return fakeOPAEvaluator{}, nil
		},
		func(normalize.NormalizedAction, opabridge.Evaluator) (policy.Decision, error) {
			return policy.Decision{
				Decision: policy.DecisionAllow,
			}, nil
		},
	)
	defer restore()

	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	regoPath := filepath.Join(dir, "policy.rego")
	if err := os.WriteFile(regoPath, []byte(`package nomos`), 0o600); err != nil {
		t.Fatalf("write rego: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	writeConfigWithOPA(t, configPath, bundlePath, dir, regoPath)

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.OverallStatus != "READY" {
		t.Fatalf("expected READY, got %s", report.OverallStatus)
	}
	assertCheckPassed(t, report, "policy.opa_evaluator_ready")
	assertCheckPassed(t, report, "policy.opa_probe_evaluates")
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
	if report.AssuranceLevel != "STRONG" {
		t.Fatalf("expected STRONG assurance, got %s", report.AssuranceLevel)
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

func TestRunStrongGuaranteeMissingRuntimeEvidenceDegradesAssurance(t *testing.T) {
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
	writeStrongConfigWithoutEvidence(t, configPath, bundlePath, dir, certPath, keyPath, clientCAPath, oidcKeyPath)

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.AssuranceLevel != "GUARDED" {
		t.Fatalf("expected GUARDED assurance when runtime evidence missing, got %s", report.AssuranceLevel)
	}
	assertCheckFailed(t, report, "strong.assurance_evidence_backed")
	assertCheckFailed(t, report, "evidence.runtime.container_backend_ready")
}

func TestRunStrongGuaranteeSPIFFEIdentityEvidenceCanSatisfyIdentityRequirement(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["prod"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
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
	writeStrongSPIFFEConfig(t, configPath, bundlePath, dir, certPath, keyPath, clientCAPath)

	report, err := Run(Options{ConfigPath: configPath, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("doctor run: %v", err)
	}
	if report.AssuranceLevel != "STRONG" {
		t.Fatalf("expected STRONG assurance with SPIFFE evidence, got %s", report.AssuranceLevel)
	}
	assertCheckPassed(t, report, "strong.workload_identity")
	assertCheckPassed(t, report, "evidence.identity.workload_identity_verified")
}

func TestM17ReferenceArtifactsExist(t *testing.T) {
	required := []string{
		filepath.Join("docs", "reference-architecture.md"),
		filepath.Join("docs", "strong-guarantee-deployment.md"),
		filepath.Join("docs", "egress-and-identity.md"),
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

func writeConfigWithOPA(t *testing.T, path, bundlePath, workspaceRoot, policyPath string) {
	t.Helper()
	cfg := map[string]any{
		"gateway": map[string]any{
			"listen":    ":8080",
			"transport": "http",
		},
		"runtime": map[string]any{
			"stateless_mode":   false,
			"strong_guarantee": false,
			"deployment_mode":  "unmanaged",
		},
		"policy": map[string]any{
			"policy_bundle_path": bundlePath,
			"opa": map[string]any{
				"enabled":     true,
				"binary_path": "opa",
				"policy_path": policyPath,
				"query":       "data.nomos.decision",
				"timeout_ms":  2000,
			},
		},
		"executor": map[string]any{
			"sandbox_enabled": false,
			"workspace_root":  workspaceRoot,
		},
		"credentials": map[string]any{"enabled": false, "secrets": []any{}},
		"audit":       map[string]any{"sink": "stdout"},
		"mcp":         map[string]any{"enabled": true},
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
			"evidence": map[string]any{
				"container_backend_ready":    true,
				"rootless_or_non_privileged": true,
				"read_only_fs":               true,
				"no_new_privileges":          true,
				"network_default_deny":       true,
				"workload_identity_verified": true,
				"durable_audit_verified":     true,
			},
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

func writeStrongConfigWithoutEvidence(t *testing.T, path, bundlePath, workspaceRoot, certPath, keyPath, clientCAPath, oidcKeyPath string) {
	t.Helper()
	writeStrongConfigForMode(t, path, bundlePath, workspaceRoot, certPath, keyPath, clientCAPath, oidcKeyPath, "k8s")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	runtimeCfg := cfg["runtime"].(map[string]any)
	runtimeCfg["evidence"] = map[string]any{}
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func writeStrongSPIFFEConfig(t *testing.T, path, bundlePath, workspaceRoot, certPath, keyPath, clientCAPath string) {
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
			"deployment_mode":  "k8s",
			"evidence": map[string]any{
				"container_backend_ready":    true,
				"rootless_or_non_privileged": true,
				"read_only_fs":               true,
				"no_new_privileges":          true,
				"network_default_deny":       true,
				"workload_identity_verified": true,
				"durable_audit_verified":     true,
			},
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
			"spiffe": map[string]any{
				"enabled":      true,
				"trust_domain": "example.org",
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

func assertCheckPassed(t *testing.T, report Report, id string) {
	t.Helper()
	for _, check := range report.Checks {
		if check.ID == id {
			if check.Status != "PASS" {
				t.Fatalf("expected %s to pass, got %s", id, check.Status)
			}
			return
		}
	}
	t.Fatalf("missing check %s", id)
}

type fakeOPAEvaluator struct{}

func (fakeOPAEvaluator) Evaluate([]byte) ([]byte, error) {
	return []byte(`{"decision":"ALLOW"}`), nil
}

func stubOPAChecks(
	newEvaluator func(opabridge.CommandConfig) (opabridge.Evaluator, error),
	eval func(normalize.NormalizedAction, opabridge.Evaluator) (policy.Decision, error),
) func() {
	prevNew := newOPACommandEvaluator
	prevEval := evaluateOPA
	newOPACommandEvaluator = newEvaluator
	if eval != nil {
		evaluateOPA = eval
	}
	return func() {
		newOPACommandEvaluator = prevNew
		evaluateOPA = prevEval
	}
}
