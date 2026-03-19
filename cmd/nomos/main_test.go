package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/assurance"
	"github.com/safe-agentic-world/nomos/internal/doctor"
	"github.com/safe-agentic-world/nomos/internal/gateway"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/version"
)

func TestResolveMCPInvocationFlagPrecedenceOverEnv(t *testing.T) {
	dir := t.TempDir()
	flagConfig := filepath.Join(dir, "flag-config.json")
	flagBundle := filepath.Join(dir, "flag-bundle.json")
	got, err := resolveMCPInvocation(flagConfig, flagBundle, "warn", true, func(string) string {
		return "ignored"
	})
	if err != nil {
		t.Fatalf("resolve mcp: %v", err)
	}
	if got.LogLevel != "warn" || got.LogLevelSource != "flag" {
		t.Fatalf("expected flag log level precedence, got %+v", got)
	}
	if !strings.HasSuffix(got.ConfigPath, "flag-config.json") || !strings.HasSuffix(got.PolicyBundle, "flag-bundle.json") {
		t.Fatalf("expected flag paths, got %+v", got)
	}
	if !got.Quiet {
		t.Fatal("expected quiet=true")
	}
}

func TestResolveMCPInvocationEnvFallback(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{
		"NOMOS_CONFIG":        filepath.Join(dir, "env-config.json"),
		"NOMOS_POLICY_BUNDLE": filepath.Join(dir, "env-bundle.json"),
		"NOMOS_LOG_LEVEL":     "debug",
	}
	got, err := resolveMCPInvocation("", "", "", false, func(key string) string {
		return env[key]
	})
	if err != nil {
		t.Fatalf("resolve mcp: %v", err)
	}
	if got.LogLevel != "debug" || got.LogLevelSource != "env" {
		t.Fatalf("expected env log level fallback, got %+v", got)
	}
	if !strings.HasSuffix(got.ConfigPath, "env-config.json") || !strings.HasSuffix(got.PolicyBundle, "env-bundle.json") {
		t.Fatalf("expected env paths, got %+v", got)
	}
}

func TestResolveMCPInvocationRequiresConfig(t *testing.T) {
	_, err := resolveMCPInvocation("", "", "", false, func(string) string { return "" })
	if err == nil {
		t.Fatal("expected missing config error")
	}
	if !strings.Contains(err.Error(), "--config/-c") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfigFailsClosedWithoutBundle(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	data := `{
  "gateway":{"listen":":8080","transport":"http"},
  "runtime":{"stateless_mode":false},
  "policy":{"policy_bundle_path":""},
  "executor":{"sandbox_enabled":false,"workspace_root":"` + filepath.ToSlash(dir) + `"},
  "credentials":{"enabled":false,"secrets":[]},
  "audit":{"sink":"stdout"},
  "mcp":{"enabled":true},
  "upstream":{"routes":[]},
  "approvals":{"enabled":false},
  "identity":{
    "principal":"system",
    "agent":"nomos",
    "environment":"dev",
    "api_keys":{"dev-api-key":"system"},
    "service_secrets":{},
    "agent_secrets":{"nomos":"dev-agent-secret"},
    "oidc":{"enabled":false,"issuer":"","audience":"","public_key_path":""}
  },
  "redaction":{"patterns":[]}
}`
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := gateway.LoadConfig(configPath, func(string) string { return "" }, "")
	if err == nil {
		t.Fatal("expected fail-closed config error")
	}
	if !strings.Contains(err.Error(), "policy.policy_bundle_path or policy.policy_bundle_paths is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHelpTextStability(t *testing.T) {
	root := rootHelpText()
	mcp := mcpHelpText()
	if !strings.Contains(root, "nomos mcp -c ./examples/configs/config.example.json -p ./examples/policies/your-policy-bundle.json") {
		t.Fatalf("unexpected root help: %q", root)
	}
	if !strings.Contains(root, "doctor") {
		t.Fatalf("expected doctor command in root help: %q", root)
	}
	if !strings.Contains(mcp, "-c, --config") || !strings.Contains(mcp, "-p, --policy-bundle") || !strings.Contains(mcp, "-l, --log-level") || !strings.Contains(mcp, "-q, --quiet") {
		t.Fatalf("missing short/long flags in mcp help: %q", mcp)
	}
}

func TestVersionOutputIncludesExpectedFields(t *testing.T) {
	out := versionOutput()
	for _, want := range []string{"version=", "go="} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected version output to contain %q, got %q", want, out)
		}
	}
}

func TestProtocolSafeMCPSinkRewritesStdoutToStderr(t *testing.T) {
	got := protocolSafeMCPSink("stdout, sqlite:test.db , webhook:https://example.com/audit")
	want := "stderr,sqlite:test.db,webhook:https://example.com/audit"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestProtocolSafeMCPSinkDefaultsToStderr(t *testing.T) {
	if got := protocolSafeMCPSink(""); got != "stderr" {
		t.Fatalf("expected stderr default, got %q", got)
	}
}

func TestMCPSinkRewriteDetection(t *testing.T) {
	if !mcpSinkRewritesStdout("stdout,sqlite:test.db") {
		t.Fatal("expected stdout sink rewrite detection")
	}
	if mcpSinkRewritesStdout("") {
		t.Fatal("did not expect empty sink to trigger stdout rewrite detection")
	}
	if mcpSinkRewritesStdout("stderr,sqlite:test.db") {
		t.Fatal("did not expect stderr-only sink to trigger stdout rewrite detection")
	}
}

func TestDecorateDoctorSummaryPlainForNonTerminalWriters(t *testing.T) {
	report := doctor.Report{
		OverallStatus: "READY",
		Checks: []doctor.Check{
			{ID: "config.load", Status: "PASS", Message: "config loaded"},
		},
	}
	got := decorateDoctorSummary(&bytes.Buffer{}, report)
	if strings.Contains(got, "\x1b[") {
		t.Fatalf("expected no ansi escapes for non-terminal writer, got %q", got)
	}
	if !strings.Contains(got, "Nomos Doctor Report") || !strings.Contains(got, "[PASS]") || !strings.Contains(got, "Result: READY") {
		t.Fatalf("expected stable human summary, got %q", got)
	}
}

func TestDecorateHelpTextPlainForNonTerminalWriters(t *testing.T) {
	input := "usage: nomos mcp [flags]\n  -c, --config <path>          config json path\n\nexample:\n  nomos mcp -c ./examples/configs/config.example.json\n"
	got := decorateHelpText(&bytes.Buffer{}, input)
	if got != input {
		t.Fatalf("expected help text to stay unchanged for non-terminal writer\nwant=%q\ngot=%q", input, got)
	}
}

func TestDocumentedArtifactsExist(t *testing.T) {
	required := []string{
		filepath.Join("..", "..", "docs", "obligations.md"),
		filepath.Join("..", "..", "docs", "policy-explain.md"),
		filepath.Join("..", "..", "examples", "policies", "safe.json"),
		filepath.Join("..", "..", "examples", "policies", "safe.yaml"),
		filepath.Join("..", "..", "examples", "policies", "all-fields.example.json"),
		filepath.Join("..", "..", "examples", "policies", "all-fields.example.yaml"),
		filepath.Join("..", "..", "examples", "policies", "local-override.yaml"),
		filepath.Join("..", "..", "examples", "configs", "config.layered.example.json"),
		filepath.Join("..", "..", "examples", "configs", "config.layered.local-override.example.json"),
	}
	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}
}

func TestPolicyCommandsSupportYAMLBundles(t *testing.T) {
	dir := t.TempDir()
	actionPath := filepath.Join(dir, "action.json")
	actionBody := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"principal":"system","agent":"nomos","environment":"dev","trace_id":"trace1","context":{"extensions":{}}}`
	if err := os.WriteFile(actionPath, []byte(actionBody), 0o600); err != nil {
		t.Fatalf("write action: %v", err)
	}
	bundlePath := filepath.Clean(filepath.Join("..", "..", "examples", "policies", "safe.yaml"))
	var testOut bytes.Buffer
	testSummary, err := executePolicyTest([]string{"--action", actionPath, "--bundle", bundlePath}, &testOut)
	if err != nil {
		t.Fatalf("execute policy test: %v", err)
	}
	var explainOut bytes.Buffer
	explainSummary, err := executePolicyExplain([]string{"--action", actionPath, "--bundle", bundlePath}, &explainOut, func(string) string { return "" })
	if err != nil {
		t.Fatalf("execute policy explain: %v", err)
	}

	if !bytes.Contains(testOut.Bytes(), []byte(`"decision":"ALLOW"`)) {
		t.Fatalf("expected policy test output to allow, got %s", testOut.String())
	}
	if !bytes.Contains(explainOut.Bytes(), []byte(`"decision": "ALLOW"`)) {
		t.Fatalf("expected policy explain output to allow, got %s", explainOut.String())
	}
	if testSummary.Decision != "ALLOW" || testSummary.MatchedRuleCount == 0 || testSummary.PolicyBundleHash == "" {
		t.Fatalf("unexpected policy test summary: %+v", testSummary)
	}
	if explainSummary.Decision != "ALLOW" || explainSummary.MatchedRuleCount == 0 || explainSummary.AssuranceLevel == "" {
		t.Fatalf("unexpected policy explain summary: %+v", explainSummary)
	}
}

func TestPolicyCommandErrorClassification(t *testing.T) {
	dir := t.TempDir()
	validActionPath := filepath.Join(dir, "valid-action.json")
	validAction := `{"schema_version":"v1","action_id":"act1","action_type":"fs.read","resource":"file://workspace/README.md","params":{},"principal":"system","agent":"nomos","environment":"dev","trace_id":"trace1","context":{"extensions":{}}}`
	if err := os.WriteFile(validActionPath, []byte(validAction), 0o600); err != nil {
		t.Fatalf("write valid action: %v", err)
	}
	invalidActionPath := filepath.Join(dir, "invalid-action.json")
	invalidAction := `{"schema_version":"v1","action_id":"act2","action_type":"fs.read","resource":"not-a-uri","params":{},"principal":"system","agent":"nomos","environment":"dev","trace_id":"trace2","context":{"extensions":{}}}`
	if err := os.WriteFile(invalidActionPath, []byte(invalidAction), 0o600); err != nil {
		t.Fatalf("write invalid action: %v", err)
	}
	unknownTopLevelPath := filepath.Join(dir, "unknown-top.yaml")
	unknownTopLevel := "version: v1\nrules: []\nextra: true\n"
	if err := os.WriteFile(unknownTopLevelPath, []byte(unknownTopLevel), 0o600); err != nil {
		t.Fatalf("write unknown top-level bundle: %v", err)
	}
	unknownNestedPath := filepath.Join(dir, "unknown-nested.yaml")
	unknownNested := "version: v1\nrules:\n  - id: safe-read-workspace\n    action_type: fs.read\n    resource: file://workspace/**\n    decision: ALLOW\n    principals: [system]\n    agents: [nomos]\n    environments: [dev]\n    extra_nested: true\n"
	if err := os.WriteFile(unknownNestedPath, []byte(unknownNested), 0o600); err != nil {
		t.Fatalf("write unknown nested bundle: %v", err)
	}
	validBundlePath := filepath.Clean(filepath.Join("..", "..", "examples", "policies", "safe.yaml"))

	_, err := executePolicyTest([]string{"--action", validActionPath, "--bundle", unknownTopLevelPath}, &bytes.Buffer{})
	if code := policyErrorCode(err); code != policyResultValidationError {
		t.Fatalf("expected top-level unknown field to classify as %s, got %q err=%v", policyResultValidationError, code, err)
	}
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "field") {
		t.Fatalf("expected field error for top-level unknown field, got %v", err)
	}

	_, err = executePolicyTest([]string{"--action", validActionPath, "--bundle", unknownNestedPath}, &bytes.Buffer{})
	if code := policyErrorCode(err); code != policyResultValidationError {
		t.Fatalf("expected nested unknown field to classify as %s, got %q err=%v", policyResultValidationError, code, err)
	}
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "field") {
		t.Fatalf("expected field error for nested unknown field, got %v", err)
	}

	_, err = executePolicyTest([]string{"--action", invalidActionPath, "--bundle", validBundlePath}, &bytes.Buffer{})
	if code := policyErrorCode(err); code != policyResultNormError {
		t.Fatalf("expected invalid resource to classify as %s, got %q err=%v", policyResultNormError, code, err)
	}
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "normalize action") {
		t.Fatalf("expected normalize action error, got %v", err)
	}
}

func TestDoctorExitCodesAndJSONDeterminism(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	writeDoctorTestConfig(t, configPath, bundlePath, true, dir)

	var out1, err1 bytes.Buffer
	code1 := runDoctorCommand([]string{"-c", configPath, "--format", "json"}, &out1, &err1, func(string) string { return "" })
	if code1 != 0 {
		t.Fatalf("expected READY exit code 0, got %d stderr=%q", code1, err1.String())
	}
	var out2, err2 bytes.Buffer
	code2 := runDoctorCommand([]string{"--config", configPath, "--format", "json"}, &out2, &err2, func(string) string { return "" })
	if code2 != 0 {
		t.Fatalf("expected READY exit code 0, got %d stderr=%q", code2, err2.String())
	}
	if out1.String() != out2.String() {
		t.Fatalf("expected deterministic json output\n1=%s\n2=%s", out1.String(), out2.String())
	}

	var parsed map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out1.Bytes()), &parsed); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	if parsed["overall_status"] != "READY" {
		t.Fatalf("expected READY, got %v", parsed["overall_status"])
	}
	if _, ok := parsed["engine_version"]; !ok {
		t.Fatal("expected engine_version in json output")
	}
	if !strings.Contains(err1.String(), "doctor completed: status=READY") {
		t.Fatalf("expected READY completion summary on stderr, got %q", err1.String())
	}
}

func TestDoctorNotReadyExitCode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	writeDoctorTestConfig(t, configPath, filepath.Join(dir, "missing.json"), true, dir)
	var out, errOut bytes.Buffer
	code := runDoctorCommand([]string{"-c", configPath}, &out, &errOut, func(string) string { return "" })
	if code != 1 {
		t.Fatalf("expected NOT_READY exit code 1, got %d", code)
	}
	if !strings.Contains(out.String(), "Result: NOT_READY") {
		t.Fatalf("expected NOT_READY summary, got: %q", out.String())
	}
	if !strings.Contains(errOut.String(), "doctor completed: status=NOT_READY") {
		t.Fatalf("expected NOT_READY completion summary on stderr, got %q", errOut.String())
	}
}

func TestDoctorInvalidFormatInternalErrorCode(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	writeDoctorTestConfig(t, configPath, bundlePath, true, dir)
	var out, errOut bytes.Buffer
	code := runDoctorCommand([]string{"-c", configPath, "--format", "yaml"}, &out, &errOut, func(string) string { return "" })
	if code != 2 {
		t.Fatalf("expected internal error exit code 2, got %d", code)
	}
}

func TestWriteRedactedLine(t *testing.T) {
	var out bytes.Buffer
	writeRedactedLine(&out, "authorization: Bearer abc.def.ghi")
	got := out.String()
	if strings.Contains(strings.ToLower(got), "authorization:") || strings.Contains(got, "abc.def.ghi") {
		t.Fatalf("expected redacted output, got: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected redaction marker, got: %q", got)
	}
}

func TestDeriveExplainAssuranceFromConfigAndPayload(t *testing.T) {
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
	for _, p := range []string{certPath, keyPath, clientCAPath} {
		if err := os.WriteFile(p, []byte("placeholder"), 0o600); err != nil {
			t.Fatalf("write tls placeholder: %v", err)
		}
	}
	configPath := filepath.Join(dir, "config.json")
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
		"policy": map[string]any{"policy_bundle_path": bundlePath},
		"executor": map[string]any{
			"sandbox_enabled": true,
			"sandbox_profile": "container",
			"workspace_root":  dir,
		},
		"credentials": map[string]any{"enabled": false, "secrets": []any{}},
		"audit":       map[string]any{"sink": "sqlite:" + filepath.Join(dir, "audit.db")},
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
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	level, err := deriveExplainAssurance(configPath, bundlePath, func(string) string { return "" })
	if err != nil {
		t.Fatalf("derive assurance: %v", err)
	}
	if level != assurance.LevelStrong {
		t.Fatalf("expected STRONG, got %s", level)
	}
	payload := buildPolicyExplainPayload(policy.ExplainDetails{
		Decision: policy.Decision{
			Decision:         policy.DecisionAllow,
			ReasonCode:       "allow_by_rule",
			MatchedRuleIDs:   []string{"r1"},
			PolicyBundleHash: "hash",
		},
		ObligationsPreview: map[string]any{},
	}, normalize.NormalizedAction{
		ActionType: "fs.read",
		Resource:   "file://workspace/README.md",
	}, explainSettings{
		AssuranceLevel:     level,
		SuggestRemediation: true,
	})
	if payload["assurance_level"] != assurance.LevelStrong {
		t.Fatalf("expected assurance_level in payload, got %+v", payload)
	}
}

func TestDeriveExplainAssuranceDefaultsToUnmanagedWithoutConfig(t *testing.T) {
	level, err := deriveExplainAssurance("", "", func(string) string { return "" })
	if err != nil {
		t.Fatalf("derive assurance: %v", err)
	}
	if level != assurance.LevelBestEffort {
		t.Fatalf("expected BEST_EFFORT, got %s", level)
	}
}

func TestPolicyExplainGoldenStability(t *testing.T) {
	payload := buildPolicyExplainPayload(policy.ExplainDetails{
		Decision: policy.Decision{
			Decision:         policy.DecisionDeny,
			ReasonCode:       "deny_by_default",
			MatchedRuleIDs:   []string{},
			PolicyBundleHash: "bundle-hash",
		},
		DenyRules:              []policy.DeniedRuleExplanation{},
		AllowRuleIDs:           []string{},
		RequireApprovalRuleIDs: []string{},
		ObligationsPreview:     map[string]any{},
	}, normalize.NormalizedAction{
		ActionType: "net.http_request",
		Resource:   "url://example.com/path",
	}, explainSettings{
		AssuranceLevel:     assurance.LevelGuarded,
		SuggestRemediation: true,
	})
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	expected := "{\n  \"assurance_level\": \"GUARDED\",\n  \"decision\": \"DENY\",\n  \"engine_version\": \"" + version.Current().Version + "\",\n  \"matched_rule_ids\": [],\n  \"minimal_allowing_change\": \"This host is not currently allowed; use an allowlisted host, request approval, or update the network allowlist for example.com.\",\n  \"obligations_preview\": {},\n  \"policy_bundle_hash\": \"bundle-hash\",\n  \"reason_code\": \"deny_by_default\",\n  \"why_denied\": {\n    \"deny_rules\": [],\n    \"matched_conditions\": {\n      \"matching_allow_rule\": false\n    },\n    \"reason_code\": \"deny_by_default\",\n    \"remediation_hint\": \"This network destination is not currently allowed.\"\n  }\n}"
	if string(data) != expected {
		t.Fatalf("unexpected explain payload\nexpected:\n%s\n\ngot:\n%s", expected, string(data))
	}
}

func TestPolicyExplainPayloadIncludesBundleInputsAndMatchedRuleProvenance(t *testing.T) {
	payload := buildPolicyExplainPayload(policy.ExplainDetails{
		Decision: policy.Decision{
			Decision:         policy.DecisionDeny,
			ReasonCode:       "deny_by_rule",
			MatchedRuleIDs:   []string{"allow-workspace", "deny-env"},
			PolicyBundleHash: "merged-bundle-hash",
			PolicyBundleInputs: []policy.BundleSource{
				{Path: "base.yaml", Hash: "hash-base", Role: "baseline"},
				{Path: "env.yaml", Hash: "hash-env", Role: "env", SignatureVerified: true},
			},
			PolicyBundleSources: []string{"base.yaml#hash-base", "env.yaml#hash-env"},
		},
		MatchedRuleProvenance: []policy.MatchedRuleProvenance{
			{RuleID: "allow-workspace", Decision: policy.DecisionAllow, BundleSource: "base.yaml#hash-base"},
			{RuleID: "deny-env", Decision: policy.DecisionDeny, BundleSource: "env.yaml#hash-env"},
		},
		DenyRules: []policy.DeniedRuleExplanation{
			{RuleID: "deny-env", ReasonCode: "deny_by_rule", MatchedConditions: map[string]bool{"resource": true}, BundleSource: "env.yaml#hash-env"},
		},
		AllowRuleIDs:       []string{"allow-workspace"},
		ObligationsPreview: map[string]any{},
	}, normalize.NormalizedAction{
		ActionType: "fs.read",
		Resource:   "file://workspace/.env",
	}, explainSettings{
		AssuranceLevel:     assurance.LevelGuarded,
		SuggestRemediation: true,
	})

	inputs, ok := payload["policy_bundle_inputs"].([]policy.BundleSource)
	if !ok || len(inputs) != 2 {
		t.Fatalf("expected structured policy_bundle_inputs in explain payload, got %#v", payload["policy_bundle_inputs"])
	}
	provenance, ok := payload["matched_rule_provenance"].([]policy.MatchedRuleProvenance)
	if !ok || len(provenance) != 2 {
		t.Fatalf("expected matched_rule_provenance in explain payload, got %#v", payload["matched_rule_provenance"])
	}
}

func TestPolicyExplainNoSecretLeakInOutput(t *testing.T) {
	payload := buildPolicyExplainPayload(policy.ExplainDetails{
		Decision: policy.Decision{
			Decision:         policy.DecisionDeny,
			ReasonCode:       "deny_by_default",
			MatchedRuleIDs:   []string{},
			PolicyBundleHash: "bundle-hash",
		},
		ObligationsPreview: map[string]any{},
	}, normalize.NormalizedAction{
		ActionType: "net.http_request",
		Resource:   "url://example.com/path",
		Params:     []byte(`{"headers":{"Authorization":"Bearer secret-value-123"}}`),
	}, explainSettings{
		AssuranceLevel:     assurance.LevelBestEffort,
		SuggestRemediation: true,
	})
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	text := string(data)
	if strings.Contains(text, "secret-value-123") || strings.Contains(strings.ToLower(text), "authorization") {
		t.Fatalf("explain output leaked sensitive header data: %s", text)
	}
}

func TestDeriveExplainSettingsCanDisableSuggestion(t *testing.T) {
	settings, err := deriveExplainSettings("", "", func(key string) string {
		switch key {
		case "NOMOS_POLICY_EXPLAIN_SUGGESTIONS":
			return "false"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("derive settings: %v", err)
	}
	if settings.SuggestRemediation {
		t.Fatal("expected remediation suggestions disabled")
	}
}

func TestDeriveExplainSettingsRespectsConfigDisable(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"version":"v1","rules":[{"id":"r1","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	configPath := filepath.Join(dir, "config.json")
	cfg := map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"runtime": map[string]any{"stateless_mode": false},
		"policy": map[string]any{
			"policy_bundle_path":  bundlePath,
			"explain_suggestions": false,
		},
		"executor": map[string]any{
			"sandbox_enabled": false,
			"workspace_root":  dir,
		},
		"credentials": map[string]any{"enabled": false, "secrets": []any{}},
		"audit":       map[string]any{"sink": "stdout"},
		"mcp":         map[string]any{"enabled": false},
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
	settings, err := deriveExplainSettings(configPath, bundlePath, func(string) string { return "" })
	if err != nil {
		t.Fatalf("derive settings: %v", err)
	}
	if settings.SuggestRemediation {
		t.Fatal("expected remediation suggestions disabled by config")
	}
}

func writeDoctorTestConfig(t *testing.T, path, bundlePath string, mcpEnabled bool, workspaceRoot string) {
	t.Helper()
	cfg := map[string]any{
		"gateway": map[string]any{"listen": ":8080", "transport": "http"},
		"runtime": map[string]any{"stateless_mode": false},
		"policy":  map[string]any{"policy_bundle_path": bundlePath},
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
