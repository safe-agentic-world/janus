package policy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/normalize"
)

func TestPolicyAllowAndDeny(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},{"id":"deny-secret","action_type":"fs.read","resource":"file://workspace/**/secret.txt","decision":"DENY","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	bundle, err := LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	engine := NewEngine(bundle)
	allowDecision := engine.Evaluate(normalize.NormalizedAction{
		ActionType:  "fs.read",
		Resource:    "file://workspace/README.md",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if allowDecision.Decision != DecisionAllow {
		t.Fatalf("expected allow, got %s", allowDecision.Decision)
	}
	denyDecision := engine.Evaluate(normalize.NormalizedAction{
		ActionType:  "fs.read",
		Resource:    "file://workspace/foo/secret.txt",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if denyDecision.Decision != DecisionDeny {
		t.Fatalf("expected deny, got %s", denyDecision.Decision)
	}
}

func TestPolicyRequireApproval(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"approve-net","action_type":"net.http_request","resource":"url://example.com/**","decision":"REQUIRE_APPROVAL","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	bundle, err := LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	engine := NewEngine(bundle)
	decision := engine.Evaluate(normalize.NormalizedAction{
		ActionType:  "net.http_request",
		Resource:    "url://example.com/path",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if decision.Decision != DecisionRequireApproval {
		t.Fatalf("expected require_approval, got %s", decision.Decision)
	}
}

func TestPolicyMatchesPrincipalsAndRiskFlags(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"allow-net","action_type":"net.http_request","resource":"url://example.com/**","decision":"ALLOW","principals":["svc1"],"agents":["nomos"],"environments":["prod"],"risk_flags":["risk.net"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	bundle, err := LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	engine := NewEngine(bundle)
	decision := engine.Evaluate(normalize.NormalizedAction{
		ActionType:  "net.http_request",
		Resource:    "url://example.com/path",
		Principal:   "svc1",
		Agent:       "nomos",
		Environment: "prod",
		Params:      []byte(`{}`),
	})
	if decision.Decision != DecisionAllow {
		t.Fatalf("expected allow, got %s", decision.Decision)
	}
	denyDecision := engine.Evaluate(normalize.NormalizedAction{
		ActionType:  "net.http_request",
		Resource:    "url://example.com/path",
		Principal:   "svc2",
		Agent:       "nomos",
		Environment: "prod",
		Params:      []byte(`{}`),
	})
	if denyDecision.Decision != DecisionDeny {
		t.Fatalf("expected deny, got %s", denyDecision.Decision)
	}
}

func TestPolicyBundleHashIncluded(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"allow-readme","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	bundle, err := LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("load bundle: %v", err)
	}
	engine := NewEngine(bundle)
	decision := engine.Evaluate(normalize.NormalizedAction{
		ActionType:  "fs.read",
		Resource:    "file://workspace/README.md",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if decision.PolicyBundleHash == "" {
		t.Fatal("expected policy bundle hash")
	}
}

func TestPolicyExplainDenyWinsReportsOnlyDenyRules(t *testing.T) {
	bundle := Bundle{
		Version: "v1",
		Hash:    "bundle-hash",
		Rules: []Rule{
			{ID: "allow-net", ActionType: "net.http_request", Resource: "url://example.com/**", Decision: DecisionAllow},
			{ID: "deny-a", ActionType: "net.http_request", Resource: "url://example.com/**", Decision: DecisionDeny},
			{ID: "deny-b", ActionType: "net.http_request", Resource: "url://example.com/**", Decision: DecisionDeny},
		},
	}
	explanation := NewEngine(bundle).Explain(normalize.NormalizedAction{
		ActionType:  "net.http_request",
		Resource:    "url://example.com/path",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if explanation.Decision.Decision != DecisionDeny {
		t.Fatalf("expected deny, got %s", explanation.Decision.Decision)
	}
	if len(explanation.DenyRules) != 2 {
		t.Fatalf("expected 2 deny rules, got %+v", explanation.DenyRules)
	}
	if explanation.DenyRules[0].RuleID != "deny-a" || explanation.DenyRules[1].RuleID != "deny-b" {
		t.Fatalf("expected sorted deny rules, got %+v", explanation.DenyRules)
	}
	if len(explanation.AllowRuleIDs) != 1 || explanation.AllowRuleIDs[0] != "allow-net" {
		t.Fatalf("expected allow rule ids retained for preview only, got %+v", explanation.AllowRuleIDs)
	}
}

func TestPolicyExecMatchAllowsBroadCommandFamilyAndDeniesNarrowerPattern(t *testing.T) {
	bundle := Bundle{
		Version: "v1",
		Hash:    "bundle-hash",
		Rules: []Rule{
			{
				ID:         "allow-git",
				ActionType: "process.exec",
				Resource:   "file://workspace/",
				Decision:   DecisionAllow,
				ExecMatch: &ExecMatch{
					ArgvPatterns: [][]string{{"git", "**"}},
				},
			},
			{
				ID:         "deny-protected-branch-push",
				ActionType: "process.exec",
				Resource:   "file://workspace/",
				Decision:   DecisionDeny,
				ExecMatch: &ExecMatch{
					ArgvPatterns: [][]string{
						{"git", "push", "**", "main"},
						{"git", "push", "**", "master"},
					},
				},
			},
		},
	}
	engine := NewEngine(bundle)

	allowed := engine.Evaluate(normalize.NormalizedAction{
		ActionType:  "process.exec",
		Resource:    "file://workspace/",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
		Params:      []byte(`{"argv":["git","status"],"cwd":"","env_allowlist_keys":[]}`),
	})
	if allowed.Decision != DecisionAllow {
		t.Fatalf("expected allow for git status, got %+v", allowed)
	}

	denied := engine.Explain(normalize.NormalizedAction{
		ActionType:  "process.exec",
		Resource:    "file://workspace/",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
		Params:      []byte(`{"argv":["git","push","origin","main"],"cwd":"","env_allowlist_keys":[]}`),
	})
	if denied.Decision.Decision != DecisionDeny {
		t.Fatalf("expected deny for protected branch push, got %+v", denied.Decision)
	}
	if len(denied.DenyRules) != 1 || denied.DenyRules[0].RuleID != "deny-protected-branch-push" {
		t.Fatalf("expected deny explanation for protected branch rule, got %+v", denied.DenyRules)
	}
	if !denied.DenyRules[0].MatchedConditions["exec_match"] {
		t.Fatalf("expected exec_match condition recorded, got %+v", denied.DenyRules[0].MatchedConditions)
	}
	if len(denied.AllowRuleIDs) != 1 || denied.AllowRuleIDs[0] != "allow-git" {
		t.Fatalf("expected broad allow retained in preview, got %+v", denied.AllowRuleIDs)
	}
}

func TestPolicyExecMatchRejectsInvalidExecParams(t *testing.T) {
	bundle := Bundle{
		Version: "v1",
		Hash:    "bundle-hash",
		Rules: []Rule{
			{
				ID:         "allow-git",
				ActionType: "process.exec",
				Resource:   "file://workspace/",
				Decision:   DecisionAllow,
				ExecMatch: &ExecMatch{
					ArgvPatterns: [][]string{{"git", "**"}},
				},
			},
		},
	}
	engine := NewEngine(bundle)
	decision := engine.Evaluate(normalize.NormalizedAction{
		ActionType:  "process.exec",
		Resource:    "file://workspace/",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
		Params:      []byte(`{"cwd":"","env_allowlist_keys":[]}`),
	})
	if decision.Decision != DecisionDeny {
		t.Fatalf("expected deny when argv is missing, got %+v", decision)
	}
}

func TestPolicyExecMatchDerivesExecConstraintsForAllowDecision(t *testing.T) {
	bundle := Bundle{
		Version: "v1",
		Hash:    "bundle-hash",
		Rules: []Rule{
			{
				ID:         "allow-git",
				ActionType: "process.exec",
				Resource:   "file://workspace/",
				Decision:   DecisionAllow,
				ExecMatch: &ExecMatch{
					ArgvPatterns: [][]string{{"git", "**"}, {"git"}},
				},
				Obligations: map[string]any{
					"sandbox_mode": "local",
				},
			},
		},
	}
	decision := NewEngine(bundle).Evaluate(normalize.NormalizedAction{
		ActionType:  "process.exec",
		Resource:    "file://workspace/",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
		Params:      []byte(`{"argv":["git","status"],"cwd":"","env_allowlist_keys":[]}`),
	})
	if decision.Decision != DecisionAllow {
		t.Fatalf("expected allow, got %+v", decision)
	}
	raw, ok := decision.Obligations["exec_constraints"]
	if !ok {
		t.Fatalf("expected derived exec_constraints, got %+v", decision.Obligations)
	}
	constraints, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("expected exec_constraints object, got %#v", raw)
	}
	patterns, ok := constraints["argv_patterns"].([]any)
	if !ok || len(patterns) != 2 {
		t.Fatalf("expected derived argv patterns, got %#v", constraints["argv_patterns"])
	}
	if _, exists := decision.Obligations["exec_allowlist"]; exists {
		t.Fatalf("did not expect legacy exec_allowlist in obligations, got %+v", decision.Obligations)
	}
}

func TestPolicyExecModelConflictFailsClosed(t *testing.T) {
	bundle := Bundle{
		Version: "v1",
		Hash:    "bundle-hash",
		Rules: []Rule{
			{
				ID:         "allow-git-match",
				ActionType: "process.exec",
				Resource:   "file://workspace/",
				Decision:   DecisionAllow,
				ExecMatch: &ExecMatch{
					ArgvPatterns: [][]string{{"git", "**"}},
				},
			},
			{
				ID:         "allow-git-legacy",
				ActionType: "process.exec",
				Resource:   "file://workspace/",
				Decision:   DecisionAllow,
				Obligations: map[string]any{
					"exec_allowlist": []any{[]any{"git"}},
				},
			},
		},
	}
	explanation := NewEngine(bundle).Explain(normalize.NormalizedAction{
		ActionType:  "process.exec",
		Resource:    "file://workspace/",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
		Params:      []byte(`{"argv":["git","status"],"cwd":"","env_allowlist_keys":[]}`),
	})
	if explanation.Decision.Decision != DecisionDeny {
		t.Fatalf("expected deny on mixed exec model conflict, got %+v", explanation.Decision)
	}
	if explanation.Decision.ReasonCode != "deny_by_exec_model_conflict" {
		t.Fatalf("expected deny_by_exec_model_conflict, got %+v", explanation.Decision)
	}
	if !explanation.ExecAuthorization.Conflict {
		t.Fatalf("expected exec authorization conflict, got %+v", explanation.ExecAuthorization)
	}
}

func TestLoadBundleYAMLJSONParity(t *testing.T) {
	jsonBundle, err := LoadBundle(filepath.Clean(filepath.Join("..", "..", "examples", "policies", "safe.json")))
	if err != nil {
		t.Fatalf("load json bundle: %v", err)
	}
	yamlBundle, err := LoadBundle(filepath.Clean(filepath.Join("..", "..", "examples", "policies", "safe.yaml")))
	if err != nil {
		t.Fatalf("load yaml bundle: %v", err)
	}
	if jsonBundle.Hash != yamlBundle.Hash {
		t.Fatalf("expected equal hashes, got json=%s yaml=%s", jsonBundle.Hash, yamlBundle.Hash)
	}

	fixtures := []normalize.NormalizedAction{
		{ActionType: "fs.read", Resource: "file://workspace/README.md", Principal: "system", Agent: "nomos", Environment: "dev"},
		{ActionType: "fs.write", Resource: "file://workspace/docs/guide.md", Principal: "system", Agent: "nomos", Environment: "dev"},
		{ActionType: "process.exec", Resource: "file://workspace/", Principal: "system", Agent: "nomos", Environment: "dev"},
	}
	jsonEngine := NewEngine(jsonBundle)
	yamlEngine := NewEngine(yamlBundle)
	for _, fixture := range fixtures {
		jsonDecision := jsonEngine.Evaluate(fixture)
		yamlDecision := yamlEngine.Evaluate(fixture)
		jsonBytes, err := json.Marshal(jsonDecision)
		if err != nil {
			t.Fatalf("marshal json decision: %v", err)
		}
		yamlBytes, err := json.Marshal(yamlDecision)
		if err != nil {
			t.Fatalf("marshal yaml decision: %v", err)
		}
		if string(jsonBytes) != string(yamlBytes) {
			t.Fatalf("expected identical decisions for %+v\njson=%s\nyaml=%s", fixture, string(jsonBytes), string(yamlBytes))
		}
	}
}

func TestLoadBundleYMLExtensionSupported(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Clean(filepath.Join("..", "..", "examples", "policies", "safe.yaml")))
	if err != nil {
		t.Fatalf("read source yaml: %v", err)
	}
	ymlPath := filepath.Join(dir, "safe.yml")
	if err := os.WriteFile(ymlPath, data, 0o600); err != nil {
		t.Fatalf("write yml bundle: %v", err)
	}
	if _, err := LoadBundle(ymlPath); err != nil {
		t.Fatalf("expected .yml bundle to load, got %v", err)
	}
}

func TestLoadBundleYAMLRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	topLevelPath := filepath.Join(dir, "top.yaml")
	topLevel := "version: v1\nrules:\n  - id: r1\n    action_type: fs.read\n    resource: file://workspace/README.md\n    decision: ALLOW\nextra_field: nope\n"
	if err := os.WriteFile(topLevelPath, []byte(topLevel), 0o600); err != nil {
		t.Fatalf("write top-level yaml: %v", err)
	}
	if _, err := LoadBundle(topLevelPath); err == nil || !strings.Contains(strings.ToLower(err.Error()), "field") {
		t.Fatalf("expected unknown top-level field error, got %v", err)
	}

	nestedPath := filepath.Join(dir, "nested.yaml")
	nested := "version: v1\nrules:\n  - id: r1\n    action_type: fs.read\n    resource: file://workspace/README.md\n    decision: ALLOW\n    unexpected_nested: nope\n"
	if err := os.WriteFile(nestedPath, []byte(nested), 0o600); err != nil {
		t.Fatalf("write nested yaml: %v", err)
	}
	if _, err := LoadBundle(nestedPath); err == nil || !strings.Contains(strings.ToLower(err.Error()), "field") {
		t.Fatalf("expected unknown nested field error, got %v", err)
	}
}

func TestLoadBundleYAMLRejectsDuplicateKeys(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "dup.yaml")
	data := "version: v1\nrules:\n  - id: r1\n    action_type: fs.read\n    action_type: fs.write\n    resource: file://workspace/README.md\n    decision: ALLOW\n"
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write duplicate yaml: %v", err)
	}
	if _, err := LoadBundle(bundlePath); err == nil || !strings.Contains(strings.ToLower(err.Error()), "duplicate yaml key") {
		t.Fatalf("expected duplicate key error, got %v", err)
	}
}

func TestLoadBundleRejectsInvalidExecMatch(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bad.json")
	data := `{"version":"v1","rules":[{"id":"bad-exec-match","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","exec_match":{"argv_patterns":[["git","**"]]}}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if _, err := LoadBundle(bundlePath); err == nil || !strings.Contains(err.Error(), "exec_match requires action_type process.exec or *") {
		t.Fatalf("expected invalid exec_match action type error, got %v", err)
	}
}

func TestLoadBundleRejectsMixedExecAuthorizationInSameRule(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bad-mixed.json")
	data := `{"version":"v1","rules":[{"id":"mixed-exec","action_type":"process.exec","resource":"file://workspace/","decision":"ALLOW","exec_match":{"argv_patterns":[["git","**"]]},"obligations":{"exec_allowlist":[["git"]]}}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if _, err := LoadBundle(bundlePath); err == nil || !strings.Contains(err.Error(), "must not declare both exec_match and exec_allowlist") {
		t.Fatalf("expected mixed exec authorization rejection, got %v", err)
	}
}

func TestValidateExecCompatibilityStrictRejectsLegacyAllowlist(t *testing.T) {
	bundle := Bundle{
		Version: "v1",
		Hash:    "bundle-hash",
		Rules: []Rule{
			{
				ID:         "legacy-exec",
				ActionType: "process.exec",
				Resource:   "file://workspace/",
				Decision:   DecisionAllow,
				Obligations: map[string]any{
					"exec_allowlist": []any{[]any{"git"}},
				},
			},
		},
	}
	if err := ValidateExecCompatibility(bundle, ExecCompatibilityStrict); err == nil || !strings.Contains(err.Error(), "policy.exec_compatibility_mode=strict") {
		t.Fatalf("expected strict compatibility rejection, got %v", err)
	}
}

func TestLoadBundleHashGoldenVectorForSafe(t *testing.T) {
	bundle, err := LoadBundle(filepath.Clean(filepath.Join("..", "..", "examples", "policies", "safe.yaml")))
	if err != nil {
		t.Fatalf("load yaml bundle: %v", err)
	}
	const expected = "7ec7bd2481d8cb07eed2c21c21563a62e6fe6277ae8333d1cbf9c01bd8b0bafb"
	if bundle.Hash != expected {
		t.Fatalf("expected hash %s, got %s", expected, bundle.Hash)
	}
}

func TestLoadBundlesDeterministicMergedIdentity(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.json")
	repo := filepath.Join(dir, "repo.json")
	if err := os.WriteFile(base, []byte(`{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write base bundle: %v", err)
	}
	if err := os.WriteFile(repo, []byte(`{"version":"v1","rules":[{"id":"deny-env","action_type":"fs.read","resource":"file://workspace/.env","decision":"DENY"}]}`), 0o600); err != nil {
		t.Fatalf("write repo bundle: %v", err)
	}
	first, err := LoadBundles([]string{base, repo})
	if err != nil {
		t.Fatalf("load merged bundles #1: %v", err)
	}
	second, err := LoadBundles([]string{base, repo})
	if err != nil {
		t.Fatalf("load merged bundles #2: %v", err)
	}
	if first.Hash == "" || second.Hash == "" {
		t.Fatal("expected merged bundle hash")
	}
	if first.Hash != second.Hash {
		t.Fatalf("expected stable merged hash, got %s vs %s", first.Hash, second.Hash)
	}
	if len(first.SourceBundles) != 2 {
		t.Fatalf("expected 2 source bundles, got %+v", first.SourceBundles)
	}
}

func TestLoadBundlesVerifiesEachBundleBeforeMerge(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	repoPath := filepath.Join(dir, "repo.json")
	baseData := []byte(`{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW"}]}`)
	repoData := []byte(`{"version":"v1","rules":[{"id":"require-approval-net","action_type":"net.http_request","resource":"url://example.com/**","decision":"REQUIRE_APPROVAL"}]}`)
	if err := os.WriteFile(basePath, baseData, 0o600); err != nil {
		t.Fatalf("write base bundle: %v", err)
	}
	if err := os.WriteFile(repoPath, repoData, 0o600); err != nil {
		t.Fatalf("write repo bundle: %v", err)
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signBundle := func(bundleData []byte) string {
		digest := sha256.Sum256(bundleData)
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("sign bundle: %v", err)
		}
		return base64.StdEncoding.EncodeToString(sig)
	}
	baseSigPath := filepath.Join(dir, "base.sig")
	repoSigPath := filepath.Join(dir, "repo.sig")
	if err := os.WriteFile(baseSigPath, []byte(signBundle(baseData)), 0o600); err != nil {
		t.Fatalf("write base sig: %v", err)
	}
	if err := os.WriteFile(repoSigPath, []byte("invalid-signature"), 0o600); err != nil {
		t.Fatalf("write repo sig: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPath := filepath.Join(dir, "bundle_pub.pem")
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	_, err = LoadBundlesWithOptions([]string{basePath, repoPath}, MultiLoadOptions{
		VerifySignatures: true,
		SignaturePaths:   []string{baseSigPath, repoSigPath},
		PublicKeyPath:    pubPath,
	})
	if err == nil || !strings.Contains(err.Error(), repoPath) || !strings.Contains(strings.ToLower(err.Error()), "signature") {
		t.Fatalf("expected per-bundle signature verification failure before merge, got %v", err)
	}
}

func TestPolicyExplainIncludesMatchedRuleBundleProvenanceForMergedBundles(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.json")
	envPath := filepath.Join(dir, "env.json")
	if err := os.WriteFile(basePath, []byte(`{"version":"v1","rules":[{"id":"allow-workspace","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW"}]}`), 0o600); err != nil {
		t.Fatalf("write base bundle: %v", err)
	}
	if err := os.WriteFile(envPath, []byte(`{"version":"v1","rules":[{"id":"deny-env","action_type":"fs.read","resource":"file://workspace/.env","decision":"DENY"}]}`), 0o600); err != nil {
		t.Fatalf("write env bundle: %v", err)
	}
	bundle, err := LoadBundlesWithOptions([]string{basePath, envPath}, MultiLoadOptions{
		BundleRoles: []string{"baseline", "env"},
	})
	if err != nil {
		t.Fatalf("load merged bundles: %v", err)
	}
	explanation := NewEngine(bundle).Explain(normalize.NormalizedAction{
		ActionType:  "fs.read",
		Resource:    "file://workspace/.env",
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	})
	if explanation.Decision.Decision != DecisionDeny {
		t.Fatalf("expected deny, got %+v", explanation.Decision)
	}
	if len(explanation.MatchedRuleProvenance) != 2 {
		t.Fatalf("expected matched-rule provenance for both matched rules, got %+v", explanation.MatchedRuleProvenance)
	}
	if explanation.MatchedRuleProvenance[0].BundleSource == "" || explanation.MatchedRuleProvenance[1].BundleSource == "" {
		t.Fatalf("expected bundle provenance labels, got %+v", explanation.MatchedRuleProvenance)
	}
	if len(explanation.Decision.PolicyBundleInputs) != 2 {
		t.Fatalf("expected ordered bundle inputs, got %+v", explanation.Decision.PolicyBundleInputs)
	}
	if explanation.Decision.PolicyBundleInputs[0].Role != "baseline" || explanation.Decision.PolicyBundleInputs[1].Role != "env" {
		t.Fatalf("expected bundle roles preserved, got %+v", explanation.Decision.PolicyBundleInputs)
	}
}

func TestLoadBundlesRejectsDuplicateRuleIDsAcrossBundles(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first.json")
	secondPath := filepath.Join(dir, "second.json")
	data := `{"version":"v1","rules":[{"id":"shared","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW"}]}`
	if err := os.WriteFile(firstPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write first bundle: %v", err)
	}
	if err := os.WriteFile(secondPath, []byte(data), 0o600); err != nil {
		t.Fatalf("write second bundle: %v", err)
	}
	if _, err := LoadBundles([]string{firstPath, secondPath}); err == nil || !strings.Contains(err.Error(), `duplicate rule id "shared"`) {
		t.Fatalf("expected duplicate rule rejection, got %v", err)
	}
}
