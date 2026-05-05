package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/normalize"
)

var defaultProfileNames = []string{"safe-dev", "ci-strict", "prod-locked"}

func TestDefaultPolicyProfilesGoldenHashes(t *testing.T) {
	expected := loadProfileHashes(t)
	changelog := readRepoFile(t, "CHANGELOG.md")
	for _, name := range defaultProfileNames {
		bundle := loadDefaultProfileBundle(t, name)
		want := strings.TrimSpace(expected[name])
		if want == "" {
			t.Errorf("missing golden hash for %s: set it to %q", name, bundle.Hash)
			continue
		}
		if bundle.Hash != want {
			t.Errorf("%s hash changed: got %q want %q; run `make pin-profile-hashes` if intentional", name, bundle.Hash, want)
			continue
		}
		if !strings.Contains(changelog, "testdata/policy-profiles/hashes.json") {
			t.Fatalf("CHANGELOG.md must reference testdata/policy-profiles/hashes.json for default profile hashes")
		}
	}
}

func TestDefaultPolicyProfileDecisions(t *testing.T) {
	tests := []struct {
		name       string
		profile    string
		actionType string
		resource   string
		params     map[string]any
		want       string
	}{
		{name: "safe dev denies dotenv", profile: "safe-dev", actionType: "fs.read", resource: "file://workspace/.env", params: map[string]any{"resource": ".env"}, want: DecisionDeny},
		{name: "safe dev denies ssh key path", profile: "safe-dev", actionType: "fs.read", resource: "file://workspace/.ssh/id_rsa", params: map[string]any{"resource": ".ssh/id_rsa"}, want: DecisionDeny},
		{name: "safe dev allows git status", profile: "safe-dev", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("git", "status"), want: DecisionAllow},
		{name: "safe dev allows go test", profile: "safe-dev", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("go", "test", "./..."), want: DecisionAllow},
		{name: "safe dev approves git push", profile: "safe-dev", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("git", "push", "origin", "main"), want: DecisionRequireApproval},
		{name: "safe dev approves terraform apply", profile: "safe-dev", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("terraform", "apply", "-auto-approve"), want: DecisionRequireApproval},
		{name: "safe dev approves terraform destroy", profile: "safe-dev", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("terraform", "destroy"), want: DecisionRequireApproval},
		{name: "safe dev approves kubectl delete", profile: "safe-dev", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("kubectl", "delete", "pod", "api"), want: DecisionRequireApproval},
		{name: "safe dev denies auth header dump", profile: "safe-dev", actionType: "net.http_request", resource: "url://github.com/api", params: httpParamsForTest("GET", map[string]string{"Authorization": "Bearer token"}), want: DecisionDeny},
		{name: "safe dev denies unknown egress by default", profile: "safe-dev", actionType: "net.http_request", resource: "url://evil.example.com/api", params: httpParamsForTest("GET", nil), want: DecisionDeny},
		{name: "ci strict denies dotenv", profile: "ci-strict", actionType: "fs.read", resource: "file://workspace/.env", params: map[string]any{"resource": ".env"}, want: DecisionDeny},
		{name: "ci strict allows git status", profile: "ci-strict", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("git", "status"), want: DecisionAllow},
		{name: "ci strict denies git push", profile: "ci-strict", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("git", "push", "origin", "main"), want: DecisionDeny},
		{name: "ci strict denies terraform destroy", profile: "ci-strict", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("terraform", "destroy"), want: DecisionDeny},
		{name: "ci strict allows go test", profile: "ci-strict", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("go", "test", "./..."), want: DecisionAllow},
		{name: "ci strict allows structured publish", profile: "ci-strict", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("nomos", "publish-artifact", "dist/app.tgz"), want: DecisionAllow},
		{name: "ci strict denies unknown egress by default", profile: "ci-strict", actionType: "net.http_request", resource: "url://unknown.example.com/api", params: httpParamsForTest("GET", nil), want: DecisionDeny},
		{name: "prod locked denies writes", profile: "prod-locked", actionType: "fs.write", resource: "file://workspace/README.md", params: map[string]any{"resource": "README.md", "content": "x"}, want: DecisionDeny},
		{name: "prod locked denies patches", profile: "prod-locked", actionType: "repo.apply_patch", resource: "repo://local/workspace", params: map[string]any{"path": "README.md", "content": "x"}, want: DecisionDeny},
		{name: "prod locked allows readonly kubectl", profile: "prod-locked", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("kubectl", "get", "pods"), want: DecisionAllow},
		{name: "prod locked approves breakglass rollout", profile: "prod-locked", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("kubectl", "rollout", "restart", "deployment/api"), want: DecisionRequireApproval},
		{name: "prod locked denies kubectl delete", profile: "prod-locked", actionType: "process.exec", resource: "file://workspace/", params: execParamsForTest("kubectl", "delete", "pod", "api"), want: DecisionDeny},
		{name: "prod locked denies unknown egress by default", profile: "prod-locked", actionType: "net.http_request", resource: "url://github.com/api", params: httpParamsForTest("GET", nil), want: DecisionDeny},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle := loadDefaultProfileBundle(t, tc.profile)
			decision := evaluateProfileDecision(t, bundle, tc.actionType, tc.resource, tc.params)
			if decision.Decision != tc.want {
				t.Fatalf("decision = %s (%s via %v), want %s", decision.Decision, decision.ReasonCode, decision.MatchedRuleIDs, tc.want)
			}
		})
	}
}

func loadProfileHashes(t *testing.T) map[string]string {
	t.Helper()
	data := readRepoFileBytes(t, filepath.Join("testdata", "policy-profiles", "hashes.json"))
	var hashes map[string]string
	if err := json.Unmarshal(data, &hashes); err != nil {
		t.Fatalf("decode profile hashes: %v", err)
	}
	return hashes
}

func loadDefaultProfileBundle(t *testing.T, name string) Bundle {
	t.Helper()
	bundle, err := LoadBundle(repoPath(filepath.Join("profiles", name+".yaml")))
	if err != nil {
		t.Fatalf("load %s profile: %v", name, err)
	}
	return bundle
}

func evaluateProfileDecision(t *testing.T, bundle Bundle, actionType, resource string, params map[string]any) Decision {
	t.Helper()
	paramBytes, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      "profile_test",
		ActionType:    actionType,
		Resource:      resource,
		Params:        paramBytes,
		TraceID:       "profile_test",
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{Principal: "system", Agent: "nomos", Environment: "dev"})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	normalized, err := normalize.Action(act)
	if err != nil {
		t.Fatalf("normalize action: %v", err)
	}
	return NewEngine(bundle).Evaluate(normalized)
}

func execParamsForTest(argv ...string) map[string]any {
	return map[string]any{
		"argv":               argv,
		"cwd":                "",
		"env_allowlist_keys": []string{},
	}
}

func httpParamsForTest(method string, headers map[string]string) map[string]any {
	if headers == nil {
		headers = map[string]string{}
	}
	return map[string]any{
		"method":  method,
		"body":    "",
		"headers": headers,
	}
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	return string(readRepoFileBytes(t, rel))
}

func readRepoFileBytes(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(repoPath(rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return data
}

func repoPath(rel string) string {
	return filepath.Join("..", "..", rel)
}
