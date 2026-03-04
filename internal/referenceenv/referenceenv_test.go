package referenceenv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/service"
)

type recordSink struct{}

func (recordSink) WriteEvent(audit.Event) error { return nil }

func TestStrongGuaranteeManifestBlocksDirectNetworkEgress(t *testing.T) {
	manifest := loadStrongManifest(t)
	agentPolicy, ok := findManifestDoc(manifest, "kind: NetworkPolicy", "name: sample-agent-egress")
	if !ok {
		t.Fatal("missing sample-agent egress network policy")
	}
	requireContains(t, agentPolicy, "app: sample-agent")
	requireContains(t, agentPolicy, "app: nomos")
	requireContains(t, agentPolicy, "port: 8080")
	requireNotContains(t, agentPolicy, "namespaceSelector: {}")
}

func TestStrongGuaranteeManifestBlocksDirectCredentialAccess(t *testing.T) {
	manifest := loadStrongManifest(t)
	agentDeployment, ok := findManifestDoc(manifest, "kind: Deployment", "name: sample-agent")
	if !ok {
		t.Fatal("missing sample-agent deployment")
	}
	requireContains(t, agentDeployment, "serviceAccountName: sample-agent")
	requireContains(t, agentDeployment, "automountServiceAccountToken: false")
	requireNotContains(t, agentDeployment, "env:")
	requireNotContains(t, agentDeployment, "envFrom:")
	requireNotContains(t, agentDeployment, "secretKeyRef:")
	requireNotContains(t, agentDeployment, "secret:")
	requireNotContains(t, agentDeployment, "projected:")
}

func TestStrongGuaranteeManifestBlocksFilesystemEscape(t *testing.T) {
	manifest := loadStrongManifest(t)
	agentDeployment, ok := findManifestDoc(manifest, "kind: Deployment", "name: sample-agent")
	if !ok {
		t.Fatal("missing sample-agent deployment")
	}
	requireContains(t, agentDeployment, "runAsNonRoot: true")
	requireContains(t, agentDeployment, "readOnlyRootFilesystem: true")
	requireContains(t, agentDeployment, "allowPrivilegeEscalation: false")
	requireNotContains(t, agentDeployment, "hostPath:")
	requireNotContains(t, agentDeployment, "volumeMounts:")
}

func TestStrongGuaranteeManifestValidationHarness(t *testing.T) {
	manifest := loadStrongManifest(t)
	report := ValidateStrongGuaranteeManifest(manifest)
	if !report.AllPassed() {
		var failed []string
		for _, check := range report.Checks {
			if !check.OK {
				failed = append(failed, check.ID)
			}
		}
		t.Fatalf("expected strong-guarantee manifest checks to pass, failed=%v", failed)
	}
}

func TestStrongGuaranteeCIWorkflowValidationHarness(t *testing.T) {
	workflow := loadStrongWorkflow(t)
	report := ValidateStrongGuaranteeCIWorkflow(workflow)
	if !report.AllPassed() {
		var failed []string
		for _, check := range report.Checks {
			if !check.OK {
				failed = append(failed, check.ID)
			}
		}
		t.Fatalf("expected strong-guarantee CI workflow checks to pass, failed=%v", failed)
	}
}

func TestOnlyNomosMediatedAllowedActionSucceeds(t *testing.T) {
	dir := t.TempDir()
	readmePath := filepath.Join(dir, "README.md")
	if err := os.WriteFile(readmePath, []byte("safe output"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	engine := policy.NewEngine(policy.Bundle{
		Version: "v1",
		Hash:    "test",
		Rules: []policy.Rule{
			{
				ID:           "allow-readme",
				ActionType:   "fs.read",
				Resource:     "file://workspace/README.md",
				Decision:     policy.DecisionAllow,
				Principals:   []string{"system"},
				Agents:       []string{"nomos"},
				Environments: []string{"prod"},
			},
		},
	})
	svc := service.New(
		engine,
		executor.NewFSReader(dir, 1024, 32),
		executor.NewFSWriter(dir, 1024),
		executor.NewPatchApplier(dir, 1024),
		executor.NewExecRunner(dir, 1024),
		executor.NewHTTPRunner(1024),
		recordSink{},
		redact.DefaultRedactor(),
		nil,
		nil,
		"container",
		func() time.Time { return time.Unix(0, 0) },
	)

	allowed := toAction(t, "read-1", "fs.read", "file://workspace/README.md", `{}`, "prod")
	resp, err := svc.Process(allowed)
	if err != nil {
		t.Fatalf("process allowed action: %v", err)
	}
	if resp.Decision != policy.DecisionAllow {
		t.Fatalf("expected ALLOW, got %s", resp.Decision)
	}
	if strings.TrimSpace(resp.Output) != "safe output" {
		t.Fatalf("unexpected output: %q", resp.Output)
	}

	denied := toAction(t, "exec-1", "process.exec", "file://workspace/", `{"argv":["curl","https://example.com"],"cwd":"","env_allowlist_keys":[]}`, "prod")
	deniedResp, err := svc.Process(denied)
	if err != nil {
		t.Fatalf("process denied action: %v", err)
	}
	if deniedResp.Decision != policy.DecisionDeny {
		t.Fatalf("expected DENY, got %s", deniedResp.Decision)
	}
	if deniedResp.Reason != "deny_by_default" {
		t.Fatalf("expected deny_by_default, got %s", deniedResp.Reason)
	}
}

func toAction(t *testing.T, id, actionType, resource, params, env string) action.Action {
	t.Helper()
	act, err := action.ToAction(action.Request{
		SchemaVersion: "v1",
		ActionID:      id,
		ActionType:    actionType,
		Resource:      resource,
		Params:        []byte(params),
		TraceID:       "trace_" + id,
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: env,
	})
	if err != nil {
		t.Fatalf("to action: %v", err)
	}
	return act
}

func loadStrongManifest(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join("..", "..", "deploy", "k8s", "strong-guarantee.yaml")))
	if err != nil {
		t.Fatalf("read strong manifest: %v", err)
	}
	return string(data)
}

func loadStrongWorkflow(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join("..", "..", "deploy", "ci", "github-actions-hardened.yml")))
	if err != nil {
		t.Fatalf("read strong workflow: %v", err)
	}
	return string(data)
}

func requireContains(t *testing.T, text, pattern string) {
	t.Helper()
	if !strings.Contains(text, pattern) {
		t.Fatalf("expected to find %q", pattern)
	}
}

func requireNotContains(t *testing.T, text, pattern string) {
	t.Helper()
	if strings.Contains(text, pattern) {
		t.Fatalf("expected not to find %q", pattern)
	}
}
