package quickstart

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/gateway"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

func TestCIBoundarySmokeFixturesLoadAndMatchCIStrict(t *testing.T) {
	root := repoRoot(t)
	configPath := filepath.Join(root, "examples", "ci", "github", "config.ci.json")
	cfg, err := gateway.LoadConfig(configPath, func(string) string { return "" }, "")
	if err != nil {
		t.Fatalf("load ci config: %v", err)
	}
	if cfg.Runtime.DeploymentMode != "ci" {
		t.Fatalf("expected ci deployment mode, got %q", cfg.Runtime.DeploymentMode)
	}
	if cfg.Runtime.StrongGuarantee {
		t.Fatal("ci boundary smoke must not claim strong guarantee")
	}

	bundlePath := filepath.Join(root, "profiles", "ci-strict.yaml")
	bundle, err := policy.LoadBundle(bundlePath)
	if err != nil {
		t.Fatalf("load ci-strict profile: %v", err)
	}
	engine := policy.NewEngine(bundle)

	tests := map[string]string{
		"allow-git-status.json": policy.DecisionAllow,
		"deny-git-push.json":    policy.DecisionDeny,
		"deny-secret-read.json": policy.DecisionDeny,
	}
	for file, want := range tests {
		t.Run(file, func(t *testing.T) {
			path := filepath.Join(root, "examples", "ci", "github", "actions", file)
			act, err := action.DecodeAction([]byte(mustReadFile(t, path)))
			if err != nil {
				t.Fatalf("decode action: %v", err)
			}
			normalized, err := normalize.Action(act)
			if err != nil {
				t.Fatalf("normalize action: %v", err)
			}
			decision := engine.Evaluate(normalized)
			if decision.Decision != want {
				t.Fatalf("decision = %s (%s via %v), want %s", decision.Decision, decision.ReasonCode, decision.MatchedRuleIDs, want)
			}
		})
	}
}

func TestCIBoundarySmokeDocsAndWorkflowsReferenceExistingFiles(t *testing.T) {
	root := repoRoot(t)
	requiredFiles := []string{
		"docs/ci-boundary-smoke.md",
		".github/workflows/nomos-ci-smoke.yml",
		"examples/ci/github/config.ci.json",
		"examples/ci/github/actions/allow-git-status.json",
		"examples/ci/github/actions/deny-git-push.json",
		"examples/ci/github/actions/deny-secret-read.json",
		"examples/ci/gitlab/.gitlab-ci.yml",
	}
	for _, rel := range requiredFiles {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("expected %s to exist: %v", rel, err)
		}
	}

	doc := mustReadFile(t, filepath.Join(root, "docs", "ci-boundary-smoke.md"))
	for _, snippet := range []string{
		"nomos doctor",
		"examples/ci/github/config.ci.json",
		"examples/ci/github/actions/allow-git-status.json",
		"examples/ci/github/actions/deny-git-push.json",
		"examples/ci/github/actions/deny-secret-read.json",
		"does not launch an AI agent",
	} {
		if !strings.Contains(doc, snippet) {
			t.Fatalf("ci boundary smoke doc missing %q", snippet)
		}
	}

	workflow := mustReadFile(t, filepath.Join(root, ".github", "workflows", "nomos-ci-smoke.yml"))
	for _, snippet := range []string{
		"examples/ci/github/config.ci.json",
		"profiles/ci-strict.yaml",
		"actions/upload-artifact",
		"artifacts/nomos-ci-smoke",
		"TestNormalizeExecParamsUnwrapsPowerShellCommand",
	} {
		if !strings.Contains(workflow, snippet) {
			t.Fatalf("ci smoke workflow missing %q", snippet)
		}
	}

	ciWorkflow := mustReadFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"))
	if !strings.Contains(ciWorkflow, "actionlint") {
		t.Fatal("enterprise CI must continue linting all workflow files")
	}
}

func TestCIActionFixturesStayValid(t *testing.T) {
	root := repoRoot(t)
	actionsRoot := filepath.Join(root, "examples", "ci", "github", "actions")
	seen := 0
	if err := filepath.WalkDir(actionsRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(path), ".json") {
			return nil
		}
		seen++
		act, err := action.DecodeAction([]byte(mustReadFile(t, path)))
		if err != nil {
			t.Fatalf("decode ci action %s: %v", path, err)
		}
		if _, err := normalize.Action(act); err != nil {
			t.Fatalf("normalize ci action %s: %v", path, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk ci actions: %v", err)
	}
	if seen == 0 {
		t.Fatal("expected CI action fixtures")
	}
}
