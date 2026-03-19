package service

import (
	"testing"

	"github.com/safe-agentic-world/nomos/internal/policy"
)

func TestExecAllowlistCompatibility(t *testing.T) {
	obligations := map[string]any{
		"exec_allowlist": []any{
			[]any{"git"},
			[]any{"go", "test"},
		},
	}
	ok, mode := execAuthorized(obligations, []byte(`{"argv":["git","status"],"cwd":"","env_allowlist_keys":[]}`), policy.ExecCompatibilityLegacyAllowlistFallback)
	if !ok || mode != "exec_allowlist" {
		t.Fatal("expected exec allowlist to allow git")
	}
	ok, mode = execAuthorized(obligations, []byte(`{"argv":["bash","-c","ls"],"cwd":"","env_allowlist_keys":[]}`), policy.ExecCompatibilityLegacyAllowlistFallback)
	if ok {
		t.Fatal("expected exec allowlist to block bash")
	}
	if mode != "exec_allowlist" {
		t.Fatalf("expected exec_allowlist mode, got %q", mode)
	}
}

func TestExecConstraintsTakePrecedence(t *testing.T) {
	obligations := map[string]any{
		"exec_constraints": map[string]any{
			"argv_patterns": []any{
				[]any{"git", "**"},
			},
		},
		"exec_allowlist": []any{
			[]any{"bash"},
		},
	}
	ok, mode := execAuthorized(obligations, []byte(`{"argv":["git","status"],"cwd":"","env_allowlist_keys":[]}`), policy.ExecCompatibilityLegacyAllowlistFallback)
	if !ok {
		t.Fatal("expected exec constraints to allow git")
	}
	if mode != "exec_constraints" {
		t.Fatalf("expected exec_constraints mode, got %q", mode)
	}
}

func TestExecStrictModeDisablesLegacyAllowlistFallback(t *testing.T) {
	obligations := map[string]any{
		"exec_allowlist": []any{
			[]any{"git"},
		},
	}
	ok, mode := execAuthorized(obligations, []byte(`{"argv":["git","status"],"cwd":"","env_allowlist_keys":[]}`), policy.ExecCompatibilityStrict)
	if ok {
		t.Fatal("expected strict mode to disable legacy allowlist fallback")
	}
	if mode != "legacy_disabled" {
		t.Fatalf("expected legacy_disabled mode, got %q", mode)
	}
}

func TestNetAllowlist(t *testing.T) {
	obligations := map[string]any{
		"net_allowlist": []any{"example.com"},
	}
	if !netAllowed(obligations, "example.com") {
		t.Fatal("expected host allowed")
	}
	if netAllowed(obligations, "evil.com") {
		t.Fatal("expected host blocked")
	}
}
