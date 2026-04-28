package ratelimit

import (
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/normalize"
)

func TestLimiterConsumesAllMatchingBucketTypes(t *testing.T) {
	now := time.Unix(100, 0)
	limiter, err := New(Config{
		Enabled:    true,
		EvictAfter: time.Hour,
		Now:        func() time.Time { return now },
		Rules: []Rule{
			{ID: "pa", Scope: ScopePrincipalAction, ActionType: "fs.read", Burst: 1, RefillPerMinute: 60},
			{ID: "pr", Scope: ScopePrincipalResource, Resource: "file://workspace/README.md", Burst: 1, RefillPerMinute: 60},
			{ID: "gt", Scope: ScopeGlobalTool, ActionType: "fs.read", Burst: 1, RefillPerMinute: 60},
		},
	})
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	action := normalizedReadAction("alice")
	first := limiter.Check(action)
	if !first.Allowed || first.MatchedRuleCount != 3 {
		t.Fatalf("expected first request to consume all buckets, got %+v", first)
	}
	second := limiter.Check(action)
	if second.Allowed || second.RuleID == "" {
		t.Fatalf("expected second request to be denied by an empty bucket, got %+v", second)
	}
}

func TestLimiterPrunesIdleBuckets(t *testing.T) {
	now := time.Unix(100, 0)
	limiter, err := New(Config{
		Enabled:    true,
		EvictAfter: time.Second,
		Now:        func() time.Time { return now },
		Rules: []Rule{
			{ID: "pa", Scope: ScopePrincipalAction, ActionType: "fs.read", Burst: 1, RefillPerMinute: 60},
		},
	})
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	if result := limiter.Check(normalizedReadAction("alice")); !result.Allowed {
		t.Fatalf("expected initial allow, got %+v", result)
	}
	now = now.Add(2 * time.Second)
	limiter.prune(now.UnixNano())
	if _, ok := limiter.buckets.Load("principal_action|pa|alice|fs.read"); ok {
		t.Fatal("expected idle bucket to be pruned")
	}
}

func normalizedReadAction(principal string) normalize.NormalizedAction {
	return normalize.NormalizedAction{
		SchemaVersion: "v1",
		ActionID:      "act",
		ActionType:    "fs.read",
		Resource:      "file://workspace/README.md",
		Params:        []byte(`{}`),
		ParamsHash:    "hash",
		Principal:     principal,
		Agent:         "nomos",
		Environment:   "dev",
		TraceID:       "trace",
	}
}
