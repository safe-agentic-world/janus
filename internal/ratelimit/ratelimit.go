package ratelimit

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/safe-agentic-world/nomos/internal/normalize"
)

const tokenScale int64 = 1_000_000

const (
	ScopePrincipalAction   = "principal_action"
	ScopePrincipalResource = "principal_resource"
	ScopeGlobalTool        = "global_tool"
)

type Config struct {
	Enabled    bool
	EvictAfter time.Duration
	Rules      []Rule
	Now        func() time.Time
}

type Rule struct {
	ID              string
	Scope           string
	Principal       string
	ActionType      string
	Resource        string
	Burst           int
	RefillPerMinute int
}

type Result struct {
	Allowed          bool
	Applied          bool
	RuleID           string
	Scope            string
	BucketKey        string
	RemainingTokens  int
	RefillPerMinute  int
	MatchedRuleCount int
	Hits             []Hit
}

type Hit struct {
	RuleID          string
	Scope           string
	BucketKey       string
	RemainingTokens int
}

type Limiter struct {
	enabled    bool
	rules      []Rule
	evictAfter time.Duration
	now        func() time.Time
	buckets    sync.Map
	checks     atomic.Uint64
}

type bucket struct {
	state atomic.Pointer[bucketState]
}

type bucketState struct {
	tokens       int64
	lastRefillNS int64
	lastSeenNS   int64
}

type matchedRule struct {
	rule      Rule
	bucketKey string
	bucket    *bucket
}

func New(config Config) (*Limiter, error) {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.EvictAfter == 0 {
		config.EvictAfter = time.Hour
	}
	if config.EvictAfter < 0 {
		return nil, errors.New("rate limit evict_after must be >= 0")
	}
	if !config.Enabled && len(config.Rules) == 0 {
		return nil, nil
	}
	rules := append([]Rule{}, config.Rules...)
	if err := validateRules(rules); err != nil {
		return nil, err
	}
	return &Limiter{
		enabled:    config.Enabled || len(rules) > 0,
		rules:      rules,
		evictAfter: config.EvictAfter,
		now:        config.Now,
	}, nil
}

func (l *Limiter) Check(action normalize.NormalizedAction) Result {
	if l == nil || !l.enabled || len(l.rules) == 0 {
		return Result{Allowed: true}
	}
	now := l.now().UTC()
	nowNS := now.UnixNano()
	if l.evictAfter > 0 && l.checks.Add(1)%64 == 0 {
		l.prune(nowNS)
	}
	matches := l.matchingRules(action, nowNS)
	if len(matches) == 0 {
		return Result{Allowed: true}
	}
	hits := make([]Hit, 0, len(matches))
	for _, match := range matches {
		state := match.bucket.advance(nowNS, match.rule)
		remaining := int(state.tokens / tokenScale)
		hits = append(hits, Hit{
			RuleID:          match.rule.ID,
			Scope:           match.rule.Scope,
			BucketKey:       match.bucketKey,
			RemainingTokens: remaining,
		})
		if state.tokens < tokenScale {
			return Result{
				Allowed:          false,
				Applied:          true,
				RuleID:           match.rule.ID,
				Scope:            match.rule.Scope,
				BucketKey:        match.bucketKey,
				RemainingTokens:  remaining,
				RefillPerMinute:  match.rule.RefillPerMinute,
				MatchedRuleCount: len(matches),
				Hits:             hits,
			}
		}
	}
	for idx, match := range matches {
		state, ok := match.bucket.tryConsume(nowNS, match.rule)
		remaining := int(state.tokens / tokenScale)
		if idx < len(hits) {
			hits[idx].RemainingTokens = remaining
		}
		if !ok {
			return Result{
				Allowed:          false,
				Applied:          true,
				RuleID:           match.rule.ID,
				Scope:            match.rule.Scope,
				BucketKey:        match.bucketKey,
				RemainingTokens:  remaining,
				RefillPerMinute:  match.rule.RefillPerMinute,
				MatchedRuleCount: len(matches),
				Hits:             hits,
			}
		}
	}
	return Result{
		Allowed:          true,
		Applied:          true,
		MatchedRuleCount: len(matches),
		Hits:             hits,
	}
}

func (l *Limiter) matchingRules(action normalize.NormalizedAction, nowNS int64) []matchedRule {
	out := make([]matchedRule, 0, len(l.rules))
	for _, rule := range l.rules {
		if !ruleMatches(rule, action) {
			continue
		}
		key := bucketKey(rule, action)
		value, _ := l.buckets.LoadOrStore(key, newBucket(rule, nowNS))
		out = append(out, matchedRule{
			rule:      rule,
			bucketKey: key,
			bucket:    value.(*bucket),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].bucketKey < out[j].bucketKey
	})
	return out
}

func (l *Limiter) prune(nowNS int64) {
	threshold := nowNS - l.evictAfter.Nanoseconds()
	l.buckets.Range(func(key, value any) bool {
		b, ok := value.(*bucket)
		if !ok {
			return true
		}
		state := b.state.Load()
		if state != nil && state.lastSeenNS < threshold {
			l.buckets.CompareAndDelete(key, value)
		}
		return true
	})
}

func newBucket(rule Rule, nowNS int64) *bucket {
	b := &bucket{}
	b.state.Store(&bucketState{
		tokens:       int64(rule.Burst) * tokenScale,
		lastRefillNS: nowNS,
		lastSeenNS:   nowNS,
	})
	return b
}

func (b *bucket) advance(nowNS int64, rule Rule) bucketState {
	for {
		old := b.state.Load()
		next := refill(*old, nowNS, rule)
		next.lastSeenNS = nowNS
		if sameState(*old, next) {
			return next
		}
		if b.state.CompareAndSwap(old, &next) {
			return next
		}
	}
}

func (b *bucket) tryConsume(nowNS int64, rule Rule) (bucketState, bool) {
	for {
		old := b.state.Load()
		next := refill(*old, nowNS, rule)
		next.lastSeenNS = nowNS
		if next.tokens < tokenScale {
			if b.state.CompareAndSwap(old, &next) {
				return next, false
			}
			continue
		}
		next.tokens -= tokenScale
		if b.state.CompareAndSwap(old, &next) {
			return next, true
		}
	}
}

func refill(old bucketState, nowNS int64, rule Rule) bucketState {
	next := old
	if nowNS < next.lastRefillNS {
		next.lastRefillNS = nowNS
		return next
	}
	elapsed := nowNS - next.lastRefillNS
	if elapsed <= 0 {
		return next
	}
	capacity := int64(rule.Burst) * tokenScale
	if next.tokens >= capacity {
		next.tokens = capacity
		next.lastRefillNS = nowNS
		return next
	}
	refillNumerator := int64(rule.RefillPerMinute) * tokenScale
	elapsedToFull := (capacity - next.tokens) * int64(time.Minute) / refillNumerator
	if elapsed >= elapsedToFull {
		next.tokens = capacity
		next.lastRefillNS = nowNS
		return next
	}
	added := elapsed * refillNumerator / int64(time.Minute)
	if added > 0 {
		next.tokens += added
		if next.tokens > capacity {
			next.tokens = capacity
		}
		next.lastRefillNS = nowNS
	}
	return next
}

func sameState(a, b bucketState) bool {
	return a.tokens == b.tokens && a.lastRefillNS == b.lastRefillNS && a.lastSeenNS == b.lastSeenNS
}

func ruleMatches(rule Rule, action normalize.NormalizedAction) bool {
	if !matchOptional(rule.Principal, action.Principal) {
		return false
	}
	if !matchOptional(rule.ActionType, action.ActionType) {
		return false
	}
	if strings.TrimSpace(rule.Resource) == "" {
		return true
	}
	ok, err := normalize.MatchPattern(rule.Resource, action.Resource)
	return err == nil && ok
}

func matchOptional(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	return pattern == strings.TrimSpace(value)
}

func bucketKey(rule Rule, action normalize.NormalizedAction) string {
	switch rule.Scope {
	case ScopePrincipalAction:
		return "principal_action|" + rule.ID + "|" + action.Principal + "|" + action.ActionType
	case ScopePrincipalResource:
		return "principal_resource|" + rule.ID + "|" + action.Principal + "|" + action.Resource
	case ScopeGlobalTool:
		return "global_tool|" + rule.ID + "|" + action.ActionType
	default:
		return "unknown|" + rule.ID
	}
}

func validateRules(rules []Rule) error {
	seen := map[string]struct{}{}
	for i, rule := range rules {
		rule.ID = strings.TrimSpace(rule.ID)
		if rule.ID == "" {
			return errors.New("rate limit rule id is required")
		}
		if _, exists := seen[rule.ID]; exists {
			return errors.New("rate limit rule ids must be unique")
		}
		seen[rule.ID] = struct{}{}
		if strings.TrimSpace(rule.Scope) == "" {
			return errors.New("rate limit rule scope is required")
		}
		switch rule.Scope {
		case ScopePrincipalAction:
			if strings.TrimSpace(rule.ActionType) == "" {
				return errors.New("principal_action rate limit rules require action_type")
			}
		case ScopePrincipalResource:
			if strings.TrimSpace(rule.Resource) == "" {
				return errors.New("principal_resource rate limit rules require resource")
			}
		case ScopeGlobalTool:
			if strings.TrimSpace(rule.ActionType) == "" {
				return errors.New("global_tool rate limit rules require action_type")
			}
		default:
			return errors.New("rate limit rule scope must be principal_action, principal_resource, or global_tool")
		}
		if rule.Burst <= 0 {
			return errors.New("rate limit rule burst must be > 0")
		}
		if rule.RefillPerMinute <= 0 {
			return errors.New("rate limit rule refill_per_minute must be > 0")
		}
		rules[i].ID = rule.ID
	}
	return nil
}
