package gateway

import (
	"time"

	"github.com/safe-agentic-world/nomos/internal/ratelimit"
)

func buildActionRateLimiter(cfg Config, now func() time.Time) (*ratelimit.Limiter, error) {
	if !cfg.RateLimits.Enabled && !cfg.RateLimits.hasRules() {
		return nil, nil
	}
	rules, err := cfg.RateLimits.Rules()
	if err != nil {
		return nil, err
	}
	evictAfter := time.Duration(cfg.RateLimits.EvictAfterSeconds) * time.Second
	return ratelimit.New(ratelimit.Config{
		Enabled:    cfg.RateLimits.Enabled || len(rules) > 0,
		EvictAfter: evictAfter,
		Rules:      rules,
		Now:        now,
	})
}
