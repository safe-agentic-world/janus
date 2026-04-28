package mcp

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/safe-agentic-world/nomos/internal/telemetry"
)

const (
	upstreamBreakerDisabled = "disabled"
	upstreamBreakerClosed   = "closed"
	upstreamBreakerOpen     = "open"
	upstreamBreakerHalfOpen = "half-open"
)

const (
	upstreamFailureNone        = "none"
	upstreamFailureTransport   = "transport"
	upstreamFailureProtocol    = "protocol"
	upstreamFailureApplication = "application"
	upstreamFailureTimeout     = "timeout"
	upstreamFailureCanceled    = "canceled"
)

type upstreamBreakerConfig struct {
	Enabled          bool
	FailureThreshold int
	FailureWindow    time.Duration
	OpenTimeout      time.Duration
}

type upstreamBreaker struct {
	server  string
	config  upstreamBreakerConfig
	clock   func() time.Time
	emitter *telemetry.Emitter

	mu             sync.Mutex
	state          string
	failures       []time.Time
	openUntil      time.Time
	probeInFlight  bool
	lastFailure    string
	lastTransition time.Time
}

type upstreamBreakerPermit struct {
	probe bool
}

type upstreamBreakerSnapshot struct {
	Server           string
	State            string
	FailureThreshold int
	FailureWindowMS  int64
	OpenTimeoutMS    int64
	FailuresInWindow int
	ProbeInFlight    bool
	LastFailure      string
	OpenUntil        time.Time
	Enabled          bool
}

func newUpstreamBreaker(server string, config upstreamBreakerConfig, clock func() time.Time, emitter *telemetry.Emitter) *upstreamBreaker {
	if clock == nil {
		clock = time.Now
	}
	config = normalizeUpstreamBreakerConfig(config)
	state := upstreamBreakerClosed
	if !config.Enabled {
		state = upstreamBreakerDisabled
	}
	return &upstreamBreaker{
		server:  strings.TrimSpace(server),
		config:  config,
		clock:   clock,
		emitter: emitter,
		state:   state,
	}
}

func normalizeUpstreamBreakerConfig(config upstreamBreakerConfig) upstreamBreakerConfig {
	if !config.Enabled {
		return config
	}
	if config.FailureThreshold <= 0 {
		config.FailureThreshold = 5
	}
	if config.FailureWindow <= 0 {
		config.FailureWindow = time.Minute
	}
	if config.OpenTimeout <= 0 {
		config.OpenTimeout = 30 * time.Second
	}
	return config
}

func (b *upstreamBreaker) beforeCall() (upstreamBreakerPermit, error) {
	if b == nil || !b.config.Enabled {
		return upstreamBreakerPermit{}, nil
	}
	b.mu.Lock()
	now := b.clock().UTC()
	b.pruneLocked(now)
	var (
		permit     upstreamBreakerPermit
		err        error
		transition *telemetry.Event
	)
	switch b.state {
	case upstreamBreakerClosed:
		permit = upstreamBreakerPermit{}
	case upstreamBreakerOpen:
		if now.Before(b.openUntil) {
			err = errUpstreamUnavailable
			break
		}
		transition = b.transitionLocked(upstreamBreakerHalfOpen, upstreamFailureNone, now)
		b.probeInFlight = true
		permit = upstreamBreakerPermit{probe: true}
	case upstreamBreakerHalfOpen:
		if b.probeInFlight {
			err = errUpstreamUnavailable
			break
		}
		b.probeInFlight = true
		permit = upstreamBreakerPermit{probe: true}
	default:
		transition = b.transitionLocked(upstreamBreakerClosed, upstreamFailureNone, now)
		permit = upstreamBreakerPermit{}
	}
	b.mu.Unlock()
	b.emitTransition(transition)
	return permit, err
}

func (b *upstreamBreaker) afterCall(permit upstreamBreakerPermit, err error) {
	if b == nil || !b.config.Enabled {
		return
	}
	kind, contributes := classifyUpstreamBreakerFailure(err)
	b.mu.Lock()
	now := b.clock().UTC()
	b.pruneLocked(now)
	var transition *telemetry.Event
	if permit.probe {
		b.probeInFlight = false
		if contributes {
			transition = b.openLocked(kind, now)
		} else {
			transition = b.closeLocked(now)
		}
		b.mu.Unlock()
		b.emitTransition(transition)
		return
	}
	if !contributes {
		b.mu.Unlock()
		return
	}
	b.lastFailure = kind
	if b.state == upstreamBreakerHalfOpen {
		transition = b.openLocked(kind, now)
		b.mu.Unlock()
		b.emitTransition(transition)
		return
	}
	if b.state != upstreamBreakerClosed {
		b.mu.Unlock()
		return
	}
	b.failures = append(b.failures, now)
	if len(b.failures) >= b.config.FailureThreshold {
		transition = b.openLocked(kind, now)
	}
	b.mu.Unlock()
	b.emitTransition(transition)
}

func (b *upstreamBreaker) snapshot() upstreamBreakerSnapshot {
	if b == nil {
		return upstreamBreakerSnapshot{State: upstreamBreakerDisabled}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock().UTC()
	b.pruneLocked(now)
	return upstreamBreakerSnapshot{
		Server:           b.server,
		State:            b.state,
		FailureThreshold: b.config.FailureThreshold,
		FailureWindowMS:  b.config.FailureWindow.Milliseconds(),
		OpenTimeoutMS:    b.config.OpenTimeout.Milliseconds(),
		FailuresInWindow: len(b.failures),
		ProbeInFlight:    b.probeInFlight,
		LastFailure:      b.lastFailure,
		OpenUntil:        b.openUntil,
		Enabled:          b.config.Enabled,
	}
}

func (b *upstreamBreaker) pruneLocked(now time.Time) {
	if b.config.FailureWindow <= 0 || len(b.failures) == 0 {
		return
	}
	cutoff := now.Add(-b.config.FailureWindow)
	keep := 0
	for _, failure := range b.failures {
		if !failure.Before(cutoff) {
			b.failures[keep] = failure
			keep++
		}
	}
	b.failures = b.failures[:keep]
}

func (b *upstreamBreaker) openLocked(kind string, now time.Time) *telemetry.Event {
	b.failures = nil
	b.openUntil = now.Add(b.config.OpenTimeout)
	b.probeInFlight = false
	b.lastFailure = kind
	return b.transitionLocked(upstreamBreakerOpen, kind, now)
}

func (b *upstreamBreaker) closeLocked(now time.Time) *telemetry.Event {
	b.failures = nil
	b.openUntil = time.Time{}
	b.probeInFlight = false
	return b.transitionLocked(upstreamBreakerClosed, upstreamFailureNone, now)
}

func (b *upstreamBreaker) transitionLocked(next, kind string, now time.Time) *telemetry.Event {
	prev := b.state
	if prev == next {
		return nil
	}
	b.state = next
	b.lastTransition = now
	if b.emitter == nil || !b.emitter.Enabled() {
		return nil
	}
	event := telemetry.Event{
		SignalType:  "trace",
		EventName:   "mcp.upstream_breaker.transition",
		TraceID:     "mcp_upstream_" + b.server,
		Correlation: "mcp_upstream_" + b.server,
		Status:      next,
		Attributes: map[string]any{
			"upstream_server": b.server,
			"from_state":      prev,
			"to_state":        next,
			"failure_kind":    kind,
		},
	}
	return &event
}

func (b *upstreamBreaker) emitTransition(event *telemetry.Event) {
	if event == nil || b.emitter == nil {
		return
	}
	b.emitter.Event(*event)
}

func classifyUpstreamBreakerFailure(err error) (string, bool) {
	if err == nil {
		return upstreamFailureNone, false
	}
	var appErr *upstreamApplicationError
	if errors.As(err, &appErr) {
		return upstreamFailureApplication, false
	}
	switch {
	case errors.Is(err, errUpstreamTimeout):
		return upstreamFailureTimeout, true
	case errors.Is(err, errUpstreamCanceled):
		return upstreamFailureCanceled, false
	case errors.Is(err, errUpstreamClosed), errors.Is(err, errUpstreamUnavailable):
		return upstreamFailureTransport, true
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(msg, "invalid upstream"),
		strings.Contains(msg, "missing tools"),
		strings.Contains(msg, "missing name"),
		strings.Contains(msg, "unframable"),
		strings.Contains(msg, "invalid rpc"),
		strings.Contains(msg, "protocol"):
		return upstreamFailureProtocol, true
	case strings.Contains(msg, "timeout"):
		return upstreamFailureTimeout, true
	default:
		return upstreamFailureTransport, true
	}
}
