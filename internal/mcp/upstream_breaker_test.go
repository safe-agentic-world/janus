package mcp

import (
	"errors"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/telemetry"
)

type breakerClock struct {
	now time.Time
}

func (c *breakerClock) Now() time.Time { return c.now }

func (c *breakerClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

type breakerTelemetrySink struct {
	events []telemetry.Event
}

func (s *breakerTelemetrySink) ExportEvent(event telemetry.Event) error {
	s.events = append(s.events, event)
	return nil
}

func (s *breakerTelemetrySink) ExportMetric(telemetry.Metric) error { return nil }

func TestUpstreamBreakerClosedToOpenUnderThresholdBreach(t *testing.T) {
	clock := &breakerClock{now: time.Unix(100, 0)}
	sink := &breakerTelemetrySink{}
	breaker := newUpstreamBreaker("retail", testBreakerConfig(), clock.Now, telemetry.NewEmitter(sink))

	for i := 0; i < 2; i++ {
		permit, err := breaker.beforeCall()
		if err != nil {
			t.Fatalf("before failure %d: %v", i, err)
		}
		breaker.afterCall(permit, errors.New("transport reset"))
	}
	snapshot := breaker.snapshot()
	if snapshot.State != upstreamBreakerOpen || snapshot.LastFailure != upstreamFailureTransport {
		t.Fatalf("expected open breaker after threshold breach, got %+v", snapshot)
	}
	if len(sink.events) == 0 || sink.events[len(sink.events)-1].Status != upstreamBreakerOpen {
		t.Fatalf("expected open transition telemetry, got %+v", sink.events)
	}
}

func TestUpstreamBreakerOpenHalfOpenClosedRecovery(t *testing.T) {
	clock := &breakerClock{now: time.Unix(100, 0)}
	breaker := newUpstreamBreaker("retail", testBreakerConfig(), clock.Now, nil)

	for i := 0; i < 2; i++ {
		permit, err := breaker.beforeCall()
		if err != nil {
			t.Fatalf("before failure %d: %v", i, err)
		}
		breaker.afterCall(permit, errors.New("upstream transport closed"))
	}
	if _, err := breaker.beforeCall(); !errors.Is(err, errUpstreamUnavailable) {
		t.Fatalf("expected open breaker to fast-fail, got %v", err)
	}
	clock.Advance(time.Second)
	probe, err := breaker.beforeCall()
	if err != nil {
		t.Fatalf("expected half-open probe permit, got %v", err)
	}
	if snapshot := breaker.snapshot(); snapshot.State != upstreamBreakerHalfOpen || !snapshot.ProbeInFlight {
		t.Fatalf("expected half-open in-flight probe, got %+v", snapshot)
	}
	breaker.afterCall(probe, nil)
	if snapshot := breaker.snapshot(); snapshot.State != upstreamBreakerClosed || snapshot.FailuresInWindow != 0 {
		t.Fatalf("expected successful probe to close breaker, got %+v", snapshot)
	}
}

func TestUpstreamBreakerHalfOpenProbeConcurrencyCap(t *testing.T) {
	clock := &breakerClock{now: time.Unix(100, 0)}
	breaker := newUpstreamBreaker("retail", testBreakerConfig(), clock.Now, nil)
	for i := 0; i < 2; i++ {
		permit, err := breaker.beforeCall()
		if err != nil {
			t.Fatalf("before failure %d: %v", i, err)
		}
		breaker.afterCall(permit, errUpstreamTimeout)
	}
	clock.Advance(time.Second)
	probe, err := breaker.beforeCall()
	if err != nil {
		t.Fatalf("expected first half-open probe, got %v", err)
	}
	if _, err := breaker.beforeCall(); !errors.Is(err, errUpstreamUnavailable) {
		t.Fatalf("expected second half-open call to fast-fail, got %v", err)
	}
	breaker.afterCall(probe, nil)
}

func TestUpstreamBreakerApplicationErrorsDoNotTrip(t *testing.T) {
	clock := &breakerClock{now: time.Unix(100, 0)}
	breaker := newUpstreamBreaker("retail", testBreakerConfig(), clock.Now, nil)
	for i := 0; i < 10; i++ {
		permit, err := breaker.beforeCall()
		if err != nil {
			t.Fatalf("before application error %d: %v", i, err)
		}
		breaker.afterCall(permit, newUpstreamApplicationError(&rpcError{Code: -32602, Message: "bad request"}))
	}
	if snapshot := breaker.snapshot(); snapshot.State != upstreamBreakerClosed || snapshot.FailuresInWindow != 0 {
		t.Fatalf("application errors must not trip breaker, got %+v", snapshot)
	}
}

func TestUpstreamBreakerFailuresAreWindowed(t *testing.T) {
	clock := &breakerClock{now: time.Unix(100, 0)}
	breaker := newUpstreamBreaker("retail", testBreakerConfig(), clock.Now, nil)

	permit, err := breaker.beforeCall()
	if err != nil {
		t.Fatalf("first failure permit: %v", err)
	}
	breaker.afterCall(permit, errors.New("transport reset"))
	clock.Advance(11 * time.Second)
	permit, err = breaker.beforeCall()
	if err != nil {
		t.Fatalf("second failure permit: %v", err)
	}
	breaker.afterCall(permit, errors.New("transport reset"))
	if snapshot := breaker.snapshot(); snapshot.State != upstreamBreakerClosed || snapshot.FailuresInWindow != 1 {
		t.Fatalf("expected expired failure to be pruned, got %+v", snapshot)
	}

	permit, err = breaker.beforeCall()
	if err != nil {
		t.Fatalf("third failure permit: %v", err)
	}
	breaker.afterCall(permit, errors.New("transport reset"))
	if snapshot := breaker.snapshot(); snapshot.State != upstreamBreakerOpen {
		t.Fatalf("expected in-window failures to open breaker, got %+v", snapshot)
	}
}

func TestUpstreamBreakerDisabledDoesNotTrip(t *testing.T) {
	clock := &breakerClock{now: time.Unix(100, 0)}
	breaker := newUpstreamBreaker("retail", upstreamBreakerConfig{Enabled: false}, clock.Now, nil)
	for i := 0; i < 10; i++ {
		permit, err := breaker.beforeCall()
		if err != nil {
			t.Fatalf("disabled breaker should not fast-fail: %v", err)
		}
		breaker.afterCall(permit, errors.New("transport reset"))
	}
	if snapshot := breaker.snapshot(); snapshot.State != upstreamBreakerDisabled || snapshot.FailuresInWindow != 0 {
		t.Fatalf("disabled breaker should preserve current behavior, got %+v", snapshot)
	}
}

func testBreakerConfig() upstreamBreakerConfig {
	return upstreamBreakerConfig{
		Enabled:          true,
		FailureThreshold: 2,
		FailureWindow:    10 * time.Second,
		OpenTimeout:      time.Second,
	}
}
