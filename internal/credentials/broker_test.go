package credentials

import (
	"testing"
	"time"
)

func TestBrokerCheckoutAndMaterializeBinding(t *testing.T) {
	now := time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC)
	b, err := NewBroker([]Secret{{ID: "s1", EnvKey: "API_TOKEN", Value: "v1", TTLSeconds: 60}}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	lease, err := b.Checkout("s1", "p1", "a1", "dev", "t1")
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	env, _, err := b.MaterializeEnv([]string{lease.ID}, []string{"API_TOKEN"}, "p1", "a1", "dev", "t1")
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if env["API_TOKEN"] != "v1" {
		t.Fatalf("unexpected env value: %v", env)
	}
	value, err := b.MaterializeValue(lease.ID, "p1", "a1", "dev", "t1")
	if err != nil {
		t.Fatalf("materialize value: %v", err)
	}
	if value != "v1" {
		t.Fatalf("unexpected materialized value: %q", value)
	}
	if _, _, err := b.MaterializeEnv([]string{lease.ID}, []string{"API_TOKEN"}, "p1", "a1", "dev", "other"); err == nil {
		t.Fatal("expected binding mismatch error")
	}
	if err := b.Release(lease.ID); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := b.MaterializeValue(lease.ID, "p1", "a1", "dev", "t1"); err == nil {
		t.Fatal("expected released lease to be unavailable")
	}
}

func TestBrokerLeaseExpiry(t *testing.T) {
	now := time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC)
	b, err := NewBroker([]Secret{{ID: "s1", EnvKey: "API_TOKEN", Value: "v1", TTLSeconds: 1}}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("new broker: %v", err)
	}
	lease, err := b.Checkout("s1", "p1", "a1", "dev", "t1")
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	now = now.Add(2 * time.Second)
	if _, _, err := b.MaterializeEnv([]string{lease.ID}, []string{"API_TOKEN"}, "p1", "a1", "dev", "t1"); err == nil {
		t.Fatal("expected expiry error")
	}
}
