package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/credentials"
	"github.com/safe-agentic-world/nomos/internal/identity"
)

type fakeUpstreamCredentialBroker struct {
	mu             sync.Mutex
	values         []string
	expiries       []time.Time
	checkoutErr    error
	materializeErr error
	checkouts      []fakeCredentialCheckout
	releases       []string
	leases         map[string]fakeCredentialLease
}

type fakeCredentialCheckout struct {
	SecretID    string
	Principal   string
	Agent       string
	Environment string
	TraceID     string
}

type fakeCredentialLease struct {
	lease credentials.Lease
	value string
}

func newFakeUpstreamCredentialBroker(values ...string) *fakeUpstreamCredentialBroker {
	return &fakeUpstreamCredentialBroker{
		values: values,
		leases: map[string]fakeCredentialLease{},
	}
}

func (b *fakeUpstreamCredentialBroker) Checkout(secretID, principal, agent, environment, traceID string) (credentials.Lease, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.checkoutErr != nil {
		return credentials.Lease{}, b.checkoutErr
	}
	idx := len(b.checkouts)
	value := "broker-token"
	if idx < len(b.values) {
		value = b.values[idx]
	} else if len(b.values) > 0 {
		value = b.values[len(b.values)-1]
	}
	expiresAt := time.Now().UTC().Add(time.Hour)
	if idx < len(b.expiries) && !b.expiries[idx].IsZero() {
		expiresAt = b.expiries[idx].UTC()
	}
	lease := credentials.Lease{
		ID:          fmt.Sprintf("lease-%d", idx+1),
		SecretID:    secretID,
		Principal:   principal,
		Agent:       agent,
		Environment: environment,
		TraceID:     traceID,
		ExpiresAt:   expiresAt,
	}
	b.checkouts = append(b.checkouts, fakeCredentialCheckout{
		SecretID:    secretID,
		Principal:   principal,
		Agent:       agent,
		Environment: environment,
		TraceID:     traceID,
	})
	b.leases[lease.ID] = fakeCredentialLease{lease: lease, value: value}
	return lease, nil
}

func (b *fakeUpstreamCredentialBroker) MaterializeValue(leaseID, principal, agent, environment, traceID string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.materializeErr != nil {
		return "", b.materializeErr
	}
	leased, ok := b.leases[leaseID]
	if !ok {
		return "", errors.New("lease not found")
	}
	lease := leased.lease
	if lease.Principal != principal || lease.Agent != agent || lease.Environment != environment || lease.TraceID != traceID {
		return "", errors.New("binding mismatch")
	}
	return leased.value, nil
}

func (b *fakeUpstreamCredentialBroker) Release(leaseID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.releases = append(b.releases, leaseID)
	delete(b.leases, leaseID)
	return nil
}

func (b *fakeUpstreamCredentialBroker) checkoutSnapshot() []fakeCredentialCheckout {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]fakeCredentialCheckout, len(b.checkouts))
	copy(out, b.checkouts)
	return out
}

func newCredentialUpstreamServer(t *testing.T, upstream UpstreamServerConfig, broker UpstreamCredentialBroker, recorder audit.Recorder, errWriter io.Writer) (*Server, error) {
	t.Helper()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(retailAllowBundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if errWriter == nil {
		errWriter = io.Discard
	}
	return NewServerWithRuntimeOptionsAndRecorder(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:         "debug",
		LogFormat:        "text",
		ErrWriter:        errWriter,
		UpstreamServers:  []UpstreamServerConfig{upstream},
		CredentialBroker: broker,
	}, recorder)
}

func TestUpstreamBrokeredBearerCredentialInjectsHeader(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	upstream.requireAuth("Authorization", "Bearer broker-token")
	broker := newFakeUpstreamCredentialBroker("broker-token")
	server, err := newCredentialUpstreamServer(t, UpstreamServerConfig{
		Name:        "retail",
		Transport:   "streamable_http",
		Endpoint:    upstream.endpoint(),
		TLSInsecure: true,
		Credentials: &UpstreamCredentialsConfig{
			Profile: "retail_token",
			Mode:    "bearer",
		},
	}, broker, nil, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleRequest(Request{
		ID:     "brokered-auth",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected response error: %+v", resp)
	}
	if upstream.authCalls.Load() == 0 {
		t.Fatal("expected upstream to receive brokered Authorization header")
	}
	checkouts := broker.checkoutSnapshot()
	if len(checkouts) != 1 {
		t.Fatalf("expected one lease checkout, got %d", len(checkouts))
	}
	if checkouts[0].SecretID != "retail_token" || checkouts[0].Principal != "system" || !strings.Contains(checkouts[0].TraceID, "retail") {
		t.Fatalf("unexpected checkout binding: %+v", checkouts[0])
	}
}

func TestUpstreamBrokeredCredentialRefreshUpdatesHTTPHeaderAndAuditsLeaseIDs(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	upstream.requireAuth("Authorization", "Bearer token-1")
	recorder := &recordingSink{}
	broker := newFakeUpstreamCredentialBroker("token-1", "token-2")
	broker.expiries = []time.Time{time.Now().Add(-time.Second), time.Now().Add(time.Hour)}

	server, err := newCredentialUpstreamServer(t, UpstreamServerConfig{
		Name:        "retail",
		Transport:   "streamable_http",
		Endpoint:    upstream.endpoint(),
		TLSInsecure: true,
		Credentials: &UpstreamCredentialsConfig{
			Profile: "retail_token",
			Mode:    "bearer",
		},
	}, broker, recorder, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	upstream.requireAuth("Authorization", "Bearer token-2")
	resp := server.handleRequest(Request{
		ID:     "refresh",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected response error after refresh: %+v", resp)
	}
	checkouts := broker.checkoutSnapshot()
	if len(checkouts) != 2 {
		t.Fatalf("expected initial checkout plus refresh, got %d", len(checkouts))
	}
	events := recorder.snapshot()
	var leaseEvents []audit.Event
	for _, event := range events {
		if event.EventType == "mcp.upstream_credential_lease" {
			leaseEvents = append(leaseEvents, event)
		}
	}
	if len(leaseEvents) != 2 {
		t.Fatalf("expected two credential lease audit events, got %d from %+v", len(leaseEvents), events)
	}
	if leaseEvents[0].CredentialLeaseIDs[0] != "lease-1" || leaseEvents[1].CredentialLeaseIDs[0] != "lease-2" {
		t.Fatalf("expected lease IDs only in audit, got %+v", leaseEvents)
	}
	payload, _ := json.Marshal(leaseEvents)
	if bytes.Contains(payload, []byte("token-1")) || bytes.Contains(payload, []byte("token-2")) {
		t.Fatalf("raw credential leaked in lease audit events: %s", payload)
	}
}

func TestUpstreamCredentialRefreshUsesInjectedClock(t *testing.T) {
	base := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)
	now := base
	broker := newFakeUpstreamCredentialBroker("token-1", "token-2")
	broker.expiries = []time.Time{base.Add(10 * time.Second), base.Add(20 * time.Second)}
	manager := newUpstreamCredentialManager(UpstreamServerConfig{
		Name: "retail",
		Credentials: &UpstreamCredentialsConfig{
			Profile:             "retail_token",
			Mode:                "bearer",
			RefreshBeforeExpiry: 5 * time.Second,
		},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, broker, nil, func() time.Time { return now })
	t.Cleanup(manager.close)

	if _, refreshed, err := manager.ensure(); err != nil || !refreshed {
		t.Fatalf("expected initial acquisition, refreshed=%v err=%v", refreshed, err)
	}
	now = base.Add(4 * time.Second)
	if _, refreshed, err := manager.ensure(); err != nil || refreshed {
		t.Fatalf("expected no refresh before refresh window, refreshed=%v err=%v", refreshed, err)
	}
	now = base.Add(5 * time.Second)
	if _, refreshed, err := manager.ensure(); err != nil || !refreshed {
		t.Fatalf("expected refresh at injected-clock boundary, refreshed=%v err=%v", refreshed, err)
	}
	if got := len(broker.checkoutSnapshot()); got != 2 {
		t.Fatalf("expected two checkouts, got %d", got)
	}
}

func TestUpstreamCredentialEnvInjectionUsesExplicitStdioEnvironment(t *testing.T) {
	broker := newFakeUpstreamCredentialBroker("env-token")
	manager := newUpstreamCredentialManager(UpstreamServerConfig{
		Name: "retail",
		Credentials: &UpstreamCredentialsConfig{
			Profile: "retail_token",
			Mode:    "env",
			Env:     "RETAIL_TOKEN",
		},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, broker, nil, nil)
	t.Cleanup(manager.close)

	material, refreshed, err := manager.ensure()
	if err != nil || !refreshed {
		t.Fatalf("expected env credential material, refreshed=%v err=%v", refreshed, err)
	}
	config := upstreamConfigWithCredentialMaterial(UpstreamServerConfig{
		EnvAllowlist: []string{"PATH"},
		Env:          map[string]string{"STATIC_ENV": "static"},
	}, material)
	env, _ := buildUpstreamEnvironment(config)
	envMap := map[string]string{}
	for _, entry := range env {
		key, value, _ := strings.Cut(entry, "=")
		envMap[key] = value
	}
	if envMap["RETAIL_TOKEN"] != "env-token" || envMap["STATIC_ENV"] != "static" {
		t.Fatalf("expected explicit brokered env injection, got %+v", envMap)
	}
}

func TestUpstreamCredentialFileInjectionWritesManagedSecretFile(t *testing.T) {
	broker := newFakeUpstreamCredentialBroker("file-token")
	manager := newUpstreamCredentialManager(UpstreamServerConfig{
		Name: "retail",
		Credentials: &UpstreamCredentialsConfig{
			Profile:  "retail_token",
			Mode:     "file",
			Env:      "RETAIL_TOKEN_FILE",
			FileName: "token.txt",
		},
	}, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, broker, nil, nil)

	material, refreshed, err := manager.ensure()
	if err != nil || !refreshed {
		t.Fatalf("expected file credential material, refreshed=%v err=%v", refreshed, err)
	}
	path := material.Env["RETAIL_TOKEN_FILE"]
	if path == "" {
		t.Fatalf("expected file path env injection, got %+v", material.Env)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read credential file: %v", err)
	}
	if string(data) != "file-token" {
		t.Fatalf("unexpected credential file content: %q", string(data))
	}
	manager.close()
	if _, err := os.Stat(path); err == nil {
		t.Fatal("expected managed credential file to be removed on close")
	}
}

func TestUpstreamBrokeredCredentialAcquisitionFailureFailsClosed(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	broker := newFakeUpstreamCredentialBroker()
	broker.checkoutErr = errors.New("backend failed with raw-secret-never-surface")

	_, err := newCredentialUpstreamServer(t, UpstreamServerConfig{
		Name:        "retail",
		Transport:   "streamable_http",
		Endpoint:    upstream.endpoint(),
		TLSInsecure: true,
		Credentials: &UpstreamCredentialsConfig{
			Profile: "retail_token",
			Mode:    "bearer",
		},
	}, broker, nil, nil)
	if err == nil {
		t.Fatal("expected credential acquisition failure")
	}
	if !strings.Contains(err.Error(), "UPSTREAM_CREDENTIAL_UNAVAILABLE") {
		t.Fatalf("expected stable credential error, got %v", err)
	}
	if strings.Contains(err.Error(), "raw-secret-never-surface") {
		t.Fatalf("raw backend error leaked: %v", err)
	}
	if upstream.callCount.Load() != 0 {
		t.Fatal("upstream should not be called after credential acquisition failure")
	}
}

func TestUpstreamBrokeredCredentialRefreshFailureOpensBreaker(t *testing.T) {
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	upstream.requireAuth("Authorization", "Bearer token-1")
	broker := newFakeUpstreamCredentialBroker("token-1")
	broker.expiries = []time.Time{time.Now().Add(-time.Second)}

	server, err := newCredentialUpstreamServer(t, UpstreamServerConfig{
		Name:           "retail",
		Transport:      "streamable_http",
		Endpoint:       upstream.endpoint(),
		TLSInsecure:    true,
		BreakerEnabled: true,
		Credentials: &UpstreamCredentialsConfig{
			Profile: "retail_token",
			Mode:    "bearer",
		},
	}, broker, nil, nil)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	broker.mu.Lock()
	broker.checkoutErr = errors.New("backend unavailable with raw-secret-never-surface")
	broker.mu.Unlock()

	resp := server.handleRequest(Request{
		ID:     "refresh-fail",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001"}),
	})
	if resp.Error != "UPSTREAM_CREDENTIAL_UNAVAILABLE" {
		t.Fatalf("expected credential refresh failure, got %+v", resp)
	}
	snapshot := server.upstream.sessionForTest("retail").breakerSnapshot()
	if snapshot.State != upstreamBreakerOpen || snapshot.LastFailure != upstreamFailureCredential {
		t.Fatalf("expected breaker-open credential state, got %+v", snapshot)
	}
}

func TestUpstreamBrokeredCredentialRedactionProof(t *testing.T) {
	const rawCredential = "raw-broker-secret-54321"
	upstream := newUpstreamHTTPTestServer(t, false, "plaintext")
	upstream.requireAuth("Authorization", "Bearer "+rawCredential)
	recorder := &recordingSink{}
	var logs bytes.Buffer
	broker := newFakeUpstreamCredentialBroker(rawCredential)

	server, err := newCredentialUpstreamServer(t, UpstreamServerConfig{
		Name:        "retail",
		Transport:   "streamable_http",
		Endpoint:    upstream.endpoint(),
		TLSInsecure: true,
		Credentials: &UpstreamCredentialsConfig{
			Profile: "retail_token",
			Mode:    "bearer",
		},
	}, broker, recorder, &logs)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	resp := server.handleRequest(Request{
		ID:     "redaction",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1001"}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected response error: %+v", resp)
	}
	respPayload, _ := json.Marshal(resp)
	eventPayload, _ := json.Marshal(recorder.snapshot())
	surfaces := string(respPayload) + "\n" + string(eventPayload) + "\n" + logs.String()
	if strings.Contains(surfaces, rawCredential) {
		t.Fatalf("raw credential leaked in output surface: %s", surfaces)
	}
}
