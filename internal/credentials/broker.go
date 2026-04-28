package credentials

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type Secret struct {
	ID         string
	EnvKey     string
	Value      string
	TTLSeconds int
}

type Lease struct {
	ID          string
	SecretID    string
	Principal   string
	Agent       string
	Environment string
	TraceID     string
	ExpiresAt   time.Time
}

type Broker struct {
	mu      sync.Mutex
	now     func() time.Time
	secrets map[string]Secret
	leases  map[string]Lease
}

func NewBroker(secrets []Secret, now func() time.Time) (*Broker, error) {
	if now == nil {
		now = time.Now
	}
	secretMap := map[string]Secret{}
	for _, s := range secrets {
		if s.ID == "" || s.EnvKey == "" || s.Value == "" {
			return nil, errors.New("secret id, env_key and value are required")
		}
		if s.TTLSeconds <= 0 {
			return nil, errors.New("secret ttl_seconds must be > 0")
		}
		secretMap[s.ID] = s
	}
	return &Broker{
		now:     now,
		secrets: secretMap,
		leases:  map[string]Lease{},
	}, nil
}

func (b *Broker) Checkout(secretID, principal, agent, environment, traceID string) (Lease, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	secret, ok := b.secrets[secretID]
	if !ok {
		return Lease{}, errors.New("secret not found")
	}
	id, err := newLeaseID()
	if err != nil {
		return Lease{}, err
	}
	lease := Lease{
		ID:          id,
		SecretID:    secretID,
		Principal:   principal,
		Agent:       agent,
		Environment: environment,
		TraceID:     traceID,
		ExpiresAt:   b.now().UTC().Add(time.Duration(secret.TTLSeconds) * time.Second),
	}
	b.leases[id] = lease
	return lease, nil
}

func (b *Broker) MaterializeEnv(leaseIDs []string, envAllowlist []string, principal, agent, environment, traceID string) (map[string]string, []string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	allowed := make(map[string]struct{}, len(envAllowlist))
	for _, key := range envAllowlist {
		allowed[key] = struct{}{}
	}
	env := map[string]string{}
	values := make([]string, 0)
	for _, id := range leaseIDs {
		lease, err := b.boundLeaseLocked(id, principal, agent, environment, traceID)
		if err != nil {
			return nil, nil, err
		}
		secret := b.secrets[lease.SecretID]
		if _, ok := allowed[secret.EnvKey]; ok {
			env[secret.EnvKey] = secret.Value
			values = append(values, secret.Value)
		}
	}
	return env, values, nil
}

func (b *Broker) MaterializeValue(leaseID, principal, agent, environment, traceID string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	lease, err := b.boundLeaseLocked(leaseID, principal, agent, environment, traceID)
	if err != nil {
		return "", err
	}
	return b.secrets[lease.SecretID].Value, nil
}

func (b *Broker) Release(leaseID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.leases, leaseID)
	return nil
}

func (b *Broker) boundLeaseLocked(leaseID, principal, agent, environment, traceID string) (Lease, error) {
	lease, ok := b.leases[leaseID]
	if !ok {
		return Lease{}, errors.New("credential lease not found")
	}
	if b.now().UTC().After(lease.ExpiresAt) {
		return Lease{}, errors.New("credential lease expired")
	}
	if lease.Principal != principal || lease.Agent != agent || lease.Environment != environment || lease.TraceID != traceID {
		return Lease{}, errors.New("credential lease binding mismatch")
	}
	return lease, nil
}

func newLeaseID() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "lease_" + hex.EncodeToString(buf), nil
}
