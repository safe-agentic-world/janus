package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/credentials"
	"github.com/safe-agentic-world/nomos/internal/identity"
)

const (
	upstreamCredentialModeBearer = "bearer"
	upstreamCredentialModeHeader = "header"
	upstreamCredentialModeEnv    = "env"
	upstreamCredentialModeFile   = "file"

	defaultUpstreamCredentialRefreshBefore = 30 * time.Second
)

type UpstreamCredentialBroker interface {
	Checkout(secretID, principal, agent, environment, traceID string) (credentials.Lease, error)
	MaterializeValue(leaseID, principal, agent, environment, traceID string) (string, error)
	Release(leaseID string) error
}

type upstreamCredentialMaterial struct {
	LeaseID          string
	Headers          map[string]string
	Env              map[string]string
	AcquiredAt       time.Time
	ExpiresAt        time.Time
	RestartOnRefresh bool
}

type upstreamCredentialManager struct {
	mu       sync.Mutex
	config   UpstreamCredentialsConfig
	broker   UpstreamCredentialBroker
	identity identity.VerifiedIdentity
	recorder audit.Recorder
	clock    func() time.Time

	serverName string
	sessionID  string

	current upstreamCredentialMaterial
	fileDir string
}

func newUpstreamCredentialManager(config UpstreamServerConfig, id identity.VerifiedIdentity, broker UpstreamCredentialBroker, recorder audit.Recorder, clock func() time.Time) *upstreamCredentialManager {
	if config.Credentials == nil {
		return nil
	}
	if clock == nil {
		clock = time.Now
	}
	return &upstreamCredentialManager{
		config:     *config.Credentials,
		broker:     broker,
		identity:   id,
		recorder:   recorder,
		clock:      clock,
		serverName: strings.TrimSpace(config.Name),
		sessionID:  upstreamCredentialSessionID(id, config.Name),
	}
}

func upstreamCredentialSessionID(id identity.VerifiedIdentity, serverName string) string {
	parts := []string{
		"mcp_upstream",
		strings.TrimSpace(id.Principal),
		strings.TrimSpace(id.Agent),
		strings.TrimSpace(id.Environment),
		strings.TrimSpace(serverName),
	}
	for i, part := range parts {
		parts[i] = strings.ReplaceAll(part, ":", "_")
	}
	return strings.Join(parts, ":")
}

func (m *upstreamCredentialManager) ensure() (upstreamCredentialMaterial, bool, error) {
	if m == nil {
		return upstreamCredentialMaterial{}, false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock().UTC()
	if m.current.LeaseID != "" && now.Before(m.refreshAtLocked()) {
		return cloneUpstreamCredentialMaterial(m.current), false, nil
	}
	if m.broker == nil {
		return upstreamCredentialMaterial{}, false, errUpstreamCredentialUnavailable
	}
	profile := strings.TrimSpace(m.config.Profile)
	if profile == "" {
		return upstreamCredentialMaterial{}, false, errUpstreamCredentialUnavailable
	}
	event := "acquired"
	if m.current.LeaseID != "" {
		event = "refreshed"
	}
	lease, err := m.broker.Checkout(profile, m.identity.Principal, m.identity.Agent, m.identity.Environment, m.sessionID)
	if err != nil {
		return upstreamCredentialMaterial{}, false, errUpstreamCredentialUnavailable
	}
	value, err := m.broker.MaterializeValue(lease.ID, m.identity.Principal, m.identity.Agent, m.identity.Environment, m.sessionID)
	if err != nil {
		_ = m.broker.Release(lease.ID)
		return upstreamCredentialMaterial{}, false, errUpstreamCredentialUnavailable
	}
	material, err := m.materialFromValueLocked(lease, value)
	if err != nil {
		_ = m.broker.Release(lease.ID)
		return upstreamCredentialMaterial{}, false, errUpstreamCredentialUnavailable
	}
	previousLeaseID := m.current.LeaseID
	m.current = material
	m.recordLease(event, material.LeaseID)
	if previousLeaseID != "" && previousLeaseID != material.LeaseID {
		_ = m.broker.Release(previousLeaseID)
	}
	return cloneUpstreamCredentialMaterial(m.current), true, nil
}

func (m *upstreamCredentialManager) materialFromValueLocked(lease credentials.Lease, value string) (upstreamCredentialMaterial, error) {
	material := upstreamCredentialMaterial{
		LeaseID:    lease.ID,
		Headers:    map[string]string{},
		Env:        map[string]string{},
		AcquiredAt: m.clock().UTC(),
		ExpiresAt:  lease.ExpiresAt.UTC(),
	}
	switch strings.TrimSpace(m.config.Mode) {
	case upstreamCredentialModeBearer:
		material.Headers["Authorization"] = "Bearer " + value
	case upstreamCredentialModeHeader:
		header := strings.TrimSpace(m.config.Header)
		if header == "" {
			return upstreamCredentialMaterial{}, errUpstreamCredentialUnavailable
		}
		material.Headers[header] = value
	case upstreamCredentialModeEnv:
		envKey := strings.TrimSpace(m.config.Env)
		if envKey == "" {
			return upstreamCredentialMaterial{}, errUpstreamCredentialUnavailable
		}
		material.Env[envKey] = value
		material.RestartOnRefresh = true
	case upstreamCredentialModeFile:
		envKey := strings.TrimSpace(m.config.Env)
		if envKey == "" {
			return upstreamCredentialMaterial{}, errUpstreamCredentialUnavailable
		}
		path, err := m.writeCredentialFileLocked(value)
		if err != nil {
			return upstreamCredentialMaterial{}, err
		}
		material.Env[envKey] = path
	default:
		return upstreamCredentialMaterial{}, errUpstreamCredentialUnavailable
	}
	return material, nil
}

func (m *upstreamCredentialManager) writeCredentialFileLocked(value string) (string, error) {
	if m.fileDir == "" {
		dir, err := os.MkdirTemp("", "nomos-upstream-credential-*")
		if err != nil {
			return "", err
		}
		m.fileDir = dir
	}
	name := strings.TrimSpace(m.config.FileName)
	if name == "" {
		name = "credential"
	}
	name = filepath.Base(name)
	if name == "." || name == string(filepath.Separator) || strings.TrimSpace(name) == "" {
		name = "credential"
	}
	path := filepath.Join(m.fileDir, name)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func (m *upstreamCredentialManager) refreshAtLocked() time.Time {
	refreshBefore := m.config.RefreshBeforeExpiry
	if refreshBefore <= 0 {
		refreshBefore = defaultUpstreamCredentialRefreshBefore
	}
	if m.current.ExpiresAt.IsZero() {
		return time.Time{}
	}
	if ttl := m.current.ExpiresAt.Sub(m.current.AcquiredAt); ttl > 0 && refreshBefore >= ttl {
		refreshBefore = ttl / 2
	}
	return m.current.ExpiresAt.Add(-refreshBefore)
}

func (m *upstreamCredentialManager) recordLease(event, leaseID string) {
	if m.recorder == nil || strings.TrimSpace(leaseID) == "" {
		return
	}
	_ = m.recorder.WriteEvent(audit.Event{
		SchemaVersion: "v1",
		Timestamp:     m.clock().UTC(),
		EventType:     "mcp.upstream_credential_lease",
		TraceID:       m.sessionID,
		ActionID:      "mcp_upstream_" + m.serverName,
		Principal:     m.identity.Principal,
		Agent:         m.identity.Agent,
		Environment:   m.identity.Environment,
		ActionType:    "mcp.upstream.credentials",
		Resource:      "mcp://" + m.serverName,
		CredentialLeaseIDs: []string{
			leaseID,
		},
		ExecutorMetadata: map[string]any{
			"upstream_server": m.serverName,
			"session_id":      m.sessionID,
			"lease_event":     event,
		},
	})
}

func (m *upstreamCredentialManager) close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	leaseID := m.current.LeaseID
	fileDir := m.fileDir
	m.current = upstreamCredentialMaterial{}
	m.fileDir = ""
	m.mu.Unlock()
	if leaseID != "" && m.broker != nil {
		_ = m.broker.Release(leaseID)
	}
	if fileDir != "" {
		_ = os.RemoveAll(fileDir)
	}
}

func cloneUpstreamCredentialMaterial(in upstreamCredentialMaterial) upstreamCredentialMaterial {
	out := in
	out.Headers = cloneStringMap(in.Headers)
	out.Env = cloneStringMap(in.Env)
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func upstreamConfigWithCredentialMaterial(config UpstreamServerConfig, material upstreamCredentialMaterial) UpstreamServerConfig {
	if len(material.Headers) > 0 {
		config.CredentialHeaders = cloneStringMap(material.Headers)
	}
	if len(material.Env) > 0 {
		env := cloneStringMap(config.Env)
		if env == nil {
			env = map[string]string{}
		}
		for k, v := range material.Env {
			env[k] = v
		}
		config.Env = env
	}
	return config
}
