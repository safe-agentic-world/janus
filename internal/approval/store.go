package approval

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const (
	ScopeFingerprint = "fingerprint"
	ScopeClass       = "class"

	StatusPending  = "PENDING"
	StatusApproved = "APPROVED"
	StatusDenied   = "DENIED"
)

var (
	ErrNotFound         = errors.New("approval not found")
	ErrAlreadyFinalized = errors.New("approval already finalized")
	ErrExpired          = errors.New("approval expired")
)

type PendingRequest struct {
	Fingerprint string
	ScopeType   string
	ScopeKey    string
	TraceID     string
	ActionID    string
	ActionType  string
	Resource    string
	ParamsHash  string
	Principal   string
	Agent       string
	Environment string
}

type Record struct {
	ApprovalID  string
	Fingerprint string
	ScopeType   string
	ScopeKey    string
	Status      string
	TraceID     string
	ActionID    string
	ActionType  string
	Resource    string
	ParamsHash  string
	Principal   string
	Agent       string
	Environment string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	UpdatedAt   time.Time
}

type Store struct {
	db  *sql.DB
	now func() time.Time
	ttl time.Duration
}

func Open(path string, ttl time.Duration, now func() time.Time) (*Store, error) {
	if path == "" {
		return nil, errors.New("approval db path is required")
	}
	if ttl <= 0 {
		return nil, errors.New("approval ttl must be > 0")
	}
	if now == nil {
		now = time.Now
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	store := &Store{db: db, now: now, ttl: ttl}
	if err := store.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) init() error {
	schema := `
CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  scope_type TEXT NOT NULL,
  scope_key TEXT NOT NULL,
  status TEXT NOT NULL,
  trace_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  resource TEXT NOT NULL,
  params_hash TEXT NOT NULL,
  principal TEXT NOT NULL,
  agent TEXT NOT NULL,
  environment TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_fingerprint ON approvals(fingerprint);
CREATE INDEX IF NOT EXISTS idx_approvals_scope ON approvals(scope_type, scope_key);
`
	_, err := s.db.Exec(schema)
	return err
}

func (s *Store) CreateOrGetPending(ctx context.Context, req PendingRequest) (Record, error) {
	if req.Fingerprint == "" || req.ScopeType == "" || req.ScopeKey == "" {
		return Record{}, errors.New("fingerprint and scope are required")
	}
	now := s.now().UTC()
	if existing, ok, err := s.findReusablePending(ctx, req, now); err != nil {
		return Record{}, err
	} else if ok {
		return existing, nil
	}
	id, err := newApprovalID()
	if err != nil {
		return Record{}, err
	}
	rec := Record{
		ApprovalID:  id,
		Fingerprint: req.Fingerprint,
		ScopeType:   req.ScopeType,
		ScopeKey:    req.ScopeKey,
		Status:      StatusPending,
		TraceID:     req.TraceID,
		ActionID:    req.ActionID,
		ActionType:  req.ActionType,
		Resource:    req.Resource,
		ParamsHash:  req.ParamsHash,
		Principal:   req.Principal,
		Agent:       req.Agent,
		Environment: req.Environment,
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.ttl),
		UpdatedAt:   now,
	}
	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO approvals (approval_id, fingerprint, scope_type, scope_key, status, trace_id, action_id, action_type, resource, params_hash, principal, agent, environment, created_at, expires_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ApprovalID, rec.Fingerprint, rec.ScopeType, rec.ScopeKey, rec.Status,
		rec.TraceID, rec.ActionID, rec.ActionType, rec.Resource, rec.ParamsHash,
		rec.Principal, rec.Agent, rec.Environment,
		rec.CreatedAt.Format(time.RFC3339Nano), rec.ExpiresAt.Format(time.RFC3339Nano), rec.UpdatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return Record{}, err
	}
	return rec, nil
}

func (s *Store) Decide(ctx context.Context, approvalID, decision string) (Record, error) {
	if approvalID == "" {
		return Record{}, errors.New("approval_id is required")
	}
	status, err := normalizeDecision(decision)
	if err != nil {
		return Record{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer func() { _ = tx.Rollback() }()
	rec, err := loadByIDTx(ctx, tx, approvalID)
	if err != nil {
		return Record{}, err
	}
	now := s.now().UTC()
	if now.After(rec.ExpiresAt) {
		return Record{}, ErrExpired
	}
	if rec.Status == status {
		if err := tx.Commit(); err != nil {
			return Record{}, err
		}
		return rec, nil
	}
	if rec.Status != StatusPending {
		return Record{}, ErrAlreadyFinalized
	}
	rec.Status = status
	rec.UpdatedAt = now
	if _, err := tx.ExecContext(ctx, `UPDATE approvals SET status = ?, updated_at = ? WHERE approval_id = ?`, rec.Status, rec.UpdatedAt.Format(time.RFC3339Nano), rec.ApprovalID); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return rec, nil
}

func (s *Store) Lookup(ctx context.Context, approvalID string) (Record, error) {
	return loadByID(ctx, s.db, approvalID)
}

func (s *Store) CheckApproved(ctx context.Context, approvalID, fingerprint, classKey string) (bool, Record, error) {
	rec, err := loadByID(ctx, s.db, approvalID)
	if err != nil {
		return false, Record{}, err
	}
	if s.now().UTC().After(rec.ExpiresAt) {
		return false, rec, nil
	}
	if rec.Status != StatusApproved {
		return false, rec, nil
	}
	switch rec.ScopeType {
	case ScopeFingerprint:
		return rec.ScopeKey == fingerprint, rec, nil
	case ScopeClass:
		return classKey != "" && rec.ScopeKey == classKey, rec, nil
	default:
		return false, rec, nil
	}
}

func (s *Store) findReusablePending(ctx context.Context, req PendingRequest, now time.Time) (Record, bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT approval_id, fingerprint, scope_type, scope_key, status, trace_id, action_id, action_type, resource, params_hash, principal, agent, environment, created_at, expires_at, updated_at
	FROM approvals WHERE fingerprint = ? AND scope_type = ? AND scope_key = ? AND principal = ? AND agent = ? AND environment = ? ORDER BY created_at DESC`,
		req.Fingerprint, req.ScopeType, req.ScopeKey, req.Principal, req.Agent, req.Environment)
	if err != nil {
		return Record{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return Record{}, false, err
		}
		if rec.Status == StatusPending && now.Before(rec.ExpiresAt) {
			return rec, true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return Record{}, false, err
	}
	return Record{}, false, nil
}

func loadByID(ctx context.Context, db queryer, approvalID string) (Record, error) {
	row := db.QueryRowContext(ctx, `SELECT approval_id, fingerprint, scope_type, scope_key, status, trace_id, action_id, action_type, resource, params_hash, principal, agent, environment, created_at, expires_at, updated_at
	FROM approvals WHERE approval_id = ?`, approvalID)
	rec, err := scanRecord(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrNotFound
		}
		return Record{}, err
	}
	return rec, nil
}

func loadByIDTx(ctx context.Context, tx *sql.Tx, approvalID string) (Record, error) {
	return loadByID(ctx, tx, approvalID)
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRecord(s scanner) (Record, error) {
	var rec Record
	var createdAt string
	var expiresAt string
	var updatedAt string
	if err := s.Scan(
		&rec.ApprovalID,
		&rec.Fingerprint,
		&rec.ScopeType,
		&rec.ScopeKey,
		&rec.Status,
		&rec.TraceID,
		&rec.ActionID,
		&rec.ActionType,
		&rec.Resource,
		&rec.ParamsHash,
		&rec.Principal,
		&rec.Agent,
		&rec.Environment,
		&createdAt,
		&expiresAt,
		&updatedAt,
	); err != nil {
		return Record{}, err
	}
	var err error
	rec.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return Record{}, err
	}
	rec.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return Record{}, err
	}
	rec.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return Record{}, err
	}
	return rec, nil
}

func (s *Store) ListPending(ctx context.Context, limit int) ([]Record, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("approval store not initialized")
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `SELECT approval_id, fingerprint, scope_type, scope_key, status, trace_id, action_id, action_type, resource, params_hash, principal, agent, environment, created_at, expires_at, updated_at
	FROM approvals WHERE status = ? ORDER BY created_at DESC LIMIT ?`, StatusPending, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Record, 0)
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeDecision(decision string) (string, error) {
	switch decision {
	case StatusApproved, "approve", "APPROVE", "approved":
		return StatusApproved, nil
	case StatusDenied, "deny", "DENY", "denied":
		return StatusDenied, nil
	default:
		return "", fmt.Errorf("invalid decision %q", decision)
	}
}

func newApprovalID() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "apr_" + hex.EncodeToString(buf), nil
}
