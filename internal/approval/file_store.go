package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const fileStoreVersion = "approval_store.v1"

type FileStore struct {
	mu      sync.Mutex
	path    string
	now     func() time.Time
	ttl     time.Duration
	records map[string]Record
}

type fileStorePayload struct {
	Version  string   `json:"version"`
	Records  []Record `json:"records"`
	Checksum string   `json:"checksum"`
}

func OpenFile(path string, ttl time.Duration, now func() time.Time) (*FileStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("approval file store path is required")
	}
	if ttl <= 0 {
		return nil, errors.New("approval ttl must be > 0")
	}
	if now == nil {
		now = time.Now
	}
	store := &FileStore{
		path:    path,
		now:     now,
		ttl:     ttl,
		records: map[string]Record{},
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	if changed := store.purgeExpiredLocked(store.now().UTC()); changed {
		if err := store.persistLocked(); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func (s *FileStore) Close() error { return nil }

func (s *FileStore) CreateOrGetPending(ctx context.Context, req PendingRequest) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if req.Fingerprint == "" || req.ScopeType == "" || req.ScopeKey == "" {
		return Record{}, errors.New("fingerprint and scope are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	changed := s.purgeExpiredLocked(now)
	if existing, ok := s.findReusablePendingLocked(req, now); ok {
		if existing.ArgumentPreviewJSON == "" && req.ArgumentPreviewJSON != "" {
			existing.ArgumentPreviewJSON = req.ArgumentPreviewJSON
			existing.UpdatedAt = now
			s.records[existing.ApprovalID] = existing
			changed = true
		}
		if changed {
			if err := s.persistLocked(); err != nil {
				return Record{}, err
			}
		}
		return existing, nil
	}
	id, err := newApprovalID()
	if err != nil {
		return Record{}, err
	}
	for {
		if _, exists := s.records[id]; !exists {
			break
		}
		id, err = newApprovalID()
		if err != nil {
			return Record{}, err
		}
	}
	rec := Record{
		ApprovalID:          id,
		Fingerprint:         req.Fingerprint,
		ScopeType:           req.ScopeType,
		ScopeKey:            req.ScopeKey,
		Status:              StatusPending,
		TraceID:             req.TraceID,
		ActionID:            req.ActionID,
		ActionType:          req.ActionType,
		Resource:            req.Resource,
		ParamsHash:          req.ParamsHash,
		ArgumentPreviewJSON: req.ArgumentPreviewJSON,
		Principal:           req.Principal,
		Agent:               req.Agent,
		Environment:         req.Environment,
		CreatedAt:           now,
		ExpiresAt:           now.Add(s.ttl),
		UpdatedAt:           now,
	}
	s.records[rec.ApprovalID] = rec
	if err := s.persistLocked(); err != nil {
		delete(s.records, rec.ApprovalID)
		return Record{}, err
	}
	return rec, nil
}

func (s *FileStore) Decide(ctx context.Context, approvalID, decision string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if approvalID == "" {
		return Record{}, errors.New("approval_id is required")
	}
	status, err := normalizeDecision(decision)
	if err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[approvalID]
	if !ok {
		return Record{}, ErrNotFound
	}
	now := s.now().UTC()
	if now.After(rec.ExpiresAt) {
		delete(s.records, approvalID)
		if err := s.persistLocked(); err != nil {
			return Record{}, err
		}
		return Record{}, ErrExpired
	}
	if rec.Status == status {
		return rec, nil
	}
	if rec.Status != StatusPending {
		return Record{}, ErrAlreadyFinalized
	}
	prev := rec
	rec.Status = status
	rec.UpdatedAt = now
	s.records[approvalID] = rec
	if err := s.persistLocked(); err != nil {
		s.records[approvalID] = prev
		return Record{}, err
	}
	return rec, nil
}

func (s *FileStore) Lookup(ctx context.Context, approvalID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[approvalID]
	if !ok {
		return Record{}, ErrNotFound
	}
	return rec, nil
}

func (s *FileStore) CheckApproved(ctx context.Context, approvalID, fingerprint, classKey string) (bool, Record, error) {
	if err := ctx.Err(); err != nil {
		return false, Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[approvalID]
	if !ok {
		return false, Record{}, ErrNotFound
	}
	if s.now().UTC().After(rec.ExpiresAt) {
		delete(s.records, approvalID)
		if err := s.persistLocked(); err != nil {
			return false, Record{}, err
		}
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

func (s *FileStore) ListPending(ctx context.Context, limit int) ([]Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if changed := s.purgeExpiredLocked(s.now().UTC()); changed {
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
	}
	out := make([]Record, 0)
	for _, rec := range s.sortedRecordsLocked() {
		if rec.Status == StatusPending {
			out = append(out, rec)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (s *FileStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s.persistLocked()
		}
		return err
	}
	var payload fileStorePayload
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return fmt.Errorf("approval file store integrity check failed: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("approval file store integrity check failed: trailing data")
	}
	if payload.Version != fileStoreVersion {
		return fmt.Errorf("approval file store integrity check failed: unsupported version %q", payload.Version)
	}
	if payload.Checksum == "" || payload.Checksum != fileStoreChecksum(payload.Version, payload.Records) {
		return errors.New("approval file store integrity check failed: checksum mismatch")
	}
	records := map[string]Record{}
	for _, rec := range payload.Records {
		if err := validateRecord(rec); err != nil {
			return fmt.Errorf("approval file store integrity check failed: %w", err)
		}
		if _, exists := records[rec.ApprovalID]; exists {
			return fmt.Errorf("approval file store integrity check failed: duplicate approval_id %q", rec.ApprovalID)
		}
		records[rec.ApprovalID] = rec
	}
	s.records = records
	return nil
}

func (s *FileStore) persistLocked() error {
	records := s.sortedRecordsLocked()
	payload := fileStorePayload{
		Version: fileStoreVersion,
		Records: records,
	}
	payload.Checksum = fileStoreChecksum(payload.Version, payload.Records)
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomic(s.path, data, 0o600)
}

func (s *FileStore) sortedRecordsLocked() []Record {
	out := make([]Record, 0, len(s.records))
	for _, rec := range s.records {
		out = append(out, rec)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ApprovalID < out[j].ApprovalID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

func (s *FileStore) findReusablePendingLocked(req PendingRequest, now time.Time) (Record, bool) {
	for _, rec := range s.sortedRecordsLocked() {
		if rec.Fingerprint == req.Fingerprint &&
			rec.ScopeType == req.ScopeType &&
			rec.ScopeKey == req.ScopeKey &&
			rec.Principal == req.Principal &&
			rec.Agent == req.Agent &&
			rec.Environment == req.Environment &&
			rec.Status == StatusPending &&
			now.Before(rec.ExpiresAt) {
			return rec, true
		}
	}
	return Record{}, false
}

func (s *FileStore) purgeExpiredLocked(now time.Time) bool {
	changed := false
	for id, rec := range s.records {
		if now.After(rec.ExpiresAt) {
			delete(s.records, id)
			changed = true
		}
	}
	return changed
}

func validateRecord(rec Record) error {
	switch {
	case strings.TrimSpace(rec.ApprovalID) == "":
		return errors.New("approval_id is required")
	case strings.TrimSpace(rec.Fingerprint) == "":
		return fmt.Errorf("approval %q fingerprint is required", rec.ApprovalID)
	case strings.TrimSpace(rec.ScopeType) == "":
		return fmt.Errorf("approval %q scope_type is required", rec.ApprovalID)
	case strings.TrimSpace(rec.ScopeKey) == "":
		return fmt.Errorf("approval %q scope_key is required", rec.ApprovalID)
	case strings.TrimSpace(rec.Status) == "":
		return fmt.Errorf("approval %q status is required", rec.ApprovalID)
	case rec.CreatedAt.IsZero() || rec.ExpiresAt.IsZero() || rec.UpdatedAt.IsZero():
		return fmt.Errorf("approval %q timestamps are required", rec.ApprovalID)
	}
	switch rec.Status {
	case StatusPending, StatusApproved, StatusDenied:
		return nil
	default:
		return fmt.Errorf("approval %q has invalid status %q", rec.ApprovalID, rec.Status)
	}
}

func fileStoreChecksum(version string, records []Record) string {
	payload := struct {
		Version string   `json:"version"`
		Records []Record `json:"records"`
	}{
		Version: version,
		Records: append([]Record{}, records...),
	}
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := replaceFile(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}
