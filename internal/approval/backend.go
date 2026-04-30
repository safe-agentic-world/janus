package approval

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"time"
)

const (
	BackendFile   = "file"
	BackendSQLite = "sqlite"
	BackendAuto   = "auto"
)

type Backend interface {
	CreateOrGetPending(ctx context.Context, req PendingRequest) (Record, error)
	Decide(ctx context.Context, approvalID, decision string) (Record, error)
	Lookup(ctx context.Context, approvalID string) (Record, error)
	CheckApproved(ctx context.Context, approvalID, fingerprint, classKey string) (bool, Record, error)
	ListPending(ctx context.Context, limit int) ([]Record, error)
	Close() error
}

type Options struct {
	Backend string
	Path    string
	TTL     time.Duration
	Now     func() time.Time
}

func NormalizeBackend(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", BackendFile:
		return BackendFile
	case BackendSQLite, "sql", "db":
		return BackendSQLite
	case BackendAuto:
		return BackendAuto
	default:
		return ""
	}
}

func OpenBackend(options Options) (Backend, error) {
	backend := NormalizeBackend(options.Backend)
	if backend == "" {
		return nil, errors.New("approval store backend must be file, sqlite, or auto")
	}
	if backend == BackendAuto {
		detected, err := detectBackend(options.Path)
		if err != nil {
			return nil, err
		}
		backend = detected
	}
	switch backend {
	case BackendFile:
		return OpenFile(options.Path, options.TTL, options.Now)
	case BackendSQLite:
		return Open(options.Path, options.TTL, options.Now)
	default:
		return nil, errors.New("unsupported approval store backend")
	}
}

func detectBackend(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("approval store path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return BackendFile, nil
		}
		return "", err
	}
	if bytes.HasPrefix(data, []byte("SQLite format 3")) {
		return BackendSQLite, nil
	}
	return BackendFile, nil
}
