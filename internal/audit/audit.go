package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
	"github.com/safe-agentic-world/nomos/internal/redact"

	_ "modernc.org/sqlite"
)

const maxChainHashInputBytes = 64 << 20

type Event struct {
	SchemaVersion         string         `json:"schema_version,omitempty"`
	Timestamp             time.Time      `json:"timestamp"`
	EventType             string         `json:"event_type"`
	TraceID               string         `json:"trace_id"`
	ActionID              string         `json:"action_id,omitempty"`
	ApprovalID            string         `json:"approval_id,omitempty"`
	Fingerprint           string         `json:"action_fingerprint,omitempty"`
	Principal             string         `json:"principal,omitempty"`
	Agent                 string         `json:"agent,omitempty"`
	Environment           string         `json:"environment,omitempty"`
	ActionType            string         `json:"action_type,omitempty"`
	Resource              string         `json:"resource,omitempty"`
	ResourceNormalized    string         `json:"resource_normalized,omitempty"`
	ParamsHash            string         `json:"params_hash,omitempty"`
	MatchedRuleIDs        []string       `json:"matched_rule_ids,omitempty"`
	Obligations           map[string]any `json:"obligations,omitempty"`
	DurationMS            int64          `json:"duration_ms,omitempty"`
	ResultClassification  string         `json:"result_classification,omitempty"`
	Retryable             bool           `json:"retryable,omitempty"`
	PolicyBundleHash      string         `json:"policy_bundle_hash,omitempty"`
	PolicyBundleSources   []string       `json:"policy_bundle_sources,omitempty"`
	PolicyBundleInputs    []PolicyInput  `json:"policy_bundle_inputs,omitempty"`
	EngineVersion         string         `json:"engine_version,omitempty"`
	ParamsRedactedSummary string         `json:"params_redacted_summary,omitempty"`
	ResultRedactedSummary string         `json:"result_redacted_summary,omitempty"`
	ExecutorMetadata      map[string]any `json:"executor_metadata,omitempty"`
	RiskLevel             string         `json:"risk_level,omitempty"`
	RiskFlags             []string       `json:"risk_flags,omitempty"`
	SandboxMode           string         `json:"sandbox_mode,omitempty"`
	NetworkMode           string         `json:"network_mode,omitempty"`
	CredentialLeaseIDs    []string       `json:"credential_lease_ids,omitempty"`
	AssuranceLevel        string         `json:"assurance_level,omitempty"`
	ActionSummary         string         `json:"action_summary,omitempty"`
	PrevEventHash         string         `json:"prev_event_hash,omitempty"`
	EventHash             string         `json:"event_hash,omitempty"`
	Decision              string         `json:"decision,omitempty"`
	Reason                string         `json:"reason,omitempty"`
}

type PolicyInput struct {
	Path              string `json:"path"`
	Hash              string `json:"hash"`
	Role              string `json:"role,omitempty"`
	SignatureVerified bool   `json:"signature_verified,omitempty"`
}

type Recorder interface {
	WriteEvent(event Event) error
}

type Writer struct {
	records  []Recorder
	mu       sync.Mutex
	prevHash string
}

func NewWriter(sink string, redactor *redact.Redactor) (*Writer, error) {
	if redactor == nil {
		return nil, errors.New("redactor is required")
	}
	sink = strings.TrimSpace(sink)
	if sink == "" {
		return nil, errors.New("audit sink is required")
	}
	recorders := make([]Recorder, 0)
	for _, part := range strings.Split(sink, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		rec, err := recorderFromSink(part, redactor)
		if err != nil {
			for _, existing := range recorders {
				if closer, ok := existing.(io.Closer); ok {
					_ = closer.Close()
				}
			}
			return nil, err
		}
		recorders = append(recorders, rec)
	}
	if len(recorders) == 0 {
		return nil, errors.New("no valid audit sinks configured")
	}
	return &Writer{records: recorders}, nil
}

func (w *Writer) WriteEvent(event Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	hashed, err := withChainHash(event, w.prevHash)
	if err != nil {
		return err
	}
	for _, recorder := range w.records {
		if err := recorder.WriteEvent(hashed); err != nil {
			return err
		}
	}
	w.prevHash = hashed.EventHash
	return nil
}

func (w *Writer) Close() error {
	for _, recorder := range w.records {
		if closer, ok := recorder.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				return err
			}
		}
	}
	return nil
}

func recorderFromSink(sink string, redactor *redact.Redactor) (Recorder, error) {
	switch {
	case sink == "stdout":
		return &jsonlRecorder{out: os.Stdout, redactor: redactor}, nil
	case sink == "stderr":
		return &jsonlRecorder{out: os.Stderr, redactor: redactor}, nil
	case strings.HasPrefix(sink, "sqlite://"):
		return newSQLiteRecorder(strings.TrimPrefix(sink, "sqlite://"), redactor)
	case strings.HasPrefix(sink, "sqlite:"):
		return newSQLiteRecorder(strings.TrimPrefix(sink, "sqlite:"), redactor)
	case strings.HasPrefix(sink, "webhook:"):
		return newWebhookRecorder(strings.TrimPrefix(sink, "webhook:"), redactor), nil
	default:
		return nil, errors.New("unsupported audit sink")
	}
}

type jsonlRecorder struct {
	out      io.Writer
	redactor *redact.Redactor
}

func (r *jsonlRecorder) WriteEvent(event Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	redacted := r.redactor.RedactBytes(payload)
	_, err = r.out.Write(append(redacted, '\n'))
	return err
}

type sqliteRecorder struct {
	db       *sql.DB
	redactor *redact.Redactor
}

func newSQLiteRecorder(path string, redactor *redact.Redactor) (*sqliteRecorder, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("sqlite sink path is required")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	rec := &sqliteRecorder{db: db, redactor: redactor}
	if err := rec.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return rec, nil
}

func (r *sqliteRecorder) init() error {
	_, err := r.db.Exec(`CREATE TABLE IF NOT EXISTS audit_events (
id INTEGER PRIMARY KEY AUTOINCREMENT,
timestamp TEXT NOT NULL,
trace_id TEXT NOT NULL,
action_id TEXT NOT NULL,
event_type TEXT NOT NULL,
decision TEXT,
result_classification TEXT,
retryable INTEGER NOT NULL,
payload_json TEXT NOT NULL
);`)
	return err
}

func (r *sqliteRecorder) WriteEvent(event Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	redacted := string(r.redactor.RedactBytes(payload))
	actionID := event.ActionID
	if actionID == "" {
		actionID = "-"
	}
	_, err = r.db.Exec(
		`INSERT INTO audit_events (timestamp, trace_id, action_id, event_type, decision, result_classification, retryable, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		event.Timestamp.UTC().Format(time.RFC3339Nano),
		event.TraceID,
		actionID,
		event.EventType,
		event.Decision,
		event.ResultClassification,
		boolToInt(event.Retryable),
		redacted,
	)
	return err
}

func (r *sqliteRecorder) Close() error {
	return r.db.Close()
}

type webhookRecorder struct {
	url      string
	client   *http.Client
	redactor *redact.Redactor
}

func newWebhookRecorder(url string, redactor *redact.Redactor) *webhookRecorder {
	return &webhookRecorder{
		url:      strings.TrimSpace(url),
		client:   &http.Client{Timeout: 2 * time.Second},
		redactor: redactor,
	}
}

func (r *webhookRecorder) WriteEvent(event Event) error {
	if r.url == "" {
		return errors.New("webhook url is required")
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	redacted := r.redactor.RedactBytes(payload)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, r.url, bytes.NewReader(redacted))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return errors.New("audit webhook returned non-success status")
	}
	return nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func withChainHash(event Event, prevHash string) (Event, error) {
	event.PrevEventHash = prevHash
	event.EventHash = ""
	payload, err := json.Marshal(event)
	if err != nil {
		return Event{}, err
	}
	if len(payload) > maxChainHashInputBytes {
		return Event{}, errors.New("audit event payload exceeds limit")
	}
	canonical, err := canonicaljson.Canonicalize(payload)
	if err != nil {
		return Event{}, err
	}
	if len(canonical) > maxChainHashInputBytes || len(prevHash) > maxChainHashInputBytes {
		return Event{}, errors.New("audit chain hash input exceeds limit")
	}
	totalLen := int64(len(canonical)) + int64(len(prevHash))
	if totalLen > maxChainHashInputBytes {
		return Event{}, errors.New("audit chain hash input exceeds limit")
	}
	data := make([]byte, 0, int(totalLen))
	data = append(data, canonical...)
	data = append(data, []byte(prevHash)...)
	event.EventHash = canonicaljson.HashSHA256(data)
	return event, nil
}
