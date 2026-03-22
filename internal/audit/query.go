package audit

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

func FirstSQLiteSinkPath(sink string) string {
	for _, part := range strings.Split(strings.TrimSpace(sink), ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "sqlite://"):
			return strings.TrimPrefix(part, "sqlite://")
		case strings.HasPrefix(part, "sqlite:"):
			return strings.TrimPrefix(part, "sqlite:")
		}
	}
	return ""
}

func LoadActionDetail(sqlitePath, actionID string) (Event, error) {
	if strings.TrimSpace(sqlitePath) == "" {
		return Event{}, errors.New("sqlite audit sink is not configured")
	}
	if strings.TrimSpace(actionID) == "" {
		return Event{}, errors.New("action_id is required")
	}
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		return Event{}, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT payload_json FROM audit_events WHERE action_id = ? ORDER BY id DESC LIMIT 20`, actionID)
	if err != nil {
		return Event{}, err
	}
	defer rows.Close()

	candidates := make([]Event, 0, 4)
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return Event{}, err
		}
		var event Event
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			return Event{}, fmt.Errorf("decode audit payload: %w", err)
		}
		candidates = append(candidates, event)
	}
	if err := rows.Err(); err != nil {
		return Event{}, err
	}
	if len(candidates) == 0 {
		return Event{}, errors.New("action not found")
	}
	for _, event := range candidates {
		if event.EventType == "action.completed" {
			return event, nil
		}
	}
	for _, event := range candidates {
		if event.EventType == "action.decision" {
			return event, nil
		}
	}
	return candidates[0], nil
}

func LoadTraceEvents(sqlitePath, traceID string) ([]Event, error) {
	if strings.TrimSpace(sqlitePath) == "" {
		return nil, errors.New("sqlite audit sink is not configured")
	}
	if strings.TrimSpace(traceID) == "" {
		return nil, errors.New("trace_id is required")
	}
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id, payload_json FROM audit_events WHERE trace_id = ? ORDER BY id ASC`, traceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]Event, 0, 8)
	for rows.Next() {
		var id int64
		var payload string
		if err := rows.Scan(&id, &payload); err != nil {
			return nil, err
		}
		var event Event
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			return nil, fmt.Errorf("decode audit payload: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, errors.New("trace not found")
	}
	return events, nil
}

type TraceListFilter struct {
	TraceID     string
	ActionType  string
	Decision    string
	Principal   string
	Agent       string
	Environment string
	Limit       int
}

type TraceSummary struct {
	TraceID        string
	ActionID       string
	ActionType     string
	Decision       string
	Principal      string
	Agent          string
	Environment    string
	LastEventType  string
	LastTimestamp  string
	EventCount     int
	AssuranceLevel string
}

func ListTraceSummaries(sqlitePath string, filter TraceListFilter) ([]TraceSummary, error) {
	if strings.TrimSpace(sqlitePath) == "" {
		return nil, errors.New("sqlite audit sink is not configured")
	}
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id, payload_json FROM audit_events ORDER BY id DESC LIMIT ?`, limit*20)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type summaryState struct {
		summary TraceSummary
	}
	states := map[string]*summaryState{}
	order := make([]string, 0, limit)
	for rows.Next() {
		var id int64
		var payload string
		if err := rows.Scan(&id, &payload); err != nil {
			return nil, err
		}
		var event Event
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			return nil, fmt.Errorf("decode audit payload: %w", err)
		}
		if !matchesTraceFilter(event, filter) {
			continue
		}
		state := states[event.TraceID]
		if state == nil {
			state = &summaryState{summary: TraceSummary{
				TraceID:        event.TraceID,
				ActionID:       event.ActionID,
				ActionType:     event.ActionType,
				Decision:       event.Decision,
				Principal:      event.Principal,
				Agent:          event.Agent,
				Environment:    event.Environment,
				LastEventType:  event.EventType,
				LastTimestamp:  event.Timestamp.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
				AssuranceLevel: event.AssuranceLevel,
			}}
			states[event.TraceID] = state
			order = append(order, event.TraceID)
		}
		state.summary.EventCount++
		if state.summary.Decision == "" && event.Decision != "" {
			state.summary.Decision = event.Decision
		}
		if state.summary.ActionType == "" && event.ActionType != "" {
			state.summary.ActionType = event.ActionType
		}
		if state.summary.ActionID == "" && event.ActionID != "" {
			state.summary.ActionID = event.ActionID
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]TraceSummary, 0, len(order))
	for _, traceID := range order {
		out = append(out, states[traceID].summary)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func matchesTraceFilter(event Event, filter TraceListFilter) bool {
	if filter.TraceID != "" && !strings.Contains(strings.ToLower(event.TraceID), strings.ToLower(filter.TraceID)) {
		return false
	}
	if filter.ActionType != "" && !strings.EqualFold(strings.TrimSpace(filter.ActionType), strings.TrimSpace(event.ActionType)) {
		return false
	}
	if filter.Decision != "" && !strings.EqualFold(strings.TrimSpace(filter.Decision), strings.TrimSpace(event.Decision)) {
		return false
	}
	if filter.Principal != "" && !strings.EqualFold(strings.TrimSpace(filter.Principal), strings.TrimSpace(event.Principal)) {
		return false
	}
	if filter.Agent != "" && !strings.EqualFold(strings.TrimSpace(filter.Agent), strings.TrimSpace(event.Agent)) {
		return false
	}
	if filter.Environment != "" && !strings.EqualFold(strings.TrimSpace(filter.Environment), strings.TrimSpace(event.Environment)) {
		return false
	}
	return strings.TrimSpace(event.TraceID) != ""
}

func SortTraceEvents(events []Event) {
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
}
