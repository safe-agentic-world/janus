package action

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/schema"
)

const (
	MaxRequestBytes = 64 * 1024
	MaxParamsBytes  = 32 * 1024
	MaxContextBytes = 8 * 1024
	MaxIDLength     = 128
)

var opaqueIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Request struct {
	SchemaVersion string          `json:"schema_version"`
	ActionID      string          `json:"action_id"`
	ActionType    string          `json:"action_type"`
	Resource      string          `json:"resource"`
	Params        json.RawMessage `json:"params"`
	TraceID       string          `json:"trace_id"`
	Context       Context         `json:"-"`
}

type Context struct {
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

func ParseContext(data json.RawMessage) (Context, error) {
	if len(bytes.TrimSpace(data)) == 0 || string(bytes.TrimSpace(data)) == "null" {
		return Context{}, errors.New("context is required")
	}
	if len(data) > MaxContextBytes {
		return Context{}, fmt.Errorf("context exceeds %d bytes", MaxContextBytes)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return Context{}, err
	}
	for key := range raw {
		if key != "extensions" {
			return Context{}, fmt.Errorf("unknown context field %q", key)
		}
	}
	var ctx Context
	if rawExtensions, ok := raw["extensions"]; ok {
		var extensions map[string]json.RawMessage
		if err := json.Unmarshal(rawExtensions, &extensions); err != nil {
			return Context{}, fmt.Errorf("invalid context.extensions: %w", err)
		}
		ctx.Extensions = extensions
	}
	return ctx, nil
}

type requestPayload struct {
	SchemaVersion string          `json:"schema_version"`
	ActionID      string          `json:"action_id"`
	ActionType    string          `json:"action_type"`
	Resource      string          `json:"resource"`
	Params        json.RawMessage `json:"params"`
	TraceID       string          `json:"trace_id"`
	Context       json.RawMessage `json:"context"`
}

func DecodeActionRequest(r io.Reader) (Request, error) {
	data, err := ReadRequestBytes(r)
	if err != nil {
		return Request{}, err
	}
	return DecodeActionRequestBytes(data)
}

func ReadRequestBytes(r io.Reader) ([]byte, error) {
	limited := io.LimitReader(r, MaxRequestBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxRequestBytes {
		return nil, fmt.Errorf("request exceeds %d bytes", MaxRequestBytes)
	}
	return data, nil
}

func DecodeActionRequestBytes(data []byte) (Request, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var payload requestPayload
	if err := dec.Decode(&payload); err != nil {
		return Request{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Request{}, errors.New("unexpected trailing data")
	}
	req := Request{
		SchemaVersion: payload.SchemaVersion,
		ActionID:      payload.ActionID,
		ActionType:    payload.ActionType,
		Resource:      payload.Resource,
		Params:        payload.Params,
		TraceID:       payload.TraceID,
	}
	if err := req.Validate(payload.Context); err != nil {
		return Request{}, err
	}
	ctx, err := ParseContext(payload.Context)
	if err != nil {
		return Request{}, err
	}
	req.Context = ctx
	return req, nil
}

func (r Request) Validate(rawContext json.RawMessage) error {
	var errs []string
	if r.SchemaVersion == "" {
		errs = append(errs, "schema_version is required")
	} else if r.SchemaVersion != "v1" {
		errs = append(errs, "schema_version must be v1")
	}
	if strings.TrimSpace(r.ActionID) == "" {
		errs = append(errs, "action_id is required")
	} else if !opaqueIDPattern.MatchString(r.ActionID) {
		errs = append(errs, "action_id has invalid format")
	}
	if strings.TrimSpace(r.ActionType) == "" {
		errs = append(errs, "action_type is required")
	} else if err := ValidateActionType(r.ActionType); err != nil {
		errs = append(errs, err.Error())
	}
	if strings.TrimSpace(r.Resource) == "" {
		errs = append(errs, "resource is required")
	}
	if strings.TrimSpace(r.TraceID) == "" {
		errs = append(errs, "trace_id is required")
	} else if !opaqueIDPattern.MatchString(r.TraceID) {
		errs = append(errs, "trace_id has invalid format")
	}
	if len(r.Params) == 0 {
		errs = append(errs, "params is required")
	} else if len(r.Params) > MaxParamsBytes {
		errs = append(errs, fmt.Sprintf("params exceeds %d bytes", MaxParamsBytes))
	} else if firstNonSpace(r.Params) != '{' {
		errs = append(errs, "params must be an object")
	}
	if len(bytes.TrimSpace(rawContext)) == 0 || string(bytes.TrimSpace(rawContext)) == "null" {
		errs = append(errs, "context is required")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func firstNonSpace(data []byte) byte {
	for _, b := range data {
		if b == ' ' || b == '\n' || b == '\t' || b == '\r' {
			continue
		}
		return b
	}
	return 0
}

type Action struct {
	SchemaVersion string          `json:"schema_version"`
	ActionID      string          `json:"action_id"`
	ActionType    string          `json:"action_type"`
	Resource      string          `json:"resource"`
	Params        json.RawMessage `json:"params"`
	Principal     string          `json:"principal"`
	Agent         string          `json:"agent"`
	Environment   string          `json:"environment"`
	Context       Context         `json:"context"`
	TraceID       string          `json:"trace_id"`
}

func ToAction(req Request, id identity.VerifiedIdentity) (Action, error) {
	if id.Principal == "" || id.Agent == "" || id.Environment == "" {
		return Action{}, errors.New("verified identity is required")
	}
	act := Action{
		SchemaVersion: req.SchemaVersion,
		ActionID:      strings.TrimSpace(req.ActionID),
		ActionType:    strings.TrimSpace(req.ActionType),
		Resource:      strings.TrimSpace(req.Resource),
		Params:        req.Params,
		Principal:     id.Principal,
		Agent:         id.Agent,
		Environment:   id.Environment,
		Context:       req.Context,
		TraceID:       strings.TrimSpace(req.TraceID),
	}
	if err := ValidateActionType(act.ActionType); err != nil {
		return Action{}, err
	}
	if err := ValidateActionSchema(act); err != nil {
		return Action{}, err
	}
	return act, nil
}

func ValidateActionSchema(action Action) error {
	data, err := json.Marshal(action)
	if err != nil {
		return err
	}
	return schema.Validate(actionSchema(), data)
}

func DecodeAction(data []byte) (Action, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var act Action
	if err := dec.Decode(&act); err != nil {
		return Action{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Action{}, errors.New("unexpected trailing data")
	}
	if err := ValidateActionSchema(act); err != nil {
		return Action{}, err
	}
	if err := ValidateActionType(act.ActionType); err != nil {
		return Action{}, err
	}
	return act, nil
}

type Response struct {
	Decision            string           `json:"decision"`
	Reason              string           `json:"reason,omitempty"`
	TraceID             string           `json:"trace_id,omitempty"`
	ActionID            string           `json:"action_id,omitempty"`
	ExecutionMode       string           `json:"execution_mode,omitempty"`
	ReportPath          string           `json:"report_path,omitempty"`
	Output              string           `json:"output,omitempty"`
	Truncated           bool             `json:"truncated,omitempty"`
	BytesWritten        int              `json:"bytes_written,omitempty"`
	Stdout              string           `json:"stdout,omitempty"`
	Stderr              string           `json:"stderr,omitempty"`
	ExitCode            int              `json:"exit_code,omitempty"`
	StatusCode          int              `json:"status_code,omitempty"`
	Obligations         map[string]any   `json:"obligations,omitempty"`
	MCPContentBlocks    []map[string]any `json:"mcp_content_blocks,omitempty"`
	ApprovalID          string           `json:"approval_id,omitempty"`
	ApprovalFingerprint string           `json:"approval_fingerprint,omitempty"`
	ApprovalExpiresAt   string           `json:"approval_expires_at,omitempty"`
	CredentialLeaseID   string           `json:"credential_lease_id,omitempty"`
	CredentialLeaseIDs  []string         `json:"credential_lease_ids,omitempty"`
}
