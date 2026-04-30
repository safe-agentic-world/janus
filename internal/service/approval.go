package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
	"github.com/safe-agentic-world/nomos/internal/normalize"
)

type approvalContext struct {
	ApprovalID string `json:"approval_id"`
}

func actionFingerprint(normalized normalize.NormalizedAction) (string, error) {
	var params any
	dec := json.NewDecoder(bytes.NewReader(normalized.Params))
	dec.UseNumber()
	if err := dec.Decode(&params); err != nil {
		return "", err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return "", errors.New("params contains trailing data")
	}
	payload := map[string]any{
		"normalized_action": map[string]any{
			"schema_version": normalized.SchemaVersion,
			"action_type":    normalized.ActionType,
			"resource":       normalized.Resource,
			"params":         params,
		},
		"principal":   normalized.Principal,
		"agent":       normalized.Agent,
		"environment": normalized.Environment,
	}
	if strings.TrimSpace(normalized.TenantID) != "" {
		payload["tenant_id"] = normalized.TenantID
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	canonicalPayload, err := canonicaljson.Canonicalize(jsonPayload)
	if err != nil {
		return "", err
	}
	return canonicaljson.HashSHA256(canonicalPayload), nil
}

func approvalClassKey(obligations map[string]any, normalized normalize.NormalizedAction) string {
	raw, ok := obligations["approval_scope_class"]
	if !ok {
		return ""
	}
	value, ok := raw.(string)
	if !ok {
		return ""
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if value == "action_type_resource" {
		return normalized.ActionType + "|" + normalized.Resource
	}
	return ""
}

func approvalIDFromExtensions(ctx action.Context) (string, error) {
	raw, ok := ctx.Extensions["approval"]
	if !ok {
		return "", nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var payload approvalContext
	if err := dec.Decode(&payload); err != nil {
		return "", fmt.Errorf("invalid approval extension: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return "", errors.New("approval extension has trailing data")
	}
	return strings.TrimSpace(payload.ApprovalID), nil
}
