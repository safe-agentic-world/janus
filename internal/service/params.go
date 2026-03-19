package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

type writeParams struct {
	Content string `json:"content"`
}

type patchParams struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type checkoutParams struct {
	SecretID string `json:"secret_id"`
}

func decodeWriteParams(raw []byte) (writeParams, error) {
	var params writeParams
	if err := decodeStrict(raw, &params); err != nil {
		return writeParams{}, err
	}
	if params.Content == "" {
		return writeParams{}, errors.New("content is required")
	}
	return params, nil
}

func decodePatchParams(raw []byte) (patchParams, error) {
	var params patchParams
	if err := decodeStrict(raw, &params); err != nil {
		return patchParams{}, err
	}
	if params.Path == "" || params.Content == "" {
		return patchParams{}, errors.New("path and content are required")
	}
	return params, nil
}

func decodeExecParams(raw []byte) (executor.ExecParams, error) {
	var params executor.ExecParams
	if err := decodeStrict(raw, &params); err != nil {
		return executor.ExecParams{}, err
	}
	if len(params.Argv) == 0 {
		return executor.ExecParams{}, errors.New("argv is required")
	}
	return params, nil
}

func decodeHTTPParams(raw []byte) (executor.HTTPParams, error) {
	var params executor.HTTPParams
	if err := decodeStrict(raw, &params); err != nil {
		return executor.HTTPParams{}, err
	}
	return params, nil
}

func redirectPolicyFromObligations(obligations map[string]any) executor.RedirectPolicy {
	policy := executor.RedirectPolicy{
		AllowHosts: netAllowlistHosts(obligations),
	}
	if enabled, ok := obligations["http_redirects"].(bool); ok {
		policy.Enabled = enabled
	}
	if limit, ok := intObligation(obligations["http_redirect_hop_limit"]); ok {
		policy.HopLimit = limit
	}
	return policy
}

func decodeCheckoutParams(raw []byte) (checkoutParams, error) {
	var params checkoutParams
	if err := decodeStrict(raw, &params); err != nil {
		return checkoutParams{}, err
	}
	if strings.TrimSpace(params.SecretID) == "" {
		return checkoutParams{}, errors.New("secret_id is required")
	}
	return params, nil
}

func decodeStrict(raw []byte, target any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("unexpected trailing data")
	}
	return nil
}

func parseURLFromResource(resource string) (string, string, error) {
	if !strings.HasPrefix(resource, "url://") {
		return "", "", errors.New("resource is not url")
	}
	raw := strings.TrimPrefix(resource, "url://")
	parsed, err := url.Parse("https://" + raw)
	if err != nil {
		return "", "", err
	}
	return parsed.Host, parsed.String(), nil
}

func execAuthorized(obligations map[string]any, rawParams []byte, compatibilityMode string) (bool, string) {
	if ok, enforced := execConstraintsAllow(obligations, rawParams); enforced {
		if ok {
			return true, "exec_constraints"
		}
		return false, "exec_constraints"
	}
	if policy.NormalizeExecCompatibilityMode(compatibilityMode) == policy.ExecCompatibilityStrict {
		if _, ok := obligations["exec_allowlist"]; ok {
			return false, "legacy_disabled"
		}
	}
	if ok, enforced := execAllowlistAllows(obligations, rawParams); enforced {
		if ok {
			return true, "exec_allowlist"
		}
		return false, "exec_allowlist"
	}
	return true, "policy_only"
}

func execConstraintsAllow(obligations map[string]any, rawParams []byte) (bool, bool) {
	constraints, ok := obligations["exec_constraints"]
	if !ok {
		return false, false
	}
	params, err := decodeExecParams(rawParams)
	if err != nil {
		return false, true
	}
	payload, ok := constraints.(map[string]any)
	if !ok {
		return false, true
	}
	rawPatterns, ok := payload["argv_patterns"]
	if !ok {
		return false, true
	}
	patterns, ok := rawPatterns.([]any)
	if !ok {
		return false, true
	}
	for _, entry := range patterns {
		pattern, ok := entry.([]any)
		if !ok {
			continue
		}
		if matchArgvPrefixOrGlob(params.Argv, pattern) {
			return true, true
		}
	}
	return false, true
}

func execAllowlistAllows(obligations map[string]any, rawParams []byte) (bool, bool) {
	allowlist, ok := obligations["exec_allowlist"]
	if !ok {
		return false, false
	}
	params, err := decodeExecParams(rawParams)
	if err != nil {
		return false, true
	}
	list, ok := allowlist.([]any)
	if !ok {
		return false, true
	}
	for _, entry := range list {
		prefix, ok := entry.([]any)
		if !ok {
			continue
		}
		if matchArgvPrefix(params.Argv, prefix) {
			return true, true
		}
	}
	return false, true
}

func matchArgvPrefix(argv []string, prefix []any) bool {
	if len(prefix) == 0 || len(argv) < len(prefix) {
		return false
	}
	for i, item := range prefix {
		value, ok := item.(string)
		if !ok || argv[i] != value {
			return false
		}
	}
	return true
}

func matchArgvPrefixOrGlob(argv []string, pattern []any) bool {
	typed := make([]string, 0, len(pattern))
	for _, item := range pattern {
		value, ok := item.(string)
		if !ok || value == "" {
			return false
		}
		typed = append(typed, value)
	}
	return matchArgvSegmentsLocal(typed, argv)
}

func matchArgvSegmentsLocal(pattern, argv []string) bool {
	if len(pattern) == 0 {
		return len(argv) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(argv); i++ {
			if matchArgvSegmentsLocal(pattern[1:], argv[i:]) {
				return true
			}
		}
		return false
	}
	if len(argv) == 0 {
		return false
	}
	if pattern[0] != "*" && pattern[0] != argv[0] {
		return false
	}
	return matchArgvSegmentsLocal(pattern[1:], argv[1:])
}

func netAllowed(obligations map[string]any, host string) bool {
	for _, value := range netAllowlistHosts(obligations) {
		if value == host {
			return true
		}
	}
	return false
}

func netAllowlistHosts(obligations map[string]any) []string {
	list, ok := obligations["net_allowlist"]
	if !ok {
		return nil
	}
	items, ok := list.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, entry := range items {
		if value, ok := entry.(string); ok {
			out = append(out, value)
		}
	}
	return out
}

func intObligation(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		if typed != float64(int(typed)) {
			return 0, false
		}
		return int(typed), true
	default:
		return 0, false
	}
}

func redactSecrets(text string, secrets []string) string {
	out := text
	for _, s := range secrets {
		if s == "" {
			continue
		}
		out = strings.ReplaceAll(out, s, "[REDACTED]")
	}
	return out
}
