package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
	"github.com/safe-agentic-world/nomos/internal/normalize"
)

func validateParamsMatch(rule Rule) error {
	if len(rule.ParamsMatch) == 0 {
		return nil
	}
	for path, expected := range rule.ParamsMatch {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("rule %s params_match path is required", rule.ID)
		}
		if condition, ok := expected.(map[string]any); ok && paramsMatchConditionKeys(condition) {
			for key, value := range condition {
				switch key {
				case "present":
					if _, ok := value.(bool); !ok {
						return fmt.Errorf("rule %s params_match.%s.present must be boolean", rule.ID, path)
					}
				case "equals":
				case "in":
					if values, ok := value.([]any); !ok || len(values) == 0 {
						return fmt.Errorf("rule %s params_match.%s.in must be a non-empty array", rule.ID, path)
					}
				default:
					return fmt.Errorf("rule %s params_match.%s has unsupported condition %q", rule.ID, path, key)
				}
			}
		}
	}
	return nil
}

func matchParams(rule Rule, action normalize.NormalizedAction) bool {
	if len(rule.ParamsMatch) == 0 {
		return true
	}
	var params any
	dec := json.NewDecoder(bytes.NewReader(action.Params))
	dec.UseNumber()
	if err := dec.Decode(&params); err != nil {
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return false
	}
	paths := make([]string, 0, len(rule.ParamsMatch))
	for path := range rule.ParamsMatch {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		actual, present := lookupParamPath(params, path)
		if !matchParamCondition(actual, present, rule.ParamsMatch[path]) {
			return false
		}
	}
	return true
}

func matchParamCondition(actual any, present bool, expected any) bool {
	condition, ok := expected.(map[string]any)
	if !ok || !paramsMatchConditionKeys(condition) {
		return present && canonicalValuesEqual(actual, expected)
	}
	if rawPresent, ok := condition["present"]; ok {
		required, _ := rawPresent.(bool)
		if present != required {
			return false
		}
	}
	if rawEquals, ok := condition["equals"]; ok {
		if !present || !canonicalValuesEqual(actual, rawEquals) {
			return false
		}
	}
	if rawIn, ok := condition["in"]; ok {
		if !present {
			return false
		}
		values, ok := rawIn.([]any)
		if !ok {
			return false
		}
		for _, value := range values {
			if canonicalValuesEqual(actual, value) {
				return true
			}
		}
		return false
	}
	return true
}

func paramsMatchConditionKeys(condition map[string]any) bool {
	_, hasPresent := condition["present"]
	_, hasEquals := condition["equals"]
	_, hasIn := condition["in"]
	return hasPresent || hasEquals || hasIn
}

func lookupParamPath(params any, path string) (any, bool) {
	current := params
	for _, segment := range strings.Split(path, ".") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return nil, false
		}
		obj, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := obj[segment]
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

func canonicalValuesEqual(left, right any) bool {
	leftBytes, err := canonicalValueBytes(left)
	if err != nil {
		return false
	}
	rightBytes, err := canonicalValueBytes(right)
	if err != nil {
		return false
	}
	return bytes.Equal(leftBytes, rightBytes)
}

func canonicalValueBytes(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	canonical, err := canonicaljson.Canonicalize(encoded)
	if err != nil {
		return nil, err
	}
	if len(canonical) == 0 {
		return nil, errors.New("empty canonical value")
	}
	return canonical, nil
}
