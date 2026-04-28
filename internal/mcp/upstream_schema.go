package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
)

const (
	upstreamToolSchemaDialect       = "https://json-schema.org/draft/2020-12/schema"
	upstreamArgumentValidationError = "ARGUMENT_VALIDATION_ERROR"

	maxForwardedArgumentBytes = 32 * 1024
	maxForwardedArgumentDepth = 32
	maxForwardedArgumentNodes = 4096
	maxUpstreamSchemaDepth    = 32
	maxUpstreamSchemaNodes    = 2048
)

type upstreamArgumentSet struct {
	CanonicalValue any
	CanonicalBytes []byte
	Hash           string
	ForwardBytes   []byte
}

type upstreamArgumentValidationDetail struct {
	Path     string `json:"path"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
}

type upstreamArgumentValidationFailure struct {
	Details []upstreamArgumentValidationDetail
}

func (f *upstreamArgumentValidationFailure) Error() string {
	return upstreamArgumentValidationError
}

func validateUpstreamToolArguments(tool upstreamTool, rawArgs json.RawMessage) (upstreamArgumentSet, error) {
	args, err := decodeForwardedArguments(rawArgs)
	if err != nil {
		return upstreamArgumentSet{}, err
	}
	if len(tool.InputSchema) == 0 {
		if !tool.AllowMissingInputSchema {
			return upstreamArgumentSet{}, argumentValidationFailure("$", "inputSchema", "missing")
		}
		return canonicalizeUpstreamArguments(args)
	}
	if detail := validateSchemaDocument(tool.InputSchema); detail != nil {
		return upstreamArgumentSet{}, &upstreamArgumentValidationFailure{Details: []upstreamArgumentValidationDetail{*detail}}
	}
	if detail := validateAgainstSchema(tool.InputSchema, args, "$", 0); detail != nil {
		return upstreamArgumentSet{}, &upstreamArgumentValidationFailure{Details: []upstreamArgumentValidationDetail{*detail}}
	}
	return canonicalizeUpstreamArguments(args)
}

func decodeForwardedArguments(rawArgs json.RawMessage) (map[string]any, error) {
	args := bytes.TrimSpace(rawArgs)
	if len(args) == 0 {
		args = []byte(`{}`)
	}
	if len(args) > maxForwardedArgumentBytes {
		return nil, argumentValidationFailure("$", fmt.Sprintf("<=%d bytes", maxForwardedArgumentBytes), "bytes")
	}
	var value any
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return nil, argumentValidationFailure("$", "valid JSON object", "invalid")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, argumentValidationFailure("$", "single JSON object", "trailing-data")
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, argumentValidationFailure("$", "object", jsonKind(value))
	}
	budget := validationBudget{maxDepth: maxForwardedArgumentDepth, maxNodes: maxForwardedArgumentNodes}
	if detail := budget.checkValue("$", obj, 0); detail != nil {
		return nil, &upstreamArgumentValidationFailure{Details: []upstreamArgumentValidationDetail{*detail}}
	}
	return obj, nil
}

func canonicalizeUpstreamArguments(args map[string]any) (upstreamArgumentSet, error) {
	forwardBytes, err := json.Marshal(args)
	if err != nil {
		return upstreamArgumentSet{}, err
	}
	canonicalBytes, err := canonicaljson.Canonicalize(forwardBytes)
	if err != nil {
		return upstreamArgumentSet{}, err
	}
	var canonicalValue any
	dec := json.NewDecoder(bytes.NewReader(canonicalBytes))
	dec.UseNumber()
	if err := dec.Decode(&canonicalValue); err != nil {
		return upstreamArgumentSet{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return upstreamArgumentSet{}, errors.New("canonicalized arguments contain trailing data")
	}
	return upstreamArgumentSet{
		CanonicalValue: canonicalValue,
		CanonicalBytes: canonicalBytes,
		Hash:           canonicaljson.HashSHA256(canonicalBytes),
		ForwardBytes:   forwardBytes,
	}, nil
}

func validateSchemaDocument(schema map[string]any) *upstreamArgumentValidationDetail {
	budget := validationBudget{maxDepth: maxUpstreamSchemaDepth, maxNodes: maxUpstreamSchemaNodes}
	if detail := budget.checkValue("$", schema, 0); detail != nil {
		return detail
	}
	if raw, ok := schema["$schema"]; ok {
		dialect, ok := raw.(string)
		if !ok {
			return validationDetail("$.$schema", upstreamToolSchemaDialect, jsonKind(raw))
		}
		dialect = strings.TrimSuffix(strings.TrimSpace(dialect), "#")
		if dialect != "" && dialect != upstreamToolSchemaDialect {
			return validationDetail("$.$schema", upstreamToolSchemaDialect, "string")
		}
	}
	return nil
}

type validationBudget struct {
	maxDepth int
	maxNodes int
	nodes    int
}

func (b *validationBudget) checkValue(path string, value any, depth int) *upstreamArgumentValidationDetail {
	if depth > b.maxDepth {
		return validationDetail(path, fmt.Sprintf("depth<=%d", b.maxDepth), jsonKind(value))
	}
	b.nodes++
	if b.nodes > b.maxNodes {
		return validationDetail(path, fmt.Sprintf("nodes<=%d", b.maxNodes), jsonKind(value))
	}
	switch typed := value.(type) {
	case map[string]any:
		keys := sortedMapKeys(typed)
		for _, key := range keys {
			if detail := b.checkValue(jsonPath(path, key), typed[key], depth+1); detail != nil {
				return detail
			}
		}
	case []any:
		for idx, item := range typed {
			if detail := b.checkValue(arrayPath(path, idx), item, depth+1); detail != nil {
				return detail
			}
		}
	}
	return nil
}

func validateAgainstSchema(schema map[string]any, value any, path string, depth int) *upstreamArgumentValidationDetail {
	if depth > maxUpstreamSchemaDepth {
		return validationDetail(path, fmt.Sprintf("schema-depth<=%d", maxUpstreamSchemaDepth), jsonKind(value))
	}
	types, detail := schemaTypes(schema)
	if detail != nil {
		return detail
	}
	if len(types) > 0 && !schemaTypeMatches(types, value) {
		return validationDetail(path, strings.Join(types, "|"), jsonKind(value))
	}
	if rawEnum, ok := schema["enum"]; ok {
		if !valueInEnum(value, rawEnum) {
			return validationDetail(path, "enum", jsonKind(value))
		}
	}
	if rawConst, ok := schema["const"]; ok {
		if !canonicalEqual(value, rawConst) {
			return validationDetail(path, "const", jsonKind(value))
		}
	}
	switch typed := value.(type) {
	case map[string]any:
		if detail := validateObjectConstraints(schema, typed, path, depth); detail != nil {
			return detail
		}
	case []any:
		if detail := validateArrayConstraints(schema, typed, path, depth); detail != nil {
			return detail
		}
	case string:
		if detail := validateStringConstraints(schema, typed, path); detail != nil {
			return detail
		}
	case json.Number:
		if detail := validateNumberConstraints(schema, typed, path); detail != nil {
			return detail
		}
	}
	if detail := validateAllOf(schema, value, path, depth); detail != nil {
		return detail
	}
	if detail := validateAnyOf(schema, value, path, depth); detail != nil {
		return detail
	}
	if detail := validateOneOf(schema, value, path, depth); detail != nil {
		return detail
	}
	return nil
}

func schemaTypes(schema map[string]any) ([]string, *upstreamArgumentValidationDetail) {
	raw, ok := schema["type"]
	if !ok {
		if _, hasProps := schema["properties"]; hasProps {
			return []string{"object"}, nil
		}
		if _, hasRequired := schema["required"]; hasRequired {
			return []string{"object"}, nil
		}
		if _, hasAdditional := schema["additionalProperties"]; hasAdditional {
			return []string{"object"}, nil
		}
		return nil, nil
	}
	switch typed := raw.(type) {
	case string:
		if !supportedSchemaType(typed) {
			return nil, validationDetail("$.type", "supported schema type", "string")
		}
		return []string{typed}, nil
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			value, ok := item.(string)
			if !ok || !supportedSchemaType(value) {
				return nil, validationDetail("$.type", "supported schema type", jsonKind(item))
			}
			out = append(out, value)
		}
		sort.Strings(out)
		return out, nil
	case []string:
		out := append([]string(nil), typed...)
		for _, item := range out {
			if !supportedSchemaType(item) {
				return nil, validationDetail("$.type", "supported schema type", "string")
			}
		}
		sort.Strings(out)
		return out, nil
	default:
		return nil, validationDetail("$.type", "string|string[]", jsonKind(raw))
	}
}

func supportedSchemaType(value string) bool {
	switch strings.TrimSpace(value) {
	case "object", "array", "string", "number", "integer", "boolean", "null":
		return true
	default:
		return false
	}
}

func schemaTypeMatches(types []string, value any) bool {
	for _, schemaType := range types {
		switch schemaType {
		case "object":
			if _, ok := value.(map[string]any); ok {
				return true
			}
		case "array":
			if _, ok := value.([]any); ok {
				return true
			}
		case "string":
			if _, ok := value.(string); ok {
				return true
			}
		case "number":
			if _, ok := value.(json.Number); ok {
				return true
			}
		case "integer":
			if number, ok := value.(json.Number); ok && isIntegerNumber(number) {
				return true
			}
		case "boolean":
			if _, ok := value.(bool); ok {
				return true
			}
		case "null":
			if value == nil {
				return true
			}
		}
	}
	return false
}

func validateObjectConstraints(schema map[string]any, obj map[string]any, path string, depth int) *upstreamArgumentValidationDetail {
	required, detail := schemaStringSlice(schema["required"])
	if detail != nil {
		return validationDetail("$.required", "string[]", detail.Actual)
	}
	sort.Strings(required)
	for _, field := range required {
		if _, ok := obj[field]; !ok {
			return validationDetail(jsonPath(path, field), "required", "missing")
		}
	}
	properties, detail := schemaProperties(schema["properties"])
	if detail != nil {
		return detail
	}
	for _, key := range sortedMapKeys(properties) {
		if value, ok := obj[key]; ok {
			if detail := validateAgainstSchema(properties[key], value, jsonPath(path, key), depth+1); detail != nil {
				return detail
			}
		}
	}
	if rawAdditional, ok := schema["additionalProperties"]; ok {
		switch typed := rawAdditional.(type) {
		case bool:
			if !typed {
				for _, key := range sortedMapKeys(obj) {
					if _, declared := properties[key]; !declared {
						return validationDetail(jsonPath(path, key), "declared property", jsonKind(obj[key]))
					}
				}
			}
		case map[string]any:
			for _, key := range sortedMapKeys(obj) {
				if _, declared := properties[key]; declared {
					continue
				}
				if detail := validateAgainstSchema(typed, obj[key], jsonPath(path, key), depth+1); detail != nil {
					return detail
				}
			}
		default:
			return validationDetail("$.additionalProperties", "boolean|schema", jsonKind(rawAdditional))
		}
	}
	return nil
}

func validateArrayConstraints(schema map[string]any, items []any, path string, depth int) *upstreamArgumentValidationDetail {
	if min, ok := schemaInteger(schema["minItems"]); ok && len(items) < min {
		return validationDetail(path, fmt.Sprintf("minItems:%d", min), "array")
	}
	if max, ok := schemaInteger(schema["maxItems"]); ok && len(items) > max {
		return validationDetail(path, fmt.Sprintf("maxItems:%d", max), "array")
	}
	if rawItems, ok := schema["items"]; ok {
		itemSchema, ok := rawItems.(map[string]any)
		if !ok {
			return validationDetail("$.items", "schema", jsonKind(rawItems))
		}
		for idx, item := range items {
			if detail := validateAgainstSchema(itemSchema, item, arrayPath(path, idx), depth+1); detail != nil {
				return detail
			}
		}
	}
	return nil
}

func validateStringConstraints(schema map[string]any, value string, path string) *upstreamArgumentValidationDetail {
	if min, ok := schemaInteger(schema["minLength"]); ok && utf8.RuneCountInString(value) < min {
		return validationDetail(path, fmt.Sprintf("minLength:%d", min), "string")
	}
	if max, ok := schemaInteger(schema["maxLength"]); ok && utf8.RuneCountInString(value) > max {
		return validationDetail(path, fmt.Sprintf("maxLength:%d", max), "string")
	}
	if rawPattern, ok := schema["pattern"]; ok {
		pattern, ok := rawPattern.(string)
		if !ok {
			return validationDetail("$.pattern", "string", jsonKind(rawPattern))
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return validationDetail("$.pattern", "valid regex", "string")
		}
		if !re.MatchString(value) {
			return validationDetail(path, "pattern", "string")
		}
	}
	return nil
}

func validateNumberConstraints(schema map[string]any, value json.Number, path string) *upstreamArgumentValidationDetail {
	actual, ok := numberRat(value)
	if !ok {
		return validationDetail(path, "valid number", "number")
	}
	if minimum, ok := schemaNumber(schema["minimum"]); ok && actual.Cmp(minimum) < 0 {
		return validationDetail(path, "minimum", "number")
	}
	if maximum, ok := schemaNumber(schema["maximum"]); ok && actual.Cmp(maximum) > 0 {
		return validationDetail(path, "maximum", "number")
	}
	if minimum, ok := schemaNumber(schema["exclusiveMinimum"]); ok && actual.Cmp(minimum) <= 0 {
		return validationDetail(path, "exclusiveMinimum", "number")
	}
	if maximum, ok := schemaNumber(schema["exclusiveMaximum"]); ok && actual.Cmp(maximum) >= 0 {
		return validationDetail(path, "exclusiveMaximum", "number")
	}
	return nil
}

func validateAllOf(schema map[string]any, value any, path string, depth int) *upstreamArgumentValidationDetail {
	raw, ok := schema["allOf"]
	if !ok {
		return nil
	}
	schemas, ok := raw.([]any)
	if !ok {
		return validationDetail("$.allOf", "schema[]", jsonKind(raw))
	}
	for _, item := range schemas {
		child, ok := item.(map[string]any)
		if !ok {
			return validationDetail("$.allOf", "schema[]", jsonKind(item))
		}
		if detail := validateAgainstSchema(child, value, path, depth+1); detail != nil {
			return detail
		}
	}
	return nil
}

func validateAnyOf(schema map[string]any, value any, path string, depth int) *upstreamArgumentValidationDetail {
	raw, ok := schema["anyOf"]
	if !ok {
		return nil
	}
	schemas, ok := raw.([]any)
	if !ok {
		return validationDetail("$.anyOf", "schema[]", jsonKind(raw))
	}
	for _, item := range schemas {
		child, ok := item.(map[string]any)
		if !ok {
			return validationDetail("$.anyOf", "schema[]", jsonKind(item))
		}
		if validateAgainstSchema(child, value, path, depth+1) == nil {
			return nil
		}
	}
	return validationDetail(path, "anyOf", jsonKind(value))
}

func validateOneOf(schema map[string]any, value any, path string, depth int) *upstreamArgumentValidationDetail {
	raw, ok := schema["oneOf"]
	if !ok {
		return nil
	}
	schemas, ok := raw.([]any)
	if !ok {
		return validationDetail("$.oneOf", "schema[]", jsonKind(raw))
	}
	matches := 0
	for _, item := range schemas {
		child, ok := item.(map[string]any)
		if !ok {
			return validationDetail("$.oneOf", "schema[]", jsonKind(item))
		}
		if validateAgainstSchema(child, value, path, depth+1) == nil {
			matches++
		}
	}
	if matches != 1 {
		return validationDetail(path, "oneOf", jsonKind(value))
	}
	return nil
}

func schemaProperties(raw any) (map[string]map[string]any, *upstreamArgumentValidationDetail) {
	if raw == nil {
		return map[string]map[string]any{}, nil
	}
	props, ok := raw.(map[string]any)
	if !ok {
		return nil, validationDetail("$.properties", "object", jsonKind(raw))
	}
	out := make(map[string]map[string]any, len(props))
	for _, key := range sortedMapKeys(props) {
		child, ok := props[key].(map[string]any)
		if !ok {
			return nil, validationDetail(jsonPath("$.properties", key), "schema", jsonKind(props[key]))
		}
		out[key] = child
	}
	return out, nil
}

func schemaStringSlice(raw any) ([]string, *upstreamArgumentValidationDetail) {
	if raw == nil {
		return nil, nil
	}
	switch typed := raw.(type) {
	case []string:
		return append([]string(nil), typed...), nil
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			value, ok := item.(string)
			if !ok {
				return nil, validationDetail("$", "string[]", jsonKind(item))
			}
			out = append(out, value)
		}
		return out, nil
	default:
		return nil, validationDetail("$", "string[]", jsonKind(raw))
	}
}

func valueInEnum(value any, rawEnum any) bool {
	var items []any
	switch typed := rawEnum.(type) {
	case []any:
		items = typed
	case []string:
		items = make([]any, 0, len(typed))
		for _, item := range typed {
			items = append(items, item)
		}
	default:
		return false
	}
	for _, item := range items {
		if canonicalEqual(value, item) {
			return true
		}
	}
	return false
}

func canonicalEqual(left, right any) bool {
	leftBytes, err := canonicalBytes(left)
	if err != nil {
		return false
	}
	rightBytes, err := canonicalBytes(right)
	if err != nil {
		return false
	}
	return bytes.Equal(leftBytes, rightBytes)
}

func canonicalBytes(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonicalize(encoded)
}

func schemaInteger(raw any) (int, bool) {
	switch typed := raw.(type) {
	case json.Number:
		value, err := strconv.Atoi(typed.String())
		return value, err == nil
	case float64:
		value := int(typed)
		return value, typed == float64(value)
	case int:
		return typed, true
	case int64:
		return int(typed), true
	default:
		return 0, false
	}
}

func schemaNumber(raw any) (*big.Rat, bool) {
	switch typed := raw.(type) {
	case json.Number:
		return numberRat(typed)
	case float64:
		return new(big.Rat).SetFloat64(typed), true
	case int:
		return big.NewRat(int64(typed), 1), true
	case int64:
		return big.NewRat(typed, 1), true
	default:
		return nil, false
	}
}

func numberRat(value json.Number) (*big.Rat, bool) {
	out, ok := new(big.Rat).SetString(value.String())
	return out, ok
}

func isIntegerNumber(value json.Number) bool {
	rat, ok := numberRat(value)
	return ok && rat.IsInt()
}

func argumentValidationFailure(path, expected, actual string) error {
	return &upstreamArgumentValidationFailure{Details: []upstreamArgumentValidationDetail{{
		Path:     path,
		Expected: expected,
		Actual:   actual,
	}}}
}

func validationDetail(path, expected, actual string) *upstreamArgumentValidationDetail {
	return &upstreamArgumentValidationDetail{
		Path:     path,
		Expected: expected,
		Actual:   actual,
	}
}

func sortedMapKeys[V any](in map[string]V) []string {
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func jsonPath(base, key string) string {
	if key == "" {
		return base + "[\"\"]"
	}
	for _, r := range key {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return base + "[" + strconv.Quote(key) + "]"
		}
	}
	return base + "." + key
}

func arrayPath(base string, idx int) string {
	return fmt.Sprintf("%s[%d]", base, idx)
}

func jsonKind(value any) string {
	switch value.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case json.Number:
		return "number"
	case bool:
		return "boolean"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%T", value)
	}
}
