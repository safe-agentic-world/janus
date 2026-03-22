package normalize

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
)

type NormalizedAction struct {
	SchemaVersion    string
	ActionID         string
	ActionType       string
	Resource         string
	Params           []byte
	ParamsHash       string
	Principal        string
	Agent            string
	Environment      string
	Context          action.Context
	TraceID          string
	TraceActionCount int
}

func Action(input action.Action) (NormalizedAction, error) {
	if strings.TrimSpace(input.ActionType) == "" {
		return NormalizedAction{}, errors.New("action_type is required")
	}
	if strings.TrimSpace(input.Resource) == "" {
		return NormalizedAction{}, errors.New("resource is required")
	}
	normalizedResource, err := normalizeResource(strings.TrimSpace(input.Resource))
	if err != nil {
		if !action.IsBuiltInActionType(input.ActionType) {
			normalizedResource, err = NormalizeCustomResource(strings.TrimSpace(input.Resource))
		}
		if err != nil {
			return NormalizedAction{}, err
		}
	}
	canonicalParams, err := canonicaljson.Canonicalize(input.Params)
	if err != nil {
		return NormalizedAction{}, fmt.Errorf("params canonicalization failed: %w", err)
	}
	paramsHash := canonicaljson.HashSHA256(canonicalParams)
	return NormalizedAction{
		SchemaVersion: input.SchemaVersion,
		ActionID:      input.ActionID,
		ActionType:    strings.TrimSpace(input.ActionType),
		Resource:      normalizedResource,
		Params:        canonicalParams,
		ParamsHash:    paramsHash,
		Principal:     input.Principal,
		Agent:         input.Agent,
		Environment:   input.Environment,
		Context:       input.Context,
		TraceID:       input.TraceID,
	}, nil
}

func NormalizeResource(raw string) (string, error) {
	return normalizeResource(strings.TrimSpace(raw))
}

func NormalizeCustomResource(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid resource uri: %w", err)
	}
	return normalizeCustomResource(parsed)
}

func NormalizeRedirectURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid redirect url: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("redirect scheme must be http or https")
	}
	if parsed.User != nil {
		return "", errors.New("redirect userinfo is not allowed")
	}
	return normalizeNetworkLocation(parsed.Host, parsed.EscapedPath())
}

func normalizeResource(raw string) (string, error) {
	if strings.HasPrefix(strings.ToLower(raw), "file://") {
		raw = strings.ReplaceAll(raw, "\\", "/")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid resource uri: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "file":
		return normalizeFileResource(parsed)
	case "repo":
		return normalizeRepoResource(parsed)
	case "url":
		return normalizeURLResource(parsed)
	case "secret":
		return normalizeSecretResource(parsed)
	default:
		return "", fmt.Errorf("unsupported resource scheme %q", parsed.Scheme)
	}
}

func normalizeFileResource(parsed *url.URL) (string, error) {
	host := strings.ToLower(parsed.Host)
	if host == "" {
		host = "workspace"
	}
	if host != "workspace" {
		return "", fmt.Errorf("unsupported file host %q", parsed.Host)
	}
	cleaned, err := normalizeResourcePath(parsed.EscapedPath(), "file")
	if err != nil {
		return "", err
	}
	if cleaned == "" {
		return "", errors.New("file path is required")
	}
	return "file://" + host + cleaned, nil
}

func normalizeRepoResource(parsed *url.URL) (string, error) {
	if parsed.Host == "" {
		return "", errors.New("repo host is required")
	}
	org := strings.ToLower(parsed.Host)
	repo := strings.ToLower(strings.TrimPrefix(parsed.Path, "/"))
	if repo == "" || strings.Contains(repo, "/") {
		return "", errors.New("repo path must be single segment")
	}
	return "repo://" + org + "/" + repo, nil
}

func normalizeURLResource(parsed *url.URL) (string, error) {
	if parsed.User != nil {
		return "", errors.New("url userinfo is not allowed")
	}
	return normalizeNetworkLocation(parsed.Host, parsed.EscapedPath())
}

func normalizeSecretResource(parsed *url.URL) (string, error) {
	host := strings.ToLower(parsed.Host)
	if host == "" {
		return "", errors.New("secret host is required")
	}
	secretPath := strings.ToLower(strings.TrimPrefix(parsed.Path, "/"))
	if secretPath == "" || strings.Contains(secretPath, "/") {
		return "", errors.New("secret path must be single segment")
	}
	return "secret://" + host + "/" + secretPath, nil
}

func normalizeCustomResource(parsed *url.URL) (string, error) {
	if parsed.User != nil {
		return "", errors.New("custom resource userinfo is not allowed")
	}
	if parsed.RawQuery != "" {
		return "", errors.New("custom resource query is not allowed")
	}
	if parsed.Fragment != "" {
		return "", errors.New("custom resource fragment is not allowed")
	}
	scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
	if scheme == "" {
		return "", errors.New("custom resource scheme is required")
	}
	host, err := normalizeHostPort(parsed.Host)
	if err != nil {
		return "", fmt.Errorf("invalid custom resource host: %w", err)
	}
	cleaned, err := normalizeResourcePath(parsed.EscapedPath(), "custom resource")
	if err != nil {
		return "", err
	}
	return scheme + "://" + host + cleaned, nil
}

func normalizeNetworkLocation(rawHost, rawPath string) (string, error) {
	host, err := normalizeHostPort(rawHost)
	if err != nil {
		return "", err
	}
	cleaned, err := normalizeResourcePath(rawPath, "url")
	if err != nil {
		return "", err
	}
	return "url://" + host + cleaned, nil
}

func normalizeHostPort(rawHost string) (string, error) {
	trimmed := strings.TrimSpace(rawHost)
	if trimmed == "" {
		return "", errors.New("url host is required")
	}
	if strings.Contains(trimmed, "%") {
		return "", errors.New("invalid url host")
	}
	hostname := ""
	port := ""
	switch {
	case strings.HasPrefix(trimmed, "["):
		if strings.HasSuffix(trimmed, "]") {
			hostname = strings.ToLower(trimmed)
			break
		}
		parsedHost, parsedPort, err := net.SplitHostPort(trimmed)
		if err != nil {
			return "", errors.New("invalid url host")
		}
		if strings.Contains(parsedHost, ":") {
			hostname = "[" + strings.ToLower(parsedHost) + "]"
		} else {
			hostname = strings.ToLower(parsedHost)
		}
		port = parsedPort
	case strings.Count(trimmed, ":") > 1:
		return "", errors.New("invalid url host")
	case strings.Contains(trimmed, ":"):
		parsedHost, parsedPort, err := net.SplitHostPort(trimmed)
		if err != nil {
			return "", errors.New("invalid url host")
		}
		hostname = strings.ToLower(parsedHost)
		port = parsedPort
	default:
		hostname = strings.ToLower(trimmed)
	}
	if hostname == "" {
		return "", errors.New("url host is required")
	}
	if port == "80" || port == "443" {
		port = ""
	}
	if port != "" {
		return hostname + ":" + port, nil
	}
	return hostname, nil
}

func normalizeResourcePath(rawPath, kind string) (string, error) {
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		return "", fmt.Errorf("invalid %s path encoding", kind)
	}
	if containsEncodedSeparators(rawPath) {
		return "", fmt.Errorf("%s path encoded separators are not allowed", kind)
	}
	if hasTraversalSegments(decodedPath) {
		if kind == "file" {
			return "", errors.New("file path traversal detected")
		}
		return "", errors.New("url path traversal detected")
	}
	cleaned := cleanPath(decodedPath)
	if cleaned == "" {
		if kind == "file" {
			return "", errors.New("file path is required")
		}
		return "/", nil
	}
	return cleaned, nil
}

func containsEncodedSeparators(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c")
}

func cleanPath(raw string) string {
	if raw == "" {
		return ""
	}
	cleaned := path.Clean("/" + strings.ReplaceAll(raw, "\\", "/"))
	if cleaned == "/" {
		return "/"
	}
	return cleaned
}

func hasTraversalSegments(raw string) bool {
	if raw == "" {
		return false
	}
	segments := strings.Split(strings.ReplaceAll(raw, "\\", "/"), "/")
	for _, segment := range segments {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func MatchPattern(pattern, value string) (bool, error) {
	if strings.Contains(pattern, "\\") || strings.Contains(value, "\\") {
		return false, errors.New("backslash is not allowed")
	}
	patternSegments := strings.Split(pattern, "/")
	valueSegments := strings.Split(value, "/")
	return matchSegments(patternSegments, valueSegments), nil
}

func matchSegments(pattern, value []string) bool {
	if len(pattern) == 0 {
		return len(value) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(value); i++ {
			if matchSegments(pattern[1:], value[i:]) {
				return true
			}
		}
		return false
	}
	if len(value) == 0 {
		return false
	}
	if !matchSegment(pattern[0], value[0]) {
		return false
	}
	return matchSegments(pattern[1:], value[1:])
}

func matchSegment(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == value
	}
	return matchWildcard(pattern, value)
}

func matchWildcard(pattern, value string) bool {
	pIdx := 0
	vIdx := 0
	starIdx := -1
	matchIdx := 0
	for vIdx < len(value) {
		if pIdx < len(pattern) && (pattern[pIdx] == value[vIdx] || pattern[pIdx] == '?') {
			pIdx++
			vIdx++
			continue
		}
		if pIdx < len(pattern) && pattern[pIdx] == '*' {
			starIdx = pIdx
			matchIdx = vIdx
			pIdx++
			continue
		}
		if starIdx != -1 {
			pIdx = starIdx + 1
			matchIdx++
			vIdx = matchIdx
			continue
		}
		return false
	}
	for pIdx < len(pattern) && pattern[pIdx] == '*' {
		pIdx++
	}
	return pIdx == len(pattern)
}

func StableKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
