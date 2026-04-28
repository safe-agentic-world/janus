package responsescan

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	RulePackVersion = "response-scan-rules/v1"
	DefaultMode     = ModeFence
	MaxScanBytes    = 1 << 20
	MaxScanDepth    = 1
	MaxFindings     = 128
)

type Mode string

const (
	ModeStrip Mode = "strip"
	ModeFence Mode = "fence"
	ModeDeny  Mode = "deny"
)

var ErrDenied = errors.New("response scan denied")

type Finding struct {
	RuleID   string `json:"rule_id"`
	Location string `json:"location"`
	Severity string `json:"severity"`
	Start    int    `json:"-"`
	End      int    `json:"-"`
}

type Result struct {
	RulePackVersion string
	Findings        []Finding
	InputTruncated  bool
	MaxDepth        int
}

type SanitizeResult struct {
	Text   string
	Result Result
	Denied bool
}

type Rule struct {
	ID       string
	Severity string
	Pattern  string
}

type Scanner struct {
	rules []compiledRule
}

type compiledRule struct {
	id       string
	severity string
	re       *regexp.Regexp
}

var defaultRules = []Rule{
	{
		ID:       "prompt_injection.instruction_override",
		Severity: "high",
		Pattern:  `(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions?|messages?|system messages?)\b`,
	},
	{
		ID:       "prompt_injection.role_override",
		Severity: "medium",
		Pattern:  `(?i)\b(system|developer)\s+prompt\b|\byou are now\b|\bact as (the )?(system|developer)\b`,
	},
	{
		ID:       "exfiltration.secret_request",
		Severity: "high",
		Pattern:  `(?i)\b(exfiltrate|leak|send|upload|reveal)\s+(the\s+)?(secrets?|tokens?|credentials?|api keys?)\b`,
	},
	{
		ID:       "obfuscation.hidden_unicode",
		Severity: "medium",
		Pattern:  `[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}]{2,}`,
	},
	{
		ID:       "exfiltration.suspicious_url",
		Severity: "medium",
		Pattern:  `(?i)\bhttps?://[^\s<>"']*(pastebin\.com|webhook\.site|requestbin\.com|ngrok(-free)?\.app|ngrok\.io|bit\.ly|tinyurl\.com)[^\s<>"']*`,
	},
}

func DefaultScanner() (*Scanner, error) {
	return NewScanner(defaultRules)
}

func NewScanner(rules []Rule) (*Scanner, error) {
	if len(rules) == 0 {
		return nil, errors.New("response scanner requires at least one rule")
	}
	compiled := make([]compiledRule, 0, len(rules))
	seen := map[string]struct{}{}
	for _, rule := range rules {
		id := strings.TrimSpace(rule.ID)
		severity := strings.TrimSpace(rule.Severity)
		pattern := strings.TrimSpace(rule.Pattern)
		if id == "" || severity == "" || pattern == "" {
			return nil, errors.New("response scanner rule id, severity, and pattern are required")
		}
		if _, ok := seen[id]; ok {
			return nil, fmt.Errorf("duplicate response scanner rule id %q", id)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile response scanner rule %q: %w", id, err)
		}
		seen[id] = struct{}{}
		compiled = append(compiled, compiledRule{id: id, severity: severity, re: re})
	}
	return &Scanner{rules: compiled}, nil
}

func NormalizeMode(value any) (Mode, bool) {
	switch typed := value.(type) {
	case nil:
		return DefaultMode, true
	case string:
		text := strings.ToLower(strings.TrimSpace(typed))
		if text == "" {
			return DefaultMode, true
		}
		switch Mode(text) {
		case ModeStrip, ModeFence, ModeDeny:
			return Mode(text), true
		default:
			return ModeDeny, false
		}
	default:
		return ModeDeny, false
	}
}

func (s *Scanner) Scan(text string) (Result, error) {
	if s == nil || len(s.rules) == 0 {
		return Result{}, errors.New("response scanner is not configured")
	}
	scanText := text
	truncated := false
	if len(scanText) > MaxScanBytes {
		scanText = trimValidUTF8(scanText, MaxScanBytes)
		truncated = true
	}
	findings := make([]Finding, 0)
	for _, rule := range s.rules {
		matches := rule.re.FindAllStringIndex(scanText, -1)
		for _, span := range matches {
			if len(span) != 2 || span[0] < 0 || span[1] <= span[0] {
				continue
			}
			findings = append(findings, Finding{
				RuleID:   rule.id,
				Severity: rule.severity,
				Start:    span[0],
				End:      span[1],
				Location: fmt.Sprintf("text[%d:%d]", span[0], span[1]),
			})
			if len(findings) >= MaxFindings {
				return Result{RulePackVersion: RulePackVersion, Findings: sortedFindings(findings), InputTruncated: truncated, MaxDepth: MaxScanDepth}, nil
			}
		}
	}
	return Result{RulePackVersion: RulePackVersion, Findings: sortedFindings(findings), InputTruncated: truncated, MaxDepth: MaxScanDepth}, nil
}

func (s *Scanner) Sanitize(text string, mode Mode) (SanitizeResult, error) {
	result, err := s.Scan(text)
	if err != nil {
		return SanitizeResult{Result: result, Denied: true}, ErrDenied
	}
	if len(result.Findings) == 0 {
		return SanitizeResult{Text: text, Result: result}, nil
	}
	switch mode {
	case ModeStrip:
		return SanitizeResult{Text: stripFindings(text, result.Findings), Result: result}, nil
	case ModeFence:
		return SanitizeResult{Text: fenceFindings(text, result.Findings), Result: result}, nil
	case ModeDeny:
		return SanitizeResult{Result: result, Denied: true}, ErrDenied
	default:
		return SanitizeResult{Result: result, Denied: true}, ErrDenied
	}
}

func sortedFindings(findings []Finding) []Finding {
	out := make([]Finding, len(findings))
	copy(out, findings)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		if out[i].End != out[j].End {
			return out[i].End < out[j].End
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

type span struct {
	start      int
	end        int
	ruleIDs    []string
	severities []string
}

func mergeFindings(findings []Finding) []span {
	if len(findings) == 0 {
		return nil
	}
	sorted := sortedFindings(findings)
	merged := []span{}
	for _, finding := range sorted {
		if finding.Start < 0 || finding.End <= finding.Start {
			continue
		}
		if len(merged) == 0 || finding.Start > merged[len(merged)-1].end {
			merged = append(merged, span{
				start:      finding.Start,
				end:        finding.End,
				ruleIDs:    []string{finding.RuleID},
				severities: []string{finding.Severity},
			})
			continue
		}
		last := &merged[len(merged)-1]
		if finding.End > last.end {
			last.end = finding.End
		}
		last.ruleIDs = appendUnique(last.ruleIDs, finding.RuleID)
		last.severities = appendUnique(last.severities, finding.Severity)
	}
	for idx := range merged {
		sort.Strings(merged[idx].ruleIDs)
		sort.Strings(merged[idx].severities)
	}
	return merged
}

func stripFindings(text string, findings []Finding) string {
	merged := mergeFindings(findings)
	if len(merged) == 0 {
		return text
	}
	var builder strings.Builder
	cursor := 0
	for _, span := range merged {
		if span.start > len(text) {
			continue
		}
		end := span.end
		if end > len(text) {
			end = len(text)
		}
		if cursor < span.start {
			builder.WriteString(text[cursor:span.start])
		}
		cursor = end
	}
	if cursor < len(text) {
		builder.WriteString(text[cursor:])
	}
	return builder.String()
}

func fenceFindings(text string, findings []Finding) string {
	merged := mergeFindings(findings)
	if len(merged) == 0 {
		return text
	}
	var builder strings.Builder
	cursor := 0
	for _, span := range merged {
		if span.start > len(text) {
			continue
		}
		end := span.end
		if end > len(text) {
			end = len(text)
		}
		if cursor < span.start {
			builder.WriteString(text[cursor:span.start])
		}
		segment := text[span.start:end]
		fence := codeFence(segment)
		builder.WriteString("[Nomos response scan: fenced untrusted upstream content; rules=")
		builder.WriteString(strings.Join(span.ruleIDs, ","))
		builder.WriteString("; severity=")
		builder.WriteString(strings.Join(span.severities, ","))
		builder.WriteString("]\n")
		builder.WriteString(fence)
		builder.WriteString("nomos-untrusted-response\n")
		builder.WriteString(segment)
		if !strings.HasSuffix(segment, "\n") {
			builder.WriteByte('\n')
		}
		builder.WriteString(fence)
		builder.WriteByte('\n')
		cursor = end
	}
	if cursor < len(text) {
		builder.WriteString(text[cursor:])
	}
	return builder.String()
}

func codeFence(text string) string {
	maxRun := 0
	run := 0
	for _, r := range text {
		if r == '`' {
			run++
			if run > maxRun {
				maxRun = run
			}
			continue
		}
		run = 0
	}
	if maxRun < 3 {
		maxRun = 3
	} else {
		maxRun++
	}
	return strings.Repeat("`", maxRun)
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func trimValidUTF8(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	out := value[:limit]
	for !utf8.ValidString(out) && len(out) > 0 {
		out = out[:len(out)-1]
	}
	return out
}
