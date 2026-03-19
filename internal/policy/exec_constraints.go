package policy

import (
	"sort"
	"strings"
)

const obligationExecConstraints = "exec_constraints"

func withDerivedExecConstraints(obligations map[string]any, rules []Rule, decision string) map[string]any {
	out := copyObligations(obligations)
	constraints := deriveExecConstraints(rules, decision)
	if len(constraints) == 0 {
		return out
	}
	out[obligationExecConstraints] = map[string]any{
		"argv_patterns": constraints,
	}
	return out
}

func deriveExecConstraints(rules []Rule, decision string) []any {
	type patternRecord struct {
		key   string
		value []any
	}
	seen := map[string]struct{}{}
	records := make([]patternRecord, 0)
	for _, rule := range rules {
		if rule.Decision != decision || rule.ExecMatch == nil {
			continue
		}
		for _, pattern := range rule.ExecMatch.ArgvPatterns {
			key := strings.Join(pattern, "\x00")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			record := patternRecord{
				key:   key,
				value: make([]any, 0, len(pattern)),
			}
			for _, token := range pattern {
				record.value = append(record.value, token)
			}
			records = append(records, record)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].key < records[j].key
	})
	out := make([]any, 0, len(records))
	for _, record := range records {
		out = append(out, record.value)
	}
	return out
}
