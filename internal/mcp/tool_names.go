package mcp

import "strings"

const (
	ToolSurfaceCanonical = "canonical"
	ToolSurfaceFriendly  = "friendly"
	ToolSurfaceBoth      = "both"
)

var advertisedToolNames = map[string]string{
	"nomos.capabilities":       "nomos_capabilities",
	"nomos.fs_read":            "nomos_fs_read",
	"nomos.fs_write":           "nomos_fs_write",
	"nomos.apply_patch":        "nomos_apply_patch",
	"nomos.exec":               "nomos_exec",
	"nomos.http_request":       "nomos_http_request",
	"repo.validate_change_set": "repo_validate_change_set",
}

var friendlyToolNames = map[string]string{
	"nomos.fs_read":      "read_file",
	"nomos.fs_write":     "write_file",
	"nomos.apply_patch":  "apply_patch",
	"nomos.exec":         "run_command",
	"nomos.http_request": "http_request",
}

var canonicalToolNames = buildCanonicalToolNames(advertisedToolNames, friendlyToolNames)

func NormalizeToolSurface(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "canonical", "nomos", "legacy":
		return ToolSurfaceCanonical
	case "friendly":
		return ToolSurfaceFriendly
	case "both":
		return ToolSurfaceBoth
	default:
		return ""
	}
}

func advertisedToolName(canonical string) string {
	if name, ok := advertisedToolNames[canonical]; ok {
		return name
	}
	return canonical
}

func advertisedToolNamesForSurface(canonical, surface string) []string {
	surface = NormalizeToolSurface(surface)
	if surface == "" {
		surface = ToolSurfaceCanonical
	}
	friendly, hasFriendly := friendlyToolNames[canonical]
	advertised := advertisedToolName(canonical)
	switch surface {
	case ToolSurfaceFriendly:
		if hasFriendly {
			return []string{friendly}
		}
		if canonical == "repo.validate_change_set" {
			return nil
		}
		return []string{advertised}
	case ToolSurfaceBoth:
		if hasFriendly {
			return []string{friendly, advertised}
		}
		return []string{advertised}
	default:
		return []string{advertised}
	}
}

func isFriendlyToolName(name string) bool {
	_, ok := canonicalToolNames[name]
	if !ok {
		return false
	}
	for _, friendly := range friendlyToolNames {
		if name == friendly {
			return true
		}
	}
	return false
}

func canonicalToolName(name string) string {
	if canonical, ok := canonicalToolNames[name]; ok {
		return canonical
	}
	return name
}

func buildCanonicalToolNames(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, in := range maps {
		for canonical, advertised := range in {
			out[advertised] = canonical
		}
	}
	return out
}
