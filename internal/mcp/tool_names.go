package mcp

var advertisedToolNames = map[string]string{
	"nomos.capabilities":       "nomos_capabilities",
	"nomos.fs_read":            "nomos_fs_read",
	"nomos.fs_write":           "nomos_fs_write",
	"nomos.apply_patch":        "nomos_apply_patch",
	"nomos.exec":               "nomos_exec",
	"nomos.http_request":       "nomos_http_request",
	"repo.validate_change_set": "repo_validate_change_set",
}

var canonicalToolNames = reverseToolNames(advertisedToolNames)

func advertisedToolName(canonical string) string {
	if name, ok := advertisedToolNames[canonical]; ok {
		return name
	}
	return canonical
}

func canonicalToolName(name string) string {
	if canonical, ok := canonicalToolNames[name]; ok {
		return canonical
	}
	return name
}

func reverseToolNames(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for canonical, advertised := range in {
		out[advertised] = canonical
	}
	return out
}
