package owaspmapping

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var categoryHeading = regexp.MustCompile(`(?m)^## (ASI\d{2}) — (.+)$`)
var inlinePath = regexp.MustCompile("`((?:docs|internal|cmd|deploy|testdata)/[^`]+)`")

func TestOWASPMappingDocIsVersionedAndComplete(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "docs", "owasp-agentic-mapping.md")
	content := mustReadFile(t, path)

	if !strings.Contains(content, "OWASP Top 10 for Agentic Applications") {
		t.Fatal("expected specific OWASP release name")
	}
	if !strings.Contains(content, "December 9, 2025") {
		t.Fatal("expected specific OWASP release date/version marker")
	}

	matches := categoryHeading.FindAllStringSubmatchIndex(content, -1)
	if len(matches) != 10 {
		t.Fatalf("expected 10 ASI categories, got %d", len(matches))
	}

	for i, match := range matches {
		id := content[match[2]:match[3]]
		start := match[0]
		end := len(content)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		section := content[start:end]

		if !strings.Contains(section, "Coverage: `FULL`") &&
			!strings.Contains(section, "Coverage: `PARTIAL`") &&
			!strings.Contains(section, "Coverage: `OUT_OF_SCOPE`") {
			t.Fatalf("%s missing coverage status", id)
		}
		if !strings.Contains(section, "Relevant Nomos controls:") {
			t.Fatalf("%s missing control mapping section", id)
		}
		if !strings.Contains(section, "Relevant code and runtime surfaces:") {
			t.Fatalf("%s missing runtime surface section", id)
		}
		paths := inlinePath.FindAllStringSubmatch(section, -1)
		if len(paths) == 0 {
			t.Fatalf("%s missing concrete path references", id)
		}
		for _, pathMatch := range paths {
			target := filepath.Join(root, filepath.FromSlash(pathMatch[1]))
			if _, err := os.Stat(target); err != nil {
				t.Fatalf("%s references missing path %s: %v", id, pathMatch[1], err)
			}
		}
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Clean(filepath.Join(dir, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "TASKS.md")); err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}
