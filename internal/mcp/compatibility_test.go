package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompatibilityDocMatchesImplementation(t *testing.T) {
	path := filepath.Clean(filepath.Join("..", "..", "docs", "mcp-compatibility.md"))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read compatibility doc: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		SupportedProtocolVersion,
		"stdio",
		"Content-Length",
		"tools/list",
		"tools/call",
		"stdout is reserved for MCP protocol bytes only",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected compatibility doc to mention %q", want)
		}
	}
}
