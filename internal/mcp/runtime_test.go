package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/identity"
)

func TestServeStdioBannerAndProtocolSeparation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	var stderr bytes.Buffer
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "info",
		LogFormat: "text",
		ErrWriter: &stderr,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	var stdout bytes.Buffer
	req := `{"id":"1","method":"nomos.fs_read","params":{"resource":"file://workspace/README.md"}}` + "\n"
	if err := server.ServeStdio(strings.NewReader(req), &stdout); err != nil {
		t.Fatalf("serve stdio: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(stderr.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one stderr banner line, got %d: %q", len(lines), stderr.String())
	}
	if !strings.Contains(lines[0], "MCP server ready") || !strings.Contains(lines[0], "env=dev") {
		t.Fatalf("unexpected banner line: %q", lines[0])
	}
	if !strings.Contains(lines[0], "policy_bundle_hash=") || !strings.Contains(lines[0], "engine=") {
		t.Fatalf("expected hash and engine in banner: %q", lines[0])
	}

	if strings.Contains(stdout.String(), "[Nomos]") {
		t.Fatalf("stdout contains non-protocol text: %q", stdout.String())
	}
	var resp Response
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &resp); err != nil {
		t.Fatalf("stdout is not JSON protocol response: %v; raw=%q", err, stdout.String())
	}
	if resp.ID != "1" || resp.Error != "" {
		t.Fatalf("unexpected protocol response: %+v", resp)
	}
}

func TestServeStdioQuietSuppressesBanner(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	var stderr bytes.Buffer
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		Quiet:     true,
		LogLevel:  "info",
		LogFormat: "text",
		ErrWriter: &stderr,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	var stdout bytes.Buffer
	if err := server.ServeStdio(strings.NewReader(""), &stdout); err != nil {
		t.Fatalf("serve stdio: %v", err)
	}
	if strings.TrimSpace(stderr.String()) != "" {
		t.Fatalf("expected quiet mode to suppress banner/logs, got: %q", stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("expected no protocol output for empty input, got: %q", stdout.String())
	}
}

func TestParseRuntimeOptionsValidation(t *testing.T) {
	if _, err := ParseRuntimeOptions(RuntimeOptions{LogLevel: "trace"}); err == nil {
		t.Fatal("expected invalid log level error")
	}
	if _, err := ParseRuntimeOptions(RuntimeOptions{LogFormat: "yaml"}); err == nil {
		t.Fatal("expected invalid log format error")
	}
	if _, err := ParseRuntimeOptions(RuntimeOptions{ToolSurface: "ambiguous"}); err == nil {
		t.Fatal("expected invalid tool surface error")
	}
	opts, err := ParseRuntimeOptions(RuntimeOptions{})
	if err != nil {
		t.Fatalf("parse defaults: %v", err)
	}
	if opts.LogLevel != "info" || opts.LogFormat != "text" || opts.ToolSurface != ToolSurfaceCanonical {
		t.Fatalf("unexpected defaults: %+v", opts)
	}
}

func TestRuntimeLoggerRedactsSecrets(t *testing.T) {
	var stderr bytes.Buffer
	logger, err := newRuntimeLogger(RuntimeOptions{
		LogLevel:  "error",
		LogFormat: "text",
		ErrWriter: &stderr,
	})
	if err != nil {
		t.Fatalf("new runtime logger: %v", err)
	}
	logger.Error("authorization: Bearer abc.def.ghi")
	got := stderr.String()
	if strings.Contains(strings.ToLower(got), "authorization:") || strings.Contains(got, "abc.def.ghi") {
		t.Fatalf("expected secret redaction, got: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("expected redaction marker, got: %q", got)
	}
}

func TestQuietModeEquivalentToErrorLevel(t *testing.T) {
	var stderr bytes.Buffer
	logger, err := newRuntimeLogger(RuntimeOptions{
		Quiet:     true,
		LogLevel:  "debug",
		LogFormat: "text",
		ErrWriter: &stderr,
	})
	if err != nil {
		t.Fatalf("new runtime logger: %v", err)
	}
	logger.Debug("debug should be suppressed")
	logger.Error("error should be emitted")
	got := stderr.String()
	if strings.Contains(got, "debug should be suppressed") {
		t.Fatalf("expected quiet mode to suppress debug logs, got: %q", got)
	}
	if !strings.Contains(got, "error should be emitted") {
		t.Fatalf("expected error log in quiet mode, got: %q", got)
	}
}
