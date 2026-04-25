package executor

import (
	"runtime"
	"strings"
	"testing"
)

func TestExecRunnerRejectsShellInterpreters(t *testing.T) {
	runner := NewExecRunner(t.TempDir(), 1024)
	argv := []string{"sh", "-c", "echo ok"}
	if runtime.GOOS == "windows" {
		argv = []string{"cmd.exe", "/c", "echo", "ok"}
	}
	_, err := runner.Run(ExecParams{Argv: argv})
	if err == nil {
		t.Fatal("expected shell interpreter rejection")
	}
	if !strings.Contains(err.Error(), "shell interpreter commands are not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}
