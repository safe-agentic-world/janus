package mcp

import (
	"reflect"
	"testing"
)

func TestNormalizeExecParamsUnwrapsPowerShellCommand(t *testing.T) {
	params, err := normalizeExecParams(execParams{
		Argv: []string{`C:\Program Files\PowerShell\7\pwsh.exe`, "-Command", "git status"},
	})
	if err != nil {
		t.Fatalf("normalize exec params: %v", err)
	}
	want := []string{"git", "status"}
	if !reflect.DeepEqual(params.Argv, want) {
		t.Fatalf("argv = %+v, want %+v", params.Argv, want)
	}
}

func TestNormalizeExecParamsUnwrapsPowerShellCommandTokens(t *testing.T) {
	params, err := normalizeExecParams(execParams{
		Argv: []string{"pwsh", "-NoProfile", "-NonInteractive", "-Command", "git", "status"},
	})
	if err != nil {
		t.Fatalf("normalize exec params: %v", err)
	}
	want := []string{"git", "status"}
	if !reflect.DeepEqual(params.Argv, want) {
		t.Fatalf("argv = %+v, want %+v", params.Argv, want)
	}
}

func TestNormalizeExecParamsUnwrapsCmdCommand(t *testing.T) {
	params, err := normalizeExecParams(execParams{
		Argv: []string{"cmd.exe", "/c", "git status"},
	})
	if err != nil {
		t.Fatalf("normalize exec params: %v", err)
	}
	want := []string{"git", "status"}
	if !reflect.DeepEqual(params.Argv, want) {
		t.Fatalf("argv = %+v, want %+v", params.Argv, want)
	}
}

func TestNormalizeExecParamsRejectsComplexShellCommand(t *testing.T) {
	for _, argv := range [][]string{
		{"pwsh", "-Command", "git status; git push"},
		{"pwsh", "-Command", "git status && git push"},
		{"bash", "-c", "git status | cat"},
	} {
		if _, err := normalizeExecParams(execParams{Argv: argv}); err == nil {
			t.Fatalf("expected complex shell command to be rejected: %+v", argv)
		}
	}
}

func TestNormalizeExecParamsLeavesDirectArgvUnchanged(t *testing.T) {
	params, err := normalizeExecParams(execParams{
		Argv: []string{"git", "status"},
	})
	if err != nil {
		t.Fatalf("normalize exec params: %v", err)
	}
	want := []string{"git", "status"}
	if !reflect.DeepEqual(params.Argv, want) {
		t.Fatalf("argv = %+v, want %+v", params.Argv, want)
	}
}
