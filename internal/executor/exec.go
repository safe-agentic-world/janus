package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type ExecParams struct {
	Argv               []string          `json:"argv"`
	Cwd                string            `json:"cwd"`
	EnvAllowlistKeys   []string          `json:"env_allowlist_keys"`
	CredentialLeaseIDs []string          `json:"credential_lease_ids,omitempty"`
	InjectedEnv        map[string]string `json:"-"`
}

type ExecResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Truncated bool
}

type ExecRunner struct {
	workspaceRoot string
	maxBytes      int
	timeout       time.Duration
}

var safeCommandNamePattern = regexp.MustCompile(`^[A-Za-z0-9._:/\\+-]+$`)
var prohibitedShellCommands = map[string]struct{}{
	"sh":         {},
	"bash":       {},
	"dash":       {},
	"zsh":        {},
	"fish":       {},
	"ksh":        {},
	"cmd":        {},
	"powershell": {},
	"pwsh":       {},
}

func NewExecRunner(workspaceRoot string, maxBytes int) *ExecRunner {
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	return &ExecRunner{
		workspaceRoot: workspaceRoot,
		maxBytes:      maxBytes,
		timeout:       5 * time.Second,
	}
}

func (r *ExecRunner) Run(params ExecParams) (ExecResult, error) {
	if len(params.Argv) == 0 {
		return ExecResult{}, errors.New("argv is required")
	}
	if err := validateExecCommand(params.Argv); err != nil {
		return ExecResult{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, params.Argv[0], params.Argv[1:]...)
	cwd := r.workspaceRoot
	if params.Cwd != "" {
		if strings.HasPrefix(params.Cwd, "..") {
			return ExecResult{}, errors.New("cwd escape detected")
		}
		cwd = params.Cwd
	}
	absRoot, err := filepath.Abs(r.workspaceRoot)
	if err != nil {
		return ExecResult{}, err
	}
	absCwd, err := filepath.Abs(cwd)
	if err != nil {
		return ExecResult{}, err
	}
	rel, err := filepath.Rel(absRoot, absCwd)
	if err != nil {
		return ExecResult{}, errors.New("cwd escape detected")
	}
	if strings.HasPrefix(rel, "..") {
		return ExecResult{}, errors.New("cwd escape detected")
	}
	cmd.Dir = absCwd
	cmd.Env = filteredEnv(params.EnvAllowlistKeys, params.InjectedEnv)
	stdout := newLimitedBuffer(r.maxBytes)
	stderr := newLimitedBuffer(r.maxBytes)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return ExecResult{}, err
		}
	}
	truncated := stdout.Truncated || stderr.Truncated
	return ExecResult{
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		ExitCode:  exitCode,
		Truncated: truncated,
	}, nil
}

func validateExecCommand(argv []string) error {
	command := strings.TrimSpace(argv[0])
	if command == "" {
		return errors.New("argv[0] is required")
	}
	if !safeCommandNamePattern.MatchString(command) {
		return errors.New("argv[0] contains unsupported characters")
	}
	if _, blocked := prohibitedShellCommands[commandRootName(command)]; blocked {
		return errors.New("shell interpreter commands are not supported")
	}
	for _, arg := range argv[1:] {
		if arg == "--" {
			continue
		}
		if strings.HasPrefix(arg, "--") {
			return errors.New("argv arguments must not start with --")
		}
	}
	return nil
}

func commandRootName(command string) string {
	base := strings.ToLower(filepath.Base(command))
	return strings.TrimSuffix(base, strings.ToLower(filepath.Ext(base)))
}

func filteredEnv(allowlist []string, injected map[string]string) []string {
	allowed := map[string]struct{}{}
	for _, key := range allowlist {
		allowed[key] = struct{}{}
	}
	out := make([]string, 0)
	for _, kv := range os.Environ() {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if _, ok := allowed[parts[0]]; ok {
			out = append(out, kv)
		}
	}
	for key, value := range injected {
		if _, ok := allowed[key]; ok {
			out = append(out, key+"="+value)
		}
	}
	return out
}

type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	Truncated bool
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{limit: limit}
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.Truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		b.buf.Write(p[:remaining])
		b.Truncated = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}
