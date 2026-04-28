package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/sandbox"
	"github.com/safe-agentic-world/nomos/internal/telemetry"
)

type RuntimeOptions struct {
	LogLevel              string
	Quiet                 bool
	LogFormat             string
	ErrWriter             io.Writer
	ExecCompatibilityMode string
	BundleRoles           []string
	SandboxEvidence       sandbox.Evidence
	ApprovalStorePath     string
	ApprovalTTLSeconds    int
	UpstreamRoutes        []UpstreamRoute
	UpstreamServers       []UpstreamServerConfig
	Telemetry             *telemetry.Emitter
}

type UpstreamRoute struct {
	URL        string
	Methods    []string
	PathPrefix string
}

type UpstreamServerConfig struct {
	Name              string
	Transport         string
	Command           string
	Args              []string
	EnvAllowlist      []string
	Env               map[string]string
	Workdir           string
	Endpoint          string
	AllowedHosts      []string
	TLSInsecure       bool
	TLSCAFile         string
	TLSCertFile       string
	TLSKeyFile        string
	AuthType          string
	AuthToken         string
	AuthHeader        string
	AuthValue         string
	AuthHeaders       map[string]string
	InitializeTimeout time.Duration
	EnumerateTimeout  time.Duration
	CallTimeout       time.Duration
	StreamTimeout     time.Duration
	BreakerEnabled    bool
	BreakerThreshold  int
	BreakerWindow     time.Duration
	BreakerOpenTime   time.Duration
}

type logLevel int

const (
	logLevelError logLevel = iota
	logLevelWarn
	logLevelInfo
	logLevelDebug
)

func ParseRuntimeOptions(options RuntimeOptions) (RuntimeOptions, error) {
	level := strings.TrimSpace(options.LogLevel)
	if level == "" {
		level = "info"
	}
	if _, err := parseLogLevel(level); err != nil {
		return RuntimeOptions{}, err
	}
	format := strings.TrimSpace(options.LogFormat)
	if format == "" {
		format = "text"
	}
	if format != "text" && format != "json" {
		return RuntimeOptions{}, fmt.Errorf("invalid log format %q: expected text or json", format)
	}
	if options.ErrWriter == nil {
		options.ErrWriter = os.Stderr
	}
	if options.ExecCompatibilityMode != "" {
		if normalized := policy.NormalizeExecCompatibilityMode(options.ExecCompatibilityMode); normalized == "" {
			return RuntimeOptions{}, fmt.Errorf("invalid exec compatibility mode %q: expected legacy_allowlist_fallback|strict", strings.TrimSpace(options.ExecCompatibilityMode))
		} else {
			options.ExecCompatibilityMode = normalized
		}
	}
	return RuntimeOptions{
		LogLevel:              level,
		Quiet:                 options.Quiet,
		LogFormat:             format,
		ErrWriter:             options.ErrWriter,
		ExecCompatibilityMode: options.ExecCompatibilityMode,
		BundleRoles:           options.BundleRoles,
		SandboxEvidence:       options.SandboxEvidence,
		ApprovalStorePath:     strings.TrimSpace(options.ApprovalStorePath),
		ApprovalTTLSeconds:    options.ApprovalTTLSeconds,
		UpstreamRoutes:        append([]UpstreamRoute(nil), options.UpstreamRoutes...),
		UpstreamServers:       append([]UpstreamServerConfig(nil), options.UpstreamServers...),
		Telemetry:             options.Telemetry,
	}, nil
}

func (c UpstreamServerConfig) breakerConfig() upstreamBreakerConfig {
	return upstreamBreakerConfig{
		Enabled:          c.BreakerEnabled,
		FailureThreshold: c.BreakerThreshold,
		FailureWindow:    c.BreakerWindow,
		OpenTimeout:      c.BreakerOpenTime,
	}
}

func parseLogLevel(value string) (logLevel, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "error":
		return logLevelError, nil
	case "warn":
		return logLevelWarn, nil
	case "info":
		return logLevelInfo, nil
	case "debug":
		return logLevelDebug, nil
	default:
		return logLevelInfo, fmt.Errorf("invalid log level %q: expected error|warn|info|debug", strings.TrimSpace(value))
	}
}

type runtimeLogger struct {
	mu       sync.Mutex
	level    logLevel
	format   string
	quiet    bool
	errOut   io.Writer
	redactor *redact.Redactor
	banner   bool
}

func newRuntimeLogger(options RuntimeOptions) (*runtimeLogger, error) {
	normalized, err := ParseRuntimeOptions(options)
	if err != nil {
		return nil, err
	}
	level, err := parseLogLevel(normalized.LogLevel)
	if err != nil {
		return nil, err
	}
	if normalized.Quiet {
		level = logLevelError
	}
	return &runtimeLogger{
		level:    level,
		format:   normalized.LogFormat,
		quiet:    normalized.Quiet,
		errOut:   normalized.ErrWriter,
		redactor: redact.DefaultRedactor(),
	}, nil
}

func (l *runtimeLogger) Error(message string) {
	l.write(logLevelError, "error", message)
}

func (l *runtimeLogger) Warn(message string) {
	l.write(logLevelWarn, "warn", message)
}

func (l *runtimeLogger) Debug(message string) {
	l.write(logLevelDebug, "debug", message)
}

func (l *runtimeLogger) ReadyBanner(environment, policyBundleHash string, policyBundleSources []string, engineVersion string, pid int) {
	if l.quiet {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.banner {
		return
	}
	line := fmt.Sprintf("[Nomos] MCP server ready (env=%s, policy_bundle_hash=%s, engine=%s, pid=%d", environment, policyBundleHash, engineVersion, pid)
	if len(policyBundleSources) > 0 {
		line += ", policy_bundle_sources=" + strings.Join(policyBundleSources, ";")
	}
	line += ")"
	l.writeLocked(line)
	l.banner = true
}

func (l *runtimeLogger) write(level logLevel, label, message string) {
	if level > l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.format == "json" {
		payload := map[string]string{
			"component": "nomos.mcp",
			"level":     label,
			"message":   message,
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return
		}
		l.writeLocked(string(data))
		return
	}
	l.writeLocked("[Nomos] " + strings.ToUpper(label) + " " + message)
}

func (l *runtimeLogger) writeLocked(line string) {
	redacted := l.redactor.RedactText(line)
	if !strings.HasSuffix(redacted, "\n") {
		redacted += "\n"
	}
	_, _ = io.WriteString(l.errOut, redacted)
}
