package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/assurance"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/sandbox"
)

type Config struct {
	Gateway     GatewayConfig     `json:"gateway"`
	Runtime     RuntimeConfig     `json:"runtime"`
	Policy      PolicyConfig      `json:"policy"`
	Executor    ExecutorConfig    `json:"executor"`
	Credentials CredentialsConfig `json:"credentials"`
	Audit       AuditConfig       `json:"audit"`
	Telemetry   TelemetryConfig   `json:"telemetry"`
	MCP         MCPConfig         `json:"mcp"`
	Upstream    UpstreamConfig    `json:"upstream"`
	Approvals   ApprovalsConfig   `json:"approvals"`
	Identity    IdentityConfig    `json:"identity"`
	Redaction   RedactionConfig   `json:"redaction"`
	SourcePath  string            `json:"-"`
}

type GatewayConfig struct {
	Listen           string    `json:"listen"`
	Transport        string    `json:"transport"`
	ConcurrencyLimit int       `json:"concurrency_limit"`
	RateLimitPerMin  int       `json:"rate_limit_per_minute"`
	CircuitFailures  int       `json:"circuit_breaker_failures"`
	CircuitCooldownS int       `json:"circuit_breaker_cooldown_seconds"`
	TLS              TLSConfig `json:"tls"`
}

type TLSConfig struct {
	Enabled      bool   `json:"enabled"`
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	ClientCAFile string `json:"client_ca_file"`
	RequireMTLS  bool   `json:"require_mtls"`
}

type RuntimeConfig struct {
	StatelessMode   bool                  `json:"stateless_mode"`
	StrongGuarantee bool                  `json:"strong_guarantee"`
	DeploymentMode  string                `json:"deployment_mode"`
	Evidence        RuntimeEvidenceConfig `json:"evidence"`
}

type RuntimeEvidenceConfig struct {
	ContainerBackendReady    bool `json:"container_backend_ready"`
	Rootless                 bool `json:"rootless_or_non_privileged"`
	ReadOnlyFS               bool `json:"read_only_fs"`
	NoNewPrivileges          bool `json:"no_new_privileges"`
	NetworkDefaultDeny       bool `json:"network_default_deny"`
	WorkloadIdentityVerified bool `json:"workload_identity_verified"`
	DurableAuditVerified     bool `json:"durable_audit_verified"`
}

type PolicyConfig struct {
	BundlePath            string    `json:"policy_bundle_path"`
	BundlePaths           []string  `json:"policy_bundle_paths"`
	BundleRoles           []string  `json:"policy_bundle_roles"`
	VerifySignatures      bool      `json:"verify_signatures"`
	SignaturePath         string    `json:"signature_path"`
	SignaturePaths        []string  `json:"signature_paths"`
	PublicKeyPath         string    `json:"public_key_path"`
	ExecCompatibilityMode string    `json:"exec_compatibility_mode"`
	ExplainSuggestions    *bool     `json:"explain_suggestions,omitempty"`
	OPA                   OPAConfig `json:"opa"`
}

type OPAConfig struct {
	Enabled    bool   `json:"enabled"`
	BinaryPath string `json:"binary_path"`
	PolicyPath string `json:"policy_path"`
	Query      string `json:"query"`
	TimeoutMS  int    `json:"timeout_ms"`
}

type ExecutorConfig struct {
	SandboxEnabled bool   `json:"sandbox_enabled"`
	WorkspaceRoot  string `json:"workspace_root"`
	MaxOutputBytes int    `json:"max_output_bytes"`
	MaxOutputLines int    `json:"max_output_lines"`
	SandboxProfile string `json:"sandbox_profile"`
}

type CredentialsConfig struct {
	Enabled bool               `json:"enabled"`
	Secrets []CredentialSecret `json:"secrets"`
}

type CredentialSecret struct {
	ID         string `json:"id"`
	EnvKey     string `json:"env_key"`
	Value      string `json:"value"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type AuditConfig struct {
	Sink string `json:"sink"`
}

type TelemetryConfig struct {
	Enabled bool   `json:"enabled"`
	Sink    string `json:"sink"`
}

type RedactionConfig struct {
	Patterns []string `json:"patterns"`
}

type MCPConfig struct {
	Enabled bool `json:"enabled"`
}

type UpstreamRoute struct {
	URL        string   `json:"url"`
	Methods    []string `json:"methods,omitempty"`
	PathPrefix string   `json:"path_prefix,omitempty"`
}

type UpstreamConfig struct {
	Routes []UpstreamRoute `json:"routes"`
}

func (u *UpstreamConfig) UnmarshalJSON(data []byte) error {
	type typedUpstreamConfig struct {
		Routes []UpstreamRoute `json:"routes"`
	}
	var typed typedUpstreamConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&typed); err == nil {
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			return errors.New("upstream config contains trailing data")
		}
		u.Routes = typed.Routes
		return nil
	}

	var legacy struct {
		Routes []string `json:"routes"`
	}
	dec = json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&legacy); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("upstream config contains trailing data")
	}
	u.Routes = make([]UpstreamRoute, 0, len(legacy.Routes))
	for _, route := range legacy.Routes {
		u.Routes = append(u.Routes, UpstreamRoute{URL: route})
	}
	return nil
}

type ApprovalsConfig struct {
	Enabled      bool   `json:"enabled"`
	StorePath    string `json:"store_path"`
	TTLSeconds   int    `json:"ttl_seconds"`
	WebhookToken string `json:"webhook_token"`
	SlackToken   string `json:"slack_token"`
	TeamsToken   string `json:"teams_token"`
}

type IdentityConfig struct {
	Principal      string            `json:"principal"`
	Agent          string            `json:"agent"`
	Environment    string            `json:"environment"`
	APIKeys        map[string]string `json:"api_keys"`
	ServiceSecrets map[string]string `json:"service_secrets"`
	AgentSecrets   map[string]string `json:"agent_secrets"`
	OIDC           OIDCConfig        `json:"oidc"`
	SPIFFE         SPIFFEConfig      `json:"spiffe"`
}

type OIDCConfig struct {
	Enabled       bool   `json:"enabled"`
	Issuer        string `json:"issuer"`
	Audience      string `json:"audience"`
	PublicKeyPath string `json:"public_key_path"`
}

type SPIFFEConfig struct {
	Enabled     bool   `json:"enabled"`
	TrustDomain string `json:"trust_domain"`
}

func LoadConfig(path string, getenv func(string) string, policyBundleOverride string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Config{}, errors.New("config contains trailing data")
	}

	ApplyEnvOverrides(&cfg, getenv)
	if policyBundleOverride != "" {
		cfg.Policy.BundlePath = policyBundleOverride
		cfg.Policy.BundlePaths = nil
	}
	cfg.SourcePath = path
	if err := cfg.ResolveRelativePaths(filepath.Dir(path)); err != nil {
		return Config{}, err
	}

	if err := cfg.SetDefaults(); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) SetDefaults() error {
	if c.Gateway.Listen == "" {
		c.Gateway.Listen = ":8080"
	}
	if c.Gateway.Transport == "" {
		c.Gateway.Transport = "http"
	}
	if c.Gateway.ConcurrencyLimit == 0 {
		c.Gateway.ConcurrencyLimit = 32
	}
	if c.Gateway.RateLimitPerMin == 0 {
		c.Gateway.RateLimitPerMin = 120
	}
	if c.Gateway.CircuitFailures == 0 {
		c.Gateway.CircuitFailures = 5
	}
	if c.Gateway.CircuitCooldownS == 0 {
		c.Gateway.CircuitCooldownS = 60
	}
	if c.Audit.Sink == "" {
		c.Audit.Sink = "stdout"
	}
	if c.Telemetry.Enabled && c.Telemetry.Sink == "" {
		c.Telemetry.Sink = "stdout"
	}
	if c.Executor.WorkspaceRoot == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		c.Executor.WorkspaceRoot = cwd
	}
	if c.Executor.MaxOutputBytes == 0 {
		c.Executor.MaxOutputBytes = 64 * 1024
	}
	if c.Executor.MaxOutputLines == 0 {
		c.Executor.MaxOutputLines = 200
	}
	if c.Policy.ExplainSuggestions == nil {
		enabled := true
		c.Policy.ExplainSuggestions = &enabled
	}
	if strings.TrimSpace(c.Policy.ExecCompatibilityMode) == "" {
		c.Policy.ExecCompatibilityMode = policy.ExecCompatibilityLegacyAllowlistFallback
	}
	if c.Policy.OPA.Enabled && c.Policy.OPA.TimeoutMS == 0 {
		c.Policy.OPA.TimeoutMS = 2000
	}
	if strings.TrimSpace(c.Runtime.DeploymentMode) == "" {
		c.Runtime.DeploymentMode = "unmanaged"
	}
	if c.Executor.SandboxProfile == "" {
		if c.Executor.SandboxEnabled {
			c.Executor.SandboxProfile = "local"
		} else {
			c.Executor.SandboxProfile = "none"
		}
	}
	if c.Credentials.Enabled && len(c.Credentials.Secrets) == 0 {
		c.Credentials.Enabled = false
	}
	if c.Approvals.Enabled {
		if c.Approvals.StorePath == "" {
			c.Approvals.StorePath = "nomos-approvals.db"
		}
		if c.Approvals.TTLSeconds == 0 {
			c.Approvals.TTLSeconds = 900
		}
	}
	return nil
}

func (c Config) Validate() error {
	var errs []string
	if c.Gateway.Listen == "" {
		errs = append(errs, "gateway.listen is required")
	}
	if c.Gateway.Transport != "http" {
		errs = append(errs, "gateway.transport must be \"http\"")
	}
	if c.Gateway.ConcurrencyLimit <= 0 {
		errs = append(errs, "gateway.concurrency_limit must be > 0")
	}
	if c.Gateway.RateLimitPerMin <= 0 {
		errs = append(errs, "gateway.rate_limit_per_minute must be > 0")
	}
	if c.Gateway.CircuitFailures <= 0 {
		errs = append(errs, "gateway.circuit_breaker_failures must be > 0")
	}
	if c.Gateway.CircuitCooldownS <= 0 {
		errs = append(errs, "gateway.circuit_breaker_cooldown_seconds must be > 0")
	}
	if c.Gateway.TLS.Enabled {
		if c.Gateway.TLS.CertFile == "" || c.Gateway.TLS.KeyFile == "" {
			errs = append(errs, "gateway.tls.cert_file and gateway.tls.key_file are required when tls.enabled is true")
		}
		if c.Gateway.TLS.RequireMTLS && c.Gateway.TLS.ClientCAFile == "" {
			errs = append(errs, "gateway.tls.client_ca_file is required when tls.require_mtls is true")
		}
	}
	if c.Identity.Principal == "" {
		errs = append(errs, "identity.principal is required")
	}
	if c.Identity.Agent == "" {
		errs = append(errs, "identity.agent is required")
	}
	if c.Identity.Environment == "" {
		errs = append(errs, "identity.environment is required")
	}
	if len(c.Identity.APIKeys) == 0 && len(c.Identity.ServiceSecrets) == 0 && !c.Identity.OIDC.Enabled && !c.Identity.SPIFFE.Enabled {
		errs = append(errs, "identity.api_keys or identity.service_secrets or identity.oidc.enabled or identity.spiffe.enabled is required")
	}
	if len(c.Identity.AgentSecrets) == 0 {
		errs = append(errs, "identity.agent_secrets is required")
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	if c.Identity.OIDC.Enabled {
		if c.Identity.OIDC.Issuer == "" || c.Identity.OIDC.Audience == "" || c.Identity.OIDC.PublicKeyPath == "" {
			return errors.New("identity.oidc.issuer, identity.oidc.audience, and identity.oidc.public_key_path are required when oidc.enabled is true")
		}
		if _, err := os.Stat(c.Identity.OIDC.PublicKeyPath); err != nil {
			return fmt.Errorf("oidc public key path invalid: %w", err)
		}
	}
	if c.Identity.SPIFFE.Enabled && strings.TrimSpace(c.Identity.SPIFFE.TrustDomain) == "" {
		return errors.New("identity.spiffe.trust_domain is required when spiffe.enabled is true")
	}
	if c.Runtime.StatelessMode {
		if c.Approvals.Enabled {
			return errors.New("approvals must be disabled in runtime.stateless_mode")
		}
		if strings.Contains(c.Audit.Sink, "sqlite:") || strings.Contains(c.Audit.Sink, "sqlite://") {
			return errors.New("sqlite audit sink is not allowed in runtime.stateless_mode")
		}
	}
	switch strings.TrimSpace(c.Runtime.DeploymentMode) {
	case "ci", "k8s", "remote_dev", "unmanaged":
	case "":
		return errors.New("runtime.deployment_mode is required")
	default:
		return errors.New("runtime.deployment_mode must be one of ci, k8s, remote_dev, unmanaged")
	}
	if c.Credentials.Enabled {
		if len(c.Credentials.Secrets) == 0 {
			return errors.New("credentials.secrets is required when credentials.enabled is true")
		}
		for _, s := range c.Credentials.Secrets {
			if s.ID == "" || s.EnvKey == "" || s.Value == "" {
				return errors.New("credentials secret id/env_key/value are required")
			}
			if s.TTLSeconds <= 0 {
				return errors.New("credentials secret ttl_seconds must be > 0")
			}
		}
	}
	if c.Telemetry.Enabled {
		sink := strings.TrimSpace(c.Telemetry.Sink)
		switch {
		case sink == "stdout", sink == "stderr", strings.HasPrefix(sink, "otlp:"):
		default:
			return errors.New("telemetry.sink must be stdout, stderr, or otlp:<base_url>")
		}
	}
	if c.Approvals.Enabled {
		if c.Approvals.StorePath == "" {
			return errors.New("approvals.store_path is required when approvals are enabled")
		}
		if c.Approvals.TTLSeconds <= 0 {
			return errors.New("approvals.ttl_seconds must be > 0 when approvals are enabled")
		}
	}
	if strings.TrimSpace(c.Policy.BundlePath) != "" && len(c.Policy.BundlePaths) > 0 {
		return errors.New("policy.policy_bundle_path and policy.policy_bundle_paths are mutually exclusive")
	}
	if policy.NormalizeExecCompatibilityMode(c.Policy.ExecCompatibilityMode) == "" {
		return errors.New("policy.exec_compatibility_mode must be one of legacy_allowlist_fallback or strict")
	}
	effectiveBundlePaths := c.Policy.BundlePaths
	if strings.TrimSpace(c.Policy.BundlePath) != "" {
		effectiveBundlePaths = []string{c.Policy.BundlePath}
	}
	if len(effectiveBundlePaths) == 0 {
		return errors.New("policy.policy_bundle_path or policy.policy_bundle_paths is required")
	}
	for _, path := range effectiveBundlePaths {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("policy bundle path invalid: %w", err)
		}
	}
	if len(c.Policy.BundleRoles) > 0 {
		if len(c.Policy.BundleRoles) != len(effectiveBundlePaths) {
			return errors.New("policy.policy_bundle_roles must have the same length as the effective policy bundle path list")
		}
		hasLocalOverride := false
		for _, role := range c.Policy.BundleRoles {
			switch normalizeBundleRole(role) {
			case "baseline", "org", "repo", "env":
			case "local_override":
				hasLocalOverride = true
			default:
				return errors.New("policy.policy_bundle_roles entries must be baseline, org, repo, env, or local_override")
			}
		}
		if hasLocalOverride {
			env := strings.ToLower(strings.TrimSpace(c.Identity.Environment))
			mode := strings.ToLower(strings.TrimSpace(c.Runtime.DeploymentMode))
			if env != "dev" && env != "local" {
				return errors.New("policy local_override bundles are only allowed for identity.environment dev or local")
			}
			if mode != "unmanaged" {
				return errors.New("policy local_override bundles are only allowed for runtime.deployment_mode unmanaged")
			}
		}
	}
	if c.Policy.VerifySignatures {
		if c.Policy.PublicKeyPath == "" {
			return errors.New("policy.public_key_path is required when policy.verify_signatures is true")
		}
		if _, err := os.Stat(c.Policy.PublicKeyPath); err != nil {
			return fmt.Errorf("policy public key path invalid: %w", err)
		}
		if len(effectiveBundlePaths) > 1 {
			if len(c.Policy.SignaturePaths) != len(effectiveBundlePaths) {
				return errors.New("policy.signature_paths must have the same length as policy.policy_bundle_paths when policy.verify_signatures is true")
			}
			for _, path := range c.Policy.SignaturePaths {
				if _, err := os.Stat(path); err != nil {
					return fmt.Errorf("policy signature path invalid: %w", err)
				}
			}
		} else {
			if c.Policy.SignaturePath == "" {
				return errors.New("policy.signature_path is required when policy.verify_signatures is true")
			}
			if _, err := os.Stat(c.Policy.SignaturePath); err != nil {
				return fmt.Errorf("policy signature path invalid: %w", err)
			}
		}
	}
	if c.Policy.OPA.Enabled {
		if strings.TrimSpace(c.Policy.OPA.BinaryPath) == "" {
			return errors.New("policy.opa.binary_path is required when policy.opa.enabled is true")
		}
		if strings.TrimSpace(c.Policy.OPA.PolicyPath) == "" {
			return errors.New("policy.opa.policy_path is required when policy.opa.enabled is true")
		}
		if strings.TrimSpace(c.Policy.OPA.Query) == "" {
			return errors.New("policy.opa.query is required when policy.opa.enabled is true")
		}
		if c.Policy.OPA.TimeoutMS <= 0 {
			return errors.New("policy.opa.timeout_ms must be > 0 when policy.opa.enabled is true")
		}
		if _, err := os.Stat(c.Policy.OPA.PolicyPath); err != nil {
			return fmt.Errorf("policy.opa.policy_path invalid: %w", err)
		}
	}
	for _, route := range c.Upstream.Routes {
		raw := strings.TrimSpace(route.URL)
		if raw == "" {
			return errors.New("upstream.routes.url is required")
		}
		parsed, err := neturl.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return errors.New("upstream.routes.url must be an absolute URL")
		}
		for _, method := range route.Methods {
			if strings.TrimSpace(method) == "" {
				return errors.New("upstream.routes.methods entries must be non-empty")
			}
		}
		if value := strings.TrimSpace(route.PathPrefix); value != "" && !strings.HasPrefix(value, "/") {
			return errors.New("upstream.routes.path_prefix must start with /")
		}
	}
	return nil
}

func ApplyEnvOverrides(cfg *Config, getenv func(string) string) {
	if v := getenv("NOMOS_GATEWAY_LISTEN"); v != "" {
		cfg.Gateway.Listen = v
	}
	if v := getenv("NOMOS_GATEWAY_TRANSPORT"); v != "" {
		cfg.Gateway.Transport = v
	}
	if v := getenv("NOMOS_GATEWAY_CONCURRENCY_LIMIT"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Gateway.ConcurrencyLimit = parsed
		}
	}
	if v := getenv("NOMOS_GATEWAY_RATE_LIMIT_PER_MINUTE"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Gateway.RateLimitPerMin = parsed
		}
	}
	if v := getenv("NOMOS_GATEWAY_CIRCUIT_BREAKER_FAILURES"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Gateway.CircuitFailures = parsed
		}
	}
	if v := getenv("NOMOS_GATEWAY_CIRCUIT_BREAKER_COOLDOWN_SECONDS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Gateway.CircuitCooldownS = parsed
		}
	}
	if v := getenv("NOMOS_RUNTIME_STATELESS_MODE"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Runtime.StatelessMode = parsed
		}
	}
	if v := getenv("NOMOS_RUNTIME_STRONG_GUARANTEE"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Runtime.StrongGuarantee = parsed
		}
	}
	if v := getenv("NOMOS_RUNTIME_DEPLOYMENT_MODE"); v != "" {
		cfg.Runtime.DeploymentMode = v
	}
	if v := getenv("NOMOS_RUNTIME_EVIDENCE_CONTAINER_BACKEND_READY"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Runtime.Evidence.ContainerBackendReady = parsed
		}
	}
	if v := getenv("NOMOS_RUNTIME_EVIDENCE_ROOTLESS"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Runtime.Evidence.Rootless = parsed
		}
	}
	if v := getenv("NOMOS_RUNTIME_EVIDENCE_READ_ONLY_FS"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Runtime.Evidence.ReadOnlyFS = parsed
		}
	}
	if v := getenv("NOMOS_RUNTIME_EVIDENCE_NO_NEW_PRIVILEGES"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Runtime.Evidence.NoNewPrivileges = parsed
		}
	}
	if v := getenv("NOMOS_RUNTIME_EVIDENCE_NETWORK_DEFAULT_DENY"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Runtime.Evidence.NetworkDefaultDeny = parsed
		}
	}
	if v := getenv("NOMOS_RUNTIME_EVIDENCE_WORKLOAD_IDENTITY_VERIFIED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Runtime.Evidence.WorkloadIdentityVerified = parsed
		}
	}
	if v := getenv("NOMOS_RUNTIME_EVIDENCE_DURABLE_AUDIT_VERIFIED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Runtime.Evidence.DurableAuditVerified = parsed
		}
	}
	if v := getenv("NOMOS_POLICY_BUNDLE_PATH"); v != "" {
		cfg.Policy.BundlePath = v
		cfg.Policy.BundlePaths = nil
	}
	if v := getenv("NOMOS_POLICY_BUNDLE_PATHS"); v != "" {
		cfg.Policy.BundlePaths = splitList(v)
		cfg.Policy.BundlePath = ""
	}
	if v := getenv("NOMOS_POLICY_BUNDLE_ROLES"); v != "" {
		cfg.Policy.BundleRoles = splitList(v)
	}
	if v := getenv("NOMOS_POLICY_VERIFY_SIGNATURES"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Policy.VerifySignatures = parsed
		}
	}
	if v := getenv("NOMOS_POLICY_SIGNATURE_PATH"); v != "" {
		cfg.Policy.SignaturePath = v
	}
	if v := getenv("NOMOS_POLICY_SIGNATURE_PATHS"); v != "" {
		cfg.Policy.SignaturePaths = splitList(v)
		cfg.Policy.SignaturePath = ""
	}
	if v := getenv("NOMOS_POLICY_PUBLIC_KEY_PATH"); v != "" {
		cfg.Policy.PublicKeyPath = v
	}
	if v := getenv("NOMOS_POLICY_EXEC_COMPATIBILITY_MODE"); v != "" {
		cfg.Policy.ExecCompatibilityMode = v
	}
	if v := getenv("NOMOS_POLICY_EXPLAIN_SUGGESTIONS"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Policy.ExplainSuggestions = &parsed
		}
	}
	if v := getenv("NOMOS_POLICY_OPA_ENABLED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Policy.OPA.Enabled = parsed
		}
	}
	if v := getenv("NOMOS_POLICY_OPA_BINARY_PATH"); v != "" {
		cfg.Policy.OPA.BinaryPath = v
	}
	if v := getenv("NOMOS_POLICY_OPA_POLICY_PATH"); v != "" {
		cfg.Policy.OPA.PolicyPath = v
	}
	if v := getenv("NOMOS_POLICY_OPA_QUERY"); v != "" {
		cfg.Policy.OPA.Query = v
	}
	if v := getenv("NOMOS_POLICY_OPA_TIMEOUT_MS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Policy.OPA.TimeoutMS = parsed
		}
	}
	if v := getenv("NOMOS_EXECUTOR_SANDBOX_ENABLED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Executor.SandboxEnabled = parsed
		}
	}
	if v := getenv("NOMOS_EXECUTOR_SANDBOX_PROFILE"); v != "" {
		cfg.Executor.SandboxProfile = v
	}
	if v := getenv("NOMOS_EXECUTOR_WORKSPACE_ROOT"); v != "" {
		cfg.Executor.WorkspaceRoot = v
	}
	if v := getenv("NOMOS_EXECUTOR_MAX_OUTPUT_BYTES"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Executor.MaxOutputBytes = parsed
		}
	}
	if v := getenv("NOMOS_EXECUTOR_MAX_OUTPUT_LINES"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Executor.MaxOutputLines = parsed
		}
	}
	if v := getenv("NOMOS_CREDENTIALS_ENABLED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Credentials.Enabled = parsed
		}
	}
	if v := getenv("NOMOS_AUDIT_SINK"); v != "" {
		cfg.Audit.Sink = v
	}
	if v := getenv("NOMOS_TELEMETRY_ENABLED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Telemetry.Enabled = parsed
		}
	}
	if v := getenv("NOMOS_TELEMETRY_SINK"); v != "" {
		cfg.Telemetry.Sink = v
	}
	if v := getenv("NOMOS_REDACTION_PATTERNS"); v != "" {
		cfg.Redaction.Patterns = splitList(v)
	}
	if v := getenv("NOMOS_MCP_ENABLED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.MCP.Enabled = parsed
		}
	}
	if v := getenv("NOMOS_UPSTREAM_ROUTES"); v != "" {
		values := splitList(v)
		cfg.Upstream.Routes = make([]UpstreamRoute, 0, len(values))
		for _, value := range values {
			cfg.Upstream.Routes = append(cfg.Upstream.Routes, UpstreamRoute{URL: value})
		}
	}
	if v := getenv("NOMOS_APPROVALS_ENABLED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Approvals.Enabled = parsed
		}
	}
	if v := getenv("NOMOS_APPROVALS_STORE_PATH"); v != "" {
		cfg.Approvals.StorePath = v
	}
	if v := getenv("NOMOS_APPROVALS_TTL_SECONDS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			cfg.Approvals.TTLSeconds = parsed
		}
	}
	if v := getenv("NOMOS_APPROVALS_WEBHOOK_TOKEN"); v != "" {
		cfg.Approvals.WebhookToken = v
	}
	if v := getenv("NOMOS_APPROVALS_SLACK_TOKEN"); v != "" {
		cfg.Approvals.SlackToken = v
	}
	if v := getenv("NOMOS_APPROVALS_TEAMS_TOKEN"); v != "" {
		cfg.Approvals.TeamsToken = v
	}
	if v := getenv("NOMOS_IDENTITY_PRINCIPAL"); v != "" {
		cfg.Identity.Principal = v
	}
	if v := getenv("NOMOS_IDENTITY_AGENT"); v != "" {
		cfg.Identity.Agent = v
	}
	if v := getenv("NOMOS_IDENTITY_ENVIRONMENT"); v != "" {
		cfg.Identity.Environment = v
	}
	if v := getenv("NOMOS_IDENTITY_API_KEY"); v != "" {
		if cfg.Identity.APIKeys == nil {
			cfg.Identity.APIKeys = map[string]string{}
		}
		cfg.Identity.APIKeys[v] = cfg.Identity.Principal
	}
	if v := getenv("NOMOS_IDENTITY_AGENT_SECRET"); v != "" {
		if cfg.Identity.AgentSecrets == nil {
			cfg.Identity.AgentSecrets = map[string]string{}
		}
		cfg.Identity.AgentSecrets[cfg.Identity.Agent] = v
	}
	if v := getenv("NOMOS_IDENTITY_OIDC_ENABLED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Identity.OIDC.Enabled = parsed
		}
	}
	if v := getenv("NOMOS_IDENTITY_OIDC_ISSUER"); v != "" {
		cfg.Identity.OIDC.Issuer = v
	}
	if v := getenv("NOMOS_IDENTITY_OIDC_AUDIENCE"); v != "" {
		cfg.Identity.OIDC.Audience = v
	}
	if v := getenv("NOMOS_IDENTITY_OIDC_PUBLIC_KEY_PATH"); v != "" {
		cfg.Identity.OIDC.PublicKeyPath = v
	}
	if v := getenv("NOMOS_IDENTITY_SPIFFE_ENABLED"); v != "" {
		if parsed, ok := parseBool(v); ok {
			cfg.Identity.SPIFFE.Enabled = parsed
		}
	}
	if v := getenv("NOMOS_IDENTITY_SPIFFE_TRUST_DOMAIN"); v != "" {
		cfg.Identity.SPIFFE.TrustDomain = v
	}
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	var out []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseBool(value string) (bool, bool) {
	parsed, err := strconv.ParseBool(value)
	return parsed, err == nil
}

func (c *Config) ResolveRelativePaths(baseDir string) error {
	baseDir = strings.TrimSpace(baseDir)
	if baseDir == "" {
		return nil
	}
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return err
	}
	c.Gateway.TLS.CertFile = resolveRelativePath(absBase, c.Gateway.TLS.CertFile)
	c.Gateway.TLS.KeyFile = resolveRelativePath(absBase, c.Gateway.TLS.KeyFile)
	c.Gateway.TLS.ClientCAFile = resolveRelativePath(absBase, c.Gateway.TLS.ClientCAFile)
	c.Policy.BundlePath = resolveRelativePath(absBase, c.Policy.BundlePath)
	c.Policy.BundlePaths = resolveRelativePaths(absBase, c.Policy.BundlePaths)
	c.Policy.SignaturePath = resolveRelativePath(absBase, c.Policy.SignaturePath)
	c.Policy.SignaturePaths = resolveRelativePaths(absBase, c.Policy.SignaturePaths)
	c.Policy.PublicKeyPath = resolveRelativePath(absBase, c.Policy.PublicKeyPath)
	c.Policy.OPA.PolicyPath = resolveRelativePath(absBase, c.Policy.OPA.PolicyPath)
	c.Executor.WorkspaceRoot = resolveRelativePath(absBase, c.Executor.WorkspaceRoot)
	c.Approvals.StorePath = resolveRelativePath(absBase, c.Approvals.StorePath)
	c.Identity.OIDC.PublicKeyPath = resolveRelativePath(absBase, c.Identity.OIDC.PublicKeyPath)
	c.Audit.Sink = resolveAuditSinkPaths(absBase, c.Audit.Sink)
	return nil
}

func resolveRelativePath(baseDir, value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return value
	}
	trimmed = normalizeConfigPathSeparators(trimmed)
	if filepath.IsAbs(trimmed) {
		return filepath.Clean(trimmed)
	}
	return filepath.Clean(filepath.Join(baseDir, trimmed))
}

func resolveAuditSinkPaths(baseDir, sink string) string {
	parts := strings.Split(strings.TrimSpace(sink), ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "sqlite://"):
			path := strings.TrimPrefix(trimmed, "sqlite://")
			out = append(out, "sqlite://"+resolveRelativePath(baseDir, path))
		case strings.HasPrefix(trimmed, "sqlite:"):
			path := strings.TrimPrefix(trimmed, "sqlite:")
			out = append(out, "sqlite:"+resolveRelativePath(baseDir, path))
		default:
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return sink
	}
	return strings.Join(out, ",")
}

func resolveRelativePaths(baseDir string, values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, resolveRelativePath(baseDir, value))
	}
	return out
}

func (p PolicyConfig) EffectiveBundlePaths() []string {
	if strings.TrimSpace(p.BundlePath) != "" {
		return []string{p.BundlePath}
	}
	out := make([]string, 0, len(p.BundlePaths))
	for _, value := range p.BundlePaths {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func (p PolicyConfig) EffectiveBundleRoles() []string {
	if len(p.BundleRoles) == 0 {
		return nil
	}
	out := make([]string, 0, len(p.BundleRoles))
	for _, value := range p.BundleRoles {
		if trimmed := normalizeBundleRole(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func (p PolicyConfig) EffectiveSignaturePaths() []string {
	if len(p.BundlePaths) > 1 {
		out := make([]string, 0, len(p.SignaturePaths))
		for _, value := range p.SignaturePaths {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	}
	if strings.TrimSpace(p.SignaturePath) == "" {
		return nil
	}
	return []string{p.SignaturePath}
}

func normalizeConfigPathSeparators(value string) string {
	if value == "" {
		return value
	}
	normalized := strings.ReplaceAll(value, "\\", "/")
	return filepath.FromSlash(normalized)
}

func normalizeBundleRole(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "baseline":
		return "baseline"
	case "org":
		return "org"
	case "repo":
		return "repo"
	case "env":
		return "env"
	case "local_override":
		return "local_override"
	default:
		return ""
	}
}

func (r RuntimeEvidenceConfig) SandboxEvidence() sandbox.Evidence {
	return sandbox.Evidence{
		ContainerBackendReady: r.ContainerBackendReady,
		Rootless:              r.Rootless,
		ReadOnlyFS:            r.ReadOnlyFS,
		NoNewPrivileges:       r.NoNewPrivileges,
		NetworkDefaultDeny:    r.NetworkDefaultDeny,
	}
}

func (c Config) AssuranceEvidence() assurance.Evidence {
	workloadIdentityConfigured := c.Identity.OIDC.Enabled || c.Identity.SPIFFE.Enabled
	noSharedAPIKeys := len(c.Identity.APIKeys) == 0
	durableAuditConfigured := hasDurableAuditSinkConfig(c.Audit.Sink)
	return assurance.Evidence{
		RuntimeIsolationVerified: c.Executor.SandboxEnabled && strings.EqualFold(strings.TrimSpace(c.Executor.SandboxProfile), "container") && c.Runtime.Evidence.SandboxEvidence().ContainerReady(),
		WorkloadIdentityVerified: c.Runtime.Evidence.WorkloadIdentityVerified && workloadIdentityConfigured && noSharedAPIKeys,
		DurableAuditVerified:     c.Runtime.Evidence.DurableAuditVerified && durableAuditConfigured,
	}
}

func hasDurableAuditSinkConfig(sink string) bool {
	for _, part := range strings.Split(sink, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "sqlite:") || strings.HasPrefix(part, "sqlite://") || strings.HasPrefix(part, "webhook:") {
			return true
		}
	}
	return false
}
