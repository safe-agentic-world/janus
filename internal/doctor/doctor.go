package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/assurance"
	"github.com/safe-agentic-world/nomos/internal/gateway"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/opabridge"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/version"
)

var (
	newOPACommandEvaluator = opabridge.NewCommandEvaluator
	evaluateOPA            = opabridge.Evaluate
)

type Check struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

type Report struct {
	OverallStatus       string                `json:"overall_status"`
	Checks              []Check               `json:"checks"`
	PolicyBundleHash    string                `json:"policy_bundle_hash,omitempty"`
	PolicyBundleSources []string              `json:"policy_bundle_sources,omitempty"`
	PolicyBundleInputs  []policy.BundleSource `json:"policy_bundle_inputs,omitempty"`
	AssuranceLevel      string                `json:"assurance_level,omitempty"`
	EngineVersion       string                `json:"engine_version"`
}

type Options struct {
	ConfigPath           string
	PolicyBundleOverride string
	Getenv               func(string) string
}

func Run(options Options) (Report, error) {
	if options.Getenv == nil {
		options.Getenv = os.Getenv
	}
	report := Report{
		OverallStatus: "READY",
		Checks:        make([]Check, 0, 16),
		EngineVersion: version.Current().Version,
	}
	mark := func(id string, ok bool, passMsg, hint string) {
		status := "PASS"
		msg := passMsg
		if !ok {
			status = "FAIL"
			msg = passMsg + " failed"
			report.OverallStatus = "NOT_READY"
		}
		report.Checks = append(report.Checks, Check{
			ID:      id,
			Status:  status,
			Message: msg,
			Hint:    hint,
		})
	}

	cfg, cfgErr := gateway.LoadConfig(options.ConfigPath, options.Getenv, options.PolicyBundleOverride)
	if cfgErr == nil {
		mark("config.load", true, "config loaded", "")
	} else {
		mark("config.load", false, "config loaded", "fix configuration errors: "+cfgErr.Error())
	}

	envKnown := false
	if cfgErr == nil {
		envKnown = isRecognizedEnvironment(cfg.Identity.Environment)
	}
	mark("config.environment_recognized", envKnown, "environment recognized", "set identity.environment to one of: ci, dev, local, prod, staging, test")

	configPathOK, configPathMsg := pathResolves(options.ConfigPath)
	mark("config.path_resolves", configPathOK, configPathMsg, "ensure --config points to a valid path")

	bundlePaths := []string{}
	if cfgErr == nil {
		bundlePaths = cfg.Policy.EffectiveBundlePaths()
	}
	bundlePathOK := len(bundlePaths) > 0
	bundlePathMsg := "path missing"
	if len(bundlePaths) > 0 {
		bundlePathMsg = "path resolves deterministically"
		for _, bundlePath := range bundlePaths {
			ok, msg := pathResolves(bundlePath)
			if !ok {
				bundlePathOK = false
				bundlePathMsg = msg
				break
			}
		}
	}
	mark("config.bundle_path_resolves", bundlePathOK, bundlePathMsg, "set --policy-bundle/-p or NOMOS_POLICY_BUNDLE")

	bundleExists := len(bundlePaths) > 0
	for _, bundlePath := range bundlePaths {
		if _, err := os.Stat(bundlePath); err != nil {
			bundleExists = false
			break
		}
	}
	mark("policy.bundle_exists", bundleExists, "policy bundle exists", "verify policy bundle path exists on disk")

	var bundle policy.Bundle
	bundleLoaded := false
	if bundleExists {
		signaturePaths := []string(nil)
		publicKeyPath := ""
		verify := false
		if cfgErr == nil {
			signaturePaths = cfg.Policy.EffectiveSignaturePaths()
			publicKeyPath = cfg.Policy.PublicKeyPath
			verify = cfg.Policy.VerifySignatures
		}
		loaded, err := policy.LoadBundlesWithOptions(bundlePaths, policy.MultiLoadOptions{
			VerifySignatures: verify,
			SignaturePaths:   signaturePaths,
			PublicKeyPath:    publicKeyPath,
			BundleRoles:      cfg.Policy.EffectiveBundleRoles(),
		})
		if err == nil {
			bundle = loaded
			bundleLoaded = true
			report.PolicyBundleHash = loaded.Hash
			report.PolicyBundleSources = policy.BundleSourceLabels(loaded)
			report.PolicyBundleInputs = append([]policy.BundleSource{}, loaded.SourceBundles...)
		}
	}
	parseHint := "fix bundle JSON/schema so policy.LoadBundle succeeds"
	if cfgErr == nil && !bundleLoaded && len(bundlePaths) > 0 {
		if _, err := policy.LoadBundlesWithOptions(bundlePaths, policy.MultiLoadOptions{
			VerifySignatures: cfg.Policy.VerifySignatures,
			SignaturePaths:   cfg.Policy.EffectiveSignaturePaths(),
			PublicKeyPath:    cfg.Policy.PublicKeyPath,
			BundleRoles:      cfg.Policy.EffectiveBundleRoles(),
		}); err != nil {
			parseHint = err.Error()
			if len(bundlePaths) == 1 && !strings.Contains(parseHint, bundlePaths[0]) {
				parseHint = fmt.Sprintf("load bundle %s: %s", bundlePaths[0], parseHint)
			}
		}
	}
	mark("policy.bundle_parses", bundleLoaded, "policy bundle parsed", parseHint)
	mark("policy.bundle_hash", bundleLoaded && report.PolicyBundleHash != "", "policy bundle hash computed", "ensure bundle bytes are readable and valid")

	if cfgErr == nil && cfg.Policy.OPA.Enabled {
		opaEvaluator, err := newOPACommandEvaluator(opabridge.CommandConfig{
			BinaryPath: cfg.Policy.OPA.BinaryPath,
			PolicyPath: cfg.Policy.OPA.PolicyPath,
			Query:      cfg.Policy.OPA.Query,
			Timeout:    time.Duration(cfg.Policy.OPA.TimeoutMS) * time.Millisecond,
		})
		opaReady := err == nil
		mark("policy.opa_evaluator_ready", opaReady, "opa evaluator initialized", "install OPA and verify policy.opa.binary_path, policy.opa.policy_path, and policy.opa.query")

		opaProbeOK := false
		if opaReady {
			_, err = evaluateOPA(normalize.NormalizedAction{
				SchemaVersion: "v1",
				ActionID:      "doctor_opa_probe",
				ActionType:    "doctor.unmatched",
				Resource:      "file://workspace/__doctor_opa_probe__",
				Params:        []byte("{}"),
				ParamsHash:    "probe",
				Principal:     cfg.Identity.Principal,
				Agent:         cfg.Identity.Agent,
				Environment:   cfg.Identity.Environment,
				TraceID:       "doctor_opa_probe_trace",
			}, opaEvaluator)
			opaProbeOK = err == nil
		}
		mark("policy.opa_probe_evaluates", opaProbeOK, "opa policy probe evaluated", "fix Rego/query output contract so OPA returns one decision object with decision in ALLOW|DENY|REQUIRE_APPROVAL")
	}

	denyByDefault := false
	if bundleLoaded && cfgErr == nil {
		engine := policy.NewEngine(bundle)
		decision := engine.Evaluate(normalize.NormalizedAction{
			ActionType:  "doctor.unmatched",
			Resource:    "file://workspace/__doctor_probe__",
			Principal:   cfg.Identity.Principal,
			Agent:       cfg.Identity.Agent,
			Environment: cfg.Identity.Environment,
			Params:      []byte("{}"),
			ParamsHash:  "probe",
		})
		denyByDefault = decision.Decision == policy.DecisionDeny
	}
	mark("policy.deny_by_default_probe", denyByDefault, "deny-by-default probe passed", "remove broad allow rules that permit unmatched probe actions")

	authModeValid := false
	if cfgErr == nil {
		authModeValid = len(cfg.Identity.APIKeys) > 0 || len(cfg.Identity.ServiceSecrets) > 0 || cfg.Identity.OIDC.Enabled
	}
	mark("identity.auth_mode_valid", authModeValid, "identity auth mode valid", "configure api_keys or service_secrets or enable oidc")

	keyPresence := false
	if cfgErr == nil {
		keyPresence = cfg.Identity.Agent != "" && cfg.Identity.AgentSecrets[cfg.Identity.Agent] != ""
		if cfg.Identity.OIDC.Enabled {
			keyPresence = keyPresence && cfg.Identity.OIDC.Issuer != "" && cfg.Identity.OIDC.Audience != "" && cfg.Identity.OIDC.PublicKeyPath != ""
		}
	}
	mark("identity.required_secrets_present", keyPresence, "identity key/secret presence valid", "ensure agent_secrets has the configured identity.agent and oidc fields are complete when enabled")
	mark("identity.environment_derivation", envKnown, "identity environment derivation valid", "use a recognized identity.environment value")

	mcpEnabled := cfgErr == nil && cfg.MCP.Enabled
	mark("mcp.enabled", mcpEnabled, "mcp mode enabled", "set mcp.enabled=true for MCP readiness")
	mark("mcp.transport_configured", mcpEnabled, "mcp stdio transport configured", "enable mcp mode in config")
	mark("mcp.stdio_structure_valid", mcpEnabled, "mcp stdio structure valid", "enable mcp mode and keep standard nomos mcp invocation")
	if cfgErr == nil {
		for _, upstream := range cfg.MCP.UpstreamServers {
			if strings.TrimSpace(upstream.Transport) != "stdio" {
				continue
			}
			checkID := "mcp.upstream_env_isolation." + strings.TrimSpace(upstream.Name)
			emptyEnv := len(upstream.EnvAllowlist) == 0 && len(upstream.Env) == 0
			absoluteCommand := filepath.IsAbs(strings.TrimSpace(upstream.Command))
			if emptyEnv {
				message := "upstream env isolation uses empty env by default"
				hint := "set env_allowlist/env explicitly to preserve parent variables"
				if !absoluteCommand {
					message = "upstream env isolation uses empty env by default and the command is not absolute"
					hint = "set env_allowlist/env explicitly or use an absolute command path"
				}
				report.Checks = append(report.Checks, Check{
					ID:      checkID,
					Status:  "WARN",
					Message: message,
					Hint:    hint,
				})
				continue
			}
			report.Checks = append(report.Checks, Check{
				ID:      checkID,
				Status:  "PASS",
				Message: "upstream env isolation configured",
				Hint:    "empty-by-default env is in effect",
			})
		}
	}

	workspaceExists := false
	workspaceCanon := false
	workspaceNonEmpty := false
	if cfgErr == nil {
		root := strings.TrimSpace(cfg.Executor.WorkspaceRoot)
		workspaceNonEmpty = root != ""
		if workspaceNonEmpty {
			if stat, err := os.Stat(root); err == nil && stat.IsDir() {
				workspaceExists = true
			}
			if abs, err := filepath.Abs(root); err == nil {
				workspaceCanon = filepath.Clean(abs) != ""
			}
		}
	}
	mark("fs.workspace_exists", workspaceExists, "workspace root exists", "set executor.workspace_root to an existing directory")
	mark("fs.workspace_canonicalizes", workspaceCanon, "workspace root canonicalizes", "set executor.workspace_root to a valid canonicalizable path")
	mark("fs.workspace_non_empty", workspaceNonEmpty, "workspace root is non-empty", "set executor.workspace_root explicitly or keep default working directory")

	if cfgErr == nil && cfg.Runtime.StrongGuarantee {
		containerSandbox := cfg.Executor.SandboxEnabled && strings.EqualFold(strings.TrimSpace(cfg.Executor.SandboxProfile), "container")
		mark("strong.sandbox_container", containerSandbox, "container sandbox profile enforced", "set executor.sandbox_enabled=true and executor.sandbox_profile=container for strong-guarantee deployments")

		controlledRuntime := isControlledStrongGuaranteeMode(cfg.Runtime.DeploymentMode)
		mark("strong.controlled_runtime_mode", controlledRuntime, "controlled runtime deployment mode configured", "set runtime.deployment_mode to ci or k8s for strong-guarantee deployments")

		networkBoundary := controlledRuntime
		mark("strong.network_boundary_controlled", networkBoundary, "controlled runtime network boundary declared", "strong-guarantee deployments require an operator-enforced outer network boundary in ci or k8s")

		mTLS := cfg.Gateway.TLS.Enabled && cfg.Gateway.TLS.RequireMTLS
		mark("strong.gateway_mtls", mTLS, "gateway mTLS enforced", "enable gateway.tls.enabled=true and gateway.tls.require_mtls=true for strong-guarantee deployments")

		workloadIdentity := cfg.Identity.OIDC.Enabled || cfg.Identity.SPIFFE.Enabled
		mark("strong.workload_identity", workloadIdentity, "workload identity configured", "enable identity.oidc or identity.spiffe for strong-guarantee deployments so identity is asserted by the environment")
		mark("strong.no_shared_api_keys", len(cfg.Identity.APIKeys) == 0, "shared API keys disabled", "remove identity.api_keys for strong-guarantee deployments and rely on workload identity or stronger non-shared auth")

		durableAudit := hasDurableAuditSink(cfg.Audit.Sink)
		mark("strong.audit_durable", durableAudit, "durable audit sink configured", "use sqlite or webhook audit sinks for strong-guarantee deployments instead of stdout-only")

		strictEnv := isStrongGuaranteeEnvironment(cfg.Identity.Environment)
		mark("strong.environment_bound", strictEnv, "deployment-bound environment is set", "set identity.environment to ci, staging, or prod for strong-guarantee deployments")

		containerEvidence := cfg.Runtime.Evidence.SandboxEvidence()
		mark("evidence.runtime.container_backend_ready", cfg.Runtime.Evidence.ContainerBackendReady, "runtime evidence confirms container backend availability", "record runtime evidence that a real hardened container backend is available")
		mark("evidence.runtime.rootless_or_non_privileged", cfg.Runtime.Evidence.Rootless, "runtime evidence confirms non-privileged execution", "record runtime evidence for rootless or equivalent non-privileged execution")
		mark("evidence.runtime.read_only_fs", cfg.Runtime.Evidence.ReadOnlyFS, "runtime evidence confirms read-only filesystem defaults", "record runtime evidence for read-only filesystem enforcement outside explicit writable mounts")
		mark("evidence.runtime.no_new_privileges", cfg.Runtime.Evidence.NoNewPrivileges, "runtime evidence confirms no-new-privileges", "record runtime evidence for no-new-privileges enforcement")
		mark("evidence.runtime.network_default_deny", cfg.Runtime.Evidence.NetworkDefaultDeny, "runtime evidence confirms default-deny egress", "record runtime evidence for default-deny egress in the hardened sandbox path")
		mark("evidence.identity.workload_identity_verified", cfg.Runtime.Evidence.WorkloadIdentityVerified, "runtime evidence confirms workload identity verification", "record workload identity evidence compatible with SPIFFE/SPIRE or workload OIDC")
		mark("evidence.audit.durable_verified", cfg.Runtime.Evidence.DurableAuditVerified, "runtime evidence confirms durable audit delivery", "record runtime evidence that durable audit delivery is configured and verified")

		report.AssuranceLevel = deriveAssuranceLevel(cfg, containerEvidence.ContainerReady())
		mark("strong.assurance_evidence_backed", report.AssuranceLevel == "STRONG", "effective assurance remains strong", "runtime evidence is incomplete or unverifiable, so effective assurance degrades below STRONG")
	} else if cfgErr == nil {
		report.AssuranceLevel = deriveAssuranceLevel(cfg, cfg.Runtime.Evidence.SandboxEvidence().ContainerReady())
	}

	if report.AssuranceLevel == "" && cfgErr != nil {
		report.AssuranceLevel = "NONE"
	}

	report.Checks = stableChecks(report.Checks)
	return report, nil
}

func pathResolves(path string) (bool, string) {
	p := strings.TrimSpace(path)
	if p == "" {
		return false, "path missing"
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false, "path resolution failed"
	}
	cleaned := filepath.Clean(abs)
	if cleaned == "" {
		return false, "path canonicalization failed"
	}
	return true, "path resolves deterministically"
}

func isRecognizedEnvironment(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "dev", "staging", "prod", "ci", "local", "test":
		return true
	default:
		return false
	}
}

func isStrongGuaranteeEnvironment(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "ci", "staging", "prod":
		return true
	default:
		return false
	}
}

func isControlledStrongGuaranteeMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "ci", "k8s":
		return true
	default:
		return false
	}
}

func hasDurableAuditSink(sink string) bool {
	for _, part := range strings.Split(sink, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "sqlite:") || strings.HasPrefix(part, "sqlite://") || strings.HasPrefix(part, "webhook:") {
			return true
		}
	}
	return false
}

func stableChecks(in []Check) []Check {
	out := make([]Check, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

func HumanSummary(report Report) string {
	var b strings.Builder
	b.WriteString("Nomos Doctor Report\n\n")
	for _, check := range report.Checks {
		b.WriteString(fmt.Sprintf("[%s] %s\n", check.Status, check.Message))
		if check.Status == "FAIL" && check.Hint != "" {
			b.WriteString(fmt.Sprintf("  hint: %s\n", check.Hint))
		}
	}
	b.WriteString("\nResult: ")
	b.WriteString(report.OverallStatus)
	if strings.TrimSpace(report.AssuranceLevel) != "" {
		b.WriteString(" (assurance=")
		b.WriteString(report.AssuranceLevel)
		b.WriteString(")")
	}
	b.WriteString("\n")
	return b.String()
}

func deriveAssuranceLevel(cfg gateway.Config, runtimeIsolationVerified bool) string {
	evidence := cfg.AssuranceEvidence()
	evidence.RuntimeIsolationVerified = runtimeIsolationVerified && evidence.RuntimeIsolationVerified
	return assurance.DeriveWithEvidence(cfg.Runtime.DeploymentMode, cfg.Runtime.StrongGuarantee, evidence)
}
