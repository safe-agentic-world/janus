package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/approval"
	"github.com/safe-agentic-world/nomos/internal/approvalpreview"
	"github.com/safe-agentic-world/nomos/internal/assurance"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/doctor"
	"github.com/safe-agentic-world/nomos/internal/gateway"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/mcp"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/telemetry"
	"github.com/safe-agentic-world/nomos/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "help", "-h", "--help":
		usage()
		os.Exit(0)
	case "version":
		fmt.Println(versionOutput())
	case "serve":
		runServe(os.Args[2:])
	case "mcp":
		runMCP(os.Args[2:])
	case "policy":
		runPolicy(os.Args[2:])
	case "approvals":
		runApprovals(os.Args[2:])
	case "doctor":
		os.Exit(runDoctorCommand(os.Args[2:], os.Stdout, os.Stderr, os.Getenv))
	default:
		usage()
		os.Exit(2)
	}
}

func versionOutput() string {
	return version.Current().String()
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	var configPath string
	var policyBundle string
	fs.StringVar(&configPath, "config", "", "path to config json")
	fs.StringVar(&configPath, "c", "", "path to config json")
	fs.StringVar(&policyBundle, "policy-bundle", "", "path to policy bundle")
	fs.StringVar(&policyBundle, "p", "", "path to policy bundle")
	fs.Usage = func() { writeHelpText(fs.Output(), serveHelpText()) }
	fs.Parse(args)

	resolved, err := resolveServeInvocation(configPath, policyBundle, os.Getenv)
	if err != nil {
		cliFatal(err.Error())
	}

	cfg, err := gateway.LoadConfig(resolved.ConfigPath, os.Getenv, resolved.PolicyBundle)
	if err != nil {
		cliFatalf("load config: %v", err)
	}

	gw, err := gateway.New(cfg)
	if err != nil {
		cliFatalf("init gateway: %v", err)
	}
	gw.SetUIReadinessReporter(func() (gateway.UIReadinessReport, error) {
		report, err := doctor.Run(doctor.Options{ConfigPath: cfg.SourcePath, Getenv: os.Getenv})
		if err != nil {
			return gateway.UIReadinessReport{}, err
		}
		return toUIReadinessReport(report), nil
	})
	if sources := gw.PolicyBundleSources(); len(sources) > 0 {
		cliInfof("policy bundle sources: %s", strings.Join(sources, ", "))
	}

	cliSuccessf("gateway listening on %s (%s)", cfg.Gateway.Listen, cfg.Gateway.Transport)
	if err := gw.Start(); err != nil {
		cliFatalf("gateway start: %v", err)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	cliWarn("shutdown signal received, stopping gateway")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := gw.Shutdown(shutdownCtx); err != nil {
		cliFatalf("gateway shutdown: %v", err)
	}
	cliSuccess("gateway stopped cleanly")
}

func toUIReadinessReport(report doctor.Report) gateway.UIReadinessReport {
	checks := make([]gateway.UIReadinessCheck, 0, len(report.Checks))
	for _, check := range report.Checks {
		checks = append(checks, gateway.UIReadinessCheck{
			ID:      check.ID,
			Status:  check.Status,
			Message: check.Message,
			Hint:    check.Hint,
		})
	}
	inputs := make([]map[string]any, 0, len(report.PolicyBundleInputs))
	for _, input := range report.PolicyBundleInputs {
		inputs = append(inputs, map[string]any{
			"path":               input.Path,
			"hash":               input.Hash,
			"role":               input.Role,
			"signature_verified": input.SignatureVerified,
		})
	}
	return gateway.UIReadinessReport{
		OverallStatus:       report.OverallStatus,
		Checks:              checks,
		PolicyBundleHash:    report.PolicyBundleHash,
		PolicyBundleSources: append([]string{}, report.PolicyBundleSources...),
		PolicyBundleInputs:  inputs,
		AssuranceLevel:      report.AssuranceLevel,
		EngineVersion:       report.EngineVersion,
	}
}

func runMCP(args []string) {
	if len(args) > 0 && args[0] == "serve" {
		runMCPServe(args[1:])
		return
	}
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	var configPath string
	var policyBundle string
	var logLevel string
	var logFormat string
	var quiet bool
	fs.StringVar(&configPath, "config", "", "path to config json")
	fs.StringVar(&configPath, "c", "", "path to config json")
	fs.StringVar(&policyBundle, "policy-bundle", "", "path to policy bundle")
	fs.StringVar(&policyBundle, "p", "", "path to policy bundle")
	fs.StringVar(&logLevel, "log-level", "info", "mcp log level: error|warn|info|debug")
	fs.StringVar(&logLevel, "l", "info", "mcp log level: error|warn|info|debug")
	fs.BoolVar(&quiet, "quiet", false, "suppress startup banner and non-error logs")
	fs.BoolVar(&quiet, "q", false, "suppress startup banner and non-error logs")
	fs.StringVar(&logFormat, "log-format", "text", "mcp log format: text|json")
	fs.Usage = func() { writeHelpText(fs.Output(), mcpHelpText()) }
	fs.Parse(args)

	resolved, err := resolveMCPInvocation(configPath, policyBundle, logLevel, quiet, os.Getenv)
	if err != nil {
		cliFatal(err.Error())
	}
	cfg, err := gateway.LoadConfig(resolved.ConfigPath, os.Getenv, resolved.PolicyBundle)
	if err != nil {
		cliFatalf("load config: %v", err)
	}
	credentialBroker, err := gateway.BuildCredentialBroker(cfg, time.Now)
	if err != nil {
		cliFatalf("init credential broker: %v", err)
	}
	runtimeOptions, err := mcp.ParseRuntimeOptions(mcp.RuntimeOptions{
		LogLevel:              resolved.LogLevel,
		Quiet:                 resolved.Quiet,
		LogFormat:             logFormat,
		ErrWriter:             os.Stderr,
		ExecCompatibilityMode: cfg.Policy.ExecCompatibilityMode,
		BundleRoles:           cfg.Policy.EffectiveBundleRoles(),
		SandboxEvidence:       cfg.Runtime.Evidence.SandboxEvidence(),
		ApprovalStorePath:     cfg.Approvals.StorePath,
		ApprovalTTLSeconds:    cfg.Approvals.TTLSeconds,
		UpstreamRoutes:        toMCPUpstreamRoutes(cfg.Upstream.Routes),
		UpstreamServers:       toMCPUpstreamServers(cfg.MCP.Timeouts, cfg.MCP.Breaker, cfg.MCP.UpstreamServers),
		CredentialBroker:      credentialBroker,
		Telemetry:             buildMCPRuntimeTelemetry(cfg),
	})
	if err != nil {
		cliFatalf("invalid mcp runtime options: %v", err)
	}
	if mcpSinkRewritesStdout(cfg.Audit.Sink) {
		cliWarn("rewriting audit sink stdout -> stderr for MCP protocol safety")
	}
	recorder, err := buildProtocolSafeMCPRecorder(cfg)
	if err != nil {
		cliFatalf("init mcp audit recorder: %v", err)
	}
	if closer, ok := recorder.(io.Closer); ok {
		defer func() {
			_ = closer.Close()
		}()
	}
	if strings.EqualFold(resolved.LogLevelSource, "env") && strings.EqualFold(resolved.LogLevel, "debug") {
		cliInfo("log-level resolved from env NOMOS_LOG_LEVEL")
	}
	if len(cfg.Policy.EffectiveBundlePaths()) > 1 {
		cliInfof("policy bundle paths: %s", strings.Join(cfg.Policy.EffectiveBundlePaths(), ", "))
	}
	id := identity.VerifiedIdentity{
		Principal:   cfg.Identity.Principal,
		Agent:       cfg.Identity.Agent,
		Environment: cfg.Identity.Environment,
	}
	assuranceLevel := assurance.DeriveWithEvidence(cfg.Runtime.DeploymentMode, cfg.Runtime.StrongGuarantee, cfg.AssuranceEvidence())
	cliSuccessf("MCP stdio server ready (assurance=%s)", assuranceLevel)
	if err := mcp.RunStdioForBundlesWithRuntimeOptionsAndRecorder(cfg.Policy.EffectiveBundlePaths(), id, cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes, cfg.Executor.MaxOutputLines, cfg.Approvals.Enabled, cfg.Executor.SandboxEnabled, cfg.Executor.SandboxProfile, runtimeOptions, recorder, assuranceLevel); err != nil {
		cliFatalf("mcp server error: %v", err)
	}
}

func runMCPServe(args []string) {
	fs := flag.NewFlagSet("mcp serve", flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	var configPath string
	var policyBundle string
	var listen string
	var useHTTP bool
	fs.StringVar(&configPath, "config", "", "path to config json")
	fs.StringVar(&configPath, "c", "", "path to config json")
	fs.StringVar(&policyBundle, "policy-bundle", "", "path to policy bundle")
	fs.StringVar(&policyBundle, "p", "", "path to policy bundle")
	fs.StringVar(&listen, "listen", "", "bind address for downstream MCP HTTP server")
	fs.BoolVar(&useHTTP, "http", false, "serve downstream MCP over streamable http")
	fs.Usage = func() { writeHelpText(fs.Output(), mcpServeHelpText()) }
	fs.Parse(args)

	if !useHTTP {
		cliFatal("--http is required for 'nomos mcp serve'")
	}
	resolved, err := resolveMCPInvocation(configPath, policyBundle, "", false, os.Getenv)
	if err != nil {
		cliFatal(err.Error())
	}
	cfg, err := gateway.LoadConfig(resolved.ConfigPath, os.Getenv, resolved.PolicyBundle)
	if err != nil {
		cliFatalf("load config: %v", err)
	}
	if strings.TrimSpace(listen) == "" {
		cliFatal("--listen is required for 'nomos mcp serve --http'")
	}
	credentialBroker, err := gateway.BuildCredentialBroker(cfg, time.Now)
	if err != nil {
		cliFatalf("init credential broker: %v", err)
	}
	runtimeOptions, err := mcp.ParseRuntimeOptions(mcp.RuntimeOptions{
		LogLevel:              "info",
		LogFormat:             "text",
		ErrWriter:             os.Stderr,
		ExecCompatibilityMode: cfg.Policy.ExecCompatibilityMode,
		BundleRoles:           cfg.Policy.EffectiveBundleRoles(),
		SandboxEvidence:       cfg.Runtime.Evidence.SandboxEvidence(),
		ApprovalStorePath:     cfg.Approvals.StorePath,
		ApprovalTTLSeconds:    cfg.Approvals.TTLSeconds,
		UpstreamRoutes:        toMCPUpstreamRoutes(cfg.Upstream.Routes),
		UpstreamServers:       toMCPUpstreamServers(cfg.MCP.Timeouts, cfg.MCP.Breaker, cfg.MCP.UpstreamServers),
		CredentialBroker:      credentialBroker,
		Telemetry:             buildMCPRuntimeTelemetry(cfg),
	})
	if err != nil {
		cliFatalf("invalid mcp runtime options: %v", err)
	}
	recorder, err := buildProtocolSafeMCPRecorder(cfg)
	if err != nil {
		cliFatalf("init mcp audit recorder: %v", err)
	}
	if closer, ok := recorder.(io.Closer); ok {
		defer func() { _ = closer.Close() }()
	}
	baseID := identity.VerifiedIdentity{
		Principal:   cfg.Identity.Principal,
		Agent:       cfg.Identity.Agent,
		Environment: cfg.Identity.Environment,
	}
	assuranceLevel := assurance.DeriveWithEvidence(cfg.Runtime.DeploymentMode, cfg.Runtime.StrongGuarantee, cfg.AssuranceEvidence())
	baseServer, err := mcp.NewServerForBundlesWithRuntimeOptionsAndRecorder(cfg.Policy.EffectiveBundlePaths(), baseID, cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes, cfg.Executor.MaxOutputLines, cfg.Approvals.Enabled, cfg.Executor.SandboxEnabled, cfg.Executor.SandboxProfile, runtimeOptions, recorder)
	if err != nil {
		cliFatalf("init mcp server: %v", err)
	}
	baseServer.SetAssuranceLevel(assuranceLevel)
	defer func() { _ = baseServer.Close() }()
	auth, err := identity.NewAuthenticator(identity.AuthConfig{
		APIKeys:           cfg.Identity.APIKeys,
		ServiceSecrets:    cfg.Identity.ServiceSecrets,
		AgentSecrets:      cfg.Identity.AgentSecrets,
		Environment:       cfg.Identity.Environment,
		OIDCEnabled:       cfg.Identity.OIDC.Enabled,
		OIDCIssuer:        cfg.Identity.OIDC.Issuer,
		OIDCAudience:      cfg.Identity.OIDC.Audience,
		OIDCPublicKeyPath: cfg.Identity.OIDC.PublicKeyPath,
		SPIFFEEnabled:     cfg.Identity.SPIFFE.Enabled,
		SPIFFETrustDomain: cfg.Identity.SPIFFE.TrustDomain,
	})
	if err != nil {
		cliFatalf("init mcp auth: %v", err)
	}
	httpServer, err := mcp.NewDownstreamHTTPServer(baseServer, auth, listen, cfg.Identity.Agent, cfg.Gateway.RateLimitPerMin)
	if err != nil {
		cliFatalf("init downstream mcp http server: %v", err)
	}
	if err := httpServer.Start(); err != nil {
		cliFatalf("start downstream mcp http server: %v", err)
	}
	cliSuccessf("MCP HTTP server ready on %s (assurance=%s)", httpServer.Addr(), assuranceLevel)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		cliFatalf("mcp http server shutdown: %v", err)
	}
}

func runPolicy(args []string) {
	if len(args) == 0 {
		cliFatal("policy command required: test|explain")
	}
	switch args[0] {
	case "test":
		runPolicyTest(args[1:])
	case "explain":
		runPolicyExplain(args[1:])
	default:
		cliFatal("policy command required: test|explain")
	}
}

func runApprovals(args []string) {
	if len(args) == 0 {
		cliFatal("approvals command required: list")
	}
	switch args[0] {
	case "list":
		if err := executeApprovalsList(args[1:], os.Stdout, os.Getenv, time.Now); err != nil {
			cliFatalf("approvals list: %v", err)
		}
	default:
		cliFatal("approvals command required: list")
	}
}

type approvalListRecord struct {
	ApprovalID      string `json:"approval_id"`
	Status          string `json:"status"`
	ExpiresAt       string `json:"expires_at"`
	Expired         bool   `json:"expired"`
	Principal       string `json:"principal"`
	Agent           string `json:"agent"`
	Environment     string `json:"environment"`
	ActionType      string `json:"action_type"`
	Resource        string `json:"resource"`
	ScopeType       string `json:"scope_type"`
	ActionID        string `json:"action_id"`
	TraceID         string `json:"trace_id"`
	ParamsHash      string `json:"params_hash"`
	ArgumentPreview any    `json:"argument_preview,omitempty"`
}

func executeApprovalsList(args []string, stdout io.Writer, getenv func(string) string, now func() time.Time) error {
	if getenv == nil {
		getenv = os.Getenv
	}
	if now == nil {
		now = time.Now
	}
	fs := flag.NewFlagSet("approvals list", flag.ExitOnError)
	storePath := fs.String("store", "", "path to approval sqlite store")
	limit := fs.Int("limit", 50, "maximum pending approvals to list")
	format := fs.String("format", "json", "output format: json|text")
	fs.Parse(args)
	resolvedStore := strings.TrimSpace(*storePath)
	if resolvedStore == "" {
		resolvedStore = strings.TrimSpace(getenv("NOMOS_APPROVALS_STORE_PATH"))
	}
	if resolvedStore == "" {
		return errors.New("--store is required unless NOMOS_APPROVALS_STORE_PATH is set")
	}
	if *limit <= 0 {
		return errors.New("--limit must be > 0")
	}
	store, err := approval.Open(resolvedStore, 15*time.Minute, now)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	records, err := store.ListPending(context.Background(), *limit)
	if err != nil {
		return err
	}
	nowUTC := now().UTC()
	out := make([]approvalListRecord, 0, len(records))
	for _, rec := range records {
		item := approvalListRecord{
			ApprovalID:  rec.ApprovalID,
			Status:      rec.Status,
			ExpiresAt:   rec.ExpiresAt.Format(time.RFC3339Nano),
			Expired:     nowUTC.After(rec.ExpiresAt),
			Principal:   rec.Principal,
			Agent:       rec.Agent,
			Environment: rec.Environment,
			ActionType:  rec.ActionType,
			Resource:    rec.Resource,
			ScopeType:   rec.ScopeType,
			ActionID:    rec.ActionID,
			TraceID:     rec.TraceID,
			ParamsHash:  rec.ParamsHash,
		}
		if preview, ok := approvalpreview.Decode(rec.ArgumentPreviewJSON); ok {
			item.ArgumentPreview = preview
		}
		out = append(out, item)
	}
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "", "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	case "text":
		for _, item := range out {
			if _, err := fmt.Fprintf(stdout, "%s %s %s %s expires=%s\n", item.ApprovalID, item.Status, item.ActionType, item.Resource, item.ExpiresAt); err != nil {
				return err
			}
			if item.ArgumentPreview != nil {
				data, err := json.MarshalIndent(item.ArgumentPreview, "", "  ")
				if err != nil {
					return err
				}
				if _, err := fmt.Fprintf(stdout, "argument_preview:\n%s\n", data); err != nil {
					return err
				}
			}
		}
		return nil
	default:
		return errors.New("--format must be json or text")
	}
}

const (
	policyResultValidationError = "VALIDATION_ERROR"
	policyResultNormError       = "NORMALIZATION_ERROR"
)

type classifiedPolicyError struct {
	code string
	err  error
}

func (e *classifiedPolicyError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *classifiedPolicyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func policyErrorCode(err error) string {
	var classified *classifiedPolicyError
	if errors.As(err, &classified) && classified != nil {
		return classified.code
	}
	return ""
}

func classifyBundleLoadError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "canonicalize bundle"):
		return policyResultNormError
	default:
		return policyResultValidationError
	}
}

func wrapPolicyError(code, operation string, err error) error {
	if err == nil {
		return nil
	}
	return &classifiedPolicyError{
		code: code,
		err:  fmt.Errorf("%s: %w", operation, err),
	}
}

func logPolicyCommandError(err error) {
	code := policyErrorCode(err)
	if code == "" {
		cliFatal(err.Error())
	}
	cliFatalf("%s: %v", code, err)
}

func runPolicyTest(args []string) {
	summary, err := executePolicyTest(args, os.Stdout)
	if err != nil {
		logPolicyCommandError(err)
	}
	cliSuccessf("policy test completed: decision=%s matched_rules=%d bundle=%s", summary.Decision, summary.MatchedRuleCount, summary.PolicyBundleHash)
}

type policyCommandSummary struct {
	Decision         string
	ReasonCode       string
	PolicyBundleHash string
	MatchedRuleCount int
	AssuranceLevel   string
}

func executePolicyTest(args []string, stdout io.Writer) (policyCommandSummary, error) {
	actionPath, bundlePath := parsePolicyFlags("test", args)
	actionData, err := os.ReadFile(actionPath)
	if err != nil {
		return policyCommandSummary{}, wrapPolicyError(policyResultValidationError, "read action", err)
	}
	act, err := action.DecodeAction(actionData)
	if err != nil {
		return policyCommandSummary{}, wrapPolicyError(policyResultValidationError, "decode action", err)
	}
	bundle, err := policy.LoadBundles([]string{bundlePath})
	if err != nil {
		return policyCommandSummary{}, wrapPolicyError(classifyBundleLoadError(err), "load bundle", err)
	}
	engine := policy.NewEngine(bundle)
	normalized, err := normalize.Action(act)
	if err != nil {
		return policyCommandSummary{}, wrapPolicyError(policyResultNormError, "normalize action", err)
	}
	decision := engine.Evaluate(normalized)
	payload := map[string]any{
		"decision":           decision.Decision,
		"reason_code":        decision.ReasonCode,
		"matched_rule_ids":   decision.MatchedRuleIDs,
		"policy_bundle_hash": decision.PolicyBundleHash,
	}
	enc := json.NewEncoder(stdout)
	if err := enc.Encode(payload); err != nil {
		return policyCommandSummary{}, err
	}
	return policyCommandSummary{
		Decision:         decision.Decision,
		ReasonCode:       decision.ReasonCode,
		PolicyBundleHash: decision.PolicyBundleHash,
		MatchedRuleCount: len(decision.MatchedRuleIDs),
	}, nil
}

func runPolicyExplain(args []string) {
	summary, err := executePolicyExplain(args, os.Stdout, os.Getenv)
	if err != nil {
		logPolicyCommandError(err)
	}
	cliSuccessf("policy explain completed: decision=%s reason=%s matched_rules=%d assurance=%s", summary.Decision, summary.ReasonCode, summary.MatchedRuleCount, summary.AssuranceLevel)
}

func executePolicyExplain(args []string, stdout io.Writer, getenv func(string) string) (policyCommandSummary, error) {
	actionPath, bundlePath, configPath := parsePolicyExplainFlags(args)
	actionData, err := os.ReadFile(actionPath)
	if err != nil {
		return policyCommandSummary{}, wrapPolicyError(policyResultValidationError, "read action", err)
	}
	act, err := action.DecodeAction(actionData)
	if err != nil {
		return policyCommandSummary{}, wrapPolicyError(policyResultValidationError, "decode action", err)
	}
	bundle, err := policy.LoadBundles([]string{bundlePath})
	if err != nil {
		return policyCommandSummary{}, wrapPolicyError(classifyBundleLoadError(err), "load bundle", err)
	}
	engine := policy.NewEngine(bundle)
	normalized, err := normalize.Action(act)
	if err != nil {
		return policyCommandSummary{}, wrapPolicyError(policyResultNormError, "normalize action", err)
	}
	explanation := engine.Explain(normalized)
	settings, err := deriveExplainSettings(configPath, bundlePath, getenv)
	if err != nil {
		return policyCommandSummary{}, wrapPolicyError(policyResultValidationError, "derive explain settings", err)
	}
	payload := buildPolicyExplainPayload(explanation, normalized, settings)
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return policyCommandSummary{}, err
	}
	return policyCommandSummary{
		Decision:         explanation.Decision.Decision,
		ReasonCode:       explanation.Decision.ReasonCode,
		PolicyBundleHash: explanation.Decision.PolicyBundleHash,
		MatchedRuleCount: len(explanation.Decision.MatchedRuleIDs),
		AssuranceLevel:   settings.AssuranceLevel,
	}, nil
}

type explainSettings struct {
	AssuranceLevel        string
	SuggestRemediation    bool
	ExecCompatibilityMode string
	Redactor              *redact.Redactor
}

func buildPolicyExplainPayload(explanation policy.ExplainDetails, normalized normalize.NormalizedAction, settings explainSettings) map[string]any {
	payload := map[string]any{
		"decision":            explanation.Decision.Decision,
		"reason_code":         explanation.Decision.ReasonCode,
		"matched_rule_ids":    explanation.Decision.MatchedRuleIDs,
		"policy_bundle_hash":  explanation.Decision.PolicyBundleHash,
		"engine_version":      version.Current().Version,
		"assurance_level":     settings.AssuranceLevel,
		"obligations_preview": explanation.ObligationsPreview,
	}
	if normalized.ActionType == "process.exec" {
		payload["exec_authorization"] = buildExecAuthorizationPayload(explanation, settings)
	}
	previewRedactor := settings.Redactor
	if previewRedactor == nil {
		previewRedactor = redact.DefaultRedactor()
	}
	if preview, ok := approvalpreview.FromNormalized(previewRedactor, normalized); ok {
		if decoded, ok := approvalpreview.Decode(string(preview)); ok {
			payload["argument_preview"] = decoded
		}
	}
	if len(explanation.Decision.PolicyBundleInputs) > 0 {
		payload["policy_bundle_inputs"] = explanation.Decision.PolicyBundleInputs
	}
	if len(explanation.Decision.PolicyBundleSources) > 1 {
		payload["policy_bundle_sources"] = explanation.Decision.PolicyBundleSources
	}
	if len(explanation.MatchedRuleProvenance) > 0 {
		payload["matched_rule_provenance"] = explanation.MatchedRuleProvenance
	}
	if explanation.Decision.Decision != policy.DecisionAllow {
		whyDenied := map[string]any{
			"reason_code":        explanation.Decision.ReasonCode,
			"deny_rules":         buildDeniedRulePayload(explanation.DenyRules),
			"matched_conditions": buildOverallMatchedConditions(explanation),
			"remediation_hint":   remediationHint(explanation, normalized),
		}
		payload["why_denied"] = whyDenied
		if settings.SuggestRemediation {
			payload["minimal_allowing_change"] = remediationSuggestion(explanation, normalized)
		}
	}
	return payload
}

func parsePolicyExplainFlags(args []string) (string, string, string) {
	fs := flag.NewFlagSet("policy explain", flag.ExitOnError)
	actionPath := fs.String("action", "", "path to action json")
	bundlePath := fs.String("bundle", "", "path to policy bundle")
	configPath := fs.String("config", "", "path to config json")
	fs.Parse(args)
	if *actionPath == "" || *bundlePath == "" {
		cliFatal("both --action and --bundle are required")
	}
	return *actionPath, *bundlePath, *configPath
}

func deriveExplainSettings(configPath, bundlePath string, getenv func(string) string) (explainSettings, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	if strings.TrimSpace(configPath) != "" {
		cfg, err := gateway.LoadConfig(configPath, getenv, bundlePath)
		if err != nil {
			return explainSettings{}, err
		}
		redactor, err := redact.NewRedactor(cfg.Redaction.Patterns)
		if err != nil {
			return explainSettings{}, err
		}
		return explainSettings{
			AssuranceLevel:        assurance.DeriveWithEvidence(cfg.Runtime.DeploymentMode, cfg.Runtime.StrongGuarantee, cfg.AssuranceEvidence()),
			SuggestRemediation:    cfg.Policy.ExplainSuggestions == nil || *cfg.Policy.ExplainSuggestions,
			ExecCompatibilityMode: cfg.Policy.ExecCompatibilityMode,
			Redactor:              redactor,
		}, nil
	}
	deploymentMode := strings.TrimSpace(getenv("NOMOS_RUNTIME_DEPLOYMENT_MODE"))
	if deploymentMode == "" {
		deploymentMode = "unmanaged"
	}
	suggestRemediation := true
	if value := strings.TrimSpace(getenv("NOMOS_POLICY_EXPLAIN_SUGGESTIONS")); value != "" {
		suggestRemediation = parseBoolEnv(value)
	}
	redactor, err := redact.NewRedactor(splitEnvList(getenv("NOMOS_REDACTION_PATTERNS")))
	if err != nil {
		return explainSettings{}, err
	}
	return explainSettings{
		AssuranceLevel: assurance.DeriveWithEvidence(deploymentMode, parseBoolEnv(getenv("NOMOS_RUNTIME_STRONG_GUARANTEE")), assurance.Evidence{
			RuntimeIsolationVerified: parseBoolEnv(getenv("NOMOS_RUNTIME_EVIDENCE_CONTAINER_BACKEND_READY")) &&
				parseBoolEnv(getenv("NOMOS_RUNTIME_EVIDENCE_ROOTLESS")) &&
				parseBoolEnv(getenv("NOMOS_RUNTIME_EVIDENCE_READ_ONLY_FS")) &&
				parseBoolEnv(getenv("NOMOS_RUNTIME_EVIDENCE_NO_NEW_PRIVILEGES")) &&
				parseBoolEnv(getenv("NOMOS_RUNTIME_EVIDENCE_NETWORK_DEFAULT_DENY")),
			WorkloadIdentityVerified: parseBoolEnv(getenv("NOMOS_RUNTIME_EVIDENCE_WORKLOAD_IDENTITY_VERIFIED")),
			DurableAuditVerified:     parseBoolEnv(getenv("NOMOS_RUNTIME_EVIDENCE_DURABLE_AUDIT_VERIFIED")),
		}),
		SuggestRemediation:    suggestRemediation,
		ExecCompatibilityMode: strings.TrimSpace(getenv("NOMOS_POLICY_EXEC_COMPATIBILITY_MODE")),
		Redactor:              redactor,
	}, nil
}

func buildExecAuthorizationPayload(explanation policy.ExplainDetails, settings explainSettings) map[string]any {
	mode := policy.NormalizeExecCompatibilityMode(settings.ExecCompatibilityMode)
	if mode == "" {
		mode = policy.ExecCompatibilityLegacyAllowlistFallback
	}
	return map[string]any{
		"condition_class":          explanation.ExecAuthorization.ConditionClass,
		"runtime_enforcement_hint": explanation.ExecAuthorization.RuntimeEnforcementHint,
		"compatibility_mode":       mode,
		"conflict":                 explanation.ExecAuthorization.Conflict,
	}
}

func deriveExplainAssurance(configPath, bundlePath string, getenv func(string) string) (string, error) {
	settings, err := deriveExplainSettings(configPath, bundlePath, getenv)
	if err != nil {
		return "", err
	}
	return settings.AssuranceLevel, nil
}

func buildDeniedRulePayload(rules []policy.DeniedRuleExplanation) []map[string]any {
	out := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		item := map[string]any{
			"rule_id":            rule.RuleID,
			"reason_code":        rule.ReasonCode,
			"matched_conditions": rule.MatchedConditions,
		}
		if rule.BundleSource != "" {
			item["bundle_source"] = rule.BundleSource
		}
		out = append(out, item)
	}
	return out
}

func buildOverallMatchedConditions(explanation policy.ExplainDetails) map[string]bool {
	if len(explanation.DenyRules) > 0 {
		return map[string]bool{
			"deny_rule_match": true,
		}
	}
	if len(explanation.RequireApprovalRuleIDs) > 0 {
		return map[string]bool{
			"approval_rule_match": true,
		}
	}
	return map[string]bool{
		"matching_allow_rule": false,
	}
}

func remediationHint(explanation policy.ExplainDetails, normalized normalize.NormalizedAction) string {
	switch explanation.Decision.ReasonCode {
	case "require_approval_by_rule":
		return "This action requires approval before it can proceed."
	case "deny_by_rule":
		return "A deny rule matched this action."
	default:
		switch normalized.ActionType {
		case "net.http_request":
			return "This network destination is not currently allowed."
		case "process.exec":
			return "This command is not currently allowed."
		case "fs.write", "repo.apply_patch":
			return "This write target is not currently allowed."
		default:
			return "No matching allow rule was found for this action."
		}
	}
}

func remediationSuggestion(explanation policy.ExplainDetails, normalized normalize.NormalizedAction) string {
	switch normalized.ActionType {
	case "net.http_request":
		host := hostFromNormalizedResource(normalized.Resource)
		if host != "" {
			return "This host is not currently allowed; use an allowlisted host, request approval, or update the network allowlist for " + host + "."
		}
		return "This host is not currently allowed; use an allowlisted host or request approval."
	case "process.exec":
		return "Exec is restricted; use an allowlisted command or request approval."
	case "fs.write", "repo.apply_patch":
		return "Write access is restricted for this resource; use an allowed path or request approval."
	default:
		if explanation.Decision.ReasonCode == "require_approval_by_rule" {
			return "Request approval for this action."
		}
		return "Adjust the requested action to match an allowlisted resource or request approval."
	}
}

func hostFromNormalizedResource(resource string) string {
	if !strings.HasPrefix(resource, "url://") {
		return ""
	}
	trimmed := strings.TrimPrefix(resource, "url://")
	if idx := strings.Index(trimmed, "/"); idx >= 0 {
		return trimmed[:idx]
	}
	return trimmed
}

func parseBoolEnv(value string) bool {
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	return err == nil && parsed
}

func splitEnvList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parsePolicyFlags(name string, args []string) (string, string) {
	fs := flag.NewFlagSet("policy "+name, flag.ExitOnError)
	actionPath := fs.String("action", "", "path to action json")
	bundlePath := fs.String("bundle", "", "path to policy bundle")
	fs.Parse(args)
	if *actionPath == "" || *bundlePath == "" {
		cliFatal("both --action and --bundle are required")
	}
	return *actionPath, *bundlePath
}

func mustJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func usage() {
	writeHelpText(os.Stderr, rootHelpText())
}

func runDoctorCommand(args []string, stdout io.Writer, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configPath string
	var policyBundle string
	var format string
	fs.StringVar(&configPath, "config", "", "path to config json")
	fs.StringVar(&configPath, "c", "", "path to config json")
	fs.StringVar(&policyBundle, "policy-bundle", "", "path to policy bundle")
	fs.StringVar(&policyBundle, "p", "", "path to policy bundle")
	fs.StringVar(&format, "format", "text", "doctor output format: text|json")
	fs.Usage = func() { writeHelpText(fs.Output(), doctorHelpText()) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	configResolved, _, err := resolvePathOption(configPath, getenv("NOMOS_CONFIG"), "--config/-c", "NOMOS_CONFIG", true)
	if err != nil {
		writeRedactedLine(stderr, err.Error())
		return 1
	}
	bundleResolved, _, err := resolvePathOption(policyBundle, getenv("NOMOS_POLICY_BUNDLE"), "--policy-bundle/-p", "NOMOS_POLICY_BUNDLE", false)
	if err != nil {
		writeRedactedLine(stderr, err.Error())
		return 1
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format != "text" && format != "json" {
		writeRedactedLine(stderr, "invalid --format value "+strconv.Quote(format)+": expected text or json")
		return 2
	}
	report, err := doctor.Run(doctor.Options{
		ConfigPath:           configResolved,
		PolicyBundleOverride: bundleResolved,
		Getenv:               getenv,
	})
	if err != nil {
		writeRedactedLine(stderr, "doctor internal error: "+err.Error())
		return 2
	}
	if format == "json" {
		data, err := json.Marshal(report)
		if err != nil {
			writeRedactedLine(stderr, "doctor internal error: "+err.Error())
			return 2
		}
		writeRedactedLine(stdout, string(data))
	} else {
		writeRedactedLine(stdout, decorateDoctorSummary(stdout, report))
	}
	if report.OverallStatus == "READY" {
		writeStatusLine(stderr, "OK", ansiGreen, fmt.Sprintf("doctor completed: status=%s checks=%d bundle=%s", report.OverallStatus, len(report.Checks), report.PolicyBundleHash))
		return 0
	}
	writeStatusLine(stderr, "WARN", ansiYellow, fmt.Sprintf("doctor completed: status=%s checks=%d", report.OverallStatus, len(report.Checks)))
	return 1
}

type resolvedServeInvocation struct {
	ConfigPath   string
	PolicyBundle string
}

type resolvedMCPInvocation struct {
	ConfigPath     string
	PolicyBundle   string
	LogLevel       string
	LogLevelSource string
	Quiet          bool
}

func resolveServeInvocation(configFlag, policyFlag string, getenv func(string) string) (resolvedServeInvocation, error) {
	configRaw, _, err := resolvePathOption(configFlag, getenv("NOMOS_CONFIG"), "--config/-c", "NOMOS_CONFIG", true)
	if err != nil {
		return resolvedServeInvocation{}, err
	}
	bundleRaw, _, err := resolvePathOption(policyFlag, getenv("NOMOS_POLICY_BUNDLE"), "--policy-bundle/-p", "NOMOS_POLICY_BUNDLE", false)
	if err != nil {
		return resolvedServeInvocation{}, err
	}
	return resolvedServeInvocation{
		ConfigPath:   configRaw,
		PolicyBundle: bundleRaw,
	}, nil
}

func resolveMCPInvocation(configFlag, policyFlag, logLevelFlag string, quiet bool, getenv func(string) string) (resolvedMCPInvocation, error) {
	configRaw, _, err := resolvePathOption(configFlag, getenv("NOMOS_CONFIG"), "--config/-c", "NOMOS_CONFIG", true)
	if err != nil {
		return resolvedMCPInvocation{}, err
	}
	bundleRaw, _, err := resolvePathOption(policyFlag, getenv("NOMOS_POLICY_BUNDLE"), "--policy-bundle/-p", "NOMOS_POLICY_BUNDLE", false)
	if err != nil {
		return resolvedMCPInvocation{}, err
	}
	level, source := resolveValue(logLevelFlag, getenv("NOMOS_LOG_LEVEL"))
	if level == "" {
		level = "info"
		source = "default"
	}
	return resolvedMCPInvocation{
		ConfigPath:     configRaw,
		PolicyBundle:   bundleRaw,
		LogLevel:       level,
		LogLevelSource: source,
		Quiet:          quiet,
	}, nil
}

func resolvePathOption(flagValue, envValue, flagName, envName string, required bool) (string, string, error) {
	value, source := resolveValue(flagValue, envValue)
	if value == "" {
		if required {
			return "", "", fmt.Errorf("%s is required (or %s)", flagName, envName)
		}
		return "", "", nil
	}
	resolved, err := resolveAbsolutePath(value)
	if err != nil {
		return "", "", fmt.Errorf("invalid path for %s/%s: %w", flagName, envName, err)
	}
	return resolved, source, nil
}

func resolveValue(flagValue, envValue string) (string, string) {
	trimmedFlag := strings.TrimSpace(flagValue)
	if trimmedFlag != "" {
		return trimmedFlag, "flag"
	}
	trimmedEnv := strings.TrimSpace(envValue)
	if trimmedEnv != "" {
		return trimmedEnv, "env"
	}
	return "", ""
}

func resolveAbsolutePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func buildProtocolSafeMCPRecorder(cfg gateway.Config) (audit.Recorder, error) {
	redactor, err := redact.NewRedactor(cfg.Redaction.Patterns)
	if err != nil {
		return nil, err
	}
	return audit.NewWriter(protocolSafeMCPSink(cfg.Audit.Sink), redactor)
}

func buildMCPRuntimeTelemetry(cfg gateway.Config) *telemetry.Emitter {
	redactor, err := redact.NewRedactor(cfg.Redaction.Patterns)
	if err != nil {
		return telemetry.NewEmitter(nil)
	}
	exporter, err := telemetry.NewExporter(telemetry.Config{
		Enabled: cfg.Telemetry.Enabled,
		Sink:    protocolSafeMCPSink(cfg.Telemetry.Sink),
	}, redactor)
	if err != nil {
		return telemetry.NewEmitter(nil)
	}
	return telemetry.NewEmitter(exporter)
}

func protocolSafeMCPSink(sink string) string {
	parts := strings.Split(strings.TrimSpace(sink), ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if trimmed == "stdout" {
			out = append(out, "stderr")
			continue
		}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return "stderr"
	}
	return strings.Join(out, ",")
}

func toMCPUpstreamRoutes(routes []gateway.UpstreamRoute) []mcp.UpstreamRoute {
	if len(routes) == 0 {
		return nil
	}
	out := make([]mcp.UpstreamRoute, 0, len(routes))
	for _, route := range routes {
		out = append(out, mcp.UpstreamRoute{
			URL:        route.URL,
			Methods:    append([]string(nil), route.Methods...),
			PathPrefix: route.PathPrefix,
		})
	}
	return out
}

func toMCPUpstreamServers(defaults gateway.MCPTimeoutConfig, breakerDefaults gateway.MCPBreakerConfig, servers []gateway.MCPUpstreamServerConfig) []mcp.UpstreamServerConfig {
	if len(servers) == 0 {
		return nil
	}
	out := make([]mcp.UpstreamServerConfig, 0, len(servers))
	for _, server := range servers {
		env := map[string]string{}
		for key, value := range server.Env {
			env[key] = value
		}
		mapped := mcp.UpstreamServerConfig{
			Name:                    server.Name,
			Transport:               server.Transport,
			Command:                 server.Command,
			Args:                    append([]string(nil), server.Args...),
			EnvAllowlist:            append([]string(nil), server.EnvAllowlist...),
			Env:                     env,
			Workdir:                 server.Workdir,
			Endpoint:                server.Endpoint,
			AllowedHosts:            append([]string(nil), server.AllowedHosts...),
			TLSInsecure:             server.TLSInsecure,
			TLSCAFile:               server.TLSCAFile,
			TLSCertFile:             server.TLSCertFile,
			TLSKeyFile:              server.TLSKeyFile,
			InitializeTimeout:       timeoutDurationFromMS(coalesceTimeout(defaults.InitializeMS, server.Timeouts.InitializeMS)),
			EnumerateTimeout:        timeoutDurationFromMS(coalesceTimeout(defaults.EnumerateMS, server.Timeouts.EnumerateMS)),
			CallTimeout:             timeoutDurationFromMS(coalesceTimeout(defaults.CallMS, server.Timeouts.CallMS)),
			StreamTimeout:           timeoutDurationFromMS(coalesceTimeout(defaults.StreamMS, server.Timeouts.StreamMS)),
			BreakerEnabled:          coalesceBreakerEnabled(breakerDefaults.Enabled, server.Breaker.Enabled),
			BreakerThreshold:        coalesceTimeout(breakerDefaults.FailureThreshold, server.Breaker.FailureThreshold),
			BreakerWindow:           timeoutDurationFromMS(coalesceTimeout(breakerDefaults.FailureWindowMS, server.Breaker.FailureWindowMS)),
			BreakerOpenTime:         timeoutDurationFromMS(coalesceTimeout(breakerDefaults.OpenTimeoutMS, server.Breaker.OpenTimeoutMS)),
			AllowMissingToolSchemas: server.AllowMissingToolSchemas,
		}
		if server.Auth != nil {
			mapped.AuthType = server.Auth.Type
			mapped.AuthToken = server.Auth.Token
			mapped.AuthHeader = server.Auth.Header
			mapped.AuthValue = server.Auth.Value
			if len(server.Auth.Values) > 0 {
				mapped.AuthHeaders = map[string]string{}
				for k, v := range server.Auth.Values {
					mapped.AuthHeaders[k] = v
				}
			}
		}
		if server.Credentials != nil {
			profile := strings.TrimSpace(server.Credentials.Profile)
			if profile == "" {
				profile = strings.TrimSpace(server.Credentials.SecretID)
			}
			mapped.Credentials = &mcp.UpstreamCredentialsConfig{
				Profile:             profile,
				Mode:                strings.TrimSpace(server.Credentials.Mode),
				Header:              strings.TrimSpace(server.Credentials.Header),
				Env:                 strings.TrimSpace(server.Credentials.Env),
				FileName:            strings.TrimSpace(server.Credentials.FileName),
				RefreshBeforeExpiry: timeoutDurationFromMS(server.Credentials.RefreshBeforeExpiryMS),
			}
		}
		out = append(out, mapped)
	}
	return out
}

func coalesceBreakerEnabled(defaultValue, overrideValue *bool) bool {
	if overrideValue != nil {
		return *overrideValue
	}
	if defaultValue != nil {
		return *defaultValue
	}
	return true
}

func coalesceTimeout(defaultMS, overrideMS int) int {
	if overrideMS > 0 {
		return overrideMS
	}
	return defaultMS
}

func timeoutDurationFromMS(ms int) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

func mcpSinkRewritesStdout(sink string) bool {
	for _, part := range strings.Split(strings.TrimSpace(sink), ",") {
		if strings.EqualFold(strings.TrimSpace(part), "stdout") {
			return true
		}
	}
	return false
}

func rootHelpText() string {
	return "nomos commands:\n" +
		"  version    print build metadata\n" +
		"  serve      start gateway server\n" +
		"  mcp        start MCP stdio server\n" +
		"  policy     policy test/explain\n" +
		"  approvals  list pending approvals\n" +
		"  doctor     deterministic preflight checks\n\n" +
		"example:\n" +
		"  nomos mcp -c ./examples/configs/config.example.json -p ./examples/policies/your-policy-bundle.json\n"
}

func serveHelpText() string {
	return "usage: nomos serve [flags]\n" +
		"  -c, --config <path>          config json path (or NOMOS_CONFIG)\n" +
		"  -p, --policy-bundle <path>   policy bundle path (or NOMOS_POLICY_BUNDLE)\n\n" +
		"example:\n" +
		"  nomos serve -c ./examples/configs/config.example.json -p ./examples/policies/your-policy-bundle.json\n"
}

func mcpHelpText() string {
	return "usage: nomos mcp [flags]\n" +
		"  -c, --config <path>          config json path (or NOMOS_CONFIG)\n" +
		"  -p, --policy-bundle <path>   policy bundle path (or NOMOS_POLICY_BUNDLE)\n" +
		"  -l, --log-level <level>      error|warn|info|debug (or NOMOS_LOG_LEVEL)\n" +
		"  -q, --quiet                  suppress banner and non-error logs\n" +
		"      --log-format <format>    text|json\n\n" +
		"example:\n" +
		"  nomos mcp -c ./examples/configs/config.example.json -p ./examples/policies/your-policy-bundle.json\n" +
		"  nomos mcp serve --http --listen 127.0.0.1:8090 -c ./examples/configs/config.example.json\n"
}

func mcpServeHelpText() string {
	return "usage: nomos mcp serve --http --listen <addr> [flags]\n" +
		"  -c, --config <path>          config json path (or NOMOS_CONFIG)\n" +
		"  -p, --policy-bundle <path>   policy bundle path (or NOMOS_POLICY_BUNDLE)\n" +
		"      --http                   serve downstream MCP over streamable http\n" +
		"      --listen <addr>          bind address for downstream MCP http server\n\n" +
		"example:\n" +
		"  nomos mcp serve --http --listen 127.0.0.1:8090 -c ./examples/configs/config.example.json\n"
}

func doctorHelpText() string {
	return "usage: nomos doctor [flags]\n" +
		"  -c, --config <path>          config json path (or NOMOS_CONFIG)\n" +
		"  -p, --policy-bundle <path>   policy bundle path (or NOMOS_POLICY_BUNDLE)\n" +
		"      --format <format>        text|json\n\n" +
		"example:\n" +
		"  nomos doctor -c ./examples/configs/config.example.json --format json\n"
}

func writeRedactedLine(w io.Writer, value string) {
	redacted := redact.DefaultRedactor().RedactText(value)
	if !strings.HasSuffix(redacted, "\n") {
		redacted += "\n"
	}
	_, _ = io.WriteString(w, redacted)
}

func writeHelpText(w io.Writer, text string) {
	_, _ = io.WriteString(w, decorateHelpText(w, text))
}

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

func cliInfo(message string) {
	writeStatusLine(os.Stderr, "INFO", ansiCyan, message)
}

func cliInfof(format string, args ...any) {
	cliInfo(fmt.Sprintf(format, args...))
}

func cliSuccess(message string) {
	writeStatusLine(os.Stderr, "OK", ansiGreen, message)
}

func cliSuccessf(format string, args ...any) {
	cliSuccess(fmt.Sprintf(format, args...))
}

func cliWarn(message string) {
	writeStatusLine(os.Stderr, "WARN", ansiYellow, message)
}

func cliFatal(message string) {
	writeStatusLine(os.Stderr, "ERROR", ansiRed, message)
	os.Exit(1)
}

func cliFatalf(format string, args ...any) {
	cliFatal(fmt.Sprintf(format, args...))
}

func writeStatusLine(w io.Writer, label, color, message string) {
	prefix := "[" + label + "]"
	if supportsColor(w) {
		prefix = colorize(color, ansiBold+prefix+ansiReset)
	}
	writeRedactedLine(w, prefix+" "+message)
}

func decorateDoctorSummary(w io.Writer, report doctor.Report) string {
	summary := doctor.HumanSummary(report)
	if !supportsColor(w) {
		return summary
	}
	replacements := []struct {
		old string
		new string
	}{
		{"Nomos Doctor Report", colorize(ansiCyan, ansiBold+"Nomos Doctor Report"+ansiReset)},
		{"[PASS]", colorize(ansiGreen, ansiBold+"[PASS]"+ansiReset)},
		{"[FAIL]", colorize(ansiRed, ansiBold+"[FAIL]"+ansiReset)},
	}
	for _, item := range replacements {
		summary = strings.ReplaceAll(summary, item.old, item.new)
	}
	if report.OverallStatus == "READY" {
		summary = strings.Replace(summary, "Result: READY", "Result: "+colorize(ansiGreen, ansiBold+"READY"+ansiReset), 1)
		return summary
	}
	summary = strings.Replace(summary, "Result: NOT_READY", "Result: "+colorize(ansiRed, ansiBold+"NOT_READY"+ansiReset), 1)
	return summary
}

func decorateHelpText(w io.Writer, text string) string {
	if !supportsColor(w) {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "usage:"):
			lines[i] = colorize(ansiCyan, ansiBold+line+ansiReset)
		case trimmed == "example:":
			lines[i] = colorize(ansiYellow, ansiBold+line+ansiReset)
		case trimmed == "nomos commands:":
			lines[i] = colorize(ansiCyan, ansiBold+line+ansiReset)
		case strings.HasPrefix(line, "  nomos "):
			lines[i] = colorize(ansiGreen, line)
		case strings.HasPrefix(line, "  version") || strings.HasPrefix(line, "  serve") || strings.HasPrefix(line, "  mcp") || strings.HasPrefix(line, "  policy") || strings.HasPrefix(line, "  doctor"):
			fields := strings.Fields(line)
			if len(fields) > 0 {
				lines[i] = strings.Replace(line, fields[0], colorize(ansiGreen, fields[0]), 1)
			}
		case strings.HasPrefix(line, "  -") || strings.HasPrefix(line, "      --"):
			lines[i] = decorateFlagLine(line)
		}
	}
	return strings.Join(lines, "\n")
}

func decorateFlagLine(line string) string {
	start := 0
	for start < len(line) && line[start] == ' ' {
		start++
	}
	end := start
	for end < len(line) && line[end] != ' ' {
		end++
	}
	if end <= start {
		return line
	}
	return line[:start] + colorize(ansiGreen, line[start:end]) + line[end:]
}

func supportsColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb") {
		return false
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func colorize(color, value string) string {
	return color + value + ansiReset
}
