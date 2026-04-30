package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/approval"
	"github.com/safe-agentic-world/nomos/internal/assurance"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/opabridge"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/service"
	"github.com/safe-agentic-world/nomos/internal/telemetry"
	"github.com/safe-agentic-world/nomos/internal/version"
)

type Gateway struct {
	cfg                 Config
	server              *http.Server
	listener            net.Listener
	writer              audit.Recorder
	redactor            *redact.Redactor
	policy              *policy.Engine
	policyState         atomic.Pointer[gatewayPolicyState]
	service             *service.Service
	approvals           *approval.Store
	auth                *identity.Authenticator
	telemetry           *telemetry.Emitter
	actionTokens        chan struct{}
	rateLimiter         *principalLimiter
	breaker             *principalBreaker
	assuranceLevel      string
	policyBundleHash    string
	policyBundleSources []string
	uiReadinessReporter func() (UIReadinessReport, error)
	reloadMu            sync.Mutex
	now                 func() time.Time
}

type gatewayPolicyState struct {
	Engine         *policy.Engine
	BundleHash     string
	BundleSources  []string
	TenantPolicies map[string]*gatewayTenantPolicyState
}

type gatewayTenantPolicyState struct {
	Engine        *policy.Engine
	BundleHash    string
	BundleSources []string
}

type ReloadResult struct {
	Outcome             string   `json:"outcome"`
	Trigger             string   `json:"trigger"`
	PolicyBundleHash    string   `json:"policy_bundle_hash"`
	PolicyBundleSources []string `json:"policy_bundle_sources,omitempty"`
	RegistryVersion     uint64   `json:"registry_version"`
	Error               string   `json:"error,omitempty"`
}

func newGatewayPolicyState(bundle policy.Bundle) *gatewayPolicyState {
	return &gatewayPolicyState{
		Engine:         policy.NewEngine(bundle),
		BundleHash:     bundle.Hash,
		BundleSources:  policy.BundleSourceLabels(bundle),
		TenantPolicies: map[string]*gatewayTenantPolicyState{},
	}
}

func newGatewayTenantPolicyState(bundle policy.Bundle) *gatewayTenantPolicyState {
	return &gatewayTenantPolicyState{
		Engine:        policy.NewEngine(bundle),
		BundleHash:    bundle.Hash,
		BundleSources: policy.BundleSourceLabels(bundle),
	}
}

func New(cfg Config) (*Gateway, error) {
	redactor, err := redact.NewRedactor(cfg.Redaction.Patterns)
	if err != nil {
		return nil, err
	}
	telemetryExporter, err := telemetry.NewExporter(telemetry.Config{
		Enabled: cfg.Telemetry.Enabled,
		Sink:    cfg.Telemetry.Sink,
	}, redactor)
	if err != nil {
		return nil, err
	}
	writer, err := audit.NewWriter(cfg.Audit.Sink, redactor)
	if err != nil {
		return nil, err
	}
	state, err := loadGatewayPolicyStateFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	engine := state.Engine
	limit := cfg.Gateway.ConcurrencyLimit
	if limit <= 0 {
		limit = 32
	}
	rateLimit := cfg.Gateway.RateLimitPerMin
	if rateLimit <= 0 {
		rateLimit = 120
	}
	breakerFailures := cfg.Gateway.CircuitFailures
	if breakerFailures <= 0 {
		breakerFailures = 5
	}
	breakerCooldown := cfg.Gateway.CircuitCooldownS
	if breakerCooldown <= 0 {
		breakerCooldown = 60
	}
	var approvalStore *approval.Store
	if cfg.Approvals.Enabled {
		approvalStore, err = approval.Open(cfg.Approvals.StorePath, time.Duration(cfg.Approvals.TTLSeconds)*time.Second, time.Now)
		if err != nil {
			return nil, err
		}
	}
	credentialBroker, err := buildCredentialBroker(cfg, time.Now)
	if err != nil {
		return nil, err
	}
	actionRateLimiter, err := buildActionRateLimiter(cfg, time.Now)
	if err != nil {
		return nil, err
	}
	exec := executor.NewFSReader(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes, cfg.Executor.MaxOutputLines)
	writerExec := executor.NewFSWriter(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	patcher := executor.NewPatchApplier(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	execRunner := executor.NewExecRunner(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	httpRunner := executor.NewHTTPRunner(cfg.Executor.MaxOutputBytes)
	svc := service.New(engine, exec, writerExec, patcher, execRunner, httpRunner, writer, redactor, approvalStore, credentialBroker, cfg.Executor.SandboxProfile, time.Now)
	svc.SetSandboxEvidence(cfg.Runtime.Evidence.SandboxEvidence(), []string{cfg.Executor.WorkspaceRoot})
	svc.SetExecCompatibilityMode(cfg.Policy.ExecCompatibilityMode)
	svc.SetRateLimiter(actionRateLimiter)
	if cfg.Policy.OPA.Enabled {
		backend, err := opabridge.NewCommandBackend(opabridge.CommandConfig{
			BinaryPath: cfg.Policy.OPA.BinaryPath,
			PolicyPath: cfg.Policy.OPA.PolicyPath,
			Query:      cfg.Policy.OPA.Query,
			Timeout:    time.Duration(cfg.Policy.OPA.TimeoutMS) * time.Millisecond,
		})
		if err != nil {
			return nil, err
		}
		svc.SetExternalPolicy(backend)
	}
	svc.SetTelemetry(telemetry.NewEmitter(telemetryExporter))
	assuranceLevel := assurance.DeriveWithEvidence(cfg.Runtime.DeploymentMode, cfg.Runtime.StrongGuarantee, cfg.AssuranceEvidence())
	svc.SetAssuranceLevel(assuranceLevel)
	authenticator, err := identity.NewAuthenticator(identity.AuthConfig{
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
		return nil, err
	}
	gw := &Gateway{
		cfg:                 cfg,
		writer:              writer,
		redactor:            redactor,
		policy:              engine,
		service:             svc,
		approvals:           approvalStore,
		auth:                authenticator,
		telemetry:           telemetry.NewEmitter(telemetryExporter),
		actionTokens:        make(chan struct{}, limit),
		rateLimiter:         newPrincipalLimiter(rateLimit, time.Now),
		breaker:             newPrincipalBreaker(breakerFailures, time.Duration(breakerCooldown)*time.Second, time.Now),
		assuranceLevel:      assuranceLevel,
		policyBundleHash:    state.BundleHash,
		policyBundleSources: append([]string{}, state.BundleSources...),
		now:                 time.Now,
	}
	gw.policyState.Store(state)
	svc.SetPolicySelector(gw.selectPolicyEngine)
	return gw, nil
}

func NewWithRecorder(cfg Config, recorder audit.Recorder, now func() time.Time) (*Gateway, error) {
	if recorder == nil {
		return nil, errors.New("recorder is required")
	}
	if now == nil {
		now = time.Now
	}
	state, err := loadGatewayPolicyStateFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	engine := state.Engine
	limit := cfg.Gateway.ConcurrencyLimit
	if limit <= 0 {
		limit = 32
	}
	rateLimit := cfg.Gateway.RateLimitPerMin
	if rateLimit <= 0 {
		rateLimit = 120
	}
	breakerFailures := cfg.Gateway.CircuitFailures
	if breakerFailures <= 0 {
		breakerFailures = 5
	}
	breakerCooldown := cfg.Gateway.CircuitCooldownS
	if breakerCooldown <= 0 {
		breakerCooldown = 60
	}
	var approvalStore *approval.Store
	if cfg.Approvals.Enabled {
		approvalStore, err = approval.Open(cfg.Approvals.StorePath, time.Duration(cfg.Approvals.TTLSeconds)*time.Second, now)
		if err != nil {
			return nil, err
		}
	}
	credentialBroker, err := buildCredentialBroker(cfg, now)
	if err != nil {
		return nil, err
	}
	actionRateLimiter, err := buildActionRateLimiter(cfg, now)
	if err != nil {
		return nil, err
	}
	redactor, err := redact.NewRedactor(cfg.Redaction.Patterns)
	if err != nil {
		return nil, err
	}
	telemetryExporter, err := telemetry.NewExporter(telemetry.Config{
		Enabled: cfg.Telemetry.Enabled,
		Sink:    cfg.Telemetry.Sink,
	}, redactor)
	if err != nil {
		return nil, err
	}
	exec := executor.NewFSReader(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes, cfg.Executor.MaxOutputLines)
	writerExec := executor.NewFSWriter(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	patcher := executor.NewPatchApplier(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	execRunner := executor.NewExecRunner(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	httpRunner := executor.NewHTTPRunner(cfg.Executor.MaxOutputBytes)
	svc := service.New(engine, exec, writerExec, patcher, execRunner, httpRunner, recorder, redactor, approvalStore, credentialBroker, cfg.Executor.SandboxProfile, now)
	svc.SetSandboxEvidence(cfg.Runtime.Evidence.SandboxEvidence(), []string{cfg.Executor.WorkspaceRoot})
	svc.SetExecCompatibilityMode(cfg.Policy.ExecCompatibilityMode)
	svc.SetRateLimiter(actionRateLimiter)
	if cfg.Policy.OPA.Enabled {
		backend, err := opabridge.NewCommandBackend(opabridge.CommandConfig{
			BinaryPath: cfg.Policy.OPA.BinaryPath,
			PolicyPath: cfg.Policy.OPA.PolicyPath,
			Query:      cfg.Policy.OPA.Query,
			Timeout:    time.Duration(cfg.Policy.OPA.TimeoutMS) * time.Millisecond,
		})
		if err != nil {
			return nil, err
		}
		svc.SetExternalPolicy(backend)
	}
	svc.SetTelemetry(telemetry.NewEmitter(telemetryExporter))
	assuranceLevel := assurance.DeriveWithEvidence(cfg.Runtime.DeploymentMode, cfg.Runtime.StrongGuarantee, cfg.AssuranceEvidence())
	svc.SetAssuranceLevel(assuranceLevel)
	authenticator, err := identity.NewAuthenticator(identity.AuthConfig{
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
		return nil, err
	}
	gw := &Gateway{
		cfg:                 cfg,
		writer:              recorder,
		redactor:            redactor,
		policy:              engine,
		service:             svc,
		approvals:           approvalStore,
		auth:                authenticator,
		telemetry:           telemetry.NewEmitter(telemetryExporter),
		actionTokens:        make(chan struct{}, limit),
		rateLimiter:         newPrincipalLimiter(rateLimit, now),
		breaker:             newPrincipalBreaker(breakerFailures, time.Duration(breakerCooldown)*time.Second, now),
		assuranceLevel:      assuranceLevel,
		policyBundleHash:    state.BundleHash,
		policyBundleSources: append([]string{}, state.BundleSources...),
		now:                 now,
	}
	gw.policyState.Store(state)
	svc.SetPolicySelector(gw.selectPolicyEngine)
	return gw, nil
}

func (g *Gateway) PolicyBundleHash() string {
	if g == nil {
		return ""
	}
	state := g.policyState.Load()
	if state == nil {
		return g.policyBundleHash
	}
	return state.BundleHash
}

func (g *Gateway) PolicyBundleSources() []string {
	if g == nil {
		return nil
	}
	sources := g.policyBundleSources
	if state := g.policyState.Load(); state != nil {
		sources = state.BundleSources
	}
	if len(sources) == 0 {
		return nil
	}
	out := make([]string, len(sources))
	copy(out, sources)
	return out
}

func (g *Gateway) currentPolicyState() *gatewayPolicyState {
	if g == nil {
		return nil
	}
	return g.policyState.Load()
}

func (g *Gateway) loadPolicyState() (*gatewayPolicyState, error) {
	return loadGatewayPolicyStateFromConfig(g.cfg)
}

func (g *Gateway) ReloadPolicy(ctx context.Context, trigger string) (ReloadResult, error) {
	if g == nil || g.service == nil {
		return ReloadResult{}, errors.New("gateway not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	trigger = strings.TrimSpace(trigger)
	if trigger == "" {
		trigger = "manual"
	}
	g.reloadMu.Lock()
	defer g.reloadMu.Unlock()
	next, err := g.loadPolicyState()
	if err != nil {
		result := ReloadResult{Outcome: "failure", Trigger: trigger, PolicyBundleHash: g.PolicyBundleHash(), PolicyBundleSources: g.PolicyBundleSources(), RegistryVersion: 0, Error: stableReloadError(err)}
		g.recordReloadAudit(result)
		return result, fmt.Errorf("reload validation failed: %w", err)
	}
	if err := g.service.SetPolicyEngine(next.Engine); err != nil {
		result := ReloadResult{Outcome: "failure", Trigger: trigger, PolicyBundleHash: g.PolicyBundleHash(), PolicyBundleSources: g.PolicyBundleSources(), RegistryVersion: 0, Error: stableReloadError(err)}
		g.recordReloadAudit(result)
		return result, err
	}
	g.policyState.Store(next)
	g.policy = next.Engine
	g.policyBundleHash = next.BundleHash
	g.policyBundleSources = append([]string{}, next.BundleSources...)
	result := ReloadResult{Outcome: "success", Trigger: trigger, PolicyBundleHash: next.BundleHash, PolicyBundleSources: append([]string{}, next.BundleSources...), RegistryVersion: 0}
	g.recordReloadAudit(result)
	return result, nil
}

func stableReloadError(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}

func (g *Gateway) recordReloadAudit(result ReloadResult) {
	if g == nil || g.writer == nil {
		return
	}
	metadata := map[string]any{
		"trigger":          result.Trigger,
		"outcome":          result.Outcome,
		"registry_version": result.RegistryVersion,
	}
	if result.Error != "" {
		metadata["error"] = result.Error
	}
	_ = g.writer.WriteEvent(audit.Event{
		SchemaVersion:       "v1",
		Timestamp:           g.now().UTC(),
		EventType:           "runtime.reload",
		TraceID:             "runtime.reload",
		PolicyBundleHash:    result.PolicyBundleHash,
		PolicyBundleSources: append([]string{}, result.PolicyBundleSources...),
		Decision:            strings.ToUpper(result.Outcome),
		Reason:              result.Error,
		ExecutorMetadata:    metadata,
		AssuranceLevel:      g.assuranceLevel,
	})
}

func (g *Gateway) SetUIReadinessReporter(fn func() (UIReadinessReport, error)) {
	if g == nil {
		return
	}
	g.uiReadinessReporter = fn
}

func (g *Gateway) Start() error {
	if g.server != nil {
		return errors.New("gateway already started")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", g.handleHealthz)
	mux.HandleFunc("/version", g.handleVersion)
	mux.HandleFunc("/ui", g.handleUIRoot)
	mux.HandleFunc("/ui/", g.handleUIStatic)
	mux.HandleFunc("/api/ui/readiness", g.handleUIReadiness)
	mux.HandleFunc("/api/ui/approvals", g.handleUIApprovals)
	mux.HandleFunc("/api/ui/approvals/decide", g.handleUIApprovalDecision)
	mux.HandleFunc("/api/ui/actions/", g.handleUIActionDetail)
	mux.HandleFunc("/api/ui/traces", g.handleUITraceList)
	mux.HandleFunc("/api/ui/traces/", g.handleUITraceDetail)
	mux.HandleFunc("/api/ui/upstreams", g.handleUIUpstreams)
	mux.HandleFunc("/api/ui/explain", g.handleUIExplain)
	mux.HandleFunc("/admin/reload", g.handleAdminReload)
	mux.HandleFunc("/explain", g.handleExplain)
	mux.HandleFunc("/run", g.handleAction)
	mux.HandleFunc("/action", g.handleAction)
	mux.HandleFunc("/actions/report", g.handleExternalReport)
	mux.HandleFunc("/approvals/decide", g.handleApprovalDecision)
	mux.HandleFunc("/webhooks/approvals", g.handleApprovalDecisionWebhook)
	mux.HandleFunc("/webhooks/slack/approvals", g.handleSlackApprovalWebhook)
	mux.HandleFunc("/webhooks/teams/approvals", g.handleTeamsApprovalWebhook)

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	if g.cfg.Gateway.TLS.Enabled {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if g.cfg.Gateway.TLS.RequireMTLS {
			caPEM, err := os.ReadFile(g.cfg.Gateway.TLS.ClientCAFile)
			if err != nil {
				return err
			}
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caPEM) {
				return errors.New("invalid gateway tls client_ca_file")
			}
			tlsConfig.ClientCAs = caPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
		server.TLSConfig = tlsConfig
	}
	g.server = server

	listener, err := net.Listen("tcp", g.cfg.Gateway.Listen)
	if err != nil {
		return err
	}
	g.listener = listener

	go func() {
		if g.cfg.Gateway.TLS.Enabled {
			_ = server.ServeTLS(listener, g.cfg.Gateway.TLS.CertFile, g.cfg.Gateway.TLS.KeyFile)
			return
		}
		_ = server.Serve(listener)
	}()
	return nil
}

func (g *Gateway) Shutdown(ctx context.Context) error {
	if closer, ok := g.writer.(io.Closer); ok {
		_ = closer.Close()
	}
	if g.approvals != nil {
		_ = g.approvals.Close()
	}
	if g.server == nil {
		return nil
	}
	return g.server.Shutdown(ctx)
}

func (g *Gateway) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (g *Gateway) handleVersion(w http.ResponseWriter, _ *http.Request) {
	info := version.Current()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

func (g *Gateway) handleAdminReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if _, err := g.auth.VerifyPrincipalOnly(r); err != nil {
		g.respondError(w, http.StatusUnauthorized, "auth_error", err.Error())
		return
	}
	if g.cfg.Gateway.TLS.RequireMTLS {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			g.respondError(w, http.StatusUnauthorized, "auth_error", "mTLS client certificate required")
			return
		}
	}
	result, err := g.ReloadPolicy(r.Context(), "admin")
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	_ = json.NewEncoder(w).Encode(result)
}

func (g *Gateway) handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	traceContext := telemetry.ParseTraceContext(r.Header)
	telemetry.PropagateTraceContext(w, traceContext)
	if !g.tryAcquireActionSlot() {
		g.respondError(w, http.StatusTooManyRequests, "rate_limited", "concurrency limit reached")
		return
	}
	defer g.releaseActionSlot()

	body, err := action.ReadRequestBytes(r.Body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}

	id, err := g.auth.Verify(r, body)
	if err != nil {
		g.respondError(w, http.StatusUnauthorized, "auth_error", err.Error())
		return
	}
	if g.cfg.Gateway.TLS.RequireMTLS {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			g.respondError(w, http.StatusUnauthorized, "auth_error", "mTLS client certificate required")
			return
		}
	}
	key := id.Principal + "|" + id.Agent + "|" + id.Environment
	if g.rateLimiter != nil && !g.rateLimiter.Allow(key) {
		g.respondError(w, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded")
		return
	}
	if g.breaker != nil && !g.breaker.Allow(key) {
		g.respondError(w, http.StatusTooManyRequests, "circuit_open", "circuit breaker is open")
		return
	}
	req, err := action.DecodeActionRequestBytes(body)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	act, err := action.ToAction(req, id)
	if err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	if err := g.attachTenant(&act, id); err != nil {
		g.respondError(w, http.StatusForbidden, "tenant_resolution_error", err.Error())
		return
	}
	if err := g.validateUpstreamRoute(act); err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
	}
	if g.telemetry != nil && g.telemetry.Enabled() {
		g.telemetry.Event(telemetry.Event{
			SignalType:  "trace",
			EventName:   "gateway.request",
			TraceID:     act.TraceID,
			Correlation: act.TraceID,
			Traceparent: traceContext.Traceparent,
			Tracestate:  traceContext.Tracestate,
			Status:      "accepted",
			Attributes: map[string]any{
				"action_id":   act.ActionID,
				"action_type": act.ActionType,
				"transport":   "http",
			},
		})
	}

	resp, err := g.service.Process(act)
	if err != nil {
		if g.breaker != nil {
			g.breaker.ObserveFailure(key)
		}
		g.respondError(w, http.StatusBadRequest, "execution_error", err.Error())
		return
	}
	if g.breaker != nil {
		g.breaker.ObserveSuccess(key)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) tryAcquireActionSlot() bool {
	select {
	case g.actionTokens <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *Gateway) releaseActionSlot() {
	select {
	case <-g.actionTokens:
	default:
	}
}

func (g *Gateway) respondError(w http.ResponseWriter, status int, code string, message string) {
	resp := action.Response{
		Decision: policy.DecisionDeny,
		Reason:   code + ": " + message,
	}
	payload, _ := json.Marshal(resp)
	redacted := redact.DefaultRedactor().RedactBytes(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(redacted)
}

func (g *Gateway) validateUpstreamRoute(act action.Action) error {
	if act.ActionType != "net.http_request" {
		return nil
	}
	if len(g.cfg.Upstream.Routes) == 0 {
		return nil
	}
	normalized, err := normalize.NormalizeResource(act.Resource)
	if err != nil {
		return err
	}
	host, reqPath, err := routeTargetFromNormalized(normalized)
	if err != nil {
		return err
	}
	method, err := requestMethodFromParams(act.Params)
	if err != nil {
		return err
	}
	for _, route := range g.cfg.Upstream.Routes {
		if upstreamRouteMatches(route, host, reqPath, method) {
			return nil
		}
	}
	return errors.New("upstream route not configured")
}

func requestMethodFromParams(raw json.RawMessage) (string, error) {
	var params struct {
		Method string `json:"method"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil {
		return "", err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return "", errors.New("unexpected trailing data")
	}
	method := strings.ToUpper(strings.TrimSpace(params.Method))
	if method == "" {
		return http.MethodGet, nil
	}
	return method, nil
}

func upstreamRouteMatches(route UpstreamRoute, host, reqPath, method string) bool {
	parsed, err := neturl.Parse(strings.TrimSpace(route.URL))
	if err != nil {
		return false
	}
	routeHost := strings.ToLower(parsed.Host)
	if routeHost != strings.ToLower(host) {
		return false
	}
	if len(route.Methods) > 0 {
		allowed := make([]string, 0, len(route.Methods))
		for _, item := range route.Methods {
			allowed = append(allowed, strings.ToUpper(strings.TrimSpace(item)))
		}
		if !slices.Contains(allowed, method) {
			return false
		}
	}
	prefix := strings.TrimSpace(route.PathPrefix)
	if prefix == "" {
		prefix = parsed.EscapedPath()
		if prefix == "" {
			prefix = "/"
		}
	}
	if reqPath == prefix {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(reqPath, prefix)
	}
	return strings.HasPrefix(reqPath, prefix+"/")
}

func routeTargetFromNormalized(resource string) (string, string, error) {
	if !strings.HasPrefix(resource, "url://") {
		return "", "", errors.New("resource is not url")
	}
	raw := strings.TrimPrefix(resource, "url://")
	host, pathValue, ok := strings.Cut(raw, "/")
	if !ok {
		return host, "/", nil
	}
	cleaned := path.Clean("/" + pathValue)
	if cleaned == "." || cleaned == "" {
		cleaned = "/"
	}
	return host, cleaned, nil
}

func (g *Gateway) emitTraceEvent(eventType, traceID, actionID string) {
	event := audit.Event{
		Timestamp:      g.now().UTC(),
		EventType:      eventType,
		TraceID:        traceID,
		ActionID:       actionID,
		AssuranceLevel: g.assuranceLevel,
	}
	_ = g.writer.WriteEvent(event)
}
