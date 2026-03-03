package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/approval"
	"github.com/safe-agentic-world/nomos/internal/assurance"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/service"
	"github.com/safe-agentic-world/nomos/internal/version"
	"github.com/safe-agentic-world/nomos/internal/normalize"
)

type Gateway struct {
	cfg            Config
	server         *http.Server
	listener       net.Listener
	writer         audit.Recorder
	policy         *policy.Engine
	service        *service.Service
	approvals      *approval.Store
	auth           *identity.Authenticator
	actionTokens   chan struct{}
	rateLimiter    *principalLimiter
	breaker        *principalBreaker
	assuranceLevel string
	now            func() time.Time
}

func New(cfg Config) (*Gateway, error) {
	redactor, err := redact.NewRedactor(cfg.Redaction.Patterns)
	if err != nil {
		return nil, err
	}
	writer, err := audit.NewWriter(cfg.Audit.Sink, redactor)
	if err != nil {
		return nil, err
	}
	bundle, err := policy.LoadBundleWithOptions(cfg.Policy.BundlePath, policy.LoadOptions{
		VerifySignature: cfg.Policy.VerifySignatures,
		SignaturePath:   cfg.Policy.SignaturePath,
		PublicKeyPath:   cfg.Policy.PublicKeyPath,
	})
	if err != nil {
		return nil, err
	}
	engine := policy.NewEngine(bundle)
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
	exec := executor.NewFSReader(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes, cfg.Executor.MaxOutputLines)
	writerExec := executor.NewFSWriter(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	patcher := executor.NewPatchApplier(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	execRunner := executor.NewExecRunner(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	httpRunner := executor.NewHTTPRunner(cfg.Executor.MaxOutputBytes)
	svc := service.New(engine, exec, writerExec, patcher, execRunner, httpRunner, writer, redactor, approvalStore, credentialBroker, cfg.Executor.SandboxProfile, time.Now)
	assuranceLevel := assurance.Derive(cfg.Runtime.DeploymentMode, cfg.Runtime.StrongGuarantee)
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
	})
	if err != nil {
		return nil, err
	}
	gw := &Gateway{
		cfg:            cfg,
		writer:         writer,
		policy:         engine,
		service:        svc,
		approvals:      approvalStore,
		auth:           authenticator,
		actionTokens:   make(chan struct{}, limit),
		rateLimiter:    newPrincipalLimiter(rateLimit, time.Now),
		breaker:        newPrincipalBreaker(breakerFailures, time.Duration(breakerCooldown)*time.Second, time.Now),
		assuranceLevel: assuranceLevel,
		now:            time.Now,
	}
	return gw, nil
}

func NewWithRecorder(cfg Config, recorder audit.Recorder, now func() time.Time) (*Gateway, error) {
	if recorder == nil {
		return nil, errors.New("recorder is required")
	}
	if now == nil {
		now = time.Now
	}
	bundle, err := policy.LoadBundleWithOptions(cfg.Policy.BundlePath, policy.LoadOptions{
		VerifySignature: cfg.Policy.VerifySignatures,
		SignaturePath:   cfg.Policy.SignaturePath,
		PublicKeyPath:   cfg.Policy.PublicKeyPath,
	})
	if err != nil {
		return nil, err
	}
	engine := policy.NewEngine(bundle)
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
	redactor, err := redact.NewRedactor(cfg.Redaction.Patterns)
	if err != nil {
		return nil, err
	}
	exec := executor.NewFSReader(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes, cfg.Executor.MaxOutputLines)
	writerExec := executor.NewFSWriter(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	patcher := executor.NewPatchApplier(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	execRunner := executor.NewExecRunner(cfg.Executor.WorkspaceRoot, cfg.Executor.MaxOutputBytes)
	httpRunner := executor.NewHTTPRunner(cfg.Executor.MaxOutputBytes)
	svc := service.New(engine, exec, writerExec, patcher, execRunner, httpRunner, recorder, redactor, approvalStore, credentialBroker, cfg.Executor.SandboxProfile, now)
	assuranceLevel := assurance.Derive(cfg.Runtime.DeploymentMode, cfg.Runtime.StrongGuarantee)
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
	})
	if err != nil {
		return nil, err
	}
	gw := &Gateway{
		cfg:            cfg,
		writer:         recorder,
		policy:         engine,
		service:        svc,
		approvals:      approvalStore,
		auth:           authenticator,
		actionTokens:   make(chan struct{}, limit),
		rateLimiter:    newPrincipalLimiter(rateLimit, now),
		breaker:        newPrincipalBreaker(breakerFailures, time.Duration(breakerCooldown)*time.Second, now),
		assuranceLevel: assuranceLevel,
		now:            now,
	}
	return gw, nil
}

func (g *Gateway) Start() error {
	if g.server != nil {
		return errors.New("gateway already started")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", g.handleHealthz)
	mux.HandleFunc("/version", g.handleVersion)
	mux.HandleFunc("/run", g.handleAction)
	mux.HandleFunc("/action", g.handleAction)
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

func (g *Gateway) handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
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
	if err := g.validateUpstreamRoute(act); err != nil {
		g.respondError(w, http.StatusBadRequest, "validation_error", err.Error())
		return
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
