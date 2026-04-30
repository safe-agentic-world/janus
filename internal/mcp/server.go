package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/approval"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/responsescan"
	"github.com/safe-agentic-world/nomos/internal/service"
	"github.com/safe-agentic-world/nomos/internal/telemetry"
	"github.com/safe-agentic-world/nomos/internal/tenant"
	"github.com/safe-agentic-world/nomos/internal/version"
)

type Server struct {
	service               *service.Service
	approvals             *approval.Store
	identity              identity.VerifiedIdentity
	approvalsEnabled      bool
	sandboxEnabled        bool
	outputMaxBytes        int
	outputMaxLines        int
	policyBundleHash      string
	policyBundleSources   []string
	assuranceLevel        string
	upstreamRoutes        []UpstreamRoute
	upstream              *upstreamSupervisor
	state                 *serverStateHolder
	reloadMu              *sync.Mutex
	recorder              audit.Recorder
	credentialBroker      UpstreamCredentialBroker
	bundlePaths           []string
	bundleRoles           []string
	execCompatibilityMode string
	responseScanner       *responsescan.Scanner
	telemetry             *telemetry.Emitter
	tenantConfig          tenant.Config
	logger                *runtimeLogger
	pid                   int
	ownsResources         bool
}

type serverReloadState struct {
	Engine              *policy.Engine
	PolicyBundleHash    string
	PolicyBundleSources []string
	UpstreamRoutes      []UpstreamRoute
	TenantPolicies      map[string]*serverTenantPolicyState
}

type serverTenantPolicyState struct {
	Engine        *policy.Engine
	BundleHash    string
	BundleSources []string
}

type serverStateHolder struct {
	ptr atomic.Pointer[serverReloadState]
}

type ReloadOptions struct {
	BundlePaths    []string
	RuntimeOptions RuntimeOptions
	Trigger        string
}

type ReloadResult struct {
	Outcome             string   `json:"outcome"`
	Trigger             string   `json:"trigger"`
	PolicyBundleHash    string   `json:"policy_bundle_hash"`
	PolicyBundleSources []string `json:"policy_bundle_sources,omitempty"`
	RegistryVersion     uint64   `json:"registry_version"`
	AddedUpstreams      []string `json:"added_upstreams,omitempty"`
	RemovedUpstreams    []string `json:"removed_upstreams,omitempty"`
	Error               string   `json:"error,omitempty"`
}

type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Ctx    context.Context `json:"-"`
}

type Response struct {
	ID     string      `json:"id"`
	Result interface{} `json:"result,omitempty"`
	Error  string      `json:"error,omitempty"`
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	Ctx     context.Context `json:"-"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type fsReadParams struct {
	Resource   string `json:"resource"`
	ApprovalID string `json:"approval_id,omitempty"`
}

type fsWriteParams struct {
	Resource   string `json:"resource"`
	Content    string `json:"content"`
	ApprovalID string `json:"approval_id,omitempty"`
}

type execParams struct {
	Argv             []string `json:"argv"`
	Cwd              string   `json:"cwd"`
	EnvAllowlistKeys []string `json:"env_allowlist_keys"`
	ApprovalID       string   `json:"approval_id,omitempty"`
}

type httpParams struct {
	Resource   string            `json:"resource"`
	Method     string            `json:"method"`
	Body       string            `json:"body"`
	Header     map[string]string `json:"headers"`
	ApprovalID string            `json:"approval_id,omitempty"`
}

type patchParams struct {
	Path       string `json:"path"`
	Content    string `json:"content"`
	ApprovalID string `json:"approval_id,omitempty"`
}

type changeSetParams struct {
	Paths []string `json:"paths"`
}

const SupportedProtocolVersion = "2024-11-05"

func newServerStateHolder(state *serverReloadState) *serverStateHolder {
	holder := &serverStateHolder{}
	holder.store(state)
	return holder
}

func newServerReloadState(engine *policy.Engine, bundle policy.Bundle, routes []UpstreamRoute, tenants map[string]*serverTenantPolicyState) *serverReloadState {
	return &serverReloadState{
		Engine:              engine,
		PolicyBundleHash:    bundle.Hash,
		PolicyBundleSources: policy.BundleSourceLabels(bundle),
		UpstreamRoutes:      append([]UpstreamRoute(nil), routes...),
		TenantPolicies:      cloneServerTenantPolicyStates(tenants),
	}
}

func (h *serverStateHolder) load() *serverReloadState {
	if h == nil {
		return nil
	}
	return h.ptr.Load()
}

func (h *serverStateHolder) store(state *serverReloadState) {
	if h == nil || state == nil {
		return
	}
	copied := &serverReloadState{
		Engine:              state.Engine,
		PolicyBundleHash:    state.PolicyBundleHash,
		PolicyBundleSources: append([]string{}, state.PolicyBundleSources...),
		UpstreamRoutes:      append([]UpstreamRoute(nil), state.UpstreamRoutes...),
		TenantPolicies:      cloneServerTenantPolicyStates(state.TenantPolicies),
	}
	h.ptr.Store(copied)
}

func cloneServerTenantPolicyStates(input map[string]*serverTenantPolicyState) map[string]*serverTenantPolicyState {
	if len(input) == 0 {
		return map[string]*serverTenantPolicyState{}
	}
	out := make(map[string]*serverTenantPolicyState, len(input))
	for id, state := range input {
		if state == nil {
			continue
		}
		out[id] = &serverTenantPolicyState{
			Engine:        state.Engine,
			BundleHash:    state.BundleHash,
			BundleSources: append([]string{}, state.BundleSources...),
		}
	}
	return out
}

func NewServer(bundlePath string, identity identity.VerifiedIdentity, workspaceRoot string, maxBytes, maxLines int, approvalsEnabled bool, sandboxEnabled bool, sandboxProfile string) (*Server, error) {
	return NewServerWithRuntimeOptions(bundlePath, identity, workspaceRoot, maxBytes, maxLines, approvalsEnabled, sandboxEnabled, sandboxProfile, RuntimeOptions{})
}

func NewServerWithRuntimeOptions(bundlePath string, identity identity.VerifiedIdentity, workspaceRoot string, maxBytes, maxLines int, approvalsEnabled bool, sandboxEnabled bool, sandboxProfile string, runtimeOptions RuntimeOptions) (*Server, error) {
	return NewServerWithRuntimeOptionsAndRecorder(bundlePath, identity, workspaceRoot, maxBytes, maxLines, approvalsEnabled, sandboxEnabled, sandboxProfile, runtimeOptions, nil)
}

func NewServerWithRuntimeOptionsAndRecorder(bundlePath string, identity identity.VerifiedIdentity, workspaceRoot string, maxBytes, maxLines int, approvalsEnabled bool, sandboxEnabled bool, sandboxProfile string, runtimeOptions RuntimeOptions, recorder audit.Recorder) (*Server, error) {
	return NewServerForBundlesWithRuntimeOptionsAndRecorder([]string{bundlePath}, identity, workspaceRoot, maxBytes, maxLines, approvalsEnabled, sandboxEnabled, sandboxProfile, runtimeOptions, recorder)
}

func NewServerForBundlesWithRuntimeOptionsAndRecorder(bundlePaths []string, identity identity.VerifiedIdentity, workspaceRoot string, maxBytes, maxLines int, approvalsEnabled bool, sandboxEnabled bool, sandboxProfile string, runtimeOptions RuntimeOptions, recorder audit.Recorder) (*Server, error) {
	if identity.Principal == "" || identity.Agent == "" || identity.Environment == "" {
		return nil, errors.New("identity is required")
	}
	parsedRuntime, err := ParseRuntimeOptions(runtimeOptions)
	if err != nil {
		return nil, err
	}
	bundle, err := policy.LoadBundlesWithOptions(bundlePaths, policy.MultiLoadOptions{
		BundleRoles: parsedRuntime.BundleRoles,
	})
	if err != nil {
		return nil, err
	}
	if err := policy.ValidateExecCompatibility(bundle, parsedRuntime.ExecCompatibilityMode); err != nil {
		return nil, err
	}
	tenantPolicies, err := loadServerTenantPolicyStates(bundlePaths, parsedRuntime)
	if err != nil {
		return nil, err
	}
	logger, err := newRuntimeLogger(parsedRuntime)
	if err != nil {
		return nil, err
	}
	responseScanner, err := responsescan.DefaultScanner()
	if err != nil {
		return nil, err
	}
	engine := policy.NewEngine(bundle)
	reader := executor.NewFSReader(workspaceRoot, maxBytes, maxLines)
	writerExec := executor.NewFSWriter(workspaceRoot, maxBytes)
	patcher := executor.NewPatchApplier(workspaceRoot, maxBytes)
	execRunner := executor.NewExecRunner(workspaceRoot, maxBytes)
	httpRunner := executor.NewHTTPRunner(maxBytes)
	if recorder == nil {
		recorder = noopRecorder{}
	}
	var approvalStore *approval.Store
	if approvalsEnabled && parsedRuntime.ApprovalStorePath != "" {
		ttl := time.Duration(parsedRuntime.ApprovalTTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = 10 * time.Minute
		}
		approvalStore, err = approval.Open(parsedRuntime.ApprovalStorePath, ttl, time.Now)
		if err != nil {
			return nil, err
		}
	}
	svc := service.New(engine, reader, writerExec, patcher, execRunner, httpRunner, recorder, logger.redactor, approvalStore, nil, sandboxProfile, nil)
	svc.SetSandboxEvidence(parsedRuntime.SandboxEvidence, []string{workspaceRoot})
	svc.SetExecCompatibilityMode(parsedRuntime.ExecCompatibilityMode)
	upstream, err := newUpstreamSupervisor(parsedRuntime.UpstreamServers, logger, parsedRuntime.Telemetry, identity, parsedRuntime.CredentialBroker, recorder)
	if err != nil {
		return nil, err
	}
	state := newServerReloadState(engine, bundle, parsedRuntime.UpstreamRoutes, tenantPolicies)
	server := &Server{
		service:               svc,
		approvals:             approvalStore,
		identity:              identity,
		approvalsEnabled:      approvalStore != nil,
		sandboxEnabled:        sandboxEnabled,
		outputMaxBytes:        maxBytes,
		outputMaxLines:        maxLines,
		policyBundleHash:      state.PolicyBundleHash,
		policyBundleSources:   append([]string{}, state.PolicyBundleSources...),
		assuranceLevel:        "NONE",
		upstreamRoutes:        append([]UpstreamRoute(nil), state.UpstreamRoutes...),
		upstream:              upstream,
		state:                 newServerStateHolder(state),
		reloadMu:              &sync.Mutex{},
		recorder:              recorder,
		credentialBroker:      parsedRuntime.CredentialBroker,
		bundlePaths:           append([]string{}, bundlePaths...),
		bundleRoles:           append([]string{}, parsedRuntime.BundleRoles...),
		execCompatibilityMode: parsedRuntime.ExecCompatibilityMode,
		responseScanner:       responseScanner,
		telemetry:             parsedRuntime.Telemetry,
		tenantConfig:          parsedRuntime.TenantConfig,
		logger:                logger,
		pid:                   os.Getpid(),
		ownsResources:         true,
	}
	svc.SetPolicySelector(server.selectPolicyEngine)
	return server, nil
}

func (s *Server) CloneForIdentity(id identity.VerifiedIdentity) *Server {
	if s == nil {
		return nil
	}
	clone := *s
	clone.identity = id
	clone.ownsResources = false
	return &clone
}

func (s *Server) currentReloadState() *serverReloadState {
	if s == nil || s.state == nil {
		return nil
	}
	return s.state.load()
}

func (s *Server) policyMetadata() (string, []string) {
	if s == nil {
		return "", nil
	}
	if state := s.currentReloadState(); state != nil {
		return state.PolicyBundleHash, append([]string{}, state.PolicyBundleSources...)
	}
	return s.policyBundleHash, append([]string{}, s.policyBundleSources...)
}

func (s *Server) currentUpstreamRoutes() []UpstreamRoute {
	if s == nil {
		return nil
	}
	if state := s.currentReloadState(); state != nil {
		return append([]UpstreamRoute(nil), state.UpstreamRoutes...)
	}
	return append([]UpstreamRoute(nil), s.upstreamRoutes...)
}

func (s *Server) SetAssuranceLevel(level string) {
	if s == nil {
		return
	}
	level = strings.TrimSpace(level)
	if level == "" {
		level = "NONE"
	}
	s.assuranceLevel = level
	s.service.SetAssuranceLevel(level)
}

func (s *Server) Reload(ctx context.Context, opts ReloadOptions) (ReloadResult, error) {
	if s == nil || s.service == nil || s.upstream == nil {
		return ReloadResult{}, errors.New("mcp server not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	trigger := strings.TrimSpace(opts.Trigger)
	if trigger == "" {
		trigger = "manual"
	}
	if s.reloadMu == nil {
		s.reloadMu = &sync.Mutex{}
	}
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	bundlePaths := append([]string{}, opts.BundlePaths...)
	if len(bundlePaths) == 0 {
		bundlePaths = append([]string{}, s.bundlePaths...)
	}
	if len(bundlePaths) == 0 {
		err := errors.New("policy bundle path is required")
		result := s.reloadFailureResult(trigger, err)
		s.recordReloadAudit(result)
		return result, err
	}
	runtimeOptions := opts.RuntimeOptions
	if runtimeOptions.ExecCompatibilityMode == "" {
		runtimeOptions.ExecCompatibilityMode = s.execCompatibilityMode
	}
	if len(runtimeOptions.BundleRoles) == 0 && len(s.bundleRoles) > 0 {
		runtimeOptions.BundleRoles = append([]string{}, s.bundleRoles...)
	}
	if runtimeOptions.CredentialBroker == nil {
		runtimeOptions.CredentialBroker = s.credentialBroker
	}
	if !runtimeOptions.TenantConfig.Configured() && s.tenantConfig.Configured() {
		runtimeOptions.TenantConfig = s.tenantConfig
	}
	parsedRuntime, err := ParseRuntimeOptions(runtimeOptions)
	if err != nil {
		result := s.reloadFailureResult(trigger, err)
		s.recordReloadAudit(result)
		return result, fmt.Errorf("reload validation failed: %w", err)
	}
	bundle, err := policy.LoadBundlesWithOptions(bundlePaths, policy.MultiLoadOptions{
		BundleRoles: parsedRuntime.BundleRoles,
	})
	if err != nil {
		result := s.reloadFailureResult(trigger, err)
		s.recordReloadAudit(result)
		return result, fmt.Errorf("reload validation failed: %w", err)
	}
	if err := policy.ValidateExecCompatibility(bundle, parsedRuntime.ExecCompatibilityMode); err != nil {
		result := s.reloadFailureResult(trigger, err)
		s.recordReloadAudit(result)
		return result, fmt.Errorf("reload validation failed: %w", err)
	}
	tenantPolicies, err := loadServerTenantPolicyStates(bundlePaths, parsedRuntime)
	if err != nil {
		result := s.reloadFailureResult(trigger, err)
		s.recordReloadAudit(result)
		return result, fmt.Errorf("reload validation failed: %w", err)
	}
	nextEngine := policy.NewEngine(bundle)
	upstreamResult, err := s.upstream.reload(ctx, parsedRuntime.UpstreamServers, s.identity, parsedRuntime.CredentialBroker, s.recorder)
	if err != nil {
		result := s.reloadFailureResult(trigger, err)
		s.recordReloadAudit(result)
		return result, fmt.Errorf("reload validation failed: %w", err)
	}
	if err := s.service.SetPolicyEngine(nextEngine); err != nil {
		result := s.reloadFailureResult(trigger, err)
		result.RegistryVersion = upstreamResult.RegistryVersion
		s.recordReloadAudit(result)
		return result, err
	}
	s.service.SetExecCompatibilityMode(parsedRuntime.ExecCompatibilityMode)
	nextState := newServerReloadState(nextEngine, bundle, parsedRuntime.UpstreamRoutes, tenantPolicies)
	if s.state == nil {
		s.state = newServerStateHolder(nextState)
	} else {
		s.state.store(nextState)
	}
	s.policyBundleHash = nextState.PolicyBundleHash
	s.policyBundleSources = append([]string{}, nextState.PolicyBundleSources...)
	s.upstreamRoutes = append([]UpstreamRoute(nil), nextState.UpstreamRoutes...)
	s.bundlePaths = append([]string{}, bundlePaths...)
	s.bundleRoles = append([]string{}, parsedRuntime.BundleRoles...)
	s.execCompatibilityMode = parsedRuntime.ExecCompatibilityMode
	s.credentialBroker = parsedRuntime.CredentialBroker
	s.tenantConfig = parsedRuntime.TenantConfig

	result := ReloadResult{
		Outcome:             "success",
		Trigger:             trigger,
		PolicyBundleHash:    nextState.PolicyBundleHash,
		PolicyBundleSources: append([]string{}, nextState.PolicyBundleSources...),
		RegistryVersion:     upstreamResult.RegistryVersion,
		AddedUpstreams:      append([]string{}, upstreamResult.Added...),
		RemovedUpstreams:    append([]string{}, upstreamResult.Removed...),
	}
	s.recordReloadAudit(result)
	return result, nil
}

func (s *Server) reloadFailureResult(trigger string, err error) ReloadResult {
	hash, sources := s.policyMetadata()
	result := ReloadResult{
		Outcome:             "failure",
		Trigger:             trigger,
		PolicyBundleHash:    hash,
		PolicyBundleSources: sources,
		RegistryVersion:     0,
		Error:               stableMCPReloadError(err),
	}
	if s != nil && s.upstream != nil {
		result.RegistryVersion = s.upstream.registryVersionSnapshot()
	}
	return result
}

func stableMCPReloadError(err error) string {
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}

func (s *Server) recordReloadAudit(result ReloadResult) {
	if s == nil || s.service == nil {
		return
	}
	metadata := map[string]any{
		"trigger":          result.Trigger,
		"outcome":          result.Outcome,
		"registry_version": result.RegistryVersion,
	}
	if len(result.AddedUpstreams) > 0 {
		metadata["added_upstreams"] = append([]string{}, result.AddedUpstreams...)
	}
	if len(result.RemovedUpstreams) > 0 {
		metadata["removed_upstreams"] = append([]string{}, result.RemovedUpstreams...)
	}
	if result.Error != "" {
		metadata["error"] = result.Error
	}
	_ = s.service.RecordAuditEvent(audit.Event{
		SchemaVersion:       "v1",
		Timestamp:           time.Now().UTC(),
		EventType:           "runtime.reload",
		TraceID:             "runtime.reload",
		PolicyBundleHash:    result.PolicyBundleHash,
		PolicyBundleSources: append([]string{}, result.PolicyBundleSources...),
		Decision:            strings.ToUpper(result.Outcome),
		Reason:              result.Error,
		ExecutorMetadata:    metadata,
		AssuranceLevel:      s.assuranceLevel,
	})
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	if s.ownsResources && s.upstream != nil {
		s.upstream.close()
		s.upstream = nil
	}
	if !s.ownsResources || s.approvals == nil {
		return nil
	}
	err := s.approvals.Close()
	s.approvals = nil
	return err
}

func (s *Server) ServeStdio(in io.Reader, out io.Writer) error {
	session := newDownstreamSession(s, in, out)
	return session.serve()
}

type stdioMode string

const (
	stdioModeLine   stdioMode = "line"
	stdioModeFramed stdioMode = "framed"
)

func readStdioPayload(reader *bufio.Reader) ([]byte, stdioMode, error) {
	for {
		peek, err := reader.Peek(1)
		if err != nil {
			return nil, "", err
		}
		if len(peek) == 0 {
			continue
		}
		switch peek[0] {
		case '\r', '\n', ' ', '\t':
			if _, err := reader.ReadByte(); err != nil {
				return nil, "", err
			}
			continue
		case '{', '[':
			line, err := reader.ReadBytes('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, "", err
			}
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				if errors.Is(err, io.EOF) {
					return nil, "", io.EOF
				}
				continue
			}
			return line, stdioModeLine, nil
		default:
			payload, err := readFramedPayload(reader)
			return payload, stdioModeFramed, err
		}
	}
}

func (s *Server) handleLinePayload(line []byte) any {
	if isRPCPayload(line) {
		resp := s.handleRPCPayload(line)
		if resp == nil {
			return nil
		}
		return resp
	}
	return s.handleLegacyLine(line)
}

func (s *Server) handleLegacyLine(line []byte) Response {
	var req Request
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.logger.Debug("invalid MCP legacy request payload")
		return Response{ID: "", Error: "invalid_request"}
	}
	s.logger.Debug("handling MCP legacy request")
	return s.handleRequest(req)
}

func isRPCPayload(payload []byte) bool {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return false
	}
	_, ok := envelope["jsonrpc"]
	return ok
}

func (s *Server) handleRPCPayload(payload []byte) *rpcResponse {
	var req rpcRequest
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return &rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}}
	}
	return s.handleRPCRequest(req, nil)
}

func (s *Server) handleRPCRequest(req rpcRequest, session *downstreamSession) *rpcResponse {
	if req.Ctx == nil {
		req.Ctx = context.Background()
	}
	if req.Method == "" {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32600, Message: "invalid request"}}
	}
	switch req.Method {
	case "initialize":
		if session != nil {
			session.clientSampling = downstreamClientSupportsSampling(req.Params)
		}
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      parseRPCID(req.ID),
			Result: map[string]any{
				"protocolVersion": SupportedProtocolVersion,
				"capabilities": map[string]any{
					"tools": map[string]any{
						"listChanged": false,
					},
					"resources": map[string]any{
						"listChanged": false,
					},
					"prompts": map[string]any{
						"listChanged": false,
					},
					"completions": map[string]any{},
				},
				"serverInfo": map[string]any{
					"name":    "nomos",
					"version": version.Current().Version,
				},
			},
		}
	case "notifications/initialized":
		return nil
	case "ping":
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      parseRPCID(req.ID),
			Result:  map[string]any{},
		}
	case "tools/list":
		tools, summary := s.toolsListForSessionWithSummary(session)
		s.recordToolDiscoveryAudit(req, session, summary)
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      parseRPCID(req.ID),
			Result: map[string]any{
				"tools": tools,
			},
		}
	case "tools/call":
		content, err := s.handleToolsCall(req, session)
		if err != nil {
			return &rpcResponse{
				JSONRPC: "2.0",
				ID:      parseRPCID(req.ID),
				Result: map[string]any{
					"content": []map[string]string{{"type": "text", "text": err.Error()}},
					"isError": true,
				},
			}
		}
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      parseRPCID(req.ID),
			Result: map[string]any{
				"content": content,
				"isError": false,
			},
		}
	case "resources/list":
		return s.handleResourcesListRPC(req, session)
	case "resources/read":
		return s.handleResourcesReadRPC(req, session)
	case "prompts/list":
		return s.handlePromptsListRPC(req, session)
	case "prompts/get":
		return s.handlePromptsGetRPC(req, session)
	case "completion/complete":
		return s.handleCompletionRPC(req, session)
	default:
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32601, Message: "method not found"}}
	}
}

func (s *Server) handleToolsCall(req rpcRequest, session *downstreamSession) ([]map[string]any, error) {
	name, args, err := parseToolCallParams(req.Params)
	if err != nil {
		return nil, errors.New("invalid params")
	}
	if session != nil && s.isForwardedTool(canonicalToolName(name)) {
		resp := s.handleForwardedToolWithSession(Request{
			ID:     rpcIDKey(parseRPCID(req.ID)),
			Method: canonicalToolName(name),
			Params: args,
			Ctx:    req.Ctx,
		}, session)
		if resp.Error != "" {
			return nil, errors.New(toolErrorMessage(canonicalToolName(name), resp.Error))
		}
		return formatToolResultContent(canonicalToolName(name), resp.Result)
	}
	if len(args) == 0 {
		args = []byte(`{}`)
	}
	legacyReq := Request{
		ID:     rpcIDKey(parseRPCID(req.ID)),
		Method: canonicalToolName(name),
		Params: args,
		Ctx:    req.Ctx,
	}
	legacyResp := s.handleRequestWithSession(legacyReq, session)
	if legacyResp.Error != "" {
		return nil, errors.New(toolErrorMessage(canonicalToolName(name), legacyResp.Error))
	}
	return formatToolResultContent(canonicalToolName(name), legacyResp.Result)
}

func parseToolCallParams(raw json.RawMessage) (string, json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", nil, errors.New("invalid params")
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", nil, err
	}
	var name string
	if rawName, ok := payload["name"]; ok {
		if err := json.Unmarshal(rawName, &name); err != nil {
			return "", nil, err
		}
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", nil, errors.New("invalid params")
	}
	if args, ok := payload["arguments"]; ok && len(bytes.TrimSpace(args)) > 0 {
		return name, args, nil
	}
	if args, ok := payload["input"]; ok && len(bytes.TrimSpace(args)) > 0 {
		return name, args, nil
	}
	return name, []byte(`{}`), nil
}

func readFramedPayload(reader *bufio.Reader) ([]byte, error) {
	headers := map[string]string{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return nil, errors.New("invalid framed header")
		}
		headers[strings.ToLower(strings.TrimSpace(parts[0]))] = strings.TrimSpace(parts[1])
	}
	lengthRaw := headers["content-length"]
	if lengthRaw == "" {
		return nil, errors.New("missing content-length")
	}
	n, err := strconv.Atoi(lengthRaw)
	if err != nil || n < 0 || n > (4*1024*1024) {
		return nil, errors.New("invalid content-length")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return body, nil
}

func writeFramedPayload(writer *bufio.Writer, payload *rpcResponse) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Content-Length: %d\r\n\r\n", len(data)); err != nil {
		return err
	}
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Flush()
}

func writeJSONLine(writer *bufio.Writer, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := writer.Write(data); err != nil {
		return err
	}
	if err := writer.WriteByte('\n'); err != nil {
		return err
	}
	return writer.Flush()
}

func parseRPCID(raw json.RawMessage) interface{} {
	if len(raw) == 0 {
		return nil
	}
	var decoded interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil
	}
	return decoded
}

func (s *Server) handleRequest(req Request) Response {
	return s.handleRequestWithSession(req, nil)
}

func (s *Server) identityForSession(session *downstreamSession) identity.VerifiedIdentity {
	if session == nil {
		return s.identity
	}
	return session.actionIdentity()
}

func (s *Server) handleRequestWithSession(req Request, session *downstreamSession) Response {
	req.Method = canonicalToolName(req.Method)
	if req.Method != "nomos.fs_read" {
		switch req.Method {
		case "nomos.capabilities":
			return s.handleCapabilities(req, session)
		case "nomos.fs_write":
			return s.handleFSWrite(req, session)
		case "nomos.apply_patch":
			return s.handleApplyPatch(req, session)
		case "nomos.exec":
			return s.handleExec(req, session)
		case "nomos.http_request":
			return s.handleHTTPRequest(req, session)
		case "repo.validate_change_set":
			return s.handleValidateChangeSet(req, session)
		default:
			if s.isForwardedTool(req.Method) {
				return s.handleForwardedToolWithSession(req, session)
			}
			return Response{ID: req.ID, Error: "method_not_found"}
		}
	}
	var params fsReadParams
	dec := json.NewDecoder(bytes.NewReader(req.Params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil || params.Resource == "" {
		return Response{ID: req.ID, Error: "invalid_params"}
	}
	resource, err := adaptMCPFileResource(params.Resource)
	if err != nil {
		return Response{ID: req.ID, Error: classifyToolError(err)}
	}
	id := s.identityForSession(session)
	actionReq := action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_" + req.ID,
		ActionType:    "fs.read",
		Resource:      resource,
		Params:        []byte(`{}`),
		TraceID:       "mcp_" + req.ID,
		Context:       action.Context{Extensions: buildActionExtensionsForSession(params.ApprovalID, session)},
	}
	act, err := action.ToAction(actionReq, id)
	if err != nil {
		return Response{ID: req.ID, Error: "validation_error"}
	}
	resp, err := s.service.Process(act)
	if err != nil {
		return Response{ID: req.ID, Error: classifyToolError(err)}
	}
	return Response{ID: req.ID, Result: resp}
}

func (s *Server) isForwardedTool(name string) bool {
	if s == nil || s.upstream == nil {
		return false
	}
	_, ok := s.upstream.toolByName(name)
	return ok
}

func (s *Server) handleForwardedTool(req Request) Response {
	return s.handleForwardedToolWithSession(req, nil)
}

func (s *Server) handleForwardedToolWithSession(req Request, session *downstreamSession) Response {
	if s.upstream == nil {
		return Response{ID: req.ID, Error: "method_not_found"}
	}
	ctx := req.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	tool, ok := s.upstream.toolByName(req.Method)
	if !ok {
		return Response{ID: req.ID, Error: "method_not_found"}
	}
	id := s.identityForSession(session)
	if !s.upstreamVisibleForIdentity(id, tool.ServerName) {
		return Response{ID: req.ID, Error: "method_not_found"}
	}
	args := bytes.TrimSpace(req.Params)
	if len(args) == 0 {
		args = []byte(`{}`)
	}
	var check map[string]any
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&check); err != nil {
		return Response{ID: req.ID, Error: "invalid_params"}
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Response{ID: req.ID, Error: "invalid_params"}
	}
	approvalID := extractForwardedApprovalID(check)
	delete(check, "approval_id")
	sanitizedArgs := mustJSONBytes(check)
	validatedArgs, err := validateUpstreamToolArguments(tool, sanitizedArgs)
	if err != nil {
		return Response{ID: req.ID, Error: upstreamArgumentValidationError}
	}
	actionReq := action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_" + req.ID,
		ActionType:    "mcp.call",
		Resource:      "mcp://" + tool.ServerName + "/" + tool.ToolName,
		Params: mustJSONBytes(map[string]any{
			"upstream_server":       tool.ServerName,
			"upstream_tool":         tool.ToolName,
			"tool_arguments":        validatedArgs.CanonicalValue,
			"tool_arguments_hash":   validatedArgs.Hash,
			"tool_schema_validated": len(tool.InputSchema) > 0,
		}),
		TraceID: "mcp_" + req.ID,
	}
	actionReq.Context = action.Context{Extensions: buildActionExtensionsForSessionWithMetadata(approvalID, session, s.upstream.envMetadata(tool.ServerName))}
	act, err := action.ToAction(actionReq, id)
	if err != nil {
		return Response{ID: req.ID, Error: "validation_error"}
	}
	resp, err := s.service.Process(act)
	if err != nil {
		return Response{ID: req.ID, Error: classifyToolError(err)}
	}
	if resp.Decision != policy.DecisionAllow {
		return Response{ID: req.ID, Result: resp}
	}
	output, err := s.upstream.callToolWithRequests(ctx, tool.ServerName, tool.ToolName, validatedArgs.ForwardBytes, s.newUpstreamRequestHandler(session, tool.ServerName, approvalID))
	if err != nil {
		return Response{ID: req.ID, Error: classifyForwardedToolError(err)}
	}
	resp.ExecutionMode = "mcp_forwarded"
	resp.ReportPath = ""
	governed := s.governForwardedContent(output, resp.Obligations, actionReq, tool, id)
	if governed.Denied {
		return Response{ID: req.ID, Error: responseScanDeniedError}
	}
	resp.Output = governed.Text
	resp.Truncated = governed.Truncated
	if len(governed.Blocks) > 0 {
		resp.MCPContentBlocks = governed.Blocks
	}
	resp.Obligations = nil
	s.recordMCPContentBlocks(actionReq, tool, resp, governed, id)
	return Response{ID: req.ID, Result: resp}
}

func (s *Server) handleFSWrite(req Request, session *downstreamSession) Response {
	id := s.identityForSession(session)
	if !s.toolEnabledForIdentity("nomos.fs_write", id) {
		return Response{ID: req.ID, Error: "denied_policy"}
	}
	var params fsWriteParams
	dec := json.NewDecoder(bytes.NewReader(req.Params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil || params.Resource == "" || params.Content == "" {
		return Response{ID: req.ID, Error: "invalid_params"}
	}
	resource, err := adaptMCPFileResource(params.Resource)
	if err != nil {
		return Response{ID: req.ID, Error: classifyToolError(err)}
	}
	actionReq := action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_" + req.ID,
		ActionType:    "fs.write",
		Resource:      resource,
		Params:        mustJSONBytes(map[string]string{"content": params.Content}),
		TraceID:       "mcp_" + req.ID,
		Context:       action.Context{Extensions: buildActionExtensionsForSession(params.ApprovalID, session)},
	}
	act, err := action.ToAction(actionReq, id)
	if err != nil {
		return Response{ID: req.ID, Error: "validation_error"}
	}
	resp, err := s.service.Process(act)
	if err != nil {
		return Response{ID: req.ID, Error: classifyToolError(err)}
	}
	return Response{ID: req.ID, Result: resp}
}

func (s *Server) handleApplyPatch(req Request, session *downstreamSession) Response {
	id := s.identityForSession(session)
	if !s.toolEnabledForIdentity("nomos.apply_patch", id) {
		return Response{ID: req.ID, Error: "denied_policy"}
	}
	var params patchParams
	dec := json.NewDecoder(bytes.NewReader(req.Params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil || params.Path == "" || params.Content == "" {
		return Response{ID: req.ID, Error: "invalid_params"}
	}
	actionReq := action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_" + req.ID,
		ActionType:    "repo.apply_patch",
		Resource:      "repo://local/workspace",
		Params:        mustJSONBytes(map[string]string{"path": params.Path, "content": params.Content}),
		TraceID:       "mcp_" + req.ID,
		Context:       action.Context{Extensions: buildActionExtensionsForSession(params.ApprovalID, session)},
	}
	act, err := action.ToAction(actionReq, id)
	if err != nil {
		return Response{ID: req.ID, Error: "validation_error"}
	}
	resp, err := s.service.Process(act)
	if err != nil {
		return Response{ID: req.ID, Error: classifyToolError(err)}
	}
	return Response{ID: req.ID, Result: resp}
}

func (s *Server) handleExec(req Request, session *downstreamSession) Response {
	id := s.identityForSession(session)
	if !s.toolEnabledForIdentity("nomos.exec", id) {
		return Response{ID: req.ID, Error: "denied_policy"}
	}
	var params execParams
	dec := json.NewDecoder(bytes.NewReader(req.Params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil || len(params.Argv) == 0 {
		return Response{ID: req.ID, Error: "invalid_params"}
	}
	actionReq := action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_" + req.ID,
		ActionType:    "process.exec",
		Resource:      "file://workspace/",
		Params: mustJSONBytes(map[string]any{
			"argv":               params.Argv,
			"cwd":                params.Cwd,
			"env_allowlist_keys": params.EnvAllowlistKeys,
		}),
		TraceID: "mcp_" + req.ID,
		Context: action.Context{Extensions: buildActionExtensionsForSession(params.ApprovalID, session)},
	}
	act, err := action.ToAction(actionReq, id)
	if err != nil {
		return Response{ID: req.ID, Error: "validation_error"}
	}
	resp, err := s.service.Process(act)
	if err != nil {
		return Response{ID: req.ID, Error: classifyToolError(err)}
	}
	return Response{ID: req.ID, Result: resp}
}

func (s *Server) handleHTTPRequest(req Request, session *downstreamSession) Response {
	id := s.identityForSession(session)
	if !s.toolEnabledForIdentity("nomos.http_request", id) {
		return Response{ID: req.ID, Error: "denied_policy"}
	}
	var params httpParams
	dec := json.NewDecoder(bytes.NewReader(req.Params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil || params.Resource == "" {
		return Response{ID: req.ID, Error: "invalid_params"}
	}
	if err := validateUpstreamRoute(s.currentUpstreamRoutes(), params.Resource, params.Method); err != nil {
		return Response{ID: req.ID, Error: "validation_error"}
	}
	actionReq := action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_" + req.ID,
		ActionType:    "net.http_request",
		Resource:      params.Resource,
		Params:        mustJSONBytes(map[string]any{"method": params.Method, "body": params.Body, "headers": params.Header}),
		TraceID:       "mcp_" + req.ID,
		Context:       action.Context{Extensions: buildActionExtensionsForSession(params.ApprovalID, session)},
	}
	act, err := action.ToAction(actionReq, id)
	if err != nil {
		return Response{ID: req.ID, Error: "validation_error"}
	}
	resp, err := s.service.Process(act)
	if err != nil {
		return Response{ID: req.ID, Error: classifyToolError(err)}
	}
	return Response{ID: req.ID, Result: resp}
}

func (s *Server) handleCapabilities(req Request, sessions ...*downstreamSession) Response {
	var session *downstreamSession
	if len(sessions) > 0 {
		session = sessions[0]
	}
	id := s.identityForSession(session)
	toolStates := s.service.ToolCapabilities(id)
	result := service.CapabilityEnvelopeFromToolStates(toolStates)
	networkMode := "deny"
	if capability, ok := toolStates["nomos.http_request"]; ok && capability.State != service.ToolStateUnavailable {
		networkMode = "allowlist"
	}
	sandboxModes := []string{"none"}
	if s.sandboxEnabled {
		sandboxModes = []string{"sandboxed"}
	}
	result.SandboxModes = sandboxModes
	result.NetworkMode = networkMode
	result.OutputMaxBytes = s.outputMaxBytes
	result.OutputMaxLines = s.outputMaxLines
	result.ApprovalsEnabled = s.approvalsEnabled
	result.AssuranceLevel = s.assuranceLevel
	result.TenantID, _ = s.tenantIDForIdentity(id)
	result.MediationNotice = capabilityMediationNotice(s.assuranceLevel)
	resourceCapability := s.service.ActionCapability("mcp.resource_read", id)
	promptCapability := s.service.ActionCapability("mcp.prompt_get", id)
	completionCapability := s.service.ActionCapability("mcp.completion", id)
	samplingCapability := s.service.ActionCapability("mcp.sample", id)
	result.MCPSurfaces = map[string]service.ToolCapability{
		"resource_read": resourceCapability,
		"prompt_get":    promptCapability,
		"completion":    completionCapability,
		"sample":        samplingCapability,
	}
	if s.upstream != nil && s.upstream.hasTools() {
		toolsSnapshot := s.upstream.snapshotTools()
		forwarded := make([]map[string]any, 0, len(toolsSnapshot))
		for _, tool := range toolsSnapshot {
			if !s.upstreamVisibleForIdentity(id, tool.ServerName) {
				continue
			}
			forwarded = append(forwarded, map[string]any{
				"name":            tool.DownstreamName,
				"upstream_server": tool.ServerName,
				"upstream_tool":   tool.ToolName,
				"action_type":     "mcp.call",
				"resource":        "mcp://" + tool.ServerName + "/" + tool.ToolName,
			})
		}
		result.ForwardedTools = forwarded
	}
	policyBundleHash, _ := s.policyMetadataForIdentity(id)
	result = service.FinalizeCapabilityEnvelope(result, id, policyBundleHash)
	return Response{ID: req.ID, Result: result}
}

func (s *Server) handleValidateChangeSet(req Request, sessions ...*downstreamSession) Response {
	var session *downstreamSession
	if len(sessions) > 0 {
		session = sessions[0]
	}
	id := s.identityForSession(session)
	var params changeSetParams
	dec := json.NewDecoder(bytes.NewReader(req.Params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil || len(params.Paths) == 0 {
		return Response{ID: req.ID, Error: "invalid_params"}
	}
	allowed, blocked, err := s.service.ValidateChangeSet(id, params.Paths)
	if err != nil {
		return Response{ID: req.ID, Error: "validation_error"}
	}
	result := map[string]any{
		"allowed": allowed,
		"blocked": blocked,
	}
	return Response{ID: req.ID, Result: result}
}

func (s *Server) toolEnabled(tool string) bool {
	return s.toolEnabledForIdentity(tool, s.identity)
}

func (s *Server) toolEnabledForIdentity(tool string, id identity.VerifiedIdentity) bool {
	capabilities := s.service.ToolCapabilities(id)
	capability, ok := capabilities[tool]
	if !ok {
		return false
	}
	return capability.State != service.ToolStateUnavailable
}

func RunStdio(bundlePath string, identity identity.VerifiedIdentity, workspaceRoot string, maxBytes, maxLines int, approvalsEnabled bool, sandboxEnabled bool, sandboxProfile string) error {
	return RunStdioWithRuntimeOptions(bundlePath, identity, workspaceRoot, maxBytes, maxLines, approvalsEnabled, sandboxEnabled, sandboxProfile, RuntimeOptions{})
}

func RunStdioWithRuntimeOptions(bundlePath string, identity identity.VerifiedIdentity, workspaceRoot string, maxBytes, maxLines int, approvalsEnabled bool, sandboxEnabled bool, sandboxProfile string, runtimeOptions RuntimeOptions) error {
	return RunStdioWithRuntimeOptionsAndRecorder(bundlePath, identity, workspaceRoot, maxBytes, maxLines, approvalsEnabled, sandboxEnabled, sandboxProfile, runtimeOptions, nil, "")
}

func RunStdioWithRuntimeOptionsAndRecorder(bundlePath string, identity identity.VerifiedIdentity, workspaceRoot string, maxBytes, maxLines int, approvalsEnabled bool, sandboxEnabled bool, sandboxProfile string, runtimeOptions RuntimeOptions, recorder audit.Recorder, assuranceLevel string) error {
	return RunStdioForBundlesWithRuntimeOptionsAndRecorder([]string{bundlePath}, identity, workspaceRoot, maxBytes, maxLines, approvalsEnabled, sandboxEnabled, sandboxProfile, runtimeOptions, recorder, assuranceLevel)
}

func RunStdioForBundlesWithRuntimeOptionsAndRecorder(bundlePaths []string, identity identity.VerifiedIdentity, workspaceRoot string, maxBytes, maxLines int, approvalsEnabled bool, sandboxEnabled bool, sandboxProfile string, runtimeOptions RuntimeOptions, recorder audit.Recorder, assuranceLevel string) error {
	server, err := NewServerForBundlesWithRuntimeOptionsAndRecorder(bundlePaths, identity, workspaceRoot, maxBytes, maxLines, approvalsEnabled, sandboxEnabled, sandboxProfile, runtimeOptions, recorder)
	if err != nil {
		return err
	}
	defer func() {
		_ = server.Close()
	}()
	server.SetAssuranceLevel(assuranceLevel)
	return server.ServeStdio(os.Stdin, os.Stdout)
}

func mustJSONBytes(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		return []byte(`{}`)
	}
	return data
}

func (s *Server) recordToolDiscoveryAudit(req rpcRequest, session *downstreamSession, summary toolDiscoverySummary) {
	if s == nil || s.service == nil {
		return
	}
	id := s.identityForSession(session)
	metadata := map[string]any{
		"principal":       id.Principal,
		"evaluated_tools": summary.evaluated,
		"hidden_tools":    summary.hidden,
		"tool_surface":    "tools/list",
	}
	tenantID, _ := s.tenantIDForIdentity(id)
	if tenantID != "" {
		metadata["tenant_id"] = tenantID
	}
	if session != nil {
		for key, value := range session.auditMetadata() {
			metadata[key] = value
		}
	}
	_ = s.service.RecordAuditEvent(audit.Event{
		SchemaVersion:        "v1",
		Timestamp:            time.Now().UTC(),
		EventType:            "mcp.tools_list",
		TraceID:              "mcp_" + rpcIDKey(parseRPCID(req.ID)),
		ActionID:             "mcp_" + rpcIDKey(parseRPCID(req.ID)),
		Principal:            id.Principal,
		Agent:                id.Agent,
		Environment:          id.Environment,
		TenantID:             tenantID,
		ActionType:           "mcp.tools_list",
		Resource:             "mcp://tools/list",
		ResultClassification: "discovery",
		ExecutorMetadata:     metadata,
	})
}

func buildActionExtensionsForSession(approvalID string, session *downstreamSession) map[string]json.RawMessage {
	return buildActionExtensionsForSessionWithMetadata(approvalID, session, nil)
}

func buildActionExtensionsForSessionWithMetadata(approvalID string, session *downstreamSession, extra map[string]any) map[string]json.RawMessage {
	extensions := map[string]json.RawMessage{}
	if strings.TrimSpace(approvalID) != "" {
		extensions["approval"] = mustJSONBytes(map[string]string{"approval_id": strings.TrimSpace(approvalID)})
	}
	metadata := map[string]any{}
	if session != nil {
		for key, value := range session.auditMetadata() {
			metadata[key] = value
		}
	}
	for key, value := range extra {
		metadata[key] = value
	}
	if len(metadata) > 0 {
		extensions["transport"] = mustJSONBytes(metadata)
	}
	return extensions
}

func extractForwardedApprovalID(payload map[string]any) string {
	value, ok := payload["approval_id"]
	if !ok {
		return ""
	}
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func adaptMCPFileResource(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("resource is empty")
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "file://") {
		return trimmed, nil
	}
	if strings.Contains(trimmed, "://") {
		return "", errors.New("resource must be a workspace-relative path or file://workspace/... resource")
	}
	if isAbsoluteHostPath(trimmed) {
		return "", errors.New("absolute host paths are not allowed; use a workspace-relative path or file://workspace/... resource")
	}
	normalized := strings.ReplaceAll(trimmed, "\\", "/")
	for strings.HasPrefix(normalized, "./") {
		normalized = strings.TrimPrefix(normalized, "./")
	}
	if normalized == "" || normalized == "." {
		return "", errors.New("resource is empty")
	}
	return "file://workspace/" + normalized, nil
}

func isAbsoluteHostPath(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false
	}
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "\\") {
		return true
	}
	if len(trimmed) >= 3 && trimmed[1] == ':' {
		drive := trimmed[0]
		if (drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z') {
			return trimmed[2] == '\\' || trimmed[2] == '/'
		}
	}
	return false
}

type noopRecorder struct{}

func (noopRecorder) WriteEvent(_ audit.Event) error { return nil }

func classifyToolError(err error) string {
	if err == nil {
		return ""
	}
	if os.IsNotExist(err) {
		return "not_found"
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(msg, "traversal"),
		strings.Contains(msg, "path escape"),
		strings.Contains(msg, "cwd escape"),
		strings.Contains(msg, "unsupported resource"),
		strings.Contains(msg, "invalid resource uri"),
		strings.Contains(msg, "workspace-relative path"),
		strings.Contains(msg, "absolute host paths"),
		strings.Contains(msg, "encoded separators"),
		strings.Contains(msg, "userinfo is not allowed"),
		strings.Contains(msg, "url host is required"),
		strings.Contains(msg, "secret host is required"),
		strings.Contains(msg, "repo host is required"),
		strings.Contains(msg, "file path is required"),
		strings.Contains(msg, "canonicalization failed"):
		return "normalization_error"
	default:
		return "execution_error"
	}
}

func classifyForwardedToolError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, errUpstreamCredentialUnavailable):
		return "UPSTREAM_CREDENTIAL_UNAVAILABLE"
	case errors.Is(err, errUpstreamUnavailable):
		return "UPSTREAM_UNAVAILABLE"
	case errors.Is(err, errUpstreamClosed):
		return "UPSTREAM_UNAVAILABLE"
	case errors.Is(err, errUpstreamTimeout):
		return "UPSTREAM_TIMEOUT"
	case errors.Is(err, errUpstreamCanceled):
		return "UPSTREAM_CANCELED"
	}
	return "execution_error"
}

func toolErrorMessage(method, code string) string {
	if code != "normalization_error" {
		return code
	}
	switch method {
	case "nomos.fs_read", "nomos.fs_write":
		return "normalization_error: use a workspace-relative path like README.md or src/app.py, or a canonical resource like file://workspace/README.md"
	default:
		return code
	}
}

func forwardedToolDescription(tool upstreamTool) string {
	description := strings.TrimSpace(tool.Description)
	if description == "" {
		description = "Forwarded upstream MCP tool."
	}
	return description + " Governed by Nomos before forwarding to upstream server " + strconv.Quote(tool.ServerName) + "."
}

const responseScanDeniedError = "RESPONSE_SCAN_DENIED"

type forwardedResponseScanResult struct {
	Text            string
	Mode            responsescan.Mode
	RulePackVersion string
	Findings        []responsescan.Finding
	Denied          bool
	Misconfigured   bool
	InputTruncated  bool
	MaxDepth        int
	ResultClass     string
}

func redactAndLimitForwardedOutput(redactor *redact.Redactor, text string, obligations map[string]any) (string, bool) {
	return limitForwardedOutput(redactForwardedOutput(redactor, text), obligations)
}

func redactForwardedOutput(redactor *redact.Redactor, text string) string {
	if redactor == nil {
		redactor = redact.DefaultRedactor()
	}
	return redactor.RedactText(text)
}

func limitForwardedOutput(text string, obligations map[string]any) (string, bool) {
	out := text
	truncated := false
	if maxBytes, ok := forwardedIntObligation(obligations["output_max_bytes"]); ok && maxBytes >= 0 && len(out) > maxBytes {
		out = trimToBytes(out, maxBytes)
		truncated = true
	}
	if maxLines, ok := forwardedIntObligation(obligations["output_max_lines"]); ok && maxLines >= 0 {
		limited, trimmed := trimToLines(out, maxLines)
		out = limited
		if trimmed {
			truncated = true
		}
	}
	return out, truncated
}

func (s *Server) scanForwardedResponse(text string, obligations map[string]any, actionReq action.Request, tool upstreamTool, id identity.VerifiedIdentity) forwardedResponseScanResult {
	mode, ok := responseScanMode(obligations)
	result := forwardedResponseScanResult{
		Text:            text,
		Mode:            mode,
		RulePackVersion: responsescan.RulePackVersion,
	}
	if !ok || s == nil || s.responseScanner == nil {
		result.Denied = true
		result.Misconfigured = true
		result.ResultClass = responseScanDeniedError
		s.recordResponseScan(actionReq, tool, result, id)
		return result
	}
	sanitized, err := s.responseScanner.Sanitize(text, mode)
	result.RulePackVersion = sanitized.Result.RulePackVersion
	if result.RulePackVersion == "" {
		result.RulePackVersion = responsescan.RulePackVersion
	}
	result.Findings = sanitized.Result.Findings
	result.InputTruncated = sanitized.Result.InputTruncated
	result.MaxDepth = sanitized.Result.MaxDepth
	result.Text = sanitized.Text
	if err != nil || sanitized.Denied {
		result.Denied = true
		result.ResultClass = responseScanDeniedError
		s.recordResponseScan(actionReq, tool, result, id)
		s.emitResponseScanTelemetry(actionReq.TraceID, mode, result.RulePackVersion, result.Findings)
		return result
	}
	if len(result.Findings) > 0 {
		result.ResultClass = "RESPONSE_SCAN_SANITIZED"
		s.recordResponseScan(actionReq, tool, result, id)
		s.emitResponseScanTelemetry(actionReq.TraceID, mode, result.RulePackVersion, result.Findings)
		return result
	}
	if result.InputTruncated {
		result.ResultClass = "RESPONSE_SCAN_PARTIAL"
		s.recordResponseScan(actionReq, tool, result, id)
	}
	return result
}

func responseScanMode(obligations map[string]any) (responsescan.Mode, bool) {
	if obligations == nil {
		return responsescan.NormalizeMode(nil)
	}
	value, exists := obligations["response_scan_mode"]
	if !exists {
		return responsescan.NormalizeMode(nil)
	}
	return responsescan.NormalizeMode(value)
}

func (s *Server) recordResponseScan(actionReq action.Request, tool upstreamTool, result forwardedResponseScanResult, id identity.VerifiedIdentity) {
	if s == nil || s.service == nil {
		return
	}
	metadata := map[string]any{
		"upstream_server":                    tool.ServerName,
		"upstream_tool":                      tool.ToolName,
		"response_scan_mode":                 string(result.Mode),
		"response_scan_rule_pack_version":    result.RulePackVersion,
		"response_scan_finding_count":        len(result.Findings),
		"response_scan_input_truncated":      result.InputTruncated,
		"response_scan_max_depth":            result.MaxDepth,
		"response_scan_misconfigured":        result.Misconfigured,
		"response_scan_downstream_tool_name": tool.DownstreamName,
	}
	if len(result.Findings) > 0 {
		metadata["response_scan_findings"] = auditResponseScanFindings(result.Findings)
	}
	classification := result.ResultClass
	if classification == "" {
		classification = "RESPONSE_SCAN_OK"
	}
	tenantID, _ := s.tenantIDForIdentity(id)
	_ = s.service.RecordAuditEvent(audit.Event{
		SchemaVersion:        "v1",
		Timestamp:            time.Now().UTC(),
		EventType:            "mcp.response_scan",
		TraceID:              actionReq.TraceID,
		ActionID:             actionReq.ActionID,
		Principal:            id.Principal,
		Agent:                id.Agent,
		Environment:          id.Environment,
		TenantID:             tenantID,
		ActionType:           actionReq.ActionType,
		Resource:             actionReq.Resource,
		ResultClassification: classification,
		ExecutorMetadata:     metadata,
	})
}

func auditResponseScanFindings(findings []responsescan.Finding) []map[string]string {
	if len(findings) == 0 {
		return nil
	}
	out := make([]map[string]string, 0, len(findings))
	for _, finding := range findings {
		out = append(out, map[string]string{
			"rule_id":  finding.RuleID,
			"location": finding.Location,
			"severity": finding.Severity,
		})
	}
	return out
}

func (s *Server) emitResponseScanTelemetry(traceID string, mode responsescan.Mode, version string, findings []responsescan.Finding) {
	if s == nil || s.telemetry == nil || !s.telemetry.Enabled() || len(findings) == 0 {
		return
	}
	type aggregate struct {
		count    int64
		severity string
	}
	counts := map[string]aggregate{}
	for _, finding := range findings {
		entry := counts[finding.RuleID]
		entry.count++
		if entry.severity == "" || finding.Severity > entry.severity {
			entry.severity = finding.Severity
		}
		counts[finding.RuleID] = entry
	}
	ruleIDs := make([]string, 0, len(counts))
	for ruleID := range counts {
		ruleIDs = append(ruleIDs, ruleID)
	}
	slices.Sort(ruleIDs)
	for _, ruleID := range ruleIDs {
		entry := counts[ruleID]
		s.telemetry.Metric(telemetry.Metric{
			SignalType: "metric",
			Name:       "nomos.response_scan_findings",
			Kind:       "counter",
			Value:      entry.count,
			TraceID:    traceID,
			Attributes: map[string]string{
				"rule_id":           ruleID,
				"severity":          entry.severity,
				"mode":              string(mode),
				"rule_pack_version": version,
			},
		})
	}
}

func forwardedIntObligation(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return int(parsed), true
	default:
		return 0, false
	}
}

func trimToBytes(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	cut := value[:limit]
	for !utf8.ValidString(cut) && len(cut) > 0 {
		cut = cut[:len(cut)-1]
	}
	return cut
}

func trimToLines(value string, maxLines int) (string, bool) {
	if maxLines <= 0 {
		if value == "" {
			return value, false
		}
		return "", true
	}
	if value == "" {
		return value, false
	}
	lineCount := 0
	for idx, r := range value {
		if lineCount >= maxLines {
			return value[:idx], true
		}
		if r == '\n' {
			lineCount++
		}
	}
	return value, false
}

func validateUpstreamRoute(routes []UpstreamRoute, resource, method string) error {
	if len(routes) == 0 {
		return nil
	}
	normalized, err := normalizeURLResource(resource)
	if err != nil {
		return err
	}
	host, reqPath, err := routeTargetFromNormalized(normalized)
	if err != nil {
		return err
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		method = "GET"
	}
	for _, route := range routes {
		if upstreamRouteMatches(route, host, reqPath, method) {
			return nil
		}
	}
	return errors.New("upstream route not configured")
}

func normalizeURLResource(resource string) (string, error) {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return "", errors.New("resource is empty")
	}
	if !strings.HasPrefix(resource, "url://") {
		return "", errors.New("resource is not url")
	}
	return resource, nil
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

func capabilityMediationNotice(level string) string {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "STRONG":
		return ""
	case "GUARDED":
		return "Guarded mediation. Verify deployment controls before assuming exclusive side-effect mediation."
	case "BEST_EFFORT":
		return "Best-effort mediation only. Built-in or unmanaged tools outside Nomos can bypass policy unless they are disabled."
	default:
		return "No mediation assurance is established for this runtime."
	}
}
