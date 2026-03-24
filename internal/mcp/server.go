package mcp

import (
	"bufio"
	"bytes"
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
	"time"
	"unicode/utf8"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/approval"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/service"
	"github.com/safe-agentic-world/nomos/internal/version"
)

type Server struct {
	service             *service.Service
	approvals           *approval.Store
	identity            identity.VerifiedIdentity
	approvalsEnabled    bool
	sandboxEnabled      bool
	outputMaxBytes      int
	outputMaxLines      int
	policyBundleHash    string
	policyBundleSources []string
	assuranceLevel      string
	upstreamRoutes      []UpstreamRoute
	upstreamRegistry    *upstreamRegistry
	logger              *runtimeLogger
	pid                 int
}

type Request struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
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
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
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
	bundle, err := policy.LoadBundlesWithOptions(bundlePaths, policy.MultiLoadOptions{
		BundleRoles: runtimeOptions.BundleRoles,
	})
	if err != nil {
		return nil, err
	}
	if err := policy.ValidateExecCompatibility(bundle, runtimeOptions.ExecCompatibilityMode); err != nil {
		return nil, err
	}
	logger, err := newRuntimeLogger(runtimeOptions)
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
	if approvalsEnabled && runtimeOptions.ApprovalStorePath != "" {
		ttl := time.Duration(runtimeOptions.ApprovalTTLSeconds) * time.Second
		if ttl <= 0 {
			ttl = 10 * time.Minute
		}
		approvalStore, err = approval.Open(runtimeOptions.ApprovalStorePath, ttl, time.Now)
		if err != nil {
			return nil, err
		}
	}
	svc := service.New(engine, reader, writerExec, patcher, execRunner, httpRunner, recorder, logger.redactor, approvalStore, nil, sandboxProfile, nil)
	svc.SetSandboxEvidence(runtimeOptions.SandboxEvidence, []string{workspaceRoot})
	svc.SetExecCompatibilityMode(runtimeOptions.ExecCompatibilityMode)
	upstreamRegistry, err := loadUpstreamRegistry(runtimeOptions.UpstreamServers)
	if err != nil {
		return nil, err
	}
	return &Server{
		service:             svc,
		approvals:           approvalStore,
		identity:            identity,
		approvalsEnabled:    approvalStore != nil,
		sandboxEnabled:      sandboxEnabled,
		outputMaxBytes:      maxBytes,
		outputMaxLines:      maxLines,
		policyBundleHash:    bundle.Hash,
		policyBundleSources: policy.BundleSourceLabels(bundle),
		assuranceLevel:      "NONE",
		upstreamRoutes:      append([]UpstreamRoute(nil), runtimeOptions.UpstreamRoutes...),
		upstreamRegistry:    upstreamRegistry,
		logger:              logger,
		pid:                 os.Getpid(),
	}, nil
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

func (s *Server) Close() error {
	if s == nil || s.approvals == nil {
		return nil
	}
	err := s.approvals.Close()
	s.approvals = nil
	return err
}

func (s *Server) ServeStdio(in io.Reader, out io.Writer) error {
	reader := bufio.NewReader(in)
	writer := bufio.NewWriter(out)
	defer writer.Flush()
	s.logger.ReadyBanner(s.identity.Environment, s.policyBundleHash, s.policyBundleSources, version.Current().Version, s.pid)
	for {
		payload, mode, readErr := readStdioPayload(reader)
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			s.logger.Error("mcp stdio read failure: " + readErr.Error())
			return readErr
		}
		if mode == stdioModeLine {
			resp := s.handleLinePayload(payload)
			if resp == nil {
				continue
			}
			if writeErr := writeJSONLine(writer, resp); writeErr != nil {
				s.logger.Error("mcp stdio line write failure: " + writeErr.Error())
				return writeErr
			}
			continue
		}
		resp := s.handleRPCPayload(payload)
		if resp == nil {
			continue
		}
		if writeErr := writeFramedPayload(writer, resp); writeErr != nil {
			s.logger.Error("mcp stdio framed write failure: " + writeErr.Error())
			return writeErr
		}
	}
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
	if req.Method == "" {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32600, Message: "invalid request"}}
	}
	switch req.Method {
	case "initialize":
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      parseRPCID(req.ID),
			Result: map[string]any{
				"protocolVersion": SupportedProtocolVersion,
				"capabilities": map[string]any{
					"tools": map[string]any{
						"listChanged": false,
					},
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
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      parseRPCID(req.ID),
			Result: map[string]any{
				"tools": s.toolsList(),
			},
		}
	case "tools/call":
		resp, err := s.handleToolsCall(req)
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
				"content": []map[string]string{{"type": "text", "text": resp}},
				"isError": false,
			},
		}
	default:
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32601, Message: "method not found"}}
	}
}

func (s *Server) handleToolsCall(req rpcRequest) (string, error) {
	name, args, err := parseToolCallParams(req.Params)
	if err != nil {
		return "", errors.New("invalid params")
	}
	if len(args) == 0 {
		args = []byte(`{}`)
	}
	legacyReq := Request{
		ID:     string(req.ID),
		Method: canonicalToolName(name),
		Params: args,
	}
	legacyResp := s.handleRequest(legacyReq)
	if legacyResp.Error != "" {
		return "", errors.New(toolErrorMessage(canonicalToolName(name), legacyResp.Error))
	}
	return formatToolResult(canonicalToolName(name), legacyResp.Result)
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

func (s *Server) toolsList() []map[string]any {
	tools := []map[string]any{
		{"name": advertisedToolName("nomos.capabilities"), "description": "Return the policy-derived capability contract for this session", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}},
		{"name": advertisedToolName("nomos.fs_read"), "description": "Read a workspace file. Use a workspace-relative path like README.md or a canonical file://workspace/... resource. Check nomos.capabilities for current allow versus approval state.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"resource": map[string]any{"type": "string"}, "approval_id": map[string]any{"type": "string"}}, "required": []string{"resource"}, "additionalProperties": false}},
		{"name": advertisedToolName("nomos.fs_write"), "description": "Write a workspace file. Use a workspace-relative path like notes.txt or a canonical file://workspace/... resource. Check nomos.capabilities for current allow versus approval state.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"resource": map[string]any{"type": "string"}, "content": map[string]any{"type": "string"}, "approval_id": map[string]any{"type": "string"}}, "required": []string{"resource", "content"}, "additionalProperties": false}},
		{"name": advertisedToolName("nomos.apply_patch"), "description": "Apply deterministic patch payload. Check nomos.capabilities for current allow versus approval state.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}, "content": map[string]any{"type": "string"}, "approval_id": map[string]any{"type": "string"}}, "required": []string{"path", "content"}, "additionalProperties": false}},
		{"name": advertisedToolName("nomos.exec"), "description": "Run a bounded process action. Check nomos.capabilities for current allow versus approval state.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"argv": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "cwd": map[string]any{"type": "string"}, "env_allowlist_keys": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "approval_id": map[string]any{"type": "string"}}, "required": []string{"argv"}, "additionalProperties": false}},
		{"name": advertisedToolName("nomos.http_request"), "description": "Run a policy-gated HTTP request. Check nomos.capabilities for current allow versus approval state.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"resource": map[string]any{"type": "string"}, "method": map[string]any{"type": "string"}, "body": map[string]any{"type": "string"}, "headers": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}}, "approval_id": map[string]any{"type": "string"}}, "required": []string{"resource"}, "additionalProperties": false}},
		{"name": advertisedToolName("repo.validate_change_set"), "description": "Validate changed repo paths against policy before attempting a patch action.", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}, "required": []string{"paths"}, "additionalProperties": false}},
	}
	for _, tool := range s.upstreamRegistry.tools {
		tools = append(tools, map[string]any{
			"name":        tool.DownstreamName,
			"description": forwardedToolDescription(tool),
			"inputSchema": tool.InputSchema,
		})
	}
	return tools
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
	req.Method = canonicalToolName(req.Method)
	if req.Method != "nomos.fs_read" {
		switch req.Method {
		case "nomos.capabilities":
			return s.handleCapabilities(req)
		case "nomos.fs_write":
			return s.handleFSWrite(req)
		case "nomos.apply_patch":
			return s.handleApplyPatch(req)
		case "nomos.exec":
			return s.handleExec(req)
		case "nomos.http_request":
			return s.handleHTTPRequest(req)
		case "repo.validate_change_set":
			return s.handleValidateChangeSet(req)
		default:
			if s.isForwardedTool(req.Method) {
				return s.handleForwardedTool(req)
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
	actionReq := action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_" + req.ID,
		ActionType:    "fs.read",
		Resource:      resource,
		Params:        []byte(`{}`),
		TraceID:       "mcp_" + req.ID,
		Context:       action.Context{Extensions: buildActionExtensions(params.ApprovalID)},
	}
	act, err := action.ToAction(actionReq, s.identity)
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
	if s == nil || s.upstreamRegistry == nil {
		return false
	}
	_, ok := s.upstreamRegistry.toolsByName[name]
	return ok
}

func (s *Server) handleForwardedTool(req Request) Response {
	tool, ok := s.upstreamRegistry.toolsByName[req.Method]
	if !ok {
		return Response{ID: req.ID, Error: "method_not_found"}
	}
	args := bytes.TrimSpace(req.Params)
	if len(args) == 0 {
		args = []byte(`{}`)
	}
	var check map[string]any
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&check); err != nil {
		return Response{ID: req.ID, Error: "invalid_params"}
	}
	approvalID := extractForwardedApprovalID(check)
	delete(check, "approval_id")
	sanitizedArgs := mustJSONBytes(check)
	actionReq := action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_" + req.ID,
		ActionType:    "mcp.call",
		Resource:      "mcp://" + tool.ServerName + "/" + tool.ToolName,
		Params: mustJSONBytes(map[string]any{
			"upstream_server": tool.ServerName,
			"upstream_tool":   tool.ToolName,
			"tool_arguments":  check,
		}),
		TraceID: "mcp_" + req.ID,
		Context: action.Context{Extensions: buildActionExtensions(approvalID)},
	}
	act, err := action.ToAction(actionReq, s.identity)
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
	config := s.upstreamRegistry.serversByName[tool.ServerName]
	output, err := callUpstreamTool(config, tool.ToolName, sanitizedArgs)
	if err != nil {
		return Response{ID: req.ID, Error: "execution_error"}
	}
	resp.ExecutionMode = "mcp_forwarded"
	resp.ReportPath = ""
	resp.Output, resp.Truncated = redactAndLimitForwardedOutput(s.logger.redactor, output, resp.Obligations)
	resp.Obligations = nil
	return Response{ID: req.ID, Result: resp}
}

func (s *Server) handleFSWrite(req Request) Response {
	if !s.toolEnabled("nomos.fs_write") {
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
		Context:       action.Context{Extensions: buildActionExtensions(params.ApprovalID)},
	}
	act, err := action.ToAction(actionReq, s.identity)
	if err != nil {
		return Response{ID: req.ID, Error: "validation_error"}
	}
	resp, err := s.service.Process(act)
	if err != nil {
		return Response{ID: req.ID, Error: classifyToolError(err)}
	}
	return Response{ID: req.ID, Result: resp}
}

func (s *Server) handleApplyPatch(req Request) Response {
	if !s.toolEnabled("nomos.apply_patch") {
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
		Context:       action.Context{Extensions: buildActionExtensions(params.ApprovalID)},
	}
	act, err := action.ToAction(actionReq, s.identity)
	if err != nil {
		return Response{ID: req.ID, Error: "validation_error"}
	}
	resp, err := s.service.Process(act)
	if err != nil {
		return Response{ID: req.ID, Error: classifyToolError(err)}
	}
	return Response{ID: req.ID, Result: resp}
}

func (s *Server) handleExec(req Request) Response {
	if !s.toolEnabled("nomos.exec") {
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
		Context: action.Context{Extensions: buildActionExtensions(params.ApprovalID)},
	}
	act, err := action.ToAction(actionReq, s.identity)
	if err != nil {
		return Response{ID: req.ID, Error: "validation_error"}
	}
	resp, err := s.service.Process(act)
	if err != nil {
		return Response{ID: req.ID, Error: classifyToolError(err)}
	}
	return Response{ID: req.ID, Result: resp}
}

func (s *Server) handleHTTPRequest(req Request) Response {
	if !s.toolEnabled("nomos.http_request") {
		return Response{ID: req.ID, Error: "denied_policy"}
	}
	var params httpParams
	dec := json.NewDecoder(bytes.NewReader(req.Params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil || params.Resource == "" {
		return Response{ID: req.ID, Error: "invalid_params"}
	}
	if err := validateUpstreamRoute(s.upstreamRoutes, params.Resource, params.Method); err != nil {
		return Response{ID: req.ID, Error: "validation_error"}
	}
	actionReq := action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_" + req.ID,
		ActionType:    "net.http_request",
		Resource:      params.Resource,
		Params:        mustJSONBytes(map[string]any{"method": params.Method, "body": params.Body, "headers": params.Header}),
		TraceID:       "mcp_" + req.ID,
		Context:       action.Context{Extensions: buildActionExtensions(params.ApprovalID)},
	}
	act, err := action.ToAction(actionReq, s.identity)
	if err != nil {
		return Response{ID: req.ID, Error: "validation_error"}
	}
	resp, err := s.service.Process(act)
	if err != nil {
		return Response{ID: req.ID, Error: classifyToolError(err)}
	}
	return Response{ID: req.ID, Result: resp}
}

func (s *Server) handleCapabilities(req Request) Response {
	toolStates := s.service.ToolCapabilities(s.identity)
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
	result.MediationNotice = capabilityMediationNotice(s.assuranceLevel)
	result = service.FinalizeCapabilityEnvelope(result, s.identity, s.policyBundleHash)
	if len(s.upstreamRegistry.tools) == 0 {
		return Response{ID: req.ID, Result: result}
	}
	forwarded := make([]map[string]any, 0, len(s.upstreamRegistry.tools))
	for _, tool := range s.upstreamRegistry.tools {
		forwarded = append(forwarded, map[string]any{
			"name":            tool.DownstreamName,
			"upstream_server": tool.ServerName,
			"upstream_tool":   tool.ToolName,
			"action_type":     "mcp.call",
			"resource":        "mcp://" + tool.ServerName + "/" + tool.ToolName,
		})
	}
	return Response{ID: req.ID, Result: map[string]any{
		"contract_version":        result.ContractVersion,
		"capability_set_hash":     result.CapabilitySetHash,
		"advisory_only":           result.AdvisoryOnly,
		"authorization_notice":    result.AuthorizationNotice,
		"enabled_tools":           result.EnabledTools,
		"immediate_tools":         result.ImmediateTools,
		"approval_gated_tools":    result.ApprovalGatedTools,
		"mixed_tools":             result.MixedTools,
		"unavailable_tools":       result.UnavailableTools,
		"advertised_tools":        result.AdvertisedTools,
		"tool_states":             result.ToolStates,
		"tool_advertisement_mode": result.ToolAdvertisementMode,
		"sandbox_modes":           result.SandboxModes,
		"network_mode":            result.NetworkMode,
		"output_max_bytes":        result.OutputMaxBytes,
		"output_max_lines":        result.OutputMaxLines,
		"approvals_enabled":       result.ApprovalsEnabled,
		"assurance_level":         result.AssuranceLevel,
		"mediation_notice":        result.MediationNotice,
		"forwarded_tools":         forwarded,
	}}
}

func (s *Server) handleValidateChangeSet(req Request) Response {
	var params changeSetParams
	dec := json.NewDecoder(bytes.NewReader(req.Params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil || len(params.Paths) == 0 {
		return Response{ID: req.ID, Error: "invalid_params"}
	}
	allowed, blocked, err := s.service.ValidateChangeSet(s.identity, params.Paths)
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
	capabilities := s.service.ToolCapabilities(s.identity)
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

func buildActionExtensions(approvalID string) map[string]json.RawMessage {
	extensions := map[string]json.RawMessage{}
	if strings.TrimSpace(approvalID) == "" {
		return extensions
	}
	extensions["approval"] = mustJSONBytes(map[string]string{"approval_id": strings.TrimSpace(approvalID)})
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

func redactAndLimitForwardedOutput(redactor *redact.Redactor, text string, obligations map[string]any) (string, bool) {
	if redactor == nil {
		redactor = redact.DefaultRedactor()
	}
	out := redactor.RedactText(text)
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
