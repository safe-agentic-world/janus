package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/service"
	"github.com/safe-agentic-world/nomos/internal/version"
)

type Server struct {
	service          *service.Service
	identity         identity.VerifiedIdentity
	approvalsEnabled bool
	sandboxEnabled   bool
	outputMaxBytes   int
	outputMaxLines   int
	policyBundleHash string
	assuranceLevel   string
	logger           *runtimeLogger
	pid              int
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
	Resource string `json:"resource"`
}

type fsWriteParams struct {
	Resource string `json:"resource"`
	Content  string `json:"content"`
}

type execParams struct {
	Argv             []string `json:"argv"`
	Cwd              string   `json:"cwd"`
	EnvAllowlistKeys []string `json:"env_allowlist_keys"`
}

type httpParams struct {
	Resource string            `json:"resource"`
	Method   string            `json:"method"`
	Body     string            `json:"body"`
	Header   map[string]string `json:"headers"`
}

type patchParams struct {
	Path    string `json:"path"`
	Content string `json:"content"`
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
	if identity.Principal == "" || identity.Agent == "" || identity.Environment == "" {
		return nil, errors.New("identity is required")
	}
	bundle, err := policy.LoadBundle(bundlePath)
	if err != nil {
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
	svc := service.New(engine, reader, writerExec, patcher, execRunner, httpRunner, recorder, logger.redactor, nil, nil, sandboxProfile, nil)
	return &Server{
		service:          svc,
		identity:         identity,
		approvalsEnabled: approvalsEnabled,
		sandboxEnabled:   sandboxEnabled,
		outputMaxBytes:   maxBytes,
		outputMaxLines:   maxLines,
		policyBundleHash: bundle.Hash,
		assuranceLevel:   "NONE",
		logger:           logger,
		pid:              os.Getpid(),
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

func (s *Server) ServeStdio(in io.Reader, out io.Writer) error {
	reader := bufio.NewReader(in)
	writer := bufio.NewWriter(out)
	defer writer.Flush()
	s.logger.ReadyBanner(s.identity.Environment, s.policyBundleHash, version.Current().Version, s.pid)
	for {
		peek, err := reader.Peek(1)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			s.logger.Error("mcp stdio read failure: " + err.Error())
			return err
		}
		if len(peek) == 0 {
			continue
		}
		if peek[0] == '{' {
			line, err := reader.ReadBytes('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				s.logger.Error("mcp stdio line read failure: " + err.Error())
				return err
			}
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				if errors.Is(err, io.EOF) {
					return nil
				}
				continue
			}
			resp := s.handleLinePayload(line)
			if writeErr := writeJSONLine(writer, resp); writeErr != nil {
				s.logger.Error("mcp stdio line write failure: " + writeErr.Error())
				return writeErr
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			continue
		}
		payload, readErr := readFramedPayload(reader)
		if readErr != nil {
			s.logger.Error("mcp stdio framed read failure: " + readErr.Error())
			return readErr
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

func (s *Server) handleLinePayload(line []byte) any {
	if isRPCPayload(line) {
		return s.handleRPCPayload(line)
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
					"tools": map[string]any{},
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
		Method: name,
		Params: args,
	}
	legacyResp := s.handleRequest(legacyReq)
	if legacyResp.Error != "" {
		return "", errors.New(legacyResp.Error)
	}
	data, err := json.Marshal(legacyResp.Result)
	if err != nil {
		return "", err
	}
	return string(data), nil
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
	return []map[string]any{
		{"name": "nomos.capabilities", "description": "Return policy-derived capability envelope", "inputSchema": map[string]any{"type": "object", "additionalProperties": false}},
		{"name": "nomos.fs_read", "description": "Read a workspace file", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"resource": map[string]any{"type": "string"}}, "required": []string{"resource"}, "additionalProperties": false}},
		{"name": "nomos.fs_write", "description": "Write a workspace file", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"resource": map[string]any{"type": "string"}, "content": map[string]any{"type": "string"}}, "required": []string{"resource", "content"}, "additionalProperties": false}},
		{"name": "nomos.apply_patch", "description": "Apply deterministic patch payload", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}, "content": map[string]any{"type": "string"}}, "required": []string{"path", "content"}, "additionalProperties": false}},
		{"name": "nomos.exec", "description": "Run a bounded process action", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"argv": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "cwd": map[string]any{"type": "string"}, "env_allowlist_keys": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}, "required": []string{"argv"}, "additionalProperties": false}},
		{"name": "nomos.http_request", "description": "Run a policy-gated HTTP request", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"resource": map[string]any{"type": "string"}, "method": map[string]any{"type": "string"}, "body": map[string]any{"type": "string"}, "headers": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}}}, "required": []string{"resource"}, "additionalProperties": false}},
		{"name": "repo.validate_change_set", "description": "Validate changed repo paths against policy", "inputSchema": map[string]any{"type": "object", "properties": map[string]any{"paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}}, "required": []string{"paths"}, "additionalProperties": false}},
	}
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
			return Response{ID: req.ID, Error: "method_not_found"}
		}
	}
	var params fsReadParams
	dec := json.NewDecoder(bytes.NewReader(req.Params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&params); err != nil || params.Resource == "" {
		return Response{ID: req.ID, Error: "invalid_params"}
	}
	actionReq := action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_" + req.ID,
		ActionType:    "fs.read",
		Resource:      params.Resource,
		Params:        []byte(`{}`),
		TraceID:       "mcp_" + req.ID,
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
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
	actionReq := action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_" + req.ID,
		ActionType:    "fs.write",
		Resource:      params.Resource,
		Params:        mustJSONBytes(map[string]string{"content": params.Content}),
		TraceID:       "mcp_" + req.ID,
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
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
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
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
		Params:        mustJSONBytes(params),
		TraceID:       "mcp_" + req.ID,
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
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
	actionReq := action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_" + req.ID,
		ActionType:    "net.http_request",
		Resource:      params.Resource,
		Params:        mustJSONBytes(map[string]any{"method": params.Method, "body": params.Body, "headers": params.Header}),
		TraceID:       "mcp_" + req.ID,
		Context:       action.Context{Extensions: map[string]json.RawMessage{}},
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
	tools := s.service.EnabledTools(s.identity)
	networkMode := "deny"
	for _, tool := range tools {
		if tool == "nomos.http_request" {
			networkMode = "allowlist"
			break
		}
	}
	sandboxModes := []string{"none"}
	if s.sandboxEnabled {
		sandboxModes = []string{"sandboxed"}
	}
	result := service.CapabilityEnvelope{
		EnabledTools:     tools,
		SandboxModes:     sandboxModes,
		NetworkMode:      networkMode,
		OutputMaxBytes:   s.outputMaxBytes,
		OutputMaxLines:   s.outputMaxLines,
		ApprovalsEnabled: s.approvalsEnabled,
		AssuranceLevel:   s.assuranceLevel,
		MediationNotice:  capabilityMediationNotice(s.assuranceLevel),
	}
	return Response{ID: req.ID, Result: result}
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
	tools := s.service.EnabledTools(s.identity)
	for _, candidate := range tools {
		if candidate == tool {
			return true
		}
	}
	return false
}

func RunStdio(bundlePath string, identity identity.VerifiedIdentity, workspaceRoot string, maxBytes, maxLines int, approvalsEnabled bool, sandboxEnabled bool, sandboxProfile string) error {
	return RunStdioWithRuntimeOptions(bundlePath, identity, workspaceRoot, maxBytes, maxLines, approvalsEnabled, sandboxEnabled, sandboxProfile, RuntimeOptions{})
}

func RunStdioWithRuntimeOptions(bundlePath string, identity identity.VerifiedIdentity, workspaceRoot string, maxBytes, maxLines int, approvalsEnabled bool, sandboxEnabled bool, sandboxProfile string, runtimeOptions RuntimeOptions) error {
	return RunStdioWithRuntimeOptionsAndRecorder(bundlePath, identity, workspaceRoot, maxBytes, maxLines, approvalsEnabled, sandboxEnabled, sandboxProfile, runtimeOptions, nil, "")
}

func RunStdioWithRuntimeOptionsAndRecorder(bundlePath string, identity identity.VerifiedIdentity, workspaceRoot string, maxBytes, maxLines int, approvalsEnabled bool, sandboxEnabled bool, sandboxProfile string, runtimeOptions RuntimeOptions, recorder audit.Recorder, assuranceLevel string) error {
	server, err := NewServerWithRuntimeOptionsAndRecorder(bundlePath, identity, workspaceRoot, maxBytes, maxLines, approvalsEnabled, sandboxEnabled, sandboxProfile, runtimeOptions, recorder)
	if err != nil {
		return err
	}
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
