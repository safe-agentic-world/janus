package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
)

type requestMeta struct {
	ApprovalID string `json:"approval_id,omitempty"`
}

type resourceReadParams struct {
	URI  string      `json:"uri"`
	Meta requestMeta `json:"_meta,omitempty"`
}

type promptGetParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
	Meta      requestMeta    `json:"_meta,omitempty"`
}

type completionParams struct {
	Ref      map[string]any `json:"ref"`
	Argument map[string]any `json:"argument"`
	Context  map[string]any `json:"context,omitempty"`
	Meta     requestMeta    `json:"_meta,omitempty"`
}

type samplingMessageParams struct {
	Meta requestMeta `json:"_meta,omitempty"`
}

func downstreamResourceURI(serverName, upstreamURI string) string {
	return fmt.Sprintf("mcp://%s/resource/%s", strings.ToLower(strings.TrimSpace(serverName)), url.PathEscape(strings.TrimSpace(upstreamURI)))
}

func downstreamPromptName(serverName, promptName string) string {
	return "upstream_prompt_" + sanitizeForwardedNamePart(serverName) + "_" + sanitizeForwardedNamePart(promptName)
}

func parseDownstreamResourceURI(raw string) (string, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", errors.New("invalid resource uri")
	}
	if !strings.EqualFold(parsed.Scheme, "mcp") || strings.TrimSpace(parsed.Host) == "" {
		return "", "", errors.New("invalid resource uri")
	}
	trimmed := strings.TrimPrefix(parsed.EscapedPath(), "/")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 || parts[0] != "resource" {
		return "", "", errors.New("invalid resource uri")
	}
	decoded, err := url.PathUnescape(parts[1])
	if err != nil || strings.TrimSpace(decoded) == "" {
		return "", "", errors.New("invalid resource uri")
	}
	return strings.ToLower(parsed.Host), decoded, nil
}

func (s *Server) processGovernedMCPAction(reqID, actionType, resource string, params any, approvalID string, session *downstreamSession, extraMetadata map[string]any) (action.Response, error) {
	actionReq := action.Request{
		SchemaVersion: "v1",
		ActionID:      "mcp_" + reqID,
		ActionType:    actionType,
		Resource:      resource,
		Params:        mustJSONBytes(params),
		TraceID:       "mcp_" + reqID,
		Context:       action.Context{Extensions: buildActionExtensionsForSessionWithMetadata(approvalID, session, extraMetadata)},
	}
	act, err := action.ToAction(actionReq, s.identity)
	if err != nil {
		return action.Response{}, err
	}
	return s.service.Process(act)
}

func rpcResponseFromActionDecision(id interface{}, resp action.Response) *rpcResponse {
	code := -32000
	message := "denied_policy"
	if resp.Decision == policy.DecisionRequireApproval {
		code = -32001
		message = "approval_required"
	}
	return &rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &rpcError{
			Code:    code,
			Message: message,
			Data: map[string]any{
				"decision":             resp.Decision,
				"reason":               resp.Reason,
				"approval_id":          resp.ApprovalID,
				"approval_fingerprint": resp.ApprovalFingerprint,
				"approval_expires_at":  resp.ApprovalExpiresAt,
				"action_id":            resp.ActionID,
				"trace_id":             resp.TraceID,
			},
		},
	}
}

func redactMCPResult(redactor *redact.Redactor, value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			switch key {
			case "text", "description", "title", "name":
				if text, ok := item.(string); ok {
					out[key] = redactor.RedactText(text)
					continue
				}
			case "values":
				if list, ok := item.([]any); ok {
					redacted := make([]any, 0, len(list))
					for _, entry := range list {
						if text, ok := entry.(string); ok {
							redacted = append(redacted, redactor.RedactText(text))
						} else {
							redacted = append(redacted, redactMCPResult(redactor, entry))
						}
					}
					out[key] = redacted
					continue
				}
			}
			out[key] = redactMCPResult(redactor, item)
		}
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, redactMCPResult(redactor, item))
		}
		return out
	case string:
		return redactor.RedactText(v)
	default:
		return value
	}
}

func decodeRPCParams(raw json.RawMessage, target any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(target)
}

func downstreamClientSupportsSampling(raw json.RawMessage) bool {
	if len(bytes.TrimSpace(raw)) == 0 {
		return false
	}
	var payload map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return false
	}
	caps, _ := payload["capabilities"].(map[string]any)
	if len(caps) == 0 {
		return false
	}
	_, ok := caps["sampling"]
	return ok
}

func (s *Server) handleResourcesListRPC(req rpcRequest) *rpcResponse {
	items := []map[string]any{}
	if s.upstream != nil {
		var err error
		items, err = s.upstream.listResources()
		if err != nil {
			return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32603, Message: err.Error()}}
		}
	}
	return &rpcResponse{
		JSONRPC: "2.0",
		ID:      parseRPCID(req.ID),
		Result: map[string]any{
			"resources": items,
		},
	}
}

func (s *Server) handleResourcesReadRPC(req rpcRequest, session *downstreamSession) *rpcResponse {
	if s.upstream == nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32601, Message: "method not found"}}
	}
	var params resourceReadParams
	if err := decodeRPCParams(req.Params, &params); err != nil || strings.TrimSpace(params.URI) == "" {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32602, Message: "invalid params"}}
	}
	serverName, upstreamURI, err := parseDownstreamResourceURI(params.URI)
	if err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32602, Message: "invalid params"}}
	}
	actionResp, err := s.processGovernedMCPAction(rpcIDKey(parseRPCID(req.ID)), "mcp.resource_read", downstreamResourceActionResource(serverName, upstreamURI), map[string]any{
		"upstream_server": serverName,
		"upstream_uri":    upstreamURI,
	}, params.Meta.ApprovalID, session, s.upstream.envMetadata(serverName))
	if err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32603, Message: err.Error()}}
	}
	if actionResp.Decision != policy.DecisionAllow {
		return rpcResponseFromActionDecision(parseRPCID(req.ID), actionResp)
	}
	result, err := s.upstream.readResourceWithRequests(serverName, upstreamURI, s.newUpstreamRequestHandler(session, serverName, params.Meta.ApprovalID))
	if err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32603, Message: err.Error()}}
	}
	return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Result: redactMCPResult(s.logger.redactor, result)}
}

func (s *Server) handlePromptsListRPC(req rpcRequest) *rpcResponse {
	items := []map[string]any{}
	if s.upstream != nil {
		var err error
		items, err = s.upstream.listPrompts()
		if err != nil {
			return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32603, Message: err.Error()}}
		}
	}
	return &rpcResponse{
		JSONRPC: "2.0",
		ID:      parseRPCID(req.ID),
		Result: map[string]any{
			"prompts": items,
		},
	}
}

func (s *Server) handlePromptsGetRPC(req rpcRequest, session *downstreamSession) *rpcResponse {
	if s.upstream == nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32601, Message: "method not found"}}
	}
	var params promptGetParams
	if err := decodeRPCParams(req.Params, &params); err != nil || strings.TrimSpace(params.Name) == "" {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32602, Message: "invalid params"}}
	}
	serverName, upstreamPrompt, err := s.resolvePromptReference(params.Name)
	if err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32602, Message: "invalid params"}}
	}
	actionResp, err := s.processGovernedMCPAction(rpcIDKey(parseRPCID(req.ID)), "mcp.prompt_get", downstreamPromptActionResource(serverName, upstreamPrompt), map[string]any{
		"upstream_server":  serverName,
		"upstream_prompt":  upstreamPrompt,
		"prompt_arguments": params.Arguments,
	}, params.Meta.ApprovalID, session, s.upstream.envMetadata(serverName))
	if err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32603, Message: err.Error()}}
	}
	if actionResp.Decision != policy.DecisionAllow {
		return rpcResponseFromActionDecision(parseRPCID(req.ID), actionResp)
	}
	result, err := s.upstream.getPromptWithRequests(serverName, upstreamPrompt, params.Arguments, s.newUpstreamRequestHandler(session, serverName, params.Meta.ApprovalID))
	if err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32603, Message: err.Error()}}
	}
	return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Result: redactMCPResult(s.logger.redactor, result)}
}

func (s *Server) handleCompletionRPC(req rpcRequest, session *downstreamSession) *rpcResponse {
	if s.upstream == nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32601, Message: "method not found"}}
	}
	var params completionParams
	if err := decodeRPCParams(req.Params, &params); err != nil || len(params.Ref) == 0 || len(params.Argument) == 0 {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32602, Message: "invalid params"}}
	}
	serverName, upstreamRef, actionResource, err := s.resolveCompletionReference(params.Ref)
	if err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32602, Message: "invalid params"}}
	}
	actionResp, err := s.processGovernedMCPAction(rpcIDKey(parseRPCID(req.ID)), "mcp.completion", actionResource, map[string]any{
		"upstream_server":    serverName,
		"completion_ref":     upstreamRef,
		"completion_arg":     params.Argument,
		"completion_context": params.Context,
	}, params.Meta.ApprovalID, session, s.upstream.envMetadata(serverName))
	if err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32603, Message: err.Error()}}
	}
	if actionResp.Decision != policy.DecisionAllow {
		return rpcResponseFromActionDecision(parseRPCID(req.ID), actionResp)
	}
	result, err := s.upstream.completeWithRequests(serverName, upstreamRef, params.Argument, params.Context, s.newUpstreamRequestHandler(session, serverName, params.Meta.ApprovalID))
	if err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32603, Message: err.Error()}}
	}
	return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Result: redactMCPResult(s.logger.redactor, result)}
}

func (s *Server) resolvePromptReference(downstreamName string) (string, string, error) {
	items, err := s.upstream.listPrompts()
	if err != nil {
		return "", "", err
	}
	for _, item := range items {
		name, _ := item["name"].(string)
		if name != downstreamName {
			continue
		}
		meta, _ := item["_meta"].(map[string]any)
		serverName, _ := meta["upstream_server"].(string)
		upstreamPrompt, _ := meta["upstream_prompt"].(string)
		if serverName != "" && upstreamPrompt != "" {
			return serverName, upstreamPrompt, nil
		}
	}
	return "", "", errors.New("prompt not found")
}

func (s *Server) resolveCompletionReference(ref map[string]any) (string, map[string]any, string, error) {
	refType, _ := ref["type"].(string)
	switch refType {
	case "ref/prompt":
		name, _ := ref["name"].(string)
		serverName, upstreamPrompt, err := s.resolvePromptReference(name)
		if err != nil {
			return "", nil, "", err
		}
		return serverName, map[string]any{"type": refType, "name": upstreamPrompt}, downstreamCompletionActionResource(serverName, "prompt", upstreamPrompt), nil
	case "ref/resource":
		uri, _ := ref["uri"].(string)
		serverName, upstreamURI, err := parseDownstreamResourceURI(uri)
		if err != nil {
			return "", nil, "", err
		}
		return serverName, map[string]any{"type": refType, "uri": upstreamURI}, downstreamCompletionActionResource(serverName, "resource", upstreamURI), nil
	default:
		return "", nil, "", errors.New("unsupported completion ref")
	}
}

func downstreamResourceActionResource(serverName, upstreamURI string) string {
	return fmt.Sprintf("mcp://%s/resource/%s", strings.ToLower(strings.TrimSpace(serverName)), url.PathEscape(strings.TrimSpace(upstreamURI)))
}

func downstreamPromptActionResource(serverName, promptName string) string {
	return fmt.Sprintf("mcp://%s/prompt/%s", strings.ToLower(strings.TrimSpace(serverName)), url.PathEscape(strings.TrimSpace(promptName)))
}

func downstreamCompletionActionResource(serverName, refType, ref string) string {
	composite := "ref/" + sanitizeForwardedNamePart(refType) + "/" + strings.TrimSpace(ref)
	return fmt.Sprintf("mcp://%s/completion/%s", strings.ToLower(strings.TrimSpace(serverName)), url.PathEscape(composite))
}

func downstreamSamplingActionResource(serverName string) string {
	return fmt.Sprintf("mcp://%s/sample", strings.ToLower(strings.TrimSpace(serverName)))
}

func (s *Server) newUpstreamRequestHandler(session *downstreamSession, serverName, approvalID string) upstreamRequestHandler {
	if session == nil {
		return nil
	}
	return func(req rpcRequest) *rpcResponse {
		switch req.Method {
		case "sampling/createMessage":
			return s.handleSamplingRPC(req, session, serverName, approvalID)
		default:
			return &rpcResponse{
				JSONRPC: "2.0",
				ID:      parseRPCID(req.ID),
				Error:   &rpcError{Code: -32601, Message: "method not found"},
			}
		}
	}
}

func (s *Server) handleSamplingRPC(req rpcRequest, session *downstreamSession, serverName, approvalID string) *rpcResponse {
	if session == nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32601, Message: "sampling unavailable"}}
	}
	if !session.clientSampling {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32601, Message: "downstream client does not support sampling"}}
	}
	params, summary, err := samplingGovernanceParams(req.Params, serverName)
	if err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32602, Message: "invalid params"}}
	}
	actionResp, err := s.processGovernedMCPAction(rpcIDKey(parseRPCID(req.ID)), "mcp.sample", downstreamSamplingActionResource(serverName), summary, approvalID, session, s.upstream.envMetadata(serverName))
	if err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32603, Message: err.Error()}}
	}
	if actionResp.Decision != policy.DecisionAllow {
		return rpcResponseFromActionDecision(parseRPCID(req.ID), actionResp)
	}
	resp, err := session.sendRequest("sampling/createMessage", params)
	if err != nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32603, Message: err.Error()}}
	}
	if resp == nil {
		return &rpcResponse{JSONRPC: "2.0", ID: parseRPCID(req.ID), Error: &rpcError{Code: -32603, Message: "downstream sampling returned no response"}}
	}
	resp.JSONRPC = "2.0"
	resp.ID = parseRPCID(req.ID)
	return resp
}

func samplingGovernanceParams(raw json.RawMessage, serverName string) (map[string]any, map[string]any, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil, errors.New("missing params")
	}
	var params map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&params); err != nil {
		return nil, nil, err
	}
	if len(params) == 0 {
		return nil, nil, errors.New("missing params")
	}
	summary := map[string]any{
		"upstream_server": serverName,
		"model_hints":     samplingModelHints(params["modelPreferences"]),
		"max_tokens":      samplingOptionalNumber(params, "maxTokens", "max_tokens"),
		"stop_conditions": samplingStopConditions(params),
		"message_digest":  samplingMessageDigest(params["messages"]),
	}
	return params, summary, nil
}

func samplingModelHints(raw any) []string {
	modelPrefs, _ := raw.(map[string]any)
	rawHints, _ := modelPrefs["hints"].([]any)
	if len(rawHints) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(rawHints))
	for _, hint := range rawHints {
		switch typed := hint.(type) {
		case string:
			typed = strings.TrimSpace(typed)
			if typed != "" {
				out = append(out, typed)
			}
		case map[string]any:
			name, _ := typed["name"].(string)
			name = strings.TrimSpace(name)
			if name != "" {
				out = append(out, name)
			}
		}
	}
	return out
}

func samplingOptionalNumber(params map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := params[key]; ok {
			return value
		}
	}
	return nil
}

func samplingStopConditions(params map[string]any) []string {
	keys := []string{"stopSequences", "stop_sequences", "stop"}
	out := make([]string, 0)
	for _, key := range keys {
		switch typed := params[key].(type) {
		case string:
			typed = strings.TrimSpace(typed)
			if typed != "" {
				out = append(out, typed)
			}
		case []any:
			for _, item := range typed {
				text, _ := item.(string)
				text = strings.TrimSpace(text)
				if text != "" {
					out = append(out, text)
				}
			}
		}
	}
	return out
}

func samplingMessageDigest(messages any) string {
	if messages == nil {
		return ""
	}
	data, err := json.Marshal(messages)
	if err != nil {
		return ""
	}
	canonical, err := canonicaljson.Canonicalize(data)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return fmt.Sprintf("%x", sum[:])
}
