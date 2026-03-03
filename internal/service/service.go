package service

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/approval"
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/credentials"
	"github.com/safe-agentic-world/nomos/internal/executor"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
	"github.com/safe-agentic-world/nomos/internal/redact"
	"github.com/safe-agentic-world/nomos/internal/sandbox"
)

type Service struct {
	policy         *policy.Engine
	fsReader       *executor.FSReader
	fsWriter       *executor.FSWriter
	patcher        *executor.PatchApplier
	execRunner     *executor.ExecRunner
	httpRunner     *executor.HTTPRunner
	recorder       audit.Recorder
	redactor       *redact.Redactor
	approvals      ApprovalStore
	credentials    CredentialBroker
	sandboxProfile string
	assuranceLevel string
	now            func() time.Time
}

type ApprovalStore interface {
	CreateOrGetPending(ctx context.Context, req approval.PendingRequest) (approval.Record, error)
	CheckApproved(ctx context.Context, approvalID, fingerprint, classKey string) (bool, approval.Record, error)
}

type CredentialBroker interface {
	Checkout(secretID, principal, agent, environment, traceID string) (credentials.Lease, error)
	MaterializeEnv(leaseIDs []string, envAllowlist []string, principal, agent, environment, traceID string) (map[string]string, []string, error)
}

func New(policyEngine *policy.Engine, fsReader *executor.FSReader, fsWriter *executor.FSWriter, patcher *executor.PatchApplier, execRunner *executor.ExecRunner, httpRunner *executor.HTTPRunner, recorder audit.Recorder, redactor *redact.Redactor, approvals ApprovalStore, credentialBroker CredentialBroker, sandboxProfile string, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{
		policy:         policyEngine,
		fsReader:       fsReader,
		fsWriter:       fsWriter,
		patcher:        patcher,
		execRunner:     execRunner,
		httpRunner:     httpRunner,
		recorder:       recorder,
		redactor:       redactor,
		approvals:      approvals,
		credentials:    credentialBroker,
		sandboxProfile: sandboxProfile,
		assuranceLevel: "NONE",
		now:            now,
	}
}

func (s *Service) SetAssuranceLevel(level string) {
	if s == nil {
		return
	}
	level = strings.TrimSpace(level)
	if level == "" {
		level = "NONE"
	}
	s.assuranceLevel = level
}

func (s *Service) Process(actionInput action.Action) (action.Response, error) {
	if s.policy == nil || s.recorder == nil || s.redactor == nil {
		return action.Response{}, errors.New("service not initialized")
	}
	started := s.now().UTC()
	auditCtx := auditContext{
		resultClass:        resultInternalError,
		retryable:          true,
		riskLevel:          "low",
		riskFlags:          []string{},
		sandboxMode:        "none",
		networkMode:        "deny",
		credentialLeaseIDs: []string{},
		fallbackAction:     actionInput,
		fallbackTraceID:    actionInput.TraceID,
		fallbackActionID:   actionInput.ActionID,
		fallbackPrincipal:  actionInput.Principal,
		fallbackAgent:      actionInput.Agent,
		fallbackEnv:        actionInput.Environment,
		actionSummary:      actionSummary(actionInput.ActionType, actionInput.Resource),
		paramsSummary:      summarizeParams(s.redactor, actionInput.Params),
	}
	defer func() {
		s.emitCompletedAudit(auditCtx, started)
	}()

	s.emitTraceEvent("trace.start", actionInput.TraceID, actionInput.ActionID)
	normalized, err := normalize.Action(actionInput)
	if err != nil {
		auditCtx.resultClass = resultNormError
		auditCtx.retryable = false
		s.emitTraceEvent("trace.end", actionInput.TraceID, actionInput.ActionID)
		return action.Response{}, err
	}
	auditCtx.normalized = &normalized

	decision := s.policy.Evaluate(normalized)
	auditCtx.decision = decision
	auditCtx.riskLevel, auditCtx.riskFlags = riskVisibility(normalized)
	auditCtx.sandboxMode, auditCtx.networkMode = visibilityModes(decision.Obligations, s.sandboxProfile, normalized.ActionType)
	auditCtx.credentialLeaseIDs = credentialLeaseIDs(decision.Obligations)
	auditCtx.actionSummary = actionSummary(normalized.ActionType, normalized.Resource)
	fingerprint, err := actionFingerprint(normalized)
	if err != nil {
		auditCtx.resultClass = resultInternalError
		auditCtx.retryable = true
		s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
		return action.Response{}, err
	}
	decisionEvent := audit.Event{
		SchemaVersion:      "v1",
		Timestamp:          s.now().UTC(),
		EventType:          "action.decision",
		TraceID:            normalized.TraceID,
		ActionID:           normalized.ActionID,
		ActionType:         normalized.ActionType,
		Resource:           normalized.Resource,
		ResourceNormalized: normalized.Resource,
		ParamsHash:         normalized.ParamsHash,
		MatchedRuleIDs:     decision.MatchedRuleIDs,
		Obligations:        decision.Obligations,
		PolicyBundleHash:   decision.PolicyBundleHash,
		RiskLevel:          auditCtx.riskLevel,
		RiskFlags:          auditCtx.riskFlags,
		SandboxMode:        auditCtx.sandboxMode,
		NetworkMode:        auditCtx.networkMode,
		CredentialLeaseIDs: auditCtx.credentialLeaseIDs,
		AssuranceLevel:     s.assuranceLevel,
		ActionSummary:      auditCtx.actionSummary,
		Principal:          normalized.Principal,
		Agent:              normalized.Agent,
		Environment:        normalized.Environment,
		Decision:           decision.Decision,
		Reason:             decision.ReasonCode,
		Fingerprint:        fingerprint,
	}
	_ = s.recorder.WriteEvent(decisionEvent)
	response := action.Response{
		Decision:            decision.Decision,
		Reason:              decision.ReasonCode,
		TraceID:             normalized.TraceID,
		ActionID:            normalized.ActionID,
		ApprovalFingerprint: fingerprint,
	}
	response.Obligations = decision.Obligations

	if decision.Decision == policy.DecisionRequireApproval {
		classKey := approvalClassKey(decision.Obligations, normalized)
		approvalID, err := approvalIDFromExtensions(actionInput.Context)
		if err != nil {
			s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
			return action.Response{}, err
		}
		if approvalID != "" && s.approvals != nil {
			ok, rec, err := s.approvals.CheckApproved(context.Background(), approvalID, fingerprint, classKey)
			if err != nil {
				auditCtx.resultClass, auditCtx.retryable = classifyError(err)
				s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
				return action.Response{}, err
			}
			if ok {
				response.Decision = policy.DecisionAllow
				response.Reason = "allow_by_approval"
				response.ApprovalID = rec.ApprovalID
				_ = s.recorder.WriteEvent(audit.Event{
					Timestamp:      s.now().UTC(),
					EventType:      "approval.applied",
					TraceID:        normalized.TraceID,
					ActionID:       normalized.ActionID,
					ApprovalID:     rec.ApprovalID,
					Fingerprint:    fingerprint,
					Principal:      normalized.Principal,
					Agent:          normalized.Agent,
					Environment:    normalized.Environment,
					AssuranceLevel: s.assuranceLevel,
				})
			}
		}
		if response.Decision != policy.DecisionAllow {
			if s.approvals != nil {
				scopeType := approval.ScopeFingerprint
				scopeKey := fingerprint
				if classKey != "" {
					scopeType = approval.ScopeClass
					scopeKey = classKey
				}
				pending, err := s.approvals.CreateOrGetPending(context.Background(), approval.PendingRequest{
					Fingerprint: fingerprint,
					ScopeType:   scopeType,
					ScopeKey:    scopeKey,
					TraceID:     normalized.TraceID,
					ActionID:    normalized.ActionID,
					ActionType:  normalized.ActionType,
					Resource:    normalized.Resource,
					ParamsHash:  normalized.ParamsHash,
					Principal:   normalized.Principal,
					Agent:       normalized.Agent,
					Environment: normalized.Environment,
				})
				if err != nil {
					auditCtx.resultClass, auditCtx.retryable = classifyError(err)
					s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
					return action.Response{}, err
				}
				response.ApprovalID = pending.ApprovalID
				response.ApprovalExpiresAt = pending.ExpiresAt.Format(time.RFC3339Nano)
				_ = s.recorder.WriteEvent(audit.Event{
					Timestamp:      s.now().UTC(),
					EventType:      "approval.requested",
					TraceID:        normalized.TraceID,
					ActionID:       normalized.ActionID,
					ApprovalID:     pending.ApprovalID,
					Fingerprint:    fingerprint,
					ActionType:     normalized.ActionType,
					Resource:       normalized.Resource,
					Principal:      normalized.Principal,
					Agent:          normalized.Agent,
					Environment:    normalized.Environment,
					AssuranceLevel: s.assuranceLevel,
				})
			}
			auditCtx.resultSummary = summarizeResponse(s.redactor, response)
			auditCtx.resultClass, auditCtx.retryable = classifyDecision(decision, response)
			s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
			return response, nil
		}
	}

	if response.Decision != policy.DecisionAllow {
		auditCtx.resultSummary = summarizeResponse(s.redactor, response)
		auditCtx.resultClass, auditCtx.retryable = classifyDecision(decision, response)
		s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
		return response, nil
	}

	if normalized.ActionType == "fs.read" {
		readResult, err := s.fsReader.Read(normalized.Resource)
		if err != nil {
			auditCtx.resultClass, auditCtx.retryable = classifyError(err)
			s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
			return response, err
		}
		redacted := s.redactor.RedactText(readResult.Content)
		response.Output, response.Truncated = applyOutputObligations(redacted, decision.Obligations, readResult.Truncated)
		auditCtx.executorMetadata = map[string]any{
			"bytes_read": readResult.BytesRead,
			"lines_read": readResult.LinesRead,
			"truncated":  response.Truncated,
		}
		auditCtx.resultSummary = summarizeResponse(s.redactor, response)
		auditCtx.resultClass, auditCtx.retryable = classifyDecision(decision, response)
		s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
		return response, nil
	}

	resp, metadata, err := s.handleAllowedAction(normalized, actionInput, decision.Obligations, response)
	if err != nil {
		auditCtx.resultClass, auditCtx.retryable = classifyError(err)
	} else {
		if len(resp.CredentialLeaseIDs) > 0 {
			auditCtx.credentialLeaseIDs = append([]string{}, resp.CredentialLeaseIDs...)
		}
		auditCtx.resultSummary = summarizeResponse(s.redactor, resp)
		auditCtx.resultClass, auditCtx.retryable = classifyDecision(decision, resp)
		if metadata != nil {
			auditCtx.executorMetadata = metadata
		}
	}
	s.emitTraceEvent("trace.end", normalized.TraceID, normalized.ActionID)
	return resp, err
}

func (s *Service) emitTraceEvent(eventType, traceID, actionID string) {
	event := audit.Event{
		Timestamp:      s.now().UTC(),
		EventType:      eventType,
		TraceID:        traceID,
		ActionID:       actionID,
		AssuranceLevel: s.assuranceLevel,
	}
	_ = s.recorder.WriteEvent(event)
}

func (s *Service) ensureSandbox(obligations map[string]any) error {
	_, err := sandbox.SelectProfile(obligations, s.sandboxProfile)
	return err
}

func (s *Service) handleAllowedAction(normalized normalize.NormalizedAction, actionInput action.Action, obligations map[string]any, response action.Response) (action.Response, map[string]any, error) {
	switch normalized.ActionType {
	case "secrets.checkout":
		params, err := decodeCheckoutParams(actionInput.Params)
		if err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "invalid_params"
			return response, nil, nil
		}
		if s.credentials == nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "credentials_unavailable"
			return response, nil, nil
		}
		lease, err := s.credentials.Checkout(params.SecretID, normalized.Principal, normalized.Agent, normalized.Environment, normalized.TraceID)
		if err != nil {
			return response, nil, err
		}
		response.CredentialLeaseID = lease.ID
		return response, nil, nil
	case "fs.write":
		if err := s.ensureSandbox(obligations); err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "sandbox_required"
			return response, nil, nil
		}
		params, err := decodeWriteParams(actionInput.Params)
		if err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "invalid_params"
			return response, nil, nil
		}
		writeResult, err := s.fsWriter.Write(normalized.Resource, []byte(params.Content))
		if err != nil {
			return response, nil, err
		}
		response.BytesWritten = writeResult.BytesWritten
		return response, map[string]any{"bytes_written": response.BytesWritten}, nil
	case "repo.apply_patch":
		if err := s.ensureSandbox(obligations); err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "sandbox_required"
			return response, nil, nil
		}
		params, err := decodePatchParams(actionInput.Params)
		if err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "invalid_params"
			return response, nil, nil
		}
		patchResult, err := s.patcher.Apply(params.Path, []byte(params.Content))
		if err != nil {
			return response, nil, err
		}
		response.BytesWritten = patchResult.BytesWritten
		return response, map[string]any{"bytes_written": response.BytesWritten}, nil
	case "process.exec":
		if err := s.ensureSandbox(obligations); err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "sandbox_required"
			return response, nil, nil
		}
		if !execAllowed(obligations, actionInput.Params) {
			response.Decision = policy.DecisionDeny
			response.Reason = "exec_not_allowlisted"
			return response, nil, nil
		}
		params, err := decodeExecParams(actionInput.Params)
		if err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "invalid_params"
			return response, nil, nil
		}
		if s.credentials != nil && len(params.CredentialLeaseIDs) > 0 {
			injected, secretValues, err := s.credentials.MaterializeEnv(params.CredentialLeaseIDs, params.EnvAllowlistKeys, normalized.Principal, normalized.Agent, normalized.Environment, normalized.TraceID)
			if err != nil {
				return response, nil, err
			}
			params.InjectedEnv = injected
			response.CredentialLeaseIDs = append([]string{}, params.CredentialLeaseIDs...)
			result, err := s.execRunner.Run(params)
			if err != nil {
				return response, nil, err
			}
			response.Stdout, response.Truncated = applyOutputObligations(redactSecrets(s.redactor.RedactText(result.Stdout), secretValues), obligations, result.Truncated)
			response.Stderr, response.Truncated = applyOutputObligations(redactSecrets(s.redactor.RedactText(result.Stderr), secretValues), obligations, response.Truncated)
			response.ExitCode = result.ExitCode
			return response, map[string]any{"exit_code": response.ExitCode, "truncated": response.Truncated}, nil
		}
		result, err := s.execRunner.Run(params)
		if err != nil {
			return response, nil, err
		}
		response.Stdout, response.Truncated = applyOutputObligations(s.redactor.RedactText(result.Stdout), obligations, result.Truncated)
		response.Stderr, response.Truncated = applyOutputObligations(s.redactor.RedactText(result.Stderr), obligations, response.Truncated)
		response.ExitCode = result.ExitCode
		return response, map[string]any{"exit_code": response.ExitCode, "truncated": response.Truncated}, nil
	case "net.http_request":
		host, urlString, err := parseURLFromResource(normalized.Resource)
		if err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "invalid_resource"
			return response, nil, nil
		}
		if !netAllowed(obligations, host) {
			response.Decision = policy.DecisionDeny
			response.Reason = "net_not_allowlisted"
			return response, nil, nil
		}
		params, err := decodeHTTPParams(actionInput.Params)
		if err != nil {
			response.Decision = policy.DecisionDeny
			response.Reason = "invalid_params"
			return response, nil, nil
		}
		result, err := s.httpRunner.DoWithPolicy(urlString, params, redirectPolicyFromObligations(obligations))
		if err != nil {
			return response, nil, err
		}
		response.StatusCode = result.StatusCode
		response.Output, response.Truncated = applyOutputObligations(s.redactor.RedactText(result.Body), obligations, result.Truncated)
		return response, map[string]any{
			"status_code":    response.StatusCode,
			"truncated":      response.Truncated,
			"final_resource": result.FinalResource,
			"redirect_hops":  result.RedirectHops,
		}, nil
	default:
		response.Decision = policy.DecisionDeny
		response.Reason = "unsupported_action"
		return response, nil, nil
	}
}

func applyOutputObligations(text string, obligations map[string]any, alreadyTruncated bool) (string, bool) {
	out := text
	truncated := alreadyTruncated
	if maxBytes, ok := intObligation(obligations["output_max_bytes"]); ok && maxBytes >= 0 {
		if len(out) > maxBytes {
			out = trimToBytes(out, maxBytes)
			truncated = true
		}
	}
	if maxLines, ok := intObligation(obligations["output_max_lines"]); ok && maxLines >= 0 {
		limited, wasTrimmed := trimToLines(out, maxLines)
		out = limited
		if wasTrimmed {
			truncated = true
		}
	}
	return out, truncated
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
	if lineCount >= maxLines {
		return "", false
	}
	return value, false
}
