package opabridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

type Evaluator interface {
	Evaluate(input []byte) ([]byte, error)
}

type Result struct {
	Decision    string         `json:"decision"`
	ReasonCode  string         `json:"reason_code,omitempty"`
	Obligations map[string]any `json:"obligations,omitempty"`
}

type CommandConfig struct {
	BinaryPath string
	PolicyPath string
	Query      string
	Timeout    time.Duration
}

type Backend struct {
	evaluator Evaluator
	policyRef string
}

func NewBackend(evaluator Evaluator, policyRef string) *Backend {
	return &Backend{
		evaluator: evaluator,
		policyRef: strings.TrimSpace(policyRef),
	}
}

func NewCommandBackend(cfg CommandConfig) (*Backend, error) {
	evaluator, err := NewCommandEvaluator(cfg)
	if err != nil {
		return nil, err
	}
	return NewBackend(evaluator, "opa:"+strings.TrimSpace(cfg.PolicyPath)+":"+strings.TrimSpace(cfg.Query)), nil
}

func (b *Backend) Evaluate(action normalize.NormalizedAction) (policy.Decision, error) {
	if b == nil {
		return policy.Decision{}, errors.New("opa evaluator unavailable")
	}
	decision, err := Evaluate(action, b.evaluator)
	if err != nil {
		return policy.Decision{}, err
	}
	decision.PolicyBundleHash = b.policyRef
	if decision.Obligations == nil {
		decision.Obligations = map[string]any{}
	}
	if decision.MatchedRuleIDs == nil {
		decision.MatchedRuleIDs = []string{}
	}
	return decision, nil
}

type commandEvaluator struct {
	binaryPath string
	policyPath string
	query      string
	timeout    time.Duration
}

func NewCommandEvaluator(cfg CommandConfig) (Evaluator, error) {
	if strings.TrimSpace(cfg.BinaryPath) == "" {
		return nil, errors.New("opa binary path is required")
	}
	if strings.TrimSpace(cfg.PolicyPath) == "" {
		return nil, errors.New("opa policy path is required")
	}
	if strings.TrimSpace(cfg.Query) == "" {
		return nil, errors.New("opa query is required")
	}
	resolved, err := exec.LookPath(cfg.BinaryPath)
	if err != nil {
		return nil, errors.New("opa binary not found")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &commandEvaluator{
		binaryPath: resolved,
		policyPath: strings.TrimSpace(cfg.PolicyPath),
		query:      strings.TrimSpace(cfg.Query),
		timeout:    timeout,
	}, nil
}

func (e *commandEvaluator) Evaluate(input []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, e.binaryPath, "eval", "--format=json", "--stdin-input", "--data", e.policyPath, e.query)
	cmd.Stdin = bytes.NewReader(input)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, errors.New("opa evaluator unavailable")
	}
	result, err := parseOPAEvalOutput(stdout.Bytes())
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

func StableInput(action normalize.NormalizedAction) ([]byte, error) {
	payload := map[string]any{
		"schema_version": action.SchemaVersion,
		"action_id":      action.ActionID,
		"action_type":    action.ActionType,
		"resource":       action.Resource,
		"params":         json.RawMessage(action.Params),
		"params_hash":    action.ParamsHash,
		"principal":      action.Principal,
		"agent":          action.Agent,
		"environment":    action.Environment,
		"trace_id":       action.TraceID,
	}
	return json.Marshal(payload)
}

func Evaluate(action normalize.NormalizedAction, evaluator Evaluator) (policy.Decision, error) {
	if evaluator == nil {
		return policy.Decision{}, errors.New("opa evaluator unavailable")
	}
	input, err := StableInput(action)
	if err != nil {
		return policy.Decision{}, err
	}
	raw, err := evaluator.Evaluate(input)
	if err != nil {
		return policy.Decision{}, errors.New("opa evaluator unavailable")
	}
	result, err := parseResult(raw)
	if err != nil {
		return policy.Decision{}, err
	}
	out := policy.Decision{
		Decision:    result.Decision,
		ReasonCode:  strings.TrimSpace(result.ReasonCode),
		Obligations: map[string]any{},
	}
	if out.ReasonCode == "" {
		switch out.Decision {
		case policy.DecisionAllow:
			out.ReasonCode = "allow_by_external_policy"
		case policy.DecisionDeny:
			out.ReasonCode = "deny_by_external_policy"
		case policy.DecisionRequireApproval:
			out.ReasonCode = "require_approval_by_external_policy"
		}
	}
	if result.Obligations != nil {
		out.Obligations = result.Obligations
	}
	return out, nil
}

func parseOPAEvalOutput(raw []byte) (Result, error) {
	var envelope struct {
		Result []struct {
			Expressions []struct {
				Value json.RawMessage `json:"value"`
			} `json:"expressions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Result{}, errors.New("opa evaluator returned invalid output")
	}
	if len(envelope.Result) != 1 || len(envelope.Result[0].Expressions) != 1 {
		return Result{}, errors.New("opa evaluator returned ambiguous decision")
	}
	return parseResult(envelope.Result[0].Expressions[0].Value)
}

func parseResult(raw []byte) (Result, error) {
	var result Result
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&result); err != nil {
		return Result{}, errors.New("opa evaluator returned invalid output")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Result{}, errors.New("opa evaluator returned invalid output")
	}
	switch result.Decision {
	case policy.DecisionAllow, policy.DecisionDeny, policy.DecisionRequireApproval:
	default:
		return Result{}, errors.New("opa evaluator returned ambiguous decision")
	}
	return result, nil
}
