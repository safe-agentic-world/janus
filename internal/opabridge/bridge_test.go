package opabridge

import (
	"bytes"
	"errors"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

type staticEvaluator struct {
	out []byte
	err error
}

func (s staticEvaluator) Evaluate(_ []byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.out, nil
}

func TestEvaluateDeterministicDecision(t *testing.T) {
	action := normalize.NormalizedAction{
		SchemaVersion: "v1",
		ActionID:      "act1",
		ActionType:    "fs.read",
		Resource:      "file://workspace/README.md",
		Params:        []byte(`{}`),
		ParamsHash:    "hash",
		Principal:     "system",
		Agent:         "nomos",
		Environment:   "dev",
		TraceID:       "trace1",
	}
	got1, err := Evaluate(action, staticEvaluator{out: []byte(`{"decision":"ALLOW","obligations":{"output_max_bytes":10}}`)})
	if err != nil {
		t.Fatalf("evaluate #1: %v", err)
	}
	got2, err := Evaluate(action, staticEvaluator{out: []byte(`{"decision":"ALLOW","obligations":{"output_max_bytes":10}}`)})
	if err != nil {
		t.Fatalf("evaluate #2: %v", err)
	}
	if got1.Decision != policy.DecisionAllow || got2.Decision != policy.DecisionAllow {
		t.Fatalf("expected allow decisions, got %+v %+v", got1, got2)
	}
	b1, _ := StableInput(action)
	b2, _ := StableInput(action)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("expected deterministic stable input\n1=%s\n2=%s", string(b1), string(b2))
	}
}

func TestEvaluateFailsClosedOnUnavailableBackend(t *testing.T) {
	_, err := Evaluate(normalize.NormalizedAction{}, staticEvaluator{err: errors.New("down")})
	if err == nil {
		t.Fatal("expected unavailable backend error")
	}
}

func TestEvaluateFailsClosedOnMalformedOrAmbiguousOutput(t *testing.T) {
	if _, err := Evaluate(normalize.NormalizedAction{}, staticEvaluator{out: []byte(`{"decision":123}`)}); err == nil {
		t.Fatal("expected malformed output error")
	}
	if _, err := Evaluate(normalize.NormalizedAction{}, staticEvaluator{out: []byte(`{"decision":"MAYBE"}`)}); err == nil {
		t.Fatal("expected ambiguous output error")
	}
}

func TestParseOPAEvalOutputAcceptsOPAEnvelope(t *testing.T) {
	result, err := parseOPAEvalOutput([]byte(`{"result":[{"expressions":[{"value":{"decision":"ALLOW","reason_code":"allow_by_external_policy"}}]}]}`))
	if err != nil {
		t.Fatalf("parse opa output: %v", err)
	}
	if result.Decision != policy.DecisionAllow || result.ReasonCode != "allow_by_external_policy" {
		t.Fatalf("unexpected parsed result: %+v", result)
	}
}

func TestBackendAnnotatesPolicyRef(t *testing.T) {
	action := normalize.NormalizedAction{
		ActionType: "fs.read",
		Resource:   "file://workspace/README.md",
		Params:     []byte(`{}`),
		ParamsHash: "hash",
	}
	backend := NewBackend(staticEvaluator{out: []byte(`{"decision":"ALLOW"}`)}, "opa:test")
	decision, err := backend.Evaluate(action)
	if err != nil {
		t.Fatalf("backend evaluate: %v", err)
	}
	if decision.PolicyBundleHash != "opa:test" {
		t.Fatalf("expected policy ref annotation, got %+v", decision)
	}
}
