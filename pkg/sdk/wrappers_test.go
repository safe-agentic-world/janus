package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type wrapperInput struct {
	OrderID string
	TraceID string
}

func TestGuardedFunctionAllowExecutesWrappedSideEffect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ActionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(DecisionResponse{
			Decision: "ALLOW",
			ActionID: req.ActionID,
			TraceID:  req.TraceID,
		})
	}))
	defer server.Close()

	client := mustTestClient(t, server.URL)
	executed := false
	guard, err := NewGuardedHTTPTool(client,
		func(in wrapperInput) (string, error) { return "url://shop.example.com/refunds/" + in.OrderID, nil },
		func(in wrapperInput) (map[string]any, error) { return map[string]any{"method": "POST"}, nil },
		func(ctx context.Context, in wrapperInput) (string, error) {
			executed = true
			return "refund-submitted", nil
		},
	)
	if err != nil {
		t.Fatalf("new guarded tool: %v", err)
	}

	result, err := guard.Invoke(context.Background(), wrapperInput{OrderID: "ORD-1001"})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !executed || !result.Executed || result.Value != "refund-submitted" || !result.IsAllowed() {
		t.Fatalf("unexpected guard result %+v executed=%v", result, executed)
	}
}

func TestGuardedFunctionDenyDoesNotExecuteWrappedSideEffect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "DENY", Reason: "deny_by_rule"})
	}))
	defer server.Close()

	client := mustTestClient(t, server.URL)
	executed := false
	guard, err := NewGuardedHTTPTool(client,
		func(in wrapperInput) (string, error) { return "url://shop.example.com/refunds/" + in.OrderID, nil },
		func(in wrapperInput) (map[string]any, error) { return map[string]any{"method": "POST"}, nil },
		func(ctx context.Context, in wrapperInput) (string, error) {
			executed = true
			return "should-not-run", nil
		},
	)
	if err != nil {
		t.Fatalf("new guarded tool: %v", err)
	}

	result, err := guard.Invoke(context.Background(), wrapperInput{OrderID: "ORD-1001"})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if executed || result.Executed || !result.IsDenied() {
		t.Fatalf("expected deny without execution, got %+v executed=%v", result, executed)
	}
}

func TestGuardedFunctionApprovalRequiredDoesNotExecuteWrappedSideEffect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DecisionResponse{
			Decision:            "REQUIRE_APPROVAL",
			Reason:              "require_approval_by_rule",
			ApprovalID:          "apr_123",
			ApprovalFingerprint: "fp_123",
		})
	}))
	defer server.Close()

	client := mustTestClient(t, server.URL)
	executed := false
	guard, err := NewGuardedSubprocessTool(client,
		func(in wrapperInput) (string, error) { return "exec://support/refunds", nil },
		func(in wrapperInput) (map[string]any, error) { return map[string]any{"argv": []string{"refund"}}, nil },
		func(ctx context.Context, in wrapperInput) (string, error) {
			executed = true
			return "should-not-run", nil
		},
	)
	if err != nil {
		t.Fatalf("new guarded tool: %v", err)
	}

	result, err := guard.Invoke(context.Background(), wrapperInput{OrderID: "ORD-1001"})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if executed || result.Executed || !result.RequiresApproval() || result.DecisionResponse.ApprovalID != "apr_123" {
		t.Fatalf("expected approval result without execution, got %+v executed=%v", result, executed)
	}
}

func TestGuardedFunctionFailsClosedOnTransportOrAuthErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "DENY", Reason: "auth_error: invalid signature"})
	}))
	server.Close()

	client := mustTestClient(t, server.URL)
	executed := false
	guard, err := NewGuardedFileReadTool(client,
		func(in wrapperInput) (string, error) { return "file://workspace/README.md", nil },
		func(in wrapperInput) (map[string]any, error) { return map[string]any{}, nil },
		func(ctx context.Context, in wrapperInput) (string, error) {
			executed = true
			return "should-not-run", nil
		},
	)
	if err != nil {
		t.Fatalf("new guarded tool: %v", err)
	}

	_, err = guard.Invoke(context.Background(), wrapperInput{})
	if err == nil {
		t.Fatal("expected transport or auth error")
	}
	if executed {
		t.Fatal("expected wrapped side effect to fail closed")
	}
}

func TestGuardedFunctionPropagatesExplicitTraceID(t *testing.T) {
	var captured ActionRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "ALLOW", ActionID: captured.ActionID, TraceID: captured.TraceID})
	}))
	defer server.Close()

	client := mustTestClient(t, server.URL)
	guard, err := NewGuardedFunction(client,
		func(in wrapperInput) (ActionRequest, error) {
			req := NewActionRequest("net.http_request", "url://shop.example.com/refunds/"+in.OrderID, map[string]any{"method": "POST"})
			req.TraceID = in.TraceID
			return req, nil
		},
		func(ctx context.Context, in wrapperInput) (string, error) { return "ok", nil },
	)
	if err != nil {
		t.Fatalf("new guarded function: %v", err)
	}

	result, err := guard.Invoke(context.Background(), wrapperInput{OrderID: "ORD-1001", TraceID: "trace-explicit-123"})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if !result.Executed || captured.TraceID != "trace-explicit-123" || result.DecisionResponse.TraceID != "trace-explicit-123" {
		t.Fatalf("expected explicit trace propagation, got captured=%+v result=%+v", captured, result)
	}
}

func TestNewGuardedFunctionRejectsMissingInputs(t *testing.T) {
	client := &Client{}
	if _, err := NewGuardedFunction[wrapperInput, string](nil, nil, nil); err == nil {
		t.Fatal("expected missing client error")
	}
	if _, err := NewGuardedFunction[wrapperInput, string](client, nil, func(context.Context, wrapperInput) (string, error) { return "", nil }); err == nil {
		t.Fatal("expected missing build error")
	}
	if _, err := NewGuardedFunction[wrapperInput, string](client, func(wrapperInput) (ActionRequest, error) { return ActionRequest{}, nil }, nil); err == nil {
		t.Fatal("expected missing execute error")
	}
}

func TestGuardedFunctionPropagatesExecutorErrorAfterAllow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "ALLOW"})
	}))
	defer server.Close()

	client := mustTestClient(t, server.URL)
	guard, err := NewGuardedHTTPTool(client,
		func(in wrapperInput) (string, error) { return "url://shop.example.com/refunds/" + in.OrderID, nil },
		func(in wrapperInput) (map[string]any, error) { return map[string]any{"method": "POST"}, nil },
		func(ctx context.Context, in wrapperInput) (string, error) {
			return "", errors.New("refund backend unavailable")
		},
	)
	if err != nil {
		t.Fatalf("new guarded tool: %v", err)
	}

	result, err := guard.Invoke(context.Background(), wrapperInput{OrderID: "ORD-1001"})
	if err == nil {
		t.Fatal("expected executor error")
	}
	if result.Executed {
		t.Fatalf("expected no completed execution marker on executor error, got %+v", result)
	}
}

func TestGuardedFunctionInvokeAndReport(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path == "/action" {
			_ = json.NewEncoder(w).Encode(DecisionResponse{Decision: "ALLOW", ExecutionMode: "external_authorized", ReportPath: "/actions/report", ActionID: "act-custom", TraceID: "trace-custom"})
			return
		}
		if r.URL.Path == "/actions/report" {
			_ = json.NewEncoder(w).Encode(ExternalReportResponse{Recorded: true, ActionID: "act-custom", TraceID: "trace-custom", Outcome: "SUCCEEDED"})
			return
		}
		t.Fatalf("unexpected path %s", r.URL.Path)
	}))
	defer server.Close()

	client := mustTestClient(t, server.URL)
	guard, err := NewGuardedFunction(client,
		func(in wrapperInput) (ActionRequest, error) {
			return NewActionRequest("payments.refund", "payment://shop.example.com/orders/"+in.OrderID, map[string]any{}), nil
		},
		func(ctx context.Context, in wrapperInput) (string, error) { return "submitted", nil },
	)
	if err != nil {
		t.Fatalf("new guarded function: %v", err)
	}
	result, err := guard.InvokeAndReport(context.Background(), wrapperInput{OrderID: "ORD-1001"}, func(input wrapperInput, value string, decision DecisionResponse) (ExternalReportRequest, error) {
		return ExternalReportRequest{
			ActionID:   decision.ActionID,
			TraceID:    decision.TraceID,
			ActionType: "payments.refund",
			Resource:   "payment://shop.example.com/orders/" + input.OrderID,
			Outcome:    "SUCCEEDED",
		}, nil
	})
	if err != nil {
		t.Fatalf("invoke and report: %v", err)
	}
	if !result.Executed || requests != 2 {
		t.Fatalf("expected action plus report requests, got executed=%v requests=%d", result.Executed, requests)
	}
}

func mustTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	client, err := NewClient(Config{
		BaseURL:     baseURL,
		BearerToken: "key1",
		AgentID:     "agent-http",
		AgentSecret: "agent-secret",
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}
