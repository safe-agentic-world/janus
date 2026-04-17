package mcp

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/identity"
)

const statefulForwardedAllowBundle = `{"version":"v1","rules":[` +
	`{"id":"allow-refund","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},` +
	`{"id":"allow-status","action_type":"mcp.call","resource":"mcp://retail/refund.status","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}` +
	`]}`

func newStatefulUpstreamServer(t *testing.T, bundle string) *Server {
	t.Helper()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "error",
		LogFormat: "text",
		ErrWriter: io.Discard,
		UpstreamServers: []UpstreamServerConfig{{
			Name:      "retail",
			Transport: "stdio",
			Command:   os.Args[0],
			Args:      []string{"-test.run=TestUpstreamMCPHelperProcess", "--", "stateful-retail"},
			Env: map[string]string{
				"GO_WANT_UPSTREAM_MCP_HELPER": "1",
			},
			Workdir: dir,
		}},
	})
	if err != nil {
		t.Fatalf("new stateful upstream server: %v", err)
	}
	server.upstream.setBackoffForTest(0, 0)
	return server
}

func TestUpstreamSessionSharedByConcurrentCalls(t *testing.T) {
	server := newStatefulUpstreamServer(t, statefulForwardedAllowBundle)
	t.Cleanup(func() { _ = server.Close() })

	priming := server.handleRequest(Request{
		ID:     "prime",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-PRIME", "reason": "prime"}),
	})
	if priming.Error != "" {
		t.Fatalf("prime: %+v", priming)
	}
	primingResult := priming.Result.(action.Response)
	if primingResult.Decision != "ALLOW" {
		t.Fatalf("prime: expected ALLOW got %+v", primingResult)
	}

	session := server.upstream.sessionForTest("retail")
	connBefore := session.connForTest()
	if connBefore == nil {
		t.Fatal("expected live upstream conn after prime")
	}

	const workers = 32
	errs := make(chan string, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			orderID := fmt.Sprintf("ORD-%04d", i)
			resp := server.handleRequest(Request{
				ID:     fmt.Sprintf("call-%d", i),
				Method: "upstream_retail_refund_request",
				Params: mustJSONBytes(map[string]any{"order_id": orderID, "reason": "bulk"}),
			})
			if resp.Error != "" {
				errs <- fmt.Sprintf("call %d: %s", i, resp.Error)
				return
			}
			result, ok := resp.Result.(action.Response)
			if !ok {
				errs <- fmt.Sprintf("call %d: expected action.Response, got %T", i, resp.Result)
				return
			}
			if result.Decision != "ALLOW" {
				errs <- fmt.Sprintf("call %d: expected ALLOW, got %+v", i, result)
				return
			}
			if !strings.Contains(result.Output, orderID) {
				errs <- fmt.Sprintf("call %d: output %q does not contain %s", i, result.Output, orderID)
				return
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatal(msg)
	}

	connAfter := session.connForTest()
	if connAfter != connBefore {
		t.Fatalf("expected shared upstream conn (one session), got %p then %p", connBefore, connAfter)
	}
}

func TestUpstreamSessionRecoversAfterCrashMidCall(t *testing.T) {
	server := newStatefulUpstreamServer(t, statefulForwardedAllowBundle)
	t.Cleanup(func() { _ = server.Close() })

	priming := server.handleRequest(Request{
		ID:     "prime",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-PRIME", "reason": "prime"}),
	})
	if priming.Error != "" {
		t.Fatalf("prime: %+v", priming)
	}

	session := server.upstream.sessionForTest("retail")
	connBefore := session.connForTest()
	if connBefore == nil {
		t.Fatal("expected live upstream conn after prime")
	}

	crash := server.handleRequest(Request{
		ID:     "crash",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "KILL", "reason": "boom"}),
	})
	if crash.Error != "upstream_unavailable" {
		t.Fatalf("expected upstream_unavailable error, got error=%q result=%+v", crash.Error, crash.Result)
	}

	recover := server.handleRequest(Request{
		ID:     "recover",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-RECOVER", "reason": "retry"}),
	})
	if recover.Error != "" {
		t.Fatalf("recover: unexpected error %q", recover.Error)
	}
	recoverResult, ok := recover.Result.(action.Response)
	if !ok {
		t.Fatalf("recover: expected action.Response, got %T", recover.Result)
	}
	if recoverResult.Decision != "ALLOW" || !strings.Contains(recoverResult.Output, "ORD-RECOVER") {
		t.Fatalf("recover: expected ALLOW with ORD-RECOVER, got %+v", recoverResult)
	}

	connAfter := session.connForTest()
	if connAfter == nil {
		t.Fatal("expected fresh upstream conn after recovery")
	}
	if connAfter == connBefore {
		t.Fatal("expected new upstream conn after crash, still holding crashed conn")
	}
}

func TestUpstreamSessionRefreshOnToolsListChanged(t *testing.T) {
	server := newStatefulUpstreamServer(t, statefulForwardedAllowBundle)
	t.Cleanup(func() { _ = server.Close() })

	priming := server.handleRequest(Request{
		ID:     "prime",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-PRIME", "reason": "prime"}),
	})
	if priming.Error != "" {
		t.Fatalf("prime: %+v", priming)
	}

	before := server.toolsList()
	if containsForwardedTool(before, "upstream_retail_refund_status") {
		t.Fatalf("did not expect upstream_retail_refund_status in initial tools list: %+v", before)
	}
	if !containsForwardedTool(before, "upstream_retail_refund_request") {
		t.Fatalf("expected upstream_retail_refund_request in initial tools list: %+v", before)
	}

	refreshed := make(chan string, 4)
	server.upstream.setRefreshHookForTest(func(serverName string) {
		select {
		case refreshed <- serverName:
		default:
		}
	})

	trigger := server.handleRequest(Request{
		ID:     "trigger",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "LIST_CHANGED", "reason": "update"}),
	})
	if trigger.Error != "" {
		t.Fatalf("trigger: %+v", trigger)
	}

	select {
	case got := <-refreshed:
		if got != "retail" {
			t.Fatalf("refresh hook fired for %q, want retail", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("refresh hook did not fire after tools/list_changed")
	}

	after := server.toolsList()
	if !containsForwardedTool(after, "upstream_retail_refund_status") {
		t.Fatalf("expected upstream_retail_refund_status after refresh, got %+v", after)
	}
	if !containsForwardedTool(after, "upstream_retail_refund_request") {
		t.Fatalf("expected upstream_retail_refund_request after refresh, got %+v", after)
	}

	statusResp := server.handleRequest(Request{
		ID:     "status",
		Method: "upstream_retail_refund_status",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-STATUS"}),
	})
	if statusResp.Error != "" {
		t.Fatalf("status call: unexpected error %q", statusResp.Error)
	}
	statusResult, ok := statusResp.Result.(action.Response)
	if !ok {
		t.Fatalf("status call: expected action.Response, got %T", statusResp.Result)
	}
	if statusResult.Decision != "ALLOW" || !strings.Contains(statusResult.Output, "ORD-STATUS") {
		t.Fatalf("status call: expected ALLOW with ORD-STATUS, got %+v", statusResult)
	}
}

func TestUpstreamSupervisorGracefulShutdownTerminatesChildren(t *testing.T) {
	server := newStatefulUpstreamServer(t, statefulForwardedAllowBundle)

	priming := server.handleRequest(Request{
		ID:     "prime",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-PRIME", "reason": "prime"}),
	})
	if priming.Error != "" {
		t.Fatalf("prime: %+v", priming)
	}

	session := server.upstream.sessionForTest("retail")
	conn := session.connForTest()
	if conn == nil || conn.cmd == nil || conn.cmd.Process == nil {
		t.Fatal("expected live upstream process after prime call")
	}
	cmd := conn.cmd

	if err := server.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if cmd.ProcessState == nil {
		t.Fatal("expected process state to be populated after Close")
	}
	if !cmd.ProcessState.Exited() {
		t.Fatalf("expected process to have exited after Close, got state %+v", cmd.ProcessState)
	}
}

func TestUpstreamSessionNoGoroutineLeakOverManySequentialCalls(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sequential leak test in short mode")
	}
	server := newStatefulUpstreamServer(t, statefulForwardedAllowBundle)
	t.Cleanup(func() { _ = server.Close() })

	priming := server.handleRequest(Request{
		ID:     "prime",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-PRIME", "reason": "prime"}),
	})
	if priming.Error != "" {
		t.Fatalf("prime: %+v", priming)
	}

	session := server.upstream.sessionForTest("retail")
	connBefore := session.connForTest()
	if connBefore == nil {
		t.Fatal("expected live upstream conn after prime")
	}

	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	const iterations = 1000
	for i := 0; i < iterations; i++ {
		resp := server.handleRequest(Request{
			ID:     fmt.Sprintf("seq-%d", i),
			Method: "upstream_retail_refund_request",
			Params: mustJSONBytes(map[string]any{"order_id": fmt.Sprintf("ORD-%04d", i), "reason": "seq"}),
		})
		if resp.Error != "" {
			t.Fatalf("seq call %d: %+v", i, resp)
		}
		result, ok := resp.Result.(action.Response)
		if !ok || result.Decision != "ALLOW" {
			t.Fatalf("seq call %d: expected ALLOW action.Response, got %T %+v", i, resp.Result, resp.Result)
		}
	}

	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()

	if after-baseline > 5 {
		t.Fatalf("goroutine leak across %d sequential calls: baseline=%d after=%d", iterations, baseline, after)
	}

	connAfter := session.connForTest()
	if connAfter != connBefore {
		t.Fatalf("expected shared upstream conn across %d sequential calls, got %p then %p", iterations, connBefore, connAfter)
	}
}

func containsForwardedTool(tools []map[string]any, name string) bool {
	for _, tool := range tools {
		if got, _ := tool["name"].(string); got == name {
			return true
		}
	}
	return false
}
