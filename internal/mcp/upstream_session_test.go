package mcp

import (
	"context"
	"errors"
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
	"github.com/safe-agentic-world/nomos/internal/audit"
	"github.com/safe-agentic-world/nomos/internal/identity"
)

const statefulForwardedAllowBundle = `{"version":"v1","rules":[` +
	`{"id":"allow-refund","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},` +
	`{"id":"allow-status","action_type":"mcp.call","resource":"mcp://retail/refund.status","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}` +
	`]}`

type recordingSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingSink) WriteEvent(event audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	return nil
}

func (r *recordingSink) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]audit.Event, len(r.events))
	copy(out, r.events)
	return out
}

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

func newEnvInspectUpstreamServer(t *testing.T, bundle string, upstream UpstreamServerConfig) *Server {
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
		LogLevel:        "error",
		LogFormat:       "text",
		ErrWriter:       io.Discard,
		UpstreamServers: []UpstreamServerConfig{upstream},
	})
	if err != nil {
		t.Fatalf("new env inspect upstream server: %v", err)
	}
	server.upstream.setBackoffForTest(0, 0)
	return server
}

func newTimeoutUpstreamServer(t *testing.T, mode string, timeout time.Duration) *Server {
	t.Helper()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-call","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
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
			Name:              "retail",
			Transport:         "stdio",
			Command:           os.Args[0],
			Args:              []string{"-test.run=TestUpstreamMCPHelperProcess", "--", mode},
			Env:               map[string]string{"GO_WANT_UPSTREAM_MCP_HELPER": "1"},
			Workdir:           dir,
			InitializeTimeout: timeout,
			EnumerateTimeout:  timeout,
			CallTimeout:       timeout,
			StreamTimeout:     timeout,
		}},
	})
	if err != nil {
		t.Fatalf("new timeout upstream server: %v", err)
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

func TestUpstreamInitializeTimeoutFailsClosed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timeout test in short mode")
	}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-call","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	_, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "error",
		LogFormat: "text",
		ErrWriter: io.Discard,
		UpstreamServers: []UpstreamServerConfig{{
			Name:              "retail",
			Transport:         "stdio",
			Command:           os.Args[0],
			Args:              []string{"-test.run=TestUpstreamMCPHelperProcess", "--", "hang-init"},
			Env:               map[string]string{"GO_WANT_UPSTREAM_MCP_HELPER": "1"},
			Workdir:           dir,
			InitializeTimeout: 25 * time.Millisecond,
			EnumerateTimeout:  25 * time.Millisecond,
			CallTimeout:       25 * time.Millisecond,
			StreamTimeout:     25 * time.Millisecond,
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "UPSTREAM_TIMEOUT") {
		t.Fatalf("expected initialize timeout, got %v", err)
	}
}

func TestUpstreamCancellationReturnsStructuredError(t *testing.T) {
	server := newTimeoutUpstreamServer(t, "hang-call", 500*time.Millisecond)
	t.Cleanup(func() { _ = server.Close() })
	session := server.upstream.sessionForTest("retail")
	if session == nil {
		t.Fatal("expected upstream session")
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err := session.call(ctx, "tools/call", map[string]any{
		"name":      "refund.request",
		"arguments": map[string]any{"order_id": "ORD-1", "reason": "slow"},
	})
	if !errors.Is(err, errUpstreamCanceled) {
		t.Fatalf("expected UPSTREAM_CANCELED, got %v", err)
	}
}

func TestUpstreamForcedTimeoutsDoNotLeakGoroutines(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping leak test in short mode")
	}
	server := newTimeoutUpstreamServer(t, "hang-call", 500*time.Millisecond)
	t.Cleanup(func() { _ = server.Close() })
	session := server.upstream.sessionForTest("retail")
	if session == nil {
		t.Fatal("expected upstream session")
	}
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	before := runtime.NumGoroutine()
	for i := 0; i < 1000; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		_, _ = session.call(ctx, "tools/call", map[string]any{
			"name":      "refund.request",
			"arguments": map[string]any{"order_id": fmt.Sprintf("ORD-%d", i), "reason": "timeout"},
		})
		cancel()
	}
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after-before > 8 {
		t.Fatalf("goroutine leak across forced timeouts: before=%d after=%d", before, after)
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
	// Close force-terminates the upstream child before waiting for it. On Unix
	// that yields a signaled process state ("signal: killed"), where Exited is
	// false even though the process is fully terminated and reaped.
	state := cmd.ProcessState.String()
	if !cmd.ProcessState.Exited() && state == "" {
		t.Fatalf("expected process to be terminated after Close, got state %+v", cmd.ProcessState)
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

func TestUpstreamEnvEmptyByDefault(t *testing.T) {
	t.Setenv("SECRET_TOKEN", "super-secret")
	t.Setenv("ALLOWLISTED_VAR", "allowed")
	server := newEnvInspectUpstreamServer(t, statefulForwardedAllowBundle, UpstreamServerConfig{
		Name:      "retail",
		Transport: "stdio",
		Command:   os.Args[0],
		Args:      []string{"-test.run=TestUpstreamMCPHelperProcess", "--", "env-inspect"},
		Workdir:   t.TempDir(),
	})
	t.Cleanup(func() { _ = server.Close() })

	session := server.upstream.sessionForTest("retail")
	result, err := session.call(context.Background(), "env.inspect", map[string]any{})
	if err != nil {
		t.Fatalf("env inspect call: %v", err)
	}
	env := helperEnvMap(t, result)
	if env["SECRET_TOKEN"] != "" || env["ALLOWLISTED_VAR"] != "" || env["OVERRIDE_VAR"] != "" || env["PATH"] != "" {
		t.Fatalf("expected empty inherited env, got %+v", env)
	}
}

func TestUpstreamEnvAllowlistPassThrough(t *testing.T) {
	t.Setenv("SECRET_TOKEN", "super-secret")
	t.Setenv("ALLOWLISTED_VAR", "allowed")
	server := newEnvInspectUpstreamServer(t, statefulForwardedAllowBundle, UpstreamServerConfig{
		Name:         "retail",
		Transport:    "stdio",
		Command:      os.Args[0],
		Args:         []string{"-test.run=TestUpstreamMCPHelperProcess", "--", "env-inspect"},
		EnvAllowlist: []string{"ALLOWLISTED_VAR"},
		Workdir:      t.TempDir(),
	})
	t.Cleanup(func() { _ = server.Close() })

	session := server.upstream.sessionForTest("retail")
	result, err := session.call(context.Background(), "env.inspect", map[string]any{})
	if err != nil {
		t.Fatalf("env inspect call: %v", err)
	}
	env := helperEnvMap(t, result)
	if env["ALLOWLISTED_VAR"] != "allowed" {
		t.Fatalf("expected allowlisted env passthrough, got %+v", env)
	}
	if env["SECRET_TOKEN"] != "" {
		t.Fatalf("expected secret to stay out of child env, got %+v", env)
	}
}

func TestUpstreamEnvOverrideWinsOverAllowlist(t *testing.T) {
	t.Setenv("OVERRIDE_VAR", "from_parent")
	server := newEnvInspectUpstreamServer(t, statefulForwardedAllowBundle, UpstreamServerConfig{
		Name:         "retail",
		Transport:    "stdio",
		Command:      os.Args[0],
		Args:         []string{"-test.run=TestUpstreamMCPHelperProcess", "--", "env-inspect"},
		EnvAllowlist: []string{"OVERRIDE_VAR"},
		Env: map[string]string{
			"OVERRIDE_VAR": "from_config",
		},
		Workdir: t.TempDir(),
	})
	t.Cleanup(func() { _ = server.Close() })

	session := server.upstream.sessionForTest("retail")
	result, err := session.call(context.Background(), "env.inspect", map[string]any{})
	if err != nil {
		t.Fatalf("env inspect call: %v", err)
	}
	env := helperEnvMap(t, result)
	if env["OVERRIDE_VAR"] != "from_config" {
		t.Fatalf("expected override to win over allowlist, got %+v", env)
	}
}

func TestUpstreamEnvShapeHashRecordedInAuditMetadata(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	bundle := `{"version":"v1","rules":[{"id":"allow-refund","action_type":"mcp.call","resource":"mcp://retail/refund.request","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	recorderA := &recordingSink{}
	recorderB := &recordingSink{}
	upstream := UpstreamServerConfig{
		Name:         "retail",
		Transport:    "stdio",
		Command:      os.Args[0],
		Args:         []string{"-test.run=TestUpstreamMCPHelperProcess", "--", "stateful-retail"},
		EnvAllowlist: []string{"ALLOWLISTED_VAR"},
		Env: map[string]string{
			"OVERRIDE_VAR": "from_config",
		},
		Workdir: dir,
	}
	serverA, err := NewServerWithRuntimeOptionsAndRecorder(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:        "error",
		LogFormat:       "text",
		ErrWriter:       io.Discard,
		UpstreamServers: []UpstreamServerConfig{upstream},
	}, recorderA)
	if err != nil {
		t.Fatalf("new server a: %v", err)
	}
	serverB, err := NewServerWithRuntimeOptionsAndRecorder(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:        "error",
		LogFormat:       "text",
		ErrWriter:       io.Discard,
		UpstreamServers: []UpstreamServerConfig{upstream},
	}, recorderB)
	if err != nil {
		t.Fatalf("new server b: %v", err)
	}
	t.Cleanup(func() { _ = serverA.Close() })
	t.Cleanup(func() { _ = serverB.Close() })

	respA := serverA.handleRequest(Request{
		ID:     "one",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-1", "reason": "test"}),
	})
	if respA.Error != "" {
		t.Fatalf("server A call: %+v", respA)
	}
	respB := serverB.handleRequest(Request{
		ID:     "two",
		Method: "upstream_retail_refund_request",
		Params: mustJSONBytes(map[string]any{"order_id": "ORD-2", "reason": "test"}),
	})
	if respB.Error != "" {
		t.Fatalf("server B call: %+v", respB)
	}

	hashA := completedEnvShapeHash(t, recorderA.snapshot())
	hashB := completedEnvShapeHash(t, recorderB.snapshot())
	if hashA == "" || hashB == "" {
		t.Fatalf("expected env shape hash in audit metadata, got a=%q b=%q", hashA, hashB)
	}
	if hashA != hashB {
		t.Fatalf("expected deterministic env shape hash, got %q and %q", hashA, hashB)
	}
}

func helperEnvMap(t *testing.T, result any) map[string]string {
	t.Helper()
	payload, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T", result)
	}
	rawEnv, ok := payload["env"].(map[string]any)
	if !ok {
		t.Fatalf("expected env map, got %+v", payload)
	}
	out := map[string]string{}
	for key, value := range rawEnv {
		text, _ := value.(string)
		out[key] = text
	}
	return out
}

func completedEnvShapeHash(t *testing.T, events []audit.Event) string {
	t.Helper()
	for _, event := range events {
		if event.EventType != "action.completed" {
			continue
		}
		if event.ExecutorMetadata == nil {
			continue
		}
		if hash, _ := event.ExecutorMetadata["upstream_env_shape_hash"].(string); hash != "" {
			return hash
		}
	}
	t.Fatal("missing upstream env shape hash in completed audit event")
	return ""
}

func containsForwardedTool(tools []map[string]any, name string) bool {
	for _, tool := range tools {
		if got, _ := tool["name"].(string); got == name {
			return true
		}
	}
	return false
}
