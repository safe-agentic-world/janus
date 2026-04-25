package mcp

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/normalize"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

func TestToolsListAllowApprovalAndDenyModes(t *testing.T) {
	server := newToolDiscoveryTestServer(t, `{"version":"v1","rules":[
		{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},
		{"id":"approval-write","action_type":"fs.write","resource":"file://workspace/**","decision":"REQUIRE_APPROVAL","principals":["system"],"agents":["nomos"],"environments":["dev"]},
		{"id":"deny-http","action_type":"net.http_request","resource":"url://example.com/**","decision":"DENY","principals":["system"],"agents":["nomos"],"environments":["dev"]}
	]}`)

	tools := server.toolsList()
	if !toolListHasName(tools, "nomos_fs_read") {
		t.Fatalf("expected allow-only tool in list, got %+v", tools)
	}
	writeTool := toolListEntry(tools, "nomos_fs_write")
	if writeTool == nil {
		t.Fatalf("expected approval tool in list, got %+v", tools)
	}
	meta, ok := writeTool["_meta"].(map[string]any)
	if !ok || meta["approval_required"] != true {
		t.Fatalf("expected approval_required metadata on fs_write, got %+v", writeTool)
	}
	if toolListHasName(tools, "nomos_http_request") {
		t.Fatalf("did not expect denied tool in list, got %+v", tools)
	}
}

func TestToolsListFailsClosedOnExternalPolicyError(t *testing.T) {
	server := newToolDiscoveryTestServer(t, `{"version":"v1","rules":[
		{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}
	]}`)
	server.service.SetExternalPolicy(&failingExternalPolicy{err: io.ErrClosedPipe})

	tools := server.toolsList()
	if toolListHasName(tools, "nomos_fs_read") {
		t.Fatalf("expected fail-closed discovery to hide fs_read, got %+v", tools)
	}
	if !toolListHasName(tools, "nomos_capabilities") {
		t.Fatalf("expected capabilities to remain advertised, got %+v", tools)
	}
}

func TestToolsListAuditMetadataRecorded(t *testing.T) {
	recorder := &recordingSink{}
	server := newToolDiscoveryTestServerWithRecorder(t, `{"version":"v1","rules":[
		{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},
		{"id":"approval-write","action_type":"fs.write","resource":"file://workspace/**","decision":"REQUIRE_APPROVAL","principals":["system"],"agents":["nomos"],"environments":["dev"]}
	]}`, recorder)

	resp := server.handleRPCRequest(rpcRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`"tools-1"`),
		Method:  "tools/list",
		Params:  []byte(`{}`),
	}, nil)
	if resp == nil || resp.Error != nil {
		t.Fatalf("unexpected tools/list response: %+v", resp)
	}
	events := recorder.snapshot()
	var found bool
	for _, event := range events {
		if event.EventType != "mcp.tools_list" {
			continue
		}
		found = true
		if event.Principal != "system" || event.Agent != "nomos" || event.Environment != "dev" {
			t.Fatalf("unexpected audit identity: %+v", event)
		}
		if event.Resource != "mcp://tools/list" || event.ActionType != "mcp.tools_list" {
			t.Fatalf("unexpected audit action fields: %+v", event)
		}
		if event.ExecutorMetadata == nil {
			t.Fatalf("missing executor metadata: %+v", event)
		}
		if got, ok := event.ExecutorMetadata["principal"].(string); !ok || got != "system" {
			t.Fatalf("missing principal metadata: %+v", event.ExecutorMetadata)
		}
		if got, ok := event.ExecutorMetadata["tool_surface"].(string); !ok || got != "tools/list" {
			t.Fatalf("missing tool surface metadata: %+v", event.ExecutorMetadata)
		}
		if got, ok := event.ExecutorMetadata["evaluated_tools"].(int); !ok || got == 0 {
			t.Fatalf("missing evaluated tools metadata: %+v", event.ExecutorMetadata)
		}
		if got, ok := event.ExecutorMetadata["hidden_tools"].(int); !ok || got == 0 {
			t.Fatalf("missing hidden tools metadata: %+v", event.ExecutorMetadata)
		}
	}
	if !found {
		t.Fatalf("expected mcp.tools_list audit event, got %+v", events)
	}
}

type failingExternalPolicy struct {
	err error
}

func (f *failingExternalPolicy) Evaluate(normalize.NormalizedAction) (policy.Decision, error) {
	if f != nil && f.err != nil {
		return policy.Decision{}, f.err
	}
	return policy.Decision{}, io.ErrClosedPipe
}

func newToolDiscoveryTestServer(t *testing.T, bundle string) *Server {
	t.Helper()
	return newToolDiscoveryTestServerWithRecorder(t, bundle, &recordingSink{})
}

func newToolDiscoveryTestServerWithRecorder(t *testing.T, bundle string, recorder *recordingSink) *Server {
	t.Helper()
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServerWithRuntimeOptionsAndRecorder(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 1024, 10, false, false, "local", RuntimeOptions{
		LogLevel:  "error",
		LogFormat: "text",
		ErrWriter: io.Discard,
	}, recorder)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server
}

func toolListHasName(tools []map[string]any, name string) bool {
	return toolListEntry(tools, name) != nil
}

func toolListEntry(tools []map[string]any, name string) map[string]any {
	for _, tool := range tools {
		if got, _ := tool["name"].(string); got == name {
			return tool
		}
	}
	return nil
}
