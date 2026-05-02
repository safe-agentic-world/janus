package mcp

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
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

func TestFriendlyAliasesCanonicalizeCoreTools(t *testing.T) {
	tests := map[string]string{
		"read_file":    "nomos.fs_read",
		"write_file":   "nomos.fs_write",
		"apply_patch":  "nomos.apply_patch",
		"run_command":  "nomos.exec",
		"http_request": "nomos.http_request",
	}
	for friendly, canonical := range tests {
		if got := canonicalToolName(friendly); got != canonical {
			t.Fatalf("%s canonicalized to %s, want %s", friendly, got, canonical)
		}
	}
}

func TestToolsListFriendlySurfaceAdvertisesDefaultToolNames(t *testing.T) {
	server := newToolDiscoveryTestServerWithOptions(t, `{"version":"v1","rules":[
		{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},
		{"id":"allow-write","action_type":"fs.write","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},
		{"id":"allow-patch","action_type":"repo.apply_patch","resource":"repo://local/workspace","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},
		{"id":"allow-exec","action_type":"process.exec","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},
		{"id":"allow-http","action_type":"net.http_request","resource":"url://example.com/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}
	]}`, RuntimeOptions{ToolSurface: ToolSurfaceFriendly})

	tools := server.toolsList()
	for _, name := range []string{"read_file", "write_file", "apply_patch", "run_command", "http_request"} {
		entry := toolListEntry(tools, name)
		if entry == nil {
			t.Fatalf("expected friendly tool %q in list, got %+v", name, tools)
		}
		description, _ := entry["description"].(string)
		if !strings.Contains(description, "Default governed") || !strings.Contains(description, "Backed by Nomos") {
			t.Fatalf("expected default-governed description for %q, got %q", name, description)
		}
	}
	for _, name := range []string{"nomos_fs_read", "nomos_fs_write", "nomos_apply_patch", "nomos_exec", "nomos_http_request"} {
		if toolListHasName(tools, name) {
			t.Fatalf("did not expect canonical compatibility tool %q in friendly-only surface: %+v", name, tools)
		}
	}
}

func TestToolsListBothSurfaceAdvertisesFriendlyAndCompatibilityNames(t *testing.T) {
	server := newToolDiscoveryTestServerWithOptions(t, `{"version":"v1","rules":[
		{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},
		{"id":"allow-write","action_type":"fs.write","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},
		{"id":"allow-patch","action_type":"repo.apply_patch","resource":"repo://local/workspace","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},
		{"id":"allow-exec","action_type":"process.exec","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]},
		{"id":"allow-http","action_type":"net.http_request","resource":"url://example.com/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}
	]}`, RuntimeOptions{ToolSurface: ToolSurfaceBoth})

	tools := server.toolsList()
	for _, name := range []string{"read_file", "nomos_fs_read", "write_file", "nomos_fs_write", "apply_patch", "nomos_apply_patch", "run_command", "nomos_exec", "http_request", "nomos_http_request"} {
		if !toolListHasName(tools, name) {
			t.Fatalf("expected tool %q in both surface, got %+v", name, tools)
		}
	}
}

func TestFriendlyRunCommandUsesCanonicalProcessExecAudit(t *testing.T) {
	recorder := &recordingSink{}
	server := newToolDiscoveryTestServerWithOptionsAndRecorder(t, `{"version":"v1","rules":[
		{"id":"allow-exec","action_type":"process.exec","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}
	]}`, RuntimeOptions{ToolSurface: ToolSurfaceFriendly}, recorder)

	resp := server.handleRequest(Request{
		ID:     "friendly-exec",
		Method: "run_command",
		Params: mustJSONBytes(map[string]any{
			"argv": []string{"go", "version"},
		}),
	})
	if resp.Error != "" {
		t.Fatalf("unexpected run_command error: %+v", resp)
	}
	events := recorder.snapshot()
	var found bool
	for _, event := range events {
		if event.ActionType != "process.exec" {
			continue
		}
		found = true
		if event.Resource != "file://workspace/" {
			t.Fatalf("unexpected canonical exec resource: %+v", event)
		}
	}
	if !found {
		t.Fatalf("expected canonical process.exec audit event, got %+v", events)
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

// Regression for M63 vs M31 precedence: under a profile that allowlists
// process.exec for legitimate inputs but denies the synthetic discovery probe
// (argv=["echo","sample"]), the probe-based hider used to drop run_command from
// tools/list — letting the agent escape to native shell. The rule-based
// capability scan must keep run_command advertised because process.exec has
// matching ALLOW rules for the calling identity.
func TestToolsListAdvertisesRunCommandWhenProbeArgvIsNotAllowlisted(t *testing.T) {
	bundle := `{"version":"v1","rules":[
		{"id":"allow-exec-go-test","action_type":"process.exec","resource":"file://workspace/","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"],"exec_match":{"argv_patterns":[["go","test"],["go","test","**"]]}}
	]}`
	server := newToolDiscoveryTestServerWithOptions(t, bundle, RuntimeOptions{ToolSurface: ToolSurfaceFriendly})

	tools := server.toolsList()
	if !toolListHasName(tools, "run_command") {
		t.Fatalf("expected run_command to be advertised under M63 precedence even though probe argv [echo sample] is not on the allowlist, got %+v", tools)
	}
	if toolListHasName(tools, "http_request") {
		t.Fatalf("did not expect http_request to be advertised when no net.http_request rule matches identity, got %+v", tools)
	}
}

// Regression for M63 vs M31 precedence: under a profile that allowlists
// net.http_request for github.com only, the synthetic discovery probe to
// example.com used to default-deny and hide http_request entirely. The
// rule-based capability scan must keep http_request advertised because
// net.http_request has at least one matching ALLOW rule for the identity.
func TestToolsListAdvertisesHttpRequestWhenProbeHostIsNotAllowlisted(t *testing.T) {
	bundle := `{"version":"v1","rules":[
		{"id":"allow-http-github","action_type":"net.http_request","resource":"url://github.com/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}
	]}`
	server := newToolDiscoveryTestServerWithOptions(t, bundle, RuntimeOptions{ToolSurface: ToolSurfaceFriendly})

	tools := server.toolsList()
	if !toolListHasName(tools, "http_request") {
		t.Fatalf("expected http_request to be advertised under M63 precedence even though probe url example.com is not on the allowlist, got %+v", tools)
	}
}

// When net.http_request has only a REQUIRE_APPROVAL rule for the identity, the
// tool is advertised with approval_required metadata (not hidden, not
// immediately allowed).
func TestToolsListAdvertisesApprovalRequiredHttpRequest(t *testing.T) {
	bundle := `{"version":"v1","rules":[
		{"id":"approval-http","action_type":"net.http_request","resource":"url://api.example.com/**","decision":"REQUIRE_APPROVAL","principals":["system"],"agents":["nomos"],"environments":["dev"]}
	]}`
	server := newToolDiscoveryTestServerWithOptions(t, bundle, RuntimeOptions{ToolSurface: ToolSurfaceFriendly})

	tools := server.toolsList()
	entry := toolListEntry(tools, "http_request")
	if entry == nil {
		t.Fatalf("expected http_request advertised when REQUIRE_APPROVAL rule matches identity, got %+v", tools)
	}
	meta, ok := entry["_meta"].(map[string]any)
	if !ok || meta["approval_required"] != true {
		t.Fatalf("expected approval_required metadata on http_request, got %+v", entry)
	}
}

// When no rule references a given action_type for the calling identity at all,
// the corresponding direct tool stays hidden — M63 advertises governed tools,
// not ungoverned ones. This guards against regressing into "advertise
// everything" behavior.
func TestToolsListHidesDirectToolWhenNoRuleMatchesIdentity(t *testing.T) {
	bundle := `{"version":"v1","rules":[
		{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}
	]}`
	server := newToolDiscoveryTestServerWithOptions(t, bundle, RuntimeOptions{ToolSurface: ToolSurfaceFriendly})

	tools := server.toolsList()
	for _, hidden := range []string{"write_file", "apply_patch", "run_command", "http_request"} {
		if toolListHasName(tools, hidden) {
			t.Fatalf("expected %s hidden when no matching rule for its action_type exists, got %+v", hidden, tools)
		}
	}
	if !toolListHasName(tools, "read_file") {
		t.Fatalf("expected read_file advertised when fs.read rule matches identity, got %+v", tools)
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
	return newToolDiscoveryTestServerWithOptionsAndRecorder(t, bundle, RuntimeOptions{}, recorder)
}

func newToolDiscoveryTestServerWithOptions(t *testing.T, bundle string, options RuntimeOptions) *Server {
	t.Helper()
	return newToolDiscoveryTestServerWithOptionsAndRecorder(t, bundle, options, &recordingSink{})
}

func newToolDiscoveryTestServerWithOptionsAndRecorder(t *testing.T, bundle string, options RuntimeOptions, recorder *recordingSink) *Server {
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
		LogLevel:    firstNonEmpty(options.LogLevel, "error"),
		LogFormat:   firstNonEmpty(options.LogFormat, "text"),
		ErrWriter:   io.Discard,
		ToolSurface: options.ToolSurface,
	}, recorder)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
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
