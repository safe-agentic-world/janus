package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safe-agentic-world/nomos/internal/assurance"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/service"
)

func TestCapabilitiesDifferByIdentity(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 64, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	resp := server.handleCapabilities(Request{ID: "1", Method: "nomos.capabilities"})
	tools, ok := resp.Result.(service.CapabilityEnvelope)
	if !ok {
		t.Fatalf("expected capability envelope")
	}
	found := false
	for _, tool := range tools.EnabledTools {
		if tool == "nomos.fs_read" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected fs_read to be enabled")
	}
	if state := tools.ToolStates["nomos.fs_read"].State; state != service.ToolStateAllow {
		t.Fatalf("expected fs_read allow state, got %+v", tools.ToolStates["nomos.fs_read"])
	}
	if !tools.AdvisoryOnly || tools.ContractVersion == "" || tools.CapabilitySetHash == "" {
		t.Fatalf("expected advisory capability contract metadata, got %+v", tools)
	}
	if mode := tools.ToolAdvertisementMode; mode != "mcp_tools_list_static" {
		t.Fatalf("expected static tool advertisement mode, got %+v", tools)
	}

	serverOther, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "other",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 64, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server other: %v", err)
	}
	respOther := serverOther.handleCapabilities(Request{ID: "2", Method: "nomos.capabilities"})
	toolsOther, ok := respOther.Result.(service.CapabilityEnvelope)
	if !ok {
		t.Fatalf("expected capability envelope")
	}
	for _, tool := range toolsOther.EnabledTools {
		if tool == "nomos.fs_read" {
			t.Fatal("did not expect fs_read to be enabled for other principal")
		}
	}
}

func TestValidateChangeSetBlocksForbiddenPaths(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"allow-docs","action_type":"repo.apply_patch","resource":"file://workspace/docs/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 64, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	params := `{"paths":["docs/readme.md","secrets.txt"]}`
	resp := server.handleValidateChangeSet(Request{ID: "1", Method: "repo.validate_change_set", Params: []byte(params)})
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected result map")
	}
	if result["allowed"].(bool) {
		t.Fatal("expected change set to be blocked")
	}
}

func TestCapabilitiesSurfaceAssuranceLevelAndNotice(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 64, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	server.SetAssuranceLevel(assurance.LevelBestEffort)

	resp := server.handleCapabilities(Request{ID: "1", Method: "nomos.capabilities"})
	tools, ok := resp.Result.(service.CapabilityEnvelope)
	if !ok {
		t.Fatalf("expected capability envelope")
	}
	if tools.AssuranceLevel != assurance.LevelBestEffort {
		t.Fatalf("expected assurance level %s, got %+v", assurance.LevelBestEffort, tools)
	}
	if tools.MediationNotice == "" {
		t.Fatalf("expected mediation notice for non-strong assurance, got %+v", tools)
	}
}

func TestCapabilitiesExposeExecWhenSafeBundleUsesExecMatch(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"deny-git-push","action_type":"process.exec","resource":"file://workspace/","decision":"DENY","principals":["system"],"agents":["nomos"],"environments":["dev"],"exec_match":{"argv_patterns":[["git","push","**"],["git","push"]]}},{"id":"allow-git","action_type":"process.exec","resource":"file://workspace/","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"],"exec_match":{"argv_patterns":[["git","**"],["git"]]},"obligations":{"sandbox_mode":"local"}}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 64, 10, false, true, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	resp := server.handleCapabilities(Request{ID: "1", Method: "nomos.capabilities"})
	tools, ok := resp.Result.(service.CapabilityEnvelope)
	if !ok {
		t.Fatalf("expected capability envelope")
	}
	found := false
	for _, tool := range tools.EnabledTools {
		if tool == "nomos.exec" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected nomos.exec enabled, got %+v", tools.EnabledTools)
	}
}

func TestCapabilitiesExposeHTTPWhenPolicyRequiresApproval(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"purchase-approval","action_type":"net.http_request","resource":"url://shop.example.com/checkout/**","decision":"REQUIRE_APPROVAL","principals":["system"],"agents":["nomos"],"environments":["dev"],"obligations":{"net_allowlist":["shop.example.com"],"approval_scope_class":"action_type_resource"}}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 64, 10, true, true, "local", RuntimeOptions{
		ApprovalStorePath:  filepath.Join(dir, "approvals.db"),
		ApprovalTTLSeconds: 600,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	resp := server.handleCapabilities(Request{ID: "1", Method: "nomos.capabilities"})
	tools, ok := resp.Result.(service.CapabilityEnvelope)
	if !ok {
		t.Fatalf("expected capability envelope")
	}
	found := false
	for _, tool := range tools.EnabledTools {
		if tool == "nomos.http_request" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected nomos.http_request enabled, got %+v", tools.EnabledTools)
	}
	if !tools.ApprovalsEnabled {
		t.Fatalf("expected approvals enabled, got %+v", tools)
	}
	if state := tools.ToolStates["nomos.http_request"].State; state != service.ToolStateRequireApproval {
		t.Fatalf("expected nomos.http_request require_approval state, got %+v", tools.ToolStates["nomos.http_request"])
	}
	if len(tools.ApprovalGatedTools) != 1 || tools.ApprovalGatedTools[0] != "nomos.http_request" {
		t.Fatalf("expected approval-gated http tool, got %+v", tools.ApprovalGatedTools)
	}
	if got := tools.ToolStates["nomos.http_request"].Constraints.HostClasses; len(got) != 1 || got[0] != "host_allowlist" {
		t.Fatalf("expected bounded host summary, got %+v", tools.ToolStates["nomos.http_request"])
	}
	if got := tools.ToolStates["nomos.http_request"].Constraints.ApprovalScopes; len(got) != 1 || got[0] != "action_type_resource" {
		t.Fatalf("expected approval scope class, got %+v", tools.ToolStates["nomos.http_request"])
	}
}

func TestCapabilitiesExposeReadToolForNarrowAllowedResource(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"allow-readme-only","action_type":"fs.read","resource":"file://workspace/README.md","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServer(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 64, 10, false, true, "local")
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	resp := server.handleCapabilities(Request{ID: "1", Method: "nomos.capabilities"})
	tools, ok := resp.Result.(service.CapabilityEnvelope)
	if !ok {
		t.Fatalf("expected capability envelope")
	}
	found := false
	for _, tool := range tools.EnabledTools {
		if tool == "nomos.fs_read" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected nomos.fs_read enabled, got %+v", tools.EnabledTools)
	}
	if state := tools.ToolStates["nomos.fs_read"].State; state != service.ToolStateAllow {
		t.Fatalf("expected nomos.fs_read allow state, got %+v", tools.ToolStates["nomos.fs_read"])
	}
	if got := tools.ToolStates["nomos.fs_read"].Constraints.ResourceClasses; len(got) != 1 || got[0] != "workspace_single_path" {
		t.Fatalf("expected narrow safe path-class disclosure, got %+v", tools.ToolStates["nomos.fs_read"])
	}
}

func TestCapabilitySetHashChangesAcrossSurfacedStates(t *testing.T) {
	dir := t.TempDir()
	allowBundlePath := filepath.Join(dir, "allow.json")
	approvalBundlePath := filepath.Join(dir, "approval.json")
	allowData := `{"version":"v1","rules":[{"id":"allow-read","action_type":"fs.read","resource":"file://workspace/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	approvalData := `{"version":"v1","rules":[{"id":"approve-read","action_type":"fs.read","resource":"file://workspace/**","decision":"REQUIRE_APPROVAL","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(allowBundlePath, []byte(allowData), 0o600); err != nil {
		t.Fatalf("write allow bundle: %v", err)
	}
	if err := os.WriteFile(approvalBundlePath, []byte(approvalData), 0o600); err != nil {
		t.Fatalf("write approval bundle: %v", err)
	}
	id := identity.VerifiedIdentity{Principal: "system", Agent: "nomos", Environment: "dev"}
	allowServer, err := NewServer(allowBundlePath, id, dir, 64, 10, false, false, "local")
	if err != nil {
		t.Fatalf("new allow server: %v", err)
	}
	approvalServer, err := NewServer(approvalBundlePath, id, dir, 64, 10, true, false, "local")
	if err != nil {
		t.Fatalf("new approval server: %v", err)
	}
	allowResp := allowServer.handleCapabilities(Request{ID: "1", Method: "nomos.capabilities"})
	approvalResp := approvalServer.handleCapabilities(Request{ID: "2", Method: "nomos.capabilities"})
	allowCaps := allowResp.Result.(service.CapabilityEnvelope)
	approvalCaps := approvalResp.Result.(service.CapabilityEnvelope)
	if allowCaps.CapabilitySetHash == approvalCaps.CapabilitySetHash {
		t.Fatalf("expected capability hash to differ across surfaced states: %q", allowCaps.CapabilitySetHash)
	}
}

func TestCapabilitiesOnlyAdvertiseApprovalsWhenMCPStoreIsConfigured(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"approval-write","action_type":"fs.write","resource":"file://workspace/**","decision":"REQUIRE_APPROVAL","principals":["system"],"agents":["nomos"],"environments":["dev"]}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	id := identity.VerifiedIdentity{Principal: "system", Agent: "nomos", Environment: "dev"}

	serverNoStore, err := NewServer(bundlePath, id, dir, 64, 10, true, false, "local")
	if err != nil {
		t.Fatalf("new server without store: %v", err)
	}
	respNoStore := serverNoStore.handleCapabilities(Request{ID: "1", Method: "nomos.capabilities"})
	capsNoStore := respNoStore.Result.(service.CapabilityEnvelope)
	if capsNoStore.ApprovalsEnabled {
		t.Fatalf("expected approvals disabled without configured MCP store, got %+v", capsNoStore)
	}

	serverWithStore, err := NewServerWithRuntimeOptions(bundlePath, id, dir, 64, 10, true, false, "local", RuntimeOptions{
		ApprovalStorePath:  filepath.Join(dir, "approvals.db"),
		ApprovalTTLSeconds: 600,
	})
	if err != nil {
		t.Fatalf("new server with store: %v", err)
	}
	t.Cleanup(func() { _ = serverWithStore.Close() })
	respWithStore := serverWithStore.handleCapabilities(Request{ID: "2", Method: "nomos.capabilities"})
	capsWithStore := respWithStore.Result.(service.CapabilityEnvelope)
	if !capsWithStore.ApprovalsEnabled {
		t.Fatalf("expected approvals enabled with configured MCP store, got %+v", capsWithStore)
	}
}

func TestHandleHTTPRequestHonorsConfiguredUpstreamRoutes(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data := `{"version":"v1","rules":[{"id":"allow-http","action_type":"net.http_request","resource":"url://api.example.com/**","decision":"ALLOW","principals":["system"],"agents":["nomos"],"environments":["dev"],"obligations":{"net_allowlist":["api.example.com"]}}]}`
	if err := os.WriteFile(bundlePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 64, 10, false, false, "local", RuntimeOptions{
		UpstreamRoutes: []UpstreamRoute{{
			URL:        "https://api.example.com/v1",
			Methods:    []string{"GET"},
			PathPrefix: "/v1",
		}},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	allowed := server.handleHTTPRequest(Request{
		ID:     "1",
		Method: "nomos.http_request",
		Params: mustJSONBytes(map[string]any{"resource": "url://api.example.com/v1/status", "method": "GET"}),
	}, nil)
	if allowed.Error == "validation_error" {
		t.Fatalf("expected configured upstream route to pass precheck, got %+v", allowed)
	}

	blocked := server.handleHTTPRequest(Request{
		ID:     "2",
		Method: "nomos.http_request",
		Params: mustJSONBytes(map[string]any{"resource": "url://api.example.com/v2/status", "method": "GET"}),
	}, nil)
	if blocked.Error != "validation_error" {
		t.Fatalf("expected upstream mismatch validation_error, got %+v", blocked)
	}
}
