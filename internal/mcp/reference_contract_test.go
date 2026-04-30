package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/safe-agentic-world/nomos/internal/action"
	"github.com/safe-agentic-world/nomos/internal/identity"
	"github.com/safe-agentic-world/nomos/internal/policy"
)

const referenceContractEnv = "NOMOS_MCP_CONTRACT_TESTS"

type referenceContractManifest struct {
	SchemaVersion   string                 `json:"schema_version"`
	ProtocolVersion string                 `json:"protocol_version"`
	References      []referenceContractPin `json:"references"`
}

type referenceContractPin struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	Source      string   `json:"source"`
	Version     string   `json:"version"`
	Integrity   string   `json:"integrity"`
	Tarball     string   `json:"tarball"`
	Transports  []string `json:"transports"`
	Scenarios   []string `json:"scenarios"`
}

type referenceContractSpec struct {
	ID                   string
	ToolName             string
	ToolArgs             map[string]any
	InvalidToolArgs      map[string]any
	FingerprintArgsA     []byte
	FingerprintArgsB     []byte
	ResourceURI          string
	PromptName           string
	SamplingPromptName   string
	SupportsSampling     bool
	RepresentativeOutput string
}

func TestReferenceMCPContractSuite(t *testing.T) {
	if os.Getenv(referenceContractEnv) != "1" {
		t.Skipf("set %s=1 to run the MCP reference contract suite", referenceContractEnv)
	}
	manifest := loadReferenceContractManifest(t)
	validateReferenceContractManifest(t, manifest)
	for _, pin := range manifest.References {
		pin := pin
		spec := referenceContractSpecForPin(t, pin)
		for _, transport := range pin.Transports {
			transport := transport
			t.Run(pin.ID+"/"+transport, func(t *testing.T) {
				runReferenceContractScenario(t, pin, spec, transport)
			})
		}
	}
}

func TestReferenceMCPContractEarlyUpstreamExitFailsClosed(t *testing.T) {
	if os.Getenv(referenceContractEnv) != "1" {
		t.Skipf("set %s=1 to run the MCP reference contract suite", referenceContractEnv)
	}
	dir := t.TempDir()
	spec := referenceContractSpec{
		ID:               "exit",
		ToolName:         "exit.now",
		ToolArgs:         map[string]any{"reason": "contract"},
		InvalidToolArgs:  map[string]any{"reason": 7},
		ResourceURI:      "contract://exit/resource",
		PromptName:       "exit.prompt",
		FingerprintArgsA: []byte(`{"reason":"contract"}`),
		FingerprintArgsB: []byte(`{"reason":"contract"}`),
	}
	server := newReferenceContractNomosServer(t, dir, spec, "stdio")
	t.Cleanup(func() { _ = server.Close() })
	resp := server.handleForwardedToolWithSession(Request{
		ID:     "early-exit",
		Method: downstreamToolName(spec.ID, spec.ToolName),
		Params: mustJSONBytes(spec.ToolArgs),
	}, newReferenceDownstreamSession(t, server, "unused"))
	if resp.Error != "UPSTREAM_UNAVAILABLE" && resp.Error != "execution_error" {
		t.Fatalf("expected fail-closed upstream exit error, got %+v", resp)
	}
}

func TestReferenceMCPContractHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_REFERENCE_MCP_HELPER") != "1" {
		return
	}
	if len(os.Args) < 4 {
		os.Exit(2)
	}
	spec := referenceContractSpecForID(os.Args[3])
	runReferenceContractStdioHelper(spec)
	os.Exit(0)
}

func runReferenceContractScenario(t *testing.T, pin referenceContractPin, spec referenceContractSpec, transport string) {
	t.Helper()
	dir := t.TempDir()
	server := newReferenceContractNomosServer(t, dir, spec, transport)
	t.Cleanup(func() { _ = server.Close() })
	session := newReferenceDownstreamSession(t, server, "sampled summary from downstream")

	initResp := server.handleRPCRequest(referenceRPCRequest("initialize", "initialize", map[string]any{
		"protocolVersion": SupportedProtocolVersion,
		"capabilities":    map[string]any{"sampling": map[string]any{}},
		"clientInfo":      map[string]any{"name": "nomos-contract", "version": "v1"},
	}), session)
	assertRPCSuccess(t, initResp)
	initResult := rpcResultMap(t, initResp)
	if initResult["protocolVersion"] != SupportedProtocolVersion {
		t.Fatalf("%s initialize protocol mismatch: %+v", pin.ID, initResult)
	}

	toolsResp := server.handleRPCRequest(referenceRPCRequest("tools", "tools/list", map[string]any{}), session)
	assertRPCSuccess(t, toolsResp)
	tools := rpcResultSlice(t, toolsResp, "tools")
	if !containsNamedEntry(tools, downstreamToolName(spec.ID, spec.ToolName)) {
		t.Fatalf("%s %s tools/list missing forwarded tool, got %+v", pin.ID, transport, tools)
	}

	callResp := server.handleRPCRequest(referenceRPCRequest("call", "tools/call", map[string]any{
		"name":      downstreamToolName(spec.ID, spec.ToolName),
		"arguments": spec.ToolArgs,
	}), session)
	assertRPCSuccess(t, callResp)
	assertToolCallText(t, callResp, spec.RepresentativeOutput)

	invalidResp := server.handleRPCRequest(referenceRPCRequest("invalid", "tools/call", map[string]any{
		"name":      downstreamToolName(spec.ID, spec.ToolName),
		"arguments": spec.InvalidToolArgs,
	}), session)
	assertToolCallError(t, invalidResp, upstreamArgumentValidationError)

	resourcesResp := server.handleRPCRequest(referenceRPCRequest("resources", "resources/list", map[string]any{}), session)
	assertRPCSuccess(t, resourcesResp)
	resources := rpcResultSlice(t, resourcesResp, "resources")
	resourceURI := downstreamResourceURI(spec.ID, spec.ResourceURI)
	if !containsURIEntry(resources, resourceURI) {
		t.Fatalf("%s %s resources/list missing %q, got %+v", pin.ID, transport, resourceURI, resources)
	}
	resourceReadResp := server.handleRPCRequest(referenceRPCRequest("resource-read", "resources/read", map[string]any{"uri": resourceURI}), session)
	assertRPCSuccess(t, resourceReadResp)
	if !strings.Contains(toJSONForTest(t, resourceReadResp.Result), "contract resource") {
		t.Fatalf("%s %s resources/read missing contract resource body: %+v", pin.ID, transport, resourceReadResp.Result)
	}

	promptsResp := server.handleRPCRequest(referenceRPCRequest("prompts", "prompts/list", map[string]any{}), session)
	assertRPCSuccess(t, promptsResp)
	prompts := rpcResultSlice(t, promptsResp, "prompts")
	promptName := downstreamPromptName(spec.ID, spec.PromptName)
	if !containsNamedEntry(prompts, promptName) {
		t.Fatalf("%s %s prompts/list missing %q, got %+v", pin.ID, transport, promptName, prompts)
	}
	promptResp := server.handleRPCRequest(referenceRPCRequest("prompt-get", "prompts/get", map[string]any{"name": promptName}), session)
	assertRPCSuccess(t, promptResp)
	if !strings.Contains(toJSONForTest(t, promptResp.Result), "contract prompt") {
		t.Fatalf("%s %s prompts/get missing contract prompt body: %+v", pin.ID, transport, promptResp.Result)
	}

	if spec.SupportsSampling && transport == "stdio" {
		samplingPrompt := downstreamPromptName(spec.ID, spec.SamplingPromptName)
		samplingResp := server.handleRPCRequest(referenceRPCRequest("prompt-sampling", "prompts/get", map[string]any{"name": samplingPrompt}), session)
		assertRPCSuccess(t, samplingResp)
		if !strings.Contains(toJSONForTest(t, samplingResp.Result), "sampled summary from downstream") {
			t.Fatalf("%s sampling prompt did not route through downstream sampling: %+v", pin.ID, samplingResp.Result)
		}
	}

	first := callForwardedForFingerprint(t, server, session, spec, "fingerprint-a", spec.FingerprintArgsA)
	second := callForwardedForFingerprint(t, server, session, spec, "fingerprint-b", spec.FingerprintArgsB)
	if first.ApprovalFingerprint == "" || first.ApprovalFingerprint != second.ApprovalFingerprint {
		t.Fatalf("%s %s expected stable canonical fingerprint, first=%q second=%q", pin.ID, transport, first.ApprovalFingerprint, second.ApprovalFingerprint)
	}

	unsupportedResp := server.handleRPCRequest(referenceRPCRequest("unsupported", "unsupported/method", map[string]any{}), session)
	if unsupportedResp == nil || unsupportedResp.Error == nil || unsupportedResp.Error.Code != -32601 {
		t.Fatalf("%s %s expected unsupported method JSON-RPC error, got %+v", pin.ID, transport, unsupportedResp)
	}

	if transport == "stdio" {
		envResult, err := server.upstream.sessionForTest(spec.ID).call(context.Background(), "env.inspect", map[string]any{})
		if err != nil {
			t.Fatalf("%s env inspect: %v", pin.ID, err)
		}
		env := envMapFromContractResult(t, envResult)
		if env["PATH"] != "" || env["SECRET_TOKEN"] != "" || env["ALLOWLISTED_VAR"] != "" {
			t.Fatalf("%s stdio upstream inherited env despite least-privilege defaults: %+v", pin.ID, env)
		}
	}
}

func loadReferenceContractManifest(t *testing.T) referenceContractManifest {
	t.Helper()
	path := filepath.Clean(filepath.Join("..", "..", "testdata", "mcp-contract", "reference-servers.json"))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read reference manifest: %v", err)
	}
	var manifest referenceContractManifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		t.Fatalf("decode reference manifest: %v", err)
	}
	return manifest
}

func validateReferenceContractManifest(t *testing.T, manifest referenceContractManifest) {
	t.Helper()
	if manifest.SchemaVersion != "nomos.mcp_reference_contract.v1" {
		t.Fatalf("unexpected reference manifest schema %q", manifest.SchemaVersion)
	}
	if manifest.ProtocolVersion != SupportedProtocolVersion {
		t.Fatalf("manifest protocol %q does not match implementation %q", manifest.ProtocolVersion, SupportedProtocolVersion)
	}
	if len(manifest.References) < 3 {
		t.Fatalf("expected at least three reference MCP servers, got %d", len(manifest.References))
	}
	ids := map[string]struct{}{}
	for _, ref := range manifest.References {
		if strings.TrimSpace(ref.ID) == "" || strings.TrimSpace(ref.Source) == "" || strings.TrimSpace(ref.Version) == "" {
			t.Fatalf("reference pin missing id/source/version: %+v", ref)
		}
		if _, exists := ids[ref.ID]; exists {
			t.Fatalf("duplicate reference id %q", ref.ID)
		}
		ids[ref.ID] = struct{}{}
		if !strings.HasPrefix(ref.Integrity, "sha512-") {
			t.Fatalf("reference %q is not pinned by sha512 integrity: %+v", ref.ID, ref)
		}
		if !strings.Contains(ref.Tarball, ref.Version) {
			t.Fatalf("reference %q tarball is not version-pinned: %+v", ref.ID, ref)
		}
		if !containsString(ref.Transports, "stdio") {
			t.Fatalf("reference %q missing stdio transport coverage", ref.ID)
		}
		if !containsString(ref.Scenarios, "tools/call") {
			t.Fatalf("reference %q missing tools/call scenario", ref.ID)
		}
	}
}

func referenceContractSpecForPin(t *testing.T, pin referenceContractPin) referenceContractSpec {
	t.Helper()
	return referenceContractSpecForID(pin.ID)
}

func referenceContractSpecForID(id string) referenceContractSpec {
	switch id {
	case "everything":
		return referenceContractSpec{
			ID:                   "everything",
			ToolName:             "echo",
			ToolArgs:             map[string]any{"message": "hello", "labels": map[string]any{"a": "1", "b": "2"}},
			InvalidToolArgs:      map[string]any{"message": 42, "labels": map[string]any{"a": "1"}},
			FingerprintArgsA:     []byte(`{"message":"hello","labels":{"b":"2","a":"1"}}`),
			FingerprintArgsB:     []byte(`{"labels":{"a":"1","b":"2"},"message":"hello"}`),
			ResourceURI:          "contract://everything/resource",
			PromptName:           "contract.summary",
			SamplingPromptName:   "contract.sample",
			SupportsSampling:     true,
			RepresentativeOutput: "everything echo hello",
		}
	case "filesystem":
		return referenceContractSpec{
			ID:                   "filesystem",
			ToolName:             "read_file",
			ToolArgs:             map[string]any{"path": "README.md", "encoding": "utf-8"},
			InvalidToolArgs:      map[string]any{"path": 42, "encoding": "utf-8"},
			FingerprintArgsA:     []byte(`{"path":"README.md","encoding":"utf-8"}`),
			FingerprintArgsB:     []byte(`{"encoding":"utf-8","path":"README.md"}`),
			ResourceURI:          "contract://filesystem/readme",
			PromptName:           "file.review",
			RepresentativeOutput: "filesystem read README.md",
		}
	case "memory":
		return referenceContractSpec{
			ID:                   "memory",
			ToolName:             "remember",
			ToolArgs:             map[string]any{"key": "topic", "value": "nomos"},
			InvalidToolArgs:      map[string]any{"key": "topic", "value": 7},
			FingerprintArgsA:     []byte(`{"key":"topic","value":"nomos"}`),
			FingerprintArgsB:     []byte(`{"value":"nomos","key":"topic"}`),
			ResourceURI:          "contract://memory/topic",
			PromptName:           "memory.recall",
			RepresentativeOutput: "memory stored topic",
		}
	case "exit":
		return referenceContractSpec{
			ID:                   "exit",
			ToolName:             "exit.now",
			ToolArgs:             map[string]any{"reason": "contract"},
			InvalidToolArgs:      map[string]any{"reason": 7},
			FingerprintArgsA:     []byte(`{"reason":"contract"}`),
			FingerprintArgsB:     []byte(`{"reason":"contract"}`),
			ResourceURI:          "contract://exit/resource",
			PromptName:           "exit.prompt",
			RepresentativeOutput: "exit",
		}
	default:
		panic("unknown reference contract spec " + id)
	}
}

func newReferenceContractNomosServer(t *testing.T, dir string, spec referenceContractSpec, transport string) *Server {
	t.Helper()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(referenceContractPolicyBundle(spec)), 0o600); err != nil {
		t.Fatalf("write reference contract policy bundle: %v", err)
	}
	upstream := referenceContractUpstreamConfig(t, dir, spec, transport)
	server, err := NewServerWithRuntimeOptions(bundlePath, identity.VerifiedIdentity{
		Principal:   "system",
		Agent:       "nomos",
		Environment: "dev",
	}, dir, 2048, 20, false, false, "local", RuntimeOptions{
		LogLevel:        "error",
		LogFormat:       "text",
		ErrWriter:       io.Discard,
		UpstreamServers: []UpstreamServerConfig{upstream},
	})
	if err != nil {
		t.Fatalf("new reference contract server %s/%s: %v", spec.ID, transport, err)
	}
	return server
}

func referenceContractUpstreamConfig(t *testing.T, dir string, spec referenceContractSpec, transport string) UpstreamServerConfig {
	t.Helper()
	switch transport {
	case "stdio":
		return UpstreamServerConfig{
			Name:              spec.ID,
			Transport:         "stdio",
			Command:           os.Args[0],
			Args:              []string{"-test.run=TestReferenceMCPContractHelperProcess", "--", spec.ID},
			Env:               map[string]string{"GO_WANT_REFERENCE_MCP_HELPER": "1"},
			Workdir:           dir,
			InitializeTimeout: 2 * time.Second,
			EnumerateTimeout:  2 * time.Second,
			CallTimeout:       2 * time.Second,
		}
	case "streamable_http":
		server := newReferenceContractHTTPServer(t, spec)
		parsed, err := url.Parse(server.URL)
		if err != nil {
			t.Fatalf("parse reference http url: %v", err)
		}
		return UpstreamServerConfig{
			Name:              spec.ID,
			Transport:         "streamable_http",
			Endpoint:          server.URL + "/mcp",
			TLSInsecure:       true,
			AllowedHosts:      []string{parsed.Hostname()},
			InitializeTimeout: 2 * time.Second,
			EnumerateTimeout:  2 * time.Second,
			CallTimeout:       2 * time.Second,
			StreamTimeout:     250 * time.Millisecond,
		}
	default:
		t.Fatalf("unsupported reference contract transport %q", transport)
		return UpstreamServerConfig{}
	}
}

func referenceContractPolicyBundle(spec referenceContractSpec) string {
	rules := []map[string]any{
		referenceAllowRule("allow-"+spec.ID+"-tool", "mcp.call", "mcp://"+spec.ID+"/"+spec.ToolName),
		referenceAllowRule("allow-"+spec.ID+"-resource", "mcp.resource_read", "mcp://"+spec.ID+"/resource/**"),
		referenceAllowRule("allow-"+spec.ID+"-prompt", "mcp.prompt_get", "mcp://"+spec.ID+"/prompt/**"),
	}
	if spec.SupportsSampling {
		rules = append(rules,
			referenceAllowRule("allow-"+spec.ID+"-sample", "mcp.sample", downstreamSamplingActionResource(spec.ID)),
		)
	}
	payload := map[string]any{"version": "v1", "rules": rules}
	data, _ := json.Marshal(payload)
	return string(data)
}

func referenceAllowRule(id, actionType, resource string) map[string]any {
	return map[string]any{
		"id":           id,
		"action_type":  actionType,
		"resource":     resource,
		"decision":     policy.DecisionAllow,
		"principals":   []string{"system"},
		"agents":       []string{"nomos"},
		"environments": []string{"dev"},
	}
}

func newReferenceContractHTTPServer(t *testing.T, spec referenceContractSpec) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "background stream not used by contract fixture", http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		method, _ := req["method"].(string)
		if method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		id := req["id"]
		result, rpcErr := referenceContractRPCResult(spec, method, req["params"])
		w.Header().Set("MCP-Session-Id", "contract-"+spec.ID)
		writeReferenceHTTPRPCResponse(w, id, result, rpcErr)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func runReferenceContractStdioHelper(spec referenceContractSpec) {
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	for {
		body, err := readMCPPayload(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			os.Exit(2)
		}
		var req map[string]any
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if err := dec.Decode(&req); err != nil {
			os.Exit(2)
		}
		method, _ := req["method"].(string)
		if method == "notifications/initialized" {
			continue
		}
		id := req["id"]
		result, rpcErr := referenceContractRPCResultWithIO(spec, method, req["params"], reader, writer)
		writeReferenceStdioRPCResponse(writer, id, result, rpcErr)
	}
}

func referenceContractRPCResult(spec referenceContractSpec, method string, rawParams any) (any, *rpcError) {
	return referenceContractRPCResultWithIO(spec, method, rawParams, nil, nil)
}

func referenceContractRPCResultWithIO(spec referenceContractSpec, method string, rawParams any, reader *bufio.Reader, writer *bufio.Writer) (any, *rpcError) {
	switch method {
	case "initialize":
		return map[string]any{
			"protocolVersion": SupportedProtocolVersion,
			"capabilities": map[string]any{
				"tools":     map[string]any{"listChanged": false},
				"resources": map[string]any{"listChanged": false},
				"prompts":   map[string]any{"listChanged": false},
			},
			"serverInfo": map[string]any{"name": spec.ID + "-reference", "version": "contract"},
		}, nil
	case "env.inspect":
		return map[string]any{"env": map[string]any{
			"PATH":            os.Getenv("PATH"),
			"SECRET_TOKEN":    os.Getenv("SECRET_TOKEN"),
			"ALLOWLISTED_VAR": os.Getenv("ALLOWLISTED_VAR"),
		}}, nil
	case "tools/list":
		return map[string]any{"tools": []map[string]any{{
			"name":        spec.ToolName,
			"description": "Contract fixture for " + spec.ID,
			"inputSchema": referenceToolSchema(spec),
		}}}, nil
	case "tools/call":
		params, _ := rawParams.(map[string]any)
		name, _ := params["name"].(string)
		if name != spec.ToolName {
			return nil, &rpcError{Code: -32602, Message: "unknown tool"}
		}
		if spec.ID == "exit" {
			os.Exit(0)
		}
		return map[string]any{
			"content": []map[string]any{{
				"type": "text",
				"text": referenceToolOutput(spec, params["arguments"]),
			}},
			"isError": false,
		}, nil
	case "resources/list":
		return map[string]any{"resources": []map[string]any{{
			"uri":         spec.ResourceURI,
			"name":        spec.ID + " contract resource",
			"description": "Deterministic contract resource.",
			"mimeType":    "text/plain",
		}}}, nil
	case "resources/read":
		params, _ := rawParams.(map[string]any)
		if uri, _ := params["uri"].(string); uri != spec.ResourceURI {
			return nil, &rpcError{Code: -32602, Message: "unknown resource"}
		}
		return map[string]any{"contents": []map[string]any{{
			"uri":      spec.ResourceURI,
			"mimeType": "text/plain",
			"text":     "contract resource for " + spec.ID,
		}}}, nil
	case "prompts/list":
		prompts := []map[string]any{{
			"name":        spec.PromptName,
			"description": "Contract prompt for " + spec.ID,
		}}
		if spec.SupportsSampling {
			prompts = append(prompts, map[string]any{
				"name":        spec.SamplingPromptName,
				"description": "Contract prompt that requests downstream sampling.",
			})
		}
		return map[string]any{"prompts": prompts}, nil
	case "prompts/get":
		params, _ := rawParams.(map[string]any)
		name, _ := params["name"].(string)
		switch name {
		case spec.PromptName:
			return map[string]any{
				"description": "contract prompt for " + spec.ID,
				"messages": []map[string]any{{
					"role":    "user",
					"content": map[string]any{"type": "text", "text": "contract prompt for " + spec.ID},
				}},
			}, nil
		case spec.SamplingPromptName:
			if !spec.SupportsSampling {
				return nil, &rpcError{Code: -32602, Message: "unknown prompt"}
			}
			if reader == nil || writer == nil {
				return nil, &rpcError{Code: -32603, Message: "sampling requires stdio fixture"}
			}
			samplingResp, err := helperSamplingRoundTrip(reader, writer, spec.ID, map[string]any{
				"messages": []map[string]any{{
					"role":    "user",
					"content": map[string]any{"type": "text", "text": "sample for " + spec.ID},
				}},
				"maxTokens": 32,
			})
			if err != nil {
				return nil, &rpcError{Code: -32603, Message: err.Error()}
			}
			return map[string]any{
				"description": "contract sampled prompt for " + spec.ID,
				"messages": []map[string]any{{
					"role":    "assistant",
					"content": samplingResp,
				}},
			}, nil
		default:
			return nil, &rpcError{Code: -32602, Message: "unknown prompt"}
		}
	default:
		return nil, &rpcError{Code: -32601, Message: "method not found"}
	}
}

func referenceToolSchema(spec referenceContractSpec) map[string]any {
	switch spec.ID {
	case "everything":
		return map[string]any{
			"type": "object",
			"properties": map[string]any{
				"message": map[string]any{"type": "string"},
				"labels":  map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}},
			},
			"required":             []string{"message"},
			"additionalProperties": false,
		}
	case "filesystem":
		return map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path":     map[string]any{"type": "string"},
				"encoding": map[string]any{"type": "string"},
			},
			"required":             []string{"path"},
			"additionalProperties": false,
		}
	case "memory":
		return map[string]any{
			"type": "object",
			"properties": map[string]any{
				"key":   map[string]any{"type": "string"},
				"value": map[string]any{"type": "string"},
			},
			"required":             []string{"key", "value"},
			"additionalProperties": false,
		}
	case "exit":
		return map[string]any{
			"type":                 "object",
			"properties":           map[string]any{"reason": map[string]any{"type": "string"}},
			"required":             []string{"reason"},
			"additionalProperties": false,
		}
	default:
		return map[string]any{"type": "object", "additionalProperties": true}
	}
}

func referenceToolOutput(spec referenceContractSpec, rawArgs any) string {
	args, _ := rawArgs.(map[string]any)
	switch spec.ID {
	case "everything":
		message, _ := args["message"].(string)
		return "everything echo " + message
	case "filesystem":
		path, _ := args["path"].(string)
		return "filesystem read " + path
	case "memory":
		key, _ := args["key"].(string)
		return "memory stored " + key
	default:
		return spec.RepresentativeOutput
	}
}

func writeReferenceStdioRPCResponse(writer *bufio.Writer, id any, result any, rpcErr *rpcError) {
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if rpcErr != nil {
		resp["error"] = rpcErr
	} else {
		resp["result"] = result
	}
	data, _ := json.Marshal(resp)
	_, _ = writer.Write(data)
	_ = writer.WriteByte('\n')
	_ = writer.Flush()
}

func writeReferenceHTTPRPCResponse(w http.ResponseWriter, id any, result any, rpcErr *rpcError) {
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if rpcErr != nil {
		resp["error"] = rpcErr
	} else {
		resp["result"] = result
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func newReferenceDownstreamSession(t *testing.T, server *Server, sampledText string) *downstreamSession {
	t.Helper()
	return newSamplingClientSession(t, server, sampledText)
}

func referenceRPCRequest(id, method string, params any) rpcRequest {
	return rpcRequest{
		JSONRPC: "2.0",
		ID:      mustJSONBytes(id),
		Method:  method,
		Params:  mustJSONBytes(params),
	}
}

func callForwardedForFingerprint(t *testing.T, server *Server, session *downstreamSession, spec referenceContractSpec, id string, args []byte) action.Response {
	t.Helper()
	resp := server.handleForwardedToolWithSession(Request{
		ID:     id,
		Method: downstreamToolName(spec.ID, spec.ToolName),
		Params: args,
	}, session)
	if resp.Error != "" {
		t.Fatalf("%s fingerprint forwarded call failed: %+v", spec.ID, resp)
	}
	actionResp, ok := resp.Result.(action.Response)
	if !ok {
		t.Fatalf("%s expected action response, got %+T", spec.ID, resp.Result)
	}
	if actionResp.Decision != policy.DecisionAllow || actionResp.ExecutionMode != "mcp_forwarded" {
		t.Fatalf("%s expected forwarded allow, got %+v", spec.ID, actionResp)
	}
	return actionResp
}

func assertRPCSuccess(t *testing.T, resp *rpcResponse) {
	t.Helper()
	if resp == nil {
		t.Fatal("expected rpc response")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected rpc error: %+v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatalf("expected rpc result: %+v", resp)
	}
}

func rpcResultMap(t *testing.T, resp *rpcResponse) map[string]any {
	t.Helper()
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %+T: %+v", resp.Result, resp.Result)
	}
	return result
}

func rpcResultSlice(t *testing.T, resp *rpcResponse, key string) []map[string]any {
	t.Helper()
	result := rpcResultMap(t, resp)
	raw, ok := result[key]
	if !ok {
		t.Fatalf("result missing %q: %+v", key, result)
	}
	items, ok := raw.([]map[string]any)
	if ok {
		return items
	}
	anyItems, ok := raw.([]any)
	if !ok {
		t.Fatalf("expected %q slice, got %+T", key, raw)
	}
	out := make([]map[string]any, 0, len(anyItems))
	for _, item := range anyItems {
		m, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("expected %q map item, got %+T", key, item)
		}
		out = append(out, m)
	}
	return out
}

func assertToolCallText(t *testing.T, resp *rpcResponse, want string) {
	t.Helper()
	result := rpcResultMap(t, resp)
	if isError, _ := result["isError"].(bool); isError {
		t.Fatalf("expected successful tool call, got %+v", result)
	}
	text := toolCallText(t, result)
	if !strings.Contains(text, want) {
		t.Fatalf("expected tool call text to contain %q, got %q", want, text)
	}
}

func assertToolCallError(t *testing.T, resp *rpcResponse, want string) {
	t.Helper()
	assertRPCSuccess(t, resp)
	result := rpcResultMap(t, resp)
	if isError, _ := result["isError"].(bool); !isError {
		t.Fatalf("expected tool call error result, got %+v", result)
	}
	text := toolCallText(t, result)
	if !strings.Contains(text, want) {
		t.Fatalf("expected tool call error to contain %q, got %q", want, text)
	}
}

func toolCallText(t *testing.T, result map[string]any) string {
	t.Helper()
	raw, ok := result["content"]
	if !ok {
		t.Fatalf("tool result missing content: %+v", result)
	}
	items, ok := raw.([]map[string]any)
	if ok && len(items) > 0 {
		text, _ := items[0]["text"].(string)
		return text
	}
	stringItems, ok := raw.([]map[string]string)
	if ok && len(stringItems) > 0 {
		return stringItems[0]["text"]
	}
	anyItems, ok := raw.([]any)
	if ok && len(anyItems) > 0 {
		item, _ := anyItems[0].(map[string]any)
		text, _ := item["text"].(string)
		return text
	}
	t.Fatalf("invalid tool content: %+v", raw)
	return ""
}

func containsNamedEntry(items []map[string]any, name string) bool {
	for _, item := range items {
		if item["name"] == name {
			return true
		}
	}
	return false
}

func containsURIEntry(items []map[string]any, uri string) bool {
	for _, item := range items {
		if item["uri"] == uri {
			return true
		}
	}
	return false
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func envMapFromContractResult(t *testing.T, result any) map[string]string {
	t.Helper()
	outer, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected env inspect map, got %+T", result)
	}
	rawEnv, ok := outer["env"].(map[string]any)
	if !ok {
		t.Fatalf("expected env map, got %+v", outer)
	}
	env := map[string]string{}
	for key, value := range rawEnv {
		env[key], _ = value.(string)
	}
	return env
}

func toJSONForTest(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal test value: %v", err)
	}
	return string(data)
}

func TestReferenceContractManifestOrderIsDeterministic(t *testing.T) {
	manifest := loadReferenceContractManifest(t)
	ids := make([]string, 0, len(manifest.References))
	for _, ref := range manifest.References {
		ids = append(ids, ref.ID)
	}
	sorted := append([]string{}, ids...)
	sort.Strings(sorted)
	if strings.Join(ids, "\x00") != strings.Join(sorted, "\x00") {
		t.Fatalf("reference manifest order must be deterministic: got %v want %v", ids, sorted)
	}
}
