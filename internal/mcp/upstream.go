package mcp

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

type upstreamTool struct {
	ServerName     string
	ToolName       string
	DownstreamName string
	Description    string
	InputSchema    map[string]any
}

type upstreamRegistry struct {
	serversByName map[string]UpstreamServerConfig
	toolsByName   map[string]upstreamTool
	tools         []upstreamTool
}

func loadUpstreamRegistry(configs []UpstreamServerConfig) (*upstreamRegistry, error) {
	if len(configs) == 0 {
		return &upstreamRegistry{
			serversByName: map[string]UpstreamServerConfig{},
			toolsByName:   map[string]upstreamTool{},
			tools:         []upstreamTool{},
		}, nil
	}
	registry := &upstreamRegistry{
		serversByName: map[string]UpstreamServerConfig{},
		toolsByName:   map[string]upstreamTool{},
		tools:         make([]upstreamTool, 0),
	}
	for _, config := range configs {
		registry.serversByName[config.Name] = config
		tools, err := fetchUpstreamTools(config)
		if err != nil {
			return nil, fmt.Errorf("load upstream mcp server %q: %w", config.Name, err)
		}
		for _, tool := range tools {
			if _, exists := registry.toolsByName[tool.DownstreamName]; exists {
				return nil, fmt.Errorf("duplicate forwarded tool name %q", tool.DownstreamName)
			}
			registry.toolsByName[tool.DownstreamName] = tool
			registry.tools = append(registry.tools, tool)
		}
	}
	return registry, nil
}

func fetchUpstreamTools(config UpstreamServerConfig) ([]upstreamTool, error) {
	result, err := callUpstreamRPC(config, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	payload, ok := result.(map[string]any)
	if !ok {
		return nil, errors.New("invalid upstream tools/list result")
	}
	rawTools, ok := payload["tools"].([]any)
	if !ok {
		return nil, errors.New("upstream tools/list missing tools")
	}
	tools := make([]upstreamTool, 0, len(rawTools))
	for _, item := range rawTools {
		raw, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("invalid upstream tool entry")
		}
		toolName, _ := raw["name"].(string)
		toolName = strings.TrimSpace(toolName)
		if toolName == "" {
			return nil, errors.New("upstream tool missing name")
		}
		description, _ := raw["description"].(string)
		schema, _ := raw["inputSchema"].(map[string]any)
		tools = append(tools, upstreamTool{
			ServerName:     config.Name,
			ToolName:       toolName,
			DownstreamName: downstreamToolName(config.Name, toolName),
			Description:    description,
			InputSchema:    cloneMap(schema),
		})
	}
	return tools, nil
}

func callUpstreamTool(config UpstreamServerConfig, toolName string, args json.RawMessage) (string, error) {
	arguments := map[string]any{}
	if len(bytes.TrimSpace(args)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(args))
		dec.UseNumber()
		if err := dec.Decode(&arguments); err != nil {
			return "", fmt.Errorf("invalid forwarded tool arguments: %w", err)
		}
	}
	result, err := callUpstreamRPC(config, "tools/call", map[string]any{
		"name":      toolName,
		"arguments": arguments,
	})
	if err != nil {
		return "", err
	}
	return stringifyUpstreamCallResult(result)
}

func callUpstreamRPC(config UpstreamServerConfig, method string, params map[string]any) (any, error) {
	if strings.TrimSpace(config.Transport) != "stdio" {
		return nil, errors.New("unsupported upstream mcp transport")
	}
	cmd := exec.Command(config.Command, config.Args...)
	if strings.TrimSpace(config.Workdir) != "" {
		cmd.Dir = config.Workdir
	}
	cmd.Env = os.Environ()
	for key, value := range config.Env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var stderrBuf bytes.Buffer
	var stderrReadErr error
	var stderrWG sync.WaitGroup
	stderrWG.Add(1)
	go func() {
		defer stderrWG.Done()
		if stderr == nil {
			return
		}
		_, stderrReadErr = io.Copy(&stderrBuf, stderr)
	}()
	defer func() {
		_ = stdin.Close()
		_ = stdout.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		_ = stderr.Close()
		stderrWG.Wait()
	}()
	reader := bufio.NewReader(stdout)
	writer := bufio.NewWriter(stdin)
	if err := writeUpstreamRPCRequest(writer, "initialize", "initialize", map[string]any{
		"protocolVersion": SupportedProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "nomos-upstream-gateway",
			"version": "v1",
		},
	}); err != nil {
		return nil, upstreamStageError(config, "initialize", err, stderrSnapshot(&stderrBuf, stderrReadErr))
	}
	initResp, err := readUpstreamRPCResponse(reader)
	if err != nil {
		return nil, upstreamStageError(config, "initialize", err, stderrSnapshot(&stderrBuf, stderrReadErr))
	}
	if initResp.Error != nil {
		return nil, upstreamStageError(config, "initialize", errors.New(initResp.Error.Message), stderrSnapshot(&stderrBuf, stderrReadErr))
	}
	if err := writeUpstreamRPCNotification(writer, "notifications/initialized", map[string]any{}); err != nil {
		return nil, upstreamStageError(config, "initialize", err, stderrSnapshot(&stderrBuf, stderrReadErr))
	}
	if err := writeUpstreamRPCRequest(writer, method, "2", params); err != nil {
		return nil, upstreamStageError(config, method, err, stderrSnapshot(&stderrBuf, stderrReadErr))
	}
	resp, err := readUpstreamRPCResponse(reader)
	if err != nil {
		return nil, upstreamStageError(config, method, err, stderrSnapshot(&stderrBuf, stderrReadErr))
	}
	if resp.Error != nil {
		return nil, upstreamStageError(config, method, errors.New(resp.Error.Message), stderrSnapshot(&stderrBuf, stderrReadErr))
	}
	return resp.Result, nil
}

func writeUpstreamRPCRequest(writer *bufio.Writer, method, id string, params map[string]any) error {
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := writer.Write(data); err != nil {
		return err
	}
	if err := writer.WriteByte('\n'); err != nil {
		return err
	}
	return writer.Flush()
}

func writeUpstreamRPCNotification(writer *bufio.Writer, method string, params map[string]any) error {
	req := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := writer.Write(data); err != nil {
		return err
	}
	if err := writer.WriteByte('\n'); err != nil {
		return err
	}
	return writer.Flush()
}

func readUpstreamRPCResponse(reader *bufio.Reader) (*rpcResponse, error) {
	body, err := readMCPPayload(reader)
	if err != nil {
		return nil, err
	}
	var resp rpcResponse
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func readMCPPayload(reader *bufio.Reader) ([]byte, error) {
	for {
		peek, err := reader.Peek(1)
		if err != nil {
			return nil, err
		}
		switch peek[0] {
		case '\r', '\n', ' ', '\t':
			if _, err := reader.ReadByte(); err != nil {
				return nil, err
			}
			continue
		case '{', '[':
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if errors.Is(err, io.EOF) && len(bytes.TrimSpace(line)) > 0 {
					return bytes.TrimSpace(line), nil
				}
				return nil, err
			}
			return bytes.TrimSpace(line), nil
		default:
			return readFramedPayload(reader)
		}
	}
}

func stringifyUpstreamCallResult(result any) (string, error) {
	payload, ok := result.(map[string]any)
	if !ok {
		data, err := json.Marshal(result)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	if isError, _ := payload["isError"].(bool); isError {
		return "", errors.New("upstream tool returned error")
	}
	content, ok := payload["content"].([]any)
	if !ok {
		data, err := json.Marshal(payload)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	var builder strings.Builder
	for _, item := range content {
		block, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if blockType, _ := block["type"].(string); blockType == "text" {
			if text, _ := block["text"].(string); text != "" {
				if builder.Len() > 0 {
					builder.WriteString("\n")
				}
				builder.WriteString(text)
			}
		}
	}
	if builder.Len() > 0 {
		return builder.String(), nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func downstreamToolName(serverName, toolName string) string {
	base := "upstream_" + sanitizeForwardedNamePart(serverName) + "_" + sanitizeForwardedNamePart(toolName)
	base = strings.Trim(base, "_")
	if base == "" {
		return "upstream_tool"
	}
	return base
}

func sanitizeForwardedNamePart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "tool"
	}
	var b strings.Builder
	lastUnderscore := false
	for _, r := range value {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_':
			b.WriteRune(r)
			lastUnderscore = false
		default:
			if !lastUnderscore {
				b.WriteByte('_')
				lastUnderscore = true
			}
		}
	}
	out := strings.Trim(b.String(), "_")
	if out != "" {
		return out
	}
	sum := sha256.Sum256([]byte(value))
	return "tool_" + fmt.Sprintf("%x", sum[:4])
}

func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func readAllStderr(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	return io.ReadAll(r)
}

func stderrSnapshot(buf *bytes.Buffer, readErr error) string {
	if readErr != nil || buf == nil {
		return ""
	}
	return strings.TrimSpace(buf.String())
}

func upstreamStageError(config UpstreamServerConfig, stage string, err error, stderr string) error {
	if err == nil {
		return nil
	}
	msg := fmt.Sprintf("upstream server %q failed during %s: %v", config.Name, stage, err)
	if stderr != "" {
		msg += "; stderr=" + summarizeStderr(stderr)
	}
	return errors.New(msg)
}

func summarizeStderr(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	if len(stderr) > 240 {
		return stderr[:240] + "..."
	}
	return stderr
}
