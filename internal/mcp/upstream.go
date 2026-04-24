package mcp

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

type upstreamTool struct {
	ServerName     string
	ToolName       string
	DownstreamName string
	Description    string
	InputSchema    map[string]any
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

func writeUpstreamRPCResponse(writer *bufio.Writer, resp *rpcResponse) error {
	data, err := json.Marshal(resp)
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
