package mcp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/action"
)

const (
	ansiReset  = "\x1b[0m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
)

func formatToolResult(name string, result any) (string, error) {
	resp, ok := result.(action.Response)
	if !ok {
		data, err := json.Marshal(result)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	return formatActionToolResult(name, resp), nil
}

func formatToolResultContent(name string, result any) ([]map[string]any, error) {
	resp, ok := result.(action.Response)
	if ok {
		return actionResponseContentBlocks(name, resp), nil
	}
	text, err := formatToolResult(name, result)
	if err != nil {
		return nil, err
	}
	return []map[string]any{{"type": "text", "text": text}}, nil
}

func actionResponseContentBlocks(name string, resp action.Response) []map[string]any {
	blocks := []map[string]any{{
		"type": "text",
		"text": formatActionToolResult(name, resp),
	}}
	for _, block := range resp.MCPContentBlocks {
		blocks = append(blocks, cloneContentBlock(block))
	}
	return blocks
}

func formatActionToolResult(name string, resp action.Response) string {
	actionLabel := toolActionLabel(name)
	headline := fmt.Sprintf("%s %s %s", colorDecision(resp.Decision), actionLabel, formatDecisionSummary(actionLabel, resp))
	details := actionDetails(resp)
	if details == "" {
		return headline
	}
	return headline + "\n\n" + details
}

func toolActionLabel(name string) string {
	switch name {
	case "nomos.fs_read":
		return "fs.read"
	case "nomos.fs_write":
		return "fs.write"
	case "nomos.apply_patch":
		return "repo.apply_patch"
	case "nomos.exec":
		return "process.exec"
	case "nomos.http_request":
		return "net.http_request"
	default:
		return name
	}
}

func colorDecision(decision string) string {
	switch strings.ToUpper(strings.TrimSpace(decision)) {
	case "ALLOW":
		return ansiGreen + "ALLOW" + ansiReset
	case "REQUIRE_APPROVAL":
		return ansiYellow + "APPROVAL" + ansiReset
	case "DENY":
		return ansiRed + "DENY" + ansiReset
	default:
		return strings.ToUpper(strings.TrimSpace(decision))
	}
}

func formatDecisionSummary(actionLabel string, resp action.Response) string {
	switch strings.ToUpper(strings.TrimSpace(resp.Decision)) {
	case "ALLOW":
		switch actionLabel {
		case "fs.read":
			if resp.Truncated {
				return "allowed and content returned (truncated)"
			}
			return "allowed and content returned"
		case "fs.write", "repo.apply_patch":
			if resp.BytesWritten > 0 {
				return fmt.Sprintf("allowed and wrote %d bytes", resp.BytesWritten)
			}
			return "allowed"
		case "process.exec":
			return fmt.Sprintf("allowed and completed with exit code %d", resp.ExitCode)
		case "net.http_request":
			if resp.StatusCode > 0 {
				return fmt.Sprintf("allowed and returned HTTP %d", resp.StatusCode)
			}
			return "allowed"
		default:
			return "allowed"
		}
	case "REQUIRE_APPROVAL":
		if resp.ApprovalID != "" {
			return fmt.Sprintf("requires approval (%s)", resp.ApprovalID)
		}
		return "requires approval"
	case "DENY":
		if resp.Reason != "" {
			return fmt.Sprintf("denied by policy (%s)", resp.Reason)
		}
		return "denied by policy"
	default:
		if resp.Reason != "" {
			return strings.ToLower(resp.Reason)
		}
		return strings.ToLower(strings.TrimSpace(resp.Decision))
	}
}

func actionDetails(resp action.Response) string {
	parts := make([]string, 0, 6)
	if strings.EqualFold(strings.TrimSpace(resp.Decision), "REQUIRE_APPROVAL") {
		meta := make([]string, 0, 3)
		if resp.ApprovalID != "" {
			meta = append(meta, "approval_id: "+resp.ApprovalID)
		}
		if resp.ApprovalFingerprint != "" {
			meta = append(meta, "approval_fingerprint: "+resp.ApprovalFingerprint)
		}
		if resp.ApprovalExpiresAt != "" {
			meta = append(meta, "approval_expires_at: "+resp.ApprovalExpiresAt)
		}
		if len(meta) > 0 {
			parts = append(parts, strings.Join(meta, "\n"))
		}
	}
	if output := strings.TrimSpace(resp.Output); output != "" {
		parts = append(parts, output)
	}
	if stdout := strings.TrimSpace(resp.Stdout); stdout != "" {
		parts = append(parts, "stdout:\n"+stdout)
	}
	if stderr := strings.TrimSpace(resp.Stderr); stderr != "" {
		parts = append(parts, "stderr:\n"+stderr)
	}
	return strings.Join(parts, "\n\n")
}
