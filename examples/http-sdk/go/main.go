package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/safe-agentic-world/nomos/pkg/sdk"
)

func main() {
	client, err := sdk.NewClient(sdk.Config{
		BaseURL:     getenv("NOMOS_BASE_URL", "http://127.0.0.1:8080"),
		BearerToken: getenv("NOMOS_API_KEY", "dev-api-key"),
		AgentID:     getenv("NOMOS_AGENT_ID", "demo-agent"),
		AgentSecret: getenv("NOMOS_AGENT_SECRET", "demo-agent-secret"),
	})
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.RunAction(context.Background(), sdk.NewActionRequest("fs.read", "file://workspace/README.md", map[string]any{}))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("decision=%s action_id=%s trace_id=%s\n", resp.Decision, resp.ActionID, resp.TraceID)
}

func getenv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
