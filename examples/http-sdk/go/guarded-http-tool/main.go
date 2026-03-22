package main

import (
	"context"
	"fmt"
	"log"

	"github.com/safe-agentic-world/nomos/pkg/sdk"
)

type refundInput struct {
	OrderID string
	Reason  string
}

func main() {
	client, err := sdk.NewClient(sdk.Config{
		BaseURL:     "http://127.0.0.1:8080",
		BearerToken: "dev-api-key",
		AgentID:     "demo-agent",
		AgentSecret: "demo-agent-secret",
	})
	if err != nil {
		log.Fatal(err)
	}

	refundTool, err := sdk.NewGuardedHTTPTool(client,
		func(in refundInput) (string, error) {
			return "url://shop.example.com/refunds/" + in.OrderID, nil
		},
		func(in refundInput) (map[string]any, error) {
			return map[string]any{
				"method": "POST",
				"body": map[string]any{
					"order_id": in.OrderID,
					"reason":   in.Reason,
				},
			}, nil
		},
		func(ctx context.Context, in refundInput) (string, error) {
			return "refund-request-submitted", nil
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	result, err := refundTool.Invoke(context.Background(), refundInput{
		OrderID: "ORD-1001",
		Reason:  "damaged on arrival",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("decision=%s executed=%t value=%q\n", result.DecisionResponse.Decision, result.Executed, result.Value)
}
