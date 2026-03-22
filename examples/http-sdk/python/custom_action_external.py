from sdk.python.nomos_sdk import ActionRequest, NomosClient


client = NomosClient(
    base_url="http://127.0.0.1:8080",
    bearer_token="dev-api-key",
    agent_id="demo-agent",
    agent_secret="demo-agent-secret",
)


decision = client.run_action(
    ActionRequest(
        action_type="payments.refund",
        resource="payment://shop.example.com/orders/ORD-1001",
        params={
            "amount": "249.00",
            "currency": "USD",
            "reason": "damaged_on_arrival",
        },
    )
)

print(decision["decision"], decision.get("execution_mode"))

if decision["decision"] == "ALLOW" and decision.get("execution_mode") == "external_authorized":
    report = client.report_external_outcome(
        {
            "action_id": decision["action_id"],
            "trace_id": decision["trace_id"],
            "action_type": "payments.refund",
            "resource": "payment://shop.example.com/orders/ORD-1001",
            "outcome": "SUCCEEDED",
            "external_reference": "refund_123",
            "approval_fingerprint": decision.get("approval_fingerprint", ""),
        }
    )
    print(report["recorded"])
