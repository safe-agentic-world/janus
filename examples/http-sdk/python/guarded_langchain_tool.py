from sdk.python.nomos_sdk import NomosClient, guard_http_tool


client = NomosClient(
    base_url="http://127.0.0.1:8080",
    bearer_token="dev-api-key",
    agent_id="demo-agent",
    agent_secret="demo-agent-secret",
)


def submit_refund(payload: dict[str, str]) -> str:
    return "refund-request-submitted"


refund_tool = guard_http_tool(
    client=client,
    resource_fn=lambda payload: f"url://shop.example.com/refunds/{payload['order_id']}",
    params_fn=lambda payload: {
        "method": "POST",
        "body": {"order_id": payload["order_id"], "reason": payload["reason"]},
    },
    execute_fn=submit_refund,
)


result = refund_tool.invoke({"order_id": "ORD-1001", "reason": "damaged on arrival"})
print(result.decision_response["decision"], result.executed, result.value)
