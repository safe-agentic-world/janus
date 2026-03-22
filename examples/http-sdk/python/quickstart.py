from sdk.python.nomos_sdk import ActionRequest, NomosClient


client = NomosClient(
    base_url="http://127.0.0.1:8080",
    bearer_token="dev-api-key",
    agent_id="demo-agent",
    agent_secret="demo-agent-secret",
)

response = client.run_action(
    ActionRequest(
        action_type="fs.read",
        resource="file://workspace/README.md",
        params={},
    )
)
print(response)
