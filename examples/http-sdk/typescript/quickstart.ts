import { NomosClient, createActionRequest } from "../../../sdk/typescript/nomos_sdk";

const client = new NomosClient({
  baseUrl: "http://127.0.0.1:8080",
  bearerToken: "dev-api-key",
  agentId: "demo-agent",
  agentSecret: "demo-agent-secret",
});

const response = await client.runAction(
  createActionRequest("fs.read", "file://workspace/README.md", {}),
);

console.log(response);
