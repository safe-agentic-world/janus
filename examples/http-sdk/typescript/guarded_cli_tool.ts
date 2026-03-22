import { NomosClient, guardSubprocessTool } from "../../../sdk/typescript/nomos_sdk";

type ExecInput = {
  argv: string[];
  cwd: string;
};

const client = new NomosClient({
  baseUrl: "http://127.0.0.1:8080",
  bearerToken: "dev-api-key",
  agentId: "demo-agent",
  agentSecret: "demo-agent-secret",
});

const guardedExec = guardSubprocessTool<ExecInput, string>({
  client,
  resource: () => "exec://workspace/tooling",
  params: (input) => ({
    argv: input.argv,
    cwd: input.cwd,
  }),
  execute: async () => "command-ran",
});

const result = await guardedExec.invoke({
  argv: ["git", "status"],
  cwd: "C:/workspace/repo",
});

console.log(result.decisionResponse.decision, result.executed, result.value);
