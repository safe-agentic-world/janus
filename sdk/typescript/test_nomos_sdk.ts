import assert from "node:assert/strict";
import http from "node:http";

import {
  GuardedFunction,
  NomosClient,
  createActionRequest,
  guardFunction,
  guardHttpTool,
} from "./nomos_sdk.ts";
import type { ActionRequest } from "./nomos_sdk.ts";

type CapturedRequest = {
  path: string;
  headers: http.IncomingHttpHeaders;
  payload: Record<string, unknown>;
};

async function startServer(responseFactory: () => { statusCode?: number; body: Record<string, unknown> }) {
  const captured: CapturedRequest[] = [];
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    req.on("end", () => {
      const payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      captured.push({ path: req.url ?? "", headers: req.headers, payload });
      const response = responseFactory();
      res.writeHead(response.statusCode ?? 200, { "content-type": "application/json" });
      res.end(JSON.stringify(response.body));
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("failed to resolve test server address");
  }
  return {
    server,
    baseUrl: `http://127.0.0.1:${address.port}`,
    captured,
  };
}

function createClient(baseUrl: string): NomosClient {
  return new NomosClient({
    baseUrl,
    bearerToken: "dev-api-key",
    agentId: "demo-agent",
    agentSecret: "demo-agent-secret",
  });
}

async function closeServer(server: http.Server): Promise<void> {
  await new Promise((resolve) => server.close(resolve));
}

async function testAllow(): Promise<void> {
  const { server, baseUrl } = await startServer(() => ({ body: { decision: "ALLOW" } }));
  try {
    const executed: string[] = [];
    const guarded = guardHttpTool<{ orderId: string }, string>({
      client: createClient(baseUrl),
      resource: (input) => `url://shop.example.com/refunds/${input.orderId}`,
      params: () => ({ method: "POST" }),
      execute: async (input) => {
        executed.push(input.orderId);
        return "refund-submitted";
      },
    });

    const result = await guarded.invoke({ orderId: "ORD-1001" });
    assert.equal(result.executed, true);
    assert.equal(result.value, "refund-submitted");
    assert.deepEqual(executed, ["ORD-1001"]);
  } finally {
    await closeServer(server);
  }
}

async function testDeny(): Promise<void> {
  const { server, baseUrl } = await startServer(() => ({ body: { decision: "DENY", reason: "deny_by_rule" } }));
  try {
    const executed: string[] = [];
    const guarded = guardHttpTool<{ orderId: string }, string>({
      client: createClient(baseUrl),
      resource: (input) => `url://shop.example.com/refunds/${input.orderId}`,
      params: () => ({ method: "POST" }),
      execute: async (input) => {
        executed.push(input.orderId);
        return "refund-submitted";
      },
    });

    const result = await guarded.invoke({ orderId: "ORD-1001" });
    assert.equal(result.executed, false);
    assert.equal(result.decisionResponse.decision, "DENY");
    assert.deepEqual(executed, []);
  } finally {
    await closeServer(server);
  }
}

async function testApproval(): Promise<void> {
  const { server, baseUrl } = await startServer(() => ({
    body: {
      decision: "REQUIRE_APPROVAL",
      approval_id: "apr_123",
      approval_fingerprint: "fp_123",
    },
  }));
  try {
    const executed: string[] = [];
    const guarded = guardHttpTool<{ orderId: string }, string>({
      client: createClient(baseUrl),
      resource: (input) => `url://shop.example.com/refunds/${input.orderId}`,
      params: () => ({ method: "POST" }),
      execute: async (input) => {
        executed.push(input.orderId);
        return "refund-submitted";
      },
    });

    const result = await guarded.invoke({ orderId: "ORD-1001" });
    assert.equal(result.executed, false);
    assert.equal(result.decisionResponse.decision, "REQUIRE_APPROVAL");
    assert.equal(result.decisionResponse.approval_id, "apr_123");
    assert.deepEqual(executed, []);
  } finally {
    await closeServer(server);
  }
}

async function testFailClosed(): Promise<void> {
  const guarded = guardFunction<string, string>({
    client: createClient("http://127.0.0.1:9"),
    buildRequest: () => createActionRequest("fs.read", "file://workspace/README.md", {}),
    execute: () => "content",
  });

  await assert.rejects(() => guarded.invoke("ignored"));
}

async function testTracePropagation(): Promise<void> {
  const { server, baseUrl, captured } = await startServer(() => ({ body: { decision: "ALLOW", trace_id: "trace-explicit-123" } }));
  try {
    const guarded = new GuardedFunction<string, string>(
      createClient(baseUrl),
      () =>
        ({
          ...createActionRequest("net.http_request", "url://shop.example.com/refunds/ORD-1001", { method: "POST" }),
          trace_id: "trace-explicit-123",
        }) as ActionRequest,
      () => "ok",
    );

    const result = await guarded.invoke("ignored");
    assert.equal(result.executed, true);
    assert.equal(captured[0]?.payload.trace_id, "trace-explicit-123");
  } finally {
    await closeServer(server);
  }
}

async function testExternalReport(): Promise<void> {
  const { server, baseUrl, captured } = await startServer(() => ({ body: { recorded: true, trace_id: "trace-custom-report", action_id: "act-custom-report", outcome: "SUCCEEDED" } }));
  try {
    const response = await createClient(baseUrl).reportExternalOutcome({
      schema_version: "v1",
      action_id: "act-custom-report",
      trace_id: "trace-custom-report",
      action_type: "payments.refund",
      resource: "payment://shop.example.com/orders/ORD-1001",
      outcome: "SUCCEEDED",
    });
    assert.equal(captured[0]?.path, "/actions/report");
    assert.equal(response.recorded, true);
  } finally {
    await closeServer(server);
  }
}

async function main(): Promise<void> {
  await testAllow();
  await testDeny();
  await testApproval();
  await testFailClosed();
  await testTracePropagation();
  await testExternalReport();
  console.log("TypeScript SDK tests passed");
}

await main();
