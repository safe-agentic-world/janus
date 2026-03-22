import { createHmac, randomBytes } from "node:crypto";

export type ActionRequest = {
  schema_version: string;
  action_id: string;
  action_type: string;
  resource: string;
  params: Record<string, unknown>;
  trace_id: string;
  context: { extensions: Record<string, unknown> };
};

export type DecisionResponse = {
  decision: string;
  reason?: string;
  trace_id?: string;
  action_id?: string;
  execution_mode?: string;
  report_path?: string;
  approval_id?: string;
  approval_fingerprint?: string;
  approval_expires_at?: string;
  obligations?: Record<string, unknown>;
  output?: string;
};

export type ExplainResponse = {
  action_id: string;
  trace_id: string;
  decision: string;
  reason_code: string;
  matched_rule_ids: string[];
  policy_bundle_hash: string;
  engine_version: string;
  assurance_level: string;
  obligations_preview: Record<string, unknown>;
};

export type ExternalReportRequest = {
  schema_version: string;
  action_id: string;
  trace_id: string;
  action_type: string;
  resource: string;
  outcome: "SUCCEEDED" | "FAILED";
  message?: string;
  external_reference?: string;
  approval_id?: string;
  approval_fingerprint?: string;
  status_code?: number;
};

export type ExternalReportResponse = {
  recorded: boolean;
  trace_id: string;
  action_id: string;
  outcome: string;
};

export type GuardResult<T> = {
  decisionResponse: DecisionResponse;
  executed: boolean;
  value?: T;
};

export type NomosClientConfig = {
  baseUrl: string;
  bearerToken: string;
  agentId: string;
  agentSecret: string;
};

function generateId(prefix: string): string {
  return `${prefix}_${randomBytes(8).toString("hex")}`;
}

export function createActionRequest(
  actionType: string,
  resource: string,
  params: Record<string, unknown>,
): ActionRequest {
  return {
    schema_version: "v1",
    action_id: generateId("sdk_act"),
    action_type: actionType,
    resource,
    params,
    trace_id: generateId("sdk_trace"),
    context: { extensions: {} },
  };
}

export class NomosClient {
  private readonly cfg: NomosClientConfig;

  constructor(cfg: NomosClientConfig) {
    this.cfg = cfg;
    if (!cfg.baseUrl || !cfg.bearerToken || !cfg.agentId || !cfg.agentSecret) {
      throw new Error("baseUrl, bearerToken, agentId, and agentSecret are required");
    }
  }

  async runAction(request: ActionRequest): Promise<DecisionResponse> {
    return this.post("/action", request);
  }

  async decideApproval(approvalId: string, decision: string): Promise<DecisionResponse> {
    return this.post("/approvals/decide", { approval_id: approvalId, decision });
  }

  async explainAction(request: ActionRequest): Promise<ExplainResponse> {
    return this.post("/explain", request);
  }

  async reportExternalOutcome(request: ExternalReportRequest): Promise<ExternalReportResponse> {
    return this.post("/actions/report", {
      schema_version: request.schema_version || "v1",
      ...request,
    });
  }

  private async post(path: string, payload: unknown): Promise<any> {
    const body = JSON.stringify(payload);
    const signature = createHmac("sha256", this.cfg.agentSecret).update(body).digest("hex");
    const response = await fetch(`${this.cfg.baseUrl.replace(/\/$/, "")}${path}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.cfg.bearerToken}`,
        "X-Nomos-Agent-Id": this.cfg.agentId,
        "X-Nomos-Agent-Signature": signature,
        "Content-Type": "application/json",
        "X-Nomos-SDK-Contract": "v1",
      },
      body,
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(`${response.status}: ${JSON.stringify(data)}`);
    }
    return data;
  }
}

export class GuardedFunction<Input, Output> {
  private readonly client: NomosClient;
  private readonly buildRequest: (input: Input) => ActionRequest;
  private readonly execute: (input: Input) => Promise<Output> | Output;

  constructor(
    client: NomosClient,
    buildRequest: (input: Input) => ActionRequest,
    execute: (input: Input) => Promise<Output> | Output,
  ) {
    this.client = client;
    this.buildRequest = buildRequest;
    this.execute = execute;
  }

  async invoke(input: Input): Promise<GuardResult<Output>> {
    const decisionResponse = await this.client.runAction(this.buildRequest(input));
    if (decisionResponse.decision !== "ALLOW") {
      return { decisionResponse, executed: false };
    }
    const value = await this.execute(input);
    return { decisionResponse, executed: true, value };
  }

  async invokeAndReport(
    input: Input,
    buildReport?: (input: Input, value: Output, decisionResponse: DecisionResponse) => ExternalReportRequest,
  ): Promise<GuardResult<Output>> {
    const result = await this.invoke(input);
    if (!result.executed || result.value === undefined || !buildReport) {
      return result;
    }
    await this.client.reportExternalOutcome(buildReport(input, result.value, result.decisionResponse));
    return result;
  }
}

export function guardFunction<Input, Output>(config: {
  client: NomosClient;
  buildRequest: (input: Input) => ActionRequest;
  execute: (input: Input) => Promise<Output> | Output;
}): GuardedFunction<Input, Output> {
  return new GuardedFunction(config.client, config.buildRequest, config.execute);
}

export function guardHttpTool<Input, Output>(config: {
  client: NomosClient;
  resource: (input: Input) => string;
  params: (input: Input) => Record<string, unknown>;
  execute: (input: Input) => Promise<Output> | Output;
}): GuardedFunction<Input, Output> {
  return guardFunction({
    client: config.client,
    buildRequest: (input) => createActionRequest("net.http_request", config.resource(input), config.params(input)),
    execute: config.execute,
  });
}

export function guardSubprocessTool<Input, Output>(config: {
  client: NomosClient;
  resource: (input: Input) => string;
  params: (input: Input) => Record<string, unknown>;
  execute: (input: Input) => Promise<Output> | Output;
}): GuardedFunction<Input, Output> {
  return guardFunction({
    client: config.client,
    buildRequest: (input) => createActionRequest("process.exec", config.resource(input), config.params(input)),
    execute: config.execute,
  });
}

export function guardFileReadTool<Input, Output>(config: {
  client: NomosClient;
  resource: (input: Input) => string;
  params: (input: Input) => Record<string, unknown>;
  execute: (input: Input) => Promise<Output> | Output;
}): GuardedFunction<Input, Output> {
  return guardFunction({
    client: config.client,
    buildRequest: (input) => createActionRequest("fs.read", config.resource(input), config.params(input)),
    execute: config.execute,
  });
}

export function guardFileWriteTool<Input, Output>(config: {
  client: NomosClient;
  resource: (input: Input) => string;
  params: (input: Input) => Record<string, unknown>;
  execute: (input: Input) => Promise<Output> | Output;
}): GuardedFunction<Input, Output> {
  return guardFunction({
    client: config.client,
    buildRequest: (input) => createActionRequest("fs.write", config.resource(input), config.params(input)),
    execute: config.execute,
  });
}
