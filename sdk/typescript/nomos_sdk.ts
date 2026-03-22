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
  constructor(private readonly cfg: NomosClientConfig) {
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
