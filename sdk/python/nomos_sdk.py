from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import urllib.request
from dataclasses import dataclass, field
from typing import Any


def _generate_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


@dataclass
class ActionRequest:
    action_type: str
    resource: str
    params: dict[str, Any]
    action_id: str | None = None
    trace_id: str | None = None
    schema_version: str = "v1"
    context: dict[str, Any] = field(default_factory=lambda: {"extensions": {}})

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "action_id": self.action_id or _generate_id("sdk_act"),
            "action_type": self.action_type,
            "resource": self.resource,
            "params": self.params,
            "trace_id": self.trace_id or _generate_id("sdk_trace"),
            "context": self.context or {"extensions": {}},
        }


class NomosClient:
    def __init__(self, *, base_url: str, bearer_token: str, agent_id: str, agent_secret: str, timeout: float = 5.0):
        if not base_url or not bearer_token or not agent_id or not agent_secret:
            raise ValueError("base_url, bearer_token, agent_id, and agent_secret are required")
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.agent_id = agent_id
        self.agent_secret = agent_secret
        self.timeout = timeout

    def run_action(self, request: ActionRequest) -> dict[str, Any]:
        return self._post("/action", request.as_dict())

    def decide_approval(self, approval_id: str, decision: str) -> dict[str, Any]:
        return self._post("/approvals/decide", {"approval_id": approval_id, "decision": decision})

    def explain_action(self, request: ActionRequest) -> dict[str, Any]:
        return self._post("/explain", request.as_dict())

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        signature = hmac.new(self.agent_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
        req = urllib.request.Request(
            self.base_url + path,
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "X-Nomos-Agent-Id": self.agent_id,
                "X-Nomos-Agent-Signature": signature,
                "Content-Type": "application/json",
                "X-Nomos-SDK-Contract": "v1",
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
