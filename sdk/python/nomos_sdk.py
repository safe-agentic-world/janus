from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Generic, TypeVar

InputT = TypeVar("InputT")
OutputT = TypeVar("OutputT")


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


@dataclass
class GuardResult(Generic[OutputT]):
    decision_response: dict[str, Any]
    executed: bool = False
    value: OutputT | None = None

    def is_allowed(self) -> bool:
        return self.decision_response.get("decision") == "ALLOW"

    def is_denied(self) -> bool:
        return self.decision_response.get("decision") == "DENY"

    def requires_approval(self) -> bool:
        return self.decision_response.get("decision") == "REQUIRE_APPROVAL"


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

    def report_external_outcome(self, payload: dict[str, Any]) -> dict[str, Any]:
        report = dict(payload)
        report.setdefault("schema_version", "v1")
        return self._post("/actions/report", report)

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


class GuardedCallable(Generic[InputT, OutputT]):
    def __init__(
        self,
        *,
        client: NomosClient,
        build_request: Callable[[InputT], ActionRequest],
        execute: Callable[[InputT], OutputT],
    ):
        self.client = client
        self.build_request = build_request
        self.execute = execute

    def invoke(self, value: InputT) -> GuardResult[OutputT]:
        request = self.build_request(value)
        decision = self.client.run_action(request)
        if decision.get("decision") != "ALLOW":
            return GuardResult(decision_response=decision)
        return GuardResult(
            decision_response=decision,
            executed=True,
            value=self.execute(value),
        )

    def invoke_and_report(
        self,
        value: InputT,
        report_builder: Callable[[InputT, OutputT, dict[str, Any]], dict[str, Any]] | None,
    ) -> GuardResult[OutputT]:
        result = self.invoke(value)
        if not result.executed or report_builder is None or result.value is None:
            return result
        self.client.report_external_outcome(report_builder(value, result.value, result.decision_response))
        return result


def guard_callable(
    *,
    client: NomosClient,
    build_request: Callable[[InputT], ActionRequest],
    execute: Callable[[InputT], OutputT],
) -> GuardedCallable[InputT, OutputT]:
    return GuardedCallable(client=client, build_request=build_request, execute=execute)


def guard_http_tool(
    *,
    client: NomosClient,
    resource_fn: Callable[[InputT], str],
    params_fn: Callable[[InputT], dict[str, Any]],
    execute_fn: Callable[[InputT], OutputT],
) -> GuardedCallable[InputT, OutputT]:
    return guard_callable(
        client=client,
        build_request=lambda value: ActionRequest(
            action_type="net.http_request",
            resource=resource_fn(value),
            params=params_fn(value),
        ),
        execute=execute_fn,
    )


def guard_subprocess_tool(
    *,
    client: NomosClient,
    resource_fn: Callable[[InputT], str],
    params_fn: Callable[[InputT], dict[str, Any]],
    execute_fn: Callable[[InputT], OutputT],
) -> GuardedCallable[InputT, OutputT]:
    return guard_callable(
        client=client,
        build_request=lambda value: ActionRequest(
            action_type="process.exec",
            resource=resource_fn(value),
            params=params_fn(value),
        ),
        execute=execute_fn,
    )


def guard_file_read_tool(
    *,
    client: NomosClient,
    resource_fn: Callable[[InputT], str],
    params_fn: Callable[[InputT], dict[str, Any]],
    execute_fn: Callable[[InputT], OutputT],
) -> GuardedCallable[InputT, OutputT]:
    return guard_callable(
        client=client,
        build_request=lambda value: ActionRequest(
            action_type="fs.read",
            resource=resource_fn(value),
            params=params_fn(value),
        ),
        execute=execute_fn,
    )


def guard_file_write_tool(
    *,
    client: NomosClient,
    resource_fn: Callable[[InputT], str],
    params_fn: Callable[[InputT], dict[str, Any]],
    execute_fn: Callable[[InputT], OutputT],
) -> GuardedCallable[InputT, OutputT]:
    return guard_callable(
        client=client,
        build_request=lambda value: ActionRequest(
            action_type="fs.write",
            resource=resource_fn(value),
            params=params_fn(value),
        ),
        execute=execute_fn,
    )
