from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sdk.python.nomos_sdk import (
    ActionRequest,
    NomosClient,
    guard_callable,
    guard_http_tool,
)


class _Handler(BaseHTTPRequestHandler):
    response_status = 200
    response_body: dict[str, object] = {"decision": "ALLOW"}
    captured_requests: list[dict[str, object]] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        payload = json.loads(body)
        _Handler.captured_requests.append(
            {
                "path": self.path,
                "headers": dict(self.headers),
                "payload": payload,
            }
        )
        self.send_response(_Handler.response_status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(_Handler.response_body).encode("utf-8"))

    def log_message(self, format: str, *args: object) -> None:
        return


class NomosPythonWrapperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self) -> None:
        _Handler.response_status = 200
        _Handler.response_body = {"decision": "ALLOW"}
        _Handler.captured_requests = []
        self.client = NomosClient(
            base_url=self.base_url,
            bearer_token="dev-api-key",
            agent_id="demo-agent",
            agent_secret="demo-agent-secret",
        )

    def test_guard_http_tool_allow_executes(self) -> None:
        executed: list[str] = []
        tool = guard_http_tool(
            client=self.client,
            resource_fn=lambda payload: f"url://shop.example.com/refunds/{payload['order_id']}",
            params_fn=lambda payload: {"method": "POST"},
            execute_fn=lambda payload: executed.append(payload["order_id"]) or "refund-submitted",
        )

        result = tool.invoke({"order_id": "ORD-1001"})

        self.assertTrue(result.executed)
        self.assertEqual(result.value, "refund-submitted")
        self.assertEqual(executed, ["ORD-1001"])

    def test_guard_http_tool_deny_does_not_execute(self) -> None:
        _Handler.response_body = {"decision": "DENY", "reason": "deny_by_rule"}
        executed: list[str] = []
        tool = guard_http_tool(
            client=self.client,
            resource_fn=lambda payload: f"url://shop.example.com/refunds/{payload['order_id']}",
            params_fn=lambda payload: {"method": "POST"},
            execute_fn=lambda payload: executed.append(payload["order_id"]) or "refund-submitted",
        )

        result = tool.invoke({"order_id": "ORD-1001"})

        self.assertFalse(result.executed)
        self.assertTrue(result.is_denied())
        self.assertEqual(executed, [])

    def test_guard_http_tool_requires_approval_does_not_execute(self) -> None:
        _Handler.response_body = {
            "decision": "REQUIRE_APPROVAL",
            "approval_id": "apr_123",
            "approval_fingerprint": "fp_123",
        }
        executed: list[str] = []
        tool = guard_http_tool(
            client=self.client,
            resource_fn=lambda payload: f"url://shop.example.com/refunds/{payload['order_id']}",
            params_fn=lambda payload: {"method": "POST"},
            execute_fn=lambda payload: executed.append(payload["order_id"]) or "refund-submitted",
        )

        result = tool.invoke({"order_id": "ORD-1001"})

        self.assertFalse(result.executed)
        self.assertTrue(result.requires_approval())
        self.assertEqual(result.decision_response["approval_id"], "apr_123")
        self.assertEqual(executed, [])

    def test_guard_callable_fails_closed_on_transport_error(self) -> None:
        broken_client = NomosClient(
            base_url="http://127.0.0.1:9",
            bearer_token="dev-api-key",
            agent_id="demo-agent",
            agent_secret="demo-agent-secret",
            timeout=0.2,
        )
        executed: list[str] = []
        guarded = guard_callable(
            client=broken_client,
            build_request=lambda value: ActionRequest(
                action_type="fs.read",
                resource="file://workspace/README.md",
                params={},
            ),
            execute=lambda value: executed.append("ran") or "content",
        )

        with self.assertRaises(Exception):
            guarded.invoke("ignored")
        self.assertEqual(executed, [])

    def test_guard_callable_propagates_explicit_trace_id(self) -> None:
        guarded = guard_callable(
            client=self.client,
            build_request=lambda value: ActionRequest(
                action_type="net.http_request",
                resource="url://shop.example.com/refunds/ORD-1001",
                params={"method": "POST"},
                trace_id="trace-explicit-123",
            ),
            execute=lambda value: "ok",
        )

        result = guarded.invoke("ignored")

        self.assertTrue(result.executed)
        self.assertEqual(_Handler.captured_requests[-1]["payload"]["trace_id"], "trace-explicit-123")

    def test_report_external_outcome(self) -> None:
        response = self.client.report_external_outcome(
            {
                "action_id": "act-custom-report",
                "trace_id": "trace-custom-report",
                "action_type": "payments.refund",
                "resource": "payment://shop.example.com/orders/ORD-1001",
                "outcome": "SUCCEEDED",
            }
        )

        self.assertEqual(_Handler.captured_requests[-1]["path"], "/actions/report")
        self.assertEqual(_Handler.captured_requests[-1]["payload"]["schema_version"], "v1")
        self.assertEqual(response["decision"], "ALLOW")


if __name__ == "__main__":
    unittest.main()
