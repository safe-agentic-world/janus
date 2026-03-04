#!/usr/bin/env python3
import json
import os
import sys
import urllib.error
import urllib.request


BASE_URL = os.environ.get("NOMOS_BASE_URL", "http://127.0.0.1:8080")
API_KEY = os.environ.get("NOMOS_API_KEY", "dev-api-key")


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def post_action(payload: dict) -> dict:
    request = urllib.request.Request(
        BASE_URL.rstrip("/") + "/run",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
            "X-Agent-Secret": "dev-agent-secret",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    allow_path = os.path.join(repo_root, "examples", "quickstart", "requests", "allow-readme.json")
    deny_path = os.path.join(repo_root, "examples", "quickstart", "requests", "deny-env.json")

    try:
        allow = post_action(load_json(allow_path))
        deny = post_action(load_json(deny_path))
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        sys.stderr.write(f"http error: {err.code} {body}\n")
        return 1
    except OSError as err:
        sys.stderr.write(f"request failed: {err}\n")
        return 1

    print(json.dumps({"allow": allow, "deny": deny}, indent=2))

    if allow.get("decision") != "ALLOW":
        sys.stderr.write("expected allow decision for README.md\n")
        return 1
    if deny.get("decision") != "DENY":
        sys.stderr.write("expected deny decision for .env\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
