#!/usr/bin/env python3
"""Verify the deployed virtual server and its Power Wiki identity path."""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any


def required_env(name: str) -> str:
    """Return one required environment value."""
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable is empty: {name}")
    return value


def api_json(
    method: str,
    url: str,
    data: dict[str, Any] | None = None,
    token: str | None = None,
) -> dict[str, Any]:
    """Send one ContextForge JSON API request."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8") if data is not None else None,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            value = json.load(response)
    except urllib.error.HTTPError as exc:
        exc.read(4096)
        raise RuntimeError(f"ContextForge {method} request failed with HTTP {exc.code}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("ContextForge API response was not a JSON object")
    return value


def parse_mcp_response(raw: bytes, content_type: str) -> dict[str, Any] | None:
    """Parse one JSON or SSE MCP response."""
    if not raw:
        return None
    text = raw.decode("utf-8")
    if "text/event-stream" in content_type:
        data_lines = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
        if not data_lines:
            raise RuntimeError("MCP SSE response contained no data event")
        return json.loads(data_lines[-1])
    value = json.loads(text)
    if not isinstance(value, dict):
        raise RuntimeError("MCP response was not a JSON object")
    return value


class McpClient:
    """Call one virtual MCP server."""

    def __init__(self, url: str, token: str):
        """Initialize the MCP client."""
        self.url = url
        self.token = token
        self.session_id: str | None = None

    def send(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Send one MCP request."""
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "MCP-Protocol-Version": "2025-11-25",
                **({"MCP-Session-Id": self.session_id} if self.session_id else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                if response.headers.get("MCP-Session-Id"):
                    self.session_id = response.headers["MCP-Session-Id"]
                return parse_mcp_response(response.read(), response.headers.get_content_type())
        except urllib.error.HTTPError as exc:
            exc.read(4096)
            raise RuntimeError(f"Virtual MCP request failed with HTTP {exc.code}") from exc


def main() -> int:
    """Verify login and a Power Wiki tool call."""
    base_url = os.environ.get("CONTEXTFORGE_URL", "http://gateway:4444").rstrip("/")
    server_id = os.environ.get("POWER_WIKI_SERVER_ID", "73c72592dd9c447d86b230930e20722d")
    admin_email = required_env("PLATFORM_ADMIN_EMAIL")
    login = api_json(
        "POST",
        f"{base_url}/v1/auth/login",
        {"email": admin_email, "password": required_env("PLATFORM_ADMIN_PASSWORD")},
    )
    token = login.get("access_token")
    if not isinstance(token, str) or not token or login.get("user", {}).get("email") != admin_email:
        raise RuntimeError("Native email login returned an invalid session")
    client = McpClient(f"{base_url}/servers/{server_id}/mcp", token)

    initialized = client.send(
        {
            "jsonrpc": "2.0",
            "id": "verify-initialize",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "power-wiki-deployment-verifier", "version": "1"},
            },
        }
    )
    if not initialized or "result" not in initialized:
        raise RuntimeError("MCP initialize returned no result")

    client.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    listed = client.send({"jsonrpc": "2.0", "id": "verify-list", "method": "tools/list", "params": {}})
    tools = listed.get("result", {}).get("tools", []) if listed else []
    status_tool = next(
        (
            tool.get("name")
            for tool in tools
            if str(tool.get("name", "")).replace("-", "_").endswith("wiki_status")
        ),
        None,
    )
    if len(tools) != 14 or not status_tool:
        raise RuntimeError(f"Expected 14 Power Wiki tools with wiki_status, received {len(tools)}")

    called = client.send(
        {
            "jsonrpc": "2.0",
            "id": "verify-call",
            "method": "tools/call",
            "params": {"name": status_tool, "arguments": {}},
        }
    )
    result = called.get("result", {}) if called else {}
    if result.get("isError") or not isinstance(result.get("content"), list):
        raise RuntimeError("Power Wiki wiki_status call failed")

    api_json("POST", f"{base_url}/v1/auth/logout", token=token)
    print(json.dumps({"status": "ok", "login": True, "tools": len(tools), "called": status_tool}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # pylint: disable=broad-exception-caught
        print(f"Deployment verification failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
