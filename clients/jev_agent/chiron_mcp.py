"""Read-only Streamable-HTTP client for the Chiron MCP. Never prints the bearer token."""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any

DEFAULT_MCP_URL = "https://punit.consolidation.demo.chironvision.com/mcp"


class McpError(RuntimeError):
    pass


class ChironMcpClient:
    def __init__(self, url: str | None = None, token: str | None = None, timeout: float | None = None) -> None:
        self.url = (url or os.environ.get("CHIRON_MCP_URL") or DEFAULT_MCP_URL).rstrip("/")
        self.token = (token if token is not None else os.environ.get("CHIRON_MCP_TOKEN", "")).strip()
        if not self.token:
            raise McpError("CHIRON_MCP_TOKEN is not set")
        self.timeout = float(timeout if timeout is not None else os.environ.get("CHIRON_MCP_TIMEOUT", "120"))
        self._session_id: str | None = None
        self._ctx = ssl.create_default_context()
        self._next_id = 1

    def _rpc(self, method: str, params: dict[str, Any] | None = None) -> Any:
        req_id = self._next_id
        self._next_id += 1
        body = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        request = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, context=self._ctx, timeout=self.timeout) as resp:
                if method == "initialize" and not self._session_id:
                    self._session_id = resp.headers.get("Mcp-Session-Id")
                raw = resp.read().decode()
                content_type = resp.headers.get("Content-Type") or ""
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode(errors="replace")[:400]
            raise McpError(f"MCP HTTP {exc.code} on {method}: {err_body}") from exc
        except Exception as exc:  # noqa: BLE001
            raise McpError(f"MCP unreachable on {method}: {type(exc).__name__}: {exc}") from exc
        payload = self._parse_response(raw, content_type)
        if "error" in payload:
            raise McpError(f"MCP error on {method}: {payload['error']}")
        return payload.get("result")

    @staticmethod
    def _parse_response(raw: str, content_type: str) -> dict[str, Any]:
        if not raw.strip():
            return {}
        if "text/event-stream" in content_type:
            for line in raw.splitlines():
                if line.startswith("data:"):
                    return json.loads(line[5:].lstrip())
            raise McpError(f"empty SSE body from MCP: {raw[:200]!r}")
        return json.loads(raw)

    def initialize(self) -> Any:
        result = self._rpc(
            "initialize",
            {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "jev-agent", "version": "0.1"}},
        )
        try:
            self._notify("notifications/initialized")
        except McpError:
            pass
        return result

    def _notify(self, method: str) -> None:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        body = {"jsonrpc": "2.0", "method": method, "params": {}}
        request = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(request, context=self._ctx, timeout=self.timeout) as resp:
            resp.read()

    def list_tools(self) -> list[str]:
        result = self._rpc("tools/list", {})
        tools = (result or {}).get("tools") or []
        return [t.get("name") for t in tools if isinstance(t, dict) and t.get("name")]

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        result = self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        return self._unwrap_tool_result(result)

    @staticmethod
    def _unwrap_tool_result(result: Any) -> Any:
        if not isinstance(result, dict):
            return result
        if result.get("isError"):
            raise McpError(f"tool error: {result}")
        structured = result.get("structuredContent")
        if structured is not None:
            return structured
        content = result.get("content") or []
        texts = [str(part.get("text") or "") for part in content if isinstance(part, dict) and part.get("type") == "text"]
        if not texts:
            return result
        joined = "\n".join(texts)
        try:
            return json.loads(joined)
        except json.JSONDecodeError:
            return {"text": joined}

    def incident_brief(self, namespace: str, since_minutes: int = 10) -> dict[str, Any]:
        out = self.call_tool("incident_brief", {"namespace": namespace, "since_minutes": int(since_minutes)})
        if not isinstance(out, dict):
            raise McpError(f"incident_brief returned {type(out).__name__}")
        return out

    def k8s_changes(self, scope: str, since_minutes: int = 30) -> dict[str, Any]:
        out = self.call_tool("k8s_changes", {"scope": scope, "since_minutes": int(since_minutes)})
        if not isinstance(out, dict):
            raise McpError(f"k8s_changes returned {type(out).__name__}")
        return out

    def active_alerts(self, scope: str, limit: int = 15) -> dict[str, Any]:
        out = self.call_tool("active_alerts", {"scope": scope, "limit": int(limit)})
        if not isinstance(out, dict):
            raise McpError(f"active_alerts returned {type(out).__name__}")
        return out
