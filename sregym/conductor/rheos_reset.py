"""Per-problem Rheos reset used by both SREGym arms.

Clears Mnemosyne rows for the problem namespace and deletes SREGYM alerts for
that namespace. Never calls reset-all, and never deletes an alert whose rule
is outside the SREGYM groups.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_RHEOS = "https://devansh.demo.chironvision.com:32443/rheos"
CREDENTIALS_FILE = Path.home() / ".config" / "sregym" / "rheos.env"
SREGYM_GROUP_PREFIX = "SREGYM_"
_SSL = ssl.create_default_context()


def problem_namespaces(app) -> list[str]:
    """Namespaces this problem's app owns, in stable order."""
    raw = getattr(app, "namespaces", None)
    if not raw:
        single = getattr(app, "namespace", None)
        raw = [single] if single else []
    found: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            continue
        namespace = item.strip()
        if namespace and namespace not in found:
            found.append(namespace)
    return found


def _load_env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def rheos_settings() -> tuple[str, str, str]:
    file_values = _load_env_file(CREDENTIALS_FILE)
    base = os.environ.get("RHEOS_BASE_URL") or file_values.get("RHEOS_BASE_URL") or DEFAULT_RHEOS
    username = os.environ.get("RHEOS_USERNAME") or file_values.get("RHEOS_USERNAME") or "admin"
    password = os.environ.get("RHEOS_PASSWORD") or file_values.get("RHEOS_PASSWORD") or ""
    if not password:
        raise RuntimeError(
            "Rheos password is not set. Export RHEOS_PASSWORD or add it to "
            f"{CREDENTIALS_FILE} before a baseline window."
        )
    return base.rstrip("/"), username, password


def _http(method: str, url: str, token: str | None = None, payload: dict | None = None, timeout: int = 120):
    headers = {}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, context=_SSL, timeout=timeout) as response:
            body = response.read()
            return response.status, body
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def _json(method: str, url: str, token: str | None = None, payload: dict | None = None) -> dict:
    status, body = _http(method, url, token=token, payload=payload)
    if status != 200:
        raise RuntimeError(f"{method} {url} failed: {status} {body[:300]!r}")
    if not body:
        return {}
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise RuntimeError(f"{method} {url} returned {type(parsed).__name__}, expected an object")
    return parsed


def _login(base: str, username: str, password: str) -> str:
    parsed = _json(
        "POST",
        f"{base}/api/v1/user/login",
        payload={"username": username, "password": password},
    )
    token = parsed.get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("Rheos login returned no token")
    return token


def _sregym_rule_ids(base: str, token: str) -> set[str]:
    parsed = _json("GET", f"{base}/api/v1/rules", token=token)
    rules = parsed.get("data") or parsed.get("rules") or []
    if not isinstance(rules, list):
        raise RuntimeError("Rheos rule list has no data array")
    ids: set[str] = set()
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        group = str(rule.get("groupName") or rule.get("group") or "")
        rule_id = rule.get("id") or rule.get("ruleId")
        if group.startswith(SREGYM_GROUP_PREFIX) and rule_id:
            ids.add(str(rule_id))
    if not ids:
        raise RuntimeError("No SREGYM rules are deployed; refusing to guess which alerts to delete")
    return ids


def _alerts_for_namespace(base: str, token: str, namespace: str) -> list[dict]:
    alerts: list[dict] = []
    page = 1
    while True:
        query = urllib.parse.urlencode(
            {"instanceKeyPrefix": namespace, "limit": 500, "page": page}
        )
        parsed = _json("GET", f"{base}/api/v1/alerts?{query}", token=token)
        batch = parsed.get("data") or []
        if not isinstance(batch, list):
            raise RuntimeError("Rheos alert list has no data array")
        alerts.extend(item for item in batch if isinstance(item, dict))
        pagination = parsed.get("pagination") or {}
        if not pagination.get("hasNextPage"):
            return alerts
        page += 1


def _alert_delete_ok(outcome) -> bool:
    """Rheos returns {"success": {...}} or {"error": {...}} per alert id.

    An alert that no longer exists (expired or deleted concurrently) counts as done.
    """
    if not isinstance(outcome, dict):
        return False
    success = outcome.get("success")
    if isinstance(success, dict) and success.get("code") == "success_bulk_delete_alerts":
        return True
    error = outcome.get("error")
    if isinstance(error, dict):
        text = f"{error.get('type', '')} {error.get('message', '')}".lower()
        return "doesnotexist" in text or "not found" in text or "does not exist" in text
    return False


def _delete_sregym_alerts(base: str, token: str, namespace: str, rule_ids: set[str]) -> tuple[int, int]:
    alerts = _alerts_for_namespace(base, token, namespace)
    delete_ids = [str(alert["alertId"]) for alert in alerts if str(alert.get("ruleId")) in rule_ids and alert.get("alertId")]
    skipped = len(alerts) - len(delete_ids)
    deleted = 0
    for start in range(0, len(delete_ids), 200):
        chunk = delete_ids[start : start + 200]
        result = _json("DELETE", f"{base}/api/v1/alerts", token=token, payload={"ids": chunk})
        for alert_id in chunk:
            if _alert_delete_ok(result.get(alert_id)):
                deleted += 1
                continue
            raise RuntimeError(f"Failed to delete SREGYM alert {alert_id} in {namespace}: {result.get(alert_id)!r}")
    return deleted, skipped


def reset_rheos_for_namespaces(namespaces: list[str]) -> dict:
    """Prefix-reset Mnemosyne and delete SREGYM alerts for each namespace."""
    cleaned = []
    for namespace in namespaces:
        if not isinstance(namespace, str) or not namespace.strip():
            raise RuntimeError("Refusing Rheos reset with an empty namespace")
        value = namespace.strip()
        if value not in cleaned:
            cleaned.append(value)
    if not cleaned:
        raise RuntimeError("Refusing Rheos reset with no namespaces")

    base, username, password = rheos_settings()
    token = _login(base, username, password)
    rule_ids = _sregym_rule_ids(base, token)
    results = []
    for namespace in cleaned:
        query = urllib.parse.urlencode({"instanceKeyPrefix": namespace})
        reset = _json("POST", f"{base}/api/mnemosyne/reset?{query}", token=token)
        deleted, skipped = _delete_sregym_alerts(base, token, namespace, rule_ids)
        results.append(
            {
                "namespace": namespace,
                "rows_cleared": reset.get("rows_cleared"),
                "tables_touched": reset.get("tables_touched"),
                "alerts_deleted": deleted,
                "alerts_left_untouched": skipped,
            }
        )
    return {"namespaces": results}
