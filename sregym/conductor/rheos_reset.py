"""Per-problem Rheos reset used by both SREGym arms.

Deletes every alert and clears in-memory rows for every live rule. Rule
definitions stay. reset-all is not used: it also deletes every history
snapshot directory, including sregym-lite. The namespace prefix reset is not
used either: its snapshot cleanup deletes any session directory whose name
starts with that prefix.
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
HISTORY_SESSION = "sregym-lite"
EXPECTED_SREGYM_RULES = 13
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
            return response.status, response.read()
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


def _list_rules(base: str, token: str) -> list[dict]:
    rules: list[dict] = []
    page = 1
    while True:
        parsed = _json("GET", f"{base}/api/v1/rules?limit=200&page={page}", token=token)
        batch = parsed.get("data") or []
        if not isinstance(batch, list):
            raise RuntimeError("Rheos rule list has no data array")
        rules.extend(item for item in batch if isinstance(item, dict))
        if not (parsed.get("pagination") or {}).get("hasNextPage"):
            return rules
        page += 1


def _rule_id(rule: dict) -> str:
    rule_id = rule.get("id") or rule.get("ruleId")
    if not rule_id:
        raise RuntimeError(f"Rule {rule.get('name')} has no id")
    return str(rule_id)


def _list_alert_ids(base: str, token: str) -> list[str]:
    ids: list[str] = []
    page = 1
    while True:
        query = urllib.parse.urlencode({"limit": 500, "page": page})
        parsed = _json("GET", f"{base}/api/v1/alerts?{query}", token=token)
        batch = parsed.get("data") or []
        if not isinstance(batch, list):
            raise RuntimeError("Rheos alert list has no data array")
        ids.extend(str(alert["alertId"]) for alert in batch if isinstance(alert, dict) and alert.get("alertId"))
        if not (parsed.get("pagination") or {}).get("hasNextPage"):
            return ids
        page += 1


def _alert_delete_ok(outcome) -> bool:
    """Rheos returns {"success": {...}} or {"error": {...}} per alert id.

    An alert that no longer exists counts as done.
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


def _delete_alert_ids(base: str, token: str, alert_ids: list[str]) -> int:
    deleted = 0
    for start in range(0, len(alert_ids), 200):
        chunk = alert_ids[start : start + 200]
        result = _json("DELETE", f"{base}/api/v1/alerts", token=token, payload={"ids": chunk})
        for alert_id in chunk:
            if _alert_delete_ok(result.get(alert_id)):
                deleted += 1
                continue
            raise RuntimeError(f"Failed to delete alert {alert_id}: {result.get(alert_id)!r}")
    return deleted


def _triggered_alert_count(base: str, token: str) -> int:
    query = urllib.parse.urlencode({"status": "TRIGGERED", "limit": 1, "page": 1})
    parsed = _json("GET", f"{base}/api/v1/alerts?{query}", token=token)
    pagination = parsed.get("pagination") or {}
    if "total" in pagination:
        return int(pagination["total"])
    batch = parsed.get("data") or []
    return len(batch)


def _row_count(base: str, token: str, rule_id: str) -> int:
    state = _json("GET", f"{base}/api/mnemosyne/tables/{rule_id}/state", token=token)
    if "row_count" in state:
        return int(state["row_count"])
    rows = state.get("rows") or []
    return len(rows) if isinstance(rows, list) else 0


def _history_session(base: str, token: str) -> dict:
    query = urllib.parse.urlencode({"sessionPrefix": HISTORY_SESSION})
    parsed = _json("GET", f"{base}/api/v1/history/sessions?{query}", token=token)
    for session in parsed.get("sessions") or []:
        if isinstance(session, dict) and session.get("session") == HISTORY_SESSION:
            return session
    raise RuntimeError(f"History session {HISTORY_SESSION} is missing")


def reset_rheos_for_namespaces(namespaces: list[str]) -> dict:
    """Delete all alerts and clear every live rule's in-memory state."""
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
    rules = _list_rules(base, token)
    sregym = [rule for rule in rules if str(rule.get("groupName") or "").startswith(SREGYM_GROUP_PREFIX)]
    if len(sregym) != EXPECTED_SREGYM_RULES:
        raise RuntimeError(
            f"Expected {EXPECTED_SREGYM_RULES} SREGYM rules before reset, found {len(sregym)}"
        )
    history_before = _history_session(base, token)
    ticks_before = int(history_before.get("tick_count") or 0)
    if ticks_before <= 0:
        raise RuntimeError(f"History session {HISTORY_SESSION} has no ticks; refusing to reset")

    alert_ids = _list_alert_ids(base, token)
    alerts_deleted = _delete_alert_ids(base, token, alert_ids)
    rows_cleared = 0
    for rule in rules:
        rule_id = _rule_id(rule)
        reset = _json("POST", f"{base}/api/mnemosyne/tables/{rule_id}/reset", token=token)
        rows_cleared += int(reset.get("rows_cleared") or 0)

    triggered = _triggered_alert_count(base, token)
    nonempty = {
        str(rule.get("name")): _row_count(base, token, _rule_id(rule))
        for rule in sregym
        if _row_count(base, token, _rule_id(rule)) > 0
    }
    history_after = _history_session(base, token)
    ticks_after = int(history_after.get("tick_count") or 0)
    if ticks_after < ticks_before:
        raise RuntimeError(
            f"History session {HISTORY_SESSION} dropped from {ticks_before} to {ticks_after} ticks"
        )
    if triggered:
        raise RuntimeError(f"{triggered} triggered alerts remain after reset")
    if nonempty:
        raise RuntimeError(f"SREGYM rule state is not empty after reset: {nonempty}")
    if len(_list_rules(base, token)) != len(rules):
        raise RuntimeError("Reset changed the number of rule definitions")

    return {
        "namespaces": cleaned,
        "rules_reset": len(rules),
        "sregym_rules": len(sregym),
        "rows_cleared": rows_cleared,
        "alerts_deleted": alerts_deleted,
        "triggered_alerts_after": triggered,
        "history_session": HISTORY_SESSION,
        "history_ticks_before": ticks_before,
        "history_ticks_after": ticks_after,
    }
