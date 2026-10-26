"""Chiron evidence for arm B. Facts from the MCP only. No fault-specific interpretation."""

from __future__ import annotations

import json
import re

from clients.jev_agent.chiron_mcp import ChironMcpClient, McpError
from clients.jev_agent.tools._common import _namespaces
from clients.jev_agent.types import MAX_FINDINGS, MAX_LINE_CHARS, AgentContext, ToolResult

_CLIENT: ChironMcpClient | None = None

# Section headers the incident brief actually uses. Order is the order Jev should see:
# the named cause first, then other causes, then symptoms, then alerts that have gone quiet,
# then failures that were already going on before any configuration change.
SECTION_ORDER = ("MOST LIKELY", "LIKELY CAUSES", "SYMPTOMS", "EARLIER, NOW QUIET", "BACKGROUND")

_KINDS = (
    "ValidatingWebhookConfiguration",
    "MutatingWebhookConfiguration",
    "PersistentVolumeClaim",
    "PersistentVolume",
    "HorizontalPodAutoscaler",
    "PodDisruptionBudget",
    "NetworkPolicy",
    "ResourceQuota",
    "LimitRange",
    "ClusterRoleBinding",
    "ClusterRole",
    "RoleBinding",
    "StorageClass",
    "ServiceAccount",
    "PriorityClass",
    "EndpointSlice",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "ConfigMap",
    "Secret",
    "Service",
    "Ingress",
    "CronJob",
    "Namespace",
    "Endpoints",
    "Role",
    "Node",
    "Job",
)
_KIND_ALT = "|".join(sorted(_KINDS, key=len, reverse=True))
_TAG_RE = re.compile(r"\[([^/\]]+)/([A-Za-z][A-Za-z0-9]*)/([^/\]]+)\]")
_NAMED_RE = re.compile(rf"\b({_KIND_ALT}) ([a-z0-9.-]+)/([A-Za-z0-9._-]+)")
_CLUSTER_RE = re.compile(rf"\b({_KIND_ALT}) ([a-z0-9._-]+)")


def _client() -> ChironMcpClient:
    global _CLIENT
    if _CLIENT is None:
        client = ChironMcpClient()
        client.initialize()
        _CLIENT = client
    return _CLIENT


def _scope(ctx: AgentContext, target: str) -> str:
    """Map a menu scope onto the namespace Chiron should be asked about."""
    if target == "namespace":
        names = _namespaces(ctx)
        return names[0] if names else "default"
    return target


def shorten(line: str, limit: int = MAX_LINE_CHARS) -> str:
    """One notebook line. Collapse whitespace, then keep the start of a long value."""
    text = " ".join(str(line).split())
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _lines(payload: object) -> list[str]:
    """Short factual lines. Nested values are JSON, cut to the notebook line limit."""
    if isinstance(payload, dict):
        items = list(payload.items())
    else:
        items = [("result", payload)]
    lines: list[str] = []
    for key, value in items[:MAX_FINDINGS]:
        rendered = value if isinstance(value, str) else json.dumps(value, default=str, sort_keys=True)
        lines.append(shorten(f"{key}: {rendered}"))
    return lines or ["empty response"]


def _brief_text(payload: object) -> str:
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        for key in ("brief", "text", "incident_brief"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return ""


def brief_lines(text: str) -> list[str]:
    """One fact per line, most useful section first, at most MAX_FINDINGS lines."""
    sections: dict[str, list[str]] = {name: [] for name in SECTION_ORDER}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        head = next((name for name in SECTION_ORDER if line.startswith(name)), None)
        if head:
            current = head
            if head == "MOST LIKELY":
                sections[head].append(line)
            continue
        if current:
            sections[current].append(line)
    ordered = [line for name in SECTION_ORDER for line in sections[name]]
    if not ordered and text.strip():
        ordered = [line.strip() for line in text.splitlines() if line.strip()]
    return [shorten(line) for line in ordered[:MAX_FINDINGS]] or ["empty brief"]


def _suspect_id(kind: str, namespace: str | None, name: str) -> str:
    kind_id = kind.lower()
    if namespace:
        return f"{kind_id}/{namespace}/{name}"
    return f"{kind_id}/{name}"


# Workloads Jev already tracks as ``<kind>/<name>`` inside the application namespace.
_APP_WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}


def _suspect_id_for(kind: str, namespace: str | None, name: str, app_namespace: str | None) -> str:
    """One id per object. A workload in the app namespace uses Jev's own id, not kind/ns/name."""
    if app_namespace and kind in _APP_WORKLOADS and (not namespace or namespace == app_namespace):
        return f"{kind.lower()}/{name}"
    return _suspect_id(kind, namespace, name)


def _mask_literals(text: str) -> str:
    """Drop quoted text and bracketed groups so a command array cannot become an object."""
    text = re.sub(r'"[^"]*"', " ", text)
    text = re.sub(r"'[^']*'", " ", text)
    previous = None
    while previous != text:
        previous = text
        text = re.sub(r"\[[^\[\]]*\]", " ", text)
    return text


# Objects created by a controller from another object: blaming them names a symptom of the
# change, not the change. The owner is named instead when the brief gives it.
_DERIVED_KINDS = {"EndpointSlice", "Endpoints", "ReplicaSet"}
_WORKLOAD_RE = re.compile(rf"\bworkload ({_KIND_ALT})/([A-Za-z0-9._-]+)")
MAX_SUSPECTS = 3


def _suspect_desc(kind: str, namespace: str | None, name: str, line: str) -> str:
    where = f"{namespace}/{name}" if namespace else name
    return shorten(
        f"{kind} {where}, which Chiron recorded changing shortly before the first symptom: {line}"
    )


def _most_likely_objects(line: str) -> list[tuple[str, str | None, str]]:
    """(kind, namespace, name) for the changed object a MOST LIKELY line names, owner first for derived kinds."""
    out: list[tuple[str, str | None, str]] = []
    for namespace, kind, name in _TAG_RE.findall(line):
        out.append((kind, namespace, name))
    if not out:
        match = _NAMED_RE.search(line)
        if match:
            out.append((match.group(1), match.group(2), match.group(3)))
        else:
            match = _CLUSTER_RE.search(line)
            if match:
                out.append((match.group(1), None, match.group(2)))
    resolved: list[tuple[str, str | None, str]] = []
    for kind, namespace, name in out:
        if kind in _DERIVED_KINDS:
            owner = _WORKLOAD_RE.search(line)
            if not owner:
                continue
            kind, name = owner.group(1), owner.group(2)
        resolved.append((kind, namespace, name))
    return resolved


def _structured_suspects(raw: dict, app_namespace: str | None) -> dict[str, str]:
    """Suspects the brief already ranked. Empty when the payload has none."""
    items = raw.get("suspects")
    if not isinstance(items, list):
        return {}
    found: dict[str, str] = {}
    text = _brief_text(raw)
    for item in items:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "")
        name = str(item.get("name") or "")
        namespace = item.get("namespace") or None
        if isinstance(namespace, str) and not namespace:
            namespace = None
        if not kind or not name:
            continue
        found.setdefault(
            _suspect_id_for(kind, namespace, name, app_namespace),
            _suspect_desc(kind, namespace, name, text),
        )
        if len(found) >= MAX_SUSPECTS:
            break
    return found


def suspects_from_brief(result: ToolResult, namespace: str | None = None) -> dict[str, str]:
    """Origin choices for the brief, most likely first.

    Uses ``suspects`` on the tool payload when it is present. Otherwise reads the
    MOST LIKELY line, ignoring text inside quotes or brackets. A workload in
    ``namespace`` is stored as ``<kind>/<name>`` so it is not also offered as
    ``<kind>/<namespace>/<name>``.
    """
    raw = result.raw if isinstance(result.raw, dict) else {}
    structured = _structured_suspects(raw, namespace)
    if structured:
        return structured
    text = _brief_text(raw) if raw else ""
    if not text:
        text = "\n".join(result.lines or [])
    found: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("MOST LIKELY"):
            continue
        # Only the change, not the symptom quoted after it. Quoted and bracketed text is not an object.
        change = _mask_literals(line.split("; ", 1)[0])
        for kind, obj_namespace, name in _most_likely_objects(change):
            found.setdefault(
                _suspect_id_for(kind, obj_namespace, name, namespace),
                _suspect_desc(kind, obj_namespace, name, line),
            )
        if len(found) >= MAX_SUSPECTS:
            break
    return dict(list(found.items())[:MAX_SUSPECTS])


def _change_lines(payload: object) -> list[str]:
    changes = payload.get("changes") if isinstance(payload, dict) else None
    if not isinstance(changes, list):
        return _lines(payload)
    rows = [row for row in changes if isinstance(row, dict)]
    rows.sort(key=lambda row: str(row.get("at") or ""), reverse=True)
    lines: list[str] = []
    for row in rows[:MAX_FINDINGS]:
        at = str(row.get("at") or "").strip()
        change = str(row.get("change") or "").strip()
        workload = str(row.get("workload") or "").strip()
        line = f"{at} {change}".strip()
        if workload:
            line += f" (workload {workload})"
        lines.append(shorten(line))
    return lines or ["no changes"]


def _alert_lines(payload: object) -> list[str]:
    alerts = None
    if isinstance(payload, dict):
        for key in ("alerts", "active_alerts", "items"):
            if isinstance(payload.get(key), list):
                alerts = payload[key]
                break
    if not isinstance(alerts, list):
        return _lines(payload)
    lines: list[str] = []
    for alert in alerts[:MAX_FINDINGS]:
        if isinstance(alert, str):
            lines.append(shorten(alert))
            continue
        if not isinstance(alert, dict):
            lines.append(shorten(str(alert)))
            continue
        rule = alert.get("rule") or alert.get("rule_name") or alert.get("name") or alert.get("message") or "alert"
        obj = alert.get("object") or alert.get("target") or alert.get("resource") or ""
        since = alert.get("since") or alert.get("since_at") or alert.get("at") or alert.get("first_at") or ""
        line = str(rule)
        if obj:
            line += f" on {obj}"
        if since:
            line += f" since {since}"
        lines.append(shorten(line))
    return lines or ["no active alerts"]


def _call(label: str, fn, render) -> ToolResult:
    try:
        payload = fn()
    except McpError as exc:
        return ToolResult(lines=[f"{label} failed: {exc}"], error=str(exc))
    except Exception as exc:  # noqa: BLE001 - a tool failure must not abort the investigation
        return ToolResult(lines=[f"{label} failed: {type(exc).__name__}: {exc}"], error=type(exc).__name__)
    raw = payload if isinstance(payload, dict) else None
    return ToolResult(lines=render(payload), raw=raw)


def chiron_applicable(ctx: AgentContext, target: str) -> bool:
    """Arm B only, and only for the two scopes the menu already uses for cluster-wide questions."""
    return bool(ctx.extra.get("chiron")) and target in ("namespace", "kube-system")


def fetch_incident_brief(namespace: str) -> ToolResult:
    """One brief for the application namespace, one fact per line, before the first decision."""

    def render(payload: object) -> list[str]:
        text = _brief_text(payload)
        return brief_lines(text) if text else _lines(payload)

    return _call("incident_brief", lambda: _client().incident_brief(namespace), render)


def run_k8s_changes(ctx: AgentContext, target: str) -> ToolResult:
    """Field changes Chiron recorded for this scope, one change per line, newest first."""
    scope = _scope(ctx, target)
    return _call("k8s_changes", lambda: _client().k8s_changes(scope), _change_lines)


def run_active_alerts(ctx: AgentContext, target: str) -> ToolResult:
    """Alerts Chiron currently holds for this scope, one alert per line."""
    scope = _scope(ctx, target)
    return _call("active_alerts", lambda: _client().active_alerts(scope), _alert_lines)


def chiron_component_applicable(ctx: AgentContext, target: str) -> bool:
    """Arm B only, for one workload Jev already has as a component."""
    return bool(ctx.extra.get("chiron")) and target in _components_safe(ctx)


def _components_safe(ctx: AgentContext):
    try:
        from clients.jev_agent.tools._common import _components
        return _components(ctx)
    except Exception:
        return ()


def _filter_lines(lines: list[str], target: str) -> list[str]:
    needle = (target or "").split("/")[-1].lower()
    if not needle:
        return lines[:12]
    hit = [ln for ln in lines if needle in ln.lower()]
    return (hit or lines)[:12]


def run_chiron_changes(ctx: AgentContext, target: str) -> ToolResult:
    """Changes for this workload and objects that name it, one fact per line."""
    scope = _scope(ctx, "namespace")
    result = _call("k8s_changes", lambda: _client().k8s_changes(scope), _change_lines)
    result.lines = _filter_lines(result.lines, target)
    return result


def run_chiron_symptoms(ctx: AgentContext, target: str) -> ToolResult:
    """This workload's Chiron alerts, one fact per line."""
    scope = _scope(ctx, "namespace")
    result = _call("active_alerts", lambda: _client().active_alerts(scope), _alert_lines)
    result.lines = _filter_lines(result.lines, target)
    return result


def run_chiron_onset_order(ctx: AgentContext, target: str) -> ToolResult:
    """Alerts in the app namespace, newest first, so Jev can see who fired first."""
    scope = _scope(ctx, target if target in ("namespace", "kube-system") else "namespace")
    return _call("active_alerts", lambda: _client().active_alerts(scope), _alert_lines)
