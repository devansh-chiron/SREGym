"""Suspect ids and brief section order. Made-up objects, not a live incident."""

from clients.jev_agent.tools.chiron import SECTION_ORDER, brief_lines, suspects_from_brief
from clients.jev_agent.types import ToolResult


def test_section_order_puts_background_last():
    assert SECTION_ORDER[-1] == "BACKGROUND"
    text = "\n".join(
        [
            "BACKGROUND (failing before any change; not the cause):",
            "- web (1 pod): steady",
            "SYMPTOMS (new since the first change):",
            "- api (1 pod): new",
            "MOST LIKELY: ConfigMap app/cfg data.k a→b at 01:00:00Z",
            "LIKELY CAUSES (config changes followed by new symptoms):",
            "- Secret app/tok data.k a→b at 01:00:01Z",
        ]
    )
    lines = brief_lines(text)
    positions = [
        next(i for i, line in enumerate(lines) if marker in line)
        for marker in ("MOST LIKELY", "Secret", "api", "steady")
    ]
    assert positions == sorted(positions)
    assert lines[0].startswith("MOST LIKELY")
    assert lines[-1].endswith("steady") or "steady" in lines[-1]


def test_deployment_in_the_app_namespace_is_one_suspect_id():
    brief = "MOST LIKELY: Deployment app/web spec.replicas 2→1 at 01:00:00Z"
    structured = ToolResult(
        lines=[brief],
        raw={
            "brief": brief,
            "suspects": [{"kind": "Deployment", "namespace": "app", "name": "web"}],
        },
    )
    assert list(suspects_from_brief(structured, "app")) == ["deployment/web"]

    fallback = ToolResult(lines=[brief], raw={"brief": brief})
    assert list(suspects_from_brief(fallback, "app")) == ["deployment/web"]


def test_command_array_is_not_a_suspect():
    brief = 'MOST LIKELY: command set to ["/bin/sh", "-c", "echo"]'
    result = ToolResult(lines=[brief], raw={"brief": brief})
    assert suspects_from_brief(result, "app") == {}

    mixed = 'MOST LIKELY: Deployment app/web command ["/bin/sh", "-c"] at 01:02:03Z'
    found = suspects_from_brief(ToolResult(lines=[mixed], raw={"brief": mixed}), "app")
    assert list(found) == ["deployment/web"]
