"""Suspect ids and brief section order. Made-up objects, not a live incident."""

from clients.jev_agent.policy import _origin_criteria
from clients.jev_agent.tools.chiron import SECTION_ORDER, brief_lines, suspects_from_brief
from clients.jev_agent.types import AgentContext, ToolResult


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


def test_aux_service_is_one_origin_choice():
    """A workload named kind/namespace/name is the same origin as kind/name, once."""
    from clients.jev_agent.notebook import Notebook

    brief = "MOST LIKELY: Deployment hotel-reservation/aux-service created at 07:17:11Z"
    suspects = suspects_from_brief(
        ToolResult(
            lines=[brief],
            raw={
                "brief": brief,
                "suspects": [{"kind": "Deployment", "namespace": "hotel-reservation", "name": "aux-service"}],
            },
        ),
        "hotel-reservation",
    )
    assert list(suspects) == ["deployment/aux-service"]

    class _Snap:
        components = {
            "deployment/aux-service": {
                "namespace": "hotel-reservation",
                "name": "aux-service",
                "kind": "Deployment",
                "services": [{"name": "aux-service"}],
                "containers": [],
            }
        }

    ctx = AgentContext(
        app_info={},
        namespaces=["hotel-reservation"],
        snapshot=_Snap(),
        overview={
            "cluster": {
                "recent_changes": [
                    {"object": "deployment/hotel-reservation/aux-service", "seconds_ago": 10},
                ]
            }
        },
        extra={"chiron": True, "chiron_suspects": suspects, "change_window_s": 1800},
    )
    criteria = _origin_criteria(ctx, Notebook({}, {}), {"deployment/aux-service": 1.0})
    deployment_ids = [key for key in criteria if key.startswith("deployment/") and key.endswith("aux-service")]
    assert deployment_ids == ["deployment/aux-service"]


def test_command_array_is_not_a_suspect():
    brief = 'MOST LIKELY: command set to ["/bin/sh", "-c", "echo"]'
    result = ToolResult(lines=[brief], raw={"brief": brief})
    assert suspects_from_brief(result, "app") == {}

    mixed = 'MOST LIKELY: Deployment app/web command ["/bin/sh", "-c"] at 01:02:03Z'
    found = suspects_from_brief(ToolResult(lines=[mixed], raw={"brief": mixed}), "app")
    assert list(found) == ["deployment/web"]
