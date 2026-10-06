"""Per-plan fixed traffic identities; historical plans keep their old tuple.

An exact prospective BuFLO policy selects one additional parameter/provenance
pair. It never changes the historical constants or infers a policy from files,
timeouts, event counts, current Main, or an unrelated setting's successful run.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from . import buflo_duration_budget as budget

FIELD = "buflo_duration_policy"
PROVENANCE_PATH = budget.PARAMETER_PATH + ".provenance.json"
PROVENANCE_SHA256 = "b69339c0b59f09f6e629eb8a44909c09d0d55dfb9e030f1909dad8280bf63278"


def policy(value: Any) -> str | None:
    if value is not None and (type(value) is not str or value != budget.POLICY):
        raise ValueError("capture traffic requires the exact prospective BuFLO200 policy")
    return value


def declared(payload: Mapping[str, Any]) -> str | None:
    if FIELD not in payload:
        return None
    value = policy(payload[FIELD])
    if (value is None or payload.get("study_version") != 6
        or type(payload.get("study_version")) is not int
        or "static_capture_amendment" not in payload):
        raise ValueError("BuFLO200 traffic requires its separate prospective static amendment")
    if "scheduling" in payload:
        from . import rapid_static_parallel_schedule as static
        from . import rapid_selected_parallel_schedule as selected
        from . import rapid_target_parallel_schedule as target
        if selected.is_selected(payload["scheduling"]):
            selected.require_plan(payload)
        elif static.is_static(payload["scheduling"]):
            static.require_plan(payload)
        elif target.is_schedule(payload["scheduling"]):
            target.require_plan(payload)
        else:
            raise ValueError("BuFLO200 traffic cannot use a historical scheduling capsule")
    return value


def files(selected: str | None = None) -> dict[str, tuple[str, str]]:
    from .rapid_lane_evidence import TRAFFIC_FILES
    result = dict(TRAFFIC_FILES)
    if policy(selected) is not None:
        result["buflo_parameters_sha256"] = (budget.PARAMETER_PATH, budget.PARAMETER_SHA256)
        result["buflo_parameter_provenance_sha256"] = (PROVENANCE_PATH, PROVENANCE_SHA256)
    return result


def plan_files(payload: Mapping[str, Any]) -> dict[str, tuple[str, str]]:
    return files(declared(payload))


def canary_policy(payload: Mapping[str, Any], mode: str | None = None) -> str | None:
    if FIELD not in payload:
        return None
    value = policy(payload[FIELD])
    campaigns = payload.get("campaigns")
    if (value is None or "static_capture_amendment" not in payload
        or not isinstance(campaigns, list) or len(campaigns) != 1
        or not isinstance(campaigns[0], Mapping) or campaigns[0].get("mode") != "buflo"
        or mode is not None and mode != "buflo"):
        raise ValueError("BuFLO200 canary requires only its explicitly amended BuFLO setting")
    return value


def canary_files(payload: Mapping[str, Any], mode: str | None = None) -> dict[str, tuple[str, str]]:
    return files(canary_policy(payload, mode))


def spec_files(spec) -> dict[str, tuple[str, str]]:
    from .rapid_lane_evidence import PLAN_TYPE, _payload
    return plan_files(_payload(spec.plan_receipt, PLAN_TYPE))


def expected(selected: str | None = None) -> dict[str, str]:
    return {key: digest for key, (_, digest) in files(selected).items()}


def artifacts(runtime: Mapping[str, str], selected: str | None) -> dict[str, dict[str, str]]:
    from .supplied_static_preparation import reference
    if policy(selected) is None:
        return {}
    roots = [Path(runtime[name]) for name in ("execution_root", "runtime_source_root", "module_root")]
    for root in roots:
        for relative, digest in ((budget.PARAMETER_PATH, budget.PARAMETER_SHA256),
                                 (PROVENANCE_PATH, PROVENANCE_SHA256)):
            from .rapid_lane_evidence import _read, _sha
            if _sha(_read(root / relative)) != digest:
                raise ValueError("BuFLO200 traffic changed its exact frozen parameter/provenance bytes")
    return {"parameters": reference(roots[0] / budget.PARAMETER_PATH),
            "provenance": reference(roots[0] / PROVENANCE_PATH)}
