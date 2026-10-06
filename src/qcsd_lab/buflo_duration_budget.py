"""Prospective fixed BuFLO duration support; historical traffic stays unchanged.

This policy extends only the number of 1200-byte, 20-ms opportunities. It does
not authorize a capture, change physical timing, or establish graph viability.
The caller must separately bind this traffic choice into a prospective plan.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

POLICY = "rapid-v6-fixed-200s-duration-budget-v1"
PARAMETER_FIELD = "duration_budget_policy"
RUN_FIELD = "buflo_duration_budget"
INPUT_POLICY = "reviewed-buflo-fixed-duration200-study-candidate-v1"
PARAMETER_PATH = "config/defense-params/buflo-duration200.json"
PARAMETER_SEMANTICS = (
    "qcsd-udp1200-adaptation-with-explicit-fixed-200-second-event-budget-and-"
    "versioned-terminal-subcell-policy"
)
FINAL_COHORT_POLICY = "rapid-v6-common-five-complete-get-body-at-most-10000000-v1"
FINAL_COHORT_BODY_LIMIT = 10_000_000
PARAMETERS = {
    "schema_version": 1,
    "interval_us": 20_000,
    "minimum_duration_us": 10_000_000,
    "packet_size": 1_200,
    "max_events": 10_000,
    "implementation_scope": "client_only_quic",
    "paper_equivalent": False,
    PARAMETER_FIELD: POLICY,
}
RECEIPT = {
    "schema_version": 1,
    "policy": POLICY,
    "interval_us": 20_000,
    "minimum_duration_us": 10_000_000,
    "packet_size": 1_200,
    "max_events": 10_000,
    "duration_budget_us": 200_000_000,
}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def parameter_bytes() -> bytes:
    return (json.dumps(PARAMETERS, indent=2, allow_nan=False) + "\n").encode()


PARAMETER_SHA256 = hashlib.sha256(parameter_bytes()).hexdigest()


def _exact(value: Any, expected: Mapping[str, Any], label: str) -> None:
    if (not isinstance(value, Mapping) or set(value) != set(expected)
        or any(type(value[key]) is not type(item) or value[key] != item
               for key, item in expected.items())):
        raise ValueError(f"{label} requires its exact typed fixed 200-second contract")


def validate_parameters(value: Any, *, ceiling: int = 1_200) -> None:
    _exact(value, PARAMETERS, "BuFLO duration parameters")
    if type(ceiling) is not int or ceiling < 1_200:
        raise ValueError("BuFLO duration parameters exceed the UDP ceiling")


def validate_receipt(value: Any) -> None:
    _exact(value, RECEIPT, "Native BuFLO duration receipt")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("BuFLO duration parameters contain a duplicate key")
        value[key] = item
    return value


def parse_parameters(raw: bytes) -> Mapping[str, Any]:
    if type(raw) is not bytes:
        raise ValueError("BuFLO duration parameter evidence must be exact bytes")
    value = json.loads(raw, object_pairs_hook=_unique_object)
    validate_parameters(value)
    return value


def validate_native_receipt(run: Mapping[str, Any], raw: bytes, *,
                            expected_path: str | None = None) -> dict[str, Any]:
    """Join the actual raw marker to the exact hashed parsed parameter file.

    The recorded parameter path may be an execution-namespace path; the frozen
    artifact bytes provide the content proof. A live caller can additionally
    require its actual supplied path. No timing or completion guard is waived.
    """
    parse_parameters(raw)
    parameter = run.get("defense_parameters")
    resolved = run.get("resolved_configuration")
    defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    digest = hashlib.sha256(raw).hexdigest()
    # Native `method` is the HTTP request method; the selected defense lives in
    # resolved_configuration.defense and the parameter provenance below.
    if (run.get("method") != "GET" or not isinstance(parameter, Mapping)
        or parameter.get("kind") != "buflo" or parameter.get("sha256") != digest
        or not isinstance(parameter.get("path"), str) or not parameter["path"]
        or parameter.get("implementation_scope") != "client_only_quic"
        or parameter.get("paper_equivalent") is not False
        or not isinstance(defense, Mapping) or defense.get("kind") != "buflo"
        or defense.get("parameters") != parameter["path"]
        or expected_path is not None and parameter["path"] != expected_path):
        raise ValueError("Native BuFLO duration receipt differs from its hashed parsed parameters")
    validate_receipt(parameter.get(RUN_FIELD))
    return {RUN_FIELD: dict(parameter[RUN_FIELD]),
            "buflo_duration_budget_parameter_sha256": digest}


def schedule_bounds(metrics: Mapping[str, Any]) -> tuple[int, int]:
    """Only metrics joined to a real parameter receipt can widen the old bound."""
    if RUN_FIELD not in metrics:
        if "buflo_duration_budget_parameter_sha256" in metrics:
            raise ValueError("BuFLO schedule budget digest has no typed Native receipt")
        return 6_000, 120_000_000
    validate_receipt(metrics[RUN_FIELD])
    digest = metrics.get("buflo_duration_budget_parameter_sha256")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise ValueError("BuFLO schedule budget has no exact parameter-byte identity")
    return 10_000, 200_000_000


def capture_limits(mode: str, original: Mapping[str, Any], *, policy: str | None) -> dict[str, Any]:
    """Derive recorder limits after an explicit prospective plan amendment."""
    if policy is not None and (type(policy) is not str or policy != POLICY):
        raise ValueError("unknown BuFLO duration budget policy")
    result = dict(original)
    if policy == POLICY and mode == "buflo":
        if (type(result.get("timeout_seconds")) is not int or result["timeout_seconds"] != 120
            or type(result.get("capture_seconds")) is not int or result["capture_seconds"] != 180):
            raise ValueError("BuFLO duration limits must derive from the original 120/180-second limits")
        result.update(timeout_seconds=240, capture_seconds=300)
    return result


def final_cohort_body_screen(total_body_bytes: int, *, policy: str) -> dict[str, Any]:
    """Prospective common-five headroom; never a retroactive GET rejection.

    Twelve MB of nominal receive-credit opportunities does not prove a graph
    completes. Framing, control traffic and live responses still need a canary.
    """
    if (policy != FINAL_COHORT_POLICY or type(total_body_bytes) is not int
        or total_body_bytes <= 0):
        raise ValueError("common-five headroom needs its explicit policy and positive complete-GET body sum")
    return {"policy": policy, "total_body_bytes": total_body_bytes,
            "maximum_body_bytes": FINAL_COHORT_BODY_LIMIT,
            "within_declared_headroom": total_body_bytes <= FINAL_COHORT_BODY_LIMIT,
            "capture_viability_proven": False, "scientific_credit": False}
