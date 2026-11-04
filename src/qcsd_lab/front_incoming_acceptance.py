"""One explicit Lab acceptance window for unchanged Native FRONT V5.

This policy measures local receive-credit advertisement timing. Native control
and source markers remain at 10 ms; packet ownership and pcap reconciliation
retain their existing validators. Selection is frozen before capture.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from . import front_fixed_configuration as native

FIELD = "front_incoming_credit_acceptance_policy"
POLICY = "rapid-front-v5-local-credit-jitter50000us-acceptance-v1"
WINDOW_US = 50_000
SOURCE_PATH = "src/qcsd_lab/front_incoming_acceptance.py"
METRIC_KEYS = {FIELD, "front_incoming_credit_acceptance_window_us",
    "front_incoming_credit_acceptance_timing_events",
    "front_incoming_credit_acceptance_window_violations",
    "front_incoming_credit_acceptance_schedule_sha256"}


def validate_policy(value: Any) -> str | None:
    if value is not None and (type(value) is not str or value != POLICY):
        raise ValueError("unknown FRONT incoming credit acceptance policy")
    return value


def policy(value: Mapping[str, Any]) -> str | None:
    if FIELD not in value:
        return None
    if value[FIELD] is None:
        raise ValueError("explicit FRONT incoming credit acceptance cannot be null")
    return validate_policy(value[FIELD])


def configured(value: Mapping[str, Any], *, mode: str | None = None) -> str | None:
    selected = policy(value)
    if selected is not None:
        from .application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY
        if (native.policy(value) != native.POLICY
            or mode is not None and mode != "front"
            or value.get("tamaraw_configuration_policy") is not None
            or "buflo_duration_policy" in value
            or value.get("qualification_delivery_compatibility") is not None
            or value.get("application_body_identity_policy") != COMPLETE_APPLICATION_DELIVERY_POLICY):
            raise ValueError("FRONT incoming acceptance requires its exact explicit V5 complete-delivery setting")
    return selected


def marker() -> dict[str, Any]:
    return {"schema_version": 1, "policy": POLICY,
        "configuration_sha256": native.CONFIGURATION_SHA256,
        "native_policy": native.POLICY, "native_window_us": 10_000,
        "acceptance_window_us": WINDOW_US,
        "time_basis": "process-CLOCK_MONOTONIC-credit-advertisement-interval-v1",
        "paper_equivalent": False, "scientific_credit": False}


def validate_campaign(*, selected_policy: str | None, profile: str, defenses,
                      body_policy: str | None, front_configuration_policy: str | None,
                      qualification_compatibility=None) -> None:
    if validate_policy(selected_policy) is None:
        return
    native.validate_campaign(selected_policy=front_configuration_policy, profile=profile,
        defenses=defenses, body_policy=body_policy,
        qualification_compatibility=qualification_compatibility)
    if front_configuration_policy != native.POLICY:
        raise ValueError("FRONT incoming acceptance lacks its exact Native V5 configuration")


def validate_run(run: Mapping[str, Any], *, selected_policy: str | None) -> None:
    if FIELD in run:
        raise ValueError("Lab FRONT incoming acceptance cannot be asserted as a Native marker")
    if validate_policy(selected_policy) is None:
        return
    from .capture_acceptance_policy import FIELD as BUFLO_FIELD, validate_front_capture_run
    if BUFLO_FIELD in run:
        raise ValueError("FRONT incoming acceptance cannot borrow a BuFLO credit window")
    native.validate_run(run, selected_policy=native.POLICY)
    validate_front_capture_run(run)


def validate_schedule(schedule: Mapping[str, Any], *, selected_policy: str | None) -> bool:
    selected = validate_policy(selected_policy)
    if selected is None:
        return not (set(schedule) & METRIC_KEYS)
    from .capture_acceptance_policy import validate_front_capture_marker
    try:
        actual_native = validate_front_capture_marker(schedule.get("front_capture_policy"))
    except ValueError:
        return False
    incoming = schedule.get("scheduled_incoming_events")
    expected = marker()
    actual = schedule.get(FIELD)
    if (actual_native.get("policy") != native.POLICY
        or not isinstance(actual, Mapping) or set(actual) != set(expected)
        or any(type(actual[key]) is not type(value) or actual[key] != value
               for key, value in expected.items())
        or type(incoming) is not int or incoming < 1
        or set(schedule) & METRIC_KEYS != METRIC_KEYS
        or type(schedule.get("front_incoming_credit_acceptance_window_us")) is not int
        or schedule["front_incoming_credit_acceptance_window_us"] != WINDOW_US
        or type(schedule.get("front_incoming_credit_acceptance_timing_events")) is not int
        or schedule["front_incoming_credit_acceptance_timing_events"] != incoming
        or type(schedule.get("front_incoming_credit_acceptance_window_violations")) is not int
        or schedule["front_incoming_credit_acceptance_window_violations"] != 0
        or type(schedule.get("incoming_credit_release_lateness_upper_bound_us_max")) is not int
        or not 0 <= schedule["incoming_credit_release_lateness_upper_bound_us_max"] < WINDOW_US):
        return False
    digest = schedule.get("front_incoming_credit_acceptance_schedule_sha256")
    return (isinstance(digest, str) and len(digest) == 64
            and all(char in "0123456789abcdef" for char in digest))
