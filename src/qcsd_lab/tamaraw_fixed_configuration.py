"""Prospective, fixed TAM receive credit; historical campaigns remain unchanged."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

FIELD = "tamaraw_configuration_policy"
POLICY = "rapid-tamaraw-initial8192-owned-bootstrap-v1"
INPUT = "tamaraw-initial8192.toml"
INITIAL16_POLICY = "resource-study-tamaraw-initial16-owned-bootstrap-v1"
INITIAL16_NATIVE = "6e50096dbce397e3f4e7be88de17d75986da5dff"


def validate_policy(value: Any) -> str | None:
    if value is None:
        return None
    if type(value) is not str or value not in (POLICY, INITIAL16_POLICY):
        raise ValueError("unknown fixed Tamaraw configuration policy")
    return value


def policy(value: Mapping[str, Any]) -> str | None:
    if FIELD not in value:
        return None
    if value[FIELD] is None:
        raise ValueError("explicit fixed Tamaraw configuration cannot be null")
    return validate_policy(value[FIELD])


def resolved_configuration(*, selected_policy: str = POLICY) -> dict[str, Any]:
    if validate_policy(selected_policy) is None:
        raise ValueError("a complete fixed Tamaraw configuration needs an explicit policy")
    return {
        "schema_version": 2, "control_interval_us": 5000,
        "initial_max_stream_data": 16 if selected_policy == INITIAL16_POLICY else 8192, "automatic_receive_window": 1048576,
        "max_chaff_streams": 5, "low_watermark": 1000000,
        "use_empty_resources": False, "max_stream_data_excess": 1000,
        "max_udp_payload_size": 1200, "drop_unsatisfied_events": False,
        "keep_alive_lead_time_us": 100000, "tail_wait_us": 0,
        "defense": {"kind": "tamaraw", "incoming_interval_us": 5000,
                    "outgoing_interval_us": 20000, "packet_size": 1200, "modulo": 100},
    }


def configuration_bytes(*, selected_policy: str = POLICY) -> bytes:
    value = resolved_configuration(selected_policy=selected_policy)
    lines = [f"{key} = {json.dumps(item)}" for key, item in value.items() if key != "defense"]
    lines += ["", "[defense]", *(f"{key} = {json.dumps(item)}" for key, item in value["defense"].items())]
    return ("\n".join(lines) + "\n").encode("ascii")


def configuration_sha256(*, selected_policy: str = POLICY) -> str:
    return hashlib.sha256(configuration_bytes(selected_policy=selected_policy)).hexdigest()


def validate_configuration(path: Path, *, selected_policy: str = POLICY) -> Path:
    path = Path(path)
    if (any(parent.is_symlink() for parent in (path, *path.parents))
        or not path.is_file() or path.read_bytes() != configuration_bytes(selected_policy=selected_policy)):
        raise ValueError("fixed Tamaraw configuration file differs from its complete declared settings")
    return path


def validate_run(run: Mapping[str, Any], *, selected_policy: str | None) -> None:
    if validate_policy(selected_policy) is None:
        return
    actual, expected = run.get("resolved_configuration"), resolved_configuration(selected_policy=selected_policy)
    if (not isinstance(actual, Mapping) or set(actual) != set(expected)
        or any(type(actual[key]) is not type(item) or actual[key] != item
               for key, item in expected.items())
        or not isinstance(actual["defense"], dict)
        or any(type(actual["defense"].get(key)) is not type(item)
               for key, item in expected["defense"].items())):
        raise ValueError("Native run changed the fixed Tamaraw configuration")


def validate_campaign(*, selected_policy: str | None, profile: str, defenses,
                      body_policy: str | None, qualification_compatibility=None) -> None:
    if validate_policy(selected_policy) is None:
        return
    if selected_policy == INITIAL16_POLICY:
        raise ValueError("initial16 is an explicit ResourceStudy condition, not a general campaign policy")
    from .application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY
    if (profile != "research-1200" or len(defenses) != 1
        or defenses[0].kind != "tamaraw" or defenses[0].baseline
        or defenses[0].parameters_path is not None or defenses[0].schedule_path is not None
        or body_policy != COMPLETE_APPLICATION_DELIVERY_POLICY
        or qualification_compatibility is not None):
        raise ValueError("fixed Tamaraw configuration requires its own complete-delivery single-setting campaign")


def validate_prepared(prepared: Mapping[str, Any]) -> None:
    from .capture_acceptance_policy import (
        validate_tamaraw_preparation_policy, validate_terminal_primary_preparation_policy,
        TAMARAW_POLICY, TERMINAL_PRIMARY_POLICY,
    )
    preparation = prepared.get("preparation")
    if (not isinstance(preparation, Mapping)
        or validate_tamaraw_preparation_policy(preparation) != TAMARAW_POLICY
        or validate_terminal_primary_preparation_policy(preparation) != TERMINAL_PRIMARY_POLICY):
        raise ValueError("fixed Tamaraw requires the preserved full-graph owned-credit preparation policies")


def target_identity() -> dict[str, Any]:
    """A fixed target identity, without a measurement or old-epoch credit claim."""
    return {FIELD: POLICY, "resolved_configuration": resolved_configuration(),
            "configuration_sha256": configuration_sha256(),
            "initial_credit_scope": "every-manually-controlled-application-and-chaff-request-stream",
            "initial_credit_bytes_per_stream": 8192,
            "extra_parser_credit_ceiling_bytes": 1000,
            "historical_tamaraw_condition_carried": False,
            "paper_equivalent": False, "scientific_credit": False}
