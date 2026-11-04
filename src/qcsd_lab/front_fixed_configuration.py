"""One finite prospective FRONT V5 setting; historical defaults stay exact."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

FIELD = "front_configuration_policy"
POLICY = "rapid-v7-front-450-600-sigma1-4-incoming10000us-padding-10pct-window10000us-reserve1000us-v5"
INPUT = "front-v5-450-600-sigma1-4-10ms.toml"
CONFIGURATION_PATH = "config/defense-params/front-v5-450-600-sigma1-4-10ms.toml"
CONFIGURATION_SHA256 = "910c4988276b74e25cfba20bcaefdaf2f7b25032e6110711145e197ddb4d6996"
PROVENANCE_PATH = "config/defense-params/front-v5-450-600-sigma1-4-10ms.toml.provenance.json"
PROVENANCE_SHA256 = "9eb410e829fd6aafdc530af390045617283c4ec360ed73a0bd5b5af31be7e927"


def validate_policy(value: Any) -> str | None:
    if value is not None and (type(value) is not str or value != POLICY):
        raise ValueError("unknown fixed FRONT configuration policy")
    return value


def policy(value: Mapping[str, Any]) -> str | None:
    if FIELD not in value:
        return None
    if value[FIELD] is None:
        raise ValueError("explicit fixed FRONT configuration cannot be null")
    return validate_policy(value[FIELD])


def resolved_configuration() -> dict[str, Any]:
    return {
        "schema_version": 2, "control_interval_us": 10000,
        "initial_max_stream_data": 16, "automatic_receive_window": 1048576,
        "max_chaff_streams": 5, "low_watermark": 1000000,
        "use_empty_resources": False, "max_stream_data_excess": 1000,
        "max_udp_payload_size": 1200, "drop_unsatisfied_events": False,
        "keep_alive_lead_time_us": 100000, "tail_wait_us": 0,
        "defense": {"kind": "front", "n_client_packets": 450, "n_server_packets": 600,
                    "packet_size": 1200, "peak_minimum_seconds": 1.0, "peak_maximum_seconds": 4.0},
    }


def configuration_bytes() -> bytes:
    value = resolved_configuration()
    lines = [f"{key} = {json.dumps(item)}" for key, item in value.items() if key != "defense"]
    lines += ["", "[defense]", *(f"{key} = {json.dumps(item)}" for key, item in value["defense"].items())]
    result = ("\n".join(lines) + "\n").encode("ascii")
    if hashlib.sha256(result).hexdigest() != CONFIGURATION_SHA256:
        raise ValueError("fixed FRONT configuration constructor changed its registered bytes")
    return result


def configuration_sha256() -> str:
    return hashlib.sha256(configuration_bytes()).hexdigest()


def validate_configuration(path: Path) -> Path:
    path = Path(path)
    if (any(parent.is_symlink() for parent in (path, *path.parents))
        or not path.is_file() or path.read_bytes() != configuration_bytes()):
        raise ValueError("fixed FRONT configuration differs from its complete declared settings")
    return path


def validate_run(run: Mapping[str, Any], *, selected_policy: str | None) -> None:
    if validate_policy(selected_policy) is None:
        return
    actual, expected = run.get("resolved_configuration"), resolved_configuration()
    if (not isinstance(actual, Mapping) or set(actual) != set(expected)
        or any(type(actual[key]) is not type(item) or actual[key] != item
               for key, item in expected.items())
        or not isinstance(actual["defense"], dict)
        or set(actual["defense"]) != set(expected["defense"])
        or any(type(actual["defense"].get(key)) is not type(item)
               for key, item in expected["defense"].items())):
        raise ValueError("Native run changed the complete fixed FRONT V5 configuration")
    from .capture_acceptance_policy import FRONT_FIELD, validate_front_capture_marker
    marker = validate_front_capture_marker(run.get(FRONT_FIELD))
    if marker.get("policy") != POLICY or marker.get("configuration_sha256") != CONFIGURATION_SHA256:
        raise ValueError("fixed FRONT run lacks its exact source-bound V5 Native marker")


def validate_campaign(*, selected_policy: str | None, profile: str, defenses,
                      body_policy: str | None, qualification_compatibility=None) -> None:
    if validate_policy(selected_policy) is None:
        return
    from .application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY
    if (profile != "research-1200" or len(defenses) != 1
        or defenses[0].kind != "front" or defenses[0].baseline
        or defenses[0].parameters_path is not None or defenses[0].schedule_path is not None
        or body_policy != COMPLETE_APPLICATION_DELIVERY_POLICY
        or qualification_compatibility is not None):
        raise ValueError("fixed FRONT requires its complete-delivery single-setting campaign")


def validate_prepared(prepared: Mapping[str, Any]) -> None:
    from .capture_acceptance_policy import (
        validate_front_preparation_policy, validate_terminal_primary_preparation_policy,
        TERMINAL_PRIMARY_POLICY,
    )
    preparation = prepared.get("preparation")
    if (not isinstance(preparation, Mapping)
        or validate_front_preparation_policy(preparation) != POLICY
        or validate_terminal_primary_preparation_policy(preparation) != TERMINAL_PRIMARY_POLICY):
        raise ValueError("fixed FRONT requires its preserved full-graph V5 prepared policies")


def validate_source_artifacts(runtime: Mapping[str, str]) -> dict[str, dict[str, str]]:
    from .rapid_lane_evidence import _read, _sha
    from .supplied_static_preparation import reference
    for name in ("execution_root", "runtime_source_root", "module_root"):
        root = Path(runtime[name])
        for relative, digest in ((CONFIGURATION_PATH, CONFIGURATION_SHA256),
                                 (PROVENANCE_PATH, PROVENANCE_SHA256)):
            path = root / relative
            if path.stat().st_mode & 0o7777 != 0o644 or _sha(_read(path)) != digest:
                raise ValueError("fixed FRONT source/execution config/provenance bytes or full mode changed")
    return {"configuration": reference(Path(runtime["execution_root"]) / CONFIGURATION_PATH),
            "provenance": reference(Path(runtime["execution_root"]) / PROVENANCE_PATH)}


def target_identity() -> dict[str, Any]:
    return {FIELD: POLICY, "resolved_configuration": resolved_configuration(),
            "configuration_sha256": CONFIGURATION_SHA256,
            "configuration_provenance_sha256": PROVENANCE_SHA256,
            "historical_front_condition_carried": False,
            "paper_equivalent": False, "scientific_credit": False}
