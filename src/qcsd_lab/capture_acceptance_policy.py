"""Source-bound prospective capture tolerances; historical defaults stay strict."""
from collections.abc import Mapping
from typing import Any

POLICY = "rapid-v5-half-period-10000us-v1"
FIELD = "buflo_incoming_credit_release_policy"


def validate_buflo_preparation_policy(preparation: Mapping[str, Any]) -> str | None:
    if FIELD not in preparation:
        return None
    if (preparation[FIELD] != POLICY
        or preparation.get("primary_document_identity_policy") != "variable-primary-document-body-v1"
        or preparation.get("application_response_policy") != "completed-terminal-http-errors-v1"):
        raise ValueError("BufLO incoming release policy requires the explicit rapid preparation contract")
    return POLICY


def incoming_release_window_from_policy(marker: Any) -> int:
    expected = {"schema_version": 1, "source": "bound-preparation-v1", "policy": POLICY,
                "incoming_release_window_us": 10_000, "period_us": 20_000,
                "cell_bytes": 1_200, "scientific_credit": False}
    if (not isinstance(marker, Mapping) or set(marker) != set(expected)
        or any(type(marker[key]) is not type(value) or marker[key] != value
               for key, value in expected.items())):
        raise ValueError("invalid BufLO incoming release policy receipt")
    return 10_000


def buflo_incoming_release_window(run: Mapping[str, Any]) -> int:
    if FIELD not in run:
        return 5_000
    window = incoming_release_window_from_policy(run[FIELD])
    parameters = run.get("defense_parameters")
    resolved = run.get("resolved_configuration")
    defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    resolved_kind = defense.get("kind") if isinstance(defense, Mapping) else None
    if (not isinstance(parameters, Mapping) or parameters.get("kind") != "buflo"
        or resolved_kind is not None and resolved_kind != "buflo"
        or run.get("primary_document_identity_policy") != "variable-primary-document-body-v1"
        or run.get("application_response_policy") != "completed-terminal-http-errors-v1"):
        raise ValueError("BufLO incoming release policy is outside its native rapid contract")
    return window


def validate_buflo_source_binding(prepared: Mapping[str, Any], run: Mapping[str, Any]) -> None:
    preparation = prepared.get("preparation", {})
    if not isinstance(preparation, Mapping):
        raise ValueError("prepared capture acceptance metadata is invalid")
    policy = validate_buflo_preparation_policy(preparation)
    parameters = run.get("defense_parameters")
    kind = parameters.get("kind") if isinstance(parameters, Mapping) else None
    resolved = run.get("resolved_configuration")
    defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    resolved_kind = defense.get("kind") if isinstance(defense, Mapping) else None
    if policy is not None and (kind == "buflo" or resolved_kind == "buflo"):
        if FIELD not in run:
            raise ValueError("opted-in BufLO source lacks its native acceptance receipt")
        buflo_incoming_release_window(run)
    elif FIELD in run:
        raise ValueError("native BufLO incoming release policy lacks matching prepared source opt-in")
