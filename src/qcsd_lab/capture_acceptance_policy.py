"""Source-bound prospective capture policies; historical defaults stay strict."""
import csv
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

POLICY = "rapid-v5-half-period-10000us-v1"
ACK_START_POLICY = "rapid-v5-half-period-10000us-ack-start-v2"
FIELD = "buflo_incoming_credit_release_policy"
TAMARAW_FIELD = "tamaraw_capture_policy"
TAMARAW_POLICY = "rapid-v5-tamaraw-owned-retry-outgoing-10000us-v1"
TAMARAW_CREDIT_SEMANTICS = "explicit-physical-ownership-with-pending-retry-v1"
FRONT_FIELD = "front_capture_policy"
FRONT_POLICY = "rapid-v5-front-bounded-outgoing-congestion-omission-1pct-v1"
TERMINAL_PRIMARY_FIELD = "terminal_primary_partial_cell_policy"
TERMINAL_PRIMARY_POLICY = "rapid-v5-one-owned-terminal-primary-partial-incoming-cell-v1"
TERMINAL_PRIMARY_PROOF_FIELD = "terminal_primary_partial_cell"
TERMINAL_PRIMARY_PROOF_SOURCE = "native-owned-terminal-primary-fin-v1"
STARTUP_POLICY = "qualified-chaff-terminal-ack-cadence-start-v1"
STARTUP_TIME_BASIS = "native-controller-defense-elapsed-us-v1"
_STARTUP_IDENTIFIERS = ("ready_endpoint", "ready_stream", "ready_resource_id", "ready_request_id")
_STARTUP_NULLABLE = (*_STARTUP_IDENTIFIERS, "armed_at_us", "ready_at_us",
                     "request_stream_final_size", "ack_observed_at_us", "eligible_exact_capacity_bytes")
_U64_MAX = 2**64 - 1


def _uint(value: Any) -> bool:
    return type(value) is int and 0 <= value <= _U64_MAX


def _exact_json(left: Any, right: Any) -> bool:
    # Python equality aliases bool/int and int/float; evidence preserves their JSON types.
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def validate_terminal_primary_preparation_policy(preparation: Mapping[str, Any]) -> str | None:
    """Admit one terminal primary split only under the prospective complete graph policy."""
    if TERMINAL_PRIMARY_FIELD not in preparation:
        return None
    if (type(preparation[TERMINAL_PRIMARY_FIELD]) is not str
        or preparation[TERMINAL_PRIMARY_FIELD] != TERMINAL_PRIMARY_POLICY
        or preparation.get("primary_document_identity_policy") != "variable-primary-document-body-v1"
        or preparation.get("application_response_policy") != "completed-terminal-http-errors-v1"
        or preparation.get("qualified_chaff_origin_policy") != "prepared-approved-origins-v1"):
        raise ValueError("terminal primary partial cell policy requires its explicit rapid preparation contract")
    return TERMINAL_PRIMARY_POLICY


def validate_terminal_primary_capture_marker(marker: Any, *, cell_size: int) -> Mapping[str, Any]:
    expected = {"schema_version": 1, "source": "bound-preparation-v1", "policy": TERMINAL_PRIMARY_POLICY,
        "cell_size": cell_size, "maximum_partial_cells": 1, "primary_resource_index": 0,
        "require_unique_stream": True, "require_fin": True, "require_nonempty_successful_primary": True,
        "require_full_advertisement": True, "require_exact_positive_split": True,
        "retired_credit_reassignment": False}
    if (type(cell_size) is not int or cell_size <= 0
        or not isinstance(marker, Mapping) or not _exact_json(marker, expected)):
        raise ValueError("invalid source-bound terminal primary partial cell marker")
    return marker


def terminal_primary_capture_cell_size(run: Mapping[str, Any]) -> int:
    resolved = run.get("resolved_configuration")
    defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    kind = defense.get("kind") if isinstance(defense, Mapping) else None
    if kind == "tamaraw":
        cell = defense.get("packet_size")
    elif kind == "buflo":
        release = run.get(FIELD)
        cell = release.get("cell_bytes") if isinstance(release, Mapping) else None
    elif kind == "cs_buflo":
        diagnostics = run.get("defense_diagnostics")
        cell = diagnostics.get("cs_buflo_runtime_udp_packet_size_bytes") if isinstance(diagnostics, Mapping) else None
    else:
        raise ValueError("terminal primary partial cell marker requires a paced capture mode")
    if (type(cell) is not int or cell <= 0
        or type(resolved.get("max_udp_payload_size")) is not int or cell > resolved["max_udp_payload_size"]
        or type(resolved.get("control_interval_us")) is not int or resolved["control_interval_us"] != 5000
        or resolved.get("drop_unsatisfied_events") is not False
        or type(resolved.get("initial_max_stream_data")) is not int or resolved["initial_max_stream_data"] != 16
        or type(resolved.get("max_stream_data_excess")) is not int or resolved["max_stream_data_excess"] != 1000
        or run.get("primary_document_identity_policy") != "variable-primary-document-body-v1"
        or run.get("application_response_policy") != "completed-terminal-http-errors-v1"):
        raise ValueError("terminal primary partial cell policy differs from actual resolved capture parameters")
    return cell


def validate_terminal_primary_source_binding(prepared: Mapping[str, Any], run: Mapping[str, Any], *,
                                            runner_directory: Path | None = None) -> None:
    preparation = prepared.get("preparation")
    declared = validate_terminal_primary_preparation_policy(preparation) if isinstance(preparation, Mapping) else None
    resolved = run.get("resolved_configuration")
    defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    paced = isinstance(defense, Mapping) and defense.get("kind") in {"tamaraw", "buflo", "cs_buflo"}
    if TERMINAL_PRIMARY_FIELD in run:
        if declared is None or not paced:
            raise ValueError("native terminal primary partial cell policy lacks matching prepared source")
        validate_terminal_primary_capture_marker(run[TERMINAL_PRIMARY_FIELD], cell_size=terminal_primary_capture_cell_size(run))
        if runner_directory is not None:
            validate_terminal_primary_partial_evidence(run, runner_directory=runner_directory, prepared=prepared)
    elif declared is not None and paced:
        raise ValueError("prepared terminal primary partial cell policy lacks its native marker")
    elif TERMINAL_PRIMARY_PROOF_FIELD in run:
        raise ValueError("terminal primary partial proof lacks its source-bound capture marker")


def validate_terminal_primary_partial_evidence(
    run: Mapping[str, Any], *, runner_directory: Path,
    prepared: Mapping[str, Any] | None = None,
    schedule_rows: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Reopen the one FIN split without changing its raw missed-cell classification."""
    from .util import sha256_file

    if TERMINAL_PRIMARY_FIELD not in run:
        if TERMINAL_PRIMARY_PROOF_FIELD in run:
            raise ValueError("terminal primary partial proof lacks its source-bound capture marker")
        return {}
    cell = terminal_primary_capture_cell_size(run)
    marker = validate_terminal_primary_capture_marker(run[TERMINAL_PRIMARY_FIELD], cell_size=cell)
    if prepared is not None:
        preparation = prepared.get("preparation")
        if not isinstance(preparation, Mapping) or validate_terminal_primary_preparation_policy(preparation) is None:
            raise ValueError("terminal primary partial evidence lacks prepared source")
    events_path = _regular_child(runner_directory, "events.csv")
    schedule_path = _regular_child(runner_directory, "schedule.csv")
    with events_path.open(newline="", encoding="utf-8") as source:
        events = list(csv.DictReader(source))
    if schedule_rows is None:
        with schedule_path.open(newline="", encoding="utf-8") as source:
            schedule_rows = list(csv.DictReader(source))
    partial_events = [row for row in events if row.get("event") == "terminal_primary_partial_cell"]
    proof = run.get(TERMINAL_PRIMARY_PROOF_FIELD)
    metrics = {TERMINAL_PRIMARY_FIELD: marker, "terminal_primary_partial_cells": 0,
        "terminal_primary_partial_retired_bytes": 0, "terminal_primary_partial_consumed_bytes": 0,
        "terminal_primary_partial_cell_size": cell,
        "terminal_primary_partial_events_sha256": sha256_file(events_path),
        "terminal_primary_partial_schedule_sha256": sha256_file(schedule_path)}
    if proof is None:
        if TERMINAL_PRIMARY_PROOF_FIELD in run or partial_events:
            raise ValueError("terminal primary partial event/proof mismatch")
        return metrics
    keys = {"schema_version", "source", "policy", "resource_id", "endpoint", "stream", "slot",
        "target_us", "cell_bytes", "requested_bytes", "advertised_bytes", "consumed_bytes",
        "retired_bytes", "fin_at_us", "status", "body_bytes"}
    integer_keys = keys - {"source", "policy"}
    if (not isinstance(proof, Mapping) or set(proof) != keys
        or any(not _uint(proof[key]) for key in integer_keys)
        or proof["schema_version"] != 1 or proof["source"] != TERMINAL_PRIMARY_PROOF_SOURCE
        or proof["policy"] != TERMINAL_PRIMARY_POLICY or proof["resource_id"] != 0
        or proof["cell_bytes"] != cell or proof["requested_bytes"] != cell or proof["advertised_bytes"] != cell
        or proof["consumed_bytes"] <= 0 or proof["retired_bytes"] <= 0
        or proof["consumed_bytes"] + proof["retired_bytes"] != cell
        or not 200 <= proof["status"] < 300 or proof["body_bytes"] <= 0):
        raise ValueError("invalid terminal primary partial physical split")
    if len(partial_events) != 1 or partial_events[0].get("outcome") != "partial":
        raise ValueError("terminal primary partial requires exactly one native event")
    try:
        event_proof = json.loads(partial_events[0]["details"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid terminal primary partial event") from error
    if not _exact_json(event_proof, proof):
        raise ValueError("terminal primary partial event differs from run proof")
    responses = run.get("responses")
    primary = [value for value in responses if isinstance(value, Mapping) and value.get("resource_id") == 0] if isinstance(responses, list) else []
    if (run.get("completion_status") != "complete" or run.get("error") is not None or len(primary) != 1
        or primary[0].get("complete") is not True or type(primary[0].get("status")) is not int
        or primary[0]["status"] != proof["status"] or type(primary[0].get("bytes")) is not int
        or primary[0]["bytes"] != proof["body_bytes"]):
        raise ValueError("terminal primary partial lacks a complete nonempty successful primary")
    selected = [row for row in schedule_rows if _csv_uint(row.get("slot_id")) == proof["slot"]]
    if len(selected) != 1:
        raise ValueError("terminal primary partial lacks a unique scheduled slot")
    row = selected[0]
    if (row.get("direction") != "incoming" or row.get("satisfaction") != "missed"
        or row.get("miss_reason") != "ReceiveCreditRetired"
        or _csv_uint(row.get("qcsd_outcome_schema_version")) != 3
        or _csv_uint(row.get("connection")) != proof["endpoint"]
        or _csv_uint(row.get("size")) != cell or _csv_uint(row.get("target_time_us")) != proof["target_us"]
        or _csv_uint(row.get("terminal_defense_elapsed_us")) != proof["fin_at_us"]
        or row.get("credit_consumed_at_us") or row.get("credit_consumption_delay_us")):
        raise ValueError("terminal primary partial differs from its raw retired incoming slot")
    advertised_us = _csv_uint(row.get("credit_advertised_at_us"))
    _csv_uint(row.get("credit_advertisement_delay_us"))
    if any(value.get("satisfaction") == "missed" and value is not row for value in schedule_rows):
        raise ValueError("terminal primary partial does not authorize another missed cell")

    # Replay real per-stream request frontiers and the cell's owned absolute ranges.
    endpoint, stream, slot = proof["endpoint"], proof["stream"], proof["slot"]
    requested: dict[tuple[int, int], int] = {}
    ranges: list[tuple[int, int, int]] = []
    observations: list[dict[str, Any]] = []
    advertisement_receipts: list[tuple[dict[str, Any], Mapping[str, Any]]] = []
    dispatched = []
    opened = []
    for index, event in enumerate(events):
        try:
            detail = json.loads(event.get("details", ""))
        except (TypeError, ValueError) as error:
            raise ValueError("invalid raw event in terminal primary proof") from error
        if event.get("event") == "application_request" and event.get("outcome") == "started" and detail == 0 and type(detail) is int:
            dispatched.append((index, _csv_uint(event.get("connection"))))
        if not isinstance(detail, Mapping):
            continue
        kind = detail.get("type")
        ep, st = detail.get("endpoint"), detail.get("stream")
        if event.get("event") == "observation" and ep == endpoint and st == stream:
            if (not _uint(detail.get("production_monotonic_ns")) or not _uint(detail.get("production_sequence"))
                or _csv_uint(event.get("monotonic_us")) != detail["production_monotonic_ns"] // 1000):
                raise ValueError("terminal primary raw observation lacks its production clock")
            observations.append(dict(detail))
            if kind == "receive_limit_advertised":
                advertisement_receipts.append((dict(detail), event))
            if kind == "stream_opened":
                if detail.get("role") != "application":
                    raise ValueError("terminal primary raw stream is not an application stream")
                opened.append(index)
        if event.get("event") != "action" or event.get("outcome") != "applied" or not _uint(ep) or not _uint(st):
            continue
        identity = (ep, st)
        if kind == "configure_manual_receive":
            requested[identity] = detail.get("initial_limit")
            continue
        if kind not in {"lease_parser_receive", "increase_receive_limit"}:
            continue
        limit = detail.get("absolute_limit")
        previous = requested.get(identity)
        if not _uint(limit) or not _uint(previous) or limit <= previous:
            raise ValueError("terminal primary raw receive frontier is not increasing")
        owner = detail.get("owner") if kind == "lease_parser_receive" else detail
        if isinstance(owner, Mapping) and owner.get("slot") == slot:
            packet = owner.get("packet")
            increase = detail.get("increase") if kind == "lease_parser_receive" else limit - previous
            if (identity != (endpoint, stream) or not _uint(increase) or increase != limit - previous
                or not isinstance(packet, Mapping) or packet.get("direction") != "incoming"
                or type(packet.get("timestamp_us")) is not int or packet["timestamp_us"] != proof["target_us"]
                or type(packet.get("length")) is not int or packet["length"] != cell):
                raise ValueError("terminal primary owned range differs from its scheduled cell")
            ranges.append((previous, limit, _csv_uint(event.get("monotonic_us"))))
        requested[identity] = limit
    if len(dispatched) != 1 or dispatched[0][1] != endpoint or len(opened) != 1 or opened[0] <= dispatched[0][0]:
        raise ValueError("terminal primary raw dispatch does not uniquely bind resource0 stream")
    stream_bindings = [value for value in events if value.get("event") == "terminal_primary_stream_binding"]
    if len(stream_bindings) != 1:
        raise ValueError("terminal primary lacks unique actual resource0 stream binding")
    binding_row = stream_bindings[0]
    binding = json.loads(binding_row["details"])
    opening = next(value for value in observations if value.get("type") == "stream_opened")
    original_opening = {key: value for key, value in opening.items()
                        if key not in {"production_sequence", "production_monotonic_ns"}}
    expected_binding = {"schema_version": 1, "source": "native-dispatched-primary-resource-stream-v1",
        "resource_id": 0, "endpoint": endpoint, "stream": stream,
        "production_sequence": opening["production_sequence"],
        "production_monotonic_ns": opening["production_monotonic_ns"], "observation": original_opening}
    if (binding_row.get("outcome") != "bound" or not _exact_json(binding, expected_binding)
        or _csv_uint(binding_row.get("connection")) != endpoint
        or _csv_uint(binding_row.get("monotonic_us")) != opening["production_monotonic_ns"] // 1000):
        raise ValueError("terminal primary stream binding differs from actual dispatched opening")
    sequences = [value["production_sequence"] for value in observations]
    if len(set(sequences)) != len(sequences) or sequences != sorted(sequences):
        raise ValueError("terminal primary raw observation identity is duplicated")
    fins = [value for value in observations if value.get("type") == "stream_finished"]
    start = run.get("defense_start_monotonic_ns")
    if (len(fins) != 1 or fins[0].get("finish") != "fin" or not _uint(start)
        or fins[0]["production_monotonic_ns"] < start):
        raise ValueError("terminal primary partial lacks its actual FIN clock")
    fin_ns = fins[0]["production_monotonic_ns"]
    reductions = [value for value in events if value.get("event") == "terminal_primary_fin_reduction"]
    if len(reductions) != 1:
        raise ValueError("terminal primary partial lacks a unique actual FIN reduction")
    reduction_row = reductions[0]
    reduction = json.loads(reduction_row["details"])
    original_fin = {key: value for key, value in fins[0].items()
                    if key not in {"production_sequence", "production_monotonic_ns"}}
    expected_reduction = {"schema_version": 1, "source": "native-controller-defense-elapsed-us-v1",
        "production_sequence": fins[0]["production_sequence"], "production_monotonic_ns": fin_ns,
        "controller_defense_elapsed_us": proof["fin_at_us"], "observation": original_fin}
    if (reduction_row.get("outcome") != "controller_reduced" or not _exact_json(reduction, expected_reduction)
        or _csv_uint(reduction_row.get("connection")) != endpoint
        or _csv_uint(reduction_row.get("monotonic_us")) != fin_ns // 1000
        or proof["fin_at_us"] < (fin_ns - start) // 1000
        or _csv_uint(partial_events[0].get("monotonic_us")) != fin_ns // 1000):
        raise ValueError("terminal primary FIN production/reduction causal binding differs from terminal proof")
    headers = [value for value in observations if value.get("type") == "response_headers"]
    final_headers = [value for value in headers if type(value.get("status")) is int and value["status"] >= 200]
    if (len(final_headers) != 1 or final_headers[0]["status"] != proof["status"]
        or any(value.get("status") is not None and (type(value["status"]) is not int or value["status"] < 100)
               for value in headers)):
        raise ValueError("terminal primary raw headers differ from successful response")
    if any((value.get("type") == "bytes_read" and not _uint(value.get("bytes")))
        or (value.get("type") == "data_frame" and not _uint(value.get("data_bytes"))) for value in observations):
        raise ValueError("terminal primary raw byte/frame extent has invalid types")
    raw_bytes = sum(value["bytes"] for value in observations if value.get("type") == "bytes_read" and _uint(value.get("bytes")))
    body_bytes = sum(value["data_bytes"] for value in observations if value.get("type") == "data_frame" and _uint(value.get("data_bytes")))
    if body_bytes != proof["body_bytes"] or any(value["production_monotonic_ns"] > fin_ns for value in observations):
        raise ValueError("terminal primary raw DATA extent differs from completed FIN response")
    advertisements = [value for value in observations if value.get("type") == "receive_limit_advertised"]
    if not ranges or sum(end - begin for begin, end, _ in ranges) != cell:
        raise ValueError("terminal primary cell lacks one full quantum of owned raw ranges")
    for begin, end, action_us in ranges:
        if not any(_uint(value.get("absolute_limit")) and value["absolute_limit"] >= end
            and value["production_monotonic_ns"] // 1000 >= action_us
            and value["production_monotonic_ns"] <= fin_ns for value in advertisements):
            raise ValueError("terminal primary owned range was not physically advertised before FIN")
    final_end = max(end for _, end, _ in ranges)
    # Production records when the transport constructs the advertisement.
    # The typed observation columns retain its later physical output handoff,
    # exactly as the pending schedule row does. Bind both clocks causally.
    if not any(value.get("absolute_limit") == final_end
        and receipt.get("outcome") == "recorded"
        and _csv_uint(receipt.get("connection")) == endpoint
        and _csv_uint(receipt.get("qcsd_outcome_schema_version")) == 2
        and _csv_uint(receipt.get("credit_advertised_at_us")) == advertised_us
        and _csv_uint(receipt.get("credit_advertisement_delay_us"))
            == _csv_uint(row.get("credit_advertisement_delay_us"))
        and value["production_monotonic_ns"] // 1000 <= advertised_us <= fin_ns // 1000
        for value, receipt in advertisement_receipts):
        raise ValueError("terminal primary schedule advertisement differs from physical observation")
    consumed = sum(max(0, min(end, raw_bytes) - begin) for begin, end, _ in ranges)
    if consumed != proof["consumed_bytes"] or cell - consumed != proof["retired_bytes"]:
        raise ValueError("terminal primary FIN raw ranges do not reproduce consumed/retired split")
    diagnostics = run.get("defense_diagnostics")
    incoming = sum(value.get("direction") == "incoming" for value in schedule_rows)
    if (not isinstance(diagnostics, Mapping)
        or diagnostics.get("scheduled_incoming_requested_bytes") != incoming * cell
        or diagnostics.get("scheduled_incoming_advertised_bytes") != incoming * cell
        or diagnostics.get("scheduled_incoming_consumed_bytes") != incoming * cell - proof["retired_bytes"]
        or diagnostics.get("scheduled_incoming_retired_bytes") != proof["retired_bytes"]
        or diagnostics.get("scheduled_incoming_unresolved_bytes") != 0):
        raise ValueError("terminal primary split differs from whole-run physical credit ledger")
    metrics.update(terminal_primary_partial_cells=1,
        terminal_primary_partial_retired_bytes=proof["retired_bytes"],
        terminal_primary_partial_consumed_bytes=proof["consumed_bytes"],
        terminal_primary_partial_proof=dict(proof))
    return metrics


def validate_front_preparation_policy(preparation: Mapping[str, Any]) -> str | None:
    """Bind a prospective one-percent outgoing padding-omission allowance."""
    from .application_response_policy import (
        APPROVED_ORIGINS_CHAFF_POLICY, COMPLETED_TERMINAL_HTTP_ERRORS_POLICY,
        VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY,
    )
    if FRONT_FIELD not in preparation:
        return None
    value = preparation[FRONT_FIELD]
    if (type(value) is not str or value != FRONT_POLICY
        or preparation.get("primary_document_identity_policy") != VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY
        or preparation.get("application_response_policy") != COMPLETED_TERMINAL_HTTP_ERRORS_POLICY
        or preparation.get("qualified_chaff_origin_policy") != APPROVED_ORIGINS_CHAFF_POLICY):
        raise ValueError("FRONT capture policy requires its explicit rapid preparation contract")
    return value


def validate_front_capture_marker(marker: Any) -> Mapping[str, Any]:
    expected = {
        "schema_version": 1, "source": "bound-preparation-v1", "policy": FRONT_POLICY,
        "outgoing_omission_reason": "CongestionLimited",
        "outgoing_omission_ratio_numerator": 1, "outgoing_omission_ratio_denominator": 100,
        "rounding": "exact-cross-multiplication-no-minimum-one",
        "packet_size": 1200, "n_client_packets": 900, "n_server_packets": 1200,
        "paper_equivalent": False, "scientific_credit": False,
    }
    if (not isinstance(marker, Mapping) or set(marker) != set(expected)
        or any(type(marker[key]) is not type(value) or marker[key] != value
               for key, value in expected.items())):
        raise ValueError("invalid FRONT source-bound capture policy")
    return marker


def validate_front_capture_run(run: Mapping[str, Any]) -> Mapping[str, Any]:
    marker = validate_front_capture_marker(run.get(FRONT_FIELD))
    resolved = run.get("resolved_configuration")
    defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    expected = {"kind": "front", "n_client_packets": 900, "n_server_packets": 1200,
                "packet_size": 1200, "peak_minimum_seconds": 0.1, "peak_maximum_seconds": 2.5}
    if (not isinstance(defense, Mapping)
        or any(type(defense.get(key)) is not type(value) or defense[key] != value
               for key, value in expected.items())
        or type(resolved.get("control_interval_us")) is not int or resolved["control_interval_us"] != 5000
        or type(resolved.get("max_udp_payload_size")) is not int or resolved["max_udp_payload_size"] != 1200
        or resolved.get("drop_unsatisfied_events") is not False
        or run.get("primary_document_identity_policy") != "variable-primary-document-body-v1"
        or run.get("application_response_policy") != "completed-terminal-http-errors-v1"):
        raise ValueError("FRONT capture policy differs from the native rapid contract")
    return marker


def validate_front_source_binding(prepared: Mapping[str, Any], run: Mapping[str, Any]) -> None:
    preparation = prepared.get("preparation")
    declared = validate_front_preparation_policy(preparation) if isinstance(preparation, Mapping) else None
    resolved = run.get("resolved_configuration")
    defense = resolved.get("defense") if isinstance(resolved, Mapping) else None
    front = isinstance(defense, Mapping) and defense.get("kind") == "front"
    if FRONT_FIELD in run:
        if declared is None or not front:
            raise ValueError("native FRONT capture policy lacks matching prepared source")
        validate_front_capture_run(run)
    elif declared is not None and front:
        raise ValueError("prepared FRONT capture policy lacks its native marker")


def validate_tamaraw_preparation_policy(preparation: Mapping[str, Any]) -> str | None:
    """Require the prospective opt-in before immutable preparation publication."""
    from .application_response_policy import (
        APPROVED_ORIGINS_CHAFF_POLICY, COMPLETED_TERMINAL_HTTP_ERRORS_POLICY,
        VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY,
    )
    if TAMARAW_FIELD not in preparation:
        return None
    value = preparation[TAMARAW_FIELD]
    if (type(value) is not str or value != TAMARAW_POLICY
        or preparation.get("primary_document_identity_policy") != VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY
        or preparation.get("application_response_policy") != COMPLETED_TERMINAL_HTTP_ERRORS_POLICY
        or preparation.get("qualified_chaff_origin_policy") != APPROVED_ORIGINS_CHAFF_POLICY):
        raise ValueError("Tamaraw capture policy requires its explicit rapid preparation contract")
    return value


def tamaraw_outgoing_window_from_policy(marker: Any) -> int:
    expected = {
        "schema_version": 1, "source": "bound-preparation-v1", "policy": TAMARAW_POLICY,
        "incoming_credit_semantics": TAMARAW_CREDIT_SEMANTICS,
        "incoming_period_us": 5_000, "outgoing_period_us": 20_000,
        "cell_bytes": 1_200, "padding_modulus": 100,
        "outgoing_release_window_us": 10_000, "historical_outgoing_release_window_us": 5_000,
        "paper_equivalent": False, "scientific_credit": False,
    }
    if (not isinstance(marker, Mapping) or set(marker) != set(expected)
        or any(type(marker[key]) is not type(value) or marker[key] != value
               for key, value in expected.items())):
        raise ValueError("invalid Tamaraw source-bound capture policy")
    return 10_000


def tamaraw_outgoing_release_window(run: Mapping[str, Any]) -> int:
    from .application_response_policy import COMPLETED_TERMINAL_HTTP_ERRORS_POLICY, VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY
    if TAMARAW_FIELD not in run:
        return 5_000
    window = tamaraw_outgoing_window_from_policy(run[TAMARAW_FIELD])
    resolved = run.get("resolved_configuration")
    parameters = resolved.get("defense") if isinstance(resolved, Mapping) else None
    expected = {"kind": "tamaraw", "incoming_interval_us": 5_000,
                "outgoing_interval_us": 20_000, "packet_size": 1_200, "modulo": 100}
    if (not isinstance(parameters, Mapping)
        or any(type(parameters.get(key)) is not type(value) or parameters[key] != value
               for key, value in expected.items())
        or type(resolved.get("control_interval_us")) is not int
        or resolved["control_interval_us"] != 5_000
        or type(resolved.get("max_udp_payload_size")) is not int
        or resolved["max_udp_payload_size"] != 1_200
        or resolved.get("drop_unsatisfied_events") is not False
        or run.get("primary_document_identity_policy") != VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY
        or run.get("application_response_policy") != COMPLETED_TERMINAL_HTTP_ERRORS_POLICY):
        raise ValueError("Tamaraw capture policy differs from the native rapid contract")
    return window


def validate_tamaraw_source_binding(prepared: Mapping[str, Any], run: Mapping[str, Any]) -> None:
    preparation = prepared.get("preparation")
    declared = validate_tamaraw_preparation_policy(preparation) if isinstance(preparation, Mapping) else None
    resolved = run.get("resolved_configuration")
    parameters = resolved.get("defense") if isinstance(resolved, Mapping) else None
    tamaraw = isinstance(parameters, Mapping) and parameters.get("kind") == "tamaraw"
    if TAMARAW_FIELD in run:
        if declared is None or not tamaraw:
            raise ValueError("native Tamaraw capture policy lacks matching prepared source")
        tamaraw_outgoing_release_window(run)
    elif declared is not None and tamaraw:
        raise ValueError("prepared Tamaraw capture policy lacks its native marker")


def _startup_present(run: Mapping[str, Any]) -> bool:
    summary, diagnostics = run.get("buflo_summary"), run.get("defense_diagnostics")
    return (isinstance(summary, Mapping) and "incoming_startup" in summary
            or isinstance(diagnostics, Mapping) and "buflo_incoming_startup" in diagnostics)


def validate_buflo_startup_receipt(value: Any, *, require_armed: bool = True) -> Mapping[str, Any]:
    """Validate the actual DTO, including an honest unarmed failure snapshot."""
    fixed = {"schema_version": 1, "policy": STARTUP_POLICY, "time_basis": STARTUP_TIME_BASIS,
             "period_us": 20_000, "packet_size_bytes": 1_200}
    keys = {*fixed, "armed", "startup_suppressed_opportunities", *_STARTUP_NULLABLE}
    if (not isinstance(value, Mapping) or set(value) != keys
        or any(type(value[key]) is not type(expected) or value[key] != expected
               for key, expected in fixed.items())
        or type(value["armed"]) is not bool
        or not _uint(value["startup_suppressed_opportunities"])):
        raise ValueError("invalid BuFLO incoming startup receipt")
    if value["armed"] is False:
        if require_armed or any(value[key] is not None for key in _STARTUP_NULLABLE):
            raise ValueError("BuFLO incoming startup is unarmed or has fabricated readiness")
        return value
    if (any(not _uint(value[key]) for key in _STARTUP_NULLABLE)
        or value["ready_resource_id"] == 0 or value["request_stream_final_size"] == 0
        or value["eligible_exact_capacity_bytes"] < 1_200
        or value["ready_at_us"] < value["ack_observed_at_us"]
        or value["armed_at_us"] != (value["ready_at_us"] // 20_000 + 1) * 20_000
        or value["armed_at_us"] > _U64_MAX
        or value["startup_suppressed_opportunities"] != value["armed_at_us"] // 20_000):
        raise ValueError("BuFLO incoming startup violates its ACK, capacity or strict cadence barrier")
    return value


def validate_buflo_preparation_policy(preparation: Mapping[str, Any]) -> str | None:
    if FIELD not in preparation:
        return None
    policy = preparation[FIELD]
    if (not isinstance(policy, str) or policy not in {POLICY, ACK_START_POLICY}
        or preparation.get("primary_document_identity_policy") != "variable-primary-document-body-v1"
        or preparation.get("application_response_policy") != "completed-terminal-http-errors-v1"
        or policy == ACK_START_POLICY
        and preparation.get("qualified_chaff_origin_policy") != "prepared-approved-origins-v1"):
        raise ValueError("BufLO incoming release policy requires the explicit rapid preparation contract")
    return policy


def incoming_release_window_from_policy(marker: Any) -> int:
    policy = marker.get("policy") if isinstance(marker, Mapping) else None
    expected = {"schema_version": 1, "source": "bound-preparation-v1", "policy": policy,
                "incoming_release_window_us": 10_000, "period_us": 20_000,
                "cell_bytes": 1_200, "scientific_credit": False}
    if (not isinstance(policy, str) or policy not in {POLICY, ACK_START_POLICY}
        or not isinstance(marker, Mapping) or set(marker) != set(expected)
        or any(type(marker[key]) is not type(value) or marker[key] != value
               for key, value in expected.items())):
        raise ValueError("invalid BufLO incoming release policy receipt")
    return 10_000


def buflo_incoming_release_window(run: Mapping[str, Any]) -> int:
    if FIELD not in run:
        if _startup_present(run):
            raise ValueError("BuFLO incoming startup lacks its V2 policy")
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
    if run[FIELD]["policy"] == ACK_START_POLICY:
        if (not isinstance(resolved, Mapping) or resolved_kind != "buflo"
            or type(resolved.get("control_interval_us")) is not int
            or resolved["control_interval_us"] != 5_000):
            raise ValueError("BuFLO ACK-start policy changes the fixed outgoing deadline")
        summary = run.get("buflo_summary")
        validate_buflo_startup_receipt(summary.get("incoming_startup") if isinstance(summary, Mapping) else None)
    elif _startup_present(run):
        raise ValueError("BuFLO incoming startup lacks its V2 policy")
    return window


def validate_buflo_source_binding(prepared: Mapping[str, Any], run: Mapping[str, Any], *,
                                 runner_directory: Path | None = None) -> None:
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
        if run[FIELD]["policy"] != policy:
            raise ValueError("native BufLO incoming release policy differs from its prepared source opt-in")
        if policy == ACK_START_POLICY:
            validate_buflo_startup_evidence(run, runner_directory=runner_directory, prepared=prepared)
    elif FIELD in run:
        raise ValueError("native BufLO incoming release policy lacks matching prepared source opt-in")
    elif _startup_present(run):
        raise ValueError("native BuFLO incoming startup lacks matching prepared V2 opt-in")


def _csv_uint(value: Any) -> int:
    if (not isinstance(value, str) or not value or not value.isascii() or not value.isdecimal()
        or len(value) > 20 or len(value) > 1 and value.startswith("0")):
        raise ValueError("invalid unsigned native startup CSV value")
    result = int(value)
    if not _uint(result):
        raise ValueError("native startup CSV value exceeds u64")
    return result


def _regular_child(directory: Path, name: str) -> Path:
    path = directory / name
    if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(directory.resolve()):
        raise ValueError("BuFLO startup proof lacks a regular native evidence file")
    return path


def validate_buflo_startup_schedule(startup: Mapping[str, Any], rows: list[Mapping[str, Any]]) -> None:
    """Reopen the actual target sets; suppressed startup opportunities have no rows."""
    validate_buflo_startup_receipt(startup)
    targets: dict[str, list[int]] = {"outgoing": [], "incoming": []}
    for row in rows:
        direction = row.get("direction")
        if direction not in targets or _csv_uint(row.get("size")) != 1_200:
            raise ValueError("BuFLO startup schedule has an invalid direction or cell")
        targets[direction].append(_csv_uint(row.get("target_time_us")))
    for direction, first in (("outgoing", 0), ("incoming", startup["armed_at_us"])):
        ordered = sorted(targets[direction])
        if (not ordered or ordered[0] != first
            or any(current - previous != 20_000
                   for previous, current in zip(ordered, ordered[1:]))):
            raise ValueError("BuFLO startup schedule violates its actual first tick or active cadence")
    if (len(targets["outgoing"]) - len(targets["incoming"]) != startup["startup_suppressed_opportunities"]
        or max(targets["outgoing"]) != max(targets["incoming"])):
        raise ValueError("BuFLO startup suppressed count differs from its actual schedule")


def validate_buflo_startup_evidence(run: Mapping[str, Any], *, runner_directory: Path | None,
                                  prepared: Mapping[str, Any] | None = None,
                                  schedule_rows: list[Mapping[str, Any]] | None = None) -> Mapping[str, Any]:
    """Re-derive terminal ACK coverage from paired production/reduction records."""
    marker = run.get(FIELD)
    if not isinstance(marker, Mapping) or marker.get("policy") != ACK_START_POLICY:
        raise ValueError("BuFLO startup evidence requires its source-bound V2 marker")
    buflo_incoming_release_window(run)
    startup = run["buflo_summary"]["incoming_startup"]
    if runner_directory is None:
        raise ValueError("BuFLO ACK-start requires reopened native event and schedule evidence")
    event_path = _regular_child(Path(runner_directory), "events.csv")
    with event_path.open(newline="", encoding="utf-8") as source:
        events = list(csv.DictReader(source))
    role = {"chaff": {"resource_id": startup["ready_resource_id"], "request_id": startup["ready_request_id"]}}
    identity = (startup["ready_endpoint"], startup["ready_stream"], role)
    originals: dict[tuple[int, int, int], Mapping[str, Any]] = {}
    bindings: list[Mapping[str, Any]] = []
    ready_count = opened_count = 0
    opened_at: tuple[int, int] | None = None
    original_sequences: set[int] = set()
    for row in events:
        event, outcome = row.get("event"), row.get("outcome")
        if event not in {"observation", "buflo_incoming_startup_ack", "buflo_incoming_startup_ready"}:
            continue
        try:
            details = json.loads(row["details"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("invalid native startup event JSON") from error
        if not isinstance(details, Mapping):
            raise ValueError("invalid native startup event object")
        if event == "buflo_incoming_startup_ready":
            if outcome != "armed" or not _exact_json(details, startup) or _csv_uint(row.get("connection")) != identity[0]:
                raise ValueError("BuFLO startup summary differs from its actual ready event")
            ready_count += 1
            continue
        if event == "buflo_incoming_startup_ack":
            if (set(details) != {"schema_version", "source", "production_sequence", "production_monotonic_ns",
                                "controller_defense_elapsed_us", "observation"}
                or type(details["schema_version"]) is not int or details["schema_version"] != 1
                or details["source"] != STARTUP_TIME_BASIS or outcome != "controller_reduced"
                or any(not _uint(details[key]) for key in ("production_sequence", "production_monotonic_ns",
                                                          "controller_defense_elapsed_us"))):
                raise ValueError("invalid native BuFLO ACK reduction event")
            observation = details["observation"]
        else:
            observation = {key: value for key, value in details.items()
                           if key not in {"production_sequence", "production_monotonic_ns"}}
        if not isinstance(observation, Mapping):
            raise ValueError("invalid native startup observation")
        if (observation.get("endpoint"), observation.get("stream"), observation.get("role")) != identity:
            continue
        if any(not _uint(observation.get(key)) for key in ("endpoint", "stream")):
            raise ValueError("invalid native startup stream identity")
        if (not isinstance(observation.get("role"), Mapping) or set(observation["role"]) != {"chaff"}
            or not isinstance(observation["role"]["chaff"], Mapping)
            or set(observation["role"]["chaff"]) != {"resource_id", "request_id"}
            or any(not _uint(observation["role"]["chaff"][key]) for key in ("resource_id", "request_id"))):
            raise ValueError("invalid native startup chaff identity")
        if event == "observation" and observation.get("type") == "stream_opened":
            if (outcome != "recorded" or _csv_uint(row.get("connection")) != identity[0]
                or not _uint(details.get("production_sequence")) or not _uint(details.get("production_monotonic_ns"))
                or _csv_uint(row.get("monotonic_us")) != details["production_monotonic_ns"] // 1_000):
                raise ValueError("BuFLO startup stream opening differs from its endpoint")
            opened_count += 1
            opened_at = (details["production_sequence"], details["production_monotonic_ns"])
            continue
        if observation.get("type") != "stream_data_acknowledged":
            continue
        if (set(observation) != {"type", "endpoint", "stream", "role", "offset", "bytes", "fin"}
            or not _uint(observation["offset"]) or not _uint(observation["bytes"])
            or type(observation["fin"]) is not bool
            or observation["offset"] + observation["bytes"] > startup["request_stream_final_size"]
            or observation["fin"] and observation["offset"] + observation["bytes"] != startup["request_stream_final_size"]
            or not _uint(details.get("production_sequence")) or not _uint(details.get("production_monotonic_ns"))
            or _csv_uint(row.get("connection")) != identity[0]
            or _csv_uint(row.get("monotonic_us")) != details["production_monotonic_ns"] // 1_000):
            raise ValueError("invalid native startup ACK range or production clock")
        key = (identity[0], details["production_sequence"], details["production_monotonic_ns"])
        if event == "observation":
            if outcome != "recorded" or key in originals or details["production_sequence"] in original_sequences:
                raise ValueError("duplicate or invalid original startup ACK")
            original_sequences.add(details["production_sequence"])
            originals[key] = observation
        else:
            bindings.append(details)
    if opened_count != 1 or opened_at is None or ready_count != 1 or not bindings:
        raise ValueError("BuFLO startup lacks its unique actual stream, ready or ACK evidence")
    ranges: list[tuple[int, int]] = []
    fin = False
    terminal_at = None
    seen = set()
    previous_clock = -1
    previous_production = opened_at[1]
    for binding in sorted(bindings, key=lambda item: item["production_sequence"]):
        key = (identity[0], binding["production_sequence"], binding["production_monotonic_ns"])
        observation = binding["observation"]
        at = binding["controller_defense_elapsed_us"]
        if (key in seen or not _exact_json(originals.get(key), observation) or at < previous_clock
            or key[1] <= opened_at[0] or key[2] < previous_production):
            raise ValueError("BuFLO startup ACK lacks its original event or honest reduction clock")
        seen.add(key)
        previous_clock = at
        previous_production = key[2]
        ranges.append((observation["offset"], observation["offset"] + observation["bytes"]))
        fin |= observation["fin"]
        covered = 0
        for lower, upper in sorted(ranges):
            if lower > covered:
                break
            covered = max(covered, upper)
        if terminal_at is None and fin and covered == startup["request_stream_final_size"]:
            terminal_at = at
    if set(originals) != seen or terminal_at != startup["ack_observed_at_us"]:
        raise ValueError("BuFLO startup lacks full terminal request ACK coverage at its recorded clock")
    responses = run.get("chaff_responses")
    matching = [row for row in responses if isinstance(row, Mapping)
                and row.get("resource_id") == identity[2]["chaff"]["resource_id"]
                and row.get("request_id") == identity[2]["chaff"]["request_id"]] if isinstance(responses, list) else []
    if (len(matching) != 1
        or any(not _uint(matching[0].get(key)) for key in ("resource_id", "request_id"))
        or any(type(matching[0].get(key)) is not int or matching[0][key] != startup["request_stream_final_size"]
               for key in ("request_stream_bytes", "expected_request_stream_bytes"))):
        raise ValueError("BuFLO startup ACK differs from its actual chaff request receipt")
    if prepared is not None:
        from .chaff_qualification import response_only_candidate_resources
        candidates = response_only_candidate_resources(prepared, str(prepared.get("id", "startup")))
        if not any(resource["id"] == startup["ready_resource_id"] and resource["url"] == matching[0].get("url")
                   for resource, _ in candidates):
            raise ValueError("BuFLO startup used an unqualified prepared chaff resource")
    if schedule_rows is None:
        with _regular_child(Path(runner_directory), "schedule.csv").open(newline="", encoding="utf-8") as source:
            schedule_rows = list(csv.DictReader(source))
    validate_buflo_startup_schedule(startup, schedule_rows)
    return startup
