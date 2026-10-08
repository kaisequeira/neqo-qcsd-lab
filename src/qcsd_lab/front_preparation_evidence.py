"""Reopen FRONT V4 construction windows without changing historical contracts."""
from collections import defaultdict
from collections.abc import Mapping
import json
from typing import Any

from .capture_acceptance_policy import FRONT_RESERVE_POLICY, FRONT_LIGHT_POLICY, validate_front_capture_run

_U64_MAX = 2**64 - 1
_ACTION_FIELDS = {"type", "endpoint", "packet", "slot", "deadline_after_us", "allow_stream_data"}
_OPTIONAL_ACTION_FIELDS = {"not_before_after_us", "send_policy"}
_WINDOW_FIELDS = {"schema_version", "policy", "construction_deadline_monotonic_ns",
                  "socket_deadline_monotonic_ns", "preparation_reserve_us"}


def _uint(value: Any) -> bool:
    return type(value) is int and 0 <= value <= _U64_MAX


def _number(row: Mapping[str, Any], key: str) -> int:
    value = row.get(key)
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise ValueError("FRONT V4 evidence lacks an unsigned CSV identity")
    result = int(value)
    if not _uint(result):
        raise ValueError("FRONT V4 CSV identity exceeds u64")
    return result


def _detail(row: Mapping[str, Any]) -> Any:
    try:
        return json.loads(row["details"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("FRONT V4 evidence has invalid JSON") from error


def _same(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def validate_windows(run: Mapping[str, Any], outgoing: Mapping[int, Mapping[str, str]],
                     omissions: Mapping[int, Mapping[str, str]],
                     events: list[dict[str, str]]) -> tuple[dict[int, dict[str, Any]], set[int]]:
    """Bind every original action to its shorter construction and original socket windows."""
    marker = validate_front_capture_run(run)
    if marker["policy"] not in {FRONT_RESERVE_POLICY, FRONT_LIGHT_POLICY}:
        raise ValueError("FRONT construction evidence requires its exact V4 or V5 source policy")
    expected_policy = marker["policy"]
    start = run["defense_start_monotonic_ns"]
    actions, windows = {}, {}
    for event in events:
        if event.get("event") == "front_prepared_output_failure":
            raise ValueError("FRONT V4 cannot accept a prepared socket-handoff failure")
        if event.get("event") == "action" and event.get("outcome") in {"applied", "expired_construction_window"}:
            action = _detail(event)
            if not isinstance(action, Mapping) or action.get("type") != "send_packet":
                continue
            slot = action.get("slot")
            if not _uint(slot) or slot not in outgoing or slot in actions:
                raise ValueError("FRONT V4 lacks unique original padding actions")
            actions[slot] = (event, action)
        elif event.get("event") == "front_padding_preparation_window":
            detail = _detail(event)
            if not isinstance(detail, Mapping):
                raise ValueError("FRONT V4 construction window is not an object")
            expired = event.get("outcome") == "expired_before_registration"
            fields = _WINDOW_FIELDS | ({"original_action", "transport_output_mutated", "socket_handoff_succeeded"}
                                      if expired else {"transport_action"})
            if (event.get("outcome") not in {"registered", "expired_before_registration"}
                or set(detail) != fields or type(detail.get("schema_version")) is not int
                or detail["schema_version"] != 1 or detail.get("policy") != expected_policy
                or type(detail.get("preparation_reserve_us")) is not int or detail["preparation_reserve_us"] != 1000):
                raise ValueError("FRONT V4 construction window changes its closed contract")
            action = detail["original_action" if expired else "transport_action"]
            slot = action.get("slot") if isinstance(action, Mapping) else None
            if not _uint(slot) or slot not in outgoing or slot in windows:
                raise ValueError("FRONT V4 repeats or invents a construction window")
            windows[slot] = {"event": event, "detail": detail, "expired": expired}
    if set(actions) != set(outgoing) or set(windows) != set(outgoing):
        raise ValueError("FRONT V4 lacks complete original action and construction-window evidence")
    preexpired = set()
    for slot, window in windows.items():
        event, action = actions[slot]
        row = outgoing[slot]
        detail = window["detail"]
        packet = action.get("packet")
        release, deadline = action.get("not_before_after_us", 0), action.get("deadline_after_us")
        if (not _ACTION_FIELDS <= set(action) <= _ACTION_FIELDS | _OPTIONAL_ACTION_FIELDS
            or action.get("allow_stream_data") is not False or action.get("send_policy", "exact") != "exact"
            or not _uint(action.get("endpoint")) or action["endpoint"] != _number(row, "connection")
            or _number(event, "connection") != action["endpoint"]
            or _number(window["event"], "connection") != action["endpoint"]
            or not isinstance(packet, Mapping) or set(packet) != {"timestamp_us", "direction", "length"}
            or not _uint(packet.get("timestamp_us")) or packet["timestamp_us"] != _number(row, "target_time_us")
            or packet.get("direction") != "outgoing" or type(packet.get("length")) is not int or packet["length"] != 1200
            or not _uint(release) or not _uint(deadline) or not 0 <= release < deadline
            or not (deadline - release in {9999, 10000} or release == 0 and deadline <= 10000)):
            raise ValueError("FRONT V4 construction reserve lacks an original pure-padding opportunity")
        construction, socket = detail["construction_deadline_monotonic_ns"], detail["socket_deadline_monotonic_ns"]
        if (not _uint(construction) or not _uint(socket) or socket - construction != 1_000_000
            or socket < deadline * 1000):
            raise ValueError("FRONT V4 construction reserve changes its exact physical deadline")
        registered_ns = socket - deadline * 1000
        nominal = start + (packet["timestamp_us"] + 10000) * 1000
        if (registered_ns < start or abs(socket - nominal) >= 1000
            or _number(event, "monotonic_us") != registered_ns // 1000
            or _number(window["event"], "monotonic_us") != registered_ns // 1000):
            raise ValueError("FRONT V4 construction window differs from its actual action clock")
        if window["expired"]:
            if (slot not in omissions or row.get("miss_reason") != "DeadlineExpired"
                or event.get("outcome") != "expired_construction_window"
                or release != 0 or not 0 < deadline <= 1000 or registered_ns < construction
                or detail["transport_output_mutated"] is not False or detail["socket_handoff_succeeded"] is not False
                or not _same(detail["original_action"], action)
                or _number(row, "terminal_defense_elapsed_us") != (registered_ns - start) // 1000):
                raise ValueError("FRONT V4 unbuilt omission lacks its exact expired registration")
            preexpired.add(slot)
        else:
            shortened = dict(action)
            shortened["deadline_after_us"] -= 1000
            if (event.get("outcome") != "applied" or deadline - release <= 1000
                or not _same(detail["transport_action"], shortened)):
                raise ValueError("FRONT V4 transport action does not reserve exactly one millisecond")
        window.update(action=action, action_us=registered_ns // 1000,
                      construction_deadline_ns=construction, socket_deadline_ns=socket)
    return windows, preexpired


def validate_physical_handoffs(run: Mapping[str, Any], windows: Mapping[int, Mapping[str, Any]],
                               omissions: Mapping[int, Any], events: list[dict[str, str]],
                               packets: list[dict[str, str]]) -> None:
    """Match actual nanosecond datagram observations to physical packet rows."""
    observations = defaultdict(list)
    sequences = set()
    for event in events:
        if event.get("event") != "observation" or event.get("outcome") != "recorded":
            continue
        detail = _detail(event)
        if not isinstance(detail, Mapping) or detail.get("type") != "datagram" or detail.get("direction") != "outgoing":
            continue
        ns, sequence = detail.get("production_monotonic_ns"), detail.get("production_sequence")
        if (not _uint(ns) or not _uint(sequence) or sequence in sequences
            or not _uint(detail.get("endpoint")) or not _uint(detail.get("length"))
            or ns < run["defense_start_monotonic_ns"]
            or _number(event, "monotonic_us") != ns // 1000
            or _number(event, "connection") != detail["endpoint"]
            or not _uint(detail.get("timestamp_us"))
            or detail["timestamp_us"] != (ns - run["defense_start_monotonic_ns"]) // 1000):
            raise ValueError("FRONT V4 physical datagram lacks its exact send clock")
        sequences.add(sequence)
        observations[(ns // 1000, detail["endpoint"], detail["length"])].append((ns, sequence))
    selected_keys = {(_number(row, "monotonic_us"), _number(row, "connection"), _number(row, "observed_udp_length"))
                     for row in packets if row.get("direction") == "outgoing" and row.get("slot_id")}
    grouped = defaultdict(list)
    for row in packets:
        if row.get("direction") == "outgoing":
            key = (_number(row, "monotonic_us"), _number(row, "connection"), _number(row, "observed_udp_length"))
            if key in selected_keys:
                grouped[key].append(row)
    for key, rows in grouped.items():
        physical = sorted(observations[key])
        if len(physical) != len(rows):
            raise ValueError("FRONT V4 handoff lacks a unique actual datagram observation")
        for row, (ns, _) in zip(rows, physical, strict=True):
            if not row.get("slot_id"):
                continue
            slot = _number(row, "slot_id")
            if slot not in windows or slot in omissions or windows[slot]["expired"]:
                raise ValueError("FRONT V4 cannot physically send an omitted padding target")
            action = windows[slot]["action"]
            release_ns = run["defense_start_monotonic_ns"] + action["packet"]["timestamp_us"] * 1000
            if not release_ns <= ns < windows[slot]["socket_deadline_ns"]:
                raise ValueError("FRONT V4 physical handoff exceeds its unchanged half-open socket window")
