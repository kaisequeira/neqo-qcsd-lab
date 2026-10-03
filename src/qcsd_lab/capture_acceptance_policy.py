"""Source-bound prospective capture policies; historical defaults stay strict."""
import csv
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

POLICY = "rapid-v5-half-period-10000us-v1"
ACK_START_POLICY = "rapid-v5-half-period-10000us-ack-start-v2"
FIELD = "buflo_incoming_credit_release_policy"
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
