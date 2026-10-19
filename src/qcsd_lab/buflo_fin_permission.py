"""Independent raw proof for the explicit BuFLO FIN-permission policy.

Permission is not received traffic.  Original and replacement MAX handoffs,
including FIN/release, retain the original half-open 32 ms window.  Actual
consumption can follow RTT.  This reader adds no exception for retired bytes;
the separate original terminal-primary reader must still validate that split.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping

FIELD = "buflo_retained_parser_fin_permission"
POLICY = "buflo-retained-owned-parser-demand-genuine-fin-permission-release-v1"
CLI_FLAG = "--buflo-retained-parser-fin-permission"
PREPARATION_FIELD = "buflo_fin_permission_policy"
CELL = 1_200
PERIOD_US = 64_000
WINDOW_US = 32_000


def validate_policy(value: Any) -> str | None:
    if value is None:
        return None
    _need(type(value) is str and value == POLICY, "unsupported explicit preparation/launch policy")
    return POLICY


def validate_source_binding(prepared: Mapping[str, Any], run: Mapping[str, Any], *,
                            selected_policy: Any, runner_directory: Path | None) -> None:
    selected = validate_policy(selected_policy)
    preparation = prepared.get("preparation")
    declared = validate_policy(preparation.get(PREPARATION_FIELD)) if isinstance(preparation, Mapping) else None
    marker = validate_run_marker(run)
    config = run.get("resolved_configuration")
    buflo = isinstance(config, Mapping) and isinstance(config.get("defense"), Mapping) and config["defense"].get("kind") == "buflo"
    if not buflo:
        _need(selected is None and marker is None, "new policy is BuFLO-only")
        return
    _need((selected is not None) == (marker is not None)
          and (selected is None and declared is None or selected == declared == POLICY),
          "prepared, explicit launch, and Native policy differ")
    if selected is not None:
        _need(runner_directory is not None, "new policy requires its actual runner evidence")
        evidence = validate_evidence(run, runner_directory=runner_directory)
        from .capture_acceptance_policy import validate_terminal_primary_partial_evidence
        primary = validate_terminal_primary_partial_evidence(run, runner_directory=runner_directory, prepared=prepared)
        validate_retirement_binding(evidence, primary)


def validate_retirement_binding(evidence: Mapping[str, Any], primary: Mapping[str, Any]) -> None:
    """The unchanged original primary proof is the only retirement exception."""
    retired = primary.get("terminal_primary_partial_retired_bytes", 0)
    _need(_uint(retired) and evidence.get("retired_bytes") == retired,
          "retirement differs from the whole original terminal-primary proof")
    if primary.get("terminal_primary_partial_cells", 0) == 1:
        proof = primary.get("terminal_primary_partial_proof")
        _need(isinstance(proof, Mapping) and _uint(proof.get("slot"))
              and proof["slot"] not in evidence.get("released_slots", []),
              "primary partial cell overlaps a secondary FIN-release cell")


def validate_metrics(value: Any) -> None:
    """Validate the explicit nonclassifier diagnostic projection after raw replay."""
    integer_keys = {"gross_advertised_bytes", "fin_released_bytes", "effective_advertised_bytes",
                    "actual_consumed_bytes", "retired_bytes", "genuine_fin_releases",
                    "replacement_partitions", "full_1200_consumed_replacement_cells", "physical_permission_window_us"}
    keys = integer_keys | {"schema_version", "policy", "payload_arrival_deadline_imposed",
                           "wire_datagram_constant_size_claim", "permission_is_received_data", "raw_files", "released_slots"}
    _need(type(value) is dict and set(value) == keys and type(value.get("schema_version")) is int
          and value["schema_version"] == 1 and value.get("policy") == POLICY
          and all(_uint(value.get(key)) for key in integer_keys)
          and value["gross_advertised_bytes"] - value["fin_released_bytes"] == value["effective_advertised_bytes"]
          and value["actual_consumed_bytes"] + value["retired_bytes"] == value["effective_advertised_bytes"]
          and value["physical_permission_window_us"] == WINDOW_US
          and value["payload_arrival_deadline_imposed"] is False
          and value["wire_datagram_constant_size_claim"] is False and value["permission_is_received_data"] is False,
          "invalid explicit independent-reader diagnostic metrics")
    released_slots = value["released_slots"]
    _need(type(released_slots) is list and all(_uint(slot) for slot in released_slots)
          and released_slots == sorted(set(released_slots))
          and len(released_slots) == value["full_1200_consumed_replacement_cells"], "released-slot census differs")
    files = value["raw_files"]
    _need(type(files) is dict and set(files) == {"run", "events", "schedule", "packets"}
          and all(type(digest) is str and len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
                  for digest in files.values()), "independent raw-file binding differs")


def _need(value: Any, message: str) -> None:
    if not value:
        raise ValueError("BuFLO FIN permission: " + message)


def _uint(value: Any) -> bool:
    return type(value) is int and 0 <= value < 2**64


def _n(value: Any) -> int:
    _need(_uint(value), "unsigned integer required")
    return value


def _csv_n(value: Any) -> int:
    _need(type(value) is str and value.isascii() and value.isdecimal(), "numeric CSV field required")
    return _n(int(value))


def _same(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(
        right, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _stamp(value: os.stat_result) -> tuple[int, ...]:
    return tuple(getattr(value, "st_" + key) for key in
                 ("dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtime_ns", "ctime_ns"))


def _read(path: Path, limit: int = 256 * 1024**2) -> tuple[bytes, tuple[int, ...]]:
    _need(path.is_absolute() and path.resolve(strict=True) == path
          and not any(p.is_symlink() for p in (path, *path.parents)), "canonical source file required")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        before = os.fstat(handle.fileno())
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
              "bounded regular unlinked source required")
        raw = handle.read(limit + 1)
        _need(len(raw) == before.st_size and _stamp(before) == _stamp(os.fstat(handle.fileno()))
              == _stamp(path.lstat()), "source changed while read")
    return raw, _stamp(before)


def _union(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        _need(0 <= start < end, "empty or negative range")
        _need(not result or start >= result[-1][1], "overlapping raw ranges")
        if result and start == result[-1][1]:
            result[-1] = (result[-1][0], end)
        else:
            result.append((start, end))
    return result


def _extent(ranges: list[tuple[int, int]]) -> int:
    return sum(end - start for start, end in _union(ranges))


def _fixed_chaff_stream_configuration(run: Mapping[str, Any], config: Mapping[str, Any]) -> bool:
    """Eight streams require their distinct current Native and typed startup authority."""
    diagnostics = run.get("defense_diagnostics")
    summary = run.get("buflo_summary")
    startup = summary.get("incoming_startup") if isinstance(summary, Mapping) else None
    aggregate = (isinstance(startup, Mapping) and startup.get("schema_version") == 3
                 or isinstance(diagnostics, Mapping) and "buflo_incoming_aggregate_startup" in diagnostics)
    if config.get("max_chaff_streams") == 5:
        _need(not aggregate, "ordinary five-stream configuration cannot claim aggregate startup")
        return True
    _need(type(config.get("max_chaff_streams")) is int and config["max_chaff_streams"] == 8
          and aggregate, "eight streams require explicit aggregate startup3")
    from . import capture_acceptance_policy as acceptance
    _need(acceptance._aggregate_startup_native_supported(run.get("migration_commit"))
          and isinstance(startup, Mapping) and type(startup.get("schema_version")) is int
          and startup["schema_version"] == 3 and isinstance(diagnostics, Mapping)
          and "buflo_incoming_startup" not in diagnostics,
          "aggregate configuration requires its exact current Native and startup namespace")
    acceptance.validate_buflo_aggregate_startup_receipt(startup)
    _need(_same(diagnostics.get("buflo_incoming_aggregate_startup"), startup)
          and run.get("chaff_manifest_hash_sha256") == startup["qualification_manifest_sha256"]
          and acceptance.buflo_incoming_release_window(run) == WINDOW_US,
          "aggregate startup, manifest hash and original cadence64 source binding differ")
    return True


def validate_run_marker(run: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """A marker never enables the policy implicitly or changes the old default."""
    config = run.get("resolved_configuration")
    selected = config.get(FIELD, False) if isinstance(config, Mapping) else False
    _need(type(selected) is bool, "explicit boolean Native selection required")
    if not selected:
        _need(FIELD not in run, "proof exists while Native opt-in is disabled")
        return None
    _need(isinstance(config, Mapping) and isinstance(config.get("defense"), Mapping)
          and config["defense"].get("kind") == "buflo" and config.get("max_udp_payload_size") == CELL
          and config.get("initial_max_stream_data") == 16 and config.get("max_stream_data_excess") == 1000
          and _fixed_chaff_stream_configuration(run, config), "fixed research-1200 BuFLO configuration differs")
    marker = run.get(FIELD)
    _need(isinstance(marker, Mapping) and set(marker) == {"accounting", "physical_proof"}, "exact new marker required")
    accounting = marker["accounting"]
    _need(isinstance(accounting, Mapping) and set(accounting) == {"schema_version", "policy", "requested",
          "gross_advertised", "fin_released", "effective_advertised", "consumed", "retired", "releases"}
          and accounting["schema_version"] == 1 and type(accounting["schema_version"]) is int
          and accounting["policy"] == POLICY and type(accounting["releases"]) is list,
          "exact gross/released/effective schema required")
    for key in ("requested", "gross_advertised", "fin_released", "effective_advertised", "consumed", "retired"):
        _n(accounting[key])
    _need(accounting["gross_advertised"] >= accounting["fin_released"]
          and accounting["gross_advertised"] - accounting["fin_released"] == accounting["effective_advertised"],
          "gross minus released differs from effective permission")
    return marker


def validate_evidence(run: Mapping[str, Any], *, runner_directory: Path) -> dict[str, Any]:
    """Reopen and replay receipt-bound raw files; never accept Native summaries alone.

    This is an additional new-policy proof.  Existing whole handoff/evaluation,
    primary exception, response identity/hash, outgoing physical evidence and
    original admission checks remain required by the caller.
    """
    marker = validate_run_marker(run)
    if marker is None:
        return {}
    paths = {name: runner_directory / (name + suffix) for name, suffix in
             (("run", ".json"), ("events", ".csv"), ("schedule", ".csv"), ("packets", ".csv"))}
    inputs = {name: _read(path) for name, path in paths.items()}
    _need(_same(json.loads(inputs["run"][0]), run), "supplied run differs from actual runner file")
    events = list(csv.DictReader(io.StringIO(inputs["events"][0].decode("utf-8"), newline="")))
    schedule = list(csv.DictReader(io.StringIO(inputs["schedule"][0].decode("utf-8"), newline="")))
    packets = list(csv.DictReader(io.StringIO(inputs["packets"][0].decode("utf-8"), newline="")))
    outgoing_controls = {( _csv_n(row.get("connection")), _csv_n(row.get("monotonic_us")))
        for row in packets if row.get("direction") == "outgoing" and row.get("connection")
        and row.get("defense_control_bytes") and _csv_n(row["defense_control_bytes"]) > 0}
    origin = _n(run.get("defense_start_monotonic_ns"))
    accounting, summary = marker["accounting"], marker["physical_proof"]
    _need(run.get("completion_status") == "complete" and run.get("error") is None,
          "complete error-free Native run required")
    slots: dict[int, dict[str, str]] = {}
    for row in schedule:
        if row.get("direction") != "incoming":
            continue
        slot = _csv_n(row.get("slot_id"))
        _need(slot not in slots and _csv_n(row.get("size")) == CELL, "duplicate or non1200 incoming cell")
        slots[slot] = row
    requested: dict[tuple[int, int], int] = {}
    raw: dict[tuple[int, int], int] = {}
    roles: dict[tuple[int, int], Any] = {}
    reads: dict[tuple[int, int], list[tuple[int, int, int, int]]] = {}
    observations: dict[int, tuple[int, dict[str, str], dict[str, Any]]] = {}
    advertisements: dict[tuple[int, int], list[tuple[int, int, int, int, int]]] = {}
    owned: list[dict[str, int | bool]] = []
    proof_rows: dict[str, list[tuple[int, dict[str, str], dict[str, Any]]]] = {
        name: [] for name in ("release", "replacement", "cell_realization")}
    last_sequence = -1
    primary_bindings = []
    for index, row in enumerate(events):
        detail = json.loads(row["details"])
        if row.get("event") == "terminal_primary_stream_binding":
            primary_bindings.append(detail)
        for name in proof_rows:
            if row.get("event") == "buflo_fin_permission_" + name:
                _need(type(detail) is dict, "proof event is not an object")
                proof_rows[name].append((index, row, detail))
        if type(detail) is not dict or not _uint(detail.get("endpoint")) or not _uint(detail.get("stream")):
            continue
        key = (detail["endpoint"], detail["stream"])
        kind = detail.get("type")
        if row.get("event") == "action" and row.get("outcome") == "applied":
            if kind == "configure_manual_receive":
                _need(key not in requested, "manual stream lifecycle repeated")
                requested[key] = _n(detail.get("initial_limit"))
            elif kind in {"lease_parser_receive", "increase_receive_limit"}:
                previous, end = requested.get(key), _n(detail.get("absolute_limit"))
                _need(_uint(previous) and previous < end, "requested MAX is not strictly advancing")
                if kind == "lease_parser_receive":
                    _need(_n(detail.get("increase")) == end - previous, "lease increase differs from raw frontier")
                owner = detail.get("owner") if kind == "lease_parser_receive" else detail
                if isinstance(owner, Mapping):
                    slot, packet = _n(owner.get("slot")), owner.get("packet")
                    _need(type(packet) is dict and set(packet) == {"timestamp_us", "direction", "length"}
                          and _uint(packet.get("timestamp_us")) and _uint(packet.get("length"))
                          and slot in slots and packet == {"timestamp_us": _csv_n(slots[slot]["target_time_us"]),
                          "direction": "incoming", "length": CELL}, "owner differs from exact original incoming cell")
                    owned.append({"endpoint": key[0], "stream": key[1], "start": previous, "end": end,
                                  "slot": slot, "action_index": index, "parser": kind == "lease_parser_receive", "advertised": False})
                requested[key] = end
        if row.get("event") != "observation":
            continue
        _need(row.get("outcome") == "recorded", "raw observation is not recorded")
        sequence, ns = _n(detail.get("production_sequence")), _n(detail.get("production_monotonic_ns"))
        _need(sequence > last_sequence and _csv_n(row.get("monotonic_us")) == ns // 1000
              and _csv_n(row.get("connection")) == key[0], "raw production sequence/clock/lifecycle differs")
        last_sequence = sequence
        observations[sequence] = (index, row, detail)
        if kind == "stream_opened":
            _need(key not in roles, "stream lifecycle reused")
            roles[key], raw[key], reads[key] = detail.get("role"), 0, []
        elif kind == "bytes_read":
            _need(key in raw, "read lacks actual stream opening")
            end = raw[key] + _n(detail.get("bytes"))
            reads[key].append((raw[key], end, sequence, ns))
            raw[key] = end
        elif kind == "receive_limit_advertised":
            limit = _n(detail.get("absolute_limit"))
            history = advertisements.setdefault(key, [])
            previous_physical = history[-1][0] if history else 16
            for owner in owned:
                if not owner["advertised"] and (owner["endpoint"], owner["stream"]) == key and owner["end"] <= limit and (
                        owner["parser"] or detail.get("slot") is None or detail["slot"] == owner["slot"]):
                    owner["advertised"] = True
                    owner["advertised_sequence"] = sequence
                    owner["advertised_before"] = previous_physical
                    owner["requested_before"] = requested[key]
            if history and limit <= history[-1][0]:
                continue
            # Bootstrap and later MAX records can be slotless and omit the old
            # scalar receipt entirely.  Preserve actual production history;
            # relevant physical handoffs are joined below to packets.csv.
            history.append((limit, sequence, ns, 0, index))
    _need(len(primary_bindings) == 1 and type(primary_bindings[0]) is dict,
          "actual original dispatched primary stream binding required")
    primary = (_n(primary_bindings[0].get("endpoint")), _n(primary_bindings[0].get("stream")))
    advertised = [owner for owner in owned if owner["advertised"]]
    per_stream: dict[tuple[int, int], list[tuple[int, int]]] = {}
    for owner in advertised:
        per_stream.setdefault((owner["endpoint"], owner["stream"]), []).append((owner["start"], owner["end"]))
    for ranges in per_stream.values():
        _union(ranges)

    def observation(sequence: Any, kind: str, key: tuple[int, int]) -> tuple[int, dict[str, str], dict[str, Any]]:
        item = observations.get(_n(sequence))
        _need(item is not None and item[2].get("type") == kind
              and (item[2].get("endpoint"), item[2].get("stream")) == key,
              "proof differs from its exact raw observation")
        return item

    def physical(key: tuple[int, int], sequence: Any, ns: Any, handoff_ns: Any,
                 start: int, end: int, target: int, deadline: int, slot: int) -> tuple[int, int, int, int, int]:
        item = observation(sequence, "receive_limit_advertised", key)
        ads = advertisements.get(key, [])
        matches = [ad for ad in ads if ad[1] == sequence]
        _need(len(matches) == 1, "physical proof does not name an advancing MAX")
        ad = matches[0]
        # Old scalar credit_advertised_at_us is the FIRST owner edge.  A
        # replacement must use the new exact handoff plus actual packet row.
        _need(ad[0] >= end and ad[2] == _n(ns) and (key[0], _n(handoff_ns) // 1000) in outgoing_controls
              and ad[2] <= handoff_ns and target <= handoff_ns < deadline,
              "actual MAX handoff is outside the original half-open window")
        owned_parts = [(max(start, o["start"]), min(end, o["end"])) for o in advertised
            if (o["endpoint"], o["stream"], o["slot"]) == (*key, slot) and o["action_index"] < item[0]
            and o["start"] < end and start < o["end"]]
        _need(_union(owned_parts) == [(start, end)], "physical range has no exact applied original owner")
        return ad

    releases = accounting["releases"]
    _need(len(proof_rows["release"]) == len(releases), "release event/run census differs")
    released_by_slot: dict[int, int] = {}
    released_ranges: dict[tuple[int, int], list[tuple[int, int]]] = {}
    used_fin_sequences: set[int] = set()
    for number, (release, (index, row, proof)) in enumerate(zip(releases, proof_rows["release"])):
        fields = {"release_index", "slot", "endpoint", "stream", "start", "end", "final_size",
                  "fin_at_us", "target_us", "deadline_us", "replacements"}
        _need(type(release) is dict and set(release) == fields and type(release["replacements"]) is list,
              "release schema differs")
        for name in fields - {"replacements"}:
            _n(release[name])
        key = release["endpoint"], release["stream"]
        target, deadline = origin + release["target_us"] * 1000, origin + release["deadline_us"] * 1000
        _need(release["release_index"] == number and release["slot"] in slots and key != primary
              and roles.get(key) == "application" and release["start"] == release["final_size"]
              and release["start"] < release["end"] == requested.get(key)
              and release["target_us"] == _csv_n(slots[release["slot"]]["target_time_us"])
              and release["deadline_us"] - release["target_us"] == WINDOW_US
              and release["target_us"] <= release["fin_at_us"] < release["deadline_us"],
              "secondary release identity/extent/clock differs")
        snapshot = {**release, "replacements": []}
        _need(row.get("outcome") == "proved" and _n(proof.get("schema_version")) == 1 and proof.get("policy") == POLICY
              and _same(proof.get("release"), snapshot) and proof.get("defense_start_monotonic_ns") == origin
              and proof.get("target_monotonic_ns") == target and proof.get("exclusive_deadline_monotonic_ns") == deadline,
              "release proof differs from initial immutable release record")
        read = observation(proof.get("last_raw_read_production_sequence"), "bytes_read", key)
        peer = observation(proof.get("peer_fin_read_production_sequence"), "peer_fin_read", key)
        fin = observation(proof.get("stream_fin_production_sequence"), "stream_finished", key)
        _need(read[0] < peer[0] < fin[0] < index and fin[2].get("finish") == "fin"
              and read[2]["production_monotonic_ns"] == proof.get("last_raw_read_production_monotonic_ns")
              and peer[2]["production_monotonic_ns"] == proof.get("peer_fin_read_production_monotonic_ns")
              and fin[2]["production_monotonic_ns"] == proof.get("stream_fin_production_monotonic_ns")
              and read[2]["production_monotonic_ns"] <= peer[2]["production_monotonic_ns"]
              and target <= peer[2]["production_monotonic_ns"] <= fin[2]["production_monotonic_ns"] < deadline
              and release["fin_at_us"] >= (fin[2]["production_monotonic_ns"] - origin) // 1000,
              "actual final-read/peer-FIN/Fin/release producer order differs")
        _need(fin[2]["production_sequence"] not in used_fin_sequences, "same FIN authorizes a second release")
        used_fin_sequences.add(fin[2]["production_sequence"])
        released_ranges.setdefault(key, []).append((release["start"], release["end"]))
        _union(released_ranges[key])
        p = peer[2]
        for name in ("final_size", "bytes_read", "bytes_received", "buffered_bytes", "encoded_receive_limit", "manual_receive_limit"):
            _n(p.get(name))
        _need(all(p.get(name) == release["final_size"] for name in ("final_size", "bytes_read", "bytes_received"))
              and p.get("buffered_bytes") == 0 and p.get("encoded_receive_limit") == p.get("manual_receive_limit") == release["end"]
              and raw.get(key) == release["final_size"] and reads[key][-1][2] == read[2]["production_sequence"],
              "genuine final read is not drained or its frontier changed")
        headers = [d for _, _, d in observations.values() if d.get("type") == "response_headers"
                   and (d.get("endpoint"), d.get("stream")) == key and _uint(d.get("status")) and d["status"] >= 200]
        _need(len(headers) == 1 and 200 <= headers[0]["status"] < 300 and headers[0]["status"] not in (204, 205)
              and "content_length" in headers[0] and headers[0]["content_length"] is None
              and headers[0]["production_sequence"] < peer[2]["production_sequence"]
              and sum(_n(d.get("data_bytes")) for _, _, d in observations.values()
                  if d.get("type") == "data_frame" and (d.get("endpoint"), d.get("stream")) == key) > 0,
              "release lacks nonbodyless successful unknown-length DATA response")
        originals = [ad for ad in advertisements.get(key, []) if ad[1] < peer[2]["production_sequence"]]
        _need(originals and originals[-1][0] == release["end"], "FIN witness names a stale physical MAX")
        original_ad = physical(key, proof.get("original_max_production_sequence"), proof.get("original_max_production_monotonic_ns"),
                 proof.get("original_max_physical_handoff_monotonic_ns"), release["start"], release["end"], target, deadline, release["slot"])
        _need(original_ad == originals[-1] and original_ad[1] < peer[2]["production_sequence"]
              and proof["original_max_physical_handoff_monotonic_ns"] <= peer[2]["production_monotonic_ns"],
              "original physical MAX follows final read or is not the latest pre-FIN MAX")
        suffix = [(max(o["start"], release["start"]), min(o["end"], release["end"])) for o in advertised
                  if (o["endpoint"], o["stream"], o["slot"]) == (*key, release["slot"])
                  and o["start"] < release["end"] and o["end"] > release["start"]]
        _need(_union(suffix) == [(release["start"], release["end"])], "release includes unowned or another slot's suffix")
        released_by_slot[release["slot"]] = released_by_slot.get(release["slot"], 0) + release["end"] - release["start"]

    replacement_events = proof_rows["replacement"]
    expected = [(release, i, value) for release in releases for i, value in enumerate(release["replacements"])]
    _need(len(replacement_events) == len(expected), "replacement run/event census differs")
    replacement_ranges: dict[tuple[int, int, int], list[tuple[int, int]]] = {}
    owner_partitions: dict[tuple[int, int, int, int, int, int], list[tuple[int, int]]] = {}
    filled = {release["release_index"]: 0 for release in releases}
    for index, _, proof in replacement_events:
        release_index = _n(proof.get("release_index"))
        _need(release_index < len(releases), "replacement names unknown release")
        release = releases[release_index]
        eligible = [r for r in releases if r["slot"] == release["slot"]
                    and proof_rows["release"][r["release_index"]][0] < index
                    and filled[r["release_index"]] < r["end"] - r["start"]]
        _need(eligible and eligible[0]["release_index"] == release_index,
              "replacement skips earlier unfilled same-slot release")
        amount = _n(proof.get("end")) - _n(proof.get("start"))
        _need(0 < amount <= release["end"] - release["start"] - filled[release_index],
              "replacement exceeds remaining FIFO released extent")
        filled[release_index] += amount
    for release, replacement_index, value in expected:
        _need(type(value) is list and len(value) == 5 and all(_uint(v) for v in value), "replacement tuple differs")
        ep, stream, start, end, reduced_us = value
        matches = [(i, row, proof) for i, row, proof in replacement_events
                   if proof.get("release_index") == release["release_index"] and proof.get("replacement_index") == replacement_index]
        _need(len(matches) == 1, "replacement identity missing or repeated")
        index, row, proof = matches[0]
        original = proof_rows["release"][release["release_index"]]
        target, deadline = original[2]["target_monotonic_ns"], original[2]["exclusive_deadline_monotonic_ns"]
        _need(row.get("outcome") == "physically_handed_off" and _n(proof.get("schema_version")) == 1 and proof.get("policy") == POLICY
              and proof.get("slot") == release["slot"] and proof.get("endpoint") == ep == release["endpoint"]
              and proof.get("stream") == stream and proof.get("start") == start < end == proof.get("end")
              and proof.get("controller_reduction_defense_elapsed_us") == reduced_us
              and release["fin_at_us"] <= reduced_us < release["deadline_us"] and original[0] < index
              and proof.get("original_target_monotonic_ns") == target and proof.get("original_exclusive_deadline_monotonic_ns") == deadline,
              "replacement identity/FIN ordering/original clock differs")
        role = roles.get((ep, stream))
        _need(isinstance(role, dict) and set(role) == {"chaff"}, "replacement is not same-connection qualified chaff")
        ad = physical((ep, stream), proof.get("production_sequence"), proof.get("production_monotonic_ns"),
                      proof.get("physical_handoff_monotonic_ns"), start, end, target, deadline, release["slot"])
        history = advertisements[(ep, stream)]
        previous = history[history.index(ad) - 1][0] if history.index(ad) else None
        before, requested_before = _n(proof.get("pre_reduction_advertised_limit")), _n(proof.get("pre_reduction_requested_limit"))
        owner_start, owner_end = _n(proof.get("pre_reduction_owner_start")), _n(proof.get("pre_reduction_owner_end"))
        actual_owners = [o for o in advertised if (o["endpoint"], o["stream"], o["slot"]) == (ep, stream, release["slot"])
                        and o.get("advertised_sequence") == ad[1] and o["start"] == owner_start and o["end"] == owner_end
                        and o.get("advertised_before") == before and o.get("requested_before") == requested_before]
        _need(len(actual_owners) == 1, "pre-reduction owner snapshot differs from exact raw applied action/frontiers")
        owner_partitions.setdefault((ad[1], release["slot"], ep, stream, owner_start, owner_end), []).append((start, end))
        _need((previous is None or previous == before) and before <= start < end <= requested_before
              and ad[0] > before and _n(proof.get("pre_reduction_owner_start")) <= start
              and end <= _n(proof.get("pre_reduction_owner_end"))
              and ad[1] > original[2]["stream_fin_production_sequence"] and ad[2] >= original[2]["stream_fin_production_monotonic_ns"],
              "replacement reuses prior permission or lacks its exact advancing owner")
        replacement_ranges.setdefault((release["slot"], ep, stream), []).append((start, end))
    for release in releases:
        _need(sum(value[3] - value[2] for value in release["replacements"]) == release["end"] - release["start"],
              "released extent not replaced byte-exactly")
    for key, ranges in replacement_ranges.items():
        _union(ranges)
    for (_, _, _, _, start, end), ranges in owner_partitions.items():
        _need(_union(ranges) == [(start, end)], "replacement partitions leave a pre-owner gap")

    realizations = proof_rows["cell_realization"]
    _need(len(realizations) == len(released_by_slot), "released-cell physical completion census differs")
    seen_slots: set[int] = set()
    for index, row, proof in realizations:
        slot = _n(proof.get("slot"))
        for name in ("schema_version", "requested_bytes", "effective_advertised_bytes", "consumed_bytes", "retired_bytes"):
            _n(proof.get(name))
        _need(slot in released_by_slot and slot not in seen_slots and row.get("outcome") == "full_1200_actual_raw_consumed"
              and proof.get("schema_version") == 1 and proof.get("policy") == POLICY
              and all(proof.get(key) == CELL for key in ("requested_bytes", "effective_advertised_bytes", "consumed_bytes"))
              and proof.get("retired_bytes") == 0 and proof.get("gross_permission_is_not_data") is True,
              "secondary released cell is incomplete, repeated, or retired")
        seen_slots.add(slot)
        target = origin + _csv_n(slots[slot]["target_time_us"]) * 1000
        deadline = target + WINDOW_US * 1000
        _need(proof.get("original_target_monotonic_ns") == target and proof.get("original_exclusive_deadline_monotonic_ns") == deadline,
              "realization moves original deadline")
        final_sequence, final_ns = _n(proof.get("final_read_production_sequence")), _n(proof.get("final_read_production_monotonic_ns"))
        final_record = observations.get(final_sequence)
        _need(final_record is not None and final_record[2].get("type") == "bytes_read"
              and final_record[2]["production_monotonic_ns"] == final_ns and final_record[0] < index,
              "eventual realization lacks actual final raw read")
        actual: dict[tuple[int, int], list[tuple[int, int]]] = {}
        contributing_sequences = []
        for owner in advertised:
            if owner["slot"] != slot:
                continue
            key = owner["endpoint"], owner["stream"]
            for start, end, seq, ns in reads[key]:
                left, right = max(start, owner["start"]), min(end, owner["end"])
                if left < right and seq <= final_sequence:
                    actual.setdefault(key, []).append((left, right))
                    contributing_sequences.append(seq)
        _need(contributing_sequences and max(contributing_sequences) == final_sequence,
              "cell realization names an unrelated later raw read")
        reported: dict[tuple[int, int], list[tuple[int, int]]] = {}
        _need(type(proof.get("ranges")) is list, "physical consumed range list required")
        for value in proof["ranges"]:
            key = _n(value.get("endpoint")), _n(value.get("stream"))
            start, end = _n(value.get("start")), _n(value.get("end"))
            physical(key, value.get("production_sequence"), value.get("production_monotonic_ns"),
                     value.get("physical_handoff_monotonic_ns"), start, end, target, deadline, slot)
            _need(value["physical_handoff_monotonic_ns"] <= final_ns, "permission follows actual terminal read")
            covered_reads = [(max(start, a), min(end, b), ns) for a, b, seq, ns in reads[key]
                             if seq <= final_sequence and a < end and start < b]
            _need(_union([(a, b) for a, b, _ in covered_reads]) == [(start, end)]
                  and all(value["physical_handoff_monotonic_ns"] <= ns for _, _, ns in covered_reads),
                  "raw consumption precedes its physical permission")
            reported.setdefault(key, []).append((start, end))
        _need({key: _union(value) for key, value in reported.items()} == {key: _union(value) for key, value in actual.items()}
              and sum(_extent(value) for value in actual.values()) == CELL,
              "physical proof does not reproduce1200 distinct actual raw consumed bytes")
    gross = sum(owner["end"] - owner["start"] for owner in advertised)
    consumed = sum(max(0, min(owner["end"], raw.get((owner["endpoint"], owner["stream"]), 0)) - owner["start"])
                   for owner in advertised)
    released = sum(released_by_slot.values())
    _need(gross == accounting["gross_advertised"] and released == accounting["fin_released"]
          and consumed == accounting["consumed"] and len(slots) * CELL == accounting["requested"]
          == accounting["effective_advertised"] and consumed + accounting["retired"] == accounting["requested"],
          "whole raw gross/released/net/consumed ledger differs")
    diagnostics = run.get("defense_diagnostics")
    _need(isinstance(diagnostics, Mapping) and all(diagnostics.get("scheduled_incoming_" + key + "_bytes") == value for key, value in
          (("requested", accounting["requested"]), ("advertised", accounting["effective_advertised"]),
           ("consumed", consumed), ("retired", accounting["retired"]), ("unresolved", 0))),
          "explicit ledger differs from unchanged original diagnostics")
    _need(_same(summary, {"schema_version": 1, "policy": POLICY, "defense_start_monotonic_ns": origin,
          "genuine_fin_release_records": len(releases), "replacement_advertisement_partitions": len(expected),
          "timely_handoff_eventually_consumed_1200_slots": len(realizations), "wire_datagram_constant_size_claim": False,
          "permission_is_received_data": False}), "Native physical summary differs from recomputed raw proof")
    for name, path in paths.items():
        _need(_stamp(path.lstat()) == inputs[name][1] and _read(path)[0] == inputs[name][0], "bound raw input changed")
    return {"schema_version": 1, "policy": POLICY, "gross_advertised_bytes": gross,
            "fin_released_bytes": released, "effective_advertised_bytes": accounting["effective_advertised"],
            "actual_consumed_bytes": consumed, "retired_bytes": accounting["retired"],
            "genuine_fin_releases": len(releases), "replacement_partitions": len(expected),
            "full_1200_consumed_replacement_cells": len(realizations),
            "released_slots": sorted(released_by_slot),
            "physical_permission_window_us": WINDOW_US, "payload_arrival_deadline_imposed": False,
            "wire_datagram_constant_size_claim": False, "permission_is_received_data": False,
            "raw_files": {name: hashlib.sha256(value[0]).hexdigest() for name, value in inputs.items()}}
