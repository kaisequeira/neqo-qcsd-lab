"""Strict readers for the sealed Neqo evidence consumed by research fitters."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .class_run_binding import (
    ClassSampleRunBinding,
    validate_class_sample_run_binding,
)
from .util import load_json, sha256_bytes


EVENT_COLUMNS = ["monotonic_us", "connection", "event", "outcome", "details"]
MAX_U64 = 2**64 - 1


@dataclass(frozen=True)
class PacketObservation:
    """One direct runner packet inside the application fitting window."""

    direction: str
    monotonic_ns: int
    connection: int
    length_bytes: int

    @property
    def monotonic_us(self) -> int:
        """Inclusive runtime histogram time, rounded up from production nanoseconds."""

        return (self.monotonic_ns + 999) // 1_000


@dataclass(frozen=True)
class TypedObservation:
    """One causally ordered serialized ``QcsdObservation``."""

    sequence: int
    production_monotonic_ns: int
    connection: int | None
    kind: str
    details: Mapping[str, Any]


@dataclass(frozen=True)
class FittingTrace:
    """The immutable evidence and identity for one accepted fitting sample."""

    sample_id: str
    workload_id: str
    request_policy: str
    visit: int
    root: Path
    packets: tuple[PacketObservation, ...]
    observations: tuple[TypedObservation, ...]
    training_input_sha256: str
    consumed_evidence: tuple[tuple[str, str], ...] = ()


def load_fitting_trace(
    sample_root: Path,
    *,
    sample_id: str,
    workload_id: str,
    request_policy: str,
    visit: int,
    udp_payload_ceiling: int = 1_200,
    require_observations: bool = False,
    accepted_artifacts: Mapping[str, str] | None = None,
    seed: int | None = None,
    run_binding: ClassSampleRunBinding | None = None,
) -> FittingTrace:
    """Read typed, natural datagrams and application events from ``events.csv`` only."""

    sample_root = sample_root.resolve()
    neqo = sample_root / "neqo"
    run_path = neqo / "run.json"
    events_path = neqo / "events.csv"
    for path in (run_path, events_path):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"fitting evidence is missing a regular file: {path}")

    run = load_json(run_path)
    if (
        not isinstance(run, Mapping)
        or run.get("completion_status") != "complete"
        or run.get("error") is not None
        or run.get("error_class") is not None
    ):
        raise ValueError(f"fitting sample did not complete: {sample_id}")
    if run_binding is not None:
        if type(seed) is not int:
            raise ValueError(f"fitting sample has no integer seed: {sample_id}")
        validate_class_sample_run_binding(
            run,
            {
                "workload_id": workload_id,
                "defense": "undefended",
                "runtime_kind": "none",
                "baseline": True,
                "seed": seed,
                "request_policy": request_policy,
            },
            run_binding,
        )
    start_ns = _integer(run.get("defense_start_monotonic_ns"), "defense start", run_path)
    completion_ns = _integer(
        run.get("application_completion_monotonic_ns"),
        "application completion",
        run_path,
    )
    if completion_ns < start_ns:
        raise ValueError(f"fitting application window is reversed: {run_path}")
    observations = _read_observations(events_path)
    packets = _natural_datagrams(
        observations,
        start_ns=start_ns,
        completion_ns=completion_ns,
        udp_payload_ceiling=udp_payload_ceiling,
        path=events_path,
    )
    retained_observations = (
        _application_observations(
            observations,
            start_ns=start_ns,
            completion_ns=completion_ns,
            path=events_path,
        )
        if require_observations
        else ()
    )
    consumed_evidence = _consumed_bindings(
        sample_root,
        accepted_artifacts,
        {"neqo/events.csv": events_path, "neqo/run.json": run_path},
    )
    identity_payload = {
        "consumed_evidence": dict(consumed_evidence),
        "request_policy": request_policy,
        "sample_id": sample_id,
        "visit": visit,
        "workload_id": workload_id,
    }
    identity = sha256_bytes(
        b"qcsd-fitting-trace-v1\0"
        + json.dumps(identity_payload, sort_keys=True, separators=(",", ":")).encode()
    )
    return FittingTrace(
        sample_id=sample_id,
        workload_id=workload_id,
        request_policy=request_policy,
        visit=visit,
        root=sample_root,
        packets=packets,
        observations=retained_observations,
        training_input_sha256=identity,
        consumed_evidence=consumed_evidence,
    )


def _natural_datagrams(
    observations: tuple[TypedObservation, ...],
    *,
    start_ns: int,
    completion_ns: int,
    udp_payload_ceiling: int,
    path: Path,
) -> tuple[PacketObservation, ...]:
    rows: list[PacketObservation] = []
    for observation in observations:
        if observation.kind != "classified_datagram":
            continue
        details = observation.details
        datagram_class = details.get("class")
        if datagram_class not in {"natural", "defense_cover"}:
            raise ValueError(f"classified datagram has an invalid causal class: {path}")
        direction = details.get("direction")
        if direction not in {"outgoing", "incoming"}:
            raise ValueError(f"classified datagram has an invalid direction: {path}")
        endpoint = _integer(details.get("endpoint"), "classified datagram endpoint", path)
        if observation.connection is not None and observation.connection != endpoint:
            raise ValueError(f"classified datagram endpoint binding is inconsistent: {path}")
        length = _integer(details.get("length"), "classified datagram length", path)
        if not 1 <= length <= udp_payload_ceiling:
            raise ValueError(
                f"classified datagram length is outside [1, {udp_payload_ceiling}]: {path}"
            )
        if (
            datagram_class == "natural"
            and start_ns <= observation.production_monotonic_ns <= completion_ns
        ):
            rows.append(
                PacketObservation(
                    str(direction),
                    observation.production_monotonic_ns,
                    endpoint,
                    length,
                )
            )
    if not rows:
        raise ValueError(
            f"fitting trace contains no natural datagrams in the application window: {path}"
        )
    directions = {row.direction for row in rows}
    if directions != {"outgoing", "incoming"}:
        raise ValueError(f"fitting trace requires natural datagrams in both directions: {path}")
    return tuple(rows)


def _application_observations(
    observations: tuple[TypedObservation, ...],
    *,
    start_ns: int,
    completion_ns: int,
    path: Path,
) -> tuple[TypedObservation, ...]:
    """Retain the numeric application window plus its unique causal closure marker."""

    markers = [
        (index, observation)
        for index, observation in enumerate(observations)
        if observation.kind == "application_complete"
    ]
    if len(markers) != 1:
        raise ValueError(f"fitting trace requires exactly one application_complete: {path}")
    marker_index, marker = markers[0]
    if marker.production_monotonic_ns < completion_ns:
        raise ValueError(f"application_complete precedes the numeric completion boundary: {path}")
    if any(
        observation.production_monotonic_ns > completion_ns
        for observation in observations[:marker_index]
    ):
        raise ValueError(
            f"typed observation intervenes between completion boundary and marker: {path}"
        )
    retained = tuple(
        observation
        for observation in observations[: marker_index + 1]
        if start_ns <= observation.production_monotonic_ns <= completion_ns
    )
    if marker.production_monotonic_ns > completion_ns:
        retained = (*retained, marker)
    return retained


def _read_observations(path: Path) -> tuple[TypedObservation, ...]:
    observations: list[TypedObservation] = []
    with path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != EVENT_COLUMNS:
            raise ValueError(f"Walkie-Talkie event evidence has invalid columns: {path}")
        for line, row in enumerate(reader, 2):
            if row.get("event") != "observation" or row.get("outcome") != "recorded":
                continue
            try:
                details = json.loads(row.get("details") or "")
            except json.JSONDecodeError as error:
                raise ValueError(f"typed observation is invalid JSON at {path}:{line}") from error
            if not isinstance(details, dict):
                raise ValueError(f"typed observation must be a JSON object at {path}:{line}")
            sequence = _integer(details.get("production_sequence"), "production sequence", path)
            production_ns = _integer(
                details.get("production_monotonic_ns"), "production timestamp", path
            )
            recorded_us = _csv_integer(row.get("monotonic_us"), "monotonic_us", path, line)
            if recorded_us != production_ns // 1_000:
                raise ValueError(f"event timestamp does not match production time: {path}:{line}")
            kind = details.get("type")
            if not isinstance(kind, str) or not kind:
                raise ValueError(f"typed observation has no type at {path}:{line}")
            connection_text = row.get("connection") or ""
            connection = (
                None
                if connection_text == ""
                else _csv_integer(connection_text, "connection", path, line)
            )
            observations.append(
                TypedObservation(sequence, production_ns, connection, kind, details)
            )
    if not observations:
        raise ValueError(f"trace contains no causal typed observations: {path}")
    sequences = [item.sequence for item in observations]
    if sorted(sequences) != list(range(len(observations))):
        raise ValueError(f"production sequences must be unique and contiguous from zero: {path}")
    causal_keys = [(item.production_monotonic_ns, item.sequence) for item in observations]
    if causal_keys != sorted(causal_keys):
        raise ValueError(f"causal production order is not monotonic: {path}")
    return tuple(observations)


def _integer(value: object, label: str, path: Path) -> int:
    if type(value) is not int or not 0 <= value <= MAX_U64:
        raise ValueError(f"{label} must be an unsigned integer: {path}")
    return value


def _csv_integer(value: object, label: str, path: Path, line: int) -> int:
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdecimal():
        raise ValueError(f"{label} must be an unsigned integer at {path}:{line}")
    parsed = int(value)
    if parsed > MAX_U64:
        raise ValueError(f"{label} exceeds u64 at {path}:{line}")
    return parsed


def _file_digest(path: Path) -> str:
    from .util import sha256_file

    return sha256_file(path)


def _consumed_bindings(
    sample_root: Path,
    accepted_artifacts: Mapping[str, str] | None,
    consumed: Mapping[str, Path],
) -> tuple[tuple[str, str], ...]:
    if accepted_artifacts is None:
        return tuple((name, _file_digest(path)) for name, path in sorted(consumed.items()))
    result: list[tuple[str, str]] = []
    for name, path in sorted(consumed.items()):
        matches = [
            digest
            for relative, digest in accepted_artifacts.items()
            if relative.endswith(f"/{name}")
        ]
        if len(matches) != 1 or matches[0] != _file_digest(path):
            raise ValueError(
                f"consumed fitting evidence is not bound by the accepted sample: {sample_root / name}"
            )
        result.append((name, matches[0]))
    return tuple(result)
