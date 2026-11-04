"""Retroactive, deterministic analysis of consolidated experiment evidence."""

from __future__ import annotations

import csv
import ctypes
import json
import shutil
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import plotting
from .capture import ObserverPacket
from .defenses import defense_from_runtime_identity
from .report import render_report
from .util import load_json


SUMMARY_FIELDS = (
    "sample",
    "sample_id",
    "workload",
    "request_policy",
    "visit",
    "defense",
    "defense_variant",
    "runtime_kind",
    "baseline",
    "state",
    "eligible",
    "attempts",
    "failure",
    "primary_observer",
    "primary_length_basis",
    "wire_bytes",
    "wire_bytes_outgoing",
    "wire_bytes_incoming",
    "wire_packets",
    "wire_packets_outgoing",
    "wire_packets_incoming",
    "udp_payload_bytes",
    "application_bytes",
    "wire_byte_ratio_vs_baseline",
    "wire_byte_overhead_ratio",
    "application_completion_seconds",
    "application_delay_seconds",
    "application_delay_ratio",
    "trace_duration_seconds",
    "defense_tail_seconds",
    "defense_tail_bytes",
    "defense_tail_packets",
    "goodput_bytes_per_second",
    "outgoing_targets",
    "outgoing_targets_satisfied",
    "target_satisfaction_ratio",
    "outgoing_targets_exact",
    "target_exactness_ratio",
    "missed_slots",
    "missed_slot_reasons",
    "padding_events",
    "padding_event_guard_triggered",
    "operationally_valid",
    "fidelity_realization_errors",
    "observer_packets",
)


@dataclass(frozen=True)
class AnalysisResult:
    result_root: Path
    derived_root: Path
    summary: Path
    report: Path
    plots: tuple[Path, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "result": str(self.result_root),
            "derived": str(self.derived_root),
            "summary": str(self.summary),
            "report": str(self.report),
            "plots": [str(path) for path in self.plots],
        }


def _verify_result(root: Path) -> Any:
    """Late binding keeps analysis importable while verification is isolated."""

    from .verification import verify_result

    return verify_result(root)


def _trace_for_sample(sample: Path) -> list[ObserverPacket]:
    return plotting.trace_for_sample(sample)


def analyze_result(
    root: Path | str,
    *,
    validation_attestation: Path | None = None,
) -> AnalysisResult:
    """Verify evidence and atomically regenerate the complete ``derived/`` tree."""

    result_root = Path(root).resolve()
    _verify_result(result_root)
    experiment = _load_experiment(result_root)
    samples = _ordered_samples(experiment)

    # Keep staging outside the sealed result root.  Verification therefore
    # continues to see an exact top-level evidence layout even if analysis is
    # interrupted by process termination before cleanup can run.
    stage = Path(
        tempfile.mkdtemp(
            prefix=f".{result_root.name}-derived-stage-",
            dir=result_root.parent,
        )
    )
    try:
        records, traces = _records(result_root, samples)
        summary_path = stage / "summary.csv"
        _write_summary(summary_path, records)

        figures = _write_plots(stage / "plots", records, traces)
        report_figures = [
            {
                "title": title,
                "caption": caption,
                "svg": path.read_text(encoding="utf-8"),
            }
            for path, title, caption in figures
        ]
        (stage / "report.html").write_text(
            render_report(
                experiment,
                records,
                report_figures,
                validation_attestation=validation_attestation,
            ),
            encoding="utf-8",
        )
        _replace_derived(result_root, stage)
    except BaseException:
        if stage.exists():
            shutil.rmtree(stage)
        raise

    derived = result_root / "derived"
    plot_paths = tuple(derived / path.relative_to(stage) for path, _title, _caption in figures)
    return AnalysisResult(
        result_root=result_root,
        derived_root=derived,
        summary=derived / "summary.csv",
        report=derived / "report.html",
        plots=plot_paths,
    )


def _load_experiment(root: Path) -> dict[str, Any]:
    path = root / "experiment.json"
    if not path.is_file():
        raise ValueError(f"result has no experiment.json: {root}")
    value = load_json(path)
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("analysis requires experiment schema_version 1")
    if not isinstance(value.get("samples"), list):
        raise ValueError("experiment samples must be a list")
    return value


def _ordered_samples(experiment: Mapping[str, Any]) -> list[dict[str, Any]]:
    samples = experiment.get("samples")
    if not isinstance(samples, list) or any(not isinstance(item, dict) for item in samples):
        raise ValueError("experiment samples must contain objects")
    by_id: dict[str, dict[str, Any]] = {}
    for sample in samples:
        sample_id = sample.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id or sample_id in by_id:
            raise ValueError("experiment sample IDs must be unique non-empty strings")
        _sample_relative_path(sample)
        by_id[sample_id] = sample
    execution_order = experiment.get("execution_order")
    if (
        not isinstance(execution_order, list)
        or any(not isinstance(item, str) for item in execution_order)
        or len(execution_order) != len(set(execution_order))
        or set(execution_order) != set(by_id)
    ):
        raise ValueError("execution_order must contain every sample ID exactly once")
    return [by_id[sample_id] for sample_id in execution_order]


def _sample_relative_path(sample: Mapping[str, Any]) -> Path:
    value = sample.get("path")
    if not isinstance(value, str) or not value:
        raise ValueError("experiment sample path is missing")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "samples":
        raise ValueError(f"experiment sample path is unsafe: {value}")
    return path


def _records(
    root: Path,
    samples: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[Path, list[ObserverPacket]]]:
    records = []
    traces: dict[Path, list[ObserverPacket]] = {}
    for sample in samples:
        relative = _sample_relative_path(sample)
        path = root / relative
        defense_variant = sample.get("defense")
        runtime_kind = sample.get("runtime_kind")
        defense = defense_from_runtime_identity(defense_variant, runtime_kind)
        record = {
            "sample": relative.as_posix(),
            "_sample_path": path,
            "sample_id": sample.get("sample_id"),
            "workload": sample.get("workload_id"),
            "request_policy": sample.get("request_policy"),
            "visit": sample.get("visit"),
            # Derived metrics aggregate by the scientific defence identity.
            # Preserve the campaign's custom label separately so reports can
            # still distinguish experimental variants of one implementation.
            "defense": defense,
            "defense_variant": defense_variant,
            "runtime_kind": runtime_kind,
            "baseline": sample.get("baseline") is True,
            "state": sample.get("state"),
            "eligible": sample.get("eligible") is True,
            "attempts": sample.get("attempts"),
            "failure": sample.get("failure"),
        }
        if sample.get("state") == "accepted":
            trace = _trace_for_sample(path)
            traces[path] = trace
            record.update(plotting.calculate_metrics(path, defense, trace=trace))
        records.append(record)
    _pair_baselines(records)
    return records, traces


def _group_key(record: Mapping[str, Any]) -> tuple[str, str, int]:
    workload = record.get("workload")
    policy = record.get("request_policy")
    visit = record.get("visit")
    if not isinstance(workload, str) or not isinstance(policy, str) or type(visit) is not int:
        raise ValueError("sample workload, request_policy, and visit are required for analysis")
    return workload, policy, visit


def _pair_baselines(records: Sequence[dict[str, Any]]) -> None:
    baselines: dict[tuple[str, str, int], dict[str, Any]] = {}
    for record in records:
        if (
            record.get("baseline") is True
            and record.get("state") == "accepted"
            and record.get("eligible") is True
        ):
            key = _group_key(record)
            if key in baselines:
                raise ValueError(f"paired visit has multiple eligible baselines: {key}")
            baselines[key] = record
    for record in records:
        baseline = baselines.get(_group_key(record))
        if (
            baseline is None
            or record.get("state") != "accepted"
            or record.get("eligible") is not True
        ):
            continue
        record["wire_byte_ratio_vs_baseline"] = _ratio(
            record.get("wire_bytes"), baseline.get("wire_bytes")
        )
        record["wire_byte_overhead_ratio"] = _overhead(
            record.get("wire_bytes"), baseline.get("wire_bytes")
        )
        record["application_delay_seconds"] = _difference(
            record.get("application_completion_seconds"),
            baseline.get("application_completion_seconds"),
        )
        record["application_delay_ratio"] = _overhead(
            record.get("application_completion_seconds"),
            baseline.get("application_completion_seconds"),
        )


def _ratio(value: object, baseline: object) -> float | None:
    if value is None or baseline is None or float(baseline) == 0:
        return None
    return float(value) / float(baseline)


def _overhead(value: object, baseline: object) -> float | None:
    ratio = _ratio(value, baseline)
    return ratio - 1 if ratio is not None else None


def _difference(value: object, baseline: object) -> float | None:
    if value is None or baseline is None:
        return None
    return float(value) - float(baseline)


def _write_summary(path: Path, records: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=SUMMARY_FIELDS, lineterminator="\n")
        writer.writeheader()
        for record in records:
            row = {field: record.get(field) for field in SUMMARY_FIELDS}
            for field in ("failure", "missed_slot_reasons", "fidelity_realization_errors"):
                value = row.get(field)
                row[field] = (
                    json.dumps(value, sort_keys=True, separators=(",", ":"))
                    if value not in (None, "", {})
                    else ""
                )
            writer.writerow(row)


def _write_plots(
    plots_root: Path,
    records: Sequence[dict[str, Any]],
    traces: Mapping[Path, Sequence[ObserverPacket]],
) -> list[tuple[Path, str, str]]:
    eligible = [
        record
        for record in records
        if record.get("state") == "accepted" and record.get("eligible") is True
    ]
    figures: list[tuple[Path, str, str]] = []
    latency = plotting.plot_aggregate_latency(eligible, plots_root / "aggregate-latency.svg")
    figures.append(
        (
            latency,
            "Aggregate application completion",
            "Bars are per-defence medians over eligible samples.",
        )
    )
    overhead = plotting.plot_aggregate_overhead(eligible, plots_root / "aggregate-overhead.svg")
    figures.append(
        (
            overhead,
            "Aggregate paired wire-byte overhead",
            "Each sample is paired with its eligible undefended workload/policy/visit baseline.",
        )
    )

    groups: dict[tuple[str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[_group_key(record)].append(record)
    for (workload, policy, visit), members in sorted(groups.items()):
        if not _complete_paired_group(members):
            continue
        group_root = plots_root / _identifier(workload) / _identifier(policy) / f"visit-{visit:03d}"
        samples = [(str(member["defense"]), Path(member["_sample_path"])) for member in members]
        variants = {
            Path(member["_sample_path"]): str(member.get("defense_variant") or member["defense"])
            for member in members
        }
        pages = plotting.plot_trace_comparison(
            samples,
            group_root / "trace-comparison",
            traces=traces,
            variants=variants,
        )
        for page, output in enumerate(pages, start=1):
            suffix = "" if page == 1 else f", page {page}"
            figures.append(
                (
                    output,
                    f"{workload} / {policy} / visit {visit}{suffix}",
                    "Observed packet density, controller-action density, signed frame sizes, "
                    "application completion, and defence tail. Time axes are panel-local.",
                )
            )
    return figures


def _complete_paired_group(members: Sequence[Mapping[str, Any]]) -> bool:
    return (
        len(members) >= 2
        and sum(member.get("baseline") is True for member in members) == 1
        and all(
            member.get("state") == "accepted" and member.get("eligible") is True
            for member in members
        )
    )


def _identifier(value: str) -> str:
    path = Path(value)
    if (
        not value
        or path.name != value
        or value in {".", ".."}
        or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
            for character in value
        )
    ):
        raise ValueError(f"analysis identifier is not path-safe: {value!r}")
    return value


def _replace_derived(root: Path, stage: Path) -> None:
    destination = root / "derived"
    if destination.exists():
        _exchange_directories(stage, destination)
        shutil.rmtree(stage)
    else:
        stage.replace(destination)


def _exchange_directories(left: Path, right: Path) -> None:
    """Atomically exchange two Linux directory entries on the same filesystem."""

    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as error:  # pragma: no cover - lab images are Linux/glibc
        raise RuntimeError("atomic derived replacement requires renameat2") from error
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100,
        str(left).encode(),
        -100,
        str(right).encode(),
        2,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, "atomic derived directory exchange failed")
