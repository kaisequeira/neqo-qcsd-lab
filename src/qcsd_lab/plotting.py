"""Deterministic figures derived from consolidated experiment evidence.

This module deliberately has no result-writing orchestration.  It accepts
explicit sample paths and metric rows, writes SVG files only, and never reads
``experiment.json``.  Keeping that boundary small makes retroactive analysis
independent from capture collection and keeps all result-layout knowledge in
``analysis.py``.
"""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.lines import Line2D

from .capture import ObserverPacket, extract_trace
from .defenses import DEFENSE_LABELS, DEFENSE_ORDER, canonical_defense
from .util import load_json, padding_event_guard_triggered

OUTGOING = "#1f77b4"
INCOMING = "#ff7f0e"
COMPLETION = "#4d4d4d"
_SVG_CONTEXT = {"svg.fonttype": "path", "svg.hashsalt": "neqo-qcsd-lab"}


def _rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source))


def trace_for_sample(sample: Path) -> list[ObserverPacket]:
    """Reproduce a sample's observer trace directly from sealed evidence."""

    run_data = load_json(sample / "neqo" / "run.json")
    trace = extract_trace(sample / "capture.pcapng", run_data.get("endpoints", []))
    if not trace:
        raise ValueError(f"direct capture trace is empty: {sample}")
    return trace


def _completion_seconds(sample: Path, trace: Sequence[ObserverPacket]) -> float | None:
    run_data = load_json(sample / "neqo" / "run.json")
    completion = run_data.get("application_completion_monotonic_ns")
    if completion is None:
        return None
    anchor = run_data.get("time_anchor_unix_ns")
    if trace and anchor is not None:
        completion_unix_ns = int(anchor) + int(completion)
        return (completion_unix_ns - trace[0].timestamp_unix_ns) / 1e9
    return float(completion) / 1e9


def _schedule_action_times(
    sample: Path,
    direction: str,
    trace: Sequence[ObserverPacket],
) -> np.ndarray:
    """Return every timestamped controller action in one direction.

    These are action-density overlays.  Incoming replacement-credit actions
    are retained and must not be interpreted as additional logical cells.
    """

    run_data = load_json(sample / "neqo" / "run.json")
    anchor = run_data.get("time_anchor_unix_ns")
    if not trace or anchor is None:
        return np.asarray([], dtype=float)
    actions = []
    for row in _rows(sample / "neqo" / "schedule.csv"):
        if row.get("direction") != direction:
            continue
        try:
            action_time_us = int(row["action_time_us"])
        except (KeyError, TypeError, ValueError):
            continue
        action_unix_ns = int(anchor) + action_time_us * 1_000
        actions.append((action_unix_ns - trace[0].timestamp_unix_ns) / 1e9)
    return np.asarray(actions, dtype=float)


def _realization_errors(defense: str, diagnostics: Mapping[str, Any]) -> dict[str, Any]:
    prefixes = {
        "traffic-morphing": ("morphing_",),
        "wtf-pad": ("padding_event_guard_", "wtf_pad_"),
        "walkie-talkie": ("walkie_talkie_",),
    }.get(canonical_defense(defense), ())
    markers = (
        "bypass",
        "deficit",
        "distance",
        "error",
        "guard",
        "l1",
        "lag_us_max",
        "overflow",
        "shortfall",
        "unrealized",
    )
    return {
        key: value
        for key, value in sorted(diagnostics.items())
        if key.startswith(prefixes) and any(marker in key for marker in markers)
    }


def calculate_metrics(
    sample: Path,
    defense: str | None = None,
    *,
    trace: Sequence[ObserverPacket] | None = None,
) -> dict[str, Any]:
    """Calculate observer and controller metrics from authoritative files only."""

    actual_trace = list(trace) if trace is not None else trace_for_sample(sample)
    run_data = load_json(sample / "neqo" / "run.json")
    schedule = _rows(sample / "neqo" / "schedule.csv")
    diagnostics = run_data.get("defense_diagnostics")
    if not isinstance(diagnostics, dict):
        diagnostics = {}
    identity = canonical_defense(defense or sample.name)

    outgoing = [packet for packet in actual_trace if packet.direction == "outgoing"]
    incoming = [packet for packet in actual_trace if packet.direction == "incoming"]
    completion = _completion_seconds(sample, actual_trace)
    trace_duration = max(
        (packet.relative_time_ns / 1e9 for packet in actual_trace),
        default=0.0,
    )
    tail = [
        packet
        for packet in actual_trace
        if completion is not None and packet.relative_time_ns / 1e9 > completion
    ]
    targets = [row for row in schedule if row.get("direction") == "outgoing"]
    satisfied = [row for row in targets if row.get("satisfaction") == "satisfied"]
    exact = []
    for row in satisfied:
        try:
            if int(row["observed_size"]) == int(row["size"]):
                exact.append(row)
        except (KeyError, TypeError, ValueError):
            pass
    misses = [row for row in schedule if row.get("satisfaction") == "missed"]
    miss_reasons = Counter(row["miss_reason"] for row in misses if row.get("miss_reason"))
    udp_bytes = sum(packet.udp_payload_len or 0 for packet in actual_trace)
    application_bytes = sum(
        int(response.get("bytes", 0)) for response in run_data.get("responses", [])
    )
    guard_triggered = padding_event_guard_triggered(run_data)
    return {
        "wire_bytes": sum(packet.frame_len for packet in actual_trace),
        "wire_bytes_outgoing": sum(packet.frame_len for packet in outgoing),
        "wire_bytes_incoming": sum(packet.frame_len for packet in incoming),
        "wire_packets": len(actual_trace),
        "wire_packets_outgoing": len(outgoing),
        "wire_packets_incoming": len(incoming),
        "udp_payload_bytes": udp_bytes,
        "application_bytes": application_bytes,
        "application_completion_seconds": completion,
        "trace_duration_seconds": trace_duration,
        "defense_tail_seconds": (
            max(0.0, trace_duration - completion) if completion is not None else None
        ),
        "defense_tail_bytes": sum(packet.frame_len for packet in tail),
        "defense_tail_packets": len(tail),
        "goodput_bytes_per_second": application_bytes / completion if completion else None,
        "outgoing_targets": len(targets),
        "outgoing_targets_satisfied": len(satisfied),
        "target_satisfaction_ratio": len(satisfied) / len(targets) if targets else None,
        "outgoing_targets_exact": len(exact),
        "target_exactness_ratio": len(exact) / len(satisfied) if satisfied else None,
        "missed_slots": len(misses),
        "missed_slot_reasons": dict(miss_reasons),
        "padding_events": diagnostics.get("padding_events"),
        "padding_event_guard_triggered": guard_triggered,
        "operationally_valid": not guard_triggered,
        "fidelity_realization_errors": _realization_errors(identity, diagnostics),
        "observer_packets": len(actual_trace),
        "primary_observer": "direct-quic",
        "primary_length_basis": "frame.len",
    }


def _bandwidth(values: np.ndarray, span: float) -> float:
    minimum = max(0.005, span / 500)
    if len(values) <= 1:
        return max(0.01, span / 100)
    deviation = float(np.std(values, ddof=1))
    return max(1.06 * max(deviation, 1e-6) * len(values) ** (-0.2), minimum)


def _density(values: np.ndarray, grid: np.ndarray, bandwidth: float) -> np.ndarray:
    if not len(values):
        return np.zeros_like(grid)
    distances = (grid[:, None] - values[None, :]) / bandwidth
    return np.exp(-0.5 * distances**2).sum(axis=1) / (len(values) * bandwidth * np.sqrt(2 * np.pi))


def _defense_rank(defense: str) -> tuple[int, str]:
    identity = canonical_defense(defense)
    try:
        return DEFENSE_ORDER.index(identity), identity
    except ValueError:
        return len(DEFENSE_ORDER), identity


def _treatment(record: Mapping[str, Any]) -> tuple[str, str]:
    defense = canonical_defense(str(record.get("defense", "")))
    variant = str(record.get("defense_variant") or defense)
    return defense, variant


def _treatment_label(defense: str, variant: str) -> str:
    label = DEFENSE_LABELS.get(defense, defense)
    return label if canonical_defense(variant) == defense else f"{label} ({variant})"


def _save_svg(figure: plt.Figure, destination: Path, title: str) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with plt.rc_context(_SVG_CONTEXT):
        figure.savefig(
            destination,
            format="svg",
            metadata={"Title": title, "Creator": "neqo-qcsd-lab", "Date": None},
        )
    plt.close(figure)
    return destination


def plot_trace_comparison(
    samples: Sequence[tuple[str, Path]],
    destination_prefix: Path,
    *,
    traces: Mapping[Path, Sequence[ObserverPacket]] | None = None,
    variants: Mapping[Path, str] | None = None,
) -> list[Path]:
    """Plot one complete paired visit, emitting pages of at most four modes."""

    variants = variants or {}
    ordered = sorted(
        samples,
        key=lambda item: (*_defense_rank(item[0]), variants.get(item[1], item[0])),
    )
    if len(ordered) < 2:
        raise ValueError("a paired trace comparison requires at least two samples")
    resolved_traces = {
        path: list(traces[path])
        if traces is not None and path in traces
        else trace_for_sample(path)
        for _defense, path in ordered
    }
    if any(not trace for trace in resolved_traces.values()):
        raise ValueError("a paired trace comparison contains an empty observer trace")
    scatter_limit = max(packet.frame_len for trace in resolved_traces.values() for packet in trace)
    outputs = []
    for page, start in enumerate(range(0, len(ordered), 4), start=1):
        panels = ordered[start : start + 4]
        suffix = "" if page == 1 else f"-{page}"
        destination = destination_prefix.with_name(destination_prefix.name + suffix).with_suffix(
            ".svg"
        )
        outputs.append(
            _plot_trace_page(
                panels,
                destination,
                {path: resolved_traces[path] for _defense, path in panels},
                scatter_limit,
                variants,
            )
        )
    return outputs


def _plot_trace_page(
    panels: Sequence[tuple[str, Path]],
    destination: Path,
    traces: Mapping[Path, Sequence[ObserverPacket]],
    scatter_limit: int,
    variants: Mapping[Path, str],
) -> Path:
    figure, axes = plt.subplots(
        2,
        len(panels),
        figsize=(4.25 * len(panels), 5.7),
        sharex="col",
        sharey=False,
        gridspec_kw={"height_ratios": [1, 2.3], "hspace": 0.06, "wspace": 0.08},
    )
    axes = np.asarray(axes).reshape(2, len(panels))
    for column, (defense, sample) in enumerate(panels):
        trace = traces[sample]
        trace_end = max(packet.relative_time_ns / 1e9 for packet in trace)
        maximum_time = trace_end if trace_end > 0 else np.finfo(float).eps
        grid = np.linspace(0, maximum_time, 600)
        observed = {
            direction: np.asarray(
                [packet.relative_time_ns / 1e9 for packet in trace if packet.direction == direction]
            )
            for direction in ("outgoing", "incoming")
        }
        all_observed = np.concatenate([values for values in observed.values() if len(values)])
        bandwidth = _bandwidth(all_observed, maximum_time)
        densities = []
        density_axis = axes[0, column]
        packet_axis = axes[1, column]
        for direction, color in (("outgoing", OUTGOING), ("incoming", INCOMING)):
            density = _density(observed[direction], grid, bandwidth)
            densities.append(density)
            density_axis.plot(grid, density, color=color, linestyle="-", linewidth=1.4)
            actions = _schedule_action_times(sample, direction, trace)
            if len(actions):
                density_axis.plot(
                    grid,
                    _density(actions, grid, bandwidth),
                    color=color,
                    linestyle="--",
                    linewidth=1.25,
                )
        for packet in trace:
            color = OUTGOING if packet.direction == "outgoing" else INCOMING
            packet_axis.scatter(
                packet.relative_time_ns / 1e9,
                packet.signed_frame_len,
                facecolors="none",
                edgecolors=color,
                marker="o",
                s=15,
                linewidths=0.7,
            )
        completion = _completion_seconds(sample, trace)
        if completion is not None:
            for axis in (density_axis, packet_axis):
                axis.axvline(completion, color=COMPLETION, linestyle=":", linewidth=1)
                if completion < trace_end:
                    axis.axvspan(
                        max(0.0, completion),
                        trace_end,
                        color="#8c8c8c",
                        alpha=0.13,
                        linewidth=0,
                    )
        identity = canonical_defense(defense)
        density_axis.set_title(
            _treatment_label(identity, variants.get(sample, defense)), fontsize=11
        )
        for axis in (density_axis, packet_axis):
            axis.grid(alpha=0.18, linewidth=0.5)
            axis.set_xlim(0, maximum_time)
        packet_axis.axhline(0, color="#777777", linewidth=0.6)
        packet_axis.set_xlabel("Time (s)")
        density_axis.set_ylim(0, max(max(float(np.max(item)) for item in densities) * 1.05, 1e-9))
        packet_axis.set_ylim(-max(scatter_limit, 1) * 1.08, max(scatter_limit, 1) * 1.08)
    axes[0, 0].set_ylabel("Packet-time\ndensity")
    axes[1, 0].set_ylabel("Signed direct-quic frame.len (bytes)")
    figure.legend(
        handles=[
            Line2D([], [], color=OUTGOING, linestyle="-", label="Outgoing observed"),
            Line2D([], [], color=OUTGOING, linestyle="--", label="Outgoing actions"),
            Line2D([], [], color=INCOMING, linestyle="-", label="Incoming observed"),
            Line2D([], [], color=INCOMING, linestyle="--", label="Incoming actions"),
            Line2D([], [], color=COMPLETION, linestyle=":", label="Application complete"),
            Line2D([], [], color="#8c8c8c", linewidth=7, alpha=0.25, label="Defense tail"),
            Line2D(
                [],
                [],
                color="#555555",
                marker="o",
                markerfacecolor="none",
                linestyle="none",
                label="Observed packet",
            ),
        ],
        loc="upper center",
        bbox_to_anchor=(0.5, 1.015),
        ncol=4,
        frameon=False,
        fontsize=8,
    )
    figure.text(
        0.5,
        0.012,
        "Dashed curves are terminal controller actions, including incoming "
        "receive-credit replacements; they are not logical target-cell counts.\n"
        "Each defence uses its direct-capture extent as a local time axis; "
        "absolute durations are reported in summary.csv.",
        ha="center",
        va="bottom",
        fontsize=7,
    )
    figure.subplots_adjust(top=0.88, bottom=0.16, left=0.08, right=0.99)
    return _save_svg(figure, destination, "QCSD trace comparison")


def _ordered_series(
    records: Iterable[Mapping[str, Any]],
    field: str,
) -> tuple[list[str], list[float | None]]:
    grouped: dict[tuple[str, str], list[float]] = {}
    for record in records:
        value = record.get(field)
        if value is None:
            continue
        grouped.setdefault(_treatment(record), []).append(float(value))
    treatments = sorted(grouped, key=lambda item: (*_defense_rank(item[0]), item[1]))
    medians = [
        float(np.median(grouped[treatment])) if grouped[treatment] else None
        for treatment in treatments
    ]
    return [_treatment_label(*treatment) for treatment in treatments], medians


def _plot_aggregate(
    records: Sequence[Mapping[str, Any]],
    destination: Path,
    *,
    field: str,
    ylabel: str,
    title: str,
    percent: bool = False,
) -> Path:
    treatments, values = _ordered_series(records, field)
    figure, axis = plt.subplots(figsize=(max(6.5, len(treatments) * 1.25), 4.2))
    if treatments:
        numeric = np.asarray([value if value is not None else 0.0 for value in values])
        if percent:
            numeric *= 100
        positions = np.arange(len(treatments))
        axis.bar(positions, numeric, color="#4c78a8", width=0.7)
        axis.set_xticks(positions, treatments)
        axis.tick_params(axis="x", rotation=25)
        axis.axhline(0, color="#666666", linewidth=0.7)
    else:
        axis.text(0.5, 0.5, "No eligible observations", ha="center", va="center")
        axis.set_xticks([])
    axis.set_ylabel(ylabel)
    axis.set_title(title)
    axis.grid(axis="y", alpha=0.2, linewidth=0.5)
    figure.tight_layout()
    return _save_svg(figure, destination, title)


def plot_aggregate_latency(records: Sequence[Mapping[str, Any]], destination: Path) -> Path:
    return _plot_aggregate(
        records,
        destination,
        field="application_completion_seconds",
        ylabel="Median application completion (s)",
        title="Application completion by defence",
    )


def plot_aggregate_overhead(records: Sequence[Mapping[str, Any]], destination: Path) -> Path:
    return _plot_aggregate(
        records,
        destination,
        field="wire_byte_overhead_ratio",
        ylabel="Median paired wire-byte overhead (%)",
        title="Paired wire-byte overhead by defence",
        percent=True,
    )
