from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.lines import Line2D

from .capture import ObserverPacket, sample_trace
from .defenses import DEFENSE_LABELS, DEFENSE_ORDER, canonical_defense
from .util import load_json, padding_event_guard_triggered

OUTGOING = "#1f77b4"
INCOMING = "#ff7f0e"
COMPLETION = "#4d4d4d"


def _rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source))


def _completion_seconds(sample: Path, trace: list[ObserverPacket]) -> float | None:
    run_json = sample / "neqo" / "run.json"
    if not run_json.exists():
        return None
    run_data = load_json(run_json)
    completion = run_data.get("application_completion_monotonic_ns")
    if completion is None:
        return None
    if trace and run_data.get("time_anchor_unix_ns") is not None:
        completion_unix_ns = int(run_data["time_anchor_unix_ns"]) + int(completion)
        return (completion_unix_ns - trace[0].timestamp_unix_ns) / 1e9
    return float(completion) / 1e9


def _schedule_action_times(
    sample: Path,
    direction: str,
    trace: list[ObserverPacket],
) -> np.ndarray:
    """Return every terminal controller action recorded for one direction.

    Incoming schedules can contain both an initial receive-credit action and
    exact replacement-credit actions after observed bytes or FIN.  The runner
    schema does not identify those replacements as new logical target cells, so
    the dashed KDE is deliberately an action-density overlay rather than a
    logical-target density.
    """

    schedule = _rows(sample / "neqo" / "schedule.csv")
    run_data = load_json(sample / "neqo" / "run.json")
    anchor = run_data.get("time_anchor_unix_ns")
    if not trace or anchor is None:
        return np.asarray([], dtype=float)

    actions = []
    for row in schedule:
        if row.get("direction") != direction:
            continue
        try:
            action_time_us = int(row["action_time_us"])
        except (KeyError, TypeError, ValueError):
            continue
        action_unix_ns = int(anchor) + action_time_us * 1_000
        actions.append((action_unix_ns - trace[0].timestamp_unix_ns) / 1e9)
    return np.asarray(actions, dtype=float)


def _chaff_bytes(events: list[dict[str, str]]) -> int:
    chaff_streams: set[tuple[str, int]] = set()
    total = 0
    for row in events:
        try:
            details = json.loads(row.get("details", ""))
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(details, dict):
            continue
        if details.get("type") == "stream_opened" and isinstance(details.get("role"), dict):
            if "chaff" in details["role"]:
                chaff_streams.add((row.get("connection", ""), int(details["stream"])))
        elif details.get("type") == "bytes_read":
            key = (row.get("connection", ""), int(details["stream"]))
            if key in chaff_streams:
                total += int(details.get("bytes", 0))
    return total


def calculate_metrics(sample: Path) -> dict[str, Any]:
    trace = sample_trace(sample)
    metadata = load_json(sample / "sample.json")
    defense = canonical_defense(str(metadata.get("defense", sample.name)))
    primary = next(
        (
            observer
            for observer in metadata.get("views", [])
            if observer.get("primary") and observer.get("valid")
        ),
        None,
    )
    if primary is None:
        raise ValueError(f"sample has no valid primary observer: {sample}")
    primary_rows = _rows(sample / primary["trace_path"])
    if not primary_rows:
        raise ValueError(f"primary observer trace is empty: {sample}")
    packets = _rows(sample / "neqo" / "packets.csv")
    schedule = _rows(sample / "neqo" / "schedule.csv")
    events = _rows(sample / "neqo" / "events.csv")
    run_data = load_json(sample / "neqo" / "run.json")
    diagnostics = run_data.get("defense_diagnostics")
    if not isinstance(diagnostics, dict):
        diagnostics = {}
    guard_triggered = padding_event_guard_triggered(run_data)
    wire_bytes = sum(packet.frame_len for packet in trace)
    outgoing_packets = [packet for packet in trace if packet.direction == "outgoing"]
    incoming_packets = [packet for packet in trace if packet.direction == "incoming"]
    udp_bytes = sum(int(row["observed_udp_length"]) for row in packets)
    application_bytes = sum(
        int(response.get("bytes", 0)) for response in run_data.get("responses", [])
    )
    outgoing_targets = [row for row in schedule if row.get("direction") == "outgoing"]
    satisfied = [row for row in outgoing_targets if row.get("satisfaction") == "satisfied"]
    exact = [
        row
        for row in satisfied
        if row.get("observed_size") and int(row["observed_size"]) == int(row["size"])
    ]
    misses = [row for row in schedule if row.get("satisfaction") == "missed"]
    miss_reasons = Counter(row["miss_reason"] for row in misses if row.get("miss_reason"))
    chaff_requests = sum("request_chaff" in row.get("details", "") for row in events)
    chaff_bytes = _chaff_bytes(events)
    completion = _completion_seconds(sample, trace)
    trace_duration = max(
        (packet.relative_time_ns / 1e9 for packet in trace),
        default=0.0,
    )
    tail_packets = [
        packet
        for packet in trace
        if completion is not None and packet.relative_time_ns / 1e9 > completion
    ]
    return {
        "defense": defense,
        "wire_bytes": wire_bytes,
        "wire_bytes_outgoing": sum(packet.frame_len for packet in outgoing_packets),
        "wire_bytes_incoming": sum(packet.frame_len for packet in incoming_packets),
        "wire_packets": len(trace),
        "wire_packets_outgoing": len(outgoing_packets),
        "wire_packets_incoming": len(incoming_packets),
        "udp_payload_bytes": udp_bytes,
        "application_bytes": application_bytes,
        "application_completion_seconds": completion,
        "trace_duration_seconds": trace_duration,
        "defense_tail_seconds": (
            max(0.0, trace_duration - completion) if completion is not None else None
        ),
        "defense_tail_bytes": sum(packet.frame_len for packet in tail_packets),
        "defense_tail_packets": len(tail_packets),
        "goodput_bytes_per_second": (application_bytes / completion) if completion else None,
        "outgoing_targets": len(outgoing_targets),
        "outgoing_targets_satisfied": len(satisfied),
        "target_satisfaction_ratio": (
            len(satisfied) / len(outgoing_targets) if outgoing_targets else None
        ),
        "outgoing_targets_exact": len(exact),
        "target_exactness_ratio": (len(exact) / len(satisfied)) if satisfied else None,
        "missed_slots": len(misses),
        "missed_slot_reasons": dict(miss_reasons),
        "chaff_requests": chaff_requests,
        "chaff_bytes": chaff_bytes,
        "observer_packets": len(trace),
        "primary_observer": primary["id"],
        "primary_length_basis": primary["length_basis"],
        "padding_events": diagnostics.get("padding_events"),
        "padding_event_guard_triggered": guard_triggered,
        "operationally_valid": not guard_triggered,
        "fidelity_realization_errors": _realization_errors(defense, diagnostics),
    }


def _realization_errors(defense: str, diagnostics: dict[str, Any]) -> dict[str, Any]:
    """Select controller-realization errors without exposing controller inputs."""

    prefixes = {
        "traffic-morphing": ("morphing_",),
        "wtf-pad": ("padding_event_guard_", "wtf_pad_"),
        "walkie-talkie": ("walkie_talkie_",),
    }.get(defense, ())
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


def _bandwidth(values: np.ndarray, span: float) -> float:
    """Choose one deterministic KDE bandwidth from a panel's observed packets."""

    minimum = max(0.005, span / 500)
    if len(values) <= 1:
        return max(0.01, span / 100)
    standard_deviation = float(np.std(values, ddof=1))
    return max(1.06 * max(standard_deviation, 1e-6) * len(values) ** (-0.2), minimum)


def _density(
    values: np.ndarray,
    grid: np.ndarray,
    bandwidth: float | None = None,
) -> np.ndarray:
    """Small deterministic Gaussian KDE without another analysis dependency."""

    if not len(values):
        return np.zeros_like(grid)
    if bandwidth is None:
        bandwidth = _bandwidth(values, float(grid[-1] - grid[0]))
    distances = (grid[:, None] - values[None, :]) / bandwidth
    return np.exp(-0.5 * distances**2).sum(axis=1) / (len(values) * bandwidth * np.sqrt(2 * np.pi))


def _mode_samples(group_path: Path, defense_order: list[str] | None = None) -> list[Path]:
    samples = [
        path.parent
        for path in sorted(group_path.glob("*/sample.json"))
        if load_json(path).get("state") == "captured"
    ]
    by_name = {str(load_json(sample / "sample.json").get("defense")): sample for sample in samples}
    requested = (
        {canonical_defense(name) for name in defense_order} if defense_order is not None else None
    )
    selected = [
        name for name in by_name if requested is None or canonical_defense(name) in requested
    ]
    rank = {name: index for index, name in enumerate(DEFENSE_ORDER)}
    return [
        by_name[name]
        for name in sorted(
            selected,
            key=lambda name: (
                rank.get(canonical_defense(name), len(rank)),
                canonical_defense(name),
            ),
        )
    ]


def _classic_direct_observer(sample: Path) -> dict[str, Any]:
    """Require the canonical direct observer used by the classic figure."""

    metadata = load_json(sample / "sample.json")
    matches = [
        observer
        for observer in metadata.get("views", [])
        if isinstance(observer, dict) and observer.get("id") == "direct-quic"
    ]
    required = {
        "kind": "direct-quic",
        "interface": "eth0",
        "link_type": "Ethernet",
        "length_basis": "frame.len",
        "primary": True,
        "valid": True,
        "capture_active_through_settle": True,
        "capture_path": "captures/direct-quic.pcapng",
        "trace_path": "traces/direct-quic.csv",
    }
    if len(matches) != 1 or any(matches[0].get(key) != value for key, value in required.items()):
        raise ValueError(
            "classic trace comparison requires one valid canonical direct-quic "
            f"observer with fixed artifact paths: {sample}"
        )
    return matches[0]


def plot_group(group_path: Path, defense_order: list[str] | None = None) -> Path:
    """Render classic direct-PCAP PDF/SVG comparisons for one paired visit."""

    samples = _mode_samples(group_path, defense_order)
    if not samples:
        raise ValueError(f"no comparable samples under {group_path}")
    for sample in samples:
        _classic_direct_observer(sample)
    traces = {sample: sample_trace(sample) for sample in samples}
    scatter_limit = max(
        (packet.frame_len for trace in traces.values() for packet in trace),
        default=0,
    )
    outputs = []
    for page, start in enumerate(range(0, len(samples), 4), start=1):
        page_samples = samples[start : start + 4]
        outputs.append(
            _plot_page(
                group_path,
                page_samples,
                page,
                traces={sample: traces[sample] for sample in page_samples},
                scatter_limit=scatter_limit,
            )
        )
    return outputs[0]


def _plot_page(
    group_path: Path,
    samples: list[Path],
    page: int,
    *,
    traces: dict[Path, list[ObserverPacket]],
    scatter_limit: int,
) -> Path:
    """Render at most four defense columns so figures remain paper-readable."""
    figure, axes = plt.subplots(
        2,
        len(samples),
        figsize=(4.25 * len(samples), 5.7),
        sharex="col",
        sharey=False,
        gridspec_kw={"height_ratios": [1, 2.3], "hspace": 0.06, "wspace": 0.08},
    )
    axes = np.asarray(axes).reshape(2, len(samples))
    for column, sample in enumerate(samples):
        trace = traces[sample]
        trace_end = max(
            (packet.relative_time_ns / 1e9 for packet in trace),
            default=0.0,
        )
        maximum_time = trace_end if trace_end > 0 else np.finfo(float).eps
        grid = np.linspace(0, maximum_time, 600)
        observed = {
            direction: np.asarray(
                [packet.relative_time_ns / 1e9 for packet in trace if packet.direction == direction]
            )
            for direction in ("outgoing", "incoming")
        }
        observed_values = [values for values in observed.values() if len(values)]
        if not observed_values:
            raise ValueError(f"direct capture trace is empty: {sample}")
        observed_all = np.concatenate(observed_values)
        bandwidth = _bandwidth(observed_all, maximum_time)
        schedule_actions = {
            direction: _schedule_action_times(sample, direction, trace)
            for direction in ("outgoing", "incoming")
        }
        density_axis = axes[0, column]
        packet_axis = axes[1, column]
        observed_densities = []
        for direction, color in (("outgoing", OUTGOING), ("incoming", INCOMING)):
            observed_density = _density(observed[direction], grid, bandwidth)
            observed_densities.append(observed_density)
            density_axis.plot(
                grid,
                observed_density,
                color=color,
                linestyle="-",
                linewidth=1.4,
            )
            if len(schedule_actions[direction]):
                density_axis.plot(
                    grid,
                    _density(schedule_actions[direction], grid, bandwidth),
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
            density_axis.axvline(completion, color=COMPLETION, linestyle=":", linewidth=1)
            packet_axis.axvline(completion, color=COMPLETION, linestyle=":", linewidth=1)
            if completion < trace_end:
                for axis in (density_axis, packet_axis):
                    axis.axvspan(
                        max(0.0, completion),
                        trace_end,
                        color="#8c8c8c",
                        alpha=0.13,
                        linewidth=0,
                    )
        defense = str(load_json(sample / "sample.json").get("defense", sample.name))
        title = DEFENSE_LABELS.get(canonical_defense(defense), defense)
        density_axis.set_title(title, fontsize=11)
        density_axis.grid(alpha=0.18, linewidth=0.5)
        packet_axis.grid(alpha=0.18, linewidth=0.5)
        packet_axis.axhline(0, color="#777777", linewidth=0.6)
        packet_axis.set_xlabel("Time (s)")
        density_axis.set_xlim(0, maximum_time)
        density_limit = max(
            (float(np.max(values)) for values in observed_densities if len(values)),
            default=1.0,
        )
        density_axis.set_ylim(0, max(density_limit * 1.05, 1e-9))
        packet_axis.set_xlim(0, maximum_time)
        packet_axis.set_ylim(
            -max(scatter_limit, 1) * 1.08,
            max(scatter_limit, 1) * 1.08,
        )
    axes[0, 0].set_ylabel("Packet-time\ndensity")
    plotted_observer = _classic_direct_observer(samples[0])
    basis = plotted_observer["length_basis"]
    identifier = plotted_observer["id"]
    axes[1, 0].set_ylabel(f"Signed {identifier} {basis} (bytes)")
    legend = [
        Line2D([], [], color=OUTGOING, linestyle="-", label="Outgoing observed"),
        Line2D(
            [],
            [],
            color=OUTGOING,
            linestyle="--",
            label="Outgoing controller actions",
        ),
        Line2D([], [], color=INCOMING, linestyle="-", label="Incoming observed"),
        Line2D(
            [],
            [],
            color=INCOMING,
            linestyle="--",
            label="Incoming controller actions",
        ),
        Line2D([], [], color=COMPLETION, linestyle=":", label="Application complete"),
        Line2D(
            [],
            [],
            color="#8c8c8c",
            linewidth=7,
            alpha=0.25,
            label="Defense tail",
        ),
        Line2D(
            [],
            [],
            color="#555555",
            marker="o",
            markerfacecolor="none",
            linestyle="none",
            label="Observed packet",
        ),
    ]
    figure.legend(
        handles=legend,
        loc="upper center",
        bbox_to_anchor=(0.5, 1.015),
        ncol=4,
        frameon=False,
        fontsize=8,
    )
    figure.text(
        0.5,
        0.012,
        "Dashed curves are terminal controller actions, including exact incoming "
        "receive-credit replacements; they are not logical target-cell counts.\n"
        "Each defence uses its actual direct-capture extent as a local time axis for "
        "shape comparison; durations are reported by the campaign table.",
        ha="center",
        va="bottom",
        fontsize=7,
    )
    figure.subplots_adjust(top=0.88, bottom=0.16, left=0.08, right=0.99)
    suffix = "" if page == 1 else f"-{page}"
    destination = group_path / f"trace-comparison{suffix}.pdf"
    with plt.rc_context({"pdf.fonttype": 42, "ps.fonttype": 42}):
        figure.savefig(
            destination,
            format="pdf",
            metadata={
                "Title": "QCSD trace comparison",
                "Creator": "neqo-qcsd-lab",
                "CreationDate": None,
                "ModDate": None,
            },
        )
    svg_destination = group_path / f"trace-comparison{suffix}.svg"
    # Text as paths plus a fixed hashsalt keep the SVG rendering- and
    # byte-deterministic so report.html can embed it reproducibly.
    with plt.rc_context({"svg.fonttype": "path", "svg.hashsalt": "neqo-qcsd-lab"}):
        figure.savefig(
            svg_destination,
            format="svg",
            metadata={
                "Title": "QCSD trace comparison",
                "Creator": "neqo-qcsd-lab",
                "Date": None,
            },
        )
    plt.close(figure)
    return destination


def plot_run(root: Path) -> list[Path]:
    """Regenerate every workload/repetition trace-comparison figure in a campaign result."""

    receipt = load_json(root / "campaign.json")
    defense_order = [item["name"] for item in receipt.get("configuration", {}).get("defenses", [])]
    groups = receipt.get("visits", [])
    group_paths = [
        root / group["path"]
        for group in groups
        if any((root / group["path"]).glob("*/sample.json"))
    ]
    outputs = []
    if not group_paths:
        raise ValueError(f"no campaign samples under {root}")
    for group_path in group_paths:
        try:
            outputs.append(plot_group(group_path, defense_order or None))
        except (FileNotFoundError, KeyError, RuntimeError, ValueError):
            if receipt.get("summary", {}).get("passed") is True:
                # A complete campaign without its required per-visit research
                # figure must not be sealed as successful.
                raise
            # Incomplete visits remain represented in campaign.json/report.html.
    return outputs
