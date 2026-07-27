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
from .util import load_json

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


def _target_times(sample: Path, direction: str, trace: list[ObserverPacket]) -> np.ndarray:
    schedule = _rows(sample / "neqo" / "schedule.csv")
    run_data = load_json(sample / "neqo" / "run.json")
    start = run_data.get("defense_start_monotonic_ns")
    offset = 0.0
    if trace and start is not None and run_data.get("time_anchor_unix_ns") is not None:
        offset = (
            int(run_data["time_anchor_unix_ns"])
            + int(start)
            - trace[0].timestamp_unix_ns
        ) / 1e9
    return np.asarray(
        [
            offset + int(row["target_time_us"]) / 1e6
            for row in schedule
            if row.get("direction") == direction
        ],
        dtype=float,
    )


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
    observed_bytes = sum(int(row["length_bytes"]) for row in primary_rows)
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
    return {
        "defense": str(metadata.get("defense", sample.name)).lower(),
        "observed_bytes": observed_bytes,
        "udp_payload_bytes": udp_bytes,
        "application_bytes": application_bytes,
        "observed_overhead_bytes": max(0, observed_bytes - application_bytes),
        "observed_overhead_ratio": (
            observed_bytes / application_bytes if application_bytes else None
        ),
        "application_completion_seconds": completion,
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
        "observer_packets": len(primary_rows),
        "primary_observer": primary["id"],
        "primary_length_basis": primary["length_basis"],
    }


def _density(values: np.ndarray, grid: np.ndarray) -> np.ndarray:
    """Small deterministic Gaussian KDE without another analysis dependency."""

    if not len(values):
        return np.zeros_like(grid)
    if len(values) == 1:
        bandwidth = max(0.01, (grid[-1] - grid[0]) / 100)
    else:
        standard_deviation = float(np.std(values, ddof=1))
        bandwidth = 1.06 * max(standard_deviation, 1e-6) * len(values) ** (-0.2)
        bandwidth = max(bandwidth, max(0.005, (grid[-1] - grid[0]) / 500))
    distances = (grid[:, None] - values[None, :]) / bandwidth
    return np.exp(-0.5 * distances**2).sum(axis=1) / (
        len(values) * bandwidth * np.sqrt(2 * np.pi)
    )


def _mode_samples(group_path: Path, defense_order: list[str] | None = None) -> list[Path]:
    samples = [
        path.parent
        for path in sorted(group_path.glob("*/sample.json"))
        if load_json(path).get("state") == "captured"
    ]
    order = defense_order or [str(load_json(sample / "sample.json").get("defense")) for sample in samples]
    by_name = {str(load_json(sample / "sample.json").get("defense")): sample for sample in samples}
    return [by_name[name] for name in order if name in by_name]


def plot_group(group_path: Path, defense_order: list[str] | None = None) -> Path:
    """Render the trace-comparison figure (PDF + embeddable SVG) for one paired visit."""

    samples = _mode_samples(group_path, defense_order)
    if not samples:
        raise ValueError(f"no comparable samples under {group_path}")
    outputs = []
    for page, start in enumerate(range(0, len(samples), 4), start=1):
        outputs.append(_plot_page(group_path, samples[start : start + 4], page))
    return outputs[0]


def _plot_page(group_path: Path, samples: list[Path], page: int) -> Path:
    """Render at most four defense columns so figures remain paper-readable."""

    traces = {sample: sample_trace(sample) for sample in samples}
    maximum_time = max(
        (
            max((packet.relative_time_ns / 1e9 for packet in trace), default=0.0)
            for trace in traces.values()
        ),
        default=1.0,
    )
    maximum_time = max(maximum_time, 0.1)
    grid = np.linspace(0, maximum_time, 600)
    figure, axes = plt.subplots(
        2,
        len(samples),
        figsize=(4.25 * len(samples), 5.7),
        sharex=True,
        sharey="row",
        gridspec_kw={"height_ratios": [1, 2.3], "hspace": 0.06, "wspace": 0.08},
    )
    axes = np.asarray(axes).reshape(2, len(samples))
    scatter_limit = max(
        (packet.frame_len for trace in traces.values() for packet in trace),
        default=0,
    )
    for column, sample in enumerate(samples):
        trace = traces[sample]
        observed = {
            direction: np.asarray(
                [
                    packet.relative_time_ns / 1e9
                    for packet in trace
                    if packet.direction == direction
                ]
            )
            for direction in ("outgoing", "incoming")
        }
        targets = {
            direction: _target_times(sample, direction, trace)
            for direction in ("outgoing", "incoming")
        }
        density_axis = axes[0, column]
        packet_axis = axes[1, column]
        for direction, color in (("outgoing", OUTGOING), ("incoming", INCOMING)):
            density_axis.plot(
                grid,
                _density(observed[direction], grid),
                color=color,
                linestyle="-",
                linewidth=1.4,
            )
            if len(targets[direction]):
                density_axis.plot(
                    grid,
                    _density(targets[direction], grid),
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
        title = str(load_json(sample / "sample.json").get("defense", sample.name))
        density_axis.set_title(title, fontsize=11)
        density_axis.grid(alpha=0.18, linewidth=0.5)
        packet_axis.grid(alpha=0.18, linewidth=0.5)
        packet_axis.axhline(0, color="#777777", linewidth=0.6)
        packet_axis.set_xlabel("Time (s)")
        density_axis.set_xlim(0, maximum_time)
        packet_axis.set_xlim(0, maximum_time)
    axes[0, 0].set_ylabel("Packet-time\ndensity")
    first_metadata = load_json(samples[0] / "sample.json")
    plotted_observer = next(
        (
            observer
            for observer in first_metadata.get("views", [])
            if observer.get("kind") == "direct-quic" and observer.get("valid")
        ),
        next(
            (
                observer
                for observer in first_metadata.get("views", [])
                if observer.get("primary") and observer.get("valid")
            ),
            {},
        ),
    )
    basis = plotted_observer.get("length_basis", "frame.len")
    identifier = plotted_observer.get("id", "observer")
    axes[1, 0].set_ylabel(f"Signed {identifier} {basis} (bytes)")
    if scatter_limit:
        axes[1, 0].set_ylim(-scatter_limit * 1.08, scatter_limit * 1.08)
    legend = [
        Line2D([], [], color=OUTGOING, linestyle="-", label="Outgoing observed"),
        Line2D([], [], color=OUTGOING, linestyle="--", label="Outgoing target"),
        Line2D([], [], color=INCOMING, linestyle="-", label="Incoming observed"),
        Line2D([], [], color=INCOMING, linestyle="--", label="Incoming target"),
        Line2D([], [], color=COMPLETION, linestyle=":", label="Application complete"),
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
        ncol=3,
        frameon=False,
        fontsize=8,
    )
    figure.subplots_adjust(top=0.88, bottom=0.1, left=0.08, right=0.99)
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


def plot_run(root: Path, *, policy: str | None = None) -> list[Path]:
    """Regenerate every workload/repetition trace-comparison figure in a campaign result."""

    receipt = load_json(root / "campaign.json")
    defense_order = [item["name"] for item in receipt.get("configuration", {}).get("defenses", [])]
    groups = receipt.get("visits", [])
    group_paths = [
        root / group["path"]
        for group in groups
        if any((root / group["path"]).glob("*/sample.json"))
    ]
    selected_policy = policy or (
        receipt.get("configuration", {}).get("outputs", {}).get("figures", "per-visit")
    )
    outputs = [plot_aggregate(root)]
    if selected_policy == "aggregate-only":
        return outputs
    if not group_paths:
        raise ValueError(f"no campaign samples under {root}")
    for group_path in group_paths:
        try:
            outputs.append(plot_group(group_path, defense_order or None))
        except (FileNotFoundError, KeyError, RuntimeError, ValueError):
            # Incomplete paired visits remain clearly represented in campaign.json
            # and report.html without making report finalization itself fail.
            continue
    return outputs


def plot_aggregate(root: Path) -> Path:
    """Render defense coverage, observer storage, and collection health."""

    receipt = load_json(root / "campaign.json")
    defense_order = [item["name"] for item in receipt.get("configuration", {}).get("defenses", [])]
    samples = [
        load_json(path)
        for path in sorted(root.rglob("sample.json"))
        if "attempts" not in path.parts
    ]
    if not defense_order:
        defense_order = list(dict.fromkeys(str(sample.get("defense")) for sample in samples))
    captured = [sum(sample.get("state") == "captured" for sample in samples if sample.get("defense") == defense) for defense in defense_order]
    eligible = [
        sum(
            sample.get("eligible") is True
            for sample in samples
            if sample.get("defense") == defense
        )
        for defense in defense_order
    ]
    retries = [sum(max(0, int(sample.get("attempts", 1)) - 1) for sample in samples if sample.get("defense") == defense) for defense in defense_order]
    observer_bytes: Counter[str] = Counter()
    for sample in samples:
        for observer in sample.get("views", []):
            if observer.get("valid"):
                observer_bytes[observer["id"]] += int(observer.get("pcapng_bytes", 0))

    figure, axes = plt.subplots(1, 3, figsize=(12, 3.6))
    positions = np.arange(len(defense_order))
    width = 0.38
    axes[0].bar(positions - width / 2, captured, width, label="Captured", color="#6baed6")
    axes[0].bar(positions + width / 2, eligible, width, label="Eligible", color="#2171b5")
    axes[0].set_xticks(positions, defense_order, rotation=30, ha="right")
    axes[0].set_ylabel("Logical samples")
    axes[0].set_title("Defense coverage")
    axes[0].legend(frameon=False, fontsize=8)

    observer_names = list(observer_bytes)
    axes[1].bar(observer_names, [observer_bytes[name] / (1024 * 1024) for name in observer_names], color="#756bb1")
    axes[1].tick_params(axis="x", rotation=30)
    axes[1].set_ylabel("PCAPNG (MiB)")
    axes[1].set_title("Storage by observer")

    failures = [
        sum(sample.get("state") != "captured" for sample in samples if sample.get("defense") == defense)
        for defense in defense_order
    ]
    axes[2].bar(positions - width / 2, failures, width, label="Failures", color="#cb181d")
    axes[2].bar(positions + width / 2, retries, width, label="Retries", color="#fdae6b")
    axes[2].set_xticks(positions, defense_order, rotation=30, ha="right")
    axes[2].set_ylabel("Count")
    axes[2].set_title("Collection health")
    axes[2].legend(frameon=False, fontsize=8)
    for axis in axes:
        axis.grid(axis="y", alpha=0.2, linewidth=0.5)
    figure.tight_layout()
    destination = root / "dataset-summary.pdf"
    with plt.rc_context({"pdf.fonttype": 42, "ps.fonttype": 42}):
        figure.savefig(
            destination,
            metadata={"Title": "QCSD dataset summary", "Creator": "neqo-qcsd-lab", "CreationDate": None, "ModDate": None},
        )
    with plt.rc_context({"svg.fonttype": "path", "svg.hashsalt": "neqo-qcsd-lab-summary"}):
        figure.savefig(
            root / "dataset-summary.svg",
            format="svg",
            metadata={"Title": "QCSD dataset summary", "Creator": "neqo-qcsd-lab", "Date": None},
        )
    plt.close(figure)
    return destination
