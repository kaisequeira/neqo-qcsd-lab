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
import plotly.graph_objects as go
from plotly.subplots import make_subplots

from .util import atomic_json, load_json


def _rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source))


def _defense(sample: Path) -> str:
    metadata = load_json(sample / "sample.json")
    return str(metadata.get("defense", sample.name)).lower()


def _completion_seconds(sample: Path) -> float | None:
    run_json = sample / "neqo" / "run.json"
    if not run_json.exists():
        return None
    run_data = load_json(run_json)
    completion = run_data.get("application_completion_monotonic_ns")
    if completion is None:
        return None
    traffic = _rows(sample / "traffic.csv")
    if traffic:
        completion_unix_ns = int(run_data["time_anchor_unix_ns"]) + int(completion)
        return (completion_unix_ns - int(traffic[0]["timestamp_unix_ns"])) / 1e9
    return float(completion) / 1e9


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
    traffic = _rows(sample / "traffic.csv")
    packets = _rows(sample / "neqo" / "packets.csv")
    schedule = _rows(sample / "neqo" / "schedule.csv")
    events = _rows(sample / "neqo" / "events.csv")
    run_data = load_json(sample / "neqo" / "run.json")
    wire_bytes = sum(int(row["frame_len"]) for row in traffic)
    udp_bytes = sum(int(row["observed_udp_length"]) for row in packets)
    application_bytes = sum(int(response.get("bytes", 0)) for response in run_data.get("responses", []))
    outgoing_targets = [row for row in schedule if row["direction"] == "outgoing"]
    satisfied = [row for row in schedule if row["direction"] == "outgoing" and row["satisfaction"] == "satisfied"]
    misses = [row for row in schedule if row["satisfaction"] == "missed"]
    miss_reasons = Counter(row["miss_reason"] for row in misses if row["miss_reason"])
    chaff_requests = sum("request_chaff" in row.get("details", "") for row in events)
    chaff_bytes = _chaff_bytes(events)
    completion = _completion_seconds(sample)
    return {
        "defense": _defense(sample),
        "wire_bytes": wire_bytes,
        "udp_payload_bytes": udp_bytes,
        "estimated_non_udp_bytes": max(0, wire_bytes - udp_bytes),
        "application_bytes": application_bytes,
        "wire_overhead_bytes": max(0, wire_bytes - application_bytes),
        "udp_overhead_bytes": max(0, udp_bytes - application_bytes),
        "wire_overhead_ratio": (wire_bytes / application_bytes) if application_bytes else None,
        "udp_overhead_ratio": (udp_bytes / application_bytes) if application_bytes else None,
        "application_completion_seconds": completion,
        "goodput_bytes_per_second": (application_bytes / completion) if completion else None,
        "outgoing_targets": len(outgoing_targets),
        "outgoing_targets_satisfied": len(satisfied),
        "target_satisfaction_ratio": (len(satisfied) / len(outgoing_targets)) if outgoing_targets else None,
        "missed_slots": len(misses),
        "missed_slot_reasons": dict(miss_reasons),
        "chaff_requests": chaff_requests,
        "chaff_bytes": chaff_bytes,
        "observer_packets": len(traffic),
    }


def plot_samples(samples: list[Path], output: Path, *, bin_ms: int = 50) -> None:
    output.mkdir(parents=True, exist_ok=True)
    valid = [sample for sample in samples if (sample / "traffic.csv").exists()]
    if not valid:
        raise ValueError("no sample contains traffic.csv")
    metrics = []
    for sample in valid:
        sample_output = output / sample.name
        sample_output.mkdir(parents=True, exist_ok=True)
        _plot_single(sample, sample_output, filtered=False)
        _plot_single(sample, sample_output, filtered=True)
        _plot_rate(sample, sample_output, bin_ms)
        _plot_exactness(sample, sample_output)
        metric = calculate_metrics(sample)
        metrics.append(metric)
        atomic_json(sample_output / "metrics.json", metric)
    _write_metrics(output / "metrics.csv", metrics)
    _plot_comparison(valid, output)


def _observer_points(sample: Path, filtered: bool) -> tuple[np.ndarray, np.ndarray]:
    traffic = _rows(sample / "traffic.csv")
    threshold = 250 if "tamaraw" in _defense(sample) else 150
    times = []
    sizes = []
    for row in traffic:
        signed = int(row["signed_frame_len"])
        if filtered and abs(signed) < threshold:
            continue
        times.append(int(row["relative_time_ns"]) / 1e9)
        sizes.append(signed)
    return np.asarray(times), np.asarray(sizes)


def _plot_single(sample: Path, output: Path, *, filtered: bool) -> None:
    times, sizes = _observer_points(sample, filtered)
    figure, axis = plt.subplots(figsize=(10, 4.5), constrained_layout=True)
    colors = np.where(sizes >= 0, "#d95f02", "#1b9e77")
    axis.scatter(times, sizes, c=colors, s=9, alpha=0.72, linewidths=0)
    completion = _completion_seconds(sample)
    if completion is not None:
        axis.axvline(completion, color="#7570b3", linestyle="--", label="application complete")
        axis.legend(loc="upper right")
    axis.axhline(0, color="black", linewidth=0.6)
    axis.set(title=f"{_defense(sample)} observer trace", xlabel="Time (s)", ylabel="Signed frame length (bytes)")
    suffix = "paper-filtered" if filtered else "unfiltered"
    for extension in ("png", "svg", "pdf"):
        figure.savefig(output / f"observer-{suffix}.{extension}", dpi=180)
    plt.close(figure)

    interactive = go.Figure()
    interactive.add_scatter(x=times, y=sizes, mode="markers", marker={"size": 5}, name="packets")
    if completion is not None:
        interactive.add_vline(x=completion, line_dash="dash", annotation_text="application complete")
    interactive.update_layout(xaxis_title="Time (s)", yaxis_title="Signed frame length (bytes)")
    interactive.write_html(output / f"observer-{suffix}.html", include_plotlyjs="directory")


def _plot_rate(sample: Path, output: Path, bin_ms: int) -> None:
    times, sizes = _observer_points(sample, False)
    if not len(times):
        return
    width = bin_ms / 1000
    bins = np.arange(0, times.max() + width * 2, width)
    outgoing, _ = np.histogram(times[sizes > 0], bins=bins, weights=sizes[sizes > 0])
    incoming, _ = np.histogram(times[sizes < 0], bins=bins, weights=-sizes[sizes < 0])
    figure, axis = plt.subplots(figsize=(10, 4), constrained_layout=True)
    axis.step(bins[:-1], outgoing / width, where="post", label="outgoing")
    axis.step(bins[:-1], incoming / width, where="post", label="incoming")
    axis.set(xlabel="Time (s)", ylabel="Bytes/s", title=f"{bin_ms} ms transmission rate")
    axis.legend()
    for extension in ("png", "svg", "pdf"):
        figure.savefig(output / f"rate-{bin_ms}ms.{extension}", dpi=180)
    plt.close(figure)


def _plot_exactness(sample: Path, output: Path) -> None:
    schedule = [
        row
        for row in _rows(sample / "neqo" / "schedule.csv")
        if row["direction"] == "outgoing" and row["observed_size"]
    ]
    if not schedule:
        return
    target = np.asarray([int(row["size"]) for row in schedule])
    observed = np.asarray([int(row["observed_size"]) for row in schedule])
    figure, axis = plt.subplots(figsize=(6, 5), constrained_layout=True)
    axis.scatter(target, observed, s=12, alpha=0.7)
    lower, upper = min(target.min(), observed.min()), max(target.max(), observed.max())
    axis.plot([lower, upper], [lower, upper], linestyle="--", color="black")
    axis.set(xlabel="Scheduled UDP payload (bytes)", ylabel="Observed UDP payload (bytes)", title="QCSD target exactness")
    for extension in ("png", "svg", "pdf"):
        figure.savefig(output / f"exactness.{extension}", dpi=180)
    plt.close(figure)


def _plot_comparison(samples: list[Path], output: Path) -> None:
    preferred = []
    for mode in ("none", "baseline", "front", "tamaraw"):
        match = next((sample for sample in samples if mode in _defense(sample)), None)
        if match and match not in preferred:
            preferred.append(match)
    if len(preferred) < 2:
        return
    figure, axes = plt.subplots(
        2,
        len(preferred),
        figsize=(5 * len(preferred), 7.5),
        squeeze=False,
        constrained_layout=True,
    )
    subplot_titles = [_defense(sample) for sample in preferred] + [""] * len(preferred)
    interactive = make_subplots(rows=2, cols=len(preferred), subplot_titles=subplot_titles)
    for column, sample in enumerate(preferred):
        times, sizes = _observer_points(sample, True)
        completion = _completion_seconds(sample)
        schedule = _rows(sample / "neqo" / "schedule.csv")
        run_data = load_json(sample / "neqo" / "run.json")
        traffic = _rows(sample / "traffic.csv")
        defense_start = run_data.get("defense_start_monotonic_ns")
        target_offset = 0.0
        if traffic and defense_start is not None:
            target_offset = (
                int(run_data["time_anchor_unix_ns"])
                + int(defense_start)
                - int(traffic[0]["timestamp_unix_ns"])
            ) / 1e9
        for row_index, (direction, mask) in enumerate(
            (("outgoing", sizes > 0), ("incoming", sizes < 0))
        ):
            observed_times = times[mask]
            observed_sizes = np.abs(sizes[mask])
            axes[row_index, column].scatter(
                observed_times,
                observed_sizes,
                s=7,
                alpha=0.7,
                label="observed frame.len",
            )
            targets = [
                row
                for row in schedule
                if row["direction"] == direction
                and row["satisfaction"] in ({"satisfied", "missed"} if direction == "outgoing" else {"credit_released", "missed"})
            ]
            target_times = [
                target_offset + int(row["target_time_us"]) / 1e6 for row in targets
            ]
            target_sizes = [int(row["size"]) for row in targets]
            if targets:
                axes[row_index, column].scatter(
                    target_times,
                    target_sizes,
                    marker="x",
                    s=14,
                    alpha=0.65,
                    label="scheduled UDP target",
                )
            if completion is not None:
                axes[row_index, column].axvline(
                    completion,
                    linestyle="--",
                    color="#7570b3",
                    label="application complete",
                )
            interactive.add_scatter(
                x=observed_times,
                y=observed_sizes,
                mode="markers",
                name=f"{_defense(sample)} {direction} observed",
                row=row_index + 1,
                col=column + 1,
            )
            if targets:
                interactive.add_scatter(
                    x=target_times,
                    y=target_sizes,
                    mode="markers",
                    marker={"symbol": "x"},
                    name=f"{_defense(sample)} {direction} target",
                    row=row_index + 1,
                    col=column + 1,
                )
            if completion is not None:
                interactive.add_vline(
                    x=completion,
                    line_dash="dash",
                    row=row_index + 1,
                    col=column + 1,
                )
        axes[0, column].set_title(_defense(sample))
        axes[1, column].set_xlabel("Time (s)")
        axes[0, column].legend(loc="upper right", fontsize="x-small")
    axes[0, 0].set_ylabel("Outgoing bytes")
    axes[1, 0].set_ylabel("Incoming bytes")
    for extension in ("png", "svg", "pdf"):
        figure.savefig(output / f"figure-2-comparison.{extension}", dpi=180)
    plt.close(figure)
    interactive.update_layout(height=950, title="QCSD Figure-2-style comparison")
    interactive.write_html(output / "figure-2-comparison.html", include_plotlyjs="directory")


def _write_metrics(path: Path, metrics: list[dict[str, Any]]) -> None:
    scalar_keys = [
        "defense",
        "wire_bytes",
        "udp_payload_bytes",
        "estimated_non_udp_bytes",
        "application_bytes",
        "wire_overhead_bytes",
        "udp_overhead_bytes",
        "wire_overhead_ratio",
        "udp_overhead_ratio",
        "application_completion_seconds",
        "goodput_bytes_per_second",
        "outgoing_targets",
        "outgoing_targets_satisfied",
        "target_satisfaction_ratio",
        "missed_slots",
        "missed_slot_reasons",
        "chaff_requests",
        "chaff_bytes",
        "observer_packets",
    ]
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=scalar_keys)
        writer.writeheader()
        for metric in metrics:
            row = {key: metric.get(key) for key in scalar_keys}
            row["missed_slot_reasons"] = json.dumps(
                metric.get("missed_slot_reasons", {}), sort_keys=True
            )
            writer.writerow(row)
