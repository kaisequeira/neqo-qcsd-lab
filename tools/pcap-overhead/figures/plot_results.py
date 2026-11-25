#!/usr/bin/env python3
"""Plot verified per-defense results from the final-PCAP overhead toolkit.

Inputs are the public aggregate.py outputs, not packet captures or metadata.
See README.md for the estimands, plot scales, and checks.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import PercentFormatter
import numpy as np

MODES = ("front", "tamaraw", "buflo", "cs-buflo", "wtf-pad")
NAMES = {"front": "FRONT", "tamaraw": "Tamaraw", "buflo": "BuFLO",
         "cs-buflo": "CS-BuFLO", "wtf-pad": "WTF-PAD"}
METRICS = ("ip_bytes", "observed_span")
AXIS_LABEL = {"ip_bytes": "Observed IP-byte overhead relative to undefended (%)",
              "observed_span": "Observed packet-trace-span overhead relative to undefended (%)"}
TITLES = {"ip_bytes": "Traffic volume", "observed_span": "Observed packet-trace span"}


def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as src:
        return list(csv.DictReader(src))


def number(value, name):
    try:
        v = float(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{name}: expected a finite number") from exc
    if not math.isfinite(v):
        raise ValueError(f"{name}: expected a finite number")
    return v


def integer(value, name):
    v = number(value, name)
    if v < 0 or not v.is_integer():
        raise ValueError(f"{name}: expected a nonnegative integer")
    return int(v)


def load_results(directory, allow_incomplete=False, synthetic_fixture=False):
    """Validate quality and exact correspondence between tables before plotting."""
    quality = json.loads((directory / "quality.json").read_text(encoding="utf-8"))
    complete = quality.get("status") == "complete"
    if not complete and not allow_incomplete:
        raise ValueError("Input analysis is incomplete; do not plot as final")
    if quality.get("extractor_errors") != 0:
        raise ValueError("Extractor errors are present or not reported")
    if quality.get("identity_or_other_flags"):
        raise ValueError("Identity or validation flags require review")
    if complete and quality.get("accepted_metric_rows") != quality.get("manifest_sessions"):
        raise ValueError("Complete status conflicts with reported manifest coverage")
    if not synthetic_fixture:
        if quality.get("manifest_sessions") != 120000 or quality.get("accepted_metric_rows") != 120000:
            raise ValueError("The study figure requires all 120,000 final PCAP rows")
        for name in ("manifest_sha256", "metric_rows_content_sha256"):
            v = quality.get(name)
            if not isinstance(v, str) or len(v) != 64 or any(c not in "0123456789abcdefABCDEF" for c in v):
                raise ValueError(f"Missing or invalid {name}")

    summaries = {}
    for row in read_csv(directory / "overall-overheads.csv"):
        key = (row.get("metric"), row.get("defense"))
        if key[0] not in METRICS or key[1] not in MODES:
            continue
        if key in summaries:
            raise ValueError(f"Duplicate summary row: {key}")
        provisional = row.get("provisional", "").strip().lower()
        if provisional not in ("true", "false"):
            raise ValueError(f"Missing or invalid provisional flag: {key}")
        if provisional == "true" and not allow_incomplete:
            raise ValueError(f"Provisional summary row: {key}")
        for field in ("macro_overhead_pct", "macro_ci95_sessions_low", "macro_ci95_sessions_high",
                      "pooled_cohort_mean_overhead_pct", "pooled_ci95_sessions_low", "pooled_ci95_sessions_high"):
            row[field] = number(row.get(field), f"{key} {field}")
        row["domains"] = integer(row.get("domains"), f"{key} domains")
        if row["domains"] == 0:
            raise ValueError(f"No domains: {key}")
        if row["macro_ci95_sessions_low"] > row["macro_ci95_sessions_high"] or row["pooled_ci95_sessions_low"] > row["pooled_ci95_sessions_high"]:
            raise ValueError(f"Reversed interval: {key}")
        summaries[key] = row
    expected = {(metric, mode) for metric in METRICS for mode in MODES}
    if set(summaries) != expected:
        raise ValueError(f"Expected all five defenses for both metrics; missing {sorted(expected-set(summaries))}")

    domains = {key: [] for key in expected}
    for row in read_csv(directory / "domain-overheads.csv"):
        key = (row.get("metric"), row.get("defense"))
        if key not in expected:
            continue
        host = row.get("domain", "").strip()
        if not host or any(x["domain"] == host for x in domains[key]):
            raise ValueError(f"Empty or duplicate domain in {key}")
        for field in ("baseline_n", "defense_n", "baseline_expected_n", "defense_expected_n"):
            row[field] = integer(row.get(field), f"{key} {host} {field}")
        if not row["baseline_n"] or not row["defense_n"]:
            raise ValueError(f"No valid baseline or defense observations: {key} {host}")
        if row["baseline_n"] > row["baseline_expected_n"] or row["defense_n"] > row["defense_expected_n"]:
            raise ValueError(f"Valid count exceeds expected count: {key} {host}")
        row["overhead_pct"] = number(row.get("overhead_pct"), f"{key} {host} overhead")
        domains[key].append(row)
    for key, rows in domains.items():
        if len(rows) != summaries[key]["domains"]:
            raise ValueError(f"Summary/domain count mismatch: {key}")
        macro = sum(r["overhead_pct"] for r in rows) / len(rows)
        if not math.isclose(macro, summaries[key]["macro_overhead_pct"], rel_tol=1e-9, abs_tol=1e-8):
            raise ValueError(f"Summary/domain mean mismatch: {key}")
        if not synthetic_fixture and (len(rows) != 50 or any(r["baseline_expected_n"] != 400 or r["defense_expected_n"] != 400 for r in rows)):
            raise ValueError(f"The study figure requires all 50 domains and 400 expected sessions per condition: {key}")
    if not allow_incomplete:
        reference_domains = {r["domain"] for r in domains[(METRICS[0], MODES[0])]}
        if any({r["domain"] for r in rows} != reference_domains for rows in domains.values()):
            raise ValueError("Different domains are represented across metric/defense comparisons")
    return quality, summaries, domains, not complete or any(r["provisional"].strip().lower() == "true" for r in summaries.values())


def maybe_symlog(ax, values):
    """Show large positive ratios without silently clipping small/negative values."""
    largest = max(abs(x) for x in values)
    if largest > 1000:
        ax.set_xscale("symlog", linthresh=100, linscale=1)
        ax.text(0.99, 0.01, "Symmetric log scale outside ±100%", transform=ax.transAxes,
                ha="right", va="bottom", fontsize=7, color="#505050")
    ax.xaxis.set_major_formatter(PercentFormatter(xmax=100, decimals=0))
    ax.axvline(0, color="#333333", linewidth=0.8, zorder=0)
    ax.grid(axis="x", color="#d7d7d7", linewidth=0.65, alpha=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.tick_params(axis="y", length=0)


def counts(rows):
    return {"defense_n": sum(r["defense_n"] for r in rows),
            "baseline_n": sum(r["baseline_n"] for r in rows),
            "defense_excluded": sum(r["defense_expected_n"] - r["defense_n"] for r in rows),
            "baseline_excluded": sum(r["baseline_expected_n"] - r["baseline_n"] for r in rows)}


def title(fig, text, provisional, synthetic_fixture=False):
    fig.suptitle(text, fontsize=15, fontweight="semibold", x=0.10, ha="left", y=0.985)
    if provisional:
        fig.text(0.5, 0.52, "PROVISIONAL — INCOMPLETE", ha="center", va="center", rotation=24,
                 fontsize=25, color="#a02020", alpha=0.14, zorder=99)
    if synthetic_fixture:
        fig.text(0.5, 0.48, "SYNTHETIC FIXTURE — NOT STUDY DATA", ha="center", va="center", rotation=24,
                 fontsize=23, color="#a02020", alpha=0.23, zorder=99)


def plot_overall(out, summaries, domains, quality, provisional, synthetic_fixture=False):
    # Separate vertical panels leave room for exact values and sample counts;
    # each has its own scale and avoids treating bytes and time as comparable.
    fig, axes = plt.subplots(2, 1, figsize=(12, 9.5))
    fig.subplots_adjust(left=0.13, right=0.77, top=0.86, bottom=0.12, hspace=0.60)
    title(fig, "Defense overhead compared with undefended traffic", provisional, synthetic_fixture)
    for ax, metric in zip(axes, METRICS):
        scale_values = []
        for i, mode in enumerate(MODES):
            r = summaries[(metric, mode)]
            y = len(MODES)-1-i
            for kind, offset, color, label in (("macro", 0.13, "#1769aa", "Equal-domain mean"),
                                                ("pooled", -0.13, "#b5520d", "Pooled ratio of cohort means")):
                if kind == "macro":
                    v, lo, hi = (r["macro_overhead_pct"], r["macro_ci95_sessions_low"], r["macro_ci95_sessions_high"])
                else:
                    v, lo, hi = (r["pooled_cohort_mean_overhead_pct"], r["pooled_ci95_sessions_low"], r["pooled_ci95_sessions_high"])
                ax.plot([lo, hi], [y+offset, y+offset], color=color, linewidth=1.5, zorder=2)
                ax.plot(v, y+offset, "o", color=color, markersize=5, zorder=3)
                scale_values.extend((lo, hi, v))
            c = counts(domains[(metric, mode)])
            ax.text(1.01, y, f"{r['macro_overhead_pct']:+,.1f}% / {r['pooled_cohort_mean_overhead_pct']:+,.1f}%\n"
                    f"n {c['defense_n']:,}/{c['baseline_n']:,} · excl {c['defense_excluded']:,}/{c['baseline_excluded']:,}",
                    transform=ax.get_yaxis_transform(), ha="left", va="center", fontsize=7.3)
        maybe_symlog(ax, scale_values)
        ax.set_yticks(range(len(MODES)), [NAMES[m] for m in reversed(MODES)])
        ax.set_ylim(-0.55, len(MODES)-0.3)
        ax.set_title(TITLES[metric], loc="left", fontsize=12, fontweight="semibold")
        ax.set_xlabel(AXIS_LABEL[metric], fontsize=9)
        ax.text(1.01, 1.02, "Equal-domain / pooled\nvalid n D/B · excluded D/B", transform=ax.transAxes,
                fontsize=7, va="bottom", ha="left", color="#555555")
    handles = [Line2D([], [], color="#1769aa", marker="o", markersize=5, label="Equal-domain mean"),
               Line2D([], [], color="#b5520d", marker="o", markersize=5, label="Pooled ratio of cohort means")]
    fig.legend(handles=handles, loc="upper left", bbox_to_anchor=(0.13, 0.95), ncol=2, frameon=False, fontsize=8)
    fig.text(0.13, 0.025, "Whiskers: 95% within-cohort bootstrap intervals, conditional on the observed domains. "
             "D/B = defended / undefended. Trace span is not application latency.", fontsize=7.5)
    save(fig, out, "01-overall-overheads")


def plot_spread(out, summaries, domains, quality, provisional, synthetic_fixture=False):
    fig, axes = plt.subplots(2, 1, figsize=(12, 9.5))
    fig.subplots_adjust(left=0.13, right=0.77, top=0.86, bottom=0.12, hspace=0.60)
    title(fig, "Variation across resource domains", provisional, synthetic_fixture)
    for ax, metric in zip(axes, METRICS):
        all_values = []
        for i, mode in enumerate(MODES):
            rows = domains[(metric, mode)]
            y = len(MODES)-1-i
            vals = np.array([r["overhead_pct"] for r in rows], dtype=float)
            all_values.extend(vals.tolist())
            low, med, high = np.percentile(vals, [5, 50, 95])
            ax.plot([low, high], [y, y], color="#202020", linewidth=2.1, zorder=2)
            ax.plot(med, y, marker="D", color="#b5520d", markersize=5, zorder=4)
            # Stable hash jitter makes repeated exports identical regardless of CSV row order.
            jitter = [((int(hashlib.sha256(r["domain"].encode()).hexdigest()[:8], 16) / 0xffffffff)-0.5)*0.32 for r in rows]
            ax.scatter(vals, y+np.array(jitter), s=12, color="#1769aa", alpha=0.56,
                       linewidths=0, zorder=3, rasterized=True)
            ax.text(1.01, y, f"{len(rows)} domains\nmedian {med:+,.1f}%", transform=ax.get_yaxis_transform(),
                    ha="left", va="center", fontsize=8)
        maybe_symlog(ax, all_values)
        ax.set_yticks(range(len(MODES)), [NAMES[m] for m in reversed(MODES)])
        ax.set_ylim(-0.55, len(MODES)-0.3)
        ax.set_title(TITLES[metric], loc="left", fontsize=12, fontweight="semibold")
        ax.set_xlabel(AXIS_LABEL[metric], fontsize=9)
    handles = [Line2D([], [], color="#1769aa", marker="o", linestyle="", markersize=4, label="Individual domain"),
               Line2D([], [], color="#202020", linewidth=2, label="5th–95th domain percentiles"),
               Line2D([], [], color="#b5520d", marker="D", linestyle="", markersize=5, label="Domain median")]
    fig.legend(handles=handles, loc="upper left", bbox_to_anchor=(0.13, 0.95), ncol=3, frameon=False, fontsize=8)
    fig.text(0.13, 0.025, "Domain points are ratios of independently captured cohort means, not paired sessions. "
             "Trace span is not application latency.", fontsize=7.5)
    save(fig, out, "02-domain-spread")


def save(fig, out, stem):
    for ext in ("pdf", "svg", "png"):
        fig.savefig(out / f"{stem}.{ext}", dpi=220, bbox_inches="tight", metadata={"Creator": "NEQO PCAP overhead toolkit"})
    plt.close(fig)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--results", type=Path, required=True, help="Aggregate output directory")
    p.add_argument("--output", type=Path, required=True, help="New or empty figure directory")
    p.add_argument("--allow-incomplete", action="store_true", help="Permit explicitly watermarked provisional plots")
    p.add_argument("--synthetic-fixture", action="store_true", help="Permit reduced synthetic fixtures and add a permanent synthetic-data watermark; do not use for study results")
    args = p.parse_args(argv)
    quality, summaries, domains, provisional = load_results(args.results, args.allow_incomplete, args.synthetic_fixture)
    if args.output.exists() and any(args.output.iterdir()):
        p.error("Output directory must be empty")
    args.output.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "pdf.fonttype": 42,
                         "svg.fonttype": "none", "axes.unicode_minus": False})
    plot_overall(args.output, summaries, domains, quality, provisional, args.synthetic_fixture)
    plot_spread(args.output, summaries, domains, quality, provisional, args.synthetic_fixture)
    rec = {"status": "synthetic_fixture" if args.synthetic_fixture else ("provisional" if provisional else "complete"),
           "manifest_sha256": quality.get("manifest_sha256"),
           "accepted_metric_rows": quality.get("accepted_metric_rows"),
           "manifest_sessions": quality.get("manifest_sessions"),
           "metric_rows_content_sha256": quality.get("metric_rows_content_sha256"),
           "inputs_sha256": {x: sha256(args.results / x) for x in ("quality.json", "overall-overheads.csv", "domain-overheads.csv")},
           "script_sha256": sha256(Path(__file__)),
           "matplotlib_version": matplotlib.__version__, "numpy_version": np.__version__,
           "note": "All plotted quantities are PCAP-derived. Observed trace span is not application completion or page-load latency."}
    (args.output / "figure-provenance.json").write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": rec["status"], "figures": 2, "output": str(args.output)}))


if __name__ == "__main__":
    main()
