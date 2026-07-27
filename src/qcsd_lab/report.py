from __future__ import annotations

import csv
import html
import json
from collections import defaultdict
from pathlib import Path
from statistics import median
from typing import Any

from .plotting import calculate_metrics
from .util import load_json

METRIC_FIELDS = [
    "sample",
    "sample_id",
    "visit_id",
    "workload",
    "repetition",
    "class_label",
    "role",
    "defense",
    "state",
    "eligible",
    "content_drift",
    "attempts",
    "primary_observer",
    "primary_length_basis",
    "observed_bytes",
    "udp_payload_bytes",
    "application_bytes",
    "observed_overhead_bytes",
    "observed_overhead_ratio",
    "observed_overhead_vs_baseline_ratio",
    "application_completion_seconds",
    "load_time_overhead_ratio",
    "goodput_bytes_per_second",
    "outgoing_targets",
    "outgoing_targets_satisfied",
    "target_satisfaction_ratio",
    "outgoing_targets_exact",
    "target_exactness_ratio",
    "missed_slots",
    "missed_slot_reasons",
    "chaff_requests",
    "chaff_bytes",
    "observer_packets",
]


def create_report(root: Path) -> tuple[Path, Path]:
    """Write classifier metrics and one compact static campaign report."""

    records = []
    for metadata_path in sorted(root.rglob("sample.json")):
        if "attempts" in metadata_path.parts:
            continue
        sample = metadata_path.parent
        metadata = load_json(metadata_path)
        metrics: dict[str, Any] = {}
        if any(view.get("valid") for view in metadata.get("views", [])):
            try:
                metrics = calculate_metrics(sample)
            except (FileNotFoundError, KeyError, RuntimeError, ValueError):
                pass
        records.append(
            {
                "sample": str(sample.relative_to(root)),
                "sample_id": metadata.get("sample_id"),
                "visit_id": metadata.get("visit_id"),
                "workload": metadata.get("workload_id", metadata.get("workload")),
                "repetition": metadata.get("repetition", metadata.get("visit")),
                "class_label": metadata.get("class_label"),
                "role": metadata.get("role"),
                "defense": metadata.get("defense"),
                "state": metadata.get("state"),
                "eligible": metadata.get("eligible") is True,
                "content_drift": metadata.get("content_drift"),
                "attempts": metadata.get("attempts"),
                **{key: metrics.get(key) for key in METRIC_FIELDS if key not in {
                    "sample", "sample_id", "visit_id", "workload", "repetition",
                    "class_label", "role", "defense", "state", "eligible",
                    "content_drift", "attempts", "observed_overhead_vs_baseline_ratio",
                    "load_time_overhead_ratio",
                }},
            }
        )
    baselines = {
        record["visit_id"]: record
        for record in records
        if load_json(root / record["sample"] / "sample.json").get("baseline") is True
    }
    for record in records:
        baseline = baselines.get(record["visit_id"])
        record["observed_overhead_vs_baseline_ratio"] = _ratio(
            record.get("observed_bytes"), baseline, "observed_bytes"
        )
        record["load_time_overhead_ratio"] = _ratio(
            record.get("application_completion_seconds"),
            baseline,
            "application_completion_seconds",
        )
    metrics_path = root / "metrics.csv"
    with metrics_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=METRIC_FIELDS)
        writer.writeheader()
        for record in records:
            row = {key: record.get(key) for key in METRIC_FIELDS}
            row["missed_slot_reasons"] = json.dumps(
                record.get("missed_slot_reasons") or {}, sort_keys=True
            )
            writer.writerow(row)
    report_path = root / "report.html"
    report_path.write_text(_html_report(root, records), encoding="utf-8")
    return metrics_path, report_path


def _html_report(root: Path, records: list[dict[str, Any]]) -> str:
    campaign = load_json(root / "campaign.json")
    summary = campaign.get("summary", {})
    info = campaign.get("campaign", {})
    status = "Complete" if summary.get("passed") else "Incomplete"
    defense_rows = []
    by_defense: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_defense[str(record.get("defense"))].append(record)
    for defense, members in by_defense.items():
        ratios = [
            float(item["observed_overhead_vs_baseline_ratio"])
            for item in members
            if item.get("observed_overhead_vs_baseline_ratio") is not None
        ]
        defense_rows.append(
            "<tr>"
            f"<td>{html.escape(defense)}</td>"
            f"<td>{sum(item.get('state') == 'captured' for item in members)}/{len(members)}</td>"
            f"<td>{sum(item.get('eligible') is True for item in members)}</td>"
            f"<td>{_number(median(ratios) if ratios else None)}</td>"
            f"<td>{sum(int(item.get('missed_slots') or 0) for item in members)}</td>"
            "</tr>"
        )
    sample_rows = []
    for record in records:
        metadata = load_json(root / record["sample"] / "sample.json")
        links = []
        for view in metadata.get("views", []):
            if not view.get("valid"):
                continue
            for key, label in (("trace_path", "trace"), ("capture_path", "pcap")):
                relative = Path(record["sample"]) / view[key]
                links.append(
                    f'<a href="{html.escape(str(relative))}">{html.escape(view["id"])} {label}</a>'
                )
        sample_rows.append(
            "<tr>"
            f"<td>{html.escape(str(record['workload']))}</td>"
            f"<td>{record['repetition']}</td>"
            f"<td>{html.escape(str(record['defense']))}</td>"
            f"<td>{html.escape(str(record['state']))}</td>"
            f"<td>{'yes' if record['eligible'] else 'no'}</td>"
            f"<td>{_bytes(record.get('observed_bytes'))}</td>"
            f"<td>{_number(record.get('observed_overhead_vs_baseline_ratio'))}</td>"
            f"<td>{'yes' if record.get('content_drift') else 'no'}</td>"
            f"<td>{record.get('attempts') or 0}</td>"
            f"<td>{' · '.join(links) or '—'}</td>"
            "</tr>"
        )
    failures = [record for record in records if record.get("state") != "captured"]
    summary_figure = (
        '<figure><img src="dataset-summary.svg" alt="Dataset coverage, storage, and collection health">'
        '<figcaption>Coverage, retained capture storage, failures, and retries.</figcaption></figure>'
        if (root / "dataset-summary.svg").is_file()
        else ""
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{html.escape(str(info.get('name', root.name)))}</title>
<style>
body{{font:15px/1.45 system-ui,sans-serif;color:#20252b;max-width:1180px;margin:2rem auto;padding:0 1rem}}
h1,h2{{line-height:1.15}} .cards{{display:flex;gap:1rem;flex-wrap:wrap}} .card{{border:1px solid #ccd2d8;padding:.7rem 1rem;border-radius:6px}}
table{{border-collapse:collapse;width:100%;font-size:.86rem}} th,td{{border-bottom:1px solid #dce1e5;padding:.45rem;text-align:left;vertical-align:top}}
th{{background:#f4f6f7}} img{{max-width:100%}} a{{color:#075985}} .incomplete{{color:#a32121}} code{{background:#f2f4f5;padding:.1rem .25rem}}
</style></head><body>
<h1>{html.escape(str(info.get('name', root.name)))}</h1>
<p class="{'complete' if summary.get('passed') else 'incomplete'}"><strong>{status}</strong> · {html.escape(str(info.get('purpose', 'unknown')))} campaign</p>
<div class="cards">
<div class="card"><strong>{summary.get('eligible_visits', summary.get('eligible_groups', 0))}</strong><br>eligible paired visits</div>
<div class="card"><strong>{len(records)}</strong><br>defense samples</div>
<div class="card"><strong>{sum(record.get('eligible') is True for record in records)}</strong><br>eligible samples</div>
<div class="card"><strong>{len(failures)}</strong><br>failed samples</div>
</div>
<h2>Defense coverage</h2>
<table><thead><tr><th>Defense</th><th>Captured</th><th>Eligible</th><th>Median bytes vs baseline</th><th>Missed slots</th></tr></thead>
<tbody>{''.join(defense_rows)}</tbody></table>
{summary_figure}
<h2>Samples and observer artifacts</h2>
<table><thead><tr><th>Workload</th><th>Visit</th><th>Defense</th><th>State</th><th>Eligible</th><th>Observed bytes</th><th>Vs baseline</th><th>Drift</th><th>Attempts</th><th>Artifacts</th></tr></thead>
<tbody>{''.join(sample_rows)}</tbody></table>
<h2>Interpretation</h2>
<p>A paired visit is one workload repetition collected separately under every defense. Its train/test assignment is shared by all variants. Classification uses only normalized timing, direction, and length traces from the declared primary observer.</p>
<p>Detailed numeric definitions are documented in <code>METHODOLOGY.md</code>. Internal qlogs, response signatures, endpoints, and defense schedules are not classifier features.</p>
</body></html>"""


def _ratio(value: Any, baseline: dict[str, Any] | None, field: str) -> float | None:
    reference = baseline.get(field) if baseline else None
    return float(value) / float(reference) if value is not None and reference else None


def _number(value: Any) -> str:
    return "—" if value is None else f"{float(value):.2f}"


def _bytes(value: Any) -> str:
    if value is None:
        return "—"
    return f"{int(value):,}"
