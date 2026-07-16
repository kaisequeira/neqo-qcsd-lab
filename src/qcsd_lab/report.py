from __future__ import annotations

import csv
import html
from pathlib import Path

from .plotting import calculate_metrics
from .util import load_json


def create_report(results: Path, output: Path) -> None:
    samples = sorted(path.parent for path in results.rglob("sample.json"))
    records = []
    for sample in samples:
        metadata = load_json(sample / "sample.json")
        metrics = calculate_metrics(sample) if (sample / "traffic.csv").exists() else {}
        records.append(
            {
                "_block": str(sample.parent.relative_to(results)),
                "sample": str(sample.relative_to(results)),
                "defense": metadata.get("defense"),
                "state": metadata.get("state"),
                "eligible": metadata.get("comparison_eligible"),
                "content_drift": metadata.get("content_drift"),
                "wire_bytes": metrics.get("wire_bytes"),
                "udp_payload_bytes": metrics.get("udp_payload_bytes"),
                "wire_overhead_bytes": metrics.get("wire_overhead_bytes"),
                "udp_overhead_bytes": metrics.get("udp_overhead_bytes"),
                "wire_overhead_ratio": metrics.get("wire_overhead_ratio"),
                "udp_overhead_ratio": metrics.get("udp_overhead_ratio"),
                "load_seconds": metrics.get("application_completion_seconds"),
                "goodput_bytes_per_second": metrics.get("goodput_bytes_per_second"),
                "satisfaction": metrics.get("target_satisfaction_ratio"),
                "missed_slots": metrics.get("missed_slots"),
                "missed_slot_reasons": metrics.get("missed_slot_reasons"),
                "chaff_requests": metrics.get("chaff_requests"),
                "chaff_bytes": metrics.get("chaff_bytes"),
            }
        )
    for record in records:
        baseline = next(
            (
                candidate
                for candidate in records
                if candidate["_block"] == record["_block"]
                and str(candidate["defense"]).lower() in {"none", "baseline", "undefended"}
            ),
            None,
        )
        record["wire_overhead_vs_baseline_ratio"] = _ratio(record["wire_bytes"], baseline, "wire_bytes")
        record["load_time_overhead_ratio"] = _ratio(record["load_seconds"], baseline, "load_seconds")
    for record in records:
        record.pop("_block", None)
    fields = list(records[0]) if records else ["sample", "defense", "state"]
    output.mkdir(parents=True, exist_ok=True)
    with (output / "report.csv").open("w", newline="", encoding="utf-8") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)
    header = "| " + " | ".join(fields) + " |"
    separator = "|" + "|".join("---" for _ in fields) + "|"
    rows = ["| " + " | ".join(str(record.get(field, "")) for field in fields) + " |" for record in records]
    markdown = "# QCSD campaign report\n\n" + "\n".join([header, separator, *rows]) + "\n"
    (output / "report.md").write_text(markdown, encoding="utf-8")
    html_rows = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(record.get(field, '')))}</td>" for field in fields) + "</tr>"
        for record in records
    )
    html_header = "".join(f"<th>{html.escape(field)}</th>" for field in fields)
    document = f"<!doctype html><meta charset='utf-8'><title>QCSD report</title><h1>QCSD campaign report</h1><table><thead><tr>{html_header}</tr></thead><tbody>{html_rows}</tbody></table>"
    (output / "report.html").write_text(document, encoding="utf-8")


def _ratio(value, baseline, field):
    if value is None or baseline is None or not baseline.get(field):
        return None
    return value / baseline[field]
