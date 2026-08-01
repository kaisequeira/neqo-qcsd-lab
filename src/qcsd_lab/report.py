from __future__ import annotations

import csv
import html
import json
from collections import defaultdict
from pathlib import Path
from statistics import median
from typing import Any

from .defenses import DEFENSE_ORDER, adaptation_table_rows
from .plotting import _realization_errors, calculate_metrics
from .util import load_json, padding_event_guard_triggered

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
    "fidelity_eligible",
    "content_drift",
    "attempts",
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
    "direct_byte_ratio_vs_baseline",
    "wire_byte_overhead_ratio",
    "application_completion_seconds",
    "load_time_overhead_ratio",
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
    "chaff_requests",
    "chaff_bytes",
    "padding_events",
    "padding_event_guard_triggered",
    "operationally_valid",
    "fidelity_realization_metrics",
    "fidelity_realization_errors",
    "observer_packets",
]

ADAPTATION_ROWS = adaptation_table_rows()


def create_report(root: Path) -> tuple[Path, Path]:
    """Write classifier metrics and one compact static campaign report."""

    campaign = load_json(root / "campaign.json")
    passed = campaign.get("summary", {}).get("passed") is True
    records = []
    for metadata_path in sorted(root.rglob("sample.json")):
        if "attempts" in metadata_path.parts:
            continue
        sample = metadata_path.parent
        metadata = load_json(metadata_path)
        metrics: dict[str, Any] = {}
        has_valid_view = any(view.get("valid") for view in metadata.get("views", []))
        if has_valid_view:
            try:
                metrics = calculate_metrics(sample)
            except (FileNotFoundError, KeyError, RuntimeError, ValueError) as error:
                if passed:
                    raise RuntimeError(
                        "cannot calculate required metrics for passed campaign "
                        f"sample {sample.relative_to(root)}: {error}"
                    ) from error
        elif passed and metadata.get("state") == "captured":
            raise RuntimeError(
                f"passed campaign sample has no valid observer view: {sample.relative_to(root)}"
            )
        fidelity_path = metadata.get("fidelity_path")
        if isinstance(fidelity_path, str):
            fidelity_file = sample / fidelity_path
            if fidelity_file.is_file():
                fidelity = load_json(fidelity_file)
                realization = fidelity.get("realization_metrics")
                if isinstance(realization, dict):
                    defense = str(metadata.get("defense", "")).lower().replace("_", "-")
                    metrics["fidelity_realization_metrics"] = realization
                    metrics["fidelity_realization_errors"] = _realization_errors(
                        defense,
                        realization,
                    )
        diagnostics = metadata.get("defense_diagnostics")
        if isinstance(diagnostics, dict):
            metrics.setdefault("padding_events", diagnostics.get("padding_events"))
            metrics.setdefault(
                "padding_event_guard_triggered",
                padding_event_guard_triggered(metadata),
            )
            defense = str(metadata.get("defense", "")).lower().replace("_", "-")
            metrics.setdefault(
                "fidelity_realization_errors",
                _realization_errors(defense, diagnostics),
            )
            metrics.setdefault(
                "fidelity_realization_metrics",
                _realization_metrics(defense, diagnostics),
            )
        if metadata.get("operationally_valid") is not None:
            metrics.setdefault(
                "operationally_valid",
                metadata.get("operationally_valid") is True,
            )
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
                "fidelity_eligible": metadata.get("fidelity_eligible") is True,
                "content_drift": metadata.get("content_drift"),
                "attempts": metadata.get("attempts"),
                **{
                    key: metrics.get(key)
                    for key in METRIC_FIELDS
                    if key
                    not in {
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
                        "fidelity_eligible",
                        "content_drift",
                        "attempts",
                        "direct_byte_ratio_vs_baseline",
                        "wire_byte_overhead_ratio",
                        "load_time_overhead_ratio",
                        "application_delay_seconds",
                        "application_delay_ratio",
                    }
                },
            }
        )
    baselines = {
        record["visit_id"]: record
        for record in records
        if load_json(root / record["sample"] / "sample.json").get("baseline") is True
    }
    for record in sorted(records, key=_record_rank):
        baseline = baselines.get(record["visit_id"])
        record["direct_byte_ratio_vs_baseline"] = _ratio(
            record.get("wire_bytes"), baseline, "wire_bytes"
        )
        record["wire_byte_overhead_ratio"] = _overhead(
            record.get("wire_bytes"), baseline, "wire_bytes"
        )
        record["load_time_overhead_ratio"] = _ratio(
            record.get("application_completion_seconds"),
            baseline,
            "application_completion_seconds",
        )
        record["application_delay_seconds"] = _difference(
            record.get("application_completion_seconds"),
            baseline,
            "application_completion_seconds",
        )
        record["application_delay_ratio"] = _overhead(
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
            row["fidelity_realization_errors"] = json.dumps(
                record.get("fidelity_realization_errors") or {},
                sort_keys=True,
                separators=(",", ":"),
            )
            row["fidelity_realization_metrics"] = json.dumps(
                record.get("fidelity_realization_metrics") or {},
                sort_keys=True,
                separators=(",", ":"),
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
    for defense in sorted(by_defense, key=_defense_rank):
        members = by_defense[defense]
        ratios = [
            float(item["wire_byte_overhead_ratio"])
            for item in members
            if item.get("wire_byte_overhead_ratio") is not None
        ]
        defense_rows.append(
            "<tr>"
            f"<td>{html.escape(defense)}</td>"
            f"<td>{sum(item.get('state') == 'captured' for item in members)}/{len(members)}</td>"
            f"<td>{sum(item.get('eligible') is True for item in members)}</td>"
            f"<td>{sum(item.get('fidelity_eligible') is True for item in members)}</td>"
            f"<td>{_percent(median(ratios) if ratios else None)}</td>"
            f"<td>{sum(int(item.get('missed_slots') or 0) for item in members)}</td>"
            "</tr>"
        )
    overhead_rows = []
    artifact_rows = []
    for record in sorted(records, key=_record_rank):
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
        fidelity_path = metadata.get("fidelity_path")
        if isinstance(fidelity_path, str) and (root / record["sample"] / fidelity_path).is_file():
            relative = Path(record["sample"]) / fidelity_path
            links.append(f'<a href="{html.escape(str(relative))}">fidelity record</a>')
        overhead_rows.append(
            "<tr>"
            f"<td>{html.escape(str(record['workload']))}</td>"
            f"<td>{record['repetition']}</td>"
            f"<td>{html.escape(str(record['defense']))}</td>"
            f"<td>{_directional(record, 'wire_bytes', _bytes)}</td>"
            f"<td>{_directional(record, 'wire_packets', _count)}</td>"
            f"<td>{_percent(record.get('wire_byte_overhead_ratio'))}</td>"
            f"<td>{_seconds(record.get('application_completion_seconds'))}</td>"
            f"<td>{_signed_seconds(record.get('application_delay_seconds'))}</td>"
            f"<td>{_seconds(record.get('trace_duration_seconds'))}</td>"
            f"<td>{_tail(record)}</td>"
            f"<td>{'yes' if record.get('fidelity_eligible') else 'no'}</td>"
            f"<td>{_errors(record.get('fidelity_realization_metrics'))}</td>"
            "</tr>"
        )
        artifact_rows.append(
            "<tr>"
            f"<td>{html.escape(str(record['workload']))}</td>"
            f"<td>{record['repetition']}</td>"
            f"<td>{html.escape(str(record['defense']))}</td>"
            f"<td>{html.escape(str(record['state']))}</td>"
            f"<td>{'yes' if record['eligible'] else 'no'}</td>"
            f"<td>{'yes' if record.get('fidelity_eligible') else 'no'}</td>"
            f"<td>{'yes' if record.get('content_drift') else 'no'}</td>"
            f"<td>{record.get('attempts') or 0}</td>"
            f"<td>{' · '.join(links) or '—'}</td>"
            "</tr>"
        )
    failures = [record for record in records if record.get("state") != "captured"]
    comparison_figures = []
    for svg in sorted(root.rglob("trace-comparison*.svg"), key=_comparison_figure_rank):
        if "attempts" in svg.parts:
            continue
        relative_svg = svg.relative_to(root)
        relative_pdf = relative_svg.with_suffix(".pdf")
        if not (root / relative_pdf).is_file():
            continue
        visit = relative_svg.parent
        comparison_figures.append(
            "<figure>"
            f'<a href="{html.escape(str(relative_pdf))}">'
            f'<img src="{html.escape(str(relative_svg))}" '
            f'alt="Direct-PCAP trace comparison for {html.escape(str(visit))}"></a>'
            "<figcaption>"
            f"{html.escape(str(visit))}: packet-time density and signed direct "
            "<code>frame.len</code>. Each defence has a local time axis; "
            "the adjacent overhead table preserves absolute duration. "
            "Open the print-quality PDF."
            "</figcaption></figure>"
        )
    comparison_section = (
        "<h2>Direct-PCAP trace comparisons</h2>"
        "<p>All panels use the tuple-filtered <code>eth0</code> capture. "
        "Solid curves are observed packets; dashed curves are recorded controller-action "
        "schedules, including exact incoming receive-credit replacements. They are action "
        "density overlays, not logical target-cell counts. "
        "Time axes are local to each defence and therefore support shape comparison, "
        "not duration comparison.</p>" + "".join(comparison_figures)
        if comparison_figures
        else ""
    )
    canonical_root = root.parent / "20260719T141832Z"
    current_workloads = {str(record.get("workload")) for record in records}
    canonical_figures = []
    available_canonical_workloads = set()
    for svg in sorted(canonical_root.glob("*/rep-000/trace-comparison.svg")):
        workload = svg.parent.parent.name
        pdf = svg.with_suffix(".pdf")
        if not pdf.is_file():
            continue
        available_canonical_workloads.add(workload)
        relative_svg = Path("..") / canonical_root.name / workload / "rep-000" / svg.name
        relative_pdf = relative_svg.with_suffix(".pdf")
        relationship = (
            "<strong>Same-workload comparator.</strong>"
            if workload in current_workloads
            else "Reference gallery only; this workload is not in the current campaign."
        )
        canonical_figures.append(
            "<figure>"
            f'<a href="{html.escape(str(relative_pdf))}">'
            f'<img src="{html.escape(str(relative_svg))}" '
            f'alt="Canonical original-three direct comparison for {html.escape(workload)}"></a>'
            "<figcaption>"
            f"{html.escape(workload)}: canonical Undefended/FRONT/Tamaraw direct capture "
            f"from <code>20260719T141832Z</code>. {relationship} "
            "Open the print-quality PDF."
            "</figcaption></figure>"
        )
    missing_canonical_workloads = sorted(current_workloads - available_canonical_workloads)
    missing_notice = (
        "<p><strong>No same-workload canonical comparator exists for:</strong> "
        + ", ".join(
            f"<code>{html.escape(workload)}</code>" for workload in missing_canonical_workloads
        )
        + ". Do not interpret another gallery workload as a like-for-like baseline.</p>"
        if missing_canonical_workloads
        else ""
    )
    gallery = (
        "<h2>Canonical original-three reference</h2>"
        "<p>These are the sealed direct <code>frame.len</code> figures used for visual "
        "comparison. Traffic Morphing fitting remains based on UDP payload size. "
        "Only entries marked as same-workload comparators support a like-for-like "
        "visual comparison.</p>" + missing_notice + "".join(canonical_figures)
    )
    canonical_section = (
        gallery
        if canonical_figures
        else (
            "<h2>Canonical original-three reference</h2>"
            "<p>The canonical root <code>20260719T141832Z</code> is unavailable or "
            "contains no complete PDF/SVG figure pairs, so no original-three figure "
            "can be linked.</p>"
        )
    )
    adaptation_rows = "".join(
        "<tr>" + "".join(f"<td>{html.escape(cell)}</td>" for cell in row) + "</tr>"
        for row in ADAPTATION_ROWS
    )
    classifier_links = " · ".join(
        f'<a href="{name}">{label}</a>'
        for name, label in (
            ("classifier.json", "classifier contract"),
            ("classifier-samples.jsonl", "classifier sample index"),
        )
        if (root / name).is_file()
    )
    classifier_section = (
        f"<p><strong>Classifier views:</strong> {classifier_links}</p>" if classifier_links else ""
    )
    stage = info.get("stage", campaign.get("configuration", {}).get("stage"))
    acceptance_notice = (
        '<p class="watermark"><strong>Operational acceptance evidence.</strong> '
        "Singleton or reviewed-fixture results are not study estimates and carry "
        "no confidence interval.</p>"
        if stage == "acceptance" or summary.get("required_visits") == 1
        else ""
    )
    research_summary = _research_summary(records, stage)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>{html.escape(str(info.get("name", root.name)))}</title>
<style>
body{{font:15px/1.45 system-ui,sans-serif;color:#20252b;max-width:1180px;margin:2rem auto;padding:0 1rem}}
h1,h2{{line-height:1.15}} .cards{{display:flex;gap:1rem;flex-wrap:wrap}} .card{{border:1px solid #ccd2d8;padding:.7rem 1rem;border-radius:6px}}
table{{border-collapse:collapse;width:100%;font-size:.86rem}} th,td{{border-bottom:1px solid #dce1e5;padding:.45rem;text-align:left;vertical-align:top}}
th{{background:#f4f6f7}} img{{max-width:100%}} a{{color:#075985}} .incomplete{{color:#a32121}} code{{background:#f2f4f5;padding:.1rem .25rem}}
.watermark{{border:2px solid #9a6700;background:#fff8c5;padding:.7rem 1rem}} .scroll{{overflow-x:auto}}
</style></head><body>
<h1>{html.escape(str(info.get("name", root.name)))}</h1>
<p class="{"complete" if summary.get("passed") else "incomplete"}"><strong>{status}</strong> · {html.escape(str(info.get("purpose", "unknown")))} campaign</p>
<div class="cards">
<div class="card"><strong>{summary.get("eligible_visits", summary.get("eligible_groups", 0))}</strong><br>eligible paired visits</div>
<div class="card"><strong>{len(records)}</strong><br>defense samples</div>
<div class="card"><strong>{sum(record.get("eligible") is True for record in records)}</strong><br>eligible samples</div>
<div class="card"><strong>{len(failures)}</strong><br>failed samples</div>
</div>
{acceptance_notice}
{classifier_section}
<h2>Defense coverage</h2>
<table><thead><tr><th>Defense</th><th>Captured</th><th>Eligible</th><th>Fidelity eligible</th><th>Median direct-byte overhead</th><th>Missed slots</th></tr></thead>
<tbody>{"".join(defense_rows)}</tbody></table>
{research_summary}
{comparison_section}
{canonical_section}
<h2>Defence adaptation matrix</h2>
<div class="scroll"><table><thead><tr><th>Defence</th><th>Preserved paper invariant</th><th>QCSD realization</th><th>Unavoidable deviation</th><th>Validation signal</th><th>Interpretation</th></tr></thead>
<tbody>{adaptation_rows}</tbody></table></div>
<h2>Paired direct-wire overhead and duration</h2>
<p>Bandwidth overhead is the paired direct wire-byte overhead: <code>(defended bytes / undefended bytes) − 1</code>. Packet-time density is not a bandwidth measure.</p>
<div class="scroll"><table><thead><tr><th>Workload</th><th>Visit</th><th>Defense</th><th>Wire bytes<br>out / in</th><th>Packets<br>out / in</th><th>Byte overhead</th><th>Application time</th><th>Paired application delay</th><th>Trace duration</th><th>Defense tail<br>time / bytes / packets</th><th>Fidelity eligible</th><th>Fidelity realization errors and totals</th></tr></thead>
<tbody>{"".join(overhead_rows)}</tbody></table></div>
<h2>Samples and observer artifacts</h2>
<table><thead><tr><th>Workload</th><th>Visit</th><th>Defense</th><th>State</th><th>Eligible</th><th>Fidelity eligible</th><th>Drift</th><th>Attempts</th><th>Artifacts</th></tr></thead>
<tbody>{"".join(artifact_rows)}</tbody></table>
<h2>Interpretation</h2>
<p>A paired visit is one workload repetition collected separately under every defense. Its split assignment is shared by all variants. Classification uses only full variable-length sequences of inter-packet time, client-relative direction, and direct <code>frame.len</code>. Individual traces are not duration-normalized.</p>
<p>Detailed numeric definitions are documented in <code>METHODOLOGY.md</code>. Internal qlogs, response signatures, endpoints, defense schedules, and raw direct PCAPs are not classifier features. Raw PCAPs retain network metadata and are <strong>not for release</strong>.</p>
</body></html>"""


def _ratio(value: Any, baseline: dict[str, Any] | None, field: str) -> float | None:
    reference = baseline.get(field) if baseline else None
    return float(value) / float(reference) if value is not None and reference else None


def _realization_metrics(defense: str, diagnostics: dict[str, Any]) -> dict[str, Any]:
    canonical = defense.lower().replace("_", "-")
    prefixes = {
        "traffic-morphing": ("morphing_",),
        "wtf-pad": ("wtf_pad_",),
        "walkie-talkie": ("walkie_talkie_",),
    }.get(canonical, ())
    generic = {
        "traffic-morphing": {"suppressed_cover_feedback"},
        "wtf-pad": {
            "padding_event_guard_triggered",
            "padding_events",
            "suppressed_cover_feedback",
        },
        "walkie-talkie": {"retried_outgoing_events"},
    }.get(canonical, set())
    return {
        key: value
        for key, value in sorted(diagnostics.items())
        if key in generic or key.startswith(prefixes)
    }


def _research_summary(records: list[dict[str, Any]], stage: Any) -> str:
    if stage != "research":
        return ""
    defenses = {str(record.get("defense")) for record in records}
    by_visit: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_visit[str(record.get("visit_id"))].append(record)
    complete_visits = {
        visit_id
        for visit_id, members in by_visit.items()
        if {str(member.get("defense")) for member in members} == defenses
        and all(
            member.get("eligible") is True and member.get("fidelity_eligible") is True
            for member in members
        )
    }
    rows = []
    for defense in sorted(defenses, key=_defense_rank):
        members = [
            record
            for record in records
            if str(record.get("defense")) == defense
            and str(record.get("visit_id")) in complete_visits
        ]
        overheads = _numeric(members, "wire_byte_overhead_ratio")
        delays = _numeric(members, "application_delay_seconds")
        durations = _numeric(members, "trace_duration_seconds")
        workload_medians = []
        by_workload: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for member in members:
            by_workload[str(member.get("workload"))].append(member)
        for workload_members in by_workload.values():
            values = _numeric(workload_members, "wire_byte_overhead_ratio")
            if values:
                workload_medians.append(median(values))
        macro = sum(workload_medians) / len(workload_medians) if workload_medians else None
        rows.append(
            "<tr>"
            f"<td>{html.escape(defense)}</td>"
            f"<td>{len(members)}</td>"
            f"<td>{_median_iqr(overheads, percent=True)}</td>"
            f"<td>{_median_iqr(delays, seconds=True)}</td>"
            f"<td>{_median_iqr(durations, seconds=True)}</td>"
            f"<td>{_percent(macro)}</td>"
            "</tr>"
        )
    return (
        "<h2>Research summary over complete seven-way pairs</h2>"
        "<p>Per-defence medians and interquartile ranges use only visits for which "
        "every configured defence is operationally and fidelity eligible. The macro "
        "column averages workload-level median overheads so large workload classes do "
        "not dominate.</p>"
        '<div class="scroll"><table><thead><tr><th>Defense</th><th>Complete pairs</th>'
        "<th>Wire-byte overhead median [IQR]</th>"
        "<th>Application delay median [IQR]</th>"
        "<th>Trace duration median [IQR]</th>"
        "<th>Macro mean workload-median overhead</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _numeric(records: list[dict[str, Any]], field: str) -> list[float]:
    return [float(record[field]) for record in records if record.get(field) is not None]


def _median_iqr(
    values: list[float],
    *,
    percent: bool = False,
    seconds: bool = False,
) -> str:
    if not values:
        return "—"
    ordered = sorted(values)
    center = median(ordered)
    low = _quantile(ordered, 0.25)
    high = _quantile(ordered, 0.75)
    if percent:
        return f"{_percent(center)} [{_percent(low)}, {_percent(high)}]"
    if seconds:
        return f"{_seconds(center)} [{_seconds(low)}, {_seconds(high)}]"
    return f"{center:.3f} [{low:.3f}, {high:.3f}]"


def _quantile(ordered: list[float], probability: float) -> float:
    if len(ordered) == 1:
        return ordered[0]
    position = probability * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def _overhead(value: Any, baseline: dict[str, Any] | None, field: str) -> float | None:
    ratio = _ratio(value, baseline, field)
    return ratio - 1.0 if ratio is not None else None


def _difference(value: Any, baseline: dict[str, Any] | None, field: str) -> float | None:
    reference = baseline.get(field) if baseline else None
    return float(value) - float(reference) if value is not None and reference is not None else None


def _defense_rank(name: str) -> tuple[int, str]:
    canonical = name.lower().replace("_", "-")
    canonical = "undefended" if canonical in {"none", "undefended"} else canonical
    try:
        return DEFENSE_ORDER.index(canonical), canonical
    except ValueError:
        return len(DEFENSE_ORDER), canonical


def _record_rank(record: dict[str, Any]) -> tuple[str, str, tuple[int, str]]:
    return (
        str(record.get("workload")),
        str(record.get("repetition")),
        _defense_rank(str(record.get("defense"))),
    )


def _comparison_figure_rank(path: Path) -> tuple[str, int]:
    suffix = path.stem.removeprefix("trace-comparison")
    try:
        page = int(suffix.removeprefix("-")) if suffix else 1
    except ValueError:
        page = 10_000
    return str(path.parent), page


def _percent(value: Any) -> str:
    return "—" if value is None else f"{float(value) * 100:+.1f}%"


def _seconds(value: Any) -> str:
    return "—" if value is None else f"{float(value):.3f} s"


def _signed_seconds(value: Any) -> str:
    return "—" if value is None else f"{float(value):+.3f} s"


def _count(value: Any) -> str:
    return "—" if value is None else f"{int(value):,}"


def _directional(
    record: dict[str, Any],
    stem: str,
    formatter: Any,
) -> str:
    outgoing = formatter(record.get(f"{stem}_outgoing"))
    incoming = formatter(record.get(f"{stem}_incoming"))
    return f"{outgoing} / {incoming}"


def _tail(record: dict[str, Any]) -> str:
    return (
        f"{_seconds(record.get('defense_tail_seconds'))} / "
        f"{_bytes(record.get('defense_tail_bytes'))} / "
        f"{_count(record.get('defense_tail_packets'))}"
    )


def _errors(value: Any) -> str:
    if not value:
        return "—"
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return html.escape(value)
    return f"<code>{html.escape(json.dumps(value, sort_keys=True, separators=(',', ':')))}</code>"


def _bytes(value: Any) -> str:
    if value is None:
        return "—"
    return f"{int(value):,}"
