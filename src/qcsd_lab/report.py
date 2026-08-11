"""Pure, self-contained HTML rendering for retroactive analysis."""

from __future__ import annotations

import html
import re
from collections import defaultdict
from statistics import median
from typing import Any, Mapping, Sequence

from .defenses import DEFENSE_LABELS, DEFENSE_ORDER, canonical_defense


def _escape(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _number(value: object, digits: int = 3) -> str:
    if value is None or value == "":
        return "—"
    return f"{float(value):.{digits}f}"


def _bytes(value: object) -> str:
    if value is None or value == "":
        return "—"
    return f"{int(value):,}"


def _percent(value: object) -> str:
    if value is None or value == "":
        return "—"
    return f"{float(value) * 100:+.1f}%"


def _defense_rank(value: str) -> tuple[int, str]:
    identity = canonical_defense(value)
    try:
        return DEFENSE_ORDER.index(identity), identity
    except ValueError:
        return len(DEFENSE_ORDER), identity


def _defense_display(record: Mapping[str, Any]) -> str:
    """Render scientific identity while retaining a custom campaign variant."""

    defense = canonical_defense(str(record.get("defense", "")))
    label = DEFENSE_LABELS.get(defense, defense)
    variant = record.get("defense_variant")
    if isinstance(variant, str) and variant and canonical_defense(variant) != defense:
        return f"{label} ({variant})"
    return label


def _inline_svg(value: str, namespace: str = "figure") -> str:
    """Make a deterministic Matplotlib SVG safe to embed in HTML.

    Matplotlib figures reuse internal IDs when their geometry is identical.
    Prefix those IDs so several standalone SVG documents can be embedded in
    one HTML document without clip paths or glyph references crossing figures.
    """

    value = re.sub(r"^\s*<\?xml[^>]*>\s*", "", value, count=1)
    value = re.sub(r"^\s*<!DOCTYPE[^>]*(?:\[[\s\S]*?\]\s*)?>\s*", "", value, count=1)
    if "<svg" not in value or "</svg>" not in value:
        raise ValueError("report figure is not an SVG document")
    identifiers = set(re.findall(r'\bid="([^"]+)"', value))
    for identifier in sorted(identifiers, key=len, reverse=True):
        replacement = f"{namespace}-{identifier}"
        value = value.replace(f'id="{identifier}"', f'id="{replacement}"')
        value = value.replace(f'href="#{identifier}"', f'href="#{replacement}"')
        value = value.replace(f'xlink:href="#{identifier}"', f'xlink:href="#{replacement}"')
        value = value.replace(f"url(#{identifier})", f"url(#{replacement})")
    return value


def render_report(
    experiment: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    figures: Sequence[Mapping[str, str]],
) -> str:
    """Render a static report with all derived figures embedded inline."""

    status = str(experiment.get("status", "unknown"))
    summary = experiment.get("summary")
    if not isinstance(summary, Mapping):
        summary = {}
    configuration = experiment.get("configuration")
    if not isinstance(configuration, Mapping):
        configuration = {}

    by_defense: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for record in records:
        defense = canonical_defense(str(record.get("defense", "")))
        variant = str(record.get("defense_variant") or defense)
        by_defense[(defense, variant)].append(record)
    defense_rows = []
    for treatment in sorted(by_defense, key=lambda item: (*_defense_rank(item[0]), item[1])):
        members = by_defense[treatment]
        accepted = [item for item in members if item.get("state") == "accepted"]
        eligible = [item for item in accepted if item.get("eligible") is True]
        overheads = [
            float(item["wire_byte_overhead_ratio"])
            for item in eligible
            if item.get("wire_byte_overhead_ratio") is not None
        ]
        latencies = [
            float(item["application_completion_seconds"])
            for item in eligible
            if item.get("application_completion_seconds") is not None
        ]
        defense_rows.append(
            "<tr>"
            f"<td>{_escape(_defense_display(members[0]))}</td>"
            f"<td>{len(accepted)}/{len(members)}</td>"
            f"<td>{len(eligible)}</td>"
            f"<td>{_percent(median(overheads) if overheads else None)}</td>"
            f"<td>{_number(median(latencies) if latencies else None)}</td>"
            f"<td>{sum(int(item.get('missed_slots') or 0) for item in members)}</td>"
            "</tr>"
        )

    sample_rows = []
    for record in records:
        sample = str(record.get("sample", ""))
        artifacts = "—"
        if sample and record.get("state") == "accepted":
            prefix = "../" + html.escape(sample)
            artifacts = (
                f'<a href="{prefix}/capture.pcapng">PCAP</a> · '
                f'<a href="{prefix}/neqo/run.json">run</a> · '
                f'<a href="{prefix}/neqo/packets.csv">packets</a> · '
                f'<a href="{prefix}/neqo/events.csv">events</a> · '
                f'<a href="{prefix}/neqo/schedule.csv">schedule</a>'
            )
        sample_rows.append(
            "<tr>"
            f"<td>{_escape(record.get('workload'))}</td>"
            f"<td>{_escape(record.get('request_policy'))}</td>"
            f"<td>{_escape(record.get('visit'))}</td>"
            f"<td>{_escape(_defense_display(record))}</td>"
            f"<td>{_escape(record.get('state'))}</td>"
            f"<td>{'yes' if record.get('eligible') is True else 'no'}</td>"
            f"<td>{_bytes(record.get('wire_bytes'))}</td>"
            f"<td>{_percent(record.get('wire_byte_overhead_ratio'))}</td>"
            f"<td>{_number(record.get('application_completion_seconds'))}</td>"
            f"<td>{_number(record.get('defense_tail_seconds'))}</td>"
            f"<td>{_escape(record.get('failure') or '') or '—'}</td>"
            f"<td>{artifacts}</td>"
            "</tr>"
        )

    figure_html = []
    for index, figure in enumerate(figures):
        figure_html.append(
            "<figure>"
            f"{_inline_svg(figure['svg'], f'figure-{index}')}"
            f"<figcaption><strong>{_escape(figure.get('title'))}</strong> — "
            f"{_escape(figure.get('caption'))}</figcaption>"
            "</figure>"
        )

    incomplete_groups = _incomplete_groups(records)
    incomplete_rows = [
        "<tr>"
        f"<td>{_escape(group[0])}</td><td>{_escape(group[1])}</td><td>{group[2]}</td>"
        f"<td>{_escape(', '.join(group[3]))}</td>"
        "</tr>"
        for group in incomplete_groups
    ]
    incomplete_section = (
        "<h2>Incomplete or ineligible paired visits</h2>"
        "<table><thead><tr><th>Workload</th><th>Policy</th><th>Visit</th>"
        "<th>Non-eligible modes</th></tr></thead><tbody>"
        + "".join(incomplete_rows)
        + "</tbody></table>"
        if incomplete_rows
        else ""
    )

    css = """
    :root { color-scheme: light; font-family: system-ui, sans-serif; color: #222; }
    body { max-width: 1180px; margin: 0 auto; padding: 2rem; line-height: 1.45; }
    h1, h2 { line-height: 1.15; }
    .facts { display: grid; grid-template-columns: repeat(auto-fit,minmax(12rem,1fr)); gap: .7rem; }
    .fact { border: 1px solid #ddd; padding: .65rem; background: #fafafa; }
    table { border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; font-size: .88rem; }
    th, td { border: 1px solid #ddd; padding: .38rem .5rem; text-align: left; vertical-align: top; }
    th { background: #f3f3f3; position: sticky; top: 0; }
    figure { margin: 2rem 0; border: 1px solid #ddd; padding: .75rem; overflow-x: auto; }
    figure svg { width: 100%; height: auto; min-width: 650px; }
    figcaption { margin-top: .5rem; color: #444; }
    code { background: #f4f4f4; padding: .05rem .25rem; }
    .warning { border-left: .3rem solid #b36b00; padding: .7rem; background: #fff8e8; }
    """
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{_escape(experiment.get('name'))} — QCSD report</title>"
        f"<style>{css}</style></head><body>"
        f"<h1>{_escape(experiment.get('name'))}</h1>"
        '<div class="facts">'
        f'<div class="fact"><strong>Purpose</strong><br>{_escape(experiment.get("purpose"))}</div>'
        f'<div class="fact"><strong>Status</strong><br>{_escape(status)}</div>'
        f'<div class="fact"><strong>Profile</strong><br>{_escape(configuration.get("profile"))}</div>'
        f'<div class="fact"><strong>Accepted</strong><br>{_escape(summary.get("accepted", 0))}/{_escape(summary.get("planned", len(records)))}</div>'
        f'<div class="fact"><strong>Eligible</strong><br>{_escape(summary.get("eligible", 0))}</div>'
        f'<div class="fact"><strong>Input digest</strong><br><code>{_escape(experiment.get("input_digest"))}</code></div>'
        "</div>"
        '<p class="warning">This report is derived output. The sealed PCAP and Neqo '
        "files are authoritative; delete <code>derived/</code> and rerun analysis to "
        "reproduce this report.</p>"
        "<h2>Defence coverage</h2><table><thead><tr><th>Defence</th>"
        "<th>Accepted</th><th>Eligible</th><th>Median paired wire overhead</th>"
        "<th>Median application time (s)</th><th>Missed slots</th>"
        "</tr></thead><tbody>"
        + "".join(defense_rows)
        + "</tbody></table>"
        + incomplete_section
        + ("<h2>Plots</h2>" + "".join(figure_html) if figure_html else "")
        + "<h2>Samples and authoritative artifacts</h2>"
        "<p>Wire overhead is paired against the eligible undefended sample with the "
        "same workload, policy, and visit. Packet-time density is not a bandwidth "
        "measure. Trace panels use a local time axis for shape comparison; use the "
        "table for absolute duration.</p>"
        "<table><thead><tr><th>Workload</th><th>Policy</th><th>Visit</th>"
        "<th>Defence</th><th>State</th><th>Eligible</th><th>Wire bytes</th>"
        "<th>Paired overhead</th><th>Application time (s)</th><th>Tail (s)</th>"
        "<th>Failure</th><th>Evidence</th></tr></thead><tbody>"
        + "".join(sample_rows)
        + "</tbody></table></body></html>\n"
    )


def _incomplete_groups(
    records: Sequence[Mapping[str, Any]],
) -> list[tuple[str, str, int, list[str]]]:
    groups: dict[tuple[str, str, int], list[Mapping[str, Any]]] = defaultdict(list)
    for record in records:
        key = (
            str(record.get("workload", "")),
            str(record.get("request_policy", "")),
            int(record.get("visit", 0)),
        )
        groups[key].append(record)
    result = []
    for key, members in sorted(groups.items()):
        if len(members) < 2:
            continue
        invalid = [
            str(member.get("defense_variant") or member.get("defense", ""))
            for member in members
            if member.get("state") != "accepted" or member.get("eligible") is not True
        ]
        baselines = [member for member in members if member.get("baseline") is True]
        if len(baselines) != 1:
            invalid.append("baseline")
        if invalid:
            result.append((*key, sorted(set(invalid), key=_defense_rank)))
    return result
