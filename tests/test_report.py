import pytest

from qcsd_lab.report import _inline_svg, render_report


def test_report_is_self_contained_and_has_no_historical_gallery_or_pdf_links():
    report = render_report(
        _experiment(),
        _records(),
        [
            {
                "title": "Trace comparison",
                "caption": "Observed packet and controller action comparison.",
                "svg": '<?xml version="1.0"?><!DOCTYPE svg PUBLIC "test"><svg><text>x</text></svg>',
            }
        ],
    )

    assert report.count("<svg") == 1
    assert "<?xml" not in report
    assert "<!DOCTYPE svg" not in report
    assert "<img" not in report
    assert "<script" not in report
    assert "trace-comparison.pdf" not in report
    assert "20260719T141832Z" not in report
    assert "historical" not in report.lower()
    assert "derived output" in report
    assert "Packet-time density is not a bandwidth measure" in report


def test_report_links_only_consolidated_authoritative_artifacts():
    report = render_report(_experiment(), _records(), [])

    prefix = "../samples/site/as-defined/visit-000/undefended"
    assert f"{prefix}/capture.pcapng" in report
    assert f"{prefix}/neqo/run.json" in report
    assert f"{prefix}/neqo/packets.csv" in report
    assert f"{prefix}/neqo/events.csv" in report
    assert f"{prefix}/neqo/schedule.csv" in report
    assert "sample.json" not in report
    assert "fidelity.yml" not in report
    assert "classifier" not in report
    assert "qlog" not in report


def test_report_surfaces_incomplete_or_ineligible_paired_visits():
    records = _records()
    records[1]["state"] = "failed"
    records[1]["eligible"] = False
    records[1]["failure"] = {"reason": "capture failed"}

    report = render_report(_experiment(), records, [])

    assert "Incomplete or ineligible paired visits" in report
    assert "front" in report
    assert "capture failed" in report


def test_report_summarizes_paired_overhead_and_latency_by_defense():
    report = render_report(_experiment(), _records(), [])

    assert "Undefended" in report
    assert "FRONT" in report
    assert "+100.0%" in report
    assert "0.200" in report
    assert "0.400" in report


def test_report_does_not_merge_custom_variants_of_one_runtime_defense():
    records = _records()
    first = {**records[1], "defense_variant": "front-a"}
    second = {
        **records[1],
        "sample": "samples/site/as-defined/visit-000/front-b",
        "defense_variant": "front-b",
        "application_completion_seconds": 0.9,
    }

    report = render_report(_experiment(), [records[0], first, second], [])

    assert report.count("FRONT (front-a)") == 2
    assert report.count("FRONT (front-b)") == 2


def test_invalid_figure_is_rejected():
    with pytest.raises(ValueError, match="not an SVG"):
        _inline_svg("not a figure")


def test_embedded_figures_namespace_reused_svg_ids():
    svg = (
        '<svg><defs><clipPath id="shared"><path/></clipPath></defs>'
        '<g clip-path="url(#shared)"><use href="#shared"/></g></svg>'
    )
    report = render_report(
        _experiment(),
        _records(),
        [
            {"title": "one", "caption": "first", "svg": svg},
            {"title": "two", "caption": "second", "svg": svg},
        ],
    )

    assert 'id="figure-0-shared"' in report
    assert "url(#figure-0-shared)" in report
    assert 'href="#figure-0-shared"' in report
    assert 'id="figure-1-shared"' in report
    assert "url(#figure-1-shared)" in report


def _experiment():
    return {
        "name": "pilot",
        "purpose": "evaluation",
        "status": "complete",
        "input_digest": "a" * 64,
        "configuration": {"profile": "research-1200"},
        "summary": {"planned": 2, "accepted": 2, "eligible": 2},
    }


def _records():
    common = {
        "workload": "site",
        "request_policy": "as-defined",
        "visit": 0,
        "state": "accepted",
        "eligible": True,
        "attempts": 1,
        "failure": None,
        "trace_duration_seconds": 0.5,
        "defense_tail_seconds": 0.1,
        "missed_slots": 0,
    }
    return [
        {
            **common,
            "sample": "samples/site/as-defined/visit-000/undefended",
            "defense": "undefended",
            "baseline": True,
            "wire_bytes": 1_000,
            "wire_byte_overhead_ratio": 0.0,
            "application_completion_seconds": 0.2,
        },
        {
            **common,
            "sample": "samples/site/as-defined/visit-000/front",
            "defense": "front",
            "baseline": False,
            "wire_bytes": 2_000,
            "wire_byte_overhead_ratio": 1.0,
            "application_completion_seconds": 0.4,
        },
    ]
