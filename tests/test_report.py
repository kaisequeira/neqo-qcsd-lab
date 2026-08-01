import csv
import json

import pytest

import qcsd_lab.report as report_module
from qcsd_lab.report import _html_report, create_report


def test_report_is_compact_static_and_links_direct_artifacts_and_figures(tmp_path):
    campaign = {
        "campaign": {"name": "live-qcsd", "purpose": "classification"},
        "summary": {
            "passed": True,
            "eligible_visits": 1,
            "required_visits": 1,
        },
    }
    (tmp_path / "campaign.json").write_text(json.dumps(campaign), encoding="utf-8")
    records = [_record("undefended", 1000), _record("front", 2000)]
    for record in records:
        sample = tmp_path / record["sample"]
        (sample / "captures").mkdir(parents=True)
        (sample / "traces").mkdir()
        (sample / "captures/direct-quic.pcapng").write_bytes(b"capture")
        (sample / "traces/direct-quic.csv").write_text("trace", encoding="utf-8")
        (sample / "fidelity.yml").write_text("{}\n", encoding="utf-8")
        (sample / "sample.json").write_text(
            json.dumps(
                {
                    "fidelity_path": "fidelity.yml",
                    "fidelity_eligible": True,
                    "views": [
                        {
                            "id": "direct-quic",
                            "valid": True,
                            "capture_path": "captures/direct-quic.pcapng",
                            "trace_path": "traces/direct-quic.csv",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
    (tmp_path / "classifier.json").write_text("{}", encoding="utf-8")
    (tmp_path / "classifier-samples.jsonl").write_text("{}\n", encoding="utf-8")
    visit = tmp_path / "site/site-visit-00000"
    (visit / "trace-comparison.svg").write_text("<svg/>", encoding="utf-8")
    (visit / "trace-comparison.pdf").write_bytes(b"%PDF")
    (visit / "trace-comparison-2.svg").write_text("<svg/>", encoding="utf-8")
    (visit / "trace-comparison-2.pdf").write_bytes(b"%PDF")

    report = _html_report(tmp_path, records)
    assert "eligible paired visits" in report
    assert "Defense coverage" in report
    assert "Samples and observer artifacts" in report
    assert "direct-quic trace" in report
    assert "direct-quic pcap" in report
    assert "Direct-PCAP trace comparisons" in report
    assert "site/site-visit-00000/trace-comparison.pdf" in report
    assert "site/site-visit-00000/trace-comparison-2.svg" in report
    assert report.index("trace-comparison.svg") < report.index("trace-comparison-2.svg")
    assert "not for release" in report
    assert "local to each defence" in report
    assert "shape comparison, not duration comparison" in report
    assert "Paired direct-wire overhead and duration" in report
    assert "(defended bytes / undefended bytes) − 1" in report
    assert "Packet-time density is not a bandwidth measure" in report
    assert "Wire bytes<br>out / in" in report
    assert "Application time" in report
    assert "Paired application delay" in report
    assert "Fidelity realization errors" in report
    assert "classifier.json" in report
    assert "classifier-samples.jsonl" in report
    assert "fidelity record" in report
    assert "Fidelity eligible" in report
    assert "full variable-length sequences" in report
    assert "not duration-normalized" in report
    assert "Operational acceptance evidence" in report
    assert "recorded controller-action schedules" in report
    assert "not logical target-cell counts" in report
    assert "qlog" in report  # appears only in the prohibited-feature explanation
    assert "endpoint.sqlog" not in report
    assert "schedule.csv" not in report
    assert "<script" not in report
    assert "<select" not in report
    assert "box-shadow" not in report


def test_metrics_use_paired_direct_wire_overhead_and_absolute_delay(tmp_path, monkeypatch):
    (tmp_path / "campaign.json").write_text(
        json.dumps(
            {
                "campaign": {"name": "paired", "purpose": "classification"},
                "summary": {"passed": True},
            }
        ),
        encoding="utf-8",
    )
    values = {
        "undefended": {
            "wire_bytes": 1000,
            "application_completion_seconds": 0.4,
        },
        "front": {
            "wire_bytes": 2500,
            "application_completion_seconds": 0.55,
        },
    }
    for defense in values:
        sample = tmp_path / f"site/site-visit-00000/{defense}"
        sample.mkdir(parents=True)
        (sample / "sample.json").write_text(
            json.dumps(
                {
                    "sample_id": defense,
                    "visit_id": "visit-1",
                    "workload_id": "site",
                    "repetition": 0,
                    "defense": defense,
                    "baseline": defense == "undefended",
                    "state": "captured",
                    "eligible": True,
                    "views": [
                        {
                            "id": "direct-quic",
                            "valid": True,
                            "trace_path": "traces/direct-quic.csv",
                            "capture_path": "captures/direct-quic.pcapng",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    def metrics(sample):
        value = values[sample.name]
        return {
            **value,
            "wire_bytes_outgoing": value["wire_bytes"] // 2,
            "wire_bytes_incoming": value["wire_bytes"] // 2,
            "wire_packets": 10,
            "wire_packets_outgoing": 5,
            "wire_packets_incoming": 5,
        }

    monkeypatch.setattr(report_module, "calculate_metrics", metrics)
    metrics_path, report_path = create_report(tmp_path)
    with metrics_path.open(newline="", encoding="utf-8") as source:
        rows = {row["defense"]: row for row in csv.DictReader(source)}
    assert float(rows["undefended"]["wire_byte_overhead_ratio"]) == 0
    assert float(rows["front"]["direct_byte_ratio_vs_baseline"]) == 2.5
    assert float(rows["front"]["wire_byte_overhead_ratio"]) == 1.5
    assert float(rows["front"]["application_delay_seconds"]) == pytest.approx(0.15)
    assert float(rows["front"]["application_delay_ratio"]) == pytest.approx(0.375)
    report = report_path.read_text(encoding="utf-8")
    assert "+150.0%" in report
    assert "0.550 s" in report
    assert "+0.150 s" in report


def test_report_links_full_canonical_gallery_and_discloses_missing_workload_comparator(
    tmp_path,
):
    root = tmp_path / "results/20260731T000000Z"
    root.mkdir(parents=True)
    (root / "campaign.json").write_text(
        json.dumps(
            {
                "campaign": {
                    "name": "paper-ready",
                    "stage": "acceptance",
                    "purpose": "classification",
                },
                "summary": {"passed": True, "required_visits": 2},
            }
        ),
        encoding="utf-8",
    )
    records = []
    for workload in ("cloudflare-quiche", "chromium-quic-page"):
        record = _record("undefended", 1_000)
        record.update(
            sample=f"{workload}/{workload}-visit-00000/undefended",
            workload=workload,
            visit_id=f"{workload}-visit",
        )
        sample = root / record["sample"]
        sample.mkdir(parents=True)
        (sample / "sample.json").write_text(json.dumps({"views": []}), encoding="utf-8")
        records.append(record)

    canonical = root.parent / "20260719T141832Z"
    for workload in ("aioquic", "cloudflare-quiche"):
        figure = canonical / workload / "rep-000"
        figure.mkdir(parents=True)
        (figure / "trace-comparison.svg").write_text("<svg/>", encoding="utf-8")
        (figure / "trace-comparison.pdf").write_bytes(b"%PDF")

    report = _html_report(root, records)
    assert "../20260719T141832Z/aioquic/rep-000/trace-comparison.pdf" in report
    assert "../20260719T141832Z/cloudflare-quiche/rep-000/trace-comparison.svg" in report
    assert "Same-workload comparator" in report
    assert "No same-workload canonical comparator exists for:" in report
    assert "<code>chromium-quic-page</code>" in report
    assert "Do not interpret another gallery workload as a like-for-like baseline" in report


def test_failed_guarded_run_is_explicit_in_metrics(tmp_path):
    (tmp_path / "campaign.json").write_text(
        json.dumps(
            {
                "campaign": {"name": "guarded", "purpose": "classification"},
                "summary": {"passed": False},
            }
        ),
        encoding="utf-8",
    )
    sample = tmp_path / "site/site-visit-00000/wtf-pad"
    sample.mkdir(parents=True)
    (sample / "sample.json").write_text(
        json.dumps(
            {
                "state": "failed",
                "defense": "wtf-pad",
                "eligible": False,
                "operationally_valid": False,
                "views": [],
                "defense_diagnostics": {
                    "padding_events": 100,
                    "padding_event_guard_triggered": True,
                },
            }
        ),
        encoding="utf-8",
    )
    metrics_path, _report_path = create_report(tmp_path)
    with metrics_path.open(newline="", encoding="utf-8") as source:
        row = next(csv.DictReader(source))
    assert row["padding_events"] == "100"
    assert row["padding_event_guard_triggered"] == "True"
    assert row["operationally_valid"] == "False"


def test_passed_campaign_does_not_seal_blank_metrics_after_metric_failure(tmp_path):
    (tmp_path / "campaign.json").write_text(
        json.dumps(
            {
                "campaign": {
                    "name": "passed",
                    "purpose": "classification",
                    "status": "complete",
                },
                "summary": {"passed": True},
            }
        ),
        encoding="utf-8",
    )
    sample = tmp_path / "site/site-visit-00000/undefended"
    sample.mkdir(parents=True)
    (sample / "sample.json").write_text(
        json.dumps(
            {
                "state": "captured",
                "views": [{"id": "direct-quic", "valid": True}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="cannot calculate required metrics"):
        create_report(tmp_path)


def _record(defense: str, wire_bytes: int) -> dict:
    ratio = 1 if defense == "undefended" else 2
    return {
        "sample": f"site/site-visit-00000/{defense}",
        "workload": "site",
        "repetition": 0,
        "defense": defense,
        "state": "captured",
        "eligible": True,
        "wire_bytes": wire_bytes,
        "wire_bytes_outgoing": wire_bytes // 2,
        "wire_bytes_incoming": wire_bytes // 2,
        "wire_packets": 10,
        "wire_packets_outgoing": 5,
        "wire_packets_incoming": 5,
        "direct_byte_ratio_vs_baseline": ratio,
        "wire_byte_overhead_ratio": ratio - 1,
        "application_delay_seconds": 0 if defense == "undefended" else 0.1,
        "trace_duration_seconds": 0.5 if defense == "undefended" else 0.8,
        "defense_tail_seconds": 0.1,
        "defense_tail_bytes": 100,
        "defense_tail_packets": 1,
        "fidelity_realization_errors": {},
        "missed_slots": 0,
    }
