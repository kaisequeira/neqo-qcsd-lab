import json

from qcsd_lab.report import _html_report


def test_report_is_compact_static_and_links_only_observer_artifacts(tmp_path):
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
        (sample / "captures/wireguard-outer.pcapng").write_bytes(b"capture")
        (sample / "traces/wireguard-outer.csv").write_text("trace", encoding="utf-8")
        (sample / "sample.json").write_text(
            json.dumps(
                {
                    "views": [
                        {
                            "id": "wireguard-outer",
                            "valid": True,
                            "capture_path": "captures/wireguard-outer.pcapng",
                            "trace_path": "traces/wireguard-outer.csv",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
    (tmp_path / "dataset-summary.svg").write_text("<svg/>", encoding="utf-8")

    report = _html_report(tmp_path, records)
    assert "eligible paired visits" in report
    assert "Defense coverage" in report
    assert "Samples and observer artifacts" in report
    assert "wireguard-outer trace" in report
    assert "wireguard-outer pcap" in report
    assert "normalized timing, direction, and length" in report
    assert "qlog" in report  # appears only in the prohibited-feature explanation
    assert "endpoint.sqlog" not in report
    assert "schedule.csv" not in report
    assert "<script" not in report
    assert "<select" not in report
    assert "box-shadow" not in report


def _record(defense: str, observed_bytes: int) -> dict:
    return {
        "sample": f"site/site-visit-00000/{defense}",
        "workload": "site",
        "repetition": 0,
        "defense": defense,
        "state": "captured",
        "eligible": True,
        "observed_bytes": observed_bytes,
        "observed_overhead_vs_baseline_ratio": 1 if defense == "undefended" else 2,
        "missed_slots": 0,
    }
