import csv
import hashlib
import json
from pathlib import Path

import pytest

import qcsd_lab.analysis as analysis
import qcsd_lab.orchestrator as orchestrator
from qcsd_lab.capture import ObserverPacket
from qcsd_lab.experiment import (
    accept_sample,
    checkpoint_experiment,
    finalize_experiment,
    initialize_experiment,
    transition_sample,
)
from qcsd_lab.verification import seal_result, verify_result


def test_analyze_verifies_then_replaces_derived_with_deterministic_svg_report(
    tmp_path,
    monkeypatch,
):
    root = _result(tmp_path, front_state="accepted")
    verified = []
    monkeypatch.setattr(analysis, "_verify_result", lambda path: verified.append(path))
    monkeypatch.setattr(analysis, "_trace_for_sample", _trace)
    (root / "derived").mkdir()
    (root / "derived/obsolete.txt").write_text("old", encoding="utf-8")
    evidence_before = _authoritative_digest(root)
    exchanges = []
    exchange_directories = analysis._exchange_directories

    def record_exchange(left, right):
        exchanges.append((left, right))
        exchange_directories(left, right)

    monkeypatch.setattr(analysis, "_exchange_directories", record_exchange)

    generated = analysis.analyze_result(root)

    assert verified == [root.resolve()]
    assert len(exchanges) == 1
    assert exchanges[0][1] == root / "derived"
    assert generated.summary == root / "derived/summary.csv"
    assert generated.report == root / "derived/report.html"
    assert not (root / "derived/obsolete.txt").exists()
    assert not list((root / "derived").rglob("*.pdf"))
    assert sorted(path.name for path in generated.plots) == [
        "aggregate-latency.svg",
        "aggregate-overhead.svg",
        "trace-comparison.svg",
    ]
    with generated.summary.open(newline="", encoding="utf-8") as source:
        rows = {row["defense"]: row for row in csv.DictReader(source)}
    assert float(rows["undefended"]["wire_byte_overhead_ratio"]) == 0
    assert float(rows["front"]["wire_byte_overhead_ratio"]) == 1
    report = generated.report.read_text(encoding="utf-8")
    assert report.count("<svg") == 3
    assert "20260719T141832Z" not in report
    assert "trace-comparison.pdf" not in report
    assert "Incoming actions" in report
    assert "Defense tail" in report
    assert "../samples/site/as-defined/visit-000/front/capture.pcapng" in report
    assert _authoritative_digest(root) == evidence_before

    first = _derived_bytes(root)
    analysis.analyze_result(root)
    assert _derived_bytes(root) == first
    assert _authoritative_digest(root) == evidence_before


def test_failed_generation_preserves_previous_derived_tree(tmp_path, monkeypatch):
    root = _result(tmp_path, front_state="accepted")
    monkeypatch.setattr(analysis, "_verify_result", lambda _path: None)
    monkeypatch.setattr(analysis, "_trace_for_sample", _trace)
    (root / "derived").mkdir()
    (root / "derived/previous.txt").write_text("complete", encoding="utf-8")
    monkeypatch.setattr(
        analysis.plotting,
        "plot_aggregate_latency",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("plot failed")),
    )

    with pytest.raises(RuntimeError, match="plot failed"):
        analysis.analyze_result(root)

    assert (root / "derived/previous.txt").read_text(encoding="utf-8") == "complete"
    assert not list(root.parent.glob(f".{root.name}-derived-stage-*"))
    assert not list(root.parent.glob(f".{root.name}-derived-old-*"))


def test_incomplete_pair_is_reported_but_not_plotted(tmp_path, monkeypatch):
    root = _result(tmp_path, front_state="failed")
    monkeypatch.setattr(analysis, "_verify_result", lambda _path: None)
    monkeypatch.setattr(analysis, "_trace_for_sample", _trace)

    result = analysis.analyze_result(root)

    assert sorted(path.name for path in result.plots) == [
        "aggregate-latency.svg",
        "aggregate-overhead.svg",
    ]
    report = result.report.read_text(encoding="utf-8")
    assert "Incomplete or ineligible paired visits" in report
    assert "front" in report
    with result.summary.open(newline="", encoding="utf-8") as source:
        rows = list(csv.DictReader(source))
    assert [row["state"] for row in rows] == ["accepted", "failed"]
    assert rows[1]["wire_bytes"] == ""


def test_analysis_stops_before_reading_samples_when_verification_fails(tmp_path, monkeypatch):
    root = _result(tmp_path, front_state="accepted")
    monkeypatch.setattr(
        analysis,
        "_verify_result",
        lambda _path: (_ for _ in ()).throw(ValueError("checksum mismatch")),
    )
    monkeypatch.setattr(
        analysis,
        "_load_experiment",
        lambda _path: (_ for _ in ()).throw(AssertionError("must not load")),
    )

    with pytest.raises(ValueError, match="checksum mismatch"):
        analysis.analyze_result(root)

    assert not (root / "derived").exists()


def test_analysis_integrates_with_real_sealed_result_verification(tmp_path, monkeypatch):
    root = _sealed_result(tmp_path)
    monkeypatch.setattr(analysis, "_trace_for_sample", _trace)
    seal_before = (root / "evidence.sha256").read_bytes()

    result = analysis.analyze_result(root)

    assert result.report.is_file()
    assert verify_result(root).experiment["status"] == "complete"
    assert (root / "evidence.sha256").read_bytes() == seal_before


def test_analysis_uses_runtime_identity_for_custom_defense_alias(tmp_path, monkeypatch):
    root = _result(tmp_path, front_state="accepted", front_name="front-experiment")
    monkeypatch.setattr(analysis, "_verify_result", lambda _path: None)
    monkeypatch.setattr(analysis, "_trace_for_sample", _trace)
    identities = []
    calculate_metrics = analysis.plotting.calculate_metrics

    def record_identity(sample, defense, *, trace):
        identities.append(defense)
        return calculate_metrics(sample, defense, trace=trace)

    monkeypatch.setattr(analysis.plotting, "calculate_metrics", record_identity)

    result = analysis.analyze_result(root)

    assert identities == ["undefended", "front"]
    with result.summary.open(newline="", encoding="utf-8") as source:
        rows = {row["defense"]: row for row in csv.DictReader(source)}
    assert rows["front"]["defense_variant"] == "front-experiment"
    assert rows["front"]["runtime_kind"] == "front"
    assert "FRONT (front-experiment)" in result.report.read_text(encoding="utf-8")


def _result(tmp_path: Path, *, front_state: str, front_name: str = "front") -> Path:
    root = tmp_path / "result"
    samples = []
    for defense, baseline, state in (
        ("undefended", True, "accepted"),
        (front_name, False, front_state),
    ):
        relative = Path(f"samples/site/as-defined/visit-000/{defense}")
        samples.append(
            {
                "sample_id": defense,
                "workload_id": "site",
                "request_policy": "as-defined",
                "visit": 0,
                "defense": defense,
                "runtime_kind": "none" if baseline else "front",
                "baseline": baseline,
                "seed": 1,
                "path": relative.as_posix(),
                "state": state,
                "attempts": 1,
                "eligible": state == "accepted",
                "failure": None if state == "accepted" else {"reason": "capture failed"},
                "diagnostics": {},
                "artifacts": {},
            }
        )
        if state == "accepted":
            _sample(root / relative, defense)
    root.mkdir(parents=True, exist_ok=True)
    experiment = {
        "schema_version": 1,
        "name": "analysis-test",
        "purpose": "evaluation",
        "status": "incomplete" if front_state != "accepted" else "complete",
        "started_at": "2026-08-06T00:00:00Z",
        "completed_at": "2026-08-06T01:00:00Z",
        "input_digest": "a" * 64,
        "source": {},
        "configuration": {
            "campaign_sha256": "b" * 64,
            "profile": "live",
            "request_policies": ["as-defined"],
            "workloads": ["site"],
            "defenses": ["undefended", "front"],
            "limits": {},
        },
        "execution_order": [item["sample_id"] for item in samples],
        "samples": samples,
        "summary": {
            "planned": 2,
            "accepted": sum(item["state"] == "accepted" for item in samples),
            "failed": sum(item["state"] == "failed" for item in samples),
            "eligible": sum(item["eligible"] for item in samples),
            "passed": front_state == "accepted",
        },
    }
    (root / "experiment.json").write_text(
        json.dumps(experiment, sort_keys=True),
        encoding="utf-8",
    )
    (root / "evidence.sha256").write_text("sealed\n", encoding="utf-8")
    return root


def _sample(path: Path, defense: str) -> None:
    neqo = path / "neqo"
    neqo.mkdir(parents=True)
    (path / "capture.pcapng").write_bytes(defense.encode())
    run = {
        "time_anchor_unix_ns": 1_000_000_000,
        "application_completion_monotonic_ns": 200_000_000,
        "endpoints": [],
        "responses": [{"bytes": 500}],
        "defense_diagnostics": {},
    }
    (neqo / "run.json").write_text(json.dumps(run), encoding="utf-8")
    (neqo / "packets.csv").write_text(
        "observed_udp_length\n100\n120\n",
        encoding="utf-8",
    )
    (neqo / "events.csv").write_text("connection,details\n", encoding="utf-8")
    (neqo / "schedule.csv").write_text(
        "action_time_us,direction,size,satisfaction,observed_size,miss_reason\n"
        "50000,outgoing,100,satisfied,100,\n"
        "70000,incoming,120,satisfied,120,\n",
        encoding="utf-8",
    )


def _sealed_result(tmp_path: Path) -> Path:
    root = tmp_path / "sealed"
    config = tmp_path / "sealed-config"
    (config / "campaigns").mkdir(parents=True)
    (config / "workloads").mkdir()
    (config / "workloads/site.json").write_text(
        '{"resources":[{"id":0,"url":"https://site.test/","type":"Document",'
        '"content_length":64,"data_length":64,"chaff_priority":true,'
        '"known_valid":true,"depends_on":[],"headers":[]}]}\n',
        encoding="utf-8",
    )
    campaign_path = config / "campaigns/campaign.yml"
    campaign_path.write_text(
        "schema: 1\n"
        "name: sealed\n"
        "purpose: smoke\n"
        "seed: 1\n"
        "profile: live\n"
        "workloads:\n  site: 1\n"
        "request_policies:\n  - as-defined\n"
        "defenses:\n  - undefended\n"
        "limits:\n"
        "  timeout_seconds: 1\n"
        "  capture_seconds: 2\n"
        "  max_attempts: 1\n"
        "  per_origin_cooldown_seconds: 0\n"
        "  settle_seconds: 0\n",
        encoding="utf-8",
    )
    source = {"lab_commit": "a" * 40}
    campaign = orchestrator.load_campaign(campaign_path)
    runtime, configuration = orchestrator._materialize_inputs(root, campaign, source)
    planned = orchestrator.plan_campaign(runtime)
    experiment = initialize_experiment(
        root,
        name="sealed",
        purpose="smoke",
        run_id="run-001",
        source=source,
        configuration=configuration,
        samples=planned,
        started_at="2026-08-06T00:00:00+00:00",
    )
    for item in planned:
        transition_sample(experiment, item["sample_id"], "running", increment_attempt=True)
        _sample(root / item["path"], item["defense"])
        accept_sample(root, experiment, item["sample_id"], eligible=True)
    checkpoint_experiment(root, experiment)
    finalize_experiment(
        root,
        experiment,
        status="complete",
        completed_at="2026-08-06T00:01:00+00:00",
    )
    seal_result(root)
    return root


def _trace(sample: Path) -> list[ObserverPacket]:
    multiplier = 1 if sample.name == "undefended" else 2
    return [
        ObserverPacket(1_000_000_000, 0, "outgoing", 100 * multiplier, 100 * multiplier, 92),
        ObserverPacket(
            1_100_000_000,
            100_000_000,
            "incoming",
            120 * multiplier,
            -120 * multiplier,
            112,
        ),
        ObserverPacket(
            1_300_000_000,
            300_000_000,
            "outgoing",
            100 * multiplier,
            100 * multiplier,
            92,
        ),
    ]


def _authoritative_digest(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file() and "derived" not in path.parts
    }


def _derived_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root / "derived").as_posix(): path.read_bytes()
        for path in sorted((root / "derived").rglob("*"))
        if path.is_file()
    }
