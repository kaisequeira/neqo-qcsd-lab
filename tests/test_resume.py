import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import qcsd_lab.campaign as campaign_module
import qcsd_lab.dataset as dataset_module
import qcsd_lab.plotting as plotting_module
import qcsd_lab.report as report_module
from qcsd_lab.campaign import (
    _campaign_receipt,
    _checkpoint,
    _dataset_card,
    collect_campaign,
    load_campaign,
    plan_campaign,
)
from qcsd_lab.util import atomic_json, sha256_file, write_checksums


def _configuration(tmp_path: Path) -> Path:
    workloads = tmp_path / "workloads"
    workloads.mkdir()
    (workloads / "site.json").write_text(
        json.dumps(
            {
                "header_policy": {},
                "resources": [
                    {
                        "id": 0,
                        "url": "https://example.test/",
                        "headers": [],
                        "depends_on": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    path = tmp_path / "campaign.yml"
    path.write_text(
        "name: resume-test\nseed: 8\nqcsd_profile: live\n"
        "workloads:\n  source: controlled\n  reviewed: false\n"
        "  monitored:\n    site: 1\n  unmonitored: {}\n"
        "limits:\n  per_origin_cooldown_seconds: 0\n  inter_sample_seconds: 0\n"
        "defenses:\n  - name: opaque\n    kind: none\n    baseline: true\n",
        encoding="utf-8",
    )
    return path


def _root(path: Path, result: Path):
    campaign = load_campaign(path, capture="direct")
    visits, samples, splits = plan_campaign(campaign)
    receipt = _campaign_receipt(campaign, visits, datetime.now(timezone.utc))
    result.mkdir()
    atomic_json(result / "splits.json", splits)
    atomic_json(result / "dataset.json", _dataset_card(campaign, receipt, "collecting"))
    _checkpoint(result, receipt, samples)
    return campaign, receipt, samples


def _successful_attempt(attempt: Path, *args, **kwargs):
    attempt.mkdir(parents=True)
    for name in ("captures", "traces", "neqo"):
        (attempt / name).mkdir()
    capture = attempt / "captures/fake.pcapng"
    trace = attempt / "traces/fake.csv"
    capture.write_bytes(b"accepted-capture")
    trace.write_text(
        "relative_time_ns,direction,length_bytes,signed_length_bytes\n0,outgoing,10,10\n",
        encoding="utf-8",
    )
    atomic_json(
        attempt / "neqo/run.json",
        {
            "responses": [
                {
                    "status": 200,
                    "bytes": 1,
                    "body_sha256": "x",
                }
            ],
            "resolved_configuration": {"defense": "opaque"},
        },
    )
    view = {
        "id": "direct-quic",
        "kind": "direct-quic",
        "interface": "eth0",
        "primary": True,
        "link_type": "Ethernet",
        "length_basis": "frame.len",
        "capture_path": "captures/fake.pcapng",
        "trace_path": "traces/fake.csv",
        "capture_sha256": sha256_file(capture),
        "trace_sha256": sha256_file(trace),
        "pcapng_bytes": capture.stat().st_size,
        "packet_count": 1,
        "truncated": False,
        "valid": True,
    }
    value = {
        "success": True,
        "runner_returncode": 0,
        "views": [view],
        "offloads": [],
        "auxiliary_failures": [],
    }
    atomic_json(attempt / "attempt.json", value)
    return value


def _avoid_analysis(monkeypatch):
    monkeypatch.setattr(plotting_module, "plot_run", lambda *_args, **_kwargs: [])

    def report(root):
        (root / "metrics.csv").write_text("sample\n", encoding="utf-8")
        (root / "report.html").write_text("<!doctype html>", encoding="utf-8")
        return root / "metrics.csv", root / "report.html"

    def projection(root):
        atomic_json(root / "projection.json", {"measured": {}})
        return root / "projection.json"

    monkeypatch.setattr(report_module, "create_report", report)
    monkeypatch.setattr(dataset_module, "write_projection", projection)


def test_resume_recovers_running_state_and_skips_accepted_sample(tmp_path, monkeypatch):
    path = _configuration(tmp_path)
    root = tmp_path / "result"
    _campaign, receipt, samples = _root(path, root)
    sample = samples[0]
    sample.update(state="running", attempts=1)
    stale = root / sample["path"] / "attempts/attempt-001"
    stale.mkdir(parents=True)
    (stale / "interrupted.log").write_text("interrupted", encoding="utf-8")
    _checkpoint(root, receipt, samples)
    calls = []

    def successful(*args, **kwargs):
        calls.append(args[0])
        return _successful_attempt(*args, **kwargs)

    monkeypatch.setattr(campaign_module, "_collect_attempt", successful)
    _avoid_analysis(monkeypatch)
    assert collect_campaign(path, tmp_path, capture="direct", resume=root) == root
    assert calls == [root / sample["path"] / "attempts/attempt-002"]
    accepted = root / sample["path"] / "captures/fake.pcapng"
    before = sha256_file(accepted)
    monkeypatch.setattr(
        campaign_module,
        "_collect_attempt",
        lambda *_args, **_kwargs: pytest.fail("accepted sample was recollected"),
    )
    assert collect_campaign(path, tmp_path, capture="direct", resume=root) == root
    assert sha256_file(accepted) == before
    index = [json.loads(line) for line in (root / "samples.jsonl").read_text().splitlines()]
    assert len(index) == 1 and index[0]["attempts"] == 2


def test_failed_attempt_retries_with_same_seed(tmp_path, monkeypatch):
    path = _configuration(tmp_path)
    root = tmp_path / "result"
    _campaign, _receipt, samples = _root(path, root)
    observed = []

    def fail_then_succeed(attempt, manifest, defense, seed, campaign):
        observed.append(seed)
        if len(observed) == 1:
            attempt.mkdir(parents=True)
            value = {"success": False, "failure": {"stage": "capture"}}
            atomic_json(attempt / "attempt.json", value)
            return value
        return _successful_attempt(attempt, manifest, defense, seed, campaign)

    monkeypatch.setattr(campaign_module, "_collect_attempt", fail_then_succeed)
    _avoid_analysis(monkeypatch)
    collect_campaign(path, tmp_path, capture="direct", resume=root)
    assert observed == [samples[0]["seed"], samples[0]["seed"]]
    assert (root / samples[0]["path"] / "attempts/attempt-001/attempt.json").is_file()


def test_resume_rejects_provenance_mismatch(tmp_path):
    path = _configuration(tmp_path)
    root = tmp_path / "result"
    root.mkdir()
    atomic_json(root / "campaign.json", {"input_digest": "wrong"})
    with pytest.raises(ValueError, match="provenance mismatch"):
        collect_campaign(path, tmp_path, capture="direct", resume=root)


def test_checksum_sealing_is_idempotent(tmp_path):
    (tmp_path / "a").write_bytes(b"a")
    write_checksums(tmp_path, [tmp_path / "a"])
    first = (tmp_path / "SHA256SUMS").read_bytes()
    write_checksums(tmp_path, [tmp_path / "a"])
    assert (tmp_path / "SHA256SUMS").read_bytes() == first
