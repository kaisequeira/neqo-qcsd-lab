import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import qcsd_lab.campaign as campaign_module
import qcsd_lab.dataset as dataset_module
import qcsd_lab.parameters as parameters_module
import qcsd_lab.plotting as plotting_module
import qcsd_lab.report as report_module
from qcsd_lab.campaign import (
    _campaign_receipt,
    _checkpoint,
    _dataset_card,
    collect_campaign,
    create_splits,
    load_campaign,
    plan_campaign,
    stable_digest,
)
from qcsd_lab.util import atomic_json, sha256_file, write_checksums


def _configuration(tmp_path: Path, *, reactive: bool = False) -> Path:
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
    if reactive:
        parameter = tmp_path / "config/defense-params/wtfpad.json"
        parameter.parent.mkdir(parents=True)
        atomic_json(
            parameter,
            {
                "schema_version": 2,
                "adaptation": "qcsd-client-only",
                "paper_equivalent": False,
                "fitting": {},
                "outgoing": {},
                "incoming": {},
            },
        )
        atomic_json(
            parameter.with_suffix(".json.provenance.json"),
            {
                "schema_version": 1,
                "generator": "test-fixture",
                "input_policy": "reviewed-engineering-fixture",
                "unsealed_engineering_opt_in": True,
                "parameter_file": {
                    "path": parameter.name,
                    "sha256": sha256_file(parameter),
                },
                "inputs": {},
            },
        )
        defense = (
            "  - name: adaptive\n"
            "    kind: wtf_pad\n"
            "    baseline: true\n"
            f"    parameters: {parameter.relative_to(tmp_path)}\n"
            "    allow_reviewed_fixture: true\n"
        )
    else:
        defense = "  - name: opaque\n    kind: none\n    baseline: true\n"
    path = tmp_path / "campaign.yml"
    path.write_text(
        "name: resume-test\nseed: 8\nqcsd_profile: live\n"
        "workloads:\n  source: controlled\n  reviewed: false\n"
        "  monitored:\n    site: 1\n  unmonitored: {}\n"
        "limits:\n  per_origin_cooldown_seconds: 0\n  inter_sample_seconds: 0\n"
        "defenses:\n" + defense,
        encoding="utf-8",
    )
    return path


def _root(path: Path, result: Path):
    campaign = load_campaign(path)
    visits, samples, splits = plan_campaign(campaign)
    receipt = _campaign_receipt(campaign, visits, datetime.now(timezone.utc))
    result.mkdir()
    atomic_json(result / "splits.json", splits)
    atomic_json(result / "dataset.json", _dataset_card(campaign, receipt, "collecting"))
    _checkpoint(result, receipt, samples)
    return campaign, receipt, samples


def _successful_attempt(
    attempt: Path,
    manifest: Path,
    workload_id: str,
    defense,
    seed: int,
    campaign,
):
    attempt.mkdir(parents=True)
    for name in ("captures", "traces", "neqo"):
        (attempt / name).mkdir()
    capture = attempt / "captures/direct-quic.pcapng"
    trace = attempt / "traces/direct-quic.csv"
    capture.write_bytes(b"accepted-capture")
    trace.write_text(
        "relative_time_ns,direction,length_bytes,signed_length_bytes\n0,outgoing,46,46\n",
        encoding="utf-8",
    )
    (attempt / "neqo/packets.csv").write_text(
        "direction,monotonic_us,connection,observed_udp_length,"
        "scheduled_target,satisfaction,slot_id\n"
        "outgoing,1000,0,4,,unshaped,\n",
        encoding="utf-8",
    )
    defense_parameters = None
    if defense.parameters_path is not None:
        campaign_module._copy_defense_parameter_artifacts(defense, attempt / "neqo")
        defense_parameters = {
            "kind": defense.kind,
            "path": str(defense.parameters_path),
            "sha256": defense.parameters_sha256,
        }
    if defense.kind == "wtf_pad":
        (attempt / "neqo/schedule.csv").write_text(
            "direction,satisfaction,miss_reason\n",
            encoding="utf-8",
        )
    atomic_json(
        attempt / "neqo/run.json",
        {
            "completion_status": "complete",
            "endpoints": [
                {
                    "id": 0,
                    "local_address": "192.0.2.1:50000",
                    "remote_address": "198.51.100.1:443",
                }
            ],
            "responses": [
                {
                    "resource_id": 0,
                    "status": 200,
                    "bytes": 1,
                    "body_sha256": "x",
                    "complete": True,
                    "outcome": "succeeded",
                }
            ],
            "resolved_configuration": {
                "defense": {
                    "kind": defense.kind,
                    **(
                        {"workload_id": workload_id}
                        if defense.kind in {"traffic_morphing", "walkie_talkie"}
                        else {}
                    ),
                },
                "max_udp_payload_size": campaign.udp_payload_ceiling,
            },
            "defense_parameters": defense_parameters,
            "defense_diagnostics": (
                {
                    "padding_events": 0,
                    "padding_event_guard_triggered": False,
                    "wtf_pad_incoming_desired_bytes": 0,
                    "wtf_pad_incoming_requested_bytes": 0,
                    "wtf_pad_incoming_received_bytes": 0,
                    "wtf_pad_incoming_shortfall_bytes": 0,
                    "wtf_pad_incoming_size_error_bytes": 0,
                    "wtf_pad_incoming_observed_events": 0,
                    "wtf_pad_incoming_lag_us_total": 0,
                    "wtf_pad_incoming_lag_us_max": 0,
                    "wtf_pad_silent_to_burst": 0,
                    "wtf_pad_burst_to_gap": 0,
                    "wtf_pad_gap_to_burst": 0,
                    "wtf_pad_burst_to_silent": 0,
                    "suppressed_cover_feedback": 0,
                }
                if defense.kind == "wtf_pad"
                else None
            ),
            "seed": seed,
            "workload_hash_sha256": sha256_file(manifest),
        },
    )
    view = {
        "id": "direct-quic",
        "kind": "direct-quic",
        "interface": "eth0",
        "primary": True,
        "link_type": "Ethernet",
        "length_basis": "frame.len",
        "capture_path": "captures/direct-quic.pcapng",
        "trace_path": "traces/direct-quic.csv",
        "capture_sha256": sha256_file(capture),
        "trace_sha256": sha256_file(trace),
        "pcapng_bytes": capture.stat().st_size,
        "packet_count": 1,
        "truncated": False,
        "capture_active_through_settle": True,
        "udp_payload_ceiling_evidence": {
            "configured_udp_payload_ceiling": campaign.udp_payload_ceiling,
            "observed_udp_payload_max": 4,
            "packets_with_udp_payload_length": 1,
            "packets_without_udp_payload_length": 0,
            "oversized_udp_payload_packets": 0,
            "runner_resolved_udp_payload_ceiling": campaign.udp_payload_ceiling,
            "runner_binding_valid": True,
            "valid": True,
        },
        "capture_offload_evidence": {
            "interface": "eth0",
            "requested": {"gro": "off", "gso": "off", "tso": "off", "uso": "off"},
            "query_returncodes": {"before": 0, "after": 0},
            "change_returncodes": {"gro": 0, "gso": 0, "tso": 0, "uso": 0},
            "before_state": {"gro": "on", "gso": "on", "tso": "on", "uso": "on"},
            "after_state": {"gro": "off", "gso": "off", "tso": "off", "uso": "off"},
            "before_sha256": "0" * 64,
            "after_sha256": "1" * 64,
            "verified": True,
        },
        "valid": True,
    }
    value = {
        "success": True,
        "runner_returncode": 0,
        "views": [view],
        "offloads": [view["capture_offload_evidence"]],
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


def _seal(root: Path) -> None:
    write_checksums(
        root,
        [path for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS"],
    )


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
    assert collect_campaign(path, tmp_path, resume=root) == root
    assert calls == [root / sample["path"] / "attempts/attempt-002"]
    accepted = root / sample["path"] / "captures/direct-quic.pcapng"
    before = sha256_file(accepted)
    monkeypatch.setattr(
        campaign_module,
        "_collect_attempt",
        lambda *_args, **_kwargs: pytest.fail("accepted sample was recollected"),
    )
    assert collect_campaign(path, tmp_path, resume=root) == root
    assert sha256_file(accepted) == before
    index = [json.loads(line) for line in (root / "samples.jsonl").read_text().splitlines()]
    assert len(index) == 1 and index[0]["attempts"] == 2


@pytest.mark.parametrize(
    "target",
    ["requested", "query-returncode", "change-returncode"],
)
def test_resume_recomputes_sealed_offload_evidence(tmp_path, monkeypatch, target):
    path = _configuration(tmp_path)
    root = tmp_path / "result"
    _campaign, _receipt, samples = _root(path, root)
    monkeypatch.setattr(campaign_module, "_collect_attempt", _successful_attempt)
    _avoid_analysis(monkeypatch)
    collect_campaign(path, tmp_path, resume=root)

    metadata_path = root / samples[0]["path"] / "sample.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    offload = metadata["views"][0]["capture_offload_evidence"]
    if target == "requested":
        offload["requested"]["gro"] = "on"
    elif target == "query-returncode":
        offload["query_returncodes"]["after"] = 1
    else:
        offload["change_returncodes"]["gso"] = 1
    metadata["capture_offloads"] = [offload]
    atomic_json(metadata_path, metadata)
    _seal(root)

    monkeypatch.setattr(
        campaign_module,
        "_collect_attempt",
        lambda *_args, **_kwargs: pytest.fail("tampered sample was recollected"),
    )
    with pytest.raises(ValueError, match="capture environment binding is invalid"):
        collect_campaign(path, tmp_path, resume=root)


def test_failed_attempt_retries_with_same_seed(tmp_path, monkeypatch):
    path = _configuration(tmp_path)
    root = tmp_path / "result"
    _campaign, _receipt, samples = _root(path, root)
    observed = []

    def fail_then_succeed(
        attempt,
        manifest,
        workload_id,
        defense,
        seed,
        campaign,
    ):
        observed.append(seed)
        if len(observed) == 1:
            attempt.mkdir(parents=True)
            value = {"success": False, "failure": {"stage": "capture"}}
            atomic_json(attempt / "attempt.json", value)
            return value
        return _successful_attempt(
            attempt,
            manifest,
            workload_id,
            defense,
            seed,
            campaign,
        )

    monkeypatch.setattr(campaign_module, "_collect_attempt", fail_then_succeed)
    _avoid_analysis(monkeypatch)
    collect_campaign(path, tmp_path, resume=root)
    assert observed == [samples[0]["seed"], samples[0]["seed"]]
    assert (root / samples[0]["path"] / "attempts/attempt-001/attempt.json").is_file()


def test_resume_rejects_provenance_mismatch(tmp_path):
    path = _configuration(tmp_path)
    root = tmp_path / "result"
    root.mkdir()
    atomic_json(root / "campaign.json", {"input_digest": "wrong"})
    with pytest.raises(ValueError, match="provenance mismatch"):
        collect_campaign(path, tmp_path, resume=root)


def test_resume_provenance_rejection_preserves_verified_seal(tmp_path):
    path = _configuration(tmp_path)
    root = tmp_path / "result"
    root.mkdir()
    atomic_json(root / "campaign.json", {"input_digest": "wrong"})
    _seal(root)
    seal = root / "SHA256SUMS"
    before = seal.read_bytes()

    with pytest.raises(ValueError, match="provenance mismatch"):
        collect_campaign(path, tmp_path, resume=root)

    assert seal.read_bytes() == before


@pytest.mark.parametrize(
    ("artifact", "message"),
    [
        (
            "defense-parameters.json",
            "provenance SHA-256 does not match",
        ),
        (
            "defense-parameters.provenance.json",
            "parameter provenance hash mismatch",
        ),
        ("run.json", "parameter run binding mismatch"),
    ],
)
def test_resume_rejects_tampered_reactive_parameter_artifacts(
    tmp_path, monkeypatch, artifact, message
):
    monkeypatch.setattr(parameters_module, "LAB_ROOT", tmp_path)
    path = _configuration(tmp_path, reactive=True)
    root = tmp_path / "result"
    _campaign, _receipt, samples = _root(path, root)
    monkeypatch.setattr(campaign_module, "_collect_attempt", _successful_attempt)
    _avoid_analysis(monkeypatch)
    collect_campaign(path, tmp_path, resume=root)

    target = root / samples[0]["path"] / "neqo" / artifact
    if artifact == "run.json":
        run_data = json.loads(target.read_text(encoding="utf-8"))
        run_data["defense_parameters"]["sha256"] = "0" * 64
        atomic_json(target, run_data)
    else:
        target.write_bytes(target.read_bytes() + b"\n")
    _seal(root)
    monkeypatch.setattr(
        campaign_module,
        "_collect_attempt",
        lambda *_args, **_kwargs: pytest.fail("tampered sample was recollected"),
    )

    with pytest.raises(ValueError, match=message):
        collect_campaign(path, tmp_path, resume=root)


def test_resume_verifies_existing_seal_before_rewriting_canonical_files(tmp_path, monkeypatch):
    path = _configuration(tmp_path)
    root = tmp_path / "result"
    _campaign, _receipt, samples = _root(path, root)
    monkeypatch.setattr(campaign_module, "_collect_attempt", _successful_attempt)
    _avoid_analysis(monkeypatch)
    collect_campaign(path, tmp_path, resume=root)
    canonical = {
        name: (root / name).read_bytes()
        for name in ("campaign.json", "dataset.json", "samples.jsonl", "SHA256SUMS")
    }

    run_path = root / samples[0]["path"] / "neqo/run.json"
    run_data = json.loads(run_path.read_text(encoding="utf-8"))
    run_data["responses"][0]["body_sha256"] = "tampered"
    atomic_json(run_path, run_data)

    with pytest.raises(ValueError, match="checksum mismatch"):
        collect_campaign(path, tmp_path, resume=root)
    assert {name: (root / name).read_bytes() for name in canonical} == canonical


def test_verified_seal_is_retired_before_resume_mutates_the_dataset(tmp_path, monkeypatch):
    path = _configuration(tmp_path)
    root = tmp_path / "result"
    _campaign, _receipt, _samples = _root(path, root)
    monkeypatch.setattr(campaign_module, "_collect_attempt", _successful_attempt)
    _avoid_analysis(monkeypatch)
    collect_campaign(path, tmp_path, resume=root)
    assert (root / "SHA256SUMS").is_file()

    original = campaign_module._materialize_resolved_workloads

    def interrupt(*_args):
        raise RuntimeError("interrupted resume")

    monkeypatch.setattr(campaign_module, "_materialize_resolved_workloads", interrupt)
    with pytest.raises(RuntimeError, match="interrupted resume"):
        collect_campaign(path, tmp_path, resume=root)
    assert not (root / "SHA256SUMS").exists()

    monkeypatch.setattr(campaign_module, "_materialize_resolved_workloads", original)
    assert collect_campaign(path, tmp_path, resume=root) == root
    assert (root / "SHA256SUMS").is_file()


def test_resume_revalidates_full_nonreactive_configuration_after_valid_reseal(
    tmp_path, monkeypatch
):
    path = _configuration(tmp_path)
    root = tmp_path / "result"
    _campaign, _receipt, samples = _root(path, root)
    monkeypatch.setattr(campaign_module, "_collect_attempt", _successful_attempt)
    _avoid_analysis(monkeypatch)
    collect_campaign(path, tmp_path, resume=root)

    run_path = root / samples[0]["path"] / "neqo/run.json"
    run_data = json.loads(run_path.read_text(encoding="utf-8"))
    run_data["resolved_configuration"]["control_interval_us"] = 999_999
    atomic_json(run_path, run_data)
    _seal(root)
    canonical = {
        name: (root / name).read_bytes()
        for name in ("campaign.json", "dataset.json", "samples.jsonl")
    }

    with pytest.raises(ValueError, match="run binding is invalid"):
        collect_campaign(path, tmp_path, resume=root)
    assert {name: (root / name).read_bytes() for name in canonical} == canonical
    assert (root / "SHA256SUMS").is_file()


def test_resume_rejects_coordinated_split_group_laundering(tmp_path, monkeypatch):
    path = _configuration(tmp_path)
    root = tmp_path / "result"
    _campaign, _receipt, samples = _root(path, root)
    monkeypatch.setattr(campaign_module, "_collect_attempt", _successful_attempt)
    _avoid_analysis(monkeypatch)
    collect_campaign(path, tmp_path, resume=root)

    campaign_path = root / "campaign.json"
    samples_path = root / "samples.jsonl"
    metadata_path = root / samples[0]["path"] / "sample.json"
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    [visit] = campaign["visits"]
    [sample] = [json.loads(line) for line in samples_path.read_text().splitlines()]
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    replacement_split_group_id = stable_digest("laundered-resume-split-group")
    visit["split_group_id"] = replacement_split_group_id
    replacement_splits = create_splits([visit], campaign["configuration"]["seed"])
    replacement_split = replacement_splits["assignments"][replacement_split_group_id]
    sample.update(
        split_group_id=replacement_split_group_id,
        split=replacement_split,
    )
    metadata.update(
        split_group_id=replacement_split_group_id,
        split=replacement_split,
    )
    atomic_json(campaign_path, campaign)
    atomic_json(root / "splits.json", replacement_splits)
    samples_path.write_text(json.dumps(sample, sort_keys=True) + "\n", encoding="utf-8")
    atomic_json(metadata_path, metadata)
    dataset_module.write_classifier_indexes(root)
    _seal(root)

    with pytest.raises(ValueError, match="run binding is invalid"):
        collect_campaign(path, tmp_path, resume=root)


def test_checksum_sealing_is_idempotent(tmp_path):
    (tmp_path / "a").write_bytes(b"a")
    write_checksums(tmp_path, [tmp_path / "a"])
    first = (tmp_path / "SHA256SUMS").read_bytes()
    write_checksums(tmp_path, [tmp_path / "a"])
    assert (tmp_path / "SHA256SUMS").read_bytes() == first
