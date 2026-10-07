"""Adversarial checks for the prospective cross-process formal launch frame.

The inherited fixture controls expensive scientific and Git validation, while
the public issuer, typed frame, file/mode/member fence, and authority binding
run as production code. These fixtures confer no capture or formal credit.
"""
from __future__ import annotations

import json
from contextlib import nullcontext
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_parallel_capture as parallel
from qcsd_lab import rapid_rolling_schedule as schedule
from tests.test_rapid_parallel_release_preparation import release_context


@pytest.fixture
def issued(release_context):
    fixture = release_context
    output = fixture.spec.execution_root / "results/fast-certificate-boundary"
    output.mkdir()

    def authenticated_source(value):
        # The synthetic source is not a Git checkout. Keep that external
        # prerequisite explicit; the actual public issuer and fences remain.
        assert value == fixture.value

    fixture.monkeypatch.setattr(parallel, "host_source", authenticated_source)
    # The inherited schedule is a controlled fixture, not a published rolling
    # schedule. Exercise the production issuer and its exact saved mount list.
    fixture.monkeypatch.setattr(schedule, "mount_roots",
        lambda reference, *, _context=None: [fixture.spec.data_root,
            fixture.spec.execution_root])
    transport = parallel.formal_entry_inputs(fixture.path, output)
    digest = transport["fast_launch_certificate_sha256"]
    certificate = output / "fast-launch-certificate.json"
    assert transport["fast_launch_certificate_path"] == str(certificate)
    assert digest == parallel.sha(certificate.read_bytes())
    assert fixture.calls.count("audit") == 1
    return SimpleNamespace(fixture=fixture, output=output, digest=digest,
        certificate=certificate, transport=transport)


def test_public_issuer_reopens_exact_two_lanes_without_new_credit(issued):
    value, facts, frame = formal.reopen_fast_certificate(
        issued.fixture.path, issued.output, issued.digest)
    assert value == issued.fixture.value
    assert [fact[5].campaign_name for fact in facts] == [
        lane.campaign_name for lane in issued.fixture.lanes]
    assert len(frame["worker_inputs"]) == 2
    assert frame["formal_accepted_trace_count"] == 0
    assert frame["scientific_credit"] is False
    assert not (issued.output / "batch-launch.json").exists()


@pytest.mark.parametrize("changed", ["wrong-digest", "missing-certificate", "other-output"])
def test_certificate_digest_and_output_root_are_not_interchangeable(issued, changed):
    output = issued.output
    digest = issued.digest
    if changed == "wrong-digest":
        digest = "0" * 64
    elif changed == "missing-certificate":
        issued.certificate.unlink()
    else:
        output = issued.output.with_name("unrelated-flight")
        output.mkdir()
        shutil.copyfile(issued.certificate, output / issued.certificate.name)
    with pytest.raises((ValueError, FileNotFoundError)):
        formal.reopen_fast_certificate(issued.fixture.path, output, digest)


@pytest.mark.parametrize("name", ["source_file", "native_file", "canonical", "client", "settings", "lane_intent"])
def test_issued_frame_rejects_postissue_byte_mutation(issued, name):
    fixture = issued.fixture
    if name == "client":
        path = fixture.spec.client_binary
    elif name == "settings":
        path = fixture.spec.execution_root / next(iter(lanes.TRAFFIC_FILES.values()))[0]
    elif name == "lane_intent":
        path = fixture.facts[1][2]
    else:
        path = getattr(fixture, name)
    path.write_bytes(path.read_bytes() + b"\nchanged after issuance")
    with pytest.raises(ValueError):
        formal.reopen_fast_certificate(fixture.path, issued.output, issued.digest)


@pytest.mark.parametrize("change", ["source-member", "runtime-member", "canary-member"])
def test_issued_frame_rejects_postissue_tree_membership(issued, change):
    fixture = issued.fixture
    directory = {
        "source-member": fixture.source_file.parent,
        "runtime-member": fixture.canonical.parent / "image-context/source",
        "canary-member": fixture.canary_raw.parent,
    }[change]
    (directory / "unexpected-member.raw").write_bytes(b"not present when certificate was issued")
    with pytest.raises(ValueError):
        formal.reopen_fast_certificate(fixture.path, issued.output, issued.digest)


def test_issued_frame_rejects_changed_authority_image(issued):
    value = json.loads(issued.fixture.path.read_bytes())
    value["runtime"]["collection_image_digest"] = "sha256:" + "e" * 64
    issued.fixture.path.write_bytes(lanes._json(value))
    with pytest.raises(ValueError):
        formal.reopen_fast_certificate(issued.fixture.path, issued.output, issued.digest)


@pytest.mark.parametrize("change", ["other-worker", "wrong-slot", "foreign-mount", "foreign-environment"])
def test_recomputed_digest_cannot_launder_forged_worker_transport(issued, change):
    frame = json.loads(issued.certificate.read_bytes())
    if change == "other-worker":
        frame["worker_inputs"][1] = frame["worker_inputs"][0]
    elif change == "wrong-slot":
        frame["facts"][1][5]["block"] += 1
    elif change == "foreign-mount":
        frame["worker_inputs"][0]["mount_roots"].append("/tmp/unbound-source")
    else:
        frame["worker_inputs"][0]["environment"]["QCSD_RAPID_ROLLING_LAUNCH_INPUT"] = "{}"
    issued.certificate.write_bytes(lanes._json(frame))
    forged_digest = parallel.sha(issued.certificate.read_bytes())
    with pytest.raises(ValueError):
        formal.reopen_fast_certificate(issued.fixture.path, issued.output, forged_digest)


def test_half_supplied_certificate_environment_is_never_a_historical_fallback(issued):
    fixture = issued.fixture
    fixture.monkeypatch.setenv("QCSD_RAPID_FAST_CERTIFICATE_PATH", str(issued.certificate))
    fixture.monkeypatch.delenv("QCSD_RAPID_FAST_CERTIFICATE_SHA256", raising=False)
    with pytest.raises(ValueError):
        formal._active_fast_certificate(fixture.path)
    fixture.monkeypatch.setenv("QCSD_RAPID_FAST_CERTIFICATE_SHA256", issued.digest)
    assert formal._active_fast_certificate(fixture.path)[0] == fixture.value
    issued.certificate.unlink()
    with pytest.raises((ValueError, FileNotFoundError)):
        formal._active_fast_certificate(fixture.path)


def test_issued_frame_rejects_mode_only_change(issued):
    source_file = issued.fixture.source_file
    before = source_file.stat().st_mode & 0o777
    source_file.chmod(0o600 if before != 0o600 else 0o644)
    assert source_file.stat().st_mode & 0o777 != before
    with pytest.raises(ValueError):
        formal.reopen_fast_certificate(issued.fixture.path, issued.output, issued.digest)


def test_both_private_worker_gates_reopen_the_issued_frame_before_exec(issued):
    fixture = issued.fixture
    monkeypatch = fixture.monkeypatch
    monkeypatch.setenv("QCSD_RAPID_FAST_CERTIFICATE_PATH", str(issued.certificate))
    monkeypatch.setenv("QCSD_RAPID_FAST_CERTIFICATE_SHA256", issued.digest)
    monkeypatch.setattr(parallel, "_gate_read_credentials", lambda: nullcontext())
    monkeypatch.setattr(formal, "_audit", lambda *_args, **_kwargs:
        pytest.fail("installed worker gate replayed the full host audit"))
    executed = []
    monkeypatch.setattr(parallel.os, "execv", lambda command, argv: executed.append((command, argv)))
    authority_sha = parallel.sha(fixture.path.read_bytes())

    for index, lane in enumerate(fixture.lanes):
        gate = issued.output / f"lane-{index+1}/gate"
        gate.mkdir(parents=True, mode=0o700)
        gate.chmod(0o700)
        worker_id = f"{index+1}" * 64
        client_cpu, orchestrator_cpu = ((2, 4), (7, 9))[index]
        monkeypatch.setenv("QCSD_CAPTURE_CLIENT_CPU", str(client_cpu))
        monkeypatch.setenv("QCSD_CAPTURE_ORCHESTRATOR_CPU", str(orchestrator_cpu))
        partition = {"measured_container_id": worker_id, "declared_workers": [
            {"id": "1" * 64, "client_cpu": 2, "orchestrator_cpu": 4},
            {"id": "2" * 64, "client_cpu": 7, "orchestrator_cpu": 9}]}
        parallel.put(gate / "host-partition.json", partition)
        parallel.put(gate / "release.json", {
            "authority_sha256": authority_sha,
            "campaign": "/lab/config/campaigns/" + lane.campaign_name + ".yml",
            "host_partition_sha256": parallel.sha((gate / "host-partition.json").read_bytes()),
            "worker_id": worker_id})
        parallel.gate(gate, authority_sha, index, fixture.path)

    assert [argv[-1] for _command, argv in executed] == [
        "/lab/config/campaigns/" + lane.campaign_name + ".yml"
        for lane in fixture.lanes]


def test_final_formal_verifier_still_requires_full_audit(issued):
    def full_audit_required(*_args, **_kwargs):
        raise RuntimeError("full formal verification entered")

    issued.fixture.monkeypatch.setattr(formal, "_audit", full_audit_required)
    with pytest.raises(RuntimeError, match="full formal verification entered"):
        formal.verify_results(issued.fixture.path, issued.output)
