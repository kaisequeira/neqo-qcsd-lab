"""Class authority reopens original qualifiers through an actual installation.

Docker output, original admission membership and packet qualification are
synthetic actuators. Source inventories, installation execution records, policy,
class receipts, qualifier bytes and block/image validators are the real paths.
"""
from __future__ import annotations

import copy
import json
import os
import subprocess
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import chaff_qualification as qualification
from qcsd_lab import rapid_capture_control_installation as installation
from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_class_epochs as classes
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_runtime_epochs as runtime_epochs
from qcsd_lab import rapid_site_admission as admission
from qcsd_lab import util
from tests.test_rapid_capture_control_compatibility import sources
from tests.test_rapid_capture_control_installation import installed as make_installation, publish
from tests.test_rapid_formal_parallel import formal_setup, ordinary_setup


def _snapshot(*roots: Path):
    return {str(path): (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_ino)
            for root in roots for path in root.rglob("*") if path.is_file()}


@pytest.fixture
def installed_class(formal_setup, ordinary_setup, sources, tmp_path, monkeypatch, request):
    seed = SimpleNamespace(**vars(ordinary_setup))
    seed.spec = formal_setup.spec
    sites = formal_setup.sites
    for shard in range(10):
        manifest = (seed.spec.campaign_dir.parent / "chaff-response-qualification-store/sets" /
                    f"shard-{shard}" / "_qualification-set.json")
        manifest.write_bytes(admission._json({"qualification_set": f"shard-{shard}",
            "workload_ids": [site.workload_id for site in sites[shard * 5:(shard + 1) * 5]]}))
        sites = tuple(replace(site, qualification_set_manifest_sha256=lanes._sha(manifest.read_bytes()))
                      if index // 5 == shard else site for index, site in enumerate(sites))
    payload = admission._unpack(seed.spec.plan_receipt.read_bytes(), lanes.PLAN_TYPE)
    payload["sites"] = [asdict(site) for site in sites]
    payload["lanes"] = [{**asdict(lane), "campaign_sha256": lanes._sha(plan.render_lane_campaign(lane, sites))}
                        for lane in plan.plan_lanes(sites, final=True, study_version=5)]
    seed.spec.plan_receipt.write_bytes(admission._json(admission._bind(lanes.PLAN_TYPE, payload)))
    for lane in plan.plan_lanes(sites, final=True, study_version=5)[:15]:
        (seed.spec.campaign_dir / f"{lane.campaign_name}.yml").write_bytes(plan.render_lane_campaign(lane, sites))
    seed.fake_plan._inputs = lambda args: (SimpleNamespace(provenance_sha256="e" * 64), sites,
        SimpleNamespace(digests=lambda: payload["bindings"]), "final-50", "f" * 64)
    state = make_installation.__wrapped__(sources, seed, tmp_path, monkeypatch)
    original = state.old_proof
    qualifier_image = original["collection_image_digest"]
    if getattr(request, "param", None) == "wrong-qualifier-image":
        qualifier_image = "sha256:" + "0" * 64
    for spec in (state.base, state.current):
        for site in sites:
            sidecar = (spec.campaign_dir.parent / "chaff-response-qualification-store/sets" /
                       site.qualification_set / f"{site.workload_id}.json")
            sidecar.write_bytes(admission._json({"qualification_image_digest": qualifier_image,
                "qualification_source": original["runtime_source"],
                "implementation_receipt": original["qualification_implementation"]}))
    publish(state)
    qualified = [spec.campaign_dir.parent / "chaff-response-qualification-store" for spec in (state.base, state.current)]
    state.preserved = _snapshot(*qualified)
    state.sites = sites
    new_runtime = state.new_proof["runtime_proof"]
    monkeypatch.setattr(qualification, "_qualification_execution_context", lambda:
        (new_runtime["qualification_implementation"], new_runtime["runtime_source"], state.current.collection_image_digest))
    monkeypatch.setattr(util, "source_metadata", lambda: new_runtime["runtime_source"])
    monkeypatch.setenv("QCSD_LAB_ROOT", str(state.current.runtime_source_root))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", state.current.collection_image_digest)
    rows = [{"candidate_id": site.candidate_id, "selected_url": site.primary_origin + "/",
             "original_terminal_sha256": f"{index + 1:064x}", "initial_site": asdict(site)}
            for index, site in enumerate(sites)]
    monkeypatch.setattr(classes, "_classes", lambda spec, proof: copy.deepcopy(rows))
    state.qualifier_calls = []

    def packet_qualification(value, **options):
        assert value["qualification_set"] == options["expected_qualification_set"]
        assert value["workload_ids"] == options["expected_workload_ids"]
        for name in options["expected_workload_ids"]:
            sidecar = admission._load((options["sidecar_root"] / f"{name}.json").read_bytes())
            qualification._validate_implementation_receipt(sidecar["implementation_receipt"], require_current=False)
            if options["require_current_implementation"]:
                runtime_epochs.validate_qualification_reuse(sidecar["implementation_receipt"],
                    new_runtime["qualification_implementation"])
        state.qualifier_calls.append(options["require_current_implementation"])
        return value

    monkeypatch.setattr(qualification, "validate_named_qualification_set_manifest", packet_qualification)

    def actual_image(command, **options):
        assert command[:2] == ["docker", "run"]
        state.calls.append(command)
        inputs = json.loads(command[-1])
        with monkeypatch.context() as child:
            child.delenv("QCSD_RAPID_COLLECTION_COMPATIBILITY", raising=False)
            for index, argument in enumerate(command):
                if argument == "--env":
                    key, value = command[index + 1].split("=", 1)
                    child.setenv(key, value)
            if command[-2] == classes.CORPUS_SCRIPT:
                lanes.executed_image_plan_check(inputs["spec"])
                try:
                    if inputs["publish"]:
                        proof = classes.publish_corpus_manifest(state.current, state.root, Path(inputs["path"]))
                    else:
                        proof = classes.verify_corpus_manifest(state.current, state.root,
                            admission._load(Path(inputs["path"]).read_bytes()))
                except ValueError as error:
                    return subprocess.CompletedProcess(command, 1, "", str(error))
            else:
                proof = (classes.executed_image_epoch_check(inputs) if command[-2] == classes.IMAGE_SCRIPT
                         else lanes.executed_image_plan_check(inputs))
        return subprocess.CompletedProcess(command, 0, json.dumps(proof), "fixture installed image\n")

    monkeypatch.setattr(lanes.subprocess, "run", actual_image)
    monkeypatch.delenv("QCSD_RAPID_COLLECTION_COMPATIBILITY", raising=False)
    state.policy = classes.initialize_study(state.current, state.root, installation=state.capsule)
    assert "QCSD_RAPID_COLLECTION_COMPATIBILITY" not in os.environ
    state.manifest = (state.current.campaign_dir.parent / "chaff-response-qualification-store/sets" /
                      "shard-0/_qualification-set.json")
    return state


def test_installed_class_policy_and_block_reopen_original_qualifiers_without_ambient_env(installed_class):
    state = installed_class
    policy = classes.verify_policy(state.current, state.root)
    assert policy["image_check"]["execution"]["capture_control_installation"] == {
        "path": str(state.capsule), "sha256": lanes._sha(state.capsule.read_bytes())}
    assert policy["image_check"]["proof"]["runtime_source"] != state.old_proof["runtime_source"]
    declaration = classes.declare_block(state.current, state.root, block=1, shard=1,
                                        qualification_manifest=state.manifest)
    block, effective = classes.verify_block(state.current, state.root, declaration)
    assert len(effective) == 50 and len(block["campaigns"]) == 5
    checked = classes.check_bound_image(state.current, state.root, declaration)
    classes._verified_check(state.current, state.root, declaration, checked)
    assert checked["proof"]["effective_sites"] == [asdict(site) for site in effective]
    assert True in state.qualifier_calls
    assert f"QCSD_RAPID_COLLECTION_COMPATIBILITY={state.capsule}" in checked["execution"]["command"]
    # Final transport must reconstruct this same authority with no operator
    # environment. The real unfinished corpus remains unable to earn credit.
    corpus = state.root / "formal-corpus.json"
    for publishing in (True, False):
        if not publishing:
            corpus.write_bytes(b"{}\n")
        with pytest.raises(ValueError, match="rejected epoch corpus closure"):
            classes.check_corpus_in_image(state.current, state.root, corpus, publish=publishing)
        command = state.calls[-1]
        assert command[-2] == classes.CORPUS_SCRIPT
        assert f"QCSD_RAPID_COLLECTION_COMPATIBILITY={state.capsule}" in command
        assert f"{state.root}:{state.root}:{'rw' if publishing else 'ro'}" in command
        assert json.loads(command[-1])["publish"] is publishing
        if publishing:
            assert not corpus.exists()
    records = [admission._load(path.read_bytes()) for path in state.root.glob("epoch-corpus-check-*.json")]
    assert len(records) == 2 and all(record["returncode"] == 1 for record in records)
    roots = [spec.campaign_dir.parent / "chaff-response-qualification-store" for spec in (state.base, state.current)]
    assert _snapshot(*roots) == state.preserved
    assert not list(state.root.glob("lanes/*/intent.json"))
    with pytest.raises((ValueError, FileExistsError)):
        classes.initialize_study(state.current, state.root)


@pytest.mark.parametrize("mutation", ["capsule-bytes", "capsule-ref", "current-source", "current-image"])
def test_installed_class_policy_rejects_changed_capsule_current_source_or_image(installed_class, mutation):
    state = installed_class
    spec = state.current
    if mutation == "capsule-bytes":
        state.capsule.write_bytes(state.capsule.read_bytes() + b"\n")
    elif mutation == "capsule-ref":
        policy = classes._open(state.policy, classes.POLICY_TYPE)
        policy["image_check"]["execution"]["capture_control_installation"]["sha256"] = "0" * 64
        state.policy.write_bytes(admission._json(admission._bind(classes.POLICY_TYPE, policy)))
    elif mutation == "current-source":
        path = spec.runtime_source_root / "src/qcsd_lab/rapid_class_epochs.py"
        path.write_bytes(path.read_bytes() + b"\n# changed current installed source\n")
    else:
        spec = replace(spec, collection_image_digest="sha256:" + "0" * 64)
    with pytest.raises(ValueError):
        classes.verify_policy(spec, state.root)
    with pytest.raises(ValueError):
        classes.declare_block(spec, state.root, block=1, shard=1, qualification_manifest=state.manifest)
    assert not list(state.root.glob("blocks/*/*/declaration.json"))


@pytest.mark.parametrize("installed_class", ["wrong-qualifier-image"], indirect=True)
def test_installed_class_block_rejects_qualifier_with_another_original_image(installed_class):
    state = installed_class
    classes.verify_policy(state.current, state.root)
    with pytest.raises(ValueError, match="preserved original image/client/source"):
        classes.declare_block(state.current, state.root, block=1, shard=1,
                              qualification_manifest=state.manifest)
    assert not list(state.root.glob("blocks/*/*/declaration.json"))
