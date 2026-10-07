"""One-action reuse over genuine retained q53; no installed/network authority.

Original audit/runtime/qualification layout boundaries use the prior HOST
fixtures. All selected q53 raw validators delegate to their unchanged body.
Negative mutations affect only private Source or temporary audit fixtures and
are restored; the actual original acquisition evidence remains read-only.
"""
from copy import deepcopy
from dataclasses import replace
import importlib.util
import json
from pathlib import Path

import pytest

from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_operation_facts as facts
from qcsd_lab import rapid_per_class_selected_enrollment as ledger
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_selected_budget_input as selected
from qcsd_lab import rapid_site_admission as receipts
from tests.test_per_class_selected_budget import SEED, actual_q53_input, genuine_seed, fixture_enrollment, write


def prepared(actual_q53_input):
    path, _, _, directory = actual_q53_input
    value, _, _ = selected.validate_input(path)
    target = selected.prepare_input(path, directory / (value["workload_id"] + ".json"))
    return target, json.loads(target.read_bytes())


def counted(monkeypatch, owner, name, counts, key):
    original = getattr(owner, name)

    def invoke(*args, **kwargs):
        counts[key] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, name, invoke)


def public_spec(enrollment, manifest, directory):
    source = Path(selected.__file__).resolve().parents[2]
    definition = importlib.util.spec_from_file_location("real_per_class_memo_layout",
        source / "tests/test_selected_capture_facts.py")
    fixture = importlib.util.module_from_spec(definition)
    definition.loader.exec_module(fixture)
    root = directory / "public-memo-spec"
    root.mkdir()
    spec, _ = fixture.make_spec(root, manifest, cohort=enrollment, declared_role=ledger.ROLE)
    (spec.runtime_source_root / "qcsd-lab").write_bytes(spec.base_launcher.read_bytes())
    host = spec.execution_root / "qcsd-lab"
    host.write_bytes(spec.base_launcher.read_bytes())
    store = spec.campaign_dir.parent / "chaff-response-qualification-store/sets/memo-layout"
    store.mkdir(parents=True)
    group = write(store / "_qualification-set.json", {
        "fixture_role": "public-loader-layout-only-no-current-qualification-claim"})
    write(spec.qualification_spec, {"schema_version": 1, "qualification_sets": [{
        "qualification_set": "memo-layout", "manifest": str(group), "sidecar_root": str(store),
        "prefix_spec_root": None}]})
    payload = json.loads(spec.plan_receipt.read_bytes())["payload"]
    write(spec.plan_receipt, receipts._bind(lanes.PLAN_TYPE, payload))
    spec = replace(spec, data_root=directory, host_launcher=host)
    return write(root / "capture-spec.json", {"schema_version": 1,
        "artifact_type": "qcsd-rapid-v6-rolling-capture-spec", "inputs": spec.serializable()})


def test_actual_q53_public_loader_caps_and_ancestry_reuse_with_fresh_actions(
        actual_q53_input, genuine_seed, monkeypatch):
    enrollment, _, _, manifest = fixture_enrollment(actual_q53_input, genuine_seed, monkeypatch)
    spec_path = public_spec(enrollment, json.loads(manifest.read_bytes()), actual_q53_input[3])
    source = Path(selected.__file__).resolve().parents[2]
    definition = importlib.util.spec_from_file_location("per_class_memo_portable",
        source / "tools/_rapid_class_mode_flight/flight/operator.py")
    operator = importlib.util.module_from_spec(definition)
    definition.loader.exec_module(operator)
    counts = {"membership": 0, "raw": 0}
    counted(monkeypatch, ledger, "_verify_enrollment_uncached", counts, "membership")
    counted(monkeypatch, selected.plain, "_raw_selected_proof", counts, "raw")
    for action in range(2):
        owner = facts.OperationFacts()
        with owner.scope():
            batch, classes, policy = rolling._verify_enrollment(enrollment)
            first = counts["membership"]
            # The dependency selector's genuine proof is carried through the
            # same action; repeated public readers perform no second proof.
            assert first == action + 1
            for _ in range(3):
                loaded = lanes.load_capture_spec(spec_path)
                verified = {}
                batch, classes, policy = rolling._verify_enrollment(loaded.cohort, _verified=verified)
                assert enrollment.absolute() in verified
                assert ledger.verify_enrollment(enrollment) == (batch, classes, policy)
                owner._enrollment(enrollment)
                caps = rolling._effective_capture_limits(batch, classes, policy)
                assert caps["max_response_bytes"] == 64 * 1024 * 1024
                assert caps["capture_megabytes"] == 256
                assert operator.typed_manifest_limits(json.loads(manifest.read_bytes())) == caps
            assert counts["membership"] == first
            assert counts["raw"] == action + 1
            classes[-1]["capture_limits"]["max_response_bytes"] = 1
            assert ledger.verify_enrollment(enrollment)[1][-1]["capture_limits"]["max_response_bytes"] == 64 * 1024 * 1024
            assert selected.validate_input(actual_q53_input[0])[2]["full_list_coverage"] is True
            owner.check()
        assert facts.current_context() is None


@pytest.mark.parametrize("mutation", ["source-bytes", "audit-bytes", "audit-mode"])
def test_cached_real_selected_proof_refuses_changed_dependencies_before_effect(
        actual_q53_input, monkeypatch, mutation):
    path, _, _, directory = actual_q53_input
    target, manifest = prepared(actual_q53_input)
    owner = facts.OperationFacts()
    with owner.scope():
        first = selected.validate_preparation(manifest["preparation"], manifest["resources"])
        value = selected.validate_input(path)[0]
        changed = Path(selected.__file__) if mutation == "source-bytes" else directory / "audit.stdout.log"
        old_bytes, old_mode = changed.read_bytes(), changed.stat().st_mode & 0o7777
        output = directory / "no-effect.json"
        try:
            if mutation == "audit-mode":
                changed.chmod(old_mode ^ 0o200)
            else:
                changed.write_bytes(old_bytes + b" ")
            # A memo returns its original facts. It never replaces the owner
            # fence, which must close before an effect or successful action.
            assert selected.validate_preparation(manifest["preparation"], manifest["resources"]) == first
            with pytest.raises(ValueError, match="bytes or mode"):
                owner.check()
                output.write_bytes(b"effect")
            assert not output.exists()
            assert Path(value["raw_root"]) in {tree for tree, _ in owner._trees}
        finally:
            changed.chmod(old_mode)
            changed.write_bytes(old_bytes)
        owner.check()
    assert target.exists()


@pytest.mark.parametrize("mutation", ["graph", "cap"])
def test_cached_proof_cannot_accept_changed_current_graph_or_caps(actual_q53_input, mutation):
    _, manifest = prepared(actual_q53_input)
    owner = facts.OperationFacts()
    with owner.scope():
        selected.validate_preparation(manifest["preparation"], manifest["resources"])
        altered = deepcopy(manifest)
        if mutation == "graph":
            altered["resources"].pop()
        else:
            altered["preparation"]["max_response_bytes"] = 16 * 1024 * 1024
        with pytest.raises(ValueError, match="complete original graph"):
            selected.validate_preparation(altered["preparation"], altered["resources"])
        owner.check()


def test_initial_real_proof_closes_raw_audit_fence_before_remember(actual_q53_input, monkeypatch):
    path, _, _, directory = actual_q53_input
    raw_validator = selected.plain._raw_selected_proof
    changed = directory / "audit.stdout.log"
    original = changed.read_bytes()

    def mutate_after_actual_raw(*args, **kwargs):
        result = raw_validator(*args, **kwargs)
        changed.write_bytes(original + b" ")
        return result

    monkeypatch.setattr(selected.plain, "_raw_selected_proof", mutate_after_actual_raw)
    owner = facts.OperationFacts()
    try:
        with owner.scope(), pytest.raises(ValueError, match="bytes or mode"):
            selected.validate_input(path)
        assert not any(key[0] == "selected-budget-input" for key in owner._facts)
    finally:
        changed.write_bytes(original)
    owner.check()


def test_no_active_action_preserves_original_uncached_real_proof(actual_q53_input, monkeypatch):
    counts = {"raw": 0}
    counted(monkeypatch, selected.plain, "_raw_selected_proof", counts, "raw")
    assert facts.current_context() is None
    a = selected.validate_input(actual_q53_input[0])
    b = selected.validate_input(actual_q53_input[0])
    assert a == b and counts["raw"] == 2


def test_metadata_only_enrollment_binds_all_executing_audit_modules_before_effect(
        actual_q53_input, genuine_seed, monkeypatch):
    enrollment, _, _, _ = fixture_enrollment(actual_q53_input, genuine_seed, monkeypatch)
    counts = {"membership": 0}
    counted(monkeypatch, ledger, "_verify_enrollment_uncached", counts, "membership")

    def no_raw_replay(*args, **kwargs):
        raise AssertionError("metadata-only enrollment unexpectedly replayed selected GET")

    monkeypatch.setattr(selected.plain, "_raw_selected_proof", no_raw_replay)
    owner = facts.OperationFacts()
    output = actual_q53_input[3] / "no-metadata-effect.json"
    with owner.scope():
        original = ledger.verify_enrollment(enrollment)
        assert counts["membership"] == 1
        for module in (selected.budget, selected.original, selected.get, selected.graph):
            path = Path(module.__file__).absolute()
            assert path in owner._files
            old_bytes, old_mode = path.read_bytes(), path.stat().st_mode & 0o7777
            for mutation in ("bytes", "mode"):
                try:
                    if mutation == "bytes":
                        path.write_bytes(old_bytes + b" ")
                    else:
                        path.chmod(old_mode ^ 0o200)
                    assert ledger.verify_enrollment(enrollment) == original
                    with pytest.raises(ValueError, match="bytes or mode"):
                        owner.check()
                        output.write_bytes(b"effect")
                    assert not output.exists()
                finally:
                    path.chmod(old_mode)
                    path.write_bytes(old_bytes)
                owner.check()
        assert counts["membership"] == 1


def test_enrollment_first_proof_cannot_outlive_changed_receipt(actual_q53_input, genuine_seed, monkeypatch):
    enrollment, _, _, _ = fixture_enrollment(actual_q53_input, genuine_seed, monkeypatch)
    original = ledger._verify_enrollment_uncached
    mode = enrollment.stat().st_mode & 0o7777
    owner = facts.OperationFacts()

    def change_after_proof(path):
        result = original(path)
        if Path(path).absolute() == enrollment.absolute():
            enrollment.chmod(mode ^ 0o200)
        return result

    monkeypatch.setattr(ledger, "_verify_enrollment_uncached", change_after_proof)
    try:
        with owner.scope(), pytest.raises(ValueError, match="operation dependency changed during validation"):
            ledger.verify_enrollment(enrollment)
        assert not any(key[0] in ("per-class-enrollment", "per-class-enrollment-bound-proof")
                       for key in owner._facts)
    finally:
        enrollment.chmod(mode)
    owner.check()


def test_old_seed_cannot_be_memoized_as_per_class_in_or_out_of_action(genuine_seed):
    with pytest.raises(ValueError):
        ledger.verify_enrollment(SEED)
    owner = facts.OperationFacts()
    with owner.scope(), pytest.raises(ValueError):
        ledger.verify_enrollment(SEED)
    assert not any(key[0] in ("per-class-enrollment", "per-class-enrollment-bound-proof")
                   for key in owner._facts)
