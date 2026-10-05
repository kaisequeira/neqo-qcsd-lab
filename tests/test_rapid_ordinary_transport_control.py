"""Genuine retained metadata and full graph transport; no actuation/deep replay.

Only the previously executed raw GET semantics and original canary deep proof
are controlled boundaries. The real enrollment chain, all graph bytes, current
control inventory, input/plan/layout readers and public argv builders execute.
"""
import ast
import copy
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from qcsd_lab import rapid_ordinary_transport_control as control
from qcsd_lab import rapid_ordinary_canary_retry as retry
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_undefended_capture as ordinary
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_selected_capture_input as selected
from qcsd_lab import rapid_site_admission as receipts
from qcsd_lab.rapid_operation_facts import OperationFacts

ROOT = Path(__file__).resolve().parents[1]


def actual_paths():
    anchor = Path(os.environ["QCSD_ORDINARY_FORMAL_ORIGINAL_PLAN"])
    current = Path(os.environ["QCSD_ORDINARY_FORMAL_CURRENT_SPEC"])
    return anchor, current


def write(path, value):
    path.write_bytes(lanes._json(value))
    return control._reference(path)


def raw_boundary(monkeypatch):
    # The original complete raw GET proof is separately retained, not replayed
    # by a mount-construction test. All its metadata/ref/body graphs are real.
    monkeypatch.setattr(selected, "_raw_selected_proof", lambda value, manifest: {"controlled": "retained original GET semantic proof"})


def fixture(tmp_path, monkeypatch):
    anchor, current = actual_paths()
    raw_boundary(monkeypatch)
    stored_spec = json.loads(current.read_bytes())
    assert set(stored_spec) == {"schema_version", "artifact_type", "inputs"}
    assert stored_spec["artifact_type"] == "qcsd-rapid-v6-rolling-capture-spec"
    old_spec = lanes.CaptureSpec(**{key: Path(value) if key in lanes.PATH_KEYS else value
        for key, value in stored_spec["inputs"].items()})
    runtime = {key: old_spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}
    runtime["module_root"] = str(ROOT)
    declaration = tmp_path / "transport-control.json"
    control.publish_control(anchor, runtime, declaration)
    renewal_path = control.publish_renewal(rolling._ref(declaration), runtime, tmp_path / "renewal.json")
    input_path = control.publish_inputs(old_spec.cohort, runtime, rolling._ref(renewal_path),
        rolling._ref(declaration), tmp_path / "ordinary-inputs.json")
    value = lanes.plan_payload(old_spec.plan_receipt.read_bytes())
    value["runtime"] = runtime
    value["qualification_spec_sha256"] = lanes._sha(input_path.read_bytes())
    ready = copy.deepcopy(value["readiness"]["undefended"])
    ready["reader_sources"] = retry._sources()
    value["readiness"] = {"undefended": ready}
    plan_path = tmp_path / "plan.json"
    envelope = json.loads(old_spec.plan_receipt.read_bytes())
    envelope["payload"] = value
    # Public packer recomputes the retained payload digest exactly.
    rolling._write(plan_path, lanes.PLAN_TYPE, value)
    spec = replace(old_spec, module_root=ROOT, qualification_spec=input_path, plan_receipt=plan_path)
    return spec, anchor, renewal_path, ready, declaration


def test_exact_control_projection_and_residual_refusal(tmp_path):
    anchor, _ = actual_paths()
    plan = json.loads(anchor.read_bytes())
    source = Path(plan["clean_runtime_root"])
    control.check_projection(source, ROOT)
    original = (source / "src/qcsd_lab/rapid_rolling_capture.py").read_bytes()
    current = (ROOT / "src/qcsd_lab/rapid_rolling_capture.py").read_bytes()
    altered = current.replace(b'def enrollment_roots(', b'def renamed_enrollment_roots(', 1)
    with pytest.raises(ValueError):
        control._boundary_projection(original, altered, "enrollment_roots", "pass")


def test_original_group_four_map_and_new_renewal_graph_identity(tmp_path, monkeypatch):
    raw_boundary(monkeypatch)
    anchor, current = actual_paths()
    plan = json.loads(anchor.read_bytes())
    with OperationFacts().scope() as context:
        bindings, manifests = control.original_group(plan, anchor.parent)
        assert [row["class_index"] for row in bindings] == list(range(7, 12))
        assert [len(manifest["resources"]) for manifest in manifests] == [70, 13, 62, 143, 77]
        old_sources = json.loads(Path(plan["ordinary_renewal"]["path"]).read_bytes())["control_sources"]
        assert old_sources != ordinary._sources()
        context.check()
    spec, _, renewal, _, _ = fixture(tmp_path, monkeypatch)
    renewed = ordinary.validate_renewal(renewal, spec.cohort)[0]
    assert renewed["control_sources"] == ordinary._sources()
    old = json.loads(Path(plan["ordinary_renewal"]["path"]).read_bytes())
    assert renewed["renewals"] == old["renewals"]
    assert renewed["rows"] == old["rows"]


def test_actual_current_plan_image_readiness_and_lane_commands(tmp_path, monkeypatch):
    spec, anchor, _, ready, _ = fixture(tmp_path, monkeypatch)
    # The original actual canary/deep proof has already passed in its original
    # image; this HOST gate exercises transport/raw command ABI, not deep again.
    monkeypatch.setattr(OperationFacts, "bind_canary", lambda self, ref, runtime: None)
    original_validate = readiness._validate_canary
    def deep_boundary(reference, *, runtime, mode, **kwargs):
        plan = json.loads(anchor.read_bytes())
        assert mode == "undefended"
        if "_transport_recovery" in kwargs:
            assert kwargs["_transport_recovery"]["command"] == kwargs["_transport_recovery"]["expected_command"]
        from qcsd_lab.rapid_capture_traffic import spec_files
        return {"source": {**json.loads(spec.source_manifest.read_bytes()), "image_digest": spec.collection_image_digest},
            "mode": mode, "workload_sha256": plan["original_workload_sha256"], "recorded_image_deep_reopened": True,
            "client_sha256": lanes._sha(spec.client_binary.read_bytes()),
            "traffic_hashes": {key: digest for key, (_, digest) in spec_files(spec).items()},
            "application_body_identity_policy": "complete-current-application-delivery-v1",
            "verified_at": "2026-10-06T00:00:00Z", **readiness.ZERO}
    monkeypatch.setattr(readiness, "_validate_canary", deep_boundary)
    with OperationFacts().scope() as context:
        sites, payload = rolling.verify_capture_plan(spec, require_current=True, _context=context)
        assert len(sites) == 5 and payload["planned_trace_count"] == 320
        campaign = payload["lanes"][1]["campaign_name"]
        argv = lanes.image_check_command(spec, campaign_name=campaign, _context=context)
        roots = rolling.readiness_roots(spec, campaign, _context=context)
        target = tmp_path / "formal/lanes" / campaign / "intent.json"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"controlled not-yet-born intent boundary")
        later = rolling.lane_check_command(spec, tmp_path / "formal", target, complete=True, _context=context)
        assert argv[argv.index("--network") + 1] == later[later.index("--network") + 1] == "none"
        audit = Path(os.environ["QCSD_ORDINARY_FORMAL_MISSING_AUDIT"]).parent
        assert audit in roots
        assert f"{audit}:{audit}:ro" in argv and f"{audit}:{audit}:ro" in later
        assert f"{tmp_path / 'formal'}:{tmp_path / 'formal'}:rw" in later
        assert all(value.endswith(":ro") for i, value in enumerate(argv) if i and argv[i - 1] == "--volume")
        context.check()


def test_marked_current_control_and_mutation_fence(tmp_path, monkeypatch):
    spec, _, _, _, declaration = fixture(tmp_path, monkeypatch)
    with OperationFacts().scope() as context:
        sites = ordinary.validate_inputs(spec.qualification_spec, enrollment=spec.cohort,
            runtime={key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}, require_current=True)
        assert len(sites) == 5
        declaration.chmod(declaration.stat().st_mode ^ 0o100)
        with pytest.raises(ValueError):
            context.check()


def test_unmarked_old_current_control_default_still_refuses(tmp_path, monkeypatch):
    spec, _, _, _, _ = fixture(tmp_path, monkeypatch)
    value = json.loads(spec.qualification_spec.read_bytes())
    del value[control.FIELD]
    path = tmp_path / "unmarked.json"
    write(path, value)
    with pytest.raises(ValueError, match="actual installed and frozen"):
        ordinary.validate_inputs(path, enrollment=spec.cohort,
            runtime={key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}, require_current=True)


def image_runtime(spec):
    """Actual retained image labels; no HOST claim of installed execution."""
    from qcsd_lab.rapid_capture_traffic import spec_files
    return {"collection_image_digest": spec.collection_image_digest,
        "runtime_source": {**json.loads(spec.source_manifest.read_bytes()), "image_digest": spec.collection_image_digest},
        **{label: lanes._sha(getattr(spec, key).read_bytes()) for key, label in (
            ("source_manifest", "source_manifest_sha256"), ("client_binary", "client_sha256"),
            ("base_launcher", "base_launcher_sha256"), ("host_launcher", "host_launcher_sha256"))},
        "qualification_implementation": {"controlled": "installed runtime proof boundary only"},
        "traffic_hashes": {key: digest for key, (_, digest) in spec_files(spec).items()}}


def test_actual_image_plan_function_and_public_owner_return_full_proof(tmp_path, monkeypatch):
    spec, _, _, _, _ = fixture(tmp_path, monkeypatch)
    runtime = image_runtime(spec)
    assert (ROOT / "src/qcsd_lab/rapid_rolling_capture.py").read_bytes() != (
        spec.runtime_source_root / "src/qcsd_lab/rapid_rolling_capture.py").read_bytes()
    with OperationFacts().scope() as context:
        proof = rolling.image_plan_check(spec, runtime, _context=context)
        assert len(proof["sites"]) == 5
        assert proof["plan_payload"] == lanes.plan_payload(spec.plan_receipt.read_bytes())
        assert proof["plan_receipt_sha256"] == lanes._sha(spec.plan_receipt.read_bytes())
        assert proof["runtime_source"] == runtime["runtime_source"]
        assert proof["overlay_source_hashes"]["src/qcsd_lab/rapid_rolling_capture.py"] == lanes._sha(
            (ROOT / "src/qcsd_lab/rapid_rolling_capture.py").read_bytes())
        context.check()
    # Run the actual public installed-plan dispatch and its closing owner;
    # only the no-Docker installed runtime preflight is a controlled boundary.
    monkeypatch.setattr(lanes, "executed_image_runtime_check", lambda value: runtime)
    assert lanes.executed_image_plan_check(spec.serializable())["plan_payload"] == proof["plan_payload"]


@pytest.mark.parametrize("field", ["collection_image_digest", "runtime_source", "client_sha256"])
def test_image_authority_refuses_changed_actual_runtime(tmp_path, monkeypatch, field):
    spec, _, _, _, _ = fixture(tmp_path, monkeypatch)
    runtime = image_runtime(spec)
    runtime[field] = {} if field == "runtime_source" else "altered actual runtime label"
    with pytest.raises(ValueError, match="actual image, Source, client"):
        rolling.image_plan_check(spec, runtime)


def test_image_authority_unmarked_default_still_refuses(tmp_path, monkeypatch):
    spec, _, _, _, _ = fixture(tmp_path, monkeypatch)
    _, payload = rolling.verify_capture_plan(spec, require_current=True)
    path = tmp_path / "unmarked.json"
    value = json.loads(spec.qualification_spec.read_bytes())
    del value[control.FIELD]
    write(path, value)
    unmarked = replace(spec, qualification_spec=path)
    # Reach the precise second predicate without replacing its implementation.
    # Generic unmarked ordinary validation remains separately refused above.
    monkeypatch.setattr(rolling, "verify_capture_plan", lambda *args, **kwargs: ((), payload))
    with pytest.raises(ValueError, match="rolling authority differs"):
        rolling.image_plan_check(unmarked, image_runtime(spec))


def test_image_projection_rejects_residual_acceptance_change(tmp_path):
    source = (ROOT / "src/qcsd_lab/rapid_rolling_capture.py").read_bytes()
    altered = source.replace(b'"cohort_generation": "rolling-50"', b'"cohort_generation": "forged-50"', 1)
    old = json.loads(actual_paths()[0].read_bytes())
    original = (Path(old["clean_runtime_root"]) / "src/qcsd_lab/rapid_rolling_capture.py").read_bytes()
    projected = control._image_projection(altered)
    with pytest.raises(ValueError, match="residual controls or acceptance"):
        control._boundary_projection(original, projected, "enrollment_roots", '''from . import rapid_undefended_capture as ordinary
stored = lanes.plan_payload(lanes._read(spec.plan_receipt))
if ordinary.FIELD in stored:
    from . import rapid_ordinary_transport_control as transport
    return transport.enrollment_roots(spec, stored)
''')
