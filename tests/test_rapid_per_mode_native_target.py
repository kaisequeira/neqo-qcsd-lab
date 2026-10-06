"""Real v1 target/progress files with explicitly controlled original deep/runtime boundaries.

These HOST fixtures confer no scientific or installed authority. The new reducer
must retain original rows and reuse unchanged v1 validation, never invent credit.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from qcsd_lab import rapid_per_mode_native_target as epochs
from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab.rapid_operation_facts import OperationFacts
from test_rapid_fixed_condition_target import case, proof, write, setting, NATIVE, CLIENT

NEW_NATIVE = "b" * 40
NEW_CLIENT = hashlib.sha256(b"controlled repaired client").hexdigest()


def installed(case, monkeypatch, native=NEW_NATIVE, client=NEW_CLIENT):
    """Controlled *original* installed-runtime boundary, read through real refs."""
    value = {"native_head": native, "files": {}, "binding": {
        "runtime_identity": {"source": {"neqo_commit": native, "neqo_pinned_commit": native},
                             "client_sha256": client},
        "published_at": (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(),
        "read_dependencies": [], "directory_dependencies": []}}
    ref = write(case.root / (native + "-controlled-runtime.json"), value)
    def read(r): return json.loads(fixed._open(r).read_bytes())
    monkeypatch.setattr(fixed, "_measurement_source", read)
    return ref


def v1_target(case, native=NEW_NATIVE, client=NEW_CLIENT):
    return fixed.publish_target(namespace="prospective-repaired-" + native[:8],
        enrollment=case.enrollment, conditions=case.conditions, native_head=native, client_sha256=client,
        history=[case.history], output=case.root / (native + "-target.json"))


def original_progress(case, monkeypatch, modes=("undefended", "front", "tamaraw")):
    initial = fixed.initialize_progress(target=case.target, proofs=[], output=case.root / "old-initial.json")
    return fixed.append_progress(progress=initial, proofs=[proof(case, monkeypatch, mode, range(4)) for mode in modes],
        output=case.root / "old-progress.json")


def plan(case, old, new, binding, *, repaired_tam=True):
    targets = {mode: [{"target": case.target, "source_binding": None}] for mode in epochs.MODES}
    targets["cs-buflo"] = [{"target": new, "source_binding": binding}]
    empty = fixed.initialize_progress(target=new, proofs=[], output=case.root / "new-initial.json")
    progress = {mode: [old] for mode in epochs.MODES}
    progress["cs-buflo"] = [empty]
    if repaired_tam:
        targets["tamaraw"].append({"target": new, "source_binding": binding})
        progress["tamaraw"].append(empty)
    return targets, progress, empty


def declare(case, targets, old, filename="epoch-target.json", parent=None):
    return epochs.publish_target(namespace="prospective-finite-epochs", mode_targets=targets,
        carry_progress=old, parent=parent, output=case.root / filename)


def repaired_proof(case, monkeypatch, mode, slots, native=NEW_NATIVE, client=NEW_CLIENT, change=None):
    def alter(row):
        row["client_sha256"] = client
        row["measurement_source"]["neqo_commit"] = native
        row["measurement_source"]["neqo_pinned_commit"] = native
        row["sample_id"] = native[:8] + "-" + row["sample_id"]
        row["result_root"] += "-" + native[:8]
        if change is not None: change(row)
    return proof(case, monkeypatch, mode, slots, row_change=alter)


def test_original_tam_and_unaffected_rows_retained_and_new_cs_starts_empty(case, monkeypatch):
    old = original_progress(case, monkeypatch, (*epochs.MODES,))
    targets, progress, _ = plan(case, old, v1_target(case), installed(case, monkeypatch))
    declaration = declare(case, targets, old)
    out = epochs.initialize_progress(target=declaration, mode_progress=progress, output=case.root / "joined.json")
    value = epochs.validate_progress(out)
    original = fixed.validate_progress(old)["accepted_rows"]
    assert value["accepted_rows"] == [r for r in original if r["mode"] != "cs-buflo"]
    assert value["target_accepted_count"] == 16
    assert all(r["measurement_source"]["neqo_commit"] == NATIVE and r["client_sha256"] == CLIENT for r in value["accepted_rows"])
    assert [r["remaining_slots"] for r in value["remaining_vectors"] if r["class_index"] == 1 and r["mode"] == "tamaraw"] == [list(range(4, 64))]
    assert epochs.chunk_inputs(out, [1], "tamaraw", epoch_index=1)["ranges"][0] == {"slot_start": 4, "slot_count": 16}
    assert epochs.chunk_inputs(out, [1], "cs-buflo", epoch_index=0)["remaining_slots"] == list(range(64))
    with pytest.raises(ValueError, match="exactly50"): epochs.final_coverage(out)


def test_repaired_rows_keep_distinct_native_labels_and_combined_missing_slots(case, monkeypatch):
    old = original_progress(case, monkeypatch)
    targets, progress, empty = plan(case, old, v1_target(case), installed(case, monkeypatch))
    declaration = declare(case, targets, old)
    initial = epochs.initialize_progress(target=declaration, mode_progress=progress, output=case.root / "joined-initial.json")
    new = fixed.append_progress(progress=empty,
        proofs=[repaired_proof(case, monkeypatch, "tamaraw", range(4, 8)), repaired_proof(case, monkeypatch, "cs-buflo", range(4))],
        output=case.root / "new-progress.json")
    progress["tamaraw"][1] = new; progress["cs-buflo"][0] = new
    out = epochs.append_progress(progress=initial, mode_progress=progress, output=case.root / "joined-next.json")
    value = epochs.validate_progress(out)
    assert value["accepted_rows"][:12] == fixed.validate_progress(old)["accepted_rows"]
    assert value["target_accepted_count"] == 20
    tam = [r for r in value["accepted_rows"] if r["mode"] == "tamaraw"]
    assert [r["logical_visit"] for r in tam] == list(range(8))
    assert [r["client_sha256"] for r in tam] == [CLIENT] * 4 + [NEW_CLIENT] * 4
    inputs = epochs.publish_chunk_inputs(out, [1], "tamaraw", epoch_index=1, output=case.root / "planning.json")
    assert epochs.read_chunk_inputs(inputs)["inputs"]["remaining_slots"] == list(range(8, 64))
    assert epochs.read_chunk_inputs(inputs)["inputs"]["old_capsule_or_chunk_authority_inferred"] is False


@pytest.mark.parametrize("forgery", ["duplicate-slot", "duplicate-physical", "earlier-intent", "client", "graph", "caps"])
def test_cross_epoch_forgery_or_overlap_is_refused(forgery, case, monkeypatch):
    old = original_progress(case, monkeypatch)
    targets, progress, empty = plan(case, old, v1_target(case), installed(case, monkeypatch))
    early = datetime.now(timezone.utc).isoformat()
    declaration = declare(case, targets, old)
    old_row = fixed.validate_progress(old)["accepted_rows"][0]
    def change(row):
        if forgery == "duplicate-physical": row.update(result_root=old_row["result_root"], sample_id=old_row["sample_id"])
        elif forgery == "earlier-intent": row["intent_started_at"] = early
        elif forgery == "client": row["client_sha256"] = CLIENT
        elif forgery == "graph": row["original_graph_sha256"] = "0" * 64
        elif forgery == "caps": row["capture_limits"]["max_response_bytes"] += 1
    output = case.root / "forged-join.json"
    with pytest.raises(ValueError):
        new = fixed.append_progress(progress=empty,
            proofs=[repaired_proof(case, monkeypatch, "tamaraw", [0 if forgery == "duplicate-slot" else 4], change=change)],
            output=case.root / "forged-v1.json")
        progress["tamaraw"][1] = new
        epochs.initialize_progress(target=declaration, mode_progress=progress, output=output)
    assert not output.exists()


def test_later_finite_epoch_revision_retains_all_original_slots_and_prefix(case, monkeypatch):
    old = original_progress(case, monkeypatch)
    new = v1_target(case); binding = installed(case, monkeypatch)
    targets, progress, _ = plan(case, old, new, binding)
    first = declare(case, targets, old)
    original = epochs.initialize_progress(target=first, mode_progress=progress, output=case.root / "role1-progress.json")
    native = "c" * 40; client = hashlib.sha256(b"controlled later repaired client").hexdigest()
    next_target = v1_target(case, native, client); next_binding = installed(case, monkeypatch, native, client)
    targets["tamaraw"].append({"target": next_target, "source_binding": next_binding})
    progress["tamaraw"].append(fixed.initialize_progress(target=next_target, proofs=[], output=case.root / "later-initial.json"))
    second = declare(case, targets, old, "role2-target.json", parent=first)
    with pytest.raises(ValueError, match="preceding"):
        epochs.initialize_progress(target=second, mode_progress=progress, output=case.root / "lost-original.json")
    updated = epochs.initialize_progress(target=second, mode_progress=progress, previous_progress=original,
        output=case.root / "role2-progress.json")
    assert epochs.validate_progress(updated)["accepted_rows"] == epochs.validate_progress(original)["accepted_rows"]
    a, b = epochs.validate_target(first), epochs.validate_target(second)
    assert b["role_revision"] == 2 and b["transition"] == "epoch-addition"
    assert b["epoch_declared_at"]["tamaraw"][:2] == a["epoch_declared_at"]["tamaraw"]
    assert b["identity"]["epochs"]["tamaraw"][:2] == a["identity"]["epochs"]["tamaraw"]
    assert b["target_id"] != a["target_id"]
    targets["tamaraw"] = targets["tamaraw"][1:]
    with pytest.raises(ValueError): declare(case, targets, old, "removed-epoch.json", parent=second)


def test_same_epoch_revision_cannot_reset_preceding_progress(case, monkeypatch):
    old = original_progress(case, monkeypatch)
    targets, progress, _ = plan(case, old, v1_target(case), installed(case, monkeypatch))
    first = declare(case, targets, old)
    original = epochs.initialize_progress(target=first, mode_progress=progress, output=case.root / "retained.json")
    second = declare(case, targets, old, "same-epochs.json", parent=first)
    assert epochs.validate_target(second)["transition"] == "same-epochs"
    with pytest.raises(ValueError, match="preceding"):
        epochs.initialize_progress(target=second, mode_progress=progress, output=case.root / "false-reset.json")
    out = epochs.initialize_progress(target=second, mode_progress=progress, previous_progress=original,
        output=case.root / "same-epoch-retained.json")
    assert epochs.accepted_slots(out) == epochs.accepted_slots(original)


@pytest.mark.parametrize("mode", ["buflo", "cs-buflo"])
def test_empty_modes_still_require_all_original_fixed_conditions(mode, case, monkeypatch):
    old = original_progress(case, monkeypatch)
    configuration, run = setting(mode)
    run["resolved_configuration"]["defense"]["fixed_parameter"] = 1400
    changed = dict(case.conditions)
    changed[mode] = fixed.describe_condition(write(case.root / "different-config.json", configuration),
        write(case.root / "different-run.json", run), mode, case.root / "different-condition.json")
    fork = fixed.publish_target(namespace="different-fixed-empty-mode", enrollment=case.enrollment,
        conditions=changed, native_head=NATIVE, client_sha256=CLIENT, history=[case.history],
        output=case.root / "different-original-target.json")
    new = fixed.publish_target(namespace="different-fixed-repaired-mode", enrollment=case.enrollment,
        conditions=changed, native_head=NEW_NATIVE, client_sha256=NEW_CLIENT, history=[case.history],
        output=case.root / "different-repaired-target.json")
    binding = installed(case, monkeypatch)
    targets = {m: [{"target": fork, "source_binding": None}] for m in epochs.MODES}
    targets["cs-buflo"] = [{"target": new, "source_binding": binding}]
    with pytest.raises(ValueError, match="original five"):
        declare(case, targets, old, "different-mode-refused.json")


def test_unrelated_same_native_progress_target_is_refused(case, monkeypatch):
    old = original_progress(case, monkeypatch)
    targets, progress, _ = plan(case, old, v1_target(case), installed(case, monkeypatch))
    declaration = declare(case, targets, old)
    unrelated = fixed.publish_target(namespace="unrelated-same-pair", enrollment=case.enrollment,
        conditions=case.conditions, native_head=NEW_NATIVE, client_sha256=NEW_CLIENT, history=[case.history],
        output=case.root / "unrelated-target.json")
    progress["cs-buflo"] = [fixed.initialize_progress(target=unrelated, proofs=[], output=case.root / "unrelated-progress.json")]
    with pytest.raises(ValueError, match="unrelated"):
        epochs.initialize_progress(target=declaration, mode_progress=progress, output=case.root / "unrelated-refused.json")


def test_authentic_v1_class_extension_remains_usable(case, monkeypatch):
    old = original_progress(case, monkeypatch)
    new = v1_target(case); binding = installed(case, monkeypatch)
    targets, progress, _ = plan(case, old, new, binding)
    first = declare(case, targets, old)
    previous = epochs.initialize_progress(target=first, mode_progress=progress, output=case.root / "class-prefix-progress.json")
    enrollment = write(case.root / "extended-enrollment.json", {"classes": case.rows})
    extension = fixed.publish_target(namespace="prospective-repaired-" + NEW_NATIVE[:8], enrollment=enrollment,
        conditions=case.conditions, native_head=NEW_NATIVE, client_sha256=NEW_CLIENT, history=[case.history],
        parent=new, output=case.root / "extended-original-target.json")
    updated = fixed.initialize_progress(target=extension, proofs=[], output=case.root / "extended-original-progress.json")
    targets["tamaraw"][1]["target"] = extension
    progress["tamaraw"][1] = updated
    progress["cs-buflo"][0] = updated  # Descendant of the still-declared CS target.
    second = declare(case, targets, old, "extended-role-target.json", parent=first)
    out = epochs.initialize_progress(target=second, mode_progress=progress, previous_progress=previous,
        output=case.root / "extended-role-progress.json")
    assert len(epochs.validate_progress(out)["classes"]) == 3
    assert epochs.accepted_slots(out) == epochs.accepted_slots(previous)


@pytest.mark.parametrize("change", ["missing-binding", "wrong-runtime", "condition", "classes", "duplicate-epoch", "empty-list"])
def test_declaration_refuses_untrusted_or_changed_epoch_inputs(change, case, monkeypatch):
    old = original_progress(case, monkeypatch)
    targets, _, _ = plan(case, old, v1_target(case), installed(case, monkeypatch))
    if change == "missing-binding": targets["cs-buflo"][0]["source_binding"] = None
    elif change == "wrong-runtime":
        ref = targets["cs-buflo"][0]["source_binding"]
        value = json.loads(Path(ref["path"]).read_bytes()); value["binding"]["runtime_identity"]["client_sha256"] = CLIENT
        targets["cs-buflo"][0]["source_binding"] = write(case.root / "changed-runtime.json", value)
    elif change in ("condition", "classes"):
        ref = targets["cs-buflo"][0]["target"]; value = deepcopy(fixed.validate_target(ref))
        if change == "condition": value["conditions"]["cs-buflo"]["identity"]["defense"]["baseline"] = True
        else: value["classes"][0]["original_graph_sha256"] = "0" * 64
        targets["cs-buflo"][0]["target"] = fixed.epoch._write(case.root / "forged-original-target.json", fixed.TARGET_TYPE, value)
    elif change == "duplicate-epoch": targets["tamaraw"].append(targets["tamaraw"][-1])
    else: targets["front"] = []
    with pytest.raises(ValueError): declare(case, targets, old, "refused.json")


def test_mode_three_field_reference_mutation_and_final_fence_refused(case, monkeypatch):
    old = original_progress(case, monkeypatch)
    targets, progress, _ = plan(case, old, v1_target(case), installed(case, monkeypatch))
    declaration = declare(case, targets, old)
    bad = deepcopy(declaration); bad["mode"] ^= 0o100
    with pytest.raises(ValueError): epochs.validate_target(bad)
    output = case.root / "refused-fence.json"
    original = fixed.validate_progress; calls = []
    def mutate(ref, *args, **kwargs):
        value = original(ref, *args, **kwargs)
        if ref == old and not calls:
            calls.append(1); Path(old["path"]).chmod(0o600 if old["mode"] != 0o600 else 0o644)
        return value
    monkeypatch.setattr(fixed, "validate_progress", mutate)
    with pytest.raises(ValueError): epochs.initialize_progress(target=declaration, mode_progress=progress, output=output)
    assert not output.exists()


@pytest.mark.parametrize("mutation", ["bytes", "mode", "membership"])
def test_single_installed_proof_retains_full_dependency_and_final_fence(mutation, case, monkeypatch):
    old = fixed.initialize_progress(target=case.target, proofs=[], output=case.root / "empty-old.json")
    new = v1_target(case); binding = installed(case, monkeypatch)
    raw_root = case.root / "immutable-runtime-raw"; raw_root.mkdir()
    dependency = write(raw_root / "controlled-original-runtime-evidence.json", {"bound": True})
    value = json.loads(Path(binding["path"]).read_bytes())
    value["binding"]["read_dependencies"] = [dependency]
    value["binding"]["directory_dependencies"] = [fixed.epoch._directory(raw_root)]
    # Original installed proof is controlled, but its reported raw predicates
    # use the genuine current file and shallow-directory owner fences.
    binding = write(case.root / "complete-controlled-runtime.json", value); calls = []
    def read(ref):
        calls.append(ref); result = json.loads(fixed._open(ref).read_bytes())
        for row in result["binding"]["read_dependencies"]: fixed._open(row)
        for row in result["binding"]["directory_dependencies"]:
            from qcsd_lab.rapid_operation_facts import current_context
            current_context().watch_directory(Path(row["path"]), expected=row)
        return result
    monkeypatch.setattr(fixed, "_measurement_source", read)
    targets, progress, _ = plan(case, old, new, binding)
    declaration = declare(case, targets, old)
    joined = epochs.initialize_progress(target=declaration, mode_progress=progress, output=case.root / "empty-joined.json")
    calls.clear(); owner = OperationFacts(); owner.begin_action()
    with owner.scope():
        files = epochs.input_files(joined)
        directories = epochs.directory_dependencies(joined)
        assert dependency in files and binding in files
        assert {"kind": "shallow-directory", **fixed.epoch._directory(raw_root)} in directories
        assert calls == [binding]  # TAM and CS use one actual installed proof.
        if mutation == "bytes": Path(dependency["path"]).write_bytes(b'{"bound":false}')
        elif mutation == "mode": Path(dependency["path"]).chmod(dependency["mode"] ^ 0o100)
        else: (raw_root / "unexpected.json").write_text('{}')
        with pytest.raises(ValueError): owner.check()


def test_public_cli_uses_bound_refs_and_distinct_planning_type(case, monkeypatch, capsys):
    old = original_progress(case, monkeypatch)
    targets, progress, _ = plan(case, old, v1_target(case), installed(case, monkeypatch))
    path = Path(__file__).parents[1] / "tools/rapid_per_mode_native_target.py"
    spec = importlib.util.spec_from_file_location("controlled_epoch_public_tool", path)
    tool = importlib.util.module_from_spec(spec); spec.loader.exec_module(tool)
    request = write(case.root / "request.json", {"namespace": "prospective-finite-epochs", "mode_targets": targets, "carry_progress": old})
    output = case.root / "public-target.json"
    assert tool.main(["target", "--request", request["path"], "--request-sha256", request["sha256"], "--output", str(output)]) == 0
    declaration = fixed.reference(output)
    inputs = write(case.root / "mode-progress.json", progress); joined = case.root / "public-progress.json"
    assert tool.main(["initialize-progress", "--target", declaration["path"], "--target-sha256", declaration["sha256"],
        "--mode-progress", inputs["path"], "--mode-progress-sha256", inputs["sha256"], "--output", str(joined)]) == 0
    assert tool.main(["check", "--progress", str(joined), "--progress-sha256", "0" * 64]) == 1
    assert epochs.CHUNK_INPUT_TYPE != fixed.CHUNK_INPUT_TYPE
    capsys.readouterr()
