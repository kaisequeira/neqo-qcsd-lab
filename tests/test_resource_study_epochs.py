"""Actual ledger/epoch controls with explicitly controlled raw-proof boundaries.

Temporary receipt fixtures are not real captures or scientific passes.
"""
from contextlib import nullcontext
import importlib.util
import json
from pathlib import Path
import sys

import pytest

from qcsd_lab.resource_study_inputs import MODES, canonical_json, sha256_file
from qcsd_lab.resource_study_store import StudyStore, DuplicateSession, _create
from qcsd_lab.resource_study_verify import ACCEPTANCE

if Path(__file__).with_name("resource_study_epochs.py").is_file():
    SPEC = importlib.util.spec_from_file_location("qcsd_lab.resource_study_epochs", Path(__file__).with_name("resource_study_epochs.py"))
    epochs = importlib.util.module_from_spec(SPEC)
    sys.modules[SPEC.name] = epochs
    SPEC.loader.exec_module(epochs)
else:
    from qcsd_lab import resource_study_epochs as epochs


@pytest.fixture
def roots(tmp_path, monkeypatch):
    from qcsd_lab import resource_study_store as storage
    # Test transaction/authority logic, without flushing the host filesystem.
    # Production FULL synchronization and durable publication remain unchanged.
    connect = StudyStore._connect
    def controlled_connect(store):
        connection = connect(store)
        connection.execute("PRAGMA synchronous=OFF")
        return connection
    monkeypatch.setattr(StudyStore, "_connect", controlled_connect)
    monkeypatch.setattr(storage.os, "fsync", lambda descriptor: None)
    monkeypatch.setattr(storage, "_fsync", lambda path: None)
    monkeypatch.setattr(epochs, "docker_lock", nullcontext)
    monkeypatch.setattr(epochs, "_verify_preparation", lambda store, host: None)
    def create(name, *, hosts=("alpha.example", "beta.example"), resource_version=0,
               parameter=0, native="a", readiness=True, acceptance=ACCEPTANCE):
        root = tmp_path / name
        store = StudyStore(root)
        store.initialize({"schema_version": 1, "record_type": "qcsd-resource-domain-study-v1",
            "class_count": 50, "resources_per_session": 20, "sessions_per_mode": 400,
            "modes": list(MODES), "total_sessions": 100000, "source_sha256": "e" * 64,
            "capture_position": "client-eth0-before-nat", "design": "controlled-resource-domain-http3-replay",
            "acceptance": acceptance})
        for host in hosts:
            relative = f"inputs/{host}/workload.json"
            _create(root / relative, canonical_json({"host": host, "version": resource_version}))
            store.enroll({"hostname": host, "urls": [f"https://{host}/{resource_version}/{i}" for i in range(20)],
                "workload_path": relative, "workload_sha256": sha256_file(root / relative),
                "runtime": {"client_sha256": native * 64, "platform": "linux/amd64",
                            "source": {"neqo_commit": "c" * 40}},
                "mode_settings": {mode: {"fixed_parameter": parameter if mode == "front" else 0} for mode in MODES},
                "mode_policies": {mode: {} for mode in MODES},
                "mode_readiness": {mode: readiness if mode == "front" else True for mode in MODES},
                "files": {relative: sha256_file(root / relative)}, "scientific_credit": False})
        return store
    return create


def mutate(path, raw):
    path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(0o444)


def admit(parent, new, **kwargs):
    return epochs.create_epoch(parent.root, new.root, **kwargs)


def reserve(store, host="alpha.example", mode="front", *, purpose="formal"):
    if hasattr(store, "_allocate_attempt"):
        return store.allocate_attempt(host, mode, purpose=purpose)
    return epochs.reserve(store, host, mode, lambda: store.allocate_attempt(host, mode), purpose=purpose)


def receipt(store, attempt, *, port=31000, purpose="formal"):
    enrollment = epochs._enrollments(store)[attempt["hostname"]][0]
    relative = attempt["path"] + "/raw.bin"
    _create(store.root / relative, b"controlled unit-test bytes, no actual packet claim")
    value = {"schema_version": 1, "record_type": "qcsd-resource-domain-session-verification-v1",
        "verified": True, "purpose": purpose, "scientific_credit": purpose == "formal",
        **{key: attempt[key] for key in ("hostname", "mode", "slot", "attempt_id")},
        "five_tuple": ["10.1.0.2", port, "192.0.2.1", 443, 17], "files": {relative: sha256_file(store.root / relative)},
        "workload_sha256": enrollment["workload_sha256"], "runtime": enrollment["runtime"],
        "mode_settings": enrollment["mode_settings"][attempt["mode"]]}
    path = store.root / attempt["path"] / "session.json"
    _create(path, canonical_json(value))
    return path


def commit(store, path):
    if hasattr(store, "_commit_verified"):
        return store.commit_verified(path,
            validator=lambda root, value: {"verified": True, "five_tuple": value["five_tuple"]})
    return epochs.credit(store, path, lambda: store.commit_verified(path,
        validator=lambda root, value: {"verified": True, "five_tuple": value["five_tuple"]}))


def test_mode_epoch_selects_all_hosts_without_rewriting_unaffected_enrollment(roots):
    parent, new = roots("parent"), roots("new", parameter=1)
    original = {host: row[2] for host, row in epochs._enrollments(parent).items()}
    value = admit(parent, new, change="mode", affected_modes=["front"])
    assert value["affected"] == [[host, "front"] for host in ("alpha.example", "beta.example")]
    for cell in value["cells"]:
        assert cell["root"] == str(new.root if cell["mode"] == "front" else parent.root)
    assert {host: row[2] for host, row in epochs._enrollments(parent).items()} == original
    progress = epochs.status(parent.root)
    assert len(progress["cells"]) == 10 and progress["accepted_count"] == 0
    assert progress["complete"] is progress["scientific_credit"] is False


def test_resource_epoch_requires_and_selects_all_five_host_cells(roots):
    parent = roots("parent")
    new = roots("new", hosts=("alpha.example",), resource_version=1)
    value = admit(parent, new, change="resources", affected_hostnames=["alpha.example"])
    assert set(map(tuple, value["affected"])) == {("alpha.example", mode) for mode in MODES}
    assert all(cell["root"] == str(parent.root) for cell in value["cells"] if cell["hostname"] == "beta.example")


@pytest.mark.parametrize("case", ["partial-resources", "partial-mode", "mixed-native", "no-change", "foreign-host"])
def test_scientific_scope_refusals(roots, case):
    parent = roots("parent")
    new = roots("new", parameter=1, native="b" if case == "mixed-native" else "a")
    kwargs = {"change": "mode", "affected_modes": ["front"]}
    if case == "partial-resources": kwargs = {"change": "resources", "affected_hostnames": ["alpha.example"], "affected_modes": ["front"]}
    if case == "partial-mode": kwargs["affected_hostnames"] = ["alpha.example"]
    if case == "no-change": kwargs["change"] = "native"
    if case == "foreign-host": kwargs["affected_hostnames"] = ["foreign.example"]
    with pytest.raises(ValueError):
        admit(parent, new, **kwargs)


def test_native_epoch_preserves_other_cells_original_runtime(roots):
    parent, new = roots("parent"), roots("new", native="b")
    value = admit(parent, new, change="native", affected_hostnames=["alpha.example"], affected_modes=["front"])
    changed = [cell for cell in value["cells"] if cell["root"] == str(new.root)]
    assert len(changed) == 1 and changed[0]["definition"]["native"][0] == "b" * 64
    assert all(cell["definition"]["native"][0] == "a" * 64 for cell in value["cells"] if cell not in changed)


def test_active_parent_reservation_and_preadmission_new_attempt_refuse(roots):
    parent, new = roots("parent"), roots("new", parameter=1)
    attempt = parent.allocate_attempt("alpha.example", "undefended")
    with pytest.raises(ValueError, match="active reservation"):
        admit(parent, new, change="mode", affected_modes=["front"])
    parent.fail_attempt(attempt["attempt_id"], "controlled cancellation")
    attempt = new.allocate_attempt("alpha.example", "front")
    new.fail_attempt(attempt["attempt_id"], "pre-admission attempt retained")
    with pytest.raises(ValueError, match="pre-admission"):
        admit(parent, new, change="mode", affected_modes=["front"])


def test_foreign_lifecycle_lock_refuses_admission(roots, monkeypatch):
    parent, new = roots("parent"), roots("new", parameter=1)
    def busy():
        raise RuntimeError("another resource-study Docker lifecycle is active")
    monkeypatch.setattr(epochs, "docker_lock", busy)
    with pytest.raises(RuntimeError, match="lifecycle"):
        admit(parent, new, change="mode", affected_modes=["front"])


def test_new_cell_requires_own_pilot_and_excluded_cells_cannot_reserve(roots):
    parent, new = roots("parent"), roots("new", parameter=1)
    admit(parent, new, change="mode", affected_modes=["front"])
    with pytest.raises(ValueError, match="own genuine"):
        reserve(new)
    with pytest.raises(ValueError, match="excluded"):
        reserve(new, mode="undefended", purpose="pilot")
    with pytest.raises(ValueError, match="superseded"):
        reserve(parent, purpose="pilot")
    assert new.status()["reserved"] == parent.status()["reserved"] == 0
    pilot = reserve(new, purpose="pilot")
    assert epochs._read(new.root / pilot["path"] / "epoch-purpose.json")["purpose"] == "pilot"
    path = receipt(new, pilot)
    with pytest.raises(ValueError, match="formal reservation"):
        commit(new, path)


@pytest.mark.parametrize("mismatch", ["hostname", "workload", "enrollment", None])
def test_pilot_is_bound_to_exact_host_workload_and_enrollment(roots, monkeypatch, mismatch):
    parent, new = roots("parent"), roots("new", resource_version=1)
    record = admit(parent, new, change="resources", affected_hostnames=["alpha.example", "beta.example"])
    cell = next(c for c in record["cells"] if c["hostname"] == "alpha.example" and c["mode"] == "front")
    enrollment = epochs._enrollments(new)["alpha.example"][0]
    value = {"purpose": "pilot", "hostname": "alpha.example", "mode": "front",
        "runtime": enrollment["runtime"], "workload_sha256": enrollment["workload_sha256"],
        "mode_settings": enrollment["mode_settings"]["front"],
        "mode_policies": enrollment["mode_policies"]["front"],
        "artifact_paths": {"enrollment": cell["enrollment_path"]},
        "files": {cell["enrollment_path"]: cell["enrollment_sha256"]}}
    if mismatch == "hostname":
        value["hostname"] = "beta.example"
    elif mismatch == "workload":
        value["workload_sha256"] = "f" * 64
    elif mismatch == "enrollment":
        value["files"][cell["enrollment_path"]] = "f" * 64
    _create(new.root / "pilots/alpha.example/front/unit/session.json", canonical_json(value))
    verified = []
    monkeypatch.setattr(epochs, "verify_receipt", lambda root, receipt: verified.append(receipt))
    if mismatch:
        with pytest.raises(ValueError, match="own genuine"):
            reserve(new)
        assert verified == [] and new.status()["reserved"] == 0
    else:
        assert reserve(new)["hostname"] == "alpha.example"
        assert verified == [value]


def test_parent_recovery_uses_selected_real_store_ledgers_before_deep_audit(roots):
    parent, new = roots("parent"), roots("new", parameter=1)
    admit(parent, new, change="mode", affected_modes=["front"])
    attempt = reserve(new, purpose="pilot")
    value = epochs.verify(parent.root, recover=True)
    assert set(value["recovery"]) == {str(parent.root), str(new.root)}
    assert value["raw_deep_verified"] is True and value["accepted_count"] == 0
    with new._transaction() as connection:
        row = connection.execute("SELECT state FROM attempts WHERE attempt_id=?", (attempt["attempt_id"],)).fetchone()
    assert row["state"] == "failed"


@pytest.mark.parametrize("mutation", ["missing-membership", "membership", "admission", "enrollment"])
def test_immutable_metadata_mutation_refuses_before_reservation(roots, mutation):
    parent, new = roots("parent"), roots("new", parameter=1)
    admit(parent, new, change="mode", affected_modes=["front"])
    if mutation == "missing-membership":
        (new.root / "epoch-membership.json").unlink()
    elif mutation == "membership":
        mutate(new.root / "epoch-membership.json", b"{}")
    elif mutation == "admission":
        mutate(parent.root / "epoch-admissions/000001.json", b"{}")
    else:
        mutate(new.root / "classes/alpha.example/enrollment.json", b"{}")
    with pytest.raises((ValueError, OSError, KeyError)):
        reserve(new, purpose="pilot")
    assert new.status()["reserved"] == 0


def test_ancestry_tuple_is_frozen_excluded_even_if_old_index_row_disappears(roots, monkeypatch):
    parent, new = roots("parent"), roots("new", parameter=1)
    old = parent.allocate_attempt("alpha.example", "front")
    old_path = receipt(parent, old)
    parent.commit_verified(old_path, validator=lambda root, value: {"verified": True, "five_tuple": value["five_tuple"]})
    admit(parent, new, change="mode", affected_modes=["front"])
    monkeypatch.setattr(epochs, "_pilot", lambda store, cell: None)
    attempt = reserve(new)
    path = receipt(new, attempt)
    with parent._transaction() as connection:
        connection.execute("DELETE FROM accepted WHERE attempt_id=?", (old["attempt_id"],))
    with pytest.raises(DuplicateSession, match="ancestor"):
        commit(new, path)
    assert new.status()["accepted_count"] == 0
    assert new.status()["reserved"] == 0
    attempt = reserve(new)
    assert commit(new, receipt(new, attempt, port=31001))["accepted"] is True
    assert epochs.status(parent.root)["accepted_count"] == 1


def test_idempotent_old_accepted_audit_preserved_but_no_new_old_cell_credit(roots):
    parent, new = roots("parent"), roots("new", parameter=1)
    attempt = parent.allocate_attempt("alpha.example", "front")
    path = receipt(parent, attempt)
    parent.commit_verified(path, validator=lambda root, value: {"verified": True, "five_tuple": value["five_tuple"]})
    admit(parent, new, change="mode", affected_modes=["front"])
    assert commit(parent, path)["idempotent"] is True
    assert epochs.status(parent.root)["accepted_count"] == 0


def test_late_host_needs_explicit_five_cell_admission_and_current_defaults(roots):
    parent, new = roots("parent"), roots("new", parameter=1)
    admit(parent, new, change="mode", affected_modes=["front"])
    stale = roots("stale", hosts=("gamma.example",))
    with pytest.raises(ValueError, match="stale"):
        admit(parent, stale, change="add-host", affected_hostnames=["gamma.example"])
    healthy = roots("healthy", hosts=("gamma.example",), parameter=1)
    value = admit(parent, healthy, change="add-host", affected_hostnames=["gamma.example"])
    assert len(value["cells"]) == 15
    assert set(map(tuple, value["affected"])) == {("gamma.example", mode) for mode in MODES}
    assert epochs.active_cell(healthy, "gamma.example", "front") is True


def test_deep_composition_rederives_selected_raw_receipts_and_never_claims_partial_complete(roots, monkeypatch, tmp_path):
    parent, new = roots("parent"), roots("new", parameter=1)
    admit(parent, new, change="mode", affected_modes=["front"])
    monkeypatch.setattr(epochs, "_pilot", lambda store, cell: None)
    attempt = reserve(new)
    commit(new, receipt(new, attempt))
    calls = []
    def raw_check(root, value):
        calls.append((root, value["attempt_id"]))
        return {"verified": True, "five_tuple": value["five_tuple"]}
    monkeypatch.setattr(epochs, "verify_receipt", raw_check)
    value = epochs.export_manifest(parent.root, tmp_path / "export.json")
    assert calls == [(new.root, attempt["attempt_id"])]
    assert value["accepted_count"] == 1 and value["raw_deep_verified"] is True
    assert value["total_sessions"] == 100000 and value["complete"] is value["scientific_credit"] is False
    monkeypatch.setattr(epochs, "verify_receipt", lambda *args: (_ for _ in ()).throw(ValueError("actual raw verification failed")))
    with pytest.raises(ValueError, match="raw verification failed"):
        epochs.status(parent.root, deep=True)


def test_root_symlink_and_candidate_plan_mismatch_refused(roots, tmp_path):
    parent, new = roots("parent"), roots("new", parameter=1)
    link = tmp_path / "linked"
    link.symlink_to(new.root, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic"):
        epochs.create_epoch(parent.root, link, change="mode", affected_modes=["front"])
    plan = json.loads((new.root / "study.json").read_text())
    plan["class_count"] = 49
    mutate(new.root / "study.json", canonical_json(plan))
    with pytest.raises(ValueError, match="binding changed"):
        admit(parent, new, change="mode", affected_modes=["front"])


def test_two_worker_reservations_serialize_without_false_foreign_owner_failure(roots, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    parent, new = roots("parent"), roots("new", parameter=1)
    admit(parent, new, change="mode", affected_modes=["front"])
    monkeypatch.setattr(epochs, "_pilot", lambda store, cell: None)
    with ThreadPoolExecutor(max_workers=2) as executor:
        attempts = list(executor.map(lambda host: reserve(new, host), ("alpha.example", "beta.example")))
    assert {attempt["hostname"] for attempt in attempts} == {"alpha.example", "beta.example"}
    assert new.status()["reserved"] == 2


def test_failed_pilot_intent_stays_out_of_formal_metrics_and_bad_purpose_refuses(roots):
    parent, new = roots("parent"), roots("new", parameter=1)
    admit(parent, new, change="mode", affected_modes=["front"])
    with pytest.raises(ValueError, match="purpose"):
        reserve(new, purpose="claimed-formal-pilot")
    attempt = reserve(new, purpose="pilot")
    new.fail_attempt(attempt["attempt_id"], "controlled failed pilot", kind="pilot-failed", wall_seconds=2.5)
    metrics = new.status()["measurements_by_mode"]["front"]
    assert metrics["pilot_wall_samples"] == 1
    assert metrics["formal_attempt_wall_samples"] == 0
