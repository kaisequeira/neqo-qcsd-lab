"""Actual ledger/epoch controls with explicitly controlled raw-proof boundaries.

Temporary receipt fixtures are not real captures or scientific passes.
"""
from contextlib import nullcontext
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys

import pytest

from qcsd_lab.resource_study_inputs import MODES, canonical_json, sha256_file
from qcsd_lab.resource_study_store import StudyStore, DuplicateSession, _create
from qcsd_lab.resource_study_verify import ACCEPTANCE
from qcsd_lab import resource_study_network as class_network

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
               parameter=0, native="a", readiness=True, acceptance=ACCEPTANCE, network_pool=None,
               network_hosts=None, native_commit="c", platform="linux/amd64", unready=(),
               settings=None, policies=None, reverse_urls=False, workload_version=None, existing=None):
        root = existing.root if existing is not None else tmp_path / name
        store = existing or StudyStore(root)
        plan = {"schema_version": 1, "record_type": "qcsd-resource-domain-study-v1",
            "class_count": 50, "resources_per_session": 20, "sessions_per_mode": 400,
            "modes": list(MODES), "total_sessions": 100000, "source_sha256": "e" * 64,
            "capture_position": "client-eth0-before-nat", "design": "controlled-resource-domain-http3-replay",
            "acceptance": acceptance}
        if network_pool is not None:
            names = network_hosts or [*hosts, *(f"class-{index:02d}.example" for index in range(50-len(hosts)))]
            plan.update(acceptance=class_network.ACCEPTANCE,
                class_network=class_network.build_network_plan(names, pool=network_pool),
                tuple_uniqueness_scope=class_network.TUPLE_SCOPE)
        if existing is None:
            store.initialize(plan)
        for host in hosts:
            relative = f"inputs/{host}/workload.json"
            _create(root / relative, canonical_json({"host": host, "version": resource_version if workload_version is None else workload_version}))
            urls = [f"https://{host}/{resource_version}/{i}" for i in range(20)]
            store.enroll({"hostname": host, "urls": list(reversed(urls)) if reverse_urls else urls,
                "workload_path": relative, "workload_sha256": sha256_file(root / relative),
                "runtime": {"client_sha256": native * 64, "platform": platform,
                            "source": {"neqo_commit": native_commit * 40}},
                "mode_settings": {**{mode: {"fixed_parameter": parameter if mode == "front" else 0} for mode in MODES}, **(settings or {})},
                "mode_policies": {**{mode: {} for mode in MODES}, **(policies or {})},
                "mode_readiness": {mode: False if (host,mode) in unready else readiness if mode == "front" else True for mode in MODES},
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
    plan = store.plan()
    if class_network.validate_network_plan(plan) is not None:
        digest = sha256_file(store.root / "study.json")
        value.update(acceptance=class_network.ACCEPTANCE, study_sha256=digest,
            tuple_uniqueness_scope=class_network.TUPLE_SCOPE,
            class_network=class_network.receipt_binding(plan, digest, attempt["hostname"]))
        value["five_tuple"][0] = plan["class_network"]["assignments"][attempt["hostname"]]["client_ipv4"]
    path = store.root / attempt["path"] / "session.json"
    _create(path, canonical_json(value))
    return path


def commit(store, path):
    if hasattr(store, "_commit_verified"):
        return store.commit_verified(path,
            validator=lambda root, value: {"verified": True, "five_tuple": value["five_tuple"]})
    return epochs.credit(store, path, lambda: store.commit_verified(path,
        validator=lambda root, value: {"verified": True, "five_tuple": value["five_tuple"]}))


def controlled_pilot(store, host, mode):
    """Exact-cell metadata for a controlled raw-reader boundary, no live proof."""
    cell = epochs._cell(store, host, mode)
    enrollment = epochs._enrollments(store)[host][0]
    value = {"purpose": "pilot", "hostname": host, "mode": mode,
        "workload_sha256": enrollment["workload_sha256"], "runtime": enrollment["runtime"],
        "mode_settings": enrollment["mode_settings"][mode], "mode_policies": enrollment["mode_policies"][mode],
        "artifact_paths": {"enrollment": cell["enrollment_path"]},
        "files": {cell["enrollment_path"]: cell["enrollment_sha256"]}}
    _create(store.root / "pilots" / host / mode / "controlled-boundary/session.json", canonical_json(value))


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


def test_network_epoch_changes_all_cells_without_importing_historical_credit(roots):
    parent = roots("parent")
    old = parent.allocate_attempt("alpha.example", "front")
    old_path = receipt(parent, old)
    old_bytes = old_path.read_bytes()
    commit(parent, old_path)
    new = roots("new", network_pool=class_network.DEFAULT_POOL)
    value = admit(parent, new, change="network")
    assert set(map(tuple, value["affected"])) == {(host, mode) for host in ("alpha.example", "beta.example") for mode in MODES}
    assert all(cell["root"] == str(new.root) and "network" in cell["definition"] for cell in value["cells"])
    assert new.status()["accepted_count"] == epochs.status(parent.root)["accepted_count"] == 0
    assert parent.status()["accepted_count"] == 1
    assert old_path.read_bytes() == old_bytes


@pytest.mark.parametrize("scope", [{"affected_hostnames": ["alpha.example"]}, {"affected_modes": ["undefended"]}])
def test_network_epoch_refuses_partial_class_or_mode_scope(roots, scope):
    parent = roots("parent");new = roots("new", network_pool=class_network.DEFAULT_POOL)
    with pytest.raises(ValueError, match="every admitted hostname"):
        admit(parent, new, change="network", **scope)


def test_new_standalone_plan_requires_exact_cell_pilot_before_reservation(roots, monkeypatch):
    store = roots("new", network_pool=class_network.DEFAULT_POOL)
    with pytest.raises(ValueError, match="matching mode pilot"):
        reserve(store)
    assert store.status()["reserved"] == 0
    cell = epochs._cell(store, "alpha.example", "front")
    enrollment = epochs._enrollments(store)["alpha.example"][0]
    value = {"purpose": "pilot", "hostname": "alpha.example", "mode": "front",
        "workload_sha256": enrollment["workload_sha256"], "runtime": enrollment["runtime"],
        "mode_settings": enrollment["mode_settings"]["front"], "mode_policies": {},
        "artifact_paths": {"enrollment": cell["enrollment_path"]},
        "files": {cell["enrollment_path"]: cell["enrollment_sha256"]}}
    _create(store.root / "pilots/alpha.example/front/controlled-boundary/session.json", canonical_json(value))
    calls = []
    monkeypatch.setattr(epochs, "verify_receipt", lambda root, receipt: calls.append((root, receipt)))
    attempt = reserve(store)
    assert calls and attempt["hostname"] == "alpha.example"
    store.fail_attempt(attempt["attempt_id"], "controlled reservation cleanup")
    for host, mode in [("beta.example", "front"), ("alpha.example", "undefended")]:
        with pytest.raises(ValueError, match="matching mode pilot"):
            reserve(store, host, mode)
    assert store.status()["reserved"] == 0


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


def test_eleven_class_buflo_epoch_then_late_class_two_runtime_admission(roots, monkeypatch):
    """Real epoch/ledger joins; raw scientific readers remain controlled fixtures."""
    hosts = [*(f"current-{i:02d}.example" for i in range(10)), "fonts.example"]
    late = "late.example"
    mapping = [*hosts, late, *(f"future-{i:02d}.example" for i in range(38))]
    unavailable = [("fonts.example", mode) for mode in MODES if mode != "undefended"]
    options = {"network_pool": class_network.DEFAULT_POOL, "network_hosts": mapping,
               "platform": "linux/arm64", "unready": unavailable}
    parent = roots("runtime002", hosts=hosts, **options)
    # Seed unchanged healthy cells and one historical BuFLO tuple to exercise
    # inherited exclusions. These are synthetic ledger-control samples only.
    old_paths = []
    with monkeypatch.context() as controlled:
        controlled.setattr(epochs, "_pilot", lambda *args: None)
        for mode, port in [("undefended",31000), ("front",31001), ("buflo",31002)]:
            attempt = reserve(parent, hosts[0], mode)
            path = receipt(parent, attempt, port=port);commit(parent,path);old_paths.append(path)
    old_bytes = [path.read_bytes() for path in old_paths]
    buflo = roots("runtime003", hosts=hosts, native="b", native_commit="d", **options)
    native_epoch = admit(parent,buflo,change="native",affected_modes=["buflo"])
    assert len(native_epoch["affected"]) == 11
    assert epochs.status(parent.root)["accepted_count"] == 2
    font = next(cell for cell in native_epoch["cells"] if (cell["hostname"],cell["mode"]) == ("fonts.example","buflo"))
    assert font["definition"]["native"] == ["b"*64,"linux/arm64","d"*40]
    assert font["definition"]["ready"] is False
    with pytest.raises(ValueError,match="not qualified"):
        reserve(buflo,"fonts.example","buflo")

    roots("late-healthy",hosts=[late],existing=parent,**options)
    healthy_modes = [mode for mode in MODES if mode != "buflo"]
    healthy = admit(parent,parent,change="add-host",affected_hostnames=[late],affected_modes=healthy_modes)
    assert len(healthy["cells"]) == 59 and healthy["exclusions"] == native_epoch["exclusions"]
    assert {epochs._key(cell):cell for cell in healthy["cells"] if cell["hostname"] != late} == {epochs._key(cell):cell for cell in native_epoch["cells"]}
    assert epochs.status(parent.root)["accepted_count"] == 2
    assert epochs.status(parent.root)["complete"] is False
    with pytest.raises(ValueError,match="excluded"):
        reserve(parent,late,"buflo",purpose="pilot")
    with pytest.raises(ValueError,match="own genuine"):
        reserve(parent,late,"undefended")
    monkeypatch.setattr(epochs,"verify_receipt",lambda root,value:{"verified":True,"five_tuple":value.get("five_tuple")})
    controlled_pilot(parent,late,"undefended")
    attempt = reserve(parent,late,"undefended");commit(parent,receipt(parent,attempt,port=32000))
    with pytest.raises(ValueError,match="own genuine"):
        reserve(parent,late,"front")
    assert epochs.status(parent.root)["accepted_count"] == 3

    roots("late-buflo",hosts=[late],existing=buflo,native="b",native_commit="d",**options)
    added = admit(parent,buflo,change="add-host",affected_hostnames=[late],affected_modes=["buflo"])
    assert len(added["cells"]) == 60 and added["exclusions"] == native_epoch["exclusions"]
    assert epochs.status(parent.root)["accepted_count"] == 3
    assert {epochs._key(cell):cell for cell in added["cells"] if epochs._key(cell)!=(late,"buflo")} == {epochs._key(cell):cell for cell in healthy["cells"]}
    with pytest.raises(ValueError,match="own genuine"):
        reserve(buflo,late,"buflo")
    controlled_pilot(buflo,late,"buflo")
    attempt = reserve(buflo,late,"buflo");commit(buflo,receipt(buflo,attempt,port=32001))
    assert epochs.status(parent.root)["accepted_count"] == 4
    assert epochs.status(parent.root)["complete"] is False
    assert commit(parent,old_paths[0])["idempotent"] is True
    assert [path.read_bytes() for path in old_paths] == old_bytes

    controlled_pilot(buflo,hosts[0],"buflo")
    attempt = reserve(buflo,hosts[0],"buflo")
    with pytest.raises(DuplicateSession,match="ancestor"):
        commit(buflo,receipt(buflo,attempt,port=31002))
    assert epochs.status(parent.root)["accepted_count"] == 4
    assert parent.status()["accepted_count"] == 4  # Three original rows plus late ordinary.


@pytest.mark.parametrize("modes", [["front"], ["front","buflo"], []])
def test_add_host_refuses_occupied_keys_without_superseding_counts(roots,modes):
    parent = roots("parent");new = roots("new",parameter=1)
    attempt = reserve(parent,"alpha.example","undefended")
    commit(parent,receipt(parent,attempt))
    initial = admit(parent,new,change="mode",affected_modes=["front"])
    before = epochs.status(parent.root)
    with pytest.raises(ValueError,match="already admitted"):
        admit(parent,new,change="add-host",affected_hostnames=["alpha.example"],affected_modes=modes)
    assert epochs._records(parent)[-1] == initial
    assert epochs.status(parent.root) == before


@pytest.mark.parametrize("history", ["pilot", "formal", "accepted"])
def test_add_host_refuses_pre_admission_attempts_in_selected_standalone_cell(roots,history):
    parent = roots("parent");changed = roots("changed",native="b")
    head = admit(parent,changed,change="native",affected_modes=["buflo"])
    late = roots("late",hosts=["late.example"])
    attempt = reserve(late,"late.example","undefended",purpose="pilot" if history == "pilot" else "formal")
    if history == "accepted":
        path = receipt(late,attempt);commit(late,path);original = path.read_bytes()
    else:
        late.fail_attempt(attempt["attempt_id"],"controlled pre-admission attempt",kind="pilot" if history == "pilot" else "failed")
    before = late.status()
    with pytest.raises(ValueError,match="cell cannot contain pre-admission session attempts"):
        admit(parent,late,change="add-host",affected_hostnames=["late.example"],affected_modes=["undefended"])
    assert epochs._records(parent)[-1] == head
    assert epochs._membership(late) is None
    assert late.status() == before
    assert epochs.status(parent.root)["accepted_count"] == 0
    if history == "accepted":assert path.read_bytes() == original


def test_add_host_preserves_other_cell_attempts_without_importing_them(roots):
    parent = roots("parent");changed = roots("changed",native="b")
    admit(parent,changed,change="native",affected_modes=["buflo"])
    late = roots("late",hosts=["late.example"])
    attempt = reserve(late,"late.example","front")
    path = receipt(late,attempt);commit(late,path);original = path.read_bytes()
    head = admit(parent,late,change="add-host",affected_hostnames=["late.example"],affected_modes=["undefended"])
    assert head["affected"] == [["late.example","undefended"]]
    assert late.status()["accepted_count"] == 1
    assert epochs.status(parent.root)["accepted_count"] == 0
    assert path.read_bytes() == original
    with pytest.raises(ValueError,match="cell cannot contain pre-admission session attempts"):
        admit(parent,late,change="add-host",affected_hostnames=["late.example"],affected_modes=["front"])
    assert epochs._records(parent)[-1] == head
    assert path.read_bytes() == original


@pytest.mark.parametrize("difference", ["urls","url-order","workload-hash","class-address"])
def test_existing_host_added_mode_cannot_change_its_class_identity(roots,difference):
    mapping = ["alpha.example","beta.example","late.example",*(f"future-{i:02d}.example" for i in range(47))]
    options = {"network_pool":class_network.DEFAULT_POOL,"network_hosts":mapping}
    parent = roots("parent",**options);buflo = roots("buflo",native="b",**options)
    admit(parent,buflo,change="native",affected_modes=["buflo"])
    healthy = roots("healthy",hosts=["late.example"],**options)
    head = admit(parent,healthy,change="add-host",affected_hostnames=["late.example"],affected_modes=["undefended","front","tamaraw","cs-buflo"])
    changed = dict(options)
    if difference == "urls":changed["resource_version"] = 1
    elif difference == "url-order":changed["reverse_urls"] = True
    elif difference == "workload-hash":changed["workload_version"] = 1
    else:changed["network_pool"] = "10.233.0.0/23"
    candidate = roots("candidate",hosts=["late.example"],native="b",**changed)
    with pytest.raises(ValueError,match="ordered resources or class address"):
        admit(parent,candidate,change="add-host",affected_hostnames=["late.example"],affected_modes=["buflo"])
    assert epochs._records(parent)[-1] == head
    assert len(head["cells"]) == 14 and epochs.status(parent.root)["accepted_count"] == 0


@pytest.mark.parametrize("difference", ["client","commit","platform","settings","policies","network"])
def test_partial_mode_admission_requires_exact_selected_mode_defaults(roots,difference):
    mapping = ["alpha.example","beta.example","late.example",*(f"future-{i:02d}.example" for i in range(47))]
    options = {"network_pool":class_network.DEFAULT_POOL,"network_hosts":mapping,"platform":"linux/arm64"}
    parent = roots("parent",**options);buflo = roots("buflo",native="b",native_commit="d",**options)
    head = admit(parent,buflo,change="native",affected_modes=["buflo"])
    changed = {**options,"native":"b","native_commit":"d"}
    if difference == "client":changed["native"] = "a"
    elif difference == "commit":changed["native_commit"] = "c"
    elif difference == "platform":changed["platform"] = "linux/amd64"
    elif difference == "settings":changed["settings"] = {"buflo":{"fixed_parameter":9}}
    elif difference == "policies":changed["policies"] = {"buflo":{"unregistered-policy":True}}
    else:changed["network_pool"] = "10.233.0.0/23"
    candidate = roots("candidate",hosts=["late.example"],**changed)
    with pytest.raises(ValueError,match="ambiguous or stale"):
        admit(parent,candidate,change="add-host",affected_hostnames=["late.example"],affected_modes=["buflo"])
    assert epochs._records(parent)[-1] == head


def test_unavailable_cells_cannot_be_ignored_to_hide_mixed_native_defaults(roots):
    parent = roots("parent",unready=[("beta.example","buflo")])
    changed = roots("changed",hosts=["alpha.example"],native="b")
    head = admit(parent,changed,change="native",affected_hostnames=["alpha.example"],affected_modes=["buflo"])
    late = roots("late",hosts=["late.example"],native="b")
    with pytest.raises(ValueError,match="ambiguous or stale"):
        admit(parent,late,change="add-host",affected_hostnames=["late.example"],affected_modes=["buflo"])
    assert epochs._records(parent)[-1] == head


def test_partial_mode_admission_cannot_change_the_acceptance_contract(roots):
    parent = roots("parent");changed = roots("changed",parameter=1)
    head = admit(parent,changed,change="mode",affected_modes=["front"])
    late = roots("late",hosts=["late.example"],acceptance="different-acceptance-contract")
    with pytest.raises(ValueError,match="ambiguous or stale"):
        admit(parent,late,change="add-host",affected_hostnames=["late.example"],affected_modes=["undefended"])
    assert epochs._records(parent)[-1] == head


def test_other_epoch_types_refuse_missing_mode_cells_explicitly(roots):
    parent = roots("parent");changed = roots("changed",parameter=1)
    admit(parent,changed,change="mode",affected_modes=["front"])
    late = roots("late",hosts=["late.example"],parameter=1)
    head = admit(parent,late,change="add-host",affected_hostnames=["late.example"],affected_modes=["undefended"])
    candidate = roots("candidate",hosts=["late.example"],native="b",parameter=1)
    with pytest.raises(ValueError,match="unadmitted hostname/mode cell"):
        admit(parent,candidate,change="native",affected_hostnames=["late.example"],affected_modes=["buflo"])
    assert epochs._records(parent)[-1] == head


def test_late_cell_admission_caps_union_at_fifty_hostnames(roots):
    hosts = [f"class-{i:02d}.example" for i in range(50)]
    parent = roots("parent",hosts=hosts)
    attempt = reserve(parent,hosts[0],"undefended");commit(parent,receipt(parent,attempt))
    late = roots("late",hosts=["class-fifty-one.example"])
    with pytest.raises(ValueError,match="fifty distinct classes"):
        admit(parent,late,change="add-host",affected_hostnames=["class-fifty-one.example"],affected_modes=["undefended"])
    assert len(epochs._records(parent)[-1]["cells"]) == 250
    assert parent.status()["accepted_count"] == epochs.status(parent.root)["accepted_count"] == 1


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
