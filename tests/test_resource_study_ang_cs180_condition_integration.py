"""Real public metadata/Store/admission controls; ROOT alone executes them.

Native GET/chaff qualification and packet proof are explicitly synthetic leaves.
The complete original selection/preparation metadata readers, source registry,
SQLite, class map, input binding, declaration, immutable history, quota and own
pilot predicates run. No output is public admission, a capture or credit.
"""
from contextlib import nullcontext
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_native as native
from qcsd_lab import resource_study_reader_compatibility as readers
from qcsd_lab import resource_study_selection as selection
from qcsd_lab.resource_study_inputs import MODES, canonical_json, sha256_file
from qcsd_lab.resource_study_store import StudyStore, _create
from tests.test_resource_study_lineage import enrollment as old_enrollment, rewrite
from tests.test_resource_study_runtime_cohorts import controlled_credit, controlled_pilot
from tests.test_resource_study_selection_integration import RUNTIME, prepare_metadata, write


HOST = "angkanet26.com"
MODE = "cs-buflo"
FIXTURES = Path(__file__).parent / "fixtures/resource_study_ang_cs180"
OLD = FIXTURES / "original-CS120-20-resources.json"
NEW = FIXTURES / "prospective-CS180-current20-resources.json"
RUNTIME137 = {"canonical_sha256": "b" * 64, "client_sha256": "b" * 64,
    "collection_image_digest": "sha256:" + "b" * 64,
    "prepare_image_digest": "sha256:" + "b" * 64,
    "native_commit": native.CS180_NATIVE, "platform": "linux/arm64",
    "source": {"neqo_commit": native.CS180_NATIVE, "lab_commit": "e" * 40}}


def replace_raw(path, raw):
    if path.exists():
        path.chmod(0o600)
        path.unlink()
    _create(path, raw)


def public(argv, capsys, *, success=True):
    code = study.main(argv)
    captured = capsys.readouterr()
    assert code == (0 if success else 1), (captured.out, captured.err)
    return json.loads(captured.out) if success else captured.err


class SyntheticPreparedGET:
    """Only the Native producer is synthetic; original metadata readers run."""
    def __init__(self, root, runtime, *, mutation=None):
        self.root, self.runtime, self.mutation = root, runtime, mutation
        self.calls = []

    def prepare(self, candidate, attempt, *, cs_buflo_duration_policy=None):
        self.calls.append((deepcopy(candidate), cs_buflo_duration_policy))
        value = prepare_metadata(self.root, candidate, attempt)
        base = attempt / "prepared"
        policy = cs_buflo_duration_policy
        raw = OLD.read_bytes() if self.mutation == "old-workload" else NEW.read_bytes()
        if candidate["hostname"] != HOST:
            raw = (base / "resources.json").read_bytes()
        manifest = json.loads(raw)
        replace_raw(base / "resources.json", raw)
        write(attempt / "job.json", {"hostname": candidate["hostname"],
            "urls": candidate["urls"], "output": str(base), "runtime": self.runtime})
        run = study.load(base / "preparation-get/native/run.json")
        run["migration_commit"] = self.runtime["native_commit"]
        for row, resource in zip(run["responses"], manifest["resources"]):
            size = resource.get("data_length", 2000) if candidate["hostname"] == HOST else row["bytes"]
            row.update(bytes=size, content_length=size,
                response_headers=[[":status", "200"], ["content-length", str(size)]])
        write(base / "preparation-get/native/run.json", run)
        write(base / "preparation-get/completed.json", {"returncode": 0,
            "timed_out": False, "client_unchanged": True,
            "client_sha256": self.runtime["client_sha256"]})
        prepared = study.load(base / "prepared-workload.json")
        preparation = prepared["preparation"]
        preparation.update(runtime=deepcopy(self.runtime),
            actual_preparation_run_sha256=sha256_file(base / "preparation-get/native/run.json"),
            expected_responses=[{key: row[key] for key in
                ("resource_id", "status", "bytes", "body_sha256")} for row in run["responses"]])
        if policy is not None:
            preparation["cs_buflo_duration_policy"] = policy
        if self.mutation == "missing-policy":
            policy = None
            preparation.pop("cs_buflo_duration_policy", None)
        write(base / "prepared-workload.json", {**manifest, "preparation": preparation})
        paths = native._parameter_bundle(base)
        limits_policy = None if self.mutation == "default120" else policy
        value.update(runtime=deepcopy(self.runtime),
            workload_sha256=sha256_file(base / "resources.json"),
            mode_policies=native.mode_policies(cs_buflo_duration_policy=policy),
            mode_settings=native._mode_settings(paths, cs_buflo_duration_policy=limits_policy))
        if self.mutation == "default120":
            # An internally consistent false120 declaration, not just a missing
            # settings.policies key; the actual condition comparison must refuse.
            value["mode_settings"][MODE]["policies"] = deepcopy(value["mode_policies"][MODE])
        # The synthetic Native producer must seal its preparation inputs just
        # as the real producer does before the original enrollment reader runs.
        for path in base.rglob("*"):
            if path.is_file():
                path.chmod(0o444)
        value["files"] = {p.relative_to(self.root).as_posix(): sha256_file(p)
            for p in base.rglob("*") if p.is_file()}
        return value


@pytest.fixture
def original250(tmp_path, monkeypatch, capsys):
    from qcsd_lab import resource_study_store as storage
    # Disposable fixtures make no persistence/Docker-custody claim. Every local
    # ledger lock, authority check and immutable file predicate remains original.
    monkeypatch.setattr(storage.os, "fsync", lambda _: None)
    monkeypatch.setattr(storage, "_fsync", lambda _: None)
    monkeypatch.setattr(epochs, "docker_lock", nullcontext)
    raw = lambda root, receipt: {"verified": True, "five_tuple": receipt.get("five_tuple")}
    for module in (epochs, cohorts, study):
        monkeypatch.setattr(module, "verify_receipt", raw)
    assert sha256_file(OLD) == native.CS180_OLD_WORKLOAD
    assert sha256_file(NEW) == native.CS180_WORKLOAD
    old_manifest, current_manifest = json.loads(OLD.read_bytes()), json.loads(NEW.read_bytes())
    assert [r["url"] for r in old_manifest["resources"]] == [r["url"] for r in current_manifest["resources"]]
    qualified = readers.qualify_execution(cohorts.verifier_contract())
    assert set(cohorts.RAW_DEPENDENCIES) == set(readers.execution_files())
    assert len(cohorts.RAW_DEPENDENCIES) == 175
    assert qualified.contract() == cohorts.verifier_contract()
    retained = [HOST, *(f"condition-control-{i:02d}.example" for i in range(48))]
    urls = {host: ([r["url"] for r in old_manifest["resources"]] if host == HOST else
        [f"https://{host}/r?i={i}" for i in range(20)]) for host in retained}
    source = tmp_path / "source.json"
    write(source, [{"crUX_domain": "fixture.example", "resources": [
        {"resource_domain": host, "resource_urls": urls.get(host,
            [f"https://{host}/r?i={i}" for i in range(20)])}
        for host in [*retained, lineage.EXCLUDED]]}])
    parent = StudyStore(tmp_path / "parent")
    study.initialize(source, parent.root, storage_reserve_bytes=2 * 1024**3)
    parameters = native._parameter_bundle(tmp_path / "original-parameters")
    settings, policies = native._mode_settings(parameters), native.mode_policies()
    for host in retained:
        value = old_enrollment(parent, host)
        value.update(urls=urls[host], runtime=deepcopy(RUNTIME),
            mode_settings=deepcopy(settings), mode_policies=deepcopy(policies))
        if host == HOST:
            replace_raw(parent.root / value["workload_path"], OLD.read_bytes())
            value["workload_sha256"] = native.CS180_OLD_WORKLOAD
            value["files"][value["workload_path"]] = native.CS180_OLD_WORKLOAD
        parent.enroll(value)
    cells = {(host, mode): epochs._cell(parent, host, mode) for host in retained for mode in MODES}
    epochs._bind(parent, parent)
    epochs._publish(parent, [], cells, "initial", cells)
    inventory = tmp_path / "MAL.json"
    write(inventory, {"urls": [{"url": f"https://{lineage.INCLUDED}/r?i={i}"} for i in range(25)]})
    mal = StudyStore(tmp_path / "literal-reserve")
    lineage.initialize(parent.root, mal.root, inventory, storage_reserve_bytes=2 * 1024**3)
    result = study.enroll(mal.root, RUNTIME, [lineage.INCLUDED],
        backend=SyntheticPreparedGET(mal.root, RUNTIME))
    assert result["enrollment"][0]["status"] == "enrolled", result
    epochs.create_epoch(parent.root, mal.root, change="replace-unused-class",
        affected_hostnames=[lineage.INCLUDED], affected_modes=list(MODES))
    before = deepcopy(epochs._records(parent)[-1])
    assert len(before["cells"]) == 250
    controlled_pilot(parent, HOST, MODE)
    old_attempt = parent.allocate_attempt(HOST, MODE)
    old_receipt = controlled_credit(parent, old_attempt, commit=False)
    parent.commit_verified(old_receipt, validator=raw)
    counter = {"root": 0}

    def fresh(*, intent=True, mutation=None, declared_runtime=None):
        counter["root"] += 1
        root = tmp_path / ("prospective-%02d" % counter["root"])
        argv = ["cohort-init", "--root", str(parent.root), "--cohort-root", str(root)]
        if intent:
            argv += ["--cs-buflo-duration-policy", native.CS180_POLICY]
        initialized = public(argv, capsys)
        assert initialized["enrolled"] is initialized["admitted"] is False
        store = StudyStore(root)
        selected = tmp_path / (root.name + "-selection.json")
        digest = write(selected, selection.make_manifest(root, HOST, urls[HOST]))
        backend = SyntheticPreparedGET(root, declared_runtime or RUNTIME137, mutation=mutation)
        return SimpleNamespace(store=store, selection=selected, digest=digest, backend=backend)

    def prepare(c, *, runtime_value=None, hosts=None, policy=native.CS180_POLICY):
        return study.enroll(c.store.root, runtime_value or RUNTIME137, hosts or [HOST],
            backend=c.backend, resource_selection=c.selection,
            resource_selection_sha256=c.digest, cs_buflo_duration_policy=policy)

    def declare(c):
        value = public(["cohort-cs180-template", "--root", str(parent.root),
            "--cohort-root", str(c.store.root), "--affected-hostname", HOST,
            "--affected-mode", MODE], capsys)
        assert value["condition_change_authorized"] is False
        value.update(condition_change_authorized=True, rationale="Synthetic metadata integration only; no live qualification")
        path = tmp_path / (c.store.root.name + "-declaration.json")
        write(path, value)
        return path

    def admit(c):
        path = declare(c)
        return public(["cohort-cs180-admit", "--root", str(parent.root),
            "--cohort-root", str(c.store.root), "--declaration", str(path),
            "--declaration-sha256", sha256_file(path)], capsys)

    return SimpleNamespace(parent=parent, before=before, old_receipt=old_receipt,
        old_receipt_bytes=old_receipt.read_bytes(), fresh=fresh, prepare=prepare,
        declare=declare, admit=admit, raw=raw, capsys=capsys)


def test_real_public_condition_admission_preserves249_and_shared_history(original250):
    f = original250
    c = f.fresh()
    result = f.prepare(c)
    assert result["enrollment"][0]["status"] == "enrolled", result
    original_new_enrollment = (c.store.root / f"classes/{HOST}/enrollment.json").read_bytes()
    record = f.admit(c)
    assert record["change"] == cohorts.CS180_CHANGE and len(record["cells"]) == 250
    old = {(v["hostname"], v["mode"]): v for v in f.before["cells"]}
    new = {(v["hostname"], v["mode"]): v for v in record["cells"]}
    assert all(new[key] == cell for key, cell in old.items() if key != (HOST, MODE))
    entry = cohorts._entry(record["cohorts"], (HOST, MODE))
    assert entry["condition_strata"]["shared_quota"] == 400
    strata = entry["condition_strata"]["strata"]
    assert strata[0]["science"]["workload_sha256"] == native.CS180_OLD_WORKLOAD
    assert strata[1]["science"]["workload_sha256"] == native.CS180_WORKLOAD
    assert [strata[1]["science"]["settings"][k] for k in ("timeout_seconds", "capture_seconds")] == [180, 240]
    assert cohorts.accepted_count(c.store, HOST, MODE) == 1
    assert f.old_receipt.read_bytes() == f.old_receipt_bytes
    with pytest.raises(ValueError, match="pilot"):
        c.store.allocate_attempt(HOST, MODE)
    controlled_pilot(c.store, HOST, MODE)
    attempt = c.store.allocate_attempt(HOST, MODE)
    assert attempt["slot"] == 2
    receipt = controlled_credit(c.store, attempt, commit=False)
    value = study.load(receipt)
    value["five_tuple"][1] = 31001
    enrollment = epochs._enrollments(c.store)[HOST][0]
    input_paths = cohorts.input_authority_artifact_paths(enrollment)
    value.setdefault("artifact_paths", {}).update(input_paths)
    value["files"].update({relative: sha256_file(c.store.root / relative)
        for relative in input_paths.values()})
    rewrite(receipt, value)
    c.store.commit_verified(receipt, validator=f.raw)
    assert cohorts.accepted_count(c.store, HOST, MODE) == 2
    assert f.parent.status()["accepted_count"] == c.store.status()["accepted_count"] == 1
    assert (c.store.root / f"classes/{HOST}/enrollment.json").read_bytes() == original_new_enrollment
    # Same admitted root continues without a new admission or preparation.
    next_attempt = c.store.allocate_attempt(HOST, MODE)
    assert next_attempt["slot"] == 3
    c.store.fail_attempt(next_attempt["attempt_id"], "declared no-capture fixture end", kind="fixture")
    with pytest.raises(ValueError):
        f.parent.allocate_attempt(HOST, MODE)
    with pytest.raises(ValueError):
        f.prepare(c)
    assert cohorts.accepted_count(c.store, HOST, MODE) == 2


def test_wrong_scope_runtime_and_missing_intent_cannot_publish(original250):
    f = original250
    head = canonical_json(epochs._records(f.parent)[-1])
    c = f.fresh()
    for hosts, runtime_value in [(["wrong.example"], RUNTIME137), ([HOST], RUNTIME)]:
        with pytest.raises(ValueError):
            f.prepare(c, hosts=hosts, runtime_value=runtime_value)
    assert c.backend.calls == []
    c = f.fresh(intent=False)
    result = f.prepare(c)
    assert result["enrollment"][0]["status"] == "not-enrolled", result
    assert "intent" in result["enrollment"][0]["reason"]
    assert canonical_json(epochs._records(f.parent)[-1]) == head
    assert f.old_receipt.read_bytes() == f.old_receipt_bytes


def test_changed_workload_default120_or_missing_policy_never_admits(original250):
    f = original250
    head = canonical_json(epochs._records(f.parent)[-1])
    for mutation in ("old-workload", "default120", "missing-policy"):
        c = f.fresh(mutation=mutation)
        result = f.prepare(c)
        if result["enrollment"][0]["status"] == "enrolled":
            # A synthetic producer may lie; genuine declared science still
            # fails before parent publication. No actual runtime was executed.
            assert mutation == "default120"
            with pytest.raises(ValueError):
                cohorts.cs180_template(f.parent.root, c.store.root,
                    affected_hostnames=[HOST], affected_modes=[MODE])
        else:
            assert result["enrollment"][0]["status"] == "not-enrolled"
            assert "CS180" in result["enrollment"][0]["reason"], result
        assert canonical_json(epochs._records(f.parent)[-1]) == head
        assert c.store.status()["accepted_count"] == c.store.status()["reserved"] == 0
        assert not (c.store.root / cohorts.MARKER).exists()


def test_real_record_validator_rejects_condition_or_unaffected_history_mutation(original250):
    f = original250
    c = f.fresh(); result = f.prepare(c)
    assert result["enrollment"][0]["status"] == "enrolled", result
    f.admit(c)
    records = epochs._records(f.parent)
    for mutation in ("missing-strata", "quota", "old-science", "member-history", "unaffected"):
        record = deepcopy(records[-1])
        entry = cohorts._entry(record["cohorts"], (HOST, MODE))
        if mutation == "missing-strata": entry.pop("condition_strata")
        elif mutation == "quota": entry["condition_strata"]["shared_quota"] = 401
        elif mutation == "old-science": entry["condition_strata"]["strata"][0]["science"]["workload_sha256"] = native.CS180_WORKLOAD
        elif mutation == "member-history": entry["condition_strata"]["strata"][0]["members"] = []
        else:
            untouched = next(v for v in record["cells"] if v["hostname"] != HOST)
            untouched["definition"]["workload_sha256"] = "0" * 64
        with pytest.raises(ValueError):
            cohorts._validate_record(f.parent, records[:-1], record)
    assert epochs._records(f.parent) == records
    assert f.old_receipt.read_bytes() == f.old_receipt_bytes


def test_ordinary_default_policy_remains120_without_condition():
    assert "cs_buflo_duration_policy" not in native.mode_policies()[MODE]
    assert native.cs_duration_policy(None) is None
    with pytest.raises(ValueError):
        native.cs_duration_policy("arbitrary-180")
