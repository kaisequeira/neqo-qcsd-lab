"""Real retirement/admission/SQLite controls with declared synthetic raw leaves.

The reused fixture replaces only live GET/raw-science inspection. These tests
retain original immutable input/enrollment joins, admission validation, locks,
write fences, pilots' exact-cell matching, allocation and commit accounting.
They issue no live Clarin admission and do not claim packet-science evidence.
ROOT alone executes this prospective test source.
"""
from copy import deepcopy
import json
import sys
from types import SimpleNamespace

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_epochs as epochs
from qcsd_lab import resource_study_resource_version_inputs as inputs
from qcsd_lab.resource_study_inputs import MODES, canonical_json, sha256_file
from qcsd_lab.resource_study_store import _create
from tests.test_resource_study_lineage import campaign, rewrite
from tests.test_resource_study_runtime_cohorts import cohort_campaign, controlled_credit, controlled_pilot
from tests.test_resource_study_resource_version_inputs import prepared_resource_cohort
from tests.test_resource_study_capture_authority import lock_home, scoped


def declaration(c, path, *, mutate=None):
    value = cohorts.resource_template(c.parent.root, c.input_path, c.input_sha)
    assert value["resource_version_input"] == {"path": str(c.input_path), "sha256": c.input_sha}
    value.update(resource_replacement_authorized=True,
                 rationale="Disposable all5 retirement fixture; synthetic GET/raw leaves, no live credit.")
    if mutate is not None:
        mutate(value)
    _create(path, canonical_json(value))
    return path, sha256_file(path)


@pytest.fixture
def retired_resource_cohort(prepared_resource_cohort, tmp_path):
    c = prepared_resource_cohort
    before = deepcopy(epochs._records(c.parent)[-1])
    receipt = c.original.old_receipt.read_bytes()
    path, digest = declaration(c, tmp_path / "all5-retirement.json")
    admitted = cohorts.create_resource_version(c.parent.root, path, digest)
    return SimpleNamespace(prepared=c, before=before, old_receipt=receipt, admitted=admitted)


def new_receipt(store, attempt, *, port=42000):
    path = controlled_credit(store, attempt, commit=False)
    value = json.loads(path.read_bytes())
    enrolled = epochs._enrollments(store)[attempt["hostname"]][0]
    cell = epochs._cell(store, attempt["hostname"], attempt["mode"])
    value["files"].update(enrolled["files"])
    value["files"][cell["enrollment_path"]] = cell["enrollment_sha256"]
    value["artifact_paths"] = {"enrollment": cell["enrollment_path"], **inputs.artifact_paths(enrolled)}
    value["mode_policies"] = enrolled["mode_policies"][attempt["mode"]]
    value["coordinator_provenance"] = study.coordinator_provenance(class_selection=True, resource_version=True)
    value["five_tuple"][1] = port
    rewrite(path, value)
    return path


def test_actual_admission_keeps_old_rows_and_counts_only_common_v1(retired_resource_cohort):
    state = retired_resource_cohort; c = state.prepared
    head = epochs._records(c.parent)[-1]
    assert head == state.admitted and head["change"] == cohorts.RESOURCE_CHANGE
    assert head["affected"] == [[c.host, mode] for mode in sorted(MODES)]
    assert head["class_transition"] == state.before["class_transition"]
    assert c.original.old_receipt.read_bytes() == state.old_receipt
    assert c.original.old.status()["accepted_count"] == 1
    status = cohorts.status(c.parent.root)
    assert status["accepted_count"] == 0 and status["historically_valid_target_excluded"] == 1
    assert len(status["class_selection"]["selected_hostnames"]) == 50
    for mode in MODES:
        entry = cohorts._entry(head["cohorts"], (c.host, mode))
        assert cohorts._writer(entry)["cell"]["root"] == str(c.mode_stores[mode].root)
        assert len(cohorts._accepted(entry)) == 0
        assert entry["resource_versions"]["strata"][-1]["target_eligible"] is True
    old_tuple = json.loads(state.old_receipt)["five_tuple"]
    from qcsd_lab.resource_study_store import _json
    assert _json(old_tuple).decode() in epochs._excluded(c.parent, epochs._records(c.parent), (c.host, "front"))


def test_v1_requires_own_mode_pilot_and_shared_quota_starts_without_old_credit(retired_resource_cohort):
    c = retired_resource_cohort.prepared; store = c.mode_stores["front"]
    with pytest.raises(ValueError, match="own genuine matching mode pilot"):
        store.allocate_attempt(c.host, "front")
    # Only FRONT obtains a synthetic exact-cell pilot; no all5 pilot gate.
    controlled_pilot(store, c.host, "front")
    attempt = store.allocate_attempt(c.host, "front")
    assert attempt["slot"] == 1  # The historical v0 slot1 remains immutable elsewhere.
    path = new_receipt(store, attempt)
    store.commit_verified(path, validator=lambda root, value: {"verified": True, "five_tuple": value["five_tuple"]})
    status = cohorts.status(c.parent.root)
    assert status["accepted_count"] == 1 and status["historically_valid_target_excluded"] == 1
    assert c.original.old.status()["accepted_count"] == 1 and store.status()["accepted_count"] == 1
    assert c.original.old_receipt.read_bytes() == retired_resource_cohort.old_receipt
    assert not list((c.mode_stores["buflo"].root / "pilots" / c.host / "buflo").glob("*/session.json"))


def test_retired_tuple_cannot_be_counted_again_even_with_an_independent_raw_flag(retired_resource_cohort):
    c = retired_resource_cohort.prepared; store = c.mode_stores["front"]
    controlled_pilot(store, c.host, "front")
    attempt = store.allocate_attempt(c.host, "front")
    old_tuple = json.loads(retired_resource_cohort.old_receipt)["five_tuple"]
    path = new_receipt(store, attempt, port=old_tuple[1])
    value = json.loads(path.read_bytes()); value["five_tuple"] = old_tuple; rewrite(path, value)
    with pytest.raises(ValueError, match="reuse a retired"):
        store.commit_verified(path, validator=lambda root, value: {"verified": True, "five_tuple": value["five_tuple"]})
    assert store.status()["accepted_count"] == 0
    assert c.original.old.status()["accepted_count"] == 1
    assert c.original.old_receipt.read_bytes() == retired_resource_cohort.old_receipt


@pytest.mark.parametrize("prepared_resource_cohort", [{"unready_mode": "buflo"}], indirect=True)
def test_unready_buflo_does_not_veto_ready_front_own_pilot_or_reservation(retired_resource_cohort):
    c = retired_resource_cohort.prepared
    head = epochs._records(c.parent)[-1]
    bf = cohorts._writer(cohorts._entry(head["cohorts"], (c.host, "buflo")))["cell"]
    assert bf["definition"]["ready"] is False
    with pytest.raises(ValueError, match="not qualified"):
        c.mode_stores["buflo"].allocate_attempt(c.host, "buflo")
    front = c.mode_stores["front"]
    controlled_pilot(front, c.host, "front")
    attempt = front.allocate_attempt(c.host, "front")
    assert attempt["slot"] == 1
    assert cohorts.status(c.parent.root)["accepted_count"] == 0


def test_v1_does_not_block_new_unrelated_cohort_initialization_or_relabel_old_pool(retired_resource_cohort, tmp_path):
    c = retired_resource_cohort.prepared
    root = tmp_path / "future-unrelated-original-cohort"
    before = deepcopy(epochs._records(c.parent)[-1])
    value = cohorts.initialize_cohort(c.parent.root, root)
    assert value["enrolled"] is value["admitted"] is value["scientific_credit"] is False
    pool = study.candidate_pool(root)[c.host]
    new_urls = cohorts._entry(before["cohorts"], (c.host, "front"))["science"]["urls"]
    assert not set(new_urls) & set(pool["urls"])
    assert epochs._records(c.parent)[-1] == before
    assert c.original.old_receipt.read_bytes() == retired_resource_cohort.old_receipt


@pytest.mark.skipif(sys.platform != "linux", reason="genuine Linux fdinfo/flock authority")
def test_resource_local_manifest_removal_refuses_the_next_owned_capture_callback(retired_resource_cohort, lock_home):
    """Remove an actual parsed v1 dependency inside the real owned flight.

    No successful reader, file guard, dependency collector or callback is
    replaced. The unchanged preparation fixture discloses its synthetic GET
    leaves. Restoring the file before closure cannot excuse a callback which
    used cached ancestry while that immutable dependency was absent.
    """
    c = retired_resource_cohort.prepared
    store = c.mode_stores["front"]
    path = store.root / inputs.APPLICATION_MANIFEST
    parked = path.with_name("parked-application-manifest.json")
    before = path.stat()
    assert not parked.exists()
    # A properly collected input must reject both the callback and closure.
    # The inner assertion prevents the later full replay from hiding a callback
    # which incorrectly accepted the missing file.
    with pytest.raises((ValueError, OSError)):
        with scoped(store):
            path.rename(parked)
            try:
                with pytest.raises((ValueError, OSError)):
                    with cohorts.capture_records_scope(c.parent, writer_root=store.root, latest_only=True):
                        pytest.fail("missing local resource manifest escaped the owned callback census")
            finally:
                parked.rename(path)
                # Force an observable metadata change even on a filesystem
                # which does not update this inode's ctime for a rename.
                if path.stat().st_ctime_ns == before.st_ctime_ns:
                    path.chmod(0o600)
                    path.chmod(0o444)


@pytest.mark.skipif(sys.platform != "linux", reason="genuine Linux fdinfo/flock authority")
def test_issued_resource_admission_replays_local_copies_without_external_constructor_files(retired_resource_cohort, lock_home):
    """The operator originals are provenance, not live post-admission inputs."""
    c = retired_resource_cohort.prepared
    store = c.mode_stores["front"]
    sources = [c.input_path, inputs._path(c.input_plan["application_manifest"]["path"])]
    parked = []
    try:
        for path in sources:
            temporary = path.with_name("parked-" + path.name)
            assert not temporary.exists()
            path.rename(temporary)
            parked.append((path, temporary))
        with scoped(store) as (auth, _):
            assert auth.records[-1] == retired_resource_cohort.admitted
            assert all(str(path) not in auth.files for path in sources)
            assert all(str(member.root / inputs.APPLICATION_MANIFEST) in auth.files
                       and str(member.root / inputs.INPUT_PLAN) in auth.files
                       for member in c.stores.values())
            with cohorts.capture_records_scope(c.parent, writer_root=store.root, latest_only=True) as records:
                assert records == [retired_resource_cohort.admitted]
        assert c.original.old_receipt.read_bytes() == retired_resource_cohort.old_receipt
    finally:
        for path, temporary in reversed(parked):
            temporary.rename(path)


@pytest.mark.parametrize("field", ["prior_accepted_snapshot", "resource_retirement"])
def test_retirement_manifests_keep_exact_raw_hash_not_only_equivalent_json(retired_resource_cohort, field):
    c = retired_resource_cohort.prepared
    ref = retired_resource_cohort.admitted[field]
    path = c.parent._relative(ref["path"]); raw = path.read_bytes()
    try:
        path.chmod(0o600); path.write_bytes(raw + b" "); path.chmod(0o444)
        # The JSON value and all receipt references remain identical. The bound
        # immutable file bytes do not, so no authority can survive this edit.
        with pytest.raises(ValueError, match="snapshot changed|historical rows"):
            epochs._records(c.parent)
    finally:
        path.chmod(0o600); path.write_bytes(raw); path.chmod(0o444)
    assert epochs._records(c.parent)[-1] == retired_resource_cohort.admitted


@pytest.mark.parametrize("mutation", ["partial5", "other-class", "mixed-manifest", "carry-credit"])
def test_invalid_resource_retirement_never_publishes_or_changes_old_history(prepared_resource_cohort, tmp_path, mutation):
    c = prepared_resource_cohort
    before = deepcopy(epochs._records(c.parent)[-1]); raw = c.original.old_receipt.read_bytes()
    def mutate(value):
        if mutation == "partial5": value["affected"].pop()
        elif mutation == "other-class": value["hostname"] = "alpha.example"
        elif mutation == "mixed-manifest": value["affected"][0]["replacement"]["definition"]["workload_sha256"] = "e" * 64
        else: value["target_eligible_count_after_retirement"] += value["retired_target_count"]
    path, digest = declaration(c, tmp_path / "refused-retirement.json", mutate=mutate)
    with pytest.raises(ValueError):
        cohorts.create_resource_version(c.parent.root, path, digest)
    assert epochs._records(c.parent)[-1] == before
    assert c.original.old_receipt.read_bytes() == raw and c.original.old.status()["accepted_count"] == 1
    assert all(not (store.root / cohorts.MARKER).exists() for store in c.stores.values())
