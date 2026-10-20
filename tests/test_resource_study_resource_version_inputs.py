"""Prospective explicit-v1 input controls; no network, runtime or live credit.

The original cohort fixture discloses its synthetic raw-proof boundaries.
Initialization/lineage, immutable-file and complete-head predicates stay real.
ROOT alone runs these focused controls after the integrated source is frozen.
"""
from copy import deepcopy
import hashlib
from types import SimpleNamespace

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_lineage as lineage
from qcsd_lab import resource_study_resource_version_inputs as inputs
from qcsd_lab import resource_study_resource_versions as versions
from qcsd_lab.resource_study_inputs import MODES, canonical_json, native_manifest, sha256_file
from qcsd_lab.resource_study_native import REQUEST_HEADERS
from qcsd_lab.resource_study_store import StudyStore, _create
from tests.test_resource_study_resource_versions import proposal
from tests.test_resource_study_runtime_cohorts import cohort_campaign
from tests.test_resource_study_lineage import campaign


@pytest.fixture
def prepared_resource_cohort(cohort_campaign, tmp_path, monkeypatch, request):
    """Real v1 inputs/Store joins; explicitly synthetic preparation/GET leaves.

    No admission, membership, accounting, exclusion or write-fence predicate is
    replaced. The backend emits disclosed deterministic Native-input metadata;
    only the original live GET inspector is controlled because no network runs.
    FRONT keeps its current distinct Native stratum in a separate fresh root.
    """
    from qcsd_lab import resource_study_epochs as epochs
    c = cohort_campaign; c.append(c.fresh())
    unready_mode = getattr(request, "param", {}).get("unready_mode")
    assert unready_mode is None or unready_mode in MODES
    host = lineage.INCLUDED
    roots = {"front": tmp_path / "resource-v1-front",
             "other": tmp_path / "resource-v1-other-modes"}
    urls = [f"https://{host}/v1-controlled-resource-{index:02d}.css" for index in range(20)]
    manifest = native_manifest(host, urls, {url: 4096 + index for index, url in enumerate(urls)})
    for row in manifest["resources"]:
        row["headers"] = deepcopy(REQUEST_HEADERS)
    manifest["resources"][0]["type"] = "Document"
    application_raw = canonical_json(manifest)
    manifest_path = tmp_path / "controlled-v1-application.json"; _create(manifest_path, application_raw)
    value = {"record_type": inputs.INPUT_TYPE, "schema_version": 1, "hostname": host,
        "application_manifest": {"path": str(manifest_path), "sha256": sha256_file(manifest_path)},
        "mode_roots": [{"mode": mode, "root": str(roots["front" if mode == "front" else "other"])}
                       for mode in sorted(MODES)],
        "mode_templates": [], "scientific_credit": False}
    input_path = tmp_path / "controlled-v1-input-plan.json"; _create(input_path, canonical_json(value))
    input_sha = sha256_file(input_path)
    get_calls = []
    def synthetic_get(store, hostname, *, enrollment=None):
        # All input, lineage and immutable-file predicates have already run.
        get_calls.append((str(store.root), hostname))
    monkeypatch.setattr(epochs, "_verify_preparation", synthetic_get)
    stores = {}
    for root in roots.values():
        inputs.initialize_resource_cohort(c.parent.root, root, input_path, input_sha)
        store = StudyStore(root); context, _ = inputs.read_context(root, store.plan())
        modes = [row["mode"] for row in value["mode_roots"] if row["root"] == str(root)]
        baseline = context["baseline_enrollments"][modes[0]]
        runtime = deepcopy(baseline["runtime"])
        class SyntheticPreparation:
            def prepare(self, candidate, output, **options):
                assert options == {}  # These actual synthetic old donors have no cap/aggregate.
                base = output / "prepared"
                job = {"hostname": host, "urls": list(urls), "output": str(base), "runtime": runtime}
                _create(output / "job.json", canonical_json(job))
                _create(base / "resources.json", application_raw)
                _create(base / "prepared-workload.json", canonical_json({
                    "resources": manifest["resources"], "preparation": {"runtime": runtime,
                        "synthetic_raw_boundary": "unit-fixture; no HTTP3 GET or qualification occurred"}}))
                _create(base / "preparation-get/input.json", application_raw)
                enrolled = deepcopy(baseline)
                relative = lambda path: path.relative_to(root).as_posix()
                enrolled.update(urls=list(urls), workload_path=relative(base / "resources.json"),
                    workload_sha256=hashlib.sha256(application_raw).hexdigest(),
                    preparation_dir=relative(base),
                    paths={"manifest": relative(base / "resources.json"),
                           "prepared_workload": relative(base / "prepared-workload.json")},
                    files={relative(path): sha256_file(path) for path in base.rglob("*") if path.is_file()},
                    source_occurrences=deepcopy(candidate["source_occurrences"]))
                enrolled.pop("class_selection", None)
                enrolled.pop("runtime_cohort_input_authority", None)
                if unready_mode is not None:
                    enrolled["mode_readiness"][unready_mode] = False
                return enrolled
        result = study.enroll(root, runtime, [host], backend=SyntheticPreparation(),
            resource_version_input=input_path, resource_version_input_sha256=input_sha)
        assert result["enrollment"] == [{"hostname": host, "status": "enrolled", "resources": 20}]
        assert store.status()["accepted_count"] == 0
        stores[str(root)] = store
    return SimpleNamespace(parent=c.parent, original=c, host=host, stores=stores,
        mode_stores={row["mode"]: stores[row["root"]] for row in value["mode_roots"]},
        input_plan=value, input_path=input_path, input_sha=input_sha,
        application_raw=application_raw, get_calls=get_calls, unready_mode=unready_mode)


def input_plan(proposal, tmp_path):
    manifest = tmp_path / "new-resource-manifest.json"
    _create(manifest, proposal["application_manifest_raw"])
    return {"record_type": inputs.INPUT_TYPE, "schema_version": 1,
        "hostname": proposal["hostname"],
        "application_manifest": {"path": str(manifest), "sha256": sha256_file(manifest)},
        "mode_roots": [{"mode": mode, "root": str(tmp_path / ("fresh-" + mode))}
                       for mode in sorted(MODES)],
        "mode_templates": deepcopy(proposal["missing_mode_templates"]), "scientific_credit": False}


def test_v1_input_maps_common_new20_and_exact_absent_mode_without_claiming_old_pool(proposal, tmp_path):
    value = input_plan(proposal, tmp_path)
    original = deepcopy(proposal)
    result = inputs.validate_input_plan(value, proposal["prior"], proposal["application_manifest_raw"])
    assert proposal == original and result["input"] == value
    assert result["urls"] == proposal["replacement_cells"][0]["definition"]["urls"]
    assert set(result["baselines"]) == set(MODES)
    assert result["baselines"]["buflo"] == proposal["missing_mode_templates"][0]
    context = {**result, "context": {"input_plan_sha256": versions.digest(value),
        "application_manifest_sha256": value["application_manifest"]["sha256"]},
        "application_manifest_raw": proposal["application_manifest_raw"]}
    candidate = inputs.candidate(context)
    assert len(candidate["source_occurrences"]) == 20
    assert candidate["source_occurrences"][0]["resource_index"] == 1
    assert candidate["source_occurrences"][0]["resource"]["url"] == result["urls"][0]
    assert "source_index" not in candidate["source_occurrences"][0]
    assert "inventory_index" not in candidate["source_occurrences"][0]


def test_original_bf_cap_is_not_silently_dropped_and_aggregate_is_not_reinterpreted(tmp_path):
    from qcsd_lab.resource_study_native import BUFLO_CAPPED_SELECTION_TYPE, BUFLO_CAPPED_SELECTION_POLICY
    root = tmp_path / "old-runtime-new-resources"
    context = {"input": {"mode_roots": [{"mode": "buflo", "root": str(root)}]},
        "baseline_enrollments": {"buflo": {"mode_policies": {"buflo": {}},
            "buflo_chaff_selection": {"record_type": BUFLO_CAPPED_SELECTION_TYPE,
                "schema_version": 1, "selection_policy": BUFLO_CAPPED_SELECTION_POLICY, "cap_bytes": 65536}}}}
    assert inputs.preparation_options(context, root) == {"buflo_chaff_cap_bytes": 65536}
    context["baseline_enrollments"]["buflo"]["buflo_small_response_aggregate_selection"] = {}
    with pytest.raises(ValueError, match="aggregate donor"):
        inputs.preparation_options(context, root)


@pytest.mark.parametrize("mutation", ["one-mode", "duplicate-mode", "old-root", "wrong-host",
                                     "fake-donor", "missing-donor", "changed-sha", "credit"])
def test_v1_input_refuses_scope_provenance_and_historical_shortcuts(proposal, tmp_path, mutation):
    value = input_plan(proposal, tmp_path)
    if mutation == "one-mode": value["mode_roots"] = value["mode_roots"][:1]
    elif mutation == "duplicate-mode": value["mode_roots"][1]["mode"] = value["mode_roots"][0]["mode"]
    elif mutation == "old-root": value["mode_roots"][0]["root"] = proposal["prior"]["cells"][0]["root"]
    elif mutation == "wrong-host": value["hostname"] = "unselected.example"
    elif mutation == "fake-donor": value["mode_templates"][0]["enrollment_sha256"] = "e" * 64
    elif mutation == "missing-donor": value["mode_templates"] = []
    elif mutation == "changed-sha": value["application_manifest"]["sha256"] = "e" * 64
    else: value["scientific_credit"] = True
    with pytest.raises(ValueError):
        inputs.validate_input_plan(value, proposal["prior"], proposal["application_manifest_raw"])


def test_init_keeps_original_context_and_freezes_truthful_v1_native_and_runtime_inputs(cohort_campaign, tmp_path):
    c = cohort_campaign
    c.append(c.fresh())  # Genuine cohort admission; no legacy-V3 preparation backdoor.
    root = tmp_path / "explicit-new-resource-version"
    other_root = tmp_path / "explicit-new-resource-version-old-native"
    host = lineage.INCLUDED
    urls = [f"https://{host}/declared-v1-{index:02d}.css" for index in range(20)]
    manifest = native_manifest(host, urls, {url: 4096 + index for index, url in enumerate(urls)})
    for row in manifest["resources"]:
        row["headers"] = deepcopy(REQUEST_HEADERS)
    manifest["resources"][0]["type"] = "Document"
    path = tmp_path / "native-new20.json"; _create(path, canonical_json(manifest))
    value = {"record_type": inputs.INPUT_TYPE, "schema_version": 1, "hostname": host,
        "application_manifest": {"path": str(path), "sha256": sha256_file(path)},
        "mode_roots": [{"mode": mode, "root": str(root if mode == "front" else other_root)}
                       for mode in sorted(MODES)],
        "mode_templates": [], "scientific_credit": False}
    input_path = tmp_path / "resource-version-input.json"; _create(input_path, canonical_json(value))
    before = c.parent._file("study.json")[0]
    result = inputs.initialize_resource_cohort(c.parent.root, root, input_path, sha256_file(input_path))
    store = StudyStore(root)
    original_raw = store._file(cohorts.INPUT_CONTEXT)[0]
    context, digest = inputs.read_context(root, store.plan())
    assert result["prepared"] is result["admitted"] is result["scientific_credit"] is False
    assert store.enrolled() == [] and store.status()["accepted_count"] == 0
    assert c.parent._file("study.json")[0] == before
    assert context["context"]["original_context_sha256"] == hashlib.sha256(original_raw).hexdigest()
    assert inputs.INPUT_CONTEXT != cohorts.INPUT_CONTEXT and store._file(cohorts.INPUT_CONTEXT)[0] == original_raw
    assert context["urls"] == urls
    assert context["baseline_enrollments"]["front"]["runtime"] != context["baseline_enrollments"]["tamaraw"]["runtime"]
    assert all(context["baseline_enrollments"][mode]["runtime"] == context["baseline_enrollments"]["tamaraw"]["runtime"]
               for mode in MODES if mode != "front")
    assert store._file(inputs.INPUT_CONTEXT)[1]["sha256"] == digest
    assert all(ref["sha256"] == store._file(ref["path"])[1]["sha256"]
               for ref in context["context"]["baseline_enrollments"].values())
    altered_runtime = deepcopy(context["baseline_enrollments"]["front"]["runtime"])
    altered_runtime["collection_image_digest"] = "sha256:" + "e" * 64
    with pytest.raises(ValueError, match="exact actual old per-mode runtime"):
        inputs._runtime(context, root, altered_runtime)


def test_partial_new_input_flags_refuse_before_any_preparation(tmp_path):
    class NoPreparation:
        def prepare(self, *args, **kwargs):
            raise AssertionError("partial input must never reach preparation")
    with pytest.raises(ValueError, match="paired input flags"):
        study.enroll(tmp_path / "unused", {}, ["www.clarin.com"], backend=NoPreparation(),
                     resource_version_input=tmp_path / "missing.json")


def test_new_v1_enrollment_cannot_fall_back_to_old_pool_when_binding_is_removed(prepared_resource_cohort):
    c = prepared_resource_cohort
    store = c.mode_stores["front"]
    enrollment = store.enrolled()[0]
    lineage.validate_enrollment(store, enrollment)
    partial = deepcopy(enrollment); del partial[inputs.AUTHORITY_KEY]
    with pytest.raises(ValueError, match="partial or unsupported"):
        lineage.validate_enrollment(store, partial)
    altered = deepcopy(enrollment)
    altered["source_occurrences"] = c.original.old.enrolled()[0]["source_occurrences"]
    with pytest.raises(ValueError, match="source occurrences"):
        lineage.validate_enrollment(store, altered)


def test_v1_receipt_requires_all_exact_new_input_job_and_baseline_artifact_roles(prepared_resource_cohort):
    c = prepared_resource_cohort
    store = c.mode_stores["front"]; enrollment = store.enrolled()[0]
    paths = inputs.artifact_paths(enrollment)
    # Pure metadata envelope, deliberately not an issued scientific receipt.
    envelope = {"artifact_paths": paths,
                "files": {path: enrollment["files"][path] for path in paths.values()}}
    inputs.validate_receipt(store.root, enrollment, envelope)
    missing = deepcopy(envelope)
    del missing["artifact_paths"]["resource_version_application_manifest"]
    with pytest.raises(ValueError, match="exact resource-version preparation artifacts"):
        inputs.validate_receipt(store.root, enrollment, missing)
    changed = deepcopy(envelope)
    changed["files"][paths["resource_version_preparation_job"]] = "e" * 64
    with pytest.raises(ValueError, match="exact resource-version preparation artifacts"):
        inputs.validate_receipt(store.root, enrollment, changed)


@pytest.mark.parametrize("prepared_resource_cohort", [{"unready_mode": "front"}], indirect=True)
def test_unready_mode_does_not_veto_another_prepared_mode(prepared_resource_cohort):
    from qcsd_lab import resource_study_epochs as epochs
    c = prepared_resource_cohort
    front = epochs._cell(c.mode_stores["front"], c.host, "front")
    tamaraw = epochs._cell(c.mode_stores["tamaraw"], c.host, "tamaraw")
    assert front["definition"]["ready"] is False and tamaraw["definition"]["ready"] is True
    assert all(store.status()["accepted_count"] == 0 for store in c.stores.values())


def test_public_resource_version_cli_requires_explicit_input_pair_and_admission_declaration():
    parser = study.parser()
    parsed = parser.parse_args(["cohort-resource-template", "--root", "/parent",
        "--resource-version-input", "/input.json", "--resource-version-input-sha256", "a" * 64])
    assert parsed.action == "cohort-resource-template" and parsed.resource_version_input_sha256 == "a" * 64
    with pytest.raises(SystemExit):
        parser.parse_args(["cohort-resource-admit", "--root", "/parent"])
