"""Authentic healthy graph metadata; raw/deep/installation are controlled boundaries.

These controls run the real condition/subgroup/graph/cap joins and grant no
qualification, readiness, traffic, installed equivalence or formal credit.
The optional held HOST files are opened by exact full SHA and permission mode.
"""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from qcsd_lab import application_response_policy as app
from qcsd_lab import rapid_capture_plan as plan
from qcsd_lab import rapid_enrolled_subgroup as subgroup
from qcsd_lab import rapid_fixed_condition_target as target
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_ordinary_group_canary as group
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_readiness as readiness
from qcsd_lab import rapid_rolling_schedule as runtime_reader
from qcsd_lab import rapid_selected_capture_input as selected_input
from qcsd_lab import rapid_target_chunks as chunks


HOST_ROOT = Path(__file__).resolve().parents[2]
ENROLLMENT = ("diagnostic-rehearsals/selected-additive-classes007-011-root-actual-20261005-001/study/batches/b0004/enrollment.json",
    "997af2b52f5525ed61484fee7661bd0cf1312cc35aa3a73a0e3b0bddd79afc84", 0o600)
TARGET = ("diagnostic-rehearsals/per-mode-native-epochs-class35-source36-root-actual-20261007-002/repaired-fixed-target.json",
    "f784eaaeab740b5c4cd631999dcd11cf704fc9e7307d5bd6fff8ae334d32fede", 0o600)
CONDITION = ("diagnostic-rehearsals/fixed-five-current-frontv4-tam8192-buflo200-condition-publication-after-repair-20261006-001/conditions/undefended-condition.json",
    "d6364b415320e332bb26b46b594747ab1fb729249fd4f0510efa94955bb02985", 0o600)
CLIENT = ("diagnostic-rehearsals/rapid-v36-cs-tam-repaired-native-runtime-20261007-001/runtime-export/neqo-qcsd-client",
    "2c9f170e1e087d116a66571e2637e605967352501131ba9a4ef0052d19321dac", 0o555)
GRAPHS = (
    ("static-073ff221d388482a832f882e0e5a986984dea546adaa39fa0e344d74d5b9b485",
     "ad3344124b396de5b890c19065de42cb5bbba7786d6359b632b9c7aa6a10c518", 201),
    ("static-8e68166a375c91d5bf7666ec6c2deb8a30c7d3a452e34cf107263ce465466da9",
     "60faaf41f688b159f6ca763597e9780f6bc2b0ebf7581aa7cb3c9bdbcd3a50e4", 38),
)
GRAPH_ROOT = "diagnostic-rehearsals/selected-additive-classes012-016-v27-root-actual-20261006-001/prepared-workloads"
NATIVE = "818d89398a5b0bc725e424b648d878185d18125d"
IDENTITY = "503a3e65d5f6f8a578150fa0dcd2ff7b2ff65bf0d812136b5cc6501dc37404db"


def pinned(root, record):
    relative, digest, mode = record
    path = root / relative
    if not path.exists():
        pytest.skip("authentic ordinary subgroup HOST facts are unavailable")
    if (not path.is_file() or any(p.is_symlink() for p in (path, *path.parents))
            or path.stat().st_mode & 0o7777 != mode
            or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
        pytest.fail("authentic ordinary subgroup HOST reference changed: " + relative)
    return path


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = Path(os.environ.get("QCSD_ORDINARY_SUBGROUP_HOST_ROOT", str(HOST_ROOT))).absolute()
    original_enrollment = pinned(root, ENROLLMENT)
    original_target = json.loads(pinned(root, TARGET).read_bytes())["payload"]
    original_condition = json.loads(pinned(root, CONDITION).read_bytes())["payload"]
    client = pinned(root, CLIENT)
    enrollment = tmp_path / "original-enrollment.json"
    enrollment.write_bytes(original_enrollment.read_bytes())
    batch = json.loads(enrollment.read_bytes())["payload"]
    # This is the exact original _chosen class-record shape, derived from the
    # retained target's unchanged fields. Original admission traversal is a
    # controlled boundary; the real closed subgroup validator runs below.
    fields = ("candidate_id", "terminal", "admission_root", "class_index",
              "primary_origin", "workload_id", "canonical_sites", "capture_input", "prepared_workload")
    classes = [{key: deepcopy(row[key]) for key in fields} for row in original_target["classes"]
               if 12 <= row["class_index"] <= 16]
    authority = subgroup.declare(enrollment, batch, classes, [12, 13])
    workloads = tmp_path / "workloads"
    workloads.mkdir()
    sites = []
    for (identifier, digest, count), row in zip(GRAPHS, classes):
        original = pinned(root, (GRAPH_ROOT + "/" + identifier + ".json", digest, 0o600))
        manifest = json.loads(original.read_bytes())
        assert len(manifest["resources"]) == count
        assert len({urlsplit(r["url"]).netloc for r in manifest["resources"]}) == 2
        assert app.primary_document_identity_policy(manifest) == app.VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY
        path = workloads / (identifier + ".json")
        path.write_bytes(original.read_bytes())
        sites.append(plan.Site(row["candidate_id"], identifier, digest, row["primary_origin"],
            "controlled-current-two-site-response-only", "f" * 64))
    source = {"lab_commit": "1" * 40, "lab_dirty": False, "neqo_commit": NATIVE,
        "neqo_pinned_commit": NATIVE, "neqo_dirty": False}
    source_file = tmp_path / "controlled-current-source.json"
    source_file.write_bytes(lanes._json(source))
    image = "sha256:" + "2" * 64
    runtime = {key: str(tmp_path) for key in lanes.RUNTIME_KEYS | rolling.RUNTIME_FIELDS}
    runtime.update(source_manifest=str(source_file), client_binary=str(client),
        collection_image_digest=image, execution_generation=1)
    spec = SimpleNamespace(cohort=enrollment, workload_root=workloads,
        source_manifest=source_file, client_binary=client, collection_image_digest=image,
        serializable=lambda: dict(runtime))
    caps = deepcopy(original_target["classes"][11]["capture_limits"])
    lane = plan.Lane("formal", 1, 4, "undefended", plan._campaign_name("formal", 1, 4, "undefended", 1, 6),
        tuple(s.workload_id for s in sites), 4, sites[0].qualification_set, study_version=6)
    base = {"lanes": [asdict(lane)], subgroup.FIELD: authority, "capture_limits": caps,
        "application_body_identity_policy": app.COMPLETE_APPLICATION_DELIVERY_POLICY}
    canary_plan = tmp_path / "controlled-canary-plan.json"
    canary_plan.write_bytes(lanes._json({subgroup.FIELD: authority, "controlled_raw_deep_boundary": True}))
    reference = {"schema_version": 1, "plan": rolling._ref(canary_plan)}
    identity = deepcopy(original_condition["identity"])
    configuration = {"profile": identity["profile"], "request_policies": [identity["request_policy"]],
        "defenses": [deepcopy(identity["defense"])], "application_body_identity_policy": identity["application_body_identity_policy"],
        "limits": {**caps, "max_attempts": 1}}
    run = {key: deepcopy(identity[key]) for key in
        ("resolved_configuration", "defense_parameters", "application_response_policy", "primary_document_identity_policy")}
    result = tmp_path / "controlled-original-canary-result"
    run_path = result / "accepted/sample/neqo/run.json"
    run_path.parent.mkdir(parents=True)
    run_path.write_bytes(lanes._json(run))
    experiment = result / "experiment.json"
    experiment.write_bytes(lanes._json({"configuration": configuration,
        "samples": [{"path": "accepted/sample", "state": "accepted", "defense": "undefended"}]}))
    actual_source = {**source, "image_digest": image}
    facts = {"source": actual_source, "authority_source": deepcopy(actual_source),
        "client_sha256": CLIENT[1], "traffic_hashes": target.traffic.expected(),
        "result_root": str(result), "application_body_identity_policy": app.COMPLETE_APPLICATION_DELIVERY_POLICY}
    monkeypatch.setattr(rolling, "_verify_enrollment", lambda path: (batch, classes, {}))
    monkeypatch.setattr(rolling, "require_mode_readiness", lambda *args, **kwargs: reference)
    monkeypatch.setattr(readiness, "validate_canary", lambda *args, **kwargs: facts)
    # The immutable selected GET receipt proof is a labeled primitive boundary.
    # Full prepared graph/response/coverage checks still run unchanged.
    monkeypatch.setattr(selected_input, "validate_preparation", lambda *args: {})
    return SimpleNamespace(spec=spec, sites=tuple(sites), base=base, reference=reference,
        facts=facts, run=run, run_path=run_path, configuration=configuration, experiment=experiment,
        canary_plan=canary_plan, batch=batch, classes=classes, original_target=original_target,
        identity=identity, source=source)


def condition(case):
    return chunks._condition(case.spec, case.sites, case.base, "undefended")


def test_current_schema1_subgroup_preserves_original503a_native_label_and_both_full_graphs(case):
    before = deepcopy(case.base)
    reference, identity = condition(case)
    assert reference is case.reference and reference["schema_version"] == 1
    assert identity == case.identity and target._digest(identity) == IDENTITY
    assert identity["primary_document_identity_policy"] == app.EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY
    assert case.base == before
    assert [len(json.loads((case.spec.workload_root / (s.workload_id + ".json")).read_bytes())["resources"])
            for s in case.sites] == [201, 38]


@pytest.mark.parametrize("change", ["absent", "wrong-canary", "class-record", "ordinal", "sites", "reordered"])
def test_current_subgroup_requires_exact_typed_original_enrollment_and_canary(case, change):
    condition(case)
    if change == "absent":
        del case.base[subgroup.FIELD]
    elif change == "wrong-canary":
        case.canary_plan.write_bytes(lanes._json({"controlled_wrong_subgroup": True}))
        case.reference["plan"] = rolling._ref(case.canary_plan)
    elif change == "class-record":
        case.classes[0]["prepared_workload"]["sha256"] = "0" * 64
    elif change == "ordinal":
        case.base[subgroup.FIELD]["batch_ordinal"] = 4.0
    elif change == "sites":
        case.sites = case.sites[:1]
    else:
        case.base[subgroup.FIELD]["class_indices"] = [13, 12]
    with pytest.raises(ValueError):
        condition(case)


@pytest.mark.parametrize("change", ["source", "authority-source", "client", "traffic", "body", "terminal", "native-primary", "historical"])
def test_subgroup_does_not_widen_current_measurement_or_acceptance_conditions(case, change):
    condition(case)
    if change in ("source", "authority-source"):
        key = "source" if change == "source" else "authority_source"
        case.facts[key] = {**case.facts[key], "lab_commit": "3" * 40}
    elif change == "client":
        case.facts["client_sha256"] = "0" * 64
    elif change == "traffic":
        case.facts["traffic_hashes"] = {}
    elif change == "body":
        del case.base["application_body_identity_policy"]
    elif change == "historical":
        case.reference["schema_version"] = 2
    else:
        field = "application_response_policy" if change == "terminal" else "primary_document_identity_policy"
        case.run[field] = (app.HTTP_2XX_ONLY_POLICY if change == "terminal" else app.VARIABLE_PRIMARY_DOCUMENT_IDENTITY_POLICY)
        case.run_path.write_bytes(lanes._json(case.run))
    with pytest.raises(ValueError):
        condition(case)


@pytest.mark.parametrize("change", ["bytes", "pruned-rehashed", "missing-response-rehashed"])
def test_subgroup_keeps_full_manifest_and_prepared_response_graph(case, change):
    condition(case)
    path = case.spec.workload_root / (case.sites[1].workload_id + ".json")
    value = json.loads(path.read_bytes())
    if change == "bytes":
        path.write_bytes(path.read_bytes() + b" ")
    else:
        if change == "pruned-rehashed":
            value["resources"].pop()
        else:
            value["preparation"]["expected_responses"].pop()
        path.write_bytes(lanes._json(value))
        site = case.sites[1]
        case.sites = (case.sites[0], plan.Site(site.candidate_id, site.workload_id,
            lanes._sha(path.read_bytes()), site.primary_origin, site.qualification_set, site.qualification_set_manifest_sha256))
    with pytest.raises(ValueError):
        condition(case)


def test_existing_schema5_current_group_branch_remains_unchanged(case):
    del case.base[subgroup.FIELD]
    case.reference.update(schema_version=5, artifact_type=group.TYPE)
    case.facts["ordinary_successful_group_canary"] = group.TYPE
    reference, identity = condition(case)
    assert reference["schema_version"] == 5 and identity == case.identity


def test_original_schema1_without_subgroup_retains_exact_primary_only(case):
    del case.base[subgroup.FIELD]
    for site in case.sites:
        path = case.spec.workload_root / (site.workload_id + ".json")
        value = json.loads(path.read_bytes())
        value["preparation"]["primary_document_identity_policy"] = app.EXACT_PRIMARY_DOCUMENT_IDENTITY_POLICY
        path.write_bytes(lanes._json(value))
    assert condition(case)[1] == case.identity


def test_changed_formal_cap_is_refused_before_runtime_or_policy_create(case, tmp_path, monkeypatch):
    condition(case)
    inputs = {"mode": "undefended", "maximum": 16, "inputs": {
        "ranges": [{"slot_start": 0, "slot_count": 16}], "classes": [
            {"candidate_id": s.candidate_id, "workload_id": s.workload_id} for s in case.sites],
        "condition": {"identity": case.identity}, "capture_limits": {**case.base["capture_limits"], "timeout_seconds": 121}}}
    monkeypatch.setattr(chunks, "_base", lambda spec: (case.sites, case.base))
    monkeypatch.setattr(target, "read_chunk_inputs", lambda ref: deepcopy(inputs))
    touched = []
    monkeypatch.setattr(runtime_reader, "reopen_runtime", lambda *args, **kwargs: touched.append(True))
    with pytest.raises(ValueError, match="caps"):
        chunks._derive(case.spec, {}, {})
    assert not touched
