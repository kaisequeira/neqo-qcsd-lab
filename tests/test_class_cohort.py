from __future__ import annotations

import copy
import json
import shutil
from collections import Counter
from pathlib import Path

import pytest
import yaml

from qcsd_lab import class_attestation as attestation
import qcsd_lab.class_cohort as cohort_module
from qcsd_lab import orchestrator, util
from qcsd_lab.experiment import (
    initialize_experiment,
    load_experiment,
    validate_planned_sample_identity,
    validate_resume_fingerprints,
)
from qcsd_lab.acquisition_selection import derive_acquisition_selection
from qcsd_lab.class_acquisition import (
    CHECKPOINT_SCHEMA_VERSION,
    COMPLETION_SCHEMA_VERSION,
    COMPLETION_TYPE,
    SCHEMA_VERSION as ACQUISITION_SCHEMA_VERSION,
    SELECTION_TYPE,
)
from qcsd_lab.class_catalogue import (
    CANDIDATE_RECEIPT_TYPE,
    CATALOGUE_SCHEMA_VERSION,
    STABILITY_PROBE_WINDOWS,
    PageCandidate,
    StabilityObservation,
    build_stability_receipt,
)
from qcsd_lab.class_campaigns import campaign_documents, validate_campaign_document
from qcsd_lab.class_layout import require_cohort_publication_roots
from qcsd_lab.class_cohort import (
    ASSEMBLY_RECEIPT_TYPE,
    FINAL_SELECTION_RECEIPT_TYPE,
    FINAL_SELECTION_SCHEMA_VERSION,
    _candidate_evidence,
    _final_selection_binding,
    _reconcile_acquisition_terminal,
    build_evidenced_cohort,
    publish_evidenced_cohort,
    validate_cohort_assembly,
    validate_cohort_assembly_receipt,
)
from qcsd_lab.class_pipeline import verify_cohort_admission
from qcsd_lab.class_study import (
    CANDIDATE_COUNT,
    CANDIDATES_PER_STRATUM,
    STUDY_ID,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    bind_receipt,
    canonical_json_bytes,
    canonical_json_sha256,
    deterministic_candidate_order,
    validate_hash_bound_receipt,
)
from qcsd_lab.util import sha256_file
from tests.test_class_campaign_execution import _complete_two_origin_workload

LIST_SHA = "a" * 64


def _candidates() -> tuple[ClassCandidate, ...]:
    return deterministic_candidate_order(
        (
            ClassCandidate(
                candidate_id=f"class-{stratum_index}-{offset:02d}",
                domain=f"site-{stratum_index}-{offset:02d}.example",
                rank=stratum.minimum_rank + offset,
                eligible=False,
            )
            for stratum_index, stratum in enumerate(TRANCO_RANK_STRATA)
            for offset in range(CANDIDATES_PER_STRATUM)
        ),
        tranco_list_sha256=LIST_SHA,
    )


def _catalogue(path: Path) -> Path:
    candidates = _candidates()
    value = bind_receipt(
        {
            "study_id": STUDY_ID,
            "catalogue_schema_version": CATALOGUE_SCHEMA_VERSION,
            "tranco": {
                "list_id": "TEST1",
                "list_sha256": LIST_SHA,
                "source_url": "https://tranco-list.eu/download/TEST1/1000000",
                "retrieved_at": "2026-08-28T00:00:00Z",
                "row_count": 1_000_000,
                "entries_sha256": "b" * 64,
            },
            "selection": {
                "rank_strata": [stratum.as_dict() for stratum in TRANCO_RANK_STRATA],
                "per_stratum": CANDIDATES_PER_STRATUM,
                "ordering": "sha256(list_sha256 || study_id || canonical_domain)",
                "outcome_fields_used": [],
            },
            "candidates": [candidate.as_dict() for candidate in candidates],
        },
        receipt_type=CANDIDATE_RECEIPT_TYPE,
    )
    path.write_bytes(canonical_json_bytes(value))
    return path


def _completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, prefix: bool = False
) -> Path:
    """Synthetic validated input boundary, not an acquisition gate pass.

    Acquisition completion reconstruction is tested in test_class_acquisition;
    this fixture isolates cohort rebuild and its terminal/selection joins.
    """
    payload: dict[str, object] = {
        "acquisition_schema_version": ACQUISITION_SCHEMA_VERSION,
        "completion_schema_version": COMPLETION_SCHEMA_VERSION,
        "checkpoint_schema_version": CHECKPOINT_SCHEMA_VERSION,
        "provenance_sha256": "1" * 64,
        "terminal_receipts": {},
    }
    candidates = _candidates()
    if prefix:
        eligible = {
            candidate.candidate_id: True
            for stratum in TRANCO_RANK_STRATA
            for candidate in [
                item for item in candidates
                if stratum.minimum_rank <= item.rank <= stratum.maximum_rank
            ][:24]
        }
        selection = derive_acquisition_selection(
            candidates,
            tranco_list_sha256=LIST_SHA,
            terminal_eligibility=eligible,
        )
    else:
        selected = {
            candidate.candidate_id
            for stratum in TRANCO_RANK_STRATA
            for candidate in [
                item
                for item in candidates
                if stratum.minimum_rank <= item.rank <= stratum.maximum_rank
            ][:24]
        }
        selection = {
            "complete": True,
            "needed_ids": [],
            "pilot_ids": [
                candidate.candidate_id
                for candidate in candidates
                if candidate.candidate_id in selected
            ],
            "terminal_ids": [candidate.candidate_id for candidate in candidates],
            "unassessed_ids": [],
        }
    payload.update(
        {
            "selection": bind_receipt(
                selection,
                receipt_type=SELECTION_TYPE,
            ),
        }
    )
    root = tmp_path / "acquisition"
    root.mkdir(exist_ok=True)
    path = root / "completion.json"
    path.write_bytes(canonical_json_bytes(bind_receipt(payload, receipt_type=COMPLETION_TYPE)))
    monkeypatch.setattr(
        cohort_module,
        "validate_acquisition_completion",
        lambda value, **_kwargs: validate_hash_bound_receipt(value, expected_type=COMPLETION_TYPE),
    )
    monkeypatch.setattr(
        cohort_module,
        "_validate_current_completion_authority",
        lambda *_args, **_kwargs: None,
    )
    # These synthetic bridge fixtures use arbitrary temporary directories.
    # The production layout check is exercised independently below.
    monkeypatch.setattr(
        cohort_module,
        "require_cohort_publication_roots",
        lambda *_args, **_kwargs: (None, None),
    )
    return path


@pytest.mark.parametrize(
    ("acquisition_schema", "completion_schema", "checkpoint_schema"),
    (
        (6, 3, 2),
        (ACQUISITION_SCHEMA_VERSION, 3, CHECKPOINT_SCHEMA_VERSION),
        (6, COMPLETION_SCHEMA_VERSION, CHECKPOINT_SCHEMA_VERSION),
        (ACQUISITION_SCHEMA_VERSION, COMPLETION_SCHEMA_VERSION, 2),
    ),
)
def test_current_cohort_publication_rejects_historical_acquisition_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    acquisition_schema: int,
    completion_schema: int,
    checkpoint_schema: int,
) -> None:
    catalogue = _catalogue(tmp_path / "candidates.json")
    completion = _completion(tmp_path, monkeypatch)
    value = json.loads(completion.read_text())
    value["payload"]["acquisition_schema_version"] = acquisition_schema
    value["payload"]["completion_schema_version"] = completion_schema
    value["payload"]["checkpoint_schema_version"] = checkpoint_schema
    completion.write_bytes(
        canonical_json_bytes(bind_receipt(value["payload"], receipt_type=COMPLETION_TYPE))
    )
    stability = tmp_path / "stability"
    workloads = tmp_path / "workloads"
    stability.mkdir()
    workloads.mkdir()
    monkeypatch.setattr(
        cohort_module,
        "_candidate_acquisition_evidence",
        lambda *_a, **_k: pytest.fail("historical completion reached cohort evidence"),
    )

    with pytest.raises(ValueError, match="current acquisition, completion and checkpoint"):
        build_evidenced_cohort(
            catalogue,
            stability_root=stability,
            workload_root=workloads,
            acquisition_completion_path=completion,
        )


def test_direct_cohort_publication_deep_rejects_v96_acquisition_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deep_validator = cohort_module._validate_current_completion_authority
    catalogue = _catalogue(tmp_path / "candidates.json")
    completion = _completion(tmp_path, monkeypatch)
    monkeypatch.setattr(
        cohort_module,
        "_validate_current_completion_authority",
        deep_validator,
    )
    authority_path = tmp_path / "acquisition-authority-v96.json"
    authority_path.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                {"fixture": "historical-v96-schema14"},
                receipt_type=attestation.ACQUISITION_AUTHORITY_RECEIPT_TYPE,
            )
        )
    )
    provenance_path = completion.parent / "provenance.json"
    provenance_path.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                {
                    "acquisition_schema_version": ACQUISITION_SCHEMA_VERSION,
                    "acquisition_authority": {
                        "path": str(authority_path.resolve()),
                        "sha256": sha256_file(authority_path),
                    },
                },
                receipt_type=attestation.ACQUISITION_PROVENANCE_TYPE,
            )
        )
    )
    completion_value = json.loads(completion.read_text())
    completion_payload = completion_value["payload"]
    completion_payload["checkpoint_schema_version"] = CHECKPOINT_SCHEMA_VERSION
    completion_payload["provenance_sha256"] = sha256_file(provenance_path)
    completion.write_bytes(
        canonical_json_bytes(bind_receipt(completion_payload, receipt_type=COMPLETION_TYPE))
    )
    stability = tmp_path / "stability"
    workloads = tmp_path / "workloads"
    stability.mkdir()
    workloads.mkdir()

    def reject_historical(path: Path, **kwargs: object) -> dict[str, object]:
        assert path == authority_path.resolve()
        assert kwargs == {"runtime_role": None, "allow_historical": False}
        raise ValueError("historical v96 schema14 authority is verify-only")

    monkeypatch.setattr(
        attestation,
        "validate_class_acquisition_authority",
        reject_historical,
    )
    monkeypatch.setattr(
        cohort_module,
        "_candidate_acquisition_evidence",
        lambda *_a, **_k: pytest.fail("historical authority reached cohort evidence"),
    )

    with pytest.raises(ValueError, match="historical v96 schema14.*verify-only"):
        build_evidenced_cohort(
            catalogue,
            stability_root=stability,
            workload_root=workloads,
            acquisition_completion_path=completion,
        )


def _eligible_evidence(candidate: ClassCandidate, **_kwargs: object):
    page = PageCandidate(
        candidate_domain=candidate.domain,
        registrable_domain=candidate.domain,
        url=f"https://{candidate.domain}/",
        source="canonical-homepage",
        ordinal=0,
        discovery_content_type=None,
    )
    return True, {
        "candidate_id": candidate.candidate_id,
        "eligible": True,
        "selected_page": page.as_dict(),
        "stability_receipt": {
            "path": f"{candidate.candidate_id}/page-00.json",
            "sha256": "c" * 64,
            "payload_sha256": "e" * 64,
        },
        "prepared_workload": {
            "path": f"{candidate.candidate_id}.json",
            "sha256": "d" * 64,
        },
        "reasons": [],
    }


def test_assembly_is_exactly_rebuilt_and_publication_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalogue = _catalogue(tmp_path / "candidates.json")
    stability = tmp_path / "stability"
    workloads = tmp_path / "workloads"
    output = tmp_path / "output"
    stability.mkdir()
    workloads.mkdir()
    output.mkdir()
    completion = _completion(tmp_path, monkeypatch)
    monkeypatch.setattr(cohort_module, "_candidate_evidence", _eligible_evidence)
    # This test exercises exact assembly rebuild/publication with synthetic
    # candidate evidence.  Acquisition lineage itself is covered separately.
    monkeypatch.setattr(
        cohort_module, "_reconcile_acquisition_terminal", lambda *_a, **_k: None
    )

    cohort, assembly = build_evidenced_cohort(
        catalogue,
        stability_root=stability,
        workload_root=workloads,
        acquisition_completion_path=completion,
    )
    assert assembly["receipt_type"] == ASSEMBLY_RECEIPT_TYPE
    assert assembly["payload"]["eligible_count"] == CANDIDATE_COUNT
    assert assembly["payload"]["selected_evidence_count"] == 120
    assert assembly["payload"]["final_selection"] is None
    validate_cohort_assembly(
        assembly,
        cohort=cohort,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=workloads,
        acquisition_completion_path=completion,
    )

    destinations = publish_evidenced_cohort(
        output / "cohort.json",
        output / "assembly.json",
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=workloads,
        acquisition_completion_path=completion,
    )
    assert all(path.is_file() for path in destinations)
    assert destinations == publish_evidenced_cohort(
        output / "cohort.json",
        output / "assembly.json",
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=workloads,
        acquisition_completion_path=completion,
    )

    changed = copy.deepcopy(assembly)
    changed["payload"]["eligible_count"] = CANDIDATE_COUNT - 1
    changed = bind_receipt(changed["payload"], receipt_type=ASSEMBLY_RECEIPT_TYPE)
    with pytest.raises(ValueError, match="counts|differs"):
        validate_cohort_assembly(
            changed,
            cohort=cohort,
            candidate_catalogue_path=catalogue,
            stability_root=stability,
            workload_root=workloads,
            acquisition_completion_path=completion,
        )


def test_completed_prefix_builds_120_class_pilot_without_failing_unused_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalogue = _catalogue(tmp_path / "candidates.json")
    stability = tmp_path / "stability"
    workloads = tmp_path / "workloads"
    stability.mkdir()
    workloads.mkdir()
    completion = _completion(tmp_path, monkeypatch, prefix=True)
    payload = json.loads(completion.read_text())["payload"]
    prefix = payload["selection"]["payload"]
    terminal_root = completion.parent / "terminals"
    terminal_root.mkdir()
    for candidate_id in prefix["terminal_ids"]:
        terminal = bind_receipt(
            {
                "candidate_id": candidate_id,
                "kind": "eligible",
                "stability_receipt": {
                    "path": str(stability / candidate_id / "page-00.json"),
                    "sha256": "c" * 64,
                },
                "admitted_workload": {
                    "path": str(workloads / f"{candidate_id}.json"),
                    "sha256": "d" * 64,
                },
            },
            receipt_type="qcsd-class-study-acquisition-terminal",
        )
        path = terminal_root / f"{candidate_id}.json"
        path.write_bytes(canonical_json_bytes(terminal))
        payload["terminal_receipts"][candidate_id] = {
            "path": f"terminals/{candidate_id}.json",
            "sha256": sha256_file(path),
        }
    completion.write_bytes(canonical_json_bytes(bind_receipt(payload, receipt_type=COMPLETION_TYPE)))
    monkeypatch.setattr(cohort_module, "_candidate_evidence", _eligible_evidence)
    cohort, assembly = build_evidenced_cohort(
        catalogue, stability_root=stability, workload_root=workloads,
        acquisition_completion_path=completion,
    )
    assert assembly["payload"]["eligible_count"] == 120
    assert assembly["payload"]["selected_evidence_count"] == 120
    tail = [row for row in assembly["payload"]["candidates"] if not row["eligible"]]
    assert len(tail) == 480
    assert all(row["reasons"] == ["unassessed-deterministic-prefix-tail"] for row in tail)
    assert set(row["candidate_id"] for row in tail) == set(prefix["unassessed_ids"])
    validate_cohort_assembly(
        assembly, cohort=cohort, candidate_catalogue_path=catalogue,
        stability_root=stability, workload_root=workloads,
        acquisition_completion_path=completion,
    )
    # Continue the synthetic completion into the real downstream admission
    # and deterministic campaign planners.  The fixture stubs live acquisition
    # and prepared workloads above, so this grants no scientific credit.
    cohort_path = tmp_path / "pilot-cohort.json"
    assembly_path = tmp_path / "pilot-assembly.json"
    cohort_path.write_bytes(canonical_json_bytes(cohort))
    assembly_path.write_bytes(canonical_json_bytes(assembly))
    admission = verify_cohort_admission(
        cohort_path,
        assembly_path,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=workloads,
        acquisition_completion_path=completion,
    )
    assert len(admission.selection.pilot) == 120
    assert len(admission.prepared_workload_sha256) == 120
    assert admission.acquisition_completion_sha256 == sha256_file(completion)
    documents = campaign_documents(
        cohort_path,
        cohort_assembly_receipt=assembly_path,
        cohort_reference="pilot-cohort.json",
        cohort_assembly_reference="pilot-assembly.json",
        _enforce_fresh_layout=False,
    )
    for role, samples in (("pilot-fitting", 480), ("pilot-compatibility", 1080)):
        document = next(item for item in documents.values() if item["evidence_role"] == role)
        assert validate_campaign_document(
            document,
            cohort_receipt=cohort_path,
            cohort_assembly_receipt=assembly_path,
            enforce_fresh_layout=False,
        ) == f"{document['name']}.yml"
        assert tuple(document["workloads"]) == tuple(
            candidate.candidate_id for candidate in admission.selection.pilot
        )
        assert (
            sum(document["workloads"].values())
            * len(document["request_policies"])
            * len(document["defenses"])
        ) == samples
    # A new publication in an explicitly unassessed tail cannot be silently
    # ignored, even when candidate evidence lookup is stubbed for this test.
    (workloads / f"{tail[0]['candidate_id']}.json").write_text("{}")
    with pytest.raises(ValueError, match="unassessed.*published evidence"):
        build_evidenced_cohort(
            catalogue, stability_root=stability, workload_root=workloads,
            acquisition_completion_path=completion,
        )


def _synthetic_acquisition_prefix_loaded_pilot_campaign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Construct a zero-credit pilot from synthetic terminal and workload inputs."""
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    catalogue = _catalogue(tmp_path / "candidates.json")
    completion = _completion(tmp_path, monkeypatch, prefix=True)
    acquisition_root = (
        tmp_path / "artifacts" / f"{STUDY_ID}-acquisition-v130"
    )
    acquisition_root.mkdir(parents=True)
    completion = completion.replace(acquisition_root / "completion.json")
    monkeypatch.setattr(
        cohort_module, "require_cohort_publication_roots", require_cohort_publication_roots
    )
    payload = json.loads(completion.read_text())["payload"]
    pilot_ids = tuple(payload["selection"]["payload"]["pilot_ids"])
    stability = tmp_path / "artifacts" / f"{STUDY_ID}-stability-v130"
    stability.mkdir()
    workload_root = tmp_path / "config" / "workloads-v130"
    workload_root.mkdir(parents=True)
    generated = tmp_path / "generated-workloads"
    generated.mkdir()
    workload_hashes = {}
    for candidate_id in pilot_ids:
        complete = _complete_two_origin_workload(
            generated, visits=2, workload_id=candidate_id
        )
        workload_path = workload_root / f"{candidate_id}.json"
        workload_path.write_bytes(complete.source_bytes)
        workload_hashes[candidate_id] = sha256_file(workload_path)

    terminals = completion.parent / "terminals"
    terminals.mkdir()
    for candidate_id in payload["selection"]["payload"]["terminal_ids"]:
        terminal = bind_receipt(
            {
                "candidate_id": candidate_id,
                "kind": "eligible",
                "stability_receipt": {
                    "path": str(stability / candidate_id / "page-00.json"),
                    "sha256": "c" * 64,
                },
                "admitted_workload": {
                    "path": str(workload_root / f"{candidate_id}.json"),
                    "sha256": workload_hashes[candidate_id],
                },
            },
            receipt_type="qcsd-class-study-acquisition-terminal",
        )
        path = terminals / f"{candidate_id}.json"
        path.write_bytes(canonical_json_bytes(terminal))
        payload["terminal_receipts"][candidate_id] = {
            "path": f"terminals/{candidate_id}.json",
            "sha256": sha256_file(path),
        }
    completion.write_bytes(canonical_json_bytes(bind_receipt(payload, receipt_type=COMPLETION_TYPE)))

    def synthetic_evidence(candidate: ClassCandidate, **_kwargs: object):
        eligible, evidence = _eligible_evidence(candidate)
        evidence["prepared_workload"]["sha256"] = workload_hashes[candidate.candidate_id]
        return eligible, evidence

    monkeypatch.setattr(cohort_module, "_candidate_evidence", synthetic_evidence)
    wrong_workload_root = tmp_path / "config" / "workloads-v131"
    wrong_workload_root.mkdir()
    with pytest.raises(ValueError, match="do not match the acquisition cohort"):
        build_evidenced_cohort(
            catalogue,
            stability_root=stability,
            workload_root=wrong_workload_root,
            acquisition_completion_path=completion,
        )
    cohort, assembly = build_evidenced_cohort(
        catalogue,
        stability_root=stability,
        workload_root=workload_root,
        acquisition_completion_path=completion,
    )
    study_root = tmp_path / "config" / "class-study" / "v1"
    study_root.mkdir(parents=True)
    cohort_path = study_root / "classifier-multiorigin100-v1-pilot-cohort.json"
    assembly_path = study_root / "classifier-multiorigin100-v1-pilot-cohort-assembly.json"
    cohort_path.write_bytes(canonical_json_bytes(cohort))
    assembly_path.write_bytes(canonical_json_bytes(assembly))
    admission = verify_cohort_admission(
        cohort_path,
        assembly_path,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=workload_root,
        acquisition_completion_path=completion,
    )
    assert tuple(candidate.candidate_id for candidate in admission.selection.pilot) == pilot_ids
    assert admission.prepared_workload_sha256 == workload_hashes

    documents = campaign_documents(
        cohort_path,
        cohort_assembly_receipt=assembly_path,
        cohort_reference="../class-study/v1/" + cohort_path.name,
        cohort_assembly_reference="../class-study/v1/" + assembly_path.name,
    )
    name = "classifier-multiorigin100-v1-pilot-fitting-1200.yml"
    document = documents[name]
    campaign_root = tmp_path / "config" / "classifier-multiorigin100-v1-campaigns"
    campaign_root.mkdir()
    campaign_path = campaign_root / name
    campaign_path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    campaign = orchestrator.load_campaign(campaign_path)
    return campaign, admission, cohort_path, assembly_path, workload_root


def test_synthetic_acquisition_prefix_reaches_loaded_pilot_capture_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise the downstream wiring without creating scientific evidence."""
    campaign, admission, cohort_path, assembly_path, workload_root = (
        _synthetic_acquisition_prefix_loaded_pilot_campaign(tmp_path, monkeypatch)
    )
    pilot_ids = tuple(candidate.candidate_id for candidate in admission.selection.pilot)
    plan = orchestrator.plan_campaign(campaign)
    assert len(plan) == 480
    assert tuple(workload.id for workload in campaign.workloads) == pilot_ids
    assert {workload.origin_count for workload in campaign.workloads} == {2}
    assert Counter((item["workload_id"], item["request_policy"]) for item in plan) == Counter(
        {(candidate_id, policy): 2 for candidate_id in pilot_ids for policy in ("as-defined", "half-duplex")}
    )
    original_assembly = json.loads(assembly_path.read_text(encoding="utf-8"))
    swapped = copy.deepcopy(original_assembly["payload"])
    swapped["workload_root"] = "workloads-v131"
    with pytest.raises(ValueError, match="publication root versions differ"):
        validate_cohort_assembly_receipt(
            bind_receipt(swapped, receipt_type=ASSEMBLY_RECEIPT_TYPE),
            cohort=json.loads(cohort_path.read_text(encoding="utf-8")),
        )
    swapped["stability_root"] = f"{STUDY_ID}-stability-v131"
    wrong_assembly = assembly_path.with_name("wrong-version-assembly.json")
    wrong_assembly.write_bytes(
        canonical_json_bytes(bind_receipt(swapped, receipt_type=ASSEMBLY_RECEIPT_TYPE))
    )
    wrong_workload_root = workload_root.with_name("workloads-v131")
    (tmp_path / "artifacts" / f"{STUDY_ID}-acquisition-v131").mkdir()
    shutil.copy2(
        workload_root / f"{pilot_ids[0]}.json",
        wrong_workload_root / f"{pilot_ids[0]}.json",
    )
    document = yaml.safe_load(campaign.path.read_text(encoding="utf-8"))
    document["class_study_cohort_assembly"] = (
        "../class-study/v1/" + wrong_assembly.name
    )
    campaign.path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="cohort acquisition completion"):
        orchestrator.load_campaign(campaign.path)


def test_synthetic_pilot_plan_reaches_durable_checkpoint_and_resume_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Check the real checkpoint consumer without claiming a capture or fitting result."""
    campaign, admission, cohort_path, assembly_path, _workload_root = (
        _synthetic_acquisition_prefix_loaded_pilot_campaign(tmp_path, monkeypatch)
    )
    plan = orchestrator.plan_campaign(campaign)
    root = tmp_path / "diagnostic-results" / campaign.name / "rehearsal-001"
    inputs = root / "inputs"
    frozen_workloads = inputs / "workloads"
    frozen_workloads.mkdir(parents=True)
    (inputs / "campaign.yml").write_bytes(campaign.source_bytes)
    (inputs / "pilot-cohort.json").write_bytes(cohort_path.read_bytes())
    (inputs / "pilot-assembly.json").write_bytes(assembly_path.read_bytes())
    for workload in campaign.workloads:
        (frozen_workloads / f"{workload.id}.json").write_bytes(workload.source_bytes)

    configuration = {
        "campaign_sha256": sha256_file(inputs / "campaign.yml"),
        "profile": campaign.profile,
        "request_policies": list(campaign.request_policies),
        "workloads": [
            {"id": workload.id, "sha256": workload.sha256}
            for workload in campaign.workloads
        ],
        "defenses": [
            {"name": defense.name, "kind": defense.kind, "baseline": defense.baseline}
            for defense in campaign.defenses
        ],
        "limits": campaign.limits.as_dict(),
        "evidence_role": campaign.evidence_role,
        "class_study_cohort_sha256": admission.cohort_sha256,
        "class_study_cohort_assembly_sha256": admission.assembly_sha256,
        "class_study_id": STUDY_ID,
        # Diagnostic placeholders satisfy checkpoint shape only; neither is
        # a class launch claim or a verified foundation attestation.
        "class_study_launch_sha256": "e" * 64,
        "class_study_foundation_sha256": "f" * 64,
        "public_origin_policy": {
            "environment": "QCSD_PUBLIC_ORIGIN_ONLY",
            "required_value": "1",
            "resolution": "resolve-once-reject-any-non-public-connect-exact-address",
        },
    }
    source = {"diagnostic": "synthetic-no-scientific-credit"}
    checkpoint = initialize_experiment(
        root,
        name=campaign.name,
        purpose=campaign.purpose,
        run_id=root.name,
        source=source,
        configuration=configuration,
        samples=plan,
        started_at="2026-10-01T00:00:00+00:00",
    )
    loaded = load_experiment(root)
    assert loaded == checkpoint
    assert loaded["summary"] == {
        "planned": 480,
        "accepted": 0,
        "failed": 0,
        "eligible": 0,
        "passed": False,
    }
    assert loaded["configuration"]["class_study_cohort_sha256"] == admission.cohort_sha256
    assert loaded["configuration"]["class_study_cohort_assembly_sha256"] == admission.assembly_sha256
    validate_planned_sample_identity(loaded, plan)
    assert validate_resume_fingerprints(root, expected_source=source) == loaded["input_digest"]

    frozen = frozen_workloads / f"{campaign.workloads[0].id}.json"
    frozen.write_bytes(frozen.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="input fingerprint mismatch"):
        validate_resume_fingerprints(root, expected_source=source)


@pytest.mark.parametrize("mutation", ["terminal", "eligibility", "rejection", "stability"])
def test_unassessed_tail_cannot_be_relabelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    completion = _completion(tmp_path, monkeypatch, prefix=True)
    payload = json.loads(completion.read_text())["payload"]
    candidate_id = payload["selection"]["payload"]["unassessed_ids"][0]
    record = cohort_module._unassessed_record(candidate_id)
    stability = tmp_path / "stability"
    workloads = tmp_path / "workloads"
    stability.mkdir()
    workloads.mkdir()
    if mutation == "terminal":
        payload["terminal_receipts"][candidate_id] = {"path": "made-up.json", "sha256": "a" * 64}
    elif mutation == "eligibility":
        record["eligible"] = True
    elif mutation == "rejection":
        record["reasons"] = ["site-unavailable"]
    else:
        (stability / candidate_id).mkdir()
    with pytest.raises(ValueError, match="unassessed"):
        _reconcile_acquisition_terminal(
            candidate_id, record, completion_payload=payload,
            completion_root=completion.parent, stability_root=stability,
            workload_root=workloads,
        )


def test_cohort_pilot_must_equal_completed_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    completion = _completion(tmp_path, monkeypatch, prefix=True)
    payload = json.loads(completion.read_text())["payload"]
    with pytest.raises(ValueError, match="pilot differs"):
        cohort_module._verify_selected_prefix(payload, _candidates()[:120])


def test_candidate_evidence_binds_selected_stability_and_workload_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = ClassCandidate("class-0-00", "site-0-00.example", 1, False)
    page = PageCandidate(
        candidate_domain=candidate.domain,
        registrable_domain=candidate.domain,
        url=f"https://{candidate.domain}/",
        source="canonical-homepage",
        ordinal=0,
        discovery_content_type=None,
    )
    workloads = tmp_path / "workloads"
    stability = tmp_path / "stability"
    candidate_root = stability / candidate.candidate_id
    workloads.mkdir()
    candidate_root.mkdir(parents=True)
    manifest_path = workloads / f"{candidate.candidate_id}.json"
    manifest_path.write_text('{"fixture":true}\n', encoding="utf-8")
    import hashlib

    manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    observations = tuple(
        StabilityObservation(
            probe_id=window.probe_id,
            observed_at={
                "t+30s": "2026-08-28T00:00:30Z",
                "t+24h": "2026-08-29T00:00:00Z",
                "t+72h": "2026-08-31T00:00:00Z",
            }[window.probe_id],
            elapsed_ms=window.target_ms,
            final_url=page.url,
            status=200,
            content_type="text/html",
            body_bytes=100,
            body_sha256="e" * 64,
            resource_graph_sha256="f" * 64,
            prepared_workload_sha256=manifest_sha,
        )
        for window in STABILITY_PROBE_WINDOWS
    )
    receipt = build_stability_receipt(
        candidate,
        page,
        tranco_list_id="TEST1",
        tranco_list_sha256=LIST_SHA,
        baseline_started_at="2026-08-28T00:00:00Z",
        observations=observations,
    )
    (candidate_root / "page-00.json").write_bytes(canonical_json_bytes(receipt))
    checked: list[str] = []
    monkeypatch.setattr(
        cohort_module,
        "validate_class_study_preparation",
        lambda _manifest, *, workload_id: checked.append(workload_id),
    )

    eligible, evidence = _candidate_evidence(
        candidate,
        stability_root=stability,
        workload_root=workloads,
        tranco={"list_id": "TEST1", "list_sha256": LIST_SHA},
    )
    assert eligible
    assert checked == [candidate.candidate_id]
    assert evidence["prepared_workload"]["sha256"] == manifest_sha
    manifest_path.write_text(json.dumps({"fixture": False}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="differs"):
        _candidate_evidence(
            candidate,
            stability_root=stability,
            workload_root=workloads,
            tranco={"list_id": "TEST1", "list_sha256": LIST_SHA},
        )


def _pair_evidence(left: str, right: str, *, marker: int) -> dict[str, object]:
    digest = f"{marker:x}" * 64
    return {
        "left": left,
        "right": right,
        "runtime_profile_real": right,
        "runtime_profile_decoy": left,
        "runtime_profile_sha256": digest,
        "endpoint_qualification": [
            {
                "workload_id": workload_id,
                "chaff_qualification_sidecar_sha256": digest,
                "prefix_pack_spec_sha256": digest,
                "qualified_chaff_manifest_sha256": digest,
                "qualified_parallel_chaff_streams": 8,
                "walkie_talkie_required_chaff_streams": 6,
            }
            for workload_id in (left, right)
        ],
    }


def _pilot_selection_lineage() -> tuple[dict[str, object], dict[str, object]]:
    empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    parameters = {
        "traffic-morphing": "a" * 64,
        "wtf-pad": "b" * 64,
        "walkie-talkie": "c" * 64,
    }
    collection_source = {
        "image_digest": "sha256:" + "5" * 64,
        "lab_commit": "6" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": empty,
        "neqo_commit": "7" * 40,
        "neqo_pinned_commit": "7" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": empty,
    }
    prepare_image = "sha256:" + "8" * 64
    authority = {
        "schema_version": 2,
        "artifact_type": "qcsd-class-study-qualification-authority",
        "foundation_attestation": {
            "path": "/evidence/foundation.json",
            "sha256": "9" * 64,
            "payload_sha256": "0" * 64,
        },
        "build_execution": {"path": "/evidence/build.json", "sha256": "1" * 64},
        "build_execution_identity": {
            "cohort_version": 23,
            "sha256": "1" * 64,
            "completion_path": "/lab/artifacts/buflo-study/build-completion-v23.json",
            "completion_sha256": "2" * 64,
            "collection_image": collection_source["image_digest"],
            "started_at": "2026-08-28T00:00:00+00:00",
            "finished_at": "2026-08-28T01:00:00+00:00",
        },
        "collection_source": collection_source,
        "prepare_source": {**collection_source, "image_digest": prepare_image},
        "prepare_image_digest": prepare_image,
    }
    return (
        {
            "numeric_provenance_sha256": "d" * 64,
            "walkie_talkie_artifact_sha256": "e" * 64,
            "source_result": {
                "campaign": f"{STUDY_ID}-pilot-fitting-1200",
                "evidence_sha256": "1" * 64,
                "experiment_sha256": "2" * 64,
                "input_digest": "3" * 64,
                "campaign_sha256": "4" * 64,
                "source_fingerprints": collection_source,
            },
        },
        {
            "campaign": f"{STUDY_ID}-pilot-compatibility-1080-1200",
            "evidence_sha256": "8" * 64,
            "experiment_sha256": "9" * 64,
            "accepted_samples": 1_080,
            "unique_class_mode_pairs": 1_080,
            "fitted_parameter_sha256": parameters,
            "finalized_bundle": {
                "source": "frozen-pilot-compatibility-inputs",
                "provenance_sha256": "f" * 64,
                "artifact_sha256": parameters,
                "qualification_authority": authority,
                "qualification_authority_sha256": canonical_json_sha256(authority),
            },
        },
    )


def test_final_selection_binding_rejects_graph_substitution(tmp_path: Path) -> None:
    graph = (("left", "right"), ("other", "reserve"))
    numeric, compatibility = _pilot_selection_lineage()
    possible_edges = 120 * 119 // 2
    payload = {
        "study_id": STUDY_ID,
        "selection_schema_version": FINAL_SELECTION_SCHEMA_VERSION,
        "selection_policy": "tranco-bound-order-with-qualified-selected-wt6-pairs",
        "pilot_cohort": {"sha256": "1" * 64, "payload_sha256": "2" * 64},
        "pilot_cohort_assembly": {
            "sha256": "3" * 64,
            "payload_sha256": "4" * 64,
        },
        "pilot_numeric_fitting": numeric,
        "pilot_compatibility": compatibility,
        "feasible_pair_rule": {
            "source": (
                "finalized-selected-wt6-profile-and-both-endpoint-qualification"
            ),
            "candidate_unordered_pairs": possible_edges,
            "qualified_pair_edges": len(graph),
            "unqualified_alternate_pairs_excluded": possible_edges - len(graph),
            "pair_specific_finalized_runtime_profile_required": True,
            "both_endpoint_frozen_prefix_qualification_required": True,
            "unselected_pairs_inferred_from_endpoint_compatibility": False,
            "numeric_fit_selected_runtime_profiles_used": True,
            "final_20_per_stratum_perfect_matching_required": True,
            "classifier_outcomes_used": False,
            "measured_bandwidth_latency_or_privacy_outcomes_used": False,
        },
        "feasible_pair_evidence": [
            _pair_evidence(left, right, marker=index + 7)
            for index, (left, right) in enumerate(graph)
        ],
        "feasible_pair_graph": [list(pair) for pair in graph],
        "selected_final_perfect_matching": [list(pair) for pair in graph],
    }
    path = tmp_path / "final-selection.json"

    def write(value: dict[str, object]) -> None:
        path.write_bytes(
            canonical_json_bytes(
                bind_receipt(value, receipt_type=FINAL_SELECTION_RECEIPT_TYPE)
            )
        )

    write(payload)
    binding = _final_selection_binding(
        path,
        feasible_pairs=graph,
        selected_matching=graph,
    )
    assert binding["payload"]["pilot_cohort"]["sha256"] == "1" * 64
    with pytest.raises(ValueError, match="feasible graph differs"):
        _final_selection_binding(
            path,
            feasible_pairs=(("left", "substitute"), ("other", "reserve")),
            selected_matching=graph,
        )

    missing = copy.deepcopy(payload)
    del missing["feasible_pair_evidence"]
    write(missing)
    with pytest.raises(ValueError, match="fields differ"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    extra = copy.deepcopy(payload)
    extra["unreceipted_selection_hint"] = True
    write(extra)
    with pytest.raises(ValueError, match="fields differ"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    mismatched_evidence = copy.deepcopy(payload)
    mismatched_evidence["feasible_pair_evidence"][1]["right"] = "substitute"
    write(mismatched_evidence)
    with pytest.raises(ValueError, match="orientation differs"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    duplicated_endpoint = copy.deepcopy(payload)
    duplicated_endpoint["feasible_pair_evidence"][1]["left"] = "left"
    write(duplicated_endpoint)
    with pytest.raises(ValueError, match="orientation differs"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    missing_evidence_field = copy.deepcopy(payload)
    del missing_evidence_field["feasible_pair_evidence"][0][
        "runtime_profile_sha256"
    ]
    write(missing_evidence_field)
    with pytest.raises(ValueError, match="evidence fields differ"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    substituted_profile_endpoint = copy.deepcopy(payload)
    substituted_profile_endpoint["feasible_pair_evidence"][0][
        "runtime_profile_real"
    ] = "substitute"
    write(substituted_profile_endpoint)
    with pytest.raises(ValueError, match="runtime profile is invalid"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    missing_endpoint_field = copy.deepcopy(payload)
    del missing_endpoint_field["feasible_pair_evidence"][0][
        "endpoint_qualification"
    ][0]["prefix_pack_spec_sha256"]
    write(missing_endpoint_field)
    with pytest.raises(ValueError, match="endpoint qualification fields differ"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    insufficient_capacity = copy.deepcopy(payload)
    insufficient_capacity["feasible_pair_evidence"][0]["endpoint_qualification"][
        0
    ]["qualified_parallel_chaff_streams"] = 5
    write(insufficient_capacity)
    with pytest.raises(ValueError, match="endpoint qualification is invalid"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    wrong_numeric_lineage = copy.deepcopy(payload)
    wrong_numeric_lineage["pilot_numeric_fitting"]["source_result"][
        "campaign"
    ] = "substituted-pilot-fitting"
    write(wrong_numeric_lineage)
    with pytest.raises(ValueError, match="source-result receipt is invalid"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    reduced_numeric = copy.deepcopy(payload)
    reduced_numeric["pilot_numeric_fitting"] = {"x": 1}
    write(reduced_numeric)
    with pytest.raises(ValueError, match="pilot_numeric_fitting evidence is invalid"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    wrong_compatibility_count = copy.deepcopy(payload)
    wrong_compatibility_count["pilot_compatibility"]["accepted_samples"] = 1_079
    write(wrong_compatibility_count)
    with pytest.raises(ValueError, match="compatibility result is invalid"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    extra_compatibility_field = copy.deepcopy(payload)
    extra_compatibility_field["pilot_compatibility"]["classifier_hint"] = True
    write(extra_compatibility_field)
    with pytest.raises(ValueError, match="pilot_compatibility evidence is invalid"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    wrong_root_rule = copy.deepcopy(payload)
    wrong_root_rule["feasible_pair_rule"]["classifier_outcomes_used"] = True
    write(wrong_root_rule)
    with pytest.raises(ValueError, match="root feasible-pair rule is invalid"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    wrong_policy = copy.deepcopy(payload)
    wrong_policy["selection_policy"] = {"arbitrary": True}
    write(wrong_policy)
    with pytest.raises(ValueError, match="fields differ from the contract"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    boolean_schema = copy.deepcopy(payload)
    boolean_schema["selection_schema_version"] = True
    write(boolean_schema)
    with pytest.raises(ValueError, match="schema version is invalid"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    legacy_schema = copy.deepcopy(payload)
    legacy_schema["selection_schema_version"] = 1
    write(legacy_schema)
    with pytest.raises(ValueError, match="pre-publication and non-evidentiary"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    successor_payload = copy.deepcopy(payload)
    successor_payload["selection_policy"] = (
        "sealed-class-incompatibility-successor-v2"
    )
    successor_payload["feasible_pair_rule"] = {
        "source": "qualified-root-120-class-60-edge-graph",
        "selection": "decision-bound-successor-50-edge-matching",
        "cumulative_failed_classes_excluded": ["failed-class"],
        "replacement_generation": 1,
        "decision_payload_sha256": "a" * 64,
    }
    write(successor_payload)
    _final_selection_binding(
        path,
        feasible_pairs=graph,
        selected_matching=graph,
    )
    successor_payload["feasible_pair_rule"]["replacement_generation"] = True
    write(successor_payload)
    with pytest.raises(ValueError, match="successor feasible-pair rule is invalid"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )

    wrong_matching = copy.deepcopy(payload)
    wrong_matching["selected_final_perfect_matching"] = [["left", "right"]]
    write(wrong_matching)
    with pytest.raises(ValueError, match="matching differs"):
        _final_selection_binding(
            path,
            feasible_pairs=graph,
            selected_matching=graph,
        )


def test_cohort_candidate_must_match_the_same_acquisition_terminal(tmp_path: Path) -> None:
    completion_root = tmp_path / "acquisition"
    terminal_root = completion_root / "terminals"
    stability_root = tmp_path / "stability"
    workload_root = tmp_path / "workloads"
    terminal_root.mkdir(parents=True)
    (stability_root / "class-0-00").mkdir(parents=True)
    workload_root.mkdir()
    stability = stability_root / "class-0-00/page-00.json"
    workload = workload_root / "class-0-00.json"
    stability.write_text("stability\n", encoding="utf-8")
    workload.write_text("workload\n", encoding="utf-8")
    terminal = bind_receipt(
        {
            "candidate_id": "class-0-00",
            "kind": "eligible",
            "reason": None,
            "provenance_sha256": "a" * 64,
            "stability_receipt": {
                "path": str(stability.resolve()),
                "sha256": sha256_file(stability),
            },
            "admitted_workload": {
                "path": str(workload.resolve()),
                "sha256": sha256_file(workload),
            },
        },
        receipt_type="qcsd-class-study-acquisition-terminal",
    )
    terminal_path = terminal_root / "class-0-00.json"
    terminal_path.write_bytes(canonical_json_bytes(terminal))
    completion_payload = {
        "terminal_receipts": {
            "class-0-00": {
                "path": "terminals/class-0-00.json",
                "sha256": sha256_file(terminal_path),
            }
        }
    }
    record = {
        "candidate_id": "class-0-00",
        "eligible": True,
        "stability_receipt": {
            "path": "class-0-00/page-00.json",
            "sha256": sha256_file(stability),
        },
        "prepared_workload": {
            "path": "class-0-00.json",
            "sha256": sha256_file(workload),
        },
    }
    _reconcile_acquisition_terminal(
        "class-0-00",
        record,
        completion_payload=completion_payload,
        completion_root=completion_root,
        stability_root=stability_root,
        workload_root=workload_root,
    )
    substituted = copy.deepcopy(record)
    substituted["prepared_workload"]["sha256"] = "b" * 64
    with pytest.raises(ValueError, match="terminal choice"):
        _reconcile_acquisition_terminal(
            "class-0-00",
            substituted,
            completion_payload=completion_payload,
            completion_root=completion_root,
            stability_root=stability_root,
            workload_root=workload_root,
        )
