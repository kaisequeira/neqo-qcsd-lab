from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import qcsd_lab.class_cohort as cohort_module
from qcsd_lab.class_acquisition import (
    initialise_runner,
    run_due_acquisition,
    write_acquisition_completion,
)
from qcsd_lab.class_catalogue import (
    CANDIDATE_RECEIPT_TYPE,
    CATALOGUE_SCHEMA_VERSION,
    STABILITY_PROBE_WINDOWS,
    PageCandidate,
    StabilityObservation,
    build_stability_receipt,
)
from qcsd_lab.class_cohort import (
    ASSEMBLY_RECEIPT_TYPE,
    FINAL_SELECTION_RECEIPT_TYPE,
    _candidate_evidence,
    _final_selection_binding,
    _reconcile_acquisition_terminal,
    build_evidenced_cohort,
    publish_evidenced_cohort,
    validate_cohort_assembly,
)
from qcsd_lab.util import sha256_file
from qcsd_lab.class_study import (
    CANDIDATE_COUNT,
    CANDIDATES_PER_STRATUM,
    STUDY_ID,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    bind_receipt,
    canonical_json_bytes,
    deterministic_candidate_order,
)

LIST_SHA = "a" * 64


class _RejectingBackend:
    def discover_navigation(self, domain: str):
        raise RuntimeError(f"unavailable: {domain}")


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


def _completion(tmp_path: Path, catalogue: Path) -> Path:
    workloads = tmp_path / "workloads"
    stability = tmp_path / "stability"
    workloads.mkdir(exist_ok=True)
    stability.mkdir(exist_ok=True)
    foundation = tmp_path / "foundation.json"
    foundation.write_bytes(
        canonical_json_bytes(
            bind_receipt(
                {"study_id": STUDY_ID},
                receipt_type="qcsd-class-study-foundation-attestation",
            )
        )
    )
    runner = initialise_runner(
        tmp_path / "acquisition",
        candidate_catalogue_path=catalogue,
        foundation_attestation=foundation,
        started_at="2026-08-28T00:00:00Z",
        browser_tool="test",
    )
    run_due_acquisition(
        runner,
        candidate_catalogue_path=catalogue,
        stability_root=stability,
        workload_root=workloads,
        backend=_RejectingBackend(),
        max_candidates=CANDIDATE_COUNT,
    )
    return write_acquisition_completion(runner, candidate_catalogue_path=catalogue)


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
    completion = _completion(tmp_path, catalogue)
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


def test_final_selection_binding_rejects_graph_substitution(tmp_path: Path) -> None:
    receipt = bind_receipt(
        {
            "study_id": STUDY_ID,
            "selection_schema_version": 1,
            "selection_policy": "verified-pilot-evidence",
            "pilot_cohort": {"sha256": "1" * 64, "payload_sha256": "2" * 64},
            "pilot_cohort_assembly": {
                "sha256": "3" * 64,
                "payload_sha256": "4" * 64,
            },
            "pilot_numeric_fitting": {"numeric_provenance_sha256": "5" * 64},
            "pilot_compatibility": {"evidence_sha256": "6" * 64},
            "feasible_pair_rule": {"classifier_or_performance_outcomes_used": False},
            "feasible_pair_graph": [["left", "right"]],
        },
        receipt_type=FINAL_SELECTION_RECEIPT_TYPE,
    )
    path = tmp_path / "final-selection.json"
    path.write_bytes(canonical_json_bytes(receipt))
    binding = _final_selection_binding(path, feasible_pairs=(("left", "right"),))
    assert binding["payload"]["pilot_cohort"]["sha256"] == "1" * 64
    with pytest.raises(ValueError, match="feasible graph differs"):
        _final_selection_binding(path, feasible_pairs=(("left", "substitute"),))


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
