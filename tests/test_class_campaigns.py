from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from qcsd_lab import chaff_qualification, orchestrator, util
from qcsd_lab.capture_session import Defense
from qcsd_lab.class_campaigns import (
    FINAL_QUALIFICATION_SET,
    PILOT_QUALIFICATION_SET,
    campaign_documents,
    validate_campaign_document,
    write_campaign_documents,
)
from qcsd_lab.class_layout import (
    AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME,
    AUTHORITATIVE_COHORT_FILENAME,
    PILOT_COHORT_ASSEMBLY_FILENAME,
    PILOT_COHORT_FILENAME,
)
from qcsd_lab.class_cohort import ASSEMBLY_RECEIPT_TYPE
from qcsd_lab.class_study import (
    CANDIDATE_COUNT,
    CANDIDATES_PER_STRATUM,
    COMPATIBILITY_MODES,
    FORMAL_MODES,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    bind_receipt,
    build_study_receipt,
    canonical_json_bytes,
    load_study_receipt,
    write_study_receipt,
)
from qcsd_lab.orchestrator import Workload
from qcsd_lab.util import sha256_file


def _cohort_receipt(tmp_path: Path, filename: str = "cohort.json") -> Path:
    candidates = []
    for stratum_index, stratum in enumerate(TRANCO_RANK_STRATA):
        for offset in range(CANDIDATES_PER_STRATUM):
            candidates.append(
                ClassCandidate(
                    candidate_id=f"class-{stratum_index}-{offset:02d}",
                    domain=f"site-{stratum_index}-{offset:02d}.example",
                    rank=stratum.minimum_rank + offset,
                    eligible=True,
                )
            )
    receipt = build_study_receipt(
        candidates,
        tranco_list_id="test-list",
        tranco_list_sha256="a" * 64,
    )
    path = tmp_path / filename
    write_study_receipt(path, receipt)
    return path


def _assembly_receipt(
    tmp_path: Path,
    cohort_path: Path,
    filename: str = "cohort-assembly.json",
) -> Path:
    cohort, selection = load_study_receipt(cohort_path)
    records = [
        {
            "candidate_id": candidate.candidate_id,
            "eligible": True,
            "selected_page": {
                "candidate_domain": candidate.domain,
                "registrable_domain": candidate.domain,
                "url": f"https://{candidate.domain}/",
                "source": "canonical-homepage",
                "ordinal": 0,
                "discovery_content_type": None,
            },
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
        for candidate in selection.candidates
    ]
    assembly = bind_receipt(
        {
            "study_id": "classifier-multiorigin100-v1",
            "assembly_schema_version": 1,
            "eligibility_policy": {
                "source": "three-window-page-stability-receipt-only",
                "probe_windows": ["t+30s", "t+24h", "t+72h"],
                "page_order": (
                    "canonical-homepage-then-hash-ordered-safe-same-domain-links"
                ),
                "outcome_optimisation": False,
                "classifier_or_defence_measurements_used": False,
                "prepared_workload_sha256_required": True,
            },
            "candidate_catalogue": {
                "path": "candidates.json",
                "sha256": "a" * 64,
                "payload_sha256": "b" * 64,
            },
            "stability_root": "stability",
            "workload_root": "workloads",
            "candidates": records,
            "eligible_count": CANDIDATE_COUNT,
            "selected_evidence_count": 120,
            "cohort": {
                "receipt_type": cohort["receipt_type"],
                "payload_sha256": cohort["payload_sha256"],
                "canonical_file_sha256": hashlib.sha256(
                    canonical_json_bytes(cohort)
                ).hexdigest(),
            },
        },
        receipt_type=ASSEMBLY_RECEIPT_TYPE,
    )
    path = tmp_path / filename
    path.write_bytes(canonical_json_bytes(assembly))
    return path


def _defense_names(document: dict[str, object]) -> tuple[str, ...]:
    defenses = document["defenses"]
    assert isinstance(defenses, list)
    return tuple(
        item if isinstance(item, str) else str(item["name"])
        for item in defenses
    )


def test_campaign_set_has_exact_excluded_and_formal_matrices(tmp_path: Path) -> None:
    cohort = _cohort_receipt(tmp_path)
    documents = campaign_documents(
        cohort,
        cohort_assembly_receipt=_assembly_receipt(tmp_path, cohort),
    )

    assert len(documents) == 24
    pilot = documents["classifier-multiorigin100-v1-pilot-compatibility-1080-1200.yml"]
    certification = documents["classifier-multiorigin100-v1-certification-900-1200.yml"]
    assert len(pilot["workloads"]) == 120
    assert len(certification["workloads"]) == 100
    assert pilot["chaff_qualification_set"] == PILOT_QUALIFICATION_SET
    assert certification["chaff_qualification_set"] == FINAL_QUALIFICATION_SET
    assert certification["class_study_cohort_assembly"].endswith(
        "classifier-multiorigin100-v1-cohort-assembly.json"
    )
    assert pilot["limits"]["max_attempts"] == 3
    assert certification["limits"]["max_attempts"] == 1

    for block in range(1, 11):
        canary = documents[f"classifier-multiorigin100-v1-canary-{block:02d}-1200.yml"]
        formal = documents[f"classifier-multiorigin100-v1-formal-{block:02d}-1200.yml"]
        assert _defense_names(canary) == ("undefended",)
        assert _defense_names(formal) == FORMAL_MODES
        assert formal["defense_order"]["block"] == block - 1
        assert canary["defense_order"]["block"] == block - 1
        assert formal["limits"]["max_attempts"] == 3
        assert canary["limits"]["max_attempts"] == 3
        assert len(formal["workloads"]) * 2 * len(formal["defenses"]) == 1_600


def test_generated_pilot_compatibility_preflight_uses_copublished_prefix_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "config"
    campaigns = config / "classifier-multiorigin100-v1-campaigns"
    cohort_root = config / "class-study/v1"
    workloads_root = config / "workloads"
    campaigns.mkdir(parents=True)
    cohort_root.mkdir(parents=True)
    workloads_root.mkdir()
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)

    source_cohort = _cohort_receipt(tmp_path)
    source_assembly = _assembly_receipt(tmp_path, source_cohort)
    cohort = cohort_root / PILOT_COHORT_FILENAME
    assembly = cohort_root / PILOT_COHORT_ASSEMBLY_FILENAME
    cohort.write_bytes(source_cohort.read_bytes())
    assembly.write_bytes(source_assembly.read_bytes())
    documents = campaign_documents(
        cohort,
        cohort_assembly_receipt=assembly,
        cohort_reference=f"../class-study/v1/{PILOT_COHORT_FILENAME}",
        cohort_assembly_reference=(
            f"../class-study/v1/{PILOT_COHORT_ASSEMBLY_FILENAME}"
        ),
    )
    filename = "classifier-multiorigin100-v1-pilot-compatibility-1080-1200.yml"
    document = documents[filename]
    campaign_path = campaigns / filename
    campaign_path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    workload_values: list[Workload] = []
    for workload_id, visits in document["workloads"].items():
        path = workloads_root / f"{workload_id}.json"
        path.write_text("{}\n", encoding="utf-8")
        workload_values.append(
            Workload(
                id=workload_id,
                visits=visits,
                path=path,
                source_bytes=path.read_bytes(),
                sha256="d" * 64,
                data={
                    "preparation": {},
                    "resources": [
                        {
                            "id": 0,
                            "url": f"https://{workload_id}.test/",
                            "type": "Document",
                            "content_length": 1,
                            "data_length": 1,
                            "chaff_priority": True,
                            "known_valid": True,
                            "depends_on": [],
                            "headers": [],
                        }
                    ],
                },
                resource_count=1,
                origin_count=1,
            )
        )
    monkeypatch.setattr(
        orchestrator,
        "_load_workloads",
        lambda *_args, **_kwargs: tuple(workload_values),
    )

    runtime_kind = {
        "undefended": "none",
        "static": "static",
        "front": "front",
        "tamaraw": "tamaraw",
        "traffic-morphing": "traffic_morphing",
        "wtf-pad": "wtf_pad",
        "walkie-talkie": "walkie_talkie",
        "buflo": "buflo",
        "cs-buflo": "cs_buflo",
    }
    historical_walkie = tmp_path / "walkie-talkie.json"
    historical_walkie.write_text('{"schema_version":5}\n', encoding="utf-8")
    provenance = tmp_path / "provenance.json"
    provenance.write_text("{}\n", encoding="utf-8")
    defenses = []
    for mode in COMPATIBILITY_MODES:
        kind = runtime_kind[mode]
        kwargs: dict[str, object] = {}
        if mode == "static":
            kwargs.update(
                schedule_path=tmp_path / "static.csv",
                schedule_sha256="8" * 64,
                mode="chaff-only",
            )
        elif kind in {
            "traffic_morphing",
            "wtf_pad",
            "walkie_talkie",
            "buflo",
            "cs_buflo",
        }:
            kwargs.update(
                parameters_path=(
                    historical_walkie
                    if mode == "walkie-talkie"
                    else tmp_path / f"{mode}.json"
                ),
                parameters_sha256="a" * 64,
                parameters_provenance_path=provenance,
                parameters_provenance_sha256=sha256_file(provenance),
                parameters_input_policy="sealed-class-study-fitting-v1",
            )
        defenses.append(
            Defense(
                name=mode,
                kind=kind,
                baseline=mode == "undefended",
                **kwargs,
            )
        )
    defenses = tuple(defenses)
    monkeypatch.setattr(
        orchestrator,
        "_load_defenses",
        lambda *_args, **_kwargs: defenses,
    )
    monkeypatch.setattr(
        orchestrator,
        "_validate_loaded_qualification_bindings",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(orchestrator, "runtime_manifest", lambda value: value)

    qualification_set = document["chaff_qualification_set"]
    published = config / "chaff-qualification-store/sets" / qualification_set
    published_specs = published / chaff_qualification.NAMED_QUALIFICATION_PREFIX_DIRECTORY
    published_specs.mkdir(parents=True)
    set_manifest = published / chaff_qualification.NAMED_QUALIFICATION_SET_MANIFEST
    set_manifest.write_text("{}\n", encoding="utf-8")
    for workload in workload_values:
        (published / f"{workload.id}.json").write_text("{}\n", encoding="utf-8")
        (published_specs / f"{workload.id}.json").write_text("{}\n", encoding="utf-8")

    def load_named(path: Path, **kwargs: object) -> SimpleNamespace:
        assert path == set_manifest.resolve()
        assert kwargs["prefix_spec_root"] == published_specs.resolve()
        return SimpleNamespace(
            manifest_path=set_manifest.resolve(),
            manifest_sha256=sha256_file(set_manifest),
        )

    observed_specs: list[Path] = []

    def load_full(path: Path, **kwargs: object) -> SimpleNamespace:
        spec = kwargs["prefix_spec_path"]
        assert isinstance(spec, Path)
        observed_specs.append(spec)
        return SimpleNamespace(
            sidecar_sha256=sha256_file(path),
            manifest_sha256="f" * 64,
            manifest={"schema_version": 2, "resources": []},
        )

    monkeypatch.setattr(chaff_qualification, "load_named_qualification_set", load_named)
    monkeypatch.setattr(chaff_qualification, "load_qualified_chaff", load_full)

    preflight = orchestrator.preflight_campaign(campaign_path)
    assert preflight["sample_count"] == 1_080
    assert len(observed_specs) == 120
    assert all(path.parent == published_specs.resolve() for path in observed_specs)


def test_campaign_publication_is_create_only_and_round_trips_yaml(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path)
    study_root = tmp_path / "config/class-study/v1"
    study_root.mkdir(parents=True)
    pilot_receipt = _cohort_receipt(study_root, PILOT_COHORT_FILENAME)
    _assembly_receipt(
        study_root,
        pilot_receipt,
        PILOT_COHORT_ASSEMBLY_FILENAME,
    )
    receipt = _cohort_receipt(study_root, AUTHORITATIVE_COHORT_FILENAME)
    assembly = _assembly_receipt(
        study_root,
        receipt,
        AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME,
    )
    destination = tmp_path / "config/classifier-multiorigin100-v1-campaigns"
    destination.mkdir(parents=True)

    paths = write_campaign_documents(
        receipt,
        destination,
        cohort_assembly_receipt=assembly,
    )

    assert len(paths) == 24
    assert all(path.is_file() and not path.is_symlink() for path in paths)
    for path in paths:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert value["name"] == path.stem
        assert value["schema"] == 2
        pilot_role = value["evidence_role"].startswith("pilot-")
        expected_cohort = (
            PILOT_COHORT_FILENAME if pilot_role else AUTHORITATIVE_COHORT_FILENAME
        )
        expected_assembly = (
            PILOT_COHORT_ASSEMBLY_FILENAME
            if pilot_role
            else AUTHORITATIVE_COHORT_ASSEMBLY_FILENAME
        )
        assert value["class_study_cohort"].endswith(expected_cohort)
        assert value["class_study_cohort_assembly"].endswith(expected_assembly)
    with pytest.raises(ValueError, match="cannot disable canonical"):
        write_campaign_documents(
            receipt,
            destination,
            cohort_assembly_receipt=assembly,
            _enforce_fresh_layout=False,
        )
    with pytest.raises(FileExistsError, match="campaign already exists"):
        write_campaign_documents(
            receipt,
            destination,
            cohort_assembly_receipt=assembly,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("timeout_seconds", 121),
        ("max_response_bytes", 1_048_575),
        ("capture_seconds", 181),
        ("capture_megabytes", 63),
        ("max_attempts", 2),
        ("per_origin_cooldown_seconds", 29),
        ("settle_seconds", 2),
    ),
)
def test_single_campaign_reconstruction_rejects_every_limit_drift(
    tmp_path: Path,
    field: str,
    replacement: int,
) -> None:
    cohort = _cohort_receipt(tmp_path)
    assembly = _assembly_receipt(tmp_path, cohort)
    documents = campaign_documents(
        cohort,
        cohort_assembly_receipt=assembly,
    )
    name = "classifier-multiorigin100-v1-formal-01-1200.yml"
    formal = documents[name]
    assert (
        validate_campaign_document(
            formal,
            cohort_receipt=cohort,
            cohort_assembly_receipt=assembly,
        )
        == name
    )

    changed_limit = yaml.safe_load(yaml.safe_dump(formal))
    changed_limit["limits"][field] = replacement
    with pytest.raises(ValueError, match="deterministic generator"):
        validate_campaign_document(
            changed_limit,
            cohort_receipt=cohort,
            cohort_assembly_receipt=assembly,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "seed",
        "sample-order",
        "defense-order",
        "static-schedule",
        "buflo-parameters",
        "cs-parameters",
    ),
)
def test_single_campaign_reconstruction_rejects_order_and_runtime_input_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    cohort = _cohort_receipt(tmp_path)
    assembly = _assembly_receipt(tmp_path, cohort)
    documents = campaign_documents(cohort, cohort_assembly_receipt=assembly)
    formal = yaml.safe_load(
        yaml.safe_dump(documents["classifier-multiorigin100-v1-formal-01-1200.yml"])
    )
    if mutation == "seed":
        formal["seed"] += 1
    elif mutation == "sample-order":
        formal["sample_order"]["window_size"] = 15
    elif mutation == "defense-order":
        formal["defense_order"]["block"] = 1
    elif mutation == "static-schedule":
        certification = documents[
            "classifier-multiorigin100-v1-certification-900-1200.yml"
        ]
        formal = yaml.safe_load(yaml.safe_dump(certification))
        next(
            item
            for item in formal["defenses"]
            if isinstance(item, dict) and item.get("name") == "static"
        )["schedule"] = "../defense-params/other-static.csv"
    elif mutation == "buflo-parameters":
        next(
            item
            for item in formal["defenses"]
            if isinstance(item, dict) and item.get("name") == "buflo"
        )["parameters"] = "../defense-params/other-buflo.json"
    else:
        next(
            item
            for item in formal["defenses"]
            if isinstance(item, dict) and item.get("name") == "cs-buflo"
        )["parameters"] = "../defense-params/cs-buflo-cpsp-live.json"

    with pytest.raises(ValueError, match="deterministic generator"):
        validate_campaign_document(
            formal,
            cohort_receipt=cohort,
            cohort_assembly_receipt=assembly,
        )


def test_single_campaign_reconstruction_rejects_noncanonical_cs_variant(
    tmp_path: Path,
) -> None:
    cohort = _cohort_receipt(tmp_path)
    assembly = _assembly_receipt(tmp_path, cohort)
    documents = campaign_documents(cohort, cohort_assembly_receipt=assembly)
    formal = documents["classifier-multiorigin100-v1-formal-01-1200.yml"]

    changed_variant = yaml.safe_load(yaml.safe_dump(formal))
    cs_buflo = next(
        item
        for item in changed_variant["defenses"]
        if isinstance(item, dict) and item.get("name") == "cs-buflo"
    )
    cs_buflo["parameters"] = "../defense-params/cs-buflo-cpsp-live.json"
    with pytest.raises(ValueError, match="deterministic generator"):
        validate_campaign_document(
            changed_variant,
            cohort_receipt=cohort,
            cohort_assembly_receipt=assembly,
        )


def test_fresh_generation_rejects_alternate_references_but_sealed_rebuild_can_read_them(
    tmp_path: Path,
) -> None:
    cohort = _cohort_receipt(tmp_path)
    assembly = _assembly_receipt(tmp_path, cohort)
    references = {
        "cohort_reference": "../class-study/cohort.json",
        "cohort_assembly_reference": "../class-study/cohort-assembly.json",
    }
    with pytest.raises(ValueError, match="alternate class-study path"):
        campaign_documents(
            cohort,
            cohort_assembly_receipt=assembly,
            **references,
        )

    sealed = campaign_documents(
        cohort,
        cohort_assembly_receipt=assembly,
        _enforce_fresh_layout=False,
        **references,
    )
    assert len(sealed) == 24


def test_campaign_writer_rejects_alternate_root_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(util, "LAB_ROOT", tmp_path / "lab")
    cohort = _cohort_receipt(tmp_path)
    assembly = _assembly_receipt(tmp_path, cohort)
    alternate = tmp_path / "alternate"
    alternate.mkdir()

    with pytest.raises(ValueError, match="outside the canonical class-study layout"):
        write_campaign_documents(
            cohort,
            alternate,
            cohort_assembly_receipt=assembly,
        )
    assert list(alternate.iterdir()) == []
