from __future__ import annotations

from collections.abc import Iterator
from collections import Counter
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import chaff_qualification
import qcsd_lab.orchestrator as orchestrator
from qcsd_lab.util import atomic_json, load_json
from tools import classifier_handoff


ROOT = Path(__file__).parents[1]
SOURCE = {
    "image_digest": "sha256:" + "1" * 64,
    "lab_commit": "2" * 40,
    "lab_dirty": False,
    "lab_patch_sha256": classifier_handoff.EMPTY_SHA256,
    "neqo_commit": "3" * 40,
    "neqo_dirty": False,
    "neqo_patch_sha256": classifier_handoff.EMPTY_SHA256,
    "neqo_pinned_commit": "3" * 40,
}
EXPORTER_SOURCE = {
    "execution_image": dict(SOURCE),
    "companion": {
        "lab_commit": SOURCE["lab_commit"],
        "lab_dirty": False,
    },
}


def _response_only_sidecar_from_full(workload_id: str) -> dict:
    """Build a validator-complete, test-only response contract from saved receipts."""

    full = load_json(ROOT / f"config/chaff-qualification-store/v2/{workload_id}.json")
    response_runs = []
    for run_index, value in enumerate(full["resource"]["response_runs"]):
        receipt = deepcopy(value["receipt"])
        receipt.update(
            qualified_parallel_chaff_streams=(
                chaff_qualification.RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
            ),
            parallel_requests=chaff_qualification.RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS,
            requests_opened_before_first_network_output=(
                chaff_qualification.RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
            ),
        )
        receipt["requests"] = receipt["requests"][
            : chaff_qualification.RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        ]
        response_runs.append(chaff_qualification._response_run_record(run_index, receipt))
    response_digest = chaff_qualification.qualification_digest(
        "qcsd-chaff-response-qualification-v2", response_runs
    )
    resource = full["resource"]
    return {
        "schema_version": chaff_qualification.RESPONSE_ONLY_SIDECAR_SCHEMA_VERSION,
        "artifact_type": chaff_qualification.RESPONSE_ONLY_SIDECAR_ARTIFACT_TYPE,
        "qualification_scope": chaff_qualification.RESPONSE_ONLY_QUALIFICATION_SCOPE,
        "workload_id": workload_id,
        "base_manifest": deepcopy(full["base_manifest"]),
        "selection_policy": full["selection_policy"],
        "application_resource_id": full["application_resource_id"],
        "selected_chaff_resource_id": full["selected_chaff_resource_id"],
        "qualified_parallel_chaff_streams": (
            chaff_qualification.RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
        ),
        "header_projection": deepcopy(full["header_projection"]),
        "method": full["method"],
        "qualification_policy": {
            "qualification_scope": chaff_qualification.RESPONSE_ONLY_QUALIFICATION_SCOPE,
            "response_runs": chaff_qualification.QUALIFICATION_RUNS,
            "parallel_response_requests": (
                chaff_qualification.RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
            ),
            "qualified_parallel_chaff_streams": (
                chaff_qualification.RESPONSE_ONLY_PARALLEL_CHAFF_STREAMS
            ),
            "profile": "research-1200",
            "response_defense": "none",
            "seed": 0,
            "udp_payload_ceiling": chaff_qualification.UDP_PAYLOAD_CEILING,
            "max_response_bytes": 1_048_576,
            "separate_chaff_namespace": True,
        },
        "qualification_source": deepcopy(full["qualification_source"]),
        "qualification_image_digest": full["qualification_image_digest"],
        "neqo_provenance": deepcopy(full["neqo_provenance"]),
        "implementation_receipt": deepcopy(full["implementation_receipt"]),
        "resource": {
            "resource_id": resource["resource_id"],
            "url": resource["url"],
            "headers": deepcopy(resource["headers"]),
            "request_stream_bytes": resource["request_stream_bytes"],
            "expected_response": deepcopy(resource["expected_response"]),
            "response_runs": response_runs,
            "response_qualification_sha256": response_digest,
        },
    }


@pytest.fixture(autouse=True)
def _poc5_qualification_inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    lab_root = tmp_path / "poc5-lab"
    campaigns = lab_root / "config/campaigns"
    workloads = lab_root / "config/workloads"
    qualifications = lab_root / "config/chaff-response-qualification-store/v1"
    campaigns.mkdir(parents=True)
    workloads.mkdir()
    qualifications.mkdir(parents=True)
    for campaign_file in (
        *classifier_handoff.POC5_CAMPAIGN_FILES,
        "classifier-poc5-rehearsal.yml",
    ):
        source = ROOT / "config/campaigns" / campaign_file
        (campaigns / campaign_file).write_bytes(source.read_bytes())
    sidecars = []
    for workload_id in classifier_handoff.POC5_CLASSES:
        source = ROOT / "config/workloads" / f"{workload_id}.json"
        (workloads / source.name).write_bytes(source.read_bytes())
        live = ROOT / f"config/chaff-response-qualification-store/v1/{workload_id}.json"
        destination = qualifications / f"{workload_id}.json"
        if live.is_file() and not live.is_symlink():
            destination.write_bytes(live.read_bytes())
            sidecars.append(load_json(live))
        else:
            sidecar = _response_only_sidecar_from_full(workload_id)
            atomic_json(destination, sidecar)
            sidecars.append(sidecar)
    receipt = sidecars[0]["implementation_receipt"]
    assert all(sidecar["implementation_receipt"] == receipt for sidecar in sidecars)
    monkeypatch.setattr(
        chaff_qualification,
        "implementation_receipt",
        lambda *_args, **_kwargs: receipt,
    )
    monkeypatch.setattr(
        chaff_qualification,
        "_implementation_source_files",
        lambda *_args, **_kwargs: receipt["source_files"],
    )
    monkeypatch.setenv("QCSD_HANDOFF_LAB_ROOT", str(lab_root))
    classifier_handoff._cached_poc5_configuration.cache_clear()
    yield
    classifier_handoff._cached_poc5_configuration.cache_clear()


def _poc5_receipts() -> list[SimpleNamespace]:
    receipts: list[SimpleNamespace] = []
    for result_index, (name, campaign_file) in enumerate(
        zip(
            classifier_handoff.POC5_RESULT_NAMES,
            classifier_handoff.POC5_CAMPAIGN_FILES,
            strict=True,
        )
    ):
        baseline_result = result_index % 2 == 0
        acquisition_block = result_index // 2
        day = acquisition_block + 1
        baseline_first = acquisition_block % 2 == 0
        hour = 0 if baseline_result == baseline_first else 1
        campaign_path = classifier_handoff._lab_root() / "config/campaigns" / campaign_file
        campaign, configuration = classifier_handoff._expected_poc5_configuration(campaign_path)
        samples = classifier_handoff.plan_campaign(campaign)
        receipts.append(
            SimpleNamespace(
                experiment={
                    "name": name,
                    "purpose": "evaluation",
                    "started_at": f"2026-08-{day:02d}T{hour:02d}:00:00+00:00",
                    "completed_at": f"2026-08-{day:02d}T{hour:02d}:30:00+00:00",
                    "source": dict(SOURCE),
                    "samples": samples,
                    "execution_order": [sample["sample_id"] for sample in samples],
                    "configuration": deepcopy(configuration),
                }
            )
        )
    return receipts


def _poc5_export_metadata() -> tuple[dict, list[dict]]:
    blocks = []
    rows = []
    for result_index, name in enumerate(classifier_handoff.POC5_RESULT_NAMES):
        acquisition_block = result_index // 2
        temporal_split = classifier_handoff.POC5_TEMPORAL_SPLITS[acquisition_block]
        baseline_result = result_index % 2 == 0
        policy = (
            {"undefended": temporal_split}
            if baseline_result
            else {
                "front": "inference",
                "tamaraw": "inference",
                "undefended": temporal_split,
            }
        )
        block_id = f"block-{result_index + 1:03d}"
        acquisition_block_id = f"acquisition-block-{acquisition_block + 1:03d}"
        day = acquisition_block + 1
        baseline_first = acquisition_block % 2 == 0
        hour = 0 if baseline_result == baseline_first else 1
        blocks.append(
            {
                "result_name": name,
                "split": None,
                "sample_splits": policy,
                "acquisition_block_index": acquisition_block,
                "acquisition_block_id": acquisition_block_id,
                "started_at": f"2026-08-{day:02d}T{hour:02d}:00:00+00:00",
                "completed_at": f"2026-08-{day:02d}T{hour:02d}:30:00+00:00",
                "source": dict(SOURCE),
            }
        )
        defenses = ("undefended",) if baseline_result else classifier_handoff.POC5_DEFENSES
        visits = range(20) if baseline_result else range(10)
        for workload_id in classifier_handoff.POC5_CLASSES:
            for defense in defenses:
                runtime_kind, baseline = classifier_handoff.POC5_RUNTIME[defense]
                for visit in visits:
                    rows.append(
                        {
                            "block_index": result_index,
                            "block_id": block_id,
                            "acquisition_block_index": acquisition_block,
                            "acquisition_block_id": acquisition_block_id,
                            "workload_id": workload_id,
                            "class_label": classifier_handoff.POC5_CLASS_LABELS[workload_id],
                            "defense": defense,
                            "defense_role": "baseline" if baseline else "inference-only",
                            "runtime_kind": runtime_kind,
                            "baseline": baseline,
                            "request_policy": "as-defined",
                            "visit": visit,
                            "split": policy[defense],
                            "paired_visit_id": (
                                f"{block_id}/{workload_id}/as-defined/visit-{visit:03d}"
                            ),
                        }
                    )
    class_counts = Counter(row["class_label"] for row in rows)
    defense_counts = Counter(row["defense"] for row in rows)
    split_counts = Counter(row["split"] for row in rows)
    dataset = {
        "exporter_source": deepcopy(EXPORTER_SOURCE),
        "blocks": blocks,
        "classes": sorted(class_counts),
        "sample_count": len(rows),
        "counts_by_class": dict(sorted(class_counts.items())),
        "counts_by_defense": dict(sorted(defense_counts.items())),
        "counts_by_split": dict(sorted(split_counts.items())),
    }
    return dataset, rows


def _poc5_rehearsal_receipt() -> SimpleNamespace:
    campaign_path = (
        classifier_handoff._lab_root() / "config/campaigns/classifier-poc5-rehearsal.yml"
    )
    campaign, configuration = classifier_handoff._expected_poc5_configuration(campaign_path)
    samples = classifier_handoff.plan_campaign(campaign)
    return SimpleNamespace(
        experiment={
            "name": classifier_handoff.POC5_REHEARSAL_RESULT_NAME,
            "purpose": "evaluation",
            "samples": samples,
            "execution_order": [sample["sample_id"] for sample in samples],
            "configuration": deepcopy(configuration),
            "source": dict(SOURCE),
        }
    )


def _poc5_rehearsal_export_metadata() -> tuple[dict, list[dict]]:
    receipt = _poc5_rehearsal_receipt()
    rows = []
    for sample in receipt.experiment["samples"]:
        workload_id = sample["workload_id"]
        rows.append(
            {
                "block_index": 0,
                "block_id": "block-001",
                "acquisition_block_index": 0,
                "acquisition_block_id": "acquisition-block-001",
                "workload_id": workload_id,
                "class_label": classifier_handoff.POC5_CLASS_LABELS[workload_id],
                "defense": sample["defense"],
                "defense_role": ("baseline" if sample["baseline"] else "inference-only"),
                "runtime_kind": sample["runtime_kind"],
                "baseline": sample["baseline"],
                "request_policy": "as-defined",
                "visit": sample["visit"],
                "split": "interface",
                "paired_visit_id": (
                    f"block-001/{workload_id}/as-defined/visit-{sample['visit']:03d}"
                ),
            }
        )
    class_counts = Counter(row["class_label"] for row in rows)
    defense_counts = Counter(row["defense"] for row in rows)
    return (
        {
            "exporter_source": deepcopy(EXPORTER_SOURCE),
            "blocks": [
                {
                    "result_name": classifier_handoff.POC5_REHEARSAL_RESULT_NAME,
                    "split": "interface",
                    "sample_splits": {
                        defense: "interface" for defense in classifier_handoff.POC5_DEFENSES
                    },
                    "acquisition_block_index": 0,
                    "acquisition_block_id": "acquisition-block-001",
                    "source": dict(SOURCE),
                }
            ],
            "classes": sorted(class_counts),
            "sample_count": len(rows),
            "counts_by_class": dict(sorted(class_counts.items())),
            "counts_by_defense": dict(sorted(defense_counts.items())),
            "counts_by_split": {"interface": len(rows)},
        },
        rows,
    )


def test_poc5_response_only_expected_config_matches_materialized_frozen_reload(
    tmp_path: Path,
) -> None:
    campaign_path = (
        classifier_handoff._lab_root() / "config/campaigns/classifier-poc5-paired-01.yml"
    )
    campaign, expected = classifier_handoff._expected_poc5_configuration(campaign_path)
    result = tmp_path / "response-only-result"

    runtime, materialized = orchestrator._materialize_inputs(result, campaign, {})
    frozen = orchestrator._campaign_from_frozen_inputs(result)
    reloaded = orchestrator._frozen_configuration(result, frozen)

    assert expected == materialized == reloaded
    assert orchestrator.plan_campaign(runtime) == orchestrator.plan_campaign(frozen)
    assert not (result / "inputs/chaff-prefix-specs").exists()
    assert all(
        record["chaff_qualification_scope"] == orchestrator.RESPONSE_ONLY_CHAFF_SCOPE
        and "chaff_prefix_spec" not in record
        and "chaff_prefix_spec_sha256" not in record
        for record in expected["workloads"]
    )
    for directory in (
        "chaff-qualifications",
        "chaff-manifests",
        "runtime-workloads",
    ):
        assert len(tuple((result / "inputs" / directory).iterdir())) == len(
            classifier_handoff.POC5_CLASSES
        )


def test_poc5_full_v2_expected_config_preserves_prefix_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workload = SimpleNamespace(
        id="qualified-site",
        visits=2,
        sha256="1" * 64,
        resource_count=3,
        origin_count=1,
        chaff_qualification_path=Path("qualification.json"),
        chaff_qualification_sha256="2" * 64,
        chaff_qualification_scope=orchestrator.FULL_CHAFF_SCOPE,
        chaff_prefix_spec_path=Path("prefix.json"),
        chaff_prefix_spec_sha256="3" * 64,
        chaff_manifest_sha256="4" * 64,
        runtime_sha256="5" * 64,
    )
    campaign = SimpleNamespace(
        workloads=(workload,),
        defenses=(),
        profile="research-1200",
        request_policies=("as-defined",),
        limits=SimpleNamespace(as_dict=lambda: {}),
    )
    campaign_path = tmp_path / "full-v2.yml"
    atomic_json(campaign_path, {})
    monkeypatch.setattr(classifier_handoff, "load_campaign", lambda _path: campaign)
    classifier_handoff._cached_poc5_configuration.cache_clear()

    _, expected = classifier_handoff._expected_poc5_configuration(campaign_path)

    assert expected["workloads"] == [
        {
            "id": "qualified-site",
            "visits": 2,
            "manifest": "inputs/workloads/qualified-site.json",
            "sha256": "1" * 64,
            "resource_count": 3,
            "origin_count": 1,
            "chaff_qualification": "inputs/chaff-qualifications/qualified-site.json",
            "chaff_qualification_sha256": "2" * 64,
            "chaff_prefix_spec": "inputs/chaff-prefix-specs/qualified-site.json",
            "chaff_prefix_spec_sha256": "3" * 64,
            "chaff_manifest": "inputs/chaff-manifests/qualified-site.json",
            "chaff_manifest_sha256": "4" * 64,
            "runtime_manifest": "inputs/runtime-workloads/qualified-site.json",
            "runtime_manifest_sha256": "5" * 64,
        }
    ]


def test_poc5_contract_accepts_only_exact_ordered_twenty_result_lineage() -> None:
    plan = classifier_handoff._validate_pilot_collection(_poc5_receipts(), [None] * 20)

    assert isinstance(plan, classifier_handoff.Poc5CollectionPlan)
    assert plan.protocol == "formal"
    assert len(plan.sample_splits) == 20
    assert plan.sample_splits[0] == {"undefended": "train"}
    assert plan.sample_splits[1] == {
        "undefended": "train",
        "front": "inference",
        "tamaraw": "inference",
    }
    assert plan.sample_splits[16]["undefended"] == "validation"
    assert plan.sample_splits[18]["undefended"] == "test"
    assert all(
        policy.get(defense) == "inference"
        for policy in plan.sample_splits
        for defense in ("front", "tamaraw")
        if defense in policy
    )


def test_poc5_contract_rejects_non_alternating_within_block_capture_order() -> None:
    receipts = _poc5_receipts()
    first = receipts[0].experiment
    second = receipts[1].experiment
    first["started_at"], second["started_at"] = second["started_at"], first["started_at"]
    first["completed_at"], second["completed_at"] = (
        second["completed_at"],
        first["completed_at"],
    )

    with pytest.raises(ValueError, match="capture order does not alternate"):
        classifier_handoff._validate_pilot_collection(receipts, [None] * 20)


@pytest.mark.parametrize("mutation", ["within-block-overlap", "block-order"])
def test_poc5_contract_rejects_overlap_and_non_temporal_blocks(mutation: str) -> None:
    receipts = _poc5_receipts()
    if mutation == "within-block-overlap":
        receipts[1].experiment["started_at"] = "2026-08-01T00:15:00+00:00"
    elif mutation == "block-order":
        receipts[2].experiment.update(
            started_at="2026-08-01T01:15:00+00:00",
            completed_at="2026-08-01T01:45:00+00:00",
        )
        receipts[3].experiment.update(
            started_at="2026-08-01T00:45:00+00:00",
            completed_at="2026-08-01T01:15:00+00:00",
        )
    else:
        raise AssertionError(f"unknown mutation: {mutation}")

    with pytest.raises(ValueError, match="alternate|temporally ordered"):
        classifier_handoff._validate_pilot_collection(receipts, [None] * 20)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("order", "20 ordered"),
        ("split", "assigned automatically"),
        ("cohort", "100-sample cohort"),
        ("campaign", "checked-in campaign"),
        ("source", "identical execution source"),
    ],
)
def test_poc5_contract_rejects_lineage_cohort_and_split_drift(mutation: str, message: str) -> None:
    receipts = _poc5_receipts()
    splits = [None] * 20
    if mutation == "order":
        receipts[0], receipts[1] = receipts[1], receipts[0]
    elif mutation == "split":
        splits[0] = "train"
    elif mutation == "cohort":
        receipts[0].experiment["samples"].pop()
    elif mutation == "campaign":
        receipts[0].experiment["configuration"]["campaign_sha256"] = "0" * 64
    elif mutation == "source":
        receipts[-1].experiment["source"]["image_digest"] = "sha256:" + "4" * 64
    else:
        raise AssertionError(f"unknown mutation: {mutation}")

    with pytest.raises(ValueError, match=message):
        classifier_handoff._validate_pilot_collection(receipts, splits)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("lab_dirty", True),
        ("neqo_dirty", True),
        ("lab_patch_sha256", "4" * 64),
        ("neqo_patch_sha256", "4" * 64),
        ("neqo_pinned_commit", "4" * 40),
    ],
)
def test_poc5_contract_rejects_dirty_or_unpinned_execution_source(
    field: str, value: object
) -> None:
    receipts = _poc5_receipts()
    for receipt in receipts:
        receipt.experiment["source"][field] = value

    with pytest.raises(ValueError, match="clean immutable execution source"):
        classifier_handoff._validate_pilot_collection(receipts, [None] * 20)


def test_poc5_export_requires_same_clean_checkout_and_capture_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipts = _poc5_receipts()
    exporter = {
        "execution_image": dict(SOURCE),
        "companion": {
            "lab_commit": SOURCE["lab_commit"],
            "lab_dirty": False,
        },
    }
    monkeypatch.setattr(
        classifier_handoff,
        "_exporter_source_receipt",
        lambda: deepcopy(exporter),
    )

    classifier_handoff._validate_poc5_export_environment(receipts)

    exporter["companion"]["lab_dirty"] = True
    with pytest.raises(ValueError, match="clean capture checkout"):
        classifier_handoff._validate_poc5_export_environment(receipts)
    exporter["companion"]["lab_dirty"] = False
    exporter["execution_image"]["image_digest"] = "sha256:" + "4" * 64
    with pytest.raises(ValueError, match="collection image"):
        classifier_handoff._validate_poc5_export_environment(receipts)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("baseline-manifest", "campaign/input configuration"),
        ("paired-runtime", "campaign/input configuration"),
        ("paired-chaff", "campaign/input configuration"),
        ("defense", "campaign/input configuration"),
        ("profile", "campaign/input configuration"),
        ("sample-order", "planned sample identity/order"),
    ],
)
def test_poc5_contract_rejects_configuration_and_sample_plan_drift(
    mutation: str, message: str
) -> None:
    receipts = _poc5_receipts()
    if mutation == "baseline-manifest":
        receipts[0].experiment["configuration"]["workloads"][0]["sha256"] = "0" * 64
    elif mutation == "paired-runtime":
        receipts[1].experiment["configuration"]["workloads"][0]["runtime_manifest_sha256"] = (
            "0" * 64
        )
    elif mutation == "paired-chaff":
        receipts[1].experiment["configuration"]["workloads"][0]["chaff_qualification_sha256"] = (
            "0" * 64
        )
    elif mutation == "defense":
        receipts[1].experiment["configuration"]["defenses"].reverse()
    elif mutation == "profile":
        receipts[0].experiment["configuration"]["profile"] = "live"
    elif mutation == "sample-order":
        samples = receipts[0].experiment["samples"]
        samples[0], samples[1] = samples[1], samples[0]
    else:
        raise AssertionError(f"unknown mutation: {mutation}")

    with pytest.raises(ValueError, match=message):
        classifier_handoff._validate_pilot_collection(receipts, [None] * 20)


def test_poc5_rehearsal_is_interface_only_and_cannot_mix_with_formal_export() -> None:
    receipt = _poc5_rehearsal_receipt()

    plan = classifier_handoff._validate_pilot_collection([receipt], ["interface"])
    assert isinstance(plan, classifier_handoff.Poc5CollectionPlan)
    assert plan.protocol == "rehearsal"
    assert plan.sample_splits == (
        {"undefended": "interface", "front": "interface", "tamaraw": "interface"},
    )

    with pytest.raises(ValueError, match="requires the interface split"):
        classifier_handoff._validate_pilot_collection([receipt], [None])
    with pytest.raises(ValueError, match="cannot mix"):
        classifier_handoff._validate_pilot_collection(
            [receipt, _poc5_receipts()[0]], ["interface", None]
        )


def test_poc5_rehearsal_handoff_is_exact_schema_v2_importer_gate() -> None:
    dataset, rows = _poc5_rehearsal_export_metadata()

    classifier_handoff._validate_poc5_rehearsal_handoff_protocol(dataset, rows)

    assert dataset["sample_count"] == 30
    assert dataset["counts_by_split"] == {"interface": 30}
    assert all(row["class_label"] != row["workload_id"] for row in rows)


def test_poc5_export_protocol_has_domain_labels_and_no_defended_training_leakage() -> None:
    dataset, rows = _poc5_export_metadata()

    classifier_handoff._validate_poc5_handoff_protocol(dataset, rows)

    assert dataset["sample_count"] == 2_500
    assert dataset["counts_by_defense"] == {
        "front": 500,
        "tamaraw": 500,
        "undefended": 1_500,
    }
    assert dataset["counts_by_split"] == {
        "inference": 1_000,
        "test": 150,
        "train": 1_200,
        "validation": 150,
    }
    assert all(
        row["split"] == "inference" and row["defense_role"] == "inference-only"
        for row in rows
        if row["defense"] in {"front", "tamaraw"}
    )
    assert dataset["blocks"][0]["acquisition_block_id"] == "acquisition-block-001"
    assert dataset["blocks"][1]["acquisition_block_id"] == "acquisition-block-001"
    assert dataset["blocks"][2]["acquisition_block_id"] == "acquisition-block-002"
    assert all(
        row["class_label"] == classifier_handoff.POC5_CLASS_LABELS[row["workload_id"]]
        for row in rows
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("defended-train", "2,500-sample protocol"),
        ("domain", "2,500-sample protocol"),
        ("pair", "paired-visit"),
        ("acquisition", "2,500-sample protocol"),
        ("result-order", "result lineage"),
        ("count", "2,500-sample protocol"),
    ],
)
def test_poc5_export_protocol_rejects_label_split_pairing_and_count_drift(
    mutation: str, message: str
) -> None:
    dataset, rows = _poc5_export_metadata()
    dataset = deepcopy(dataset)
    rows = deepcopy(rows)
    if mutation == "defended-train":
        next(row for row in rows if row["defense"] == "front")["split"] = "train"
    elif mutation == "domain":
        rows[0]["class_label"] = "wrong.example"
    elif mutation == "pair":
        rows[0]["paired_visit_id"] = "wrong"
    elif mutation == "acquisition":
        rows[0]["acquisition_block_id"] = "acquisition-block-999"
    elif mutation == "result-order":
        dataset["blocks"][0], dataset["blocks"][1] = (
            dataset["blocks"][1],
            dataset["blocks"][0],
        )
    elif mutation == "count":
        rows.pop()
    else:
        raise AssertionError(f"unknown mutation: {mutation}")

    with pytest.raises(ValueError, match=message):
        classifier_handoff._validate_poc5_handoff_protocol(dataset, rows)


def test_schema_v1_rejects_inference_split() -> None:
    with pytest.raises(ValueError, match="block split"):
        classifier_handoff._normalize_splits(["inference"], 1)

    row = {
        "schema_version": classifier_handoff.SCHEMA_VERSION,
        "block_index": 0,
        "visit": 0,
        "seed": 1,
        "attempts": 1,
        "packet_count": 1,
        "defense": "undefended",
        "split": "inference",
    }
    with pytest.raises(ValueError, match="sample split is invalid"):
        classifier_handoff._validate_sample_row(
            row,
            {0: {"*": "inference"}},
            schema_version=classifier_handoff.SCHEMA_VERSION,
        )
