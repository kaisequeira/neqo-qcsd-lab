from __future__ import annotations

from collections import Counter
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import chaff_qualification
from qcsd_lab.util import load_json
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


@pytest.fixture(autouse=True)
def _native_executed_qualification_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    sidecar = load_json(ROOT / "config/chaff-qualification-store/v2/getbootstrap-home-r3.json")
    receipt = sidecar["implementation_receipt"]
    monkeypatch.setattr(
        chaff_qualification,
        "implementation_receipt",
        lambda *_args, **_kwargs: receipt,
    )


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
        campaign_path = ROOT / "config/campaigns" / campaign_file
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
    campaign_path = ROOT / "config/campaigns/classifier-poc5-rehearsal.yml"
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
