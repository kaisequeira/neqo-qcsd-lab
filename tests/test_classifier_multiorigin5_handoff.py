from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import chaff_qualification
import qcsd_lab.orchestrator as orchestrator
from qcsd_lab.orchestrator import plan_campaign
from qcsd_lab.util import load_json
from tools import classifier_handoff
from tests.test_classifier_poc5_handoff import _poc5_export_metadata


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
def _qualification_runtime(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    qualification_root = (
        ROOT
        / "config/chaff-response-qualification-store/sets"
        / classifier_handoff.MULTIORIGIN5_QUALIFICATION_SET
    )
    sidecars = [
        load_json(qualification_root / f"{workload_id}.json")
        for workload_id in classifier_handoff.MULTIORIGIN5_CLASSES
    ]
    receipt = sidecars[0]["implementation_receipt"]
    source = sidecars[0]["qualification_source"]
    assert all(value["implementation_receipt"] == receipt for value in sidecars)
    assert all(value["qualification_source"] == source for value in sidecars)
    monkeypatch.setattr(
        chaff_qualification,
        "implementation_receipt",
        lambda *_args, **_kwargs: deepcopy(receipt),
    )
    monkeypatch.setattr(
        chaff_qualification,
        "_implementation_source_files",
        lambda *_args, **_kwargs: deepcopy(receipt["source_files"]),
    )
    monkeypatch.setattr(
        chaff_qualification,
        "source_metadata",
        lambda: deepcopy(source),
    )
    classifier_handoff._cached_multiorigin5_configuration.cache_clear()
    yield
    classifier_handoff._cached_multiorigin5_configuration.cache_clear()


def _receipts() -> list[SimpleNamespace]:
    receipts: list[SimpleNamespace] = []
    for result_index, (name, campaign_file) in enumerate(
        zip(
            classifier_handoff.MULTIORIGIN5_RESULT_NAMES,
            classifier_handoff.MULTIORIGIN5_CAMPAIGN_FILES,
            strict=True,
        )
    ):
        baseline_result = result_index % 2 == 0
        acquisition_block = result_index // 2
        day = acquisition_block + 1
        baseline_first = acquisition_block % 2 == 0
        hour = 0 if baseline_result == baseline_first else 1
        campaign_path = ROOT / "config/campaigns" / campaign_file
        campaign, configuration = classifier_handoff._expected_multiorigin5_configuration(
            campaign_path
        )
        samples = plan_campaign(campaign)
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


def _rehearsal_receipt() -> SimpleNamespace:
    campaign_path = (
        ROOT / "config/campaigns" / classifier_handoff.MULTIORIGIN5_REHEARSAL_CAMPAIGN_FILE
    )
    campaign, configuration = classifier_handoff._expected_multiorigin5_configuration(campaign_path)
    samples = plan_campaign(campaign)
    return SimpleNamespace(
        experiment={
            "name": classifier_handoff.MULTIORIGIN5_REHEARSAL_RESULT_NAME,
            "purpose": "evaluation",
            "source": dict(SOURCE),
            "samples": samples,
            "execution_order": [sample["sample_id"] for sample in samples],
            "configuration": deepcopy(configuration),
        }
    )


def _formal_export_metadata() -> tuple[dict, list[dict]]:
    blocks = []
    rows = []
    for result_index, name in enumerate(classifier_handoff.MULTIORIGIN5_RESULT_NAMES):
        acquisition_block = result_index // 2
        temporal_split = classifier_handoff.MULTIORIGIN5_TEMPORAL_SPLITS[acquisition_block]
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
        acquisition_id = f"acquisition-block-{acquisition_block + 1:03d}"
        day = acquisition_block + 1
        baseline_first = acquisition_block % 2 == 0
        hour = 0 if baseline_result == baseline_first else 1
        blocks.append(
            {
                "result_name": name,
                "split": None,
                "sample_splits": policy,
                "acquisition_block_index": acquisition_block,
                "acquisition_block_id": acquisition_id,
                "started_at": f"2026-08-{day:02d}T{hour:02d}:00:00+00:00",
                "completed_at": f"2026-08-{day:02d}T{hour:02d}:30:00+00:00",
                "source": dict(SOURCE),
            }
        )
        defenses = ("undefended",) if baseline_result else classifier_handoff.MULTIORIGIN5_DEFENSES
        visits = range(20) if baseline_result else range(10)
        for workload_id in classifier_handoff.MULTIORIGIN5_CLASSES:
            for defense in defenses:
                runtime_kind, baseline = classifier_handoff.MULTIORIGIN5_RUNTIME[defense]
                for visit in visits:
                    rows.append(
                        {
                            "block_index": result_index,
                            "block_id": block_id,
                            "acquisition_block_index": acquisition_block,
                            "acquisition_block_id": acquisition_id,
                            "workload_id": workload_id,
                            "class_label": (
                                classifier_handoff.MULTIORIGIN5_CLASS_LABELS[workload_id]
                            ),
                            "defense": defense,
                            "defense_role": ("baseline" if baseline else "inference-only"),
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
    return (
        {
            "exporter_source": deepcopy(EXPORTER_SOURCE),
            "blocks": blocks,
            "classes": sorted(class_counts),
            "sample_count": len(rows),
            "counts_by_class": dict(sorted(class_counts.items())),
            "counts_by_defense": dict(sorted(defense_counts.items())),
            "counts_by_split": dict(sorted(split_counts.items())),
        },
        rows,
    )


def _rehearsal_export_metadata() -> tuple[dict, list[dict]]:
    receipt = _rehearsal_receipt()
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
                "class_label": classifier_handoff.MULTIORIGIN5_CLASS_LABELS[workload_id],
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
                    "result_name": classifier_handoff.MULTIORIGIN5_REHEARSAL_RESULT_NAME,
                    "split": "interface",
                    "sample_splits": {
                        defense: "interface" for defense in classifier_handoff.MULTIORIGIN5_DEFENSES
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


def test_multiorigin5_contract_freezes_exact_names_order_classes_and_usage() -> None:
    assert classifier_handoff.MULTIORIGIN5_RESULT_NAMES == tuple(
        name
        for block in range(1, 11)
        for name in (
            f"research-classifier-multiorigin5-v1-baseline-{block:02d}-1200",
            f"research-classifier-multiorigin5-v1-paired-{block:02d}-1200",
        )
    )
    assert classifier_handoff.MULTIORIGIN5_CAMPAIGN_FILES == tuple(
        name
        for block in range(1, 11)
        for name in (
            f"classifier-multiorigin5-v1-baseline-{block:02d}.yml",
            f"classifier-multiorigin5-v1-paired-{block:02d}.yml",
        )
    )
    assert classifier_handoff.MULTIORIGIN5_CLASS_LABELS == {
        "getbootstrap-home-r4": "getbootstrap.com",
        "cloudflare-quiche-r4": "cloudflare-quic.com",
        "hyper-basic-client-r3": "hyper.rs",
        "serde-home-r2": "serde.rs",
        "rfc9114-text-r2": "www.rfc-editor.org",
    }
    usage = (ROOT / "classifier-pilot").read_text(encoding="utf-8")
    assert "POC5 and classifier-multiorigin5-v1 contracts" in usage
    assert "baseline-01,\npaired-01" in usage


def test_multiorigin5_collection_assigns_protocol_and_exact_qualification_binding() -> None:
    receipts = _receipts()

    plan = classifier_handoff._validate_pilot_collection(receipts, [None] * 20)

    assert isinstance(plan, classifier_handoff.Multiorigin5CollectionPlan)
    assert plan.protocol == "formal"
    assert plan.sample_splits[0] == {"undefended": "train"}
    assert plan.sample_splits[1] == {
        "undefended": "train",
        "front": "inference",
        "tamaraw": "inference",
    }
    assert plan.sample_splits[16]["undefended"] == "validation"
    assert plan.sample_splits[18]["undefended"] == "test"
    for index, receipt in enumerate(receipts):
        configuration = receipt.experiment["configuration"]
        if index % 2 == 0:
            assert "chaff_qualification_set" not in configuration
        else:
            assert configuration["chaff_qualification_set"] == (
                classifier_handoff.MULTIORIGIN5_QUALIFICATION_SET
            )


@pytest.mark.parametrize(
    "campaign_file",
    [
        "classifier-multiorigin5-v1-baseline-01.yml",
        "classifier-multiorigin5-v1-paired-01.yml",
        "classifier-multiorigin5-v1-rehearsal.yml",
    ],
)
def test_multiorigin5_expected_configuration_matches_materialized_frozen_reload(
    tmp_path: Path,
    campaign_file: str,
) -> None:
    campaign_path = ROOT / "config/campaigns" / campaign_file
    campaign, expected = classifier_handoff._expected_multiorigin5_configuration(campaign_path)
    result = tmp_path / campaign_path.stem

    runtime, materialized = orchestrator._materialize_inputs(result, campaign, {})
    frozen = orchestrator._campaign_from_frozen_inputs(result)
    reloaded = orchestrator._frozen_configuration(result, frozen)

    assert expected == materialized == reloaded
    assert plan_campaign(runtime) == plan_campaign(frozen)
    qualification_set = (
        None if "baseline" in campaign_file else classifier_handoff.MULTIORIGIN5_QUALIFICATION_SET
    )
    assert expected.get("chaff_qualification_set") == qualification_set
    assert ("chaff_qualification_set" in expected) is (qualification_set is not None)


@pytest.mark.parametrize("result_index", [0, 1])
def test_multiorigin5_collection_rejects_qualification_set_presence_or_value_drift(
    result_index: int,
) -> None:
    receipts = _receipts()
    configuration = receipts[result_index].experiment["configuration"]
    if result_index == 0:
        configuration["chaff_qualification_set"] = classifier_handoff.MULTIORIGIN5_QUALIFICATION_SET
    else:
        configuration.pop("chaff_qualification_set")

    with pytest.raises(ValueError, match="campaign/input configuration"):
        classifier_handoff._validate_pilot_collection(receipts, [None] * 20)


def test_multiorigin5_rejects_noncanonical_or_mixed_result_lineages() -> None:
    receipts = _receipts()
    receipts[0], receipts[1] = receipts[1], receipts[0]
    with pytest.raises(ValueError, match="20 ordered"):
        classifier_handoff._validate_pilot_collection(receipts, [None] * 20)

    mixed = [
        _receipts()[0],
        SimpleNamespace(experiment={"name": classifier_handoff.POC5_RESULT_NAMES[0]}),
    ]
    with pytest.raises(ValueError, match="cannot mix POC5 and multi-origin"):
        classifier_handoff._validate_pilot_collection(mixed, [None, None])

    with pytest.raises(ValueError, match="rehearsal cannot mix"):
        classifier_handoff._validate_pilot_collection(
            [_rehearsal_receipt(), _receipts()[0]],
            ["interface", None],
        )


def test_multiorigin5_formal_handoff_freezes_schema_v2_classifier_contract() -> None:
    dataset, rows = _formal_export_metadata()

    classifier_handoff._validate_multiorigin5_handoff_protocol(dataset, rows)

    assert dataset["sample_count"] == 2_500
    assert dataset["counts_by_class"] == {
        label: 500 for label in sorted(classifier_handoff.MULTIORIGIN5_CLASS_LABELS.values())
    }
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


def test_multiorigin5_rehearsal_is_a_separate_30_sample_interface_gate() -> None:
    receipt = _rehearsal_receipt()
    plan = classifier_handoff._validate_pilot_collection([receipt], ["interface"])
    dataset, rows = _rehearsal_export_metadata()

    classifier_handoff._validate_multiorigin5_rehearsal_handoff_protocol(dataset, rows)

    assert isinstance(plan, classifier_handoff.Multiorigin5CollectionPlan)
    assert plan.protocol == "rehearsal"
    assert receipt.experiment["configuration"]["chaff_qualification_set"] == (
        classifier_handoff.MULTIORIGIN5_QUALIFICATION_SET
    )
    assert dataset["sample_count"] == 30
    assert dataset["counts_by_split"] == {"interface": 30}


def test_historical_poc5_schema_v2_protocol_still_validates_unchanged() -> None:
    dataset, rows = _poc5_export_metadata()

    classifier_handoff._validate_poc5_handoff_protocol(dataset, rows)

    assert classifier_handoff.POC5_CLASSES == (
        "getbootstrap-home-r3",
        "cloudflare-quiche-r3",
        "hyper-basic-client-r2",
        "serde-home-r1",
        "rfc9114-text-r1",
    )
    assert dataset["sample_count"] == 2_500
