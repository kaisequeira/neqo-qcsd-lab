from __future__ import annotations

import json
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml

from qcsd_lab.capture_session import Defense, Limits
from qcsd_lab.orchestrator import Campaign, load_campaign, plan_campaign


ROOT = Path(__file__).parents[1]
CAMPAIGN_DIR = ROOT / "config/campaigns"
QUALIFICATION_SET = "classifier-multiorigin5-v1"
WORKLOADS = (
    "getbootstrap-home-r4",
    "cloudflare-quiche-r4",
    "hyper-basic-client-r3",
    "serde-home-r2",
    "rfc9114-text-r2",
)
WORKLOAD_ORDERS = (
    tuple(WORKLOADS[shift:] + WORKLOADS[:shift] for shift in range(len(WORKLOADS))) * 2
)
RESOURCE_COUNTS = {
    "getbootstrap-home-r4": 9,
    "cloudflare-quiche-r4": 6,
    "hyper-basic-client-r3": 7,
    "serde-home-r2": 20,
    "rfc9114-text-r2": 2,
}
APPROVED_ORIGINS = {
    "getbootstrap-home-r4": ("https://getbootstrap.com",),
    "cloudflare-quiche-r4": (
        "https://blog-cloudflare-com-assets.storage.googleapis.com",
        "https://blog.cloudflare.com",
        "https://cloudflare-quic.com",
    ),
    "hyper-basic-client-r3": ("https://cdn.jsdelivr.net", "https://hyper.rs"),
    "serde-home-r2": ("https://serde.rs",),
    "rfc9114-text-r2": ("https://www.rfc-editor.org",),
}
BASELINE_SEEDS = tuple(range(2_026_081_901, 2_026_081_911))
# Prospectively selected from 2026092001..2026122000 using deterministic plan
# expansion only. No capture outcome or classifier score informed selection.
PAIRED_SEEDS = (
    2_026_097_302,
    2_026_111_021,
    2_026_111_042,
    2_026_111_173,
    2_026_112_316,
    2_026_116_570,
    2_026_118_718,
    2_026_119_980,
    2_026_121_265,
    2_026_121_446,
)
REHEARSAL_SEED = 2_026_081_899
BASELINE_DEFENSES = ("undefended",)
PAIRED_DEFENSES = ("undefended", "front", "tamaraw")
DEFENSE_KINDS = {
    "undefended": "none",
    "front": "front",
    "tamaraw": "tamaraw",
}
EXPECTED_PAIRED_POSITION_COUNTS = (
    ((33, 34, 33), (33, 33, 34), (34, 33, 33)),
    ((33, 34, 33), (33, 33, 34), (34, 33, 33)),
    ((33, 34, 33), (33, 33, 34), (34, 33, 33)),
    ((34, 33, 33), (33, 34, 33), (33, 33, 34)),
    ((34, 33, 33), (34, 34, 32), (32, 33, 35)),
)
LIMITS = {
    "timeout_seconds": 120,
    "max_response_bytes": 1_048_576,
    "capture_seconds": 180,
    "capture_megabytes": 64,
    "max_attempts": 3,
    "per_origin_cooldown_seconds": 30,
    "settle_seconds": 1,
}
BASE_KEYS = {
    "schema",
    "name",
    "purpose",
    "seed",
    "profile",
    "workloads",
    "request_policies",
    "defenses",
    "limits",
}
FORMAL_CASES = tuple(
    (
        block,
        kind,
        CAMPAIGN_DIR / f"classifier-multiorigin5-v1-{kind}-{block:02d}.yml",
        20 if kind == "baseline" else 10,
        BASELINE_DEFENSES if kind == "baseline" else PAIRED_DEFENSES,
        BASELINE_SEEDS[block - 1] if kind == "baseline" else PAIRED_SEEDS[block - 1],
    )
    for block in range(1, 11)
    for kind in ("baseline", "paired")
)
FORMAL_PATHS = tuple(case[2] for case in FORMAL_CASES)
REHEARSAL_PATH = CAMPAIGN_DIR / "classifier-multiorigin5-v1-rehearsal.yml"
HISTORICAL_PATHS = tuple(
    CAMPAIGN_DIR / f"classifier-poc5-{kind}-{block:02d}.yml"
    for block in range(1, 11)
    for kind in ("baseline", "paired")
) + (CAMPAIGN_DIR / "classifier-poc5-rehearsal.yml",)


def _load_value(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


@pytest.fixture(scope="module")
def planning_base() -> Campaign:
    return load_campaign(FORMAL_PATHS[0])


@pytest.fixture(scope="module")
def historical_base() -> Campaign:
    return load_campaign(CAMPAIGN_DIR / "classifier-poc5-baseline-01.yml")


def _planning_campaign(base: Campaign, path: Path, value: dict[str, Any]) -> Campaign:
    catalog = {workload.id: workload for workload in base.workloads}
    return replace(
        base,
        path=path,
        source_bytes=path.read_bytes(),
        name=value["name"],
        purpose=value["purpose"],
        seed=value["seed"],
        profile=value["profile"],
        workloads=tuple(
            replace(catalog[workload_id], visits=visits)
            for workload_id, visits in value["workloads"].items()
        ),
        request_policies=tuple(value["request_policies"]),
        defenses=tuple(
            Defense(
                name=name,
                kind=DEFENSE_KINDS[name],
                baseline=name == "undefended",
            )
            for name in value["defenses"]
        ),
        limits=Limits(**value["limits"]),
        chaff_qualification_set=value.get("chaff_qualification_set"),
    )


def _planned(base: Campaign, paths: tuple[Path, ...]) -> tuple[dict[str, Any], ...]:
    return tuple(
        sample
        for path in paths
        for sample in plan_campaign(_planning_campaign(base, path, _load_value(path)))
    )


@pytest.mark.parametrize(
    ("block", "kind", "path", "visits", "defenses", "seed"),
    FORMAL_CASES,
)
def test_multiorigin5_formal_campaign_contract(
    planning_base: Campaign,
    block: int,
    kind: str,
    path: Path,
    visits: int,
    defenses: tuple[str, ...],
    seed: int,
) -> None:
    value = _load_value(path)
    expected_keys = BASE_KEYS | ({"chaff_qualification_set"} if kind == "paired" else set())

    assert set(value) == expected_keys
    assert value["schema"] == 1
    assert value["name"] == (f"research-classifier-multiorigin5-v1-{kind}-{block:02d}-1200")
    assert value["purpose"] == "evaluation"
    assert value["seed"] == seed
    assert value["profile"] == "research-1200"
    assert tuple(value["workloads"]) == WORKLOAD_ORDERS[block - 1]
    assert set(value["workloads"].values()) == {visits}
    assert value["request_policies"] == ["as-defined"]
    assert tuple(value["defenses"]) == defenses
    assert value["limits"] == LIMITS
    assert value.get("chaff_qualification_set") == (QUALIFICATION_SET if kind == "paired" else None)

    plan = plan_campaign(_planning_campaign(planning_base, path, value))
    expected_samples = len(WORKLOADS) * visits * len(defenses)
    assert len(plan) == expected_samples
    assert len({sample["sample_id"] for sample in plan}) == expected_samples
    assert len({sample["seed"] for sample in plan}) == expected_samples
    assert Counter((sample["workload_id"], sample["defense"]) for sample in plan) == Counter(
        {(workload_id, defense): visits for workload_id in WORKLOADS for defense in defenses}
    )


def test_multiorigin5_workloads_freeze_complete_rendered_get_coverage(
    planning_base: Campaign,
) -> None:
    assert {workload.id: workload.resource_count for workload in planning_base.workloads} == (
        RESOURCE_COUNTS
    )
    assert {workload.id: workload.origin_count for workload in planning_base.workloads} == {
        workload_id: len(origins) for workload_id, origins in APPROVED_ORIGINS.items()
    }

    for workload_id in WORKLOADS:
        manifest = json.loads(
            (ROOT / f"config/workloads/{workload_id}.json").read_text(encoding="utf-8")
        )
        preparation = manifest["preparation"]
        coverage = preparation["coverage_admission"]
        assert tuple(preparation["approved_origins"]) == APPROVED_ORIGINS[workload_id]
        assert coverage == {
            "schema_version": 1,
            "policy": "all-approved-origins-and-rendered-resources",
            "required_origins": list(APPROVED_ORIGINS[workload_id]),
            "required_resources": [
                {"id": resource["id"], "url": resource["url"]} for resource in manifest["resources"]
            ],
        }
        assert len(manifest["resources"]) == RESOURCE_COUNTS[workload_id]
        assert not any(
            exclusion["reason"] == "HTTP/3 preflight unavailable"
            for exclusion in preparation["exclusions"]
        )


def test_multiorigin5_defended_campaigns_bind_one_exact_qualification_set() -> None:
    qualification_root = ROOT / "config/chaff-response-qualification-store/sets" / QUALIFICATION_SET
    assert qualification_root.is_dir() and not qualification_root.is_symlink()
    assert {path.name for path in qualification_root.iterdir()} == {
        f"{workload_id}.json" for workload_id in WORKLOADS
    }
    assert all(path.is_file() and not path.is_symlink() for path in qualification_root.iterdir())
    assert "chaff_qualification_set" not in _load_value(FORMAL_PATHS[0])
    for path in (*FORMAL_PATHS[1::2], REHEARSAL_PATH):
        assert _load_value(path)["chaff_qualification_set"] == QUALIFICATION_SET


def test_multiorigin5_formal_aggregate_is_exactly_2500_balanced_samples(
    planning_base: Campaign,
) -> None:
    actual_paths = tuple(
        sorted(CAMPAIGN_DIR.glob("classifier-multiorigin5-v1-baseline-*.yml"))
    ) + tuple(sorted(CAMPAIGN_DIR.glob("classifier-multiorigin5-v1-paired-*.yml")))
    assert actual_paths == tuple(FORMAL_PATHS[::2]) + tuple(FORMAL_PATHS[1::2])
    values = tuple(_load_value(path) for path in FORMAL_PATHS)
    assert len({value["name"] for value in values}) == 20
    assert len({value["seed"] for value in values}) == 20
    assert {value["seed"] for value in values}.isdisjoint({REHEARSAL_SEED})

    plans = tuple(
        plan_campaign(_planning_campaign(planning_base, path, value))
        for path, value in zip(FORMAL_PATHS, values, strict=True)
    )
    combined = tuple(sample for plan in plans for sample in plan)
    assert len(combined) == 2_500
    assert len({sample["sample_id"] for sample in combined}) == 2_500
    assert len({sample["seed"] for sample in combined}) == 2_500
    assert Counter(sample["defense"] for sample in combined) == Counter(
        {"undefended": 1_500, "front": 500, "tamaraw": 500}
    )
    assert Counter((sample["workload_id"], sample["defense"]) for sample in combined) == Counter(
        {
            (workload_id, defense): count
            for workload_id in WORKLOADS
            for defense, count in (
                ("undefended", 300),
                ("front", 100),
                ("tamaraw", 100),
            )
        }
    )

    split_ranges = ((plans[:16], 240), (plans[16:18], 30), (plans[18:20], 30))
    for selected, expected in split_ranges:
        clean = (
            sample for plan in selected for sample in plan if sample["defense"] == "undefended"
        )
        assert Counter(sample["workload_id"] for sample in clean) == Counter(
            {workload_id: expected for workload_id in WORKLOADS}
        )

    defense_positions: Counter[tuple[str, str, int]] = Counter()
    for plan in plans[1::2]:
        for start in range(0, len(plan), len(PAIRED_DEFENSES)):
            visit = plan[start : start + len(PAIRED_DEFENSES)]
            assert len({(sample["workload_id"], sample["visit"]) for sample in visit}) == 1
            assert {sample["defense"] for sample in visit} == set(PAIRED_DEFENSES)
            for position, sample in enumerate(visit):
                defense_positions[(sample["workload_id"], sample["defense"], position)] += 1
    observed = tuple(
        tuple(
            tuple(defense_positions[(workload_id, defense, position)] for position in range(3))
            for defense in PAIRED_DEFENSES
        )
        for workload_id in WORKLOADS
    )
    assert observed == EXPECTED_PAIRED_POSITION_COUNTS
    assert min(defense_positions.values()) == 32
    assert max(defense_positions.values()) == 35
    assert sum(count not in {33, 34} for count in defense_positions.values()) == 3

    for block in range(10):
        assert tuple(values[2 * block]["workloads"]) == tuple(values[2 * block + 1]["workloads"])
    positions = Counter(
        (workload_id, position)
        for order in WORKLOAD_ORDERS
        for position, workload_id in enumerate(order)
    )
    assert set(positions.values()) == {2}


def test_multiorigin5_chronology_contract_alternates_within_blocks() -> None:
    capture_order = tuple(
        path
        for block in range(10)
        for path in (
            (FORMAL_PATHS[2 * block], FORMAL_PATHS[2 * block + 1])
            if block % 2 == 0
            else (FORMAL_PATHS[2 * block + 1], FORMAL_PATHS[2 * block])
        )
    )
    assert len(capture_order) == 20
    assert set(capture_order) == set(FORMAL_PATHS)
    for block in range(10):
        first, second = capture_order[2 * block : 2 * block + 2]
        assert ("baseline" in first.name) is (block % 2 == 0)
        assert ("paired" in second.name) is (block % 2 == 0)


def test_multiorigin5_rehearsal_is_excluded_and_fresh_from_historical_poc5(
    planning_base: Campaign,
    historical_base: Campaign,
) -> None:
    value = _load_value(REHEARSAL_PATH)
    assert set(value) == BASE_KEYS | {"chaff_qualification_set"}
    assert value["name"] == "research-classifier-multiorigin5-v1-rehearsal-1200"
    assert value["seed"] == REHEARSAL_SEED
    assert value["chaff_qualification_set"] == QUALIFICATION_SET
    assert tuple(value["workloads"]) == WORKLOADS
    assert set(value["workloads"].values()) == {2}
    assert tuple(value["defenses"]) == PAIRED_DEFENSES
    assert set(CAMPAIGN_DIR.glob("classifier-multiorigin5-v1-*.yml")) == {
        *FORMAL_PATHS,
        REHEARSAL_PATH,
    }

    current = _planned(planning_base, (*FORMAL_PATHS, REHEARSAL_PATH))
    historical = _planned(historical_base, HISTORICAL_PATHS)
    rehearsal = _planned(planning_base, (REHEARSAL_PATH,))
    assert len(current) == 2_530
    assert len(rehearsal) == 30
    assert len({sample["sample_id"] for sample in current}) == 2_530
    assert len({sample["seed"] for sample in current}) == 2_530
    assert {sample["sample_id"] for sample in current}.isdisjoint(
        {sample["sample_id"] for sample in historical}
    )
    assert {sample["seed"] for sample in current}.isdisjoint(
        {sample["seed"] for sample in historical}
    )
    assert Counter((sample["workload_id"], sample["defense"]) for sample in rehearsal) == Counter(
        {(workload_id, defense): 2 for workload_id in WORKLOADS for defense in PAIRED_DEFENSES}
    )
