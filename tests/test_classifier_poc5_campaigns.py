from __future__ import annotations

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
WORKLOADS = (
    "getbootstrap-home-r3",
    "apache-traffic-server-docs-r3",
    "nginx-quic-r3",
    "cloudflare-quiche-r3",
    "nghttp2-ngtcp2-r3",
)
WORKLOAD_ORDERS = (
    tuple(WORKLOADS[shift:] + WORKLOADS[:shift] for shift in range(len(WORKLOADS))) * 2
)
BASELINE_SEEDS = tuple(range(2_026_081_501, 2_026_081_511))
# Prospectively selected from 2026082001..2026092000 using only deterministic
# plan expansion. The criterion first bounds every class/defense/position cell
# as tightly as possible around 100/3, then minimizes cells outside 33..34.
# No capture result or workload outcome was available to this selection.
PAIRED_SEEDS = (
    2_026_082_902,
    2_026_083_050,
    2_026_085_096,
    2_026_085_118,
    2_026_085_300,
    2_026_085_353,
    2_026_085_559,
    2_026_085_658,
    2_026_089_403,
    2_026_090_539,
)
REHEARSAL_SEED = 2_026_081_499
BASELINE_DEFENSES = ("undefended",)
PAIRED_DEFENSES = ("undefended", "front", "tamaraw")
DEFENSE_KINDS = {
    "undefended": "none",
    "front": "front",
    "tamaraw": "tamaraw",
}
EXPECTED_PAIRED_POSITION_COUNTS = (
    ((34, 34, 32), (33, 33, 34), (33, 33, 34)),
    ((33, 33, 34), (33, 34, 33), (34, 33, 33)),
    ((34, 32, 34), (33, 34, 33), (33, 34, 33)),
    ((34, 33, 33), (33, 35, 32), (33, 32, 35)),
    ((33, 33, 34), (34, 33, 33), (33, 34, 33)),
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
FORMAL_CASES = tuple(
    (
        block,
        kind,
        CAMPAIGN_DIR / f"classifier-poc5-{kind}-{block:02d}.yml",
        20 if kind == "baseline" else 10,
        BASELINE_DEFENSES if kind == "baseline" else PAIRED_DEFENSES,
        BASELINE_SEEDS[block - 1] if kind == "baseline" else PAIRED_SEEDS[block - 1],
    )
    for block in range(1, 11)
    for kind in ("baseline", "paired")
)
FORMAL_PATHS = tuple(case[2] for case in FORMAL_CASES)
REHEARSAL_PATH = CAMPAIGN_DIR / "classifier-poc5-rehearsal.yml"
CAMPAIGN_KEYS = {
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


def _load_value(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


@pytest.fixture(scope="module")
def planning_base() -> Campaign:
    return load_campaign(CAMPAIGN_DIR / "fitting.yml")


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
    )


@pytest.mark.parametrize(
    ("block", "kind", "path", "visits", "defenses", "seed"),
    FORMAL_CASES,
)
def test_poc5_formal_campaign_contract(
    planning_base: Campaign,
    block: int,
    kind: str,
    path: Path,
    visits: int,
    defenses: tuple[str, ...],
    seed: int,
) -> None:
    value = _load_value(path)

    assert set(value) == CAMPAIGN_KEYS
    assert value["schema"] == 1
    assert value["name"] == f"research-classifier-poc5-{kind}-{block:02d}-1200"
    assert value["purpose"] == "evaluation"
    assert value["seed"] == seed
    assert value["profile"] == "research-1200"
    assert tuple(value["workloads"]) == WORKLOAD_ORDERS[block - 1]
    assert set(value["workloads"].values()) == {visits}
    assert value["request_policies"] == ["as-defined"]
    assert tuple(value["defenses"]) == defenses
    assert value["limits"] == LIMITS

    plan = plan_campaign(_planning_campaign(planning_base, path, value))
    expected_samples = len(WORKLOADS) * visits * len(defenses)
    assert len(plan) == expected_samples
    assert len({sample["sample_id"] for sample in plan}) == expected_samples
    assert len({sample["seed"] for sample in plan}) == expected_samples
    assert Counter(sample["runtime_kind"] for sample in plan) == Counter(
        {DEFENSE_KINDS[defense]: len(WORKLOADS) * visits for defense in defenses}
    )
    assert Counter((sample["workload_id"], sample["defense"]) for sample in plan) == Counter(
        {(workload_id, defense): visits for workload_id in WORKLOADS for defense in defenses}
    )


def test_poc5_formal_aggregate_is_exactly_2500_balanced_samples(
    planning_base: Campaign,
) -> None:
    actual_paths = tuple(sorted(CAMPAIGN_DIR.glob("classifier-poc5-baseline-*.yml"))) + tuple(
        sorted(CAMPAIGN_DIR.glob("classifier-poc5-paired-*.yml"))
    )
    assert len(FORMAL_PATHS) == 20
    assert actual_paths == tuple(FORMAL_PATHS[::2]) + tuple(FORMAL_PATHS[1::2])
    assert REHEARSAL_PATH not in FORMAL_PATHS

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
    assert Counter(sample["workload_id"] for sample in combined) == Counter(
        {workload_id: 500 for workload_id in WORKLOADS}
    )

    train = tuple(
        sample for plan in plans[:16] for sample in plan if sample["defense"] == "undefended"
    )
    validation = tuple(
        sample for plan in plans[16:18] for sample in plan if sample["defense"] == "undefended"
    )
    clean_test = tuple(
        sample for plan in plans[18:20] for sample in plan if sample["defense"] == "undefended"
    )
    defended_inference = tuple(
        sample for sample in combined if sample["defense"] in {"front", "tamaraw"}
    )
    assert Counter(sample["workload_id"] for sample in train) == Counter(
        {workload_id: 240 for workload_id in WORKLOADS}
    )
    assert Counter(sample["workload_id"] for sample in validation) == Counter(
        {workload_id: 30 for workload_id in WORKLOADS}
    )
    assert Counter(sample["workload_id"] for sample in clean_test) == Counter(
        {workload_id: 30 for workload_id in WORKLOADS}
    )
    assert Counter(
        (sample["workload_id"], sample["defense"]) for sample in defended_inference
    ) == Counter(
        {
            (workload_id, defense): 100
            for workload_id in WORKLOADS
            for defense in ("front", "tamaraw")
        }
    )

    defense_positions: Counter[tuple[str, str, int]] = Counter()
    for plan in plans[1::2]:
        for start in range(0, len(plan), len(PAIRED_DEFENSES)):
            visit = plan[start : start + len(PAIRED_DEFENSES)]
            assert len({(sample["workload_id"], sample["visit"]) for sample in visit}) == 1
            assert {sample["defense"] for sample in visit} == set(PAIRED_DEFENSES)
            for position, sample in enumerate(visit):
                defense_positions[(sample["workload_id"], sample["defense"], position)] += 1
    observed_position_counts = tuple(
        tuple(
            tuple(defense_positions[(workload_id, defense, position)] for position in range(3))
            for defense in PAIRED_DEFENSES
        )
        for workload_id in WORKLOADS
    )
    assert observed_position_counts == EXPECTED_PAIRED_POSITION_COUNTS
    assert min(defense_positions.values()) >= 32
    assert max(defense_positions.values()) <= 35

    for block in range(10):
        assert tuple(values[2 * block]["workloads"]) == tuple(values[2 * block + 1]["workloads"])
    positions = Counter(
        (workload_id, position)
        for order in WORKLOAD_ORDERS
        for position, workload_id in enumerate(order)
    )
    assert set(positions.values()) == {2}


def test_poc5_rehearsal_is_a_separate_excluded_30_sample_gate(
    planning_base: Campaign,
) -> None:
    value = _load_value(REHEARSAL_PATH)

    assert set(value) == CAMPAIGN_KEYS
    assert value["name"] == "research-classifier-poc5-rehearsal-1200"
    assert value["seed"] == REHEARSAL_SEED
    assert tuple(value["workloads"]) == WORKLOADS
    assert set(value["workloads"].values()) == {2}
    assert tuple(value["defenses"]) == PAIRED_DEFENSES
    assert value["limits"] == LIMITS
    assert REHEARSAL_PATH not in FORMAL_PATHS
    assert set(CAMPAIGN_DIR.glob("classifier-poc5-*.yml")) == {
        *FORMAL_PATHS,
        REHEARSAL_PATH,
    }

    rehearsal = plan_campaign(_planning_campaign(planning_base, REHEARSAL_PATH, value))
    formal_ids = {
        sample["sample_id"]
        for path in FORMAL_PATHS
        for sample in plan_campaign(_planning_campaign(planning_base, path, _load_value(path)))
    }
    assert len(rehearsal) == 30
    assert len({sample["sample_id"] for sample in rehearsal}) == 30
    assert len({sample["seed"] for sample in rehearsal}) == 30
    assert formal_ids.isdisjoint({sample["sample_id"] for sample in rehearsal})
    assert Counter((sample["workload_id"], sample["defense"]) for sample in rehearsal) == Counter(
        {(workload_id, defense): 2 for workload_id in WORKLOADS for defense in PAIRED_DEFENSES}
    )
