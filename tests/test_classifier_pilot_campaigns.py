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
PILOT_PATHS = tuple(CAMPAIGN_DIR / f"classifier-pilot-{block:02d}.yml" for block in range(1, 8))
WORKLOADS = (
    "getbootstrap-home-r3",
    "bootstrap-introduction-r3",
    "apache-traffic-server-docs-r3",
    "nginx-quic-r3",
    "cloudflare-quiche-r3",
    "nghttp2-ngtcp2-r3",
)
WORKLOAD_ORDERS = tuple(
    WORKLOADS[offset:] + WORKLOADS[:offset] for offset in range(len(WORKLOADS))
) + (tuple(reversed(WORKLOADS)),)
DEFENSES = (
    "undefended",
    "static-control",
    "front",
    "tamaraw",
    "traffic-morphing",
    "wtf-pad",
    "walkie-talkie",
)
PILOT_SEEDS = (
    2_026_002_447,
    2_026_013_892,
    2_026_012_707,
    2_026_020_253,
    2_026_034_124,
    2_026_000_066,
    2_026_000_506,
)
DEFENSE_KINDS = {
    "undefended": "none",
    "static-control": "static",
    "front": "front",
    "tamaraw": "tamaraw",
    "traffic-morphing": "traffic_morphing",
    "wtf-pad": "wtf_pad",
    "walkie-talkie": "walkie_talkie",
}
DEFENSE_CONFIGURATION: list[str | dict[str, str]] = [
    "undefended",
    {
        "name": "static-control",
        "kind": "static",
        "schedule": "../defense-params/static-control-1200.csv",
        "mode": "chaff-only",
    },
    "front",
    "tamaraw",
    {
        "name": "traffic-morphing",
        "kind": "traffic_morphing",
        "parameters": "../../artifacts/research-1200/traffic-morphing.json",
    },
    {
        "name": "wtf-pad",
        "kind": "wtf_pad",
        "parameters": "../../artifacts/research-1200/wtf-pad.json",
    },
    {
        "name": "walkie-talkie",
        "kind": "walkie_talkie",
        "parameters": "../../artifacts/research-1200/walkie-talkie.json",
    },
]
LIMITS = {
    "timeout_seconds": 120,
    "max_response_bytes": 1_048_576,
    "capture_seconds": 180,
    "capture_megabytes": 64,
    "max_attempts": 3,
    "per_origin_cooldown_seconds": 30,
    "settle_seconds": 1,
}


def _load_value(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


@pytest.fixture(scope="module")
def planning_base() -> Campaign:
    # The fitting campaign loads without crossing the evaluation-bundle authority
    # boundary and supplies the exact six checked-in prepared workload objects.
    return load_campaign(CAMPAIGN_DIR / "fitting.yml")


def _planning_campaign(base: Campaign, path: Path, value: dict[str, Any]) -> Campaign:
    workloads = {workload.id: workload for workload in base.workloads}
    defenses = tuple(
        Defense(
            name=entry if isinstance(entry, str) else entry["name"],
            kind=DEFENSE_KINDS[entry if isinstance(entry, str) else entry["name"]],
            baseline=entry == "undefended",
        )
        for entry in value["defenses"]
    )
    return replace(
        base,
        path=path,
        source_bytes=path.read_bytes(),
        name=value["name"],
        purpose=value["purpose"],
        seed=value["seed"],
        profile=value["profile"],
        workloads=tuple(
            replace(workloads[workload_id], visits=visits)
            for workload_id, visits in value["workloads"].items()
        ),
        request_policies=tuple(value["request_policies"]),
        defenses=defenses,
        limits=Limits(**value["limits"]),
    )


@pytest.mark.parametrize(
    ("block", "path", "expected_order"),
    tuple(zip(range(1, 8), PILOT_PATHS, WORKLOAD_ORDERS, strict=True)),
)
def test_classifier_pilot_block_contract_and_exact_42_sample_expansion(
    planning_base: Campaign,
    block: int,
    path: Path,
    expected_order: tuple[str, ...],
) -> None:
    value = _load_value(path)

    assert set(value) == {
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
    assert value["schema"] == 1
    assert value["name"] == f"research-classifier-pilot-{block:02d}-1200"
    assert value["purpose"] == "evaluation"
    assert value["seed"] == PILOT_SEEDS[block - 1]
    assert value["profile"] == "research-1200"
    assert tuple(value["workloads"]) == expected_order
    assert set(value["workloads"].values()) == {1}
    assert value["request_policies"] == ["as-defined"]
    assert value["defenses"] == DEFENSE_CONFIGURATION
    assert value["limits"] == LIMITS

    plan = plan_campaign(_planning_campaign(planning_base, path, value))
    assert len(plan) == 42
    assert len({sample["sample_id"] for sample in plan}) == 42
    chunks = tuple(plan[index : index + len(DEFENSES)] for index in range(0, 42, 7))
    assert tuple(chunk[0]["workload_id"] for chunk in chunks) == expected_order
    for chunk in chunks:
        assert len(chunk) == 7
        assert {sample["workload_id"] for sample in chunk} == {chunk[0]["workload_id"]}
        assert {sample["request_policy"] for sample in chunk} == {"as-defined"}
        assert {sample["visit"] for sample in chunk} == {0}
        assert {sample["defense"] for sample in chunk} == set(DEFENSES)


def test_classifier_pilot_blocks_are_distinct_and_expand_to_294_samples(
    planning_base: Campaign,
) -> None:
    assert tuple(sorted(CAMPAIGN_DIR.glob("classifier-pilot-*.yml"))) == PILOT_PATHS
    values = tuple(_load_value(path) for path in PILOT_PATHS)
    assert len({value["name"] for value in values}) == 7
    assert len({value["seed"] for value in values}) == 7
    assert len({tuple(value["workloads"]) for value in values}) == 7

    combined = [
        sample
        for path, value in zip(PILOT_PATHS, values, strict=True)
        for sample in plan_campaign(_planning_campaign(planning_base, path, value))
    ]
    assert len(combined) == 294
    assert len({sample["sample_id"] for sample in combined}) == 294
    assert Counter((sample["workload_id"], sample["defense"]) for sample in combined) == Counter(
        {(workload_id, defense): 7 for workload_id in WORKLOADS for defense in DEFENSES}
    )

    position_counts: Counter[tuple[str, str, int]] = Counter()
    for path, value in zip(PILOT_PATHS, values, strict=True):
        plan = plan_campaign(_planning_campaign(planning_base, path, value))
        for start in range(0, len(plan), len(DEFENSES)):
            for position, sample in enumerate(plan[start : start + len(DEFENSES)]):
                position_counts[(sample["workload_id"], sample["defense"], position)] += 1
    assert max(position_counts.values()) <= 2
