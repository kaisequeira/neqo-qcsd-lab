from __future__ import annotations

import hashlib
import json
import shutil
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml

import qcsd_lab.orchestrator as orchestrator
from qcsd_lab.capture_session import PARAMETER_FLAG_BY_KIND
from qcsd_lab.fitting import EXACT_BUNDLE_FILES, fit_result
from qcsd_lab.manifest import validate_research_preparation
from qcsd_lab.util import sha256_file
from tests.test_fitting_bundle import WORKLOADS, _make_fitting_result


DEFENSES = (
    "undefended",
    "static-control",
    "front",
    "tamaraw",
    "traffic-morphing",
    "wtf-pad",
    "walkie-talkie",
)


@pytest.fixture(scope="module")
def research_workspace(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """Create six strict manifests and one real, production-verified temporary bundle."""

    base = tmp_path_factory.mktemp("research-campaign-contract")
    result = _make_fitting_result(base)
    bundle = fit_result(result, artifacts_root=base / "artifacts")
    for workload_id in WORKLOADS:
        manifest = json.loads((base / f"config/workloads/{workload_id}.json").read_text())
        validate_research_preparation(manifest, workload_id=workload_id)
    _write_static_control(base)
    return base, bundle


def _write_static_control(base: Path) -> None:
    path = base / "config/defense-params/static-control-1200.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# seconds,signed_size\n0.000000,1200\n0.005000,-1200\n0.010000,1200\n0.015000,-1200\n",
        encoding="utf-8",
    )


def _evaluation_campaign(
    *, name: str, seed: int, visits: int, bundle_paths: dict[str, Path] | None = None
) -> dict[str, Any]:
    paths = bundle_paths or {
        "traffic-morphing": Path("../../artifacts/research-1200/traffic-morphing.json"),
        "wtf-pad": Path("../../artifacts/research-1200/wtf-pad.json"),
        "walkie-talkie": Path("../../artifacts/research-1200/walkie-talkie.json"),
    }
    return {
        "schema": 1,
        "name": name,
        "purpose": "evaluation",
        "seed": seed,
        "profile": "research-1200",
        "workloads": {workload_id: visits for workload_id in WORKLOADS},
        "request_policies": ["as-defined"],
        "defenses": [
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
                "parameters": str(paths["traffic-morphing"]),
            },
            {
                "name": "wtf-pad",
                "kind": "wtf_pad",
                "parameters": str(paths["wtf-pad"]),
            },
            {
                "name": "walkie-talkie",
                "kind": "walkie_talkie",
                "parameters": str(paths["walkie-talkie"]),
            },
        ],
    }


def _write_campaign(base: Path, filename: str, value: dict[str, Any]) -> Path:
    path = base / "config/campaigns" / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    return path


def _copy_prepared_inputs(source: Path, destination: Path) -> None:
    workloads = destination / "config/workloads"
    workloads.mkdir(parents=True)
    for workload_id in WORKLOADS:
        shutil.copy2(
            source / f"config/workloads/{workload_id}.json",
            workloads / f"{workload_id}.json",
        )
    _write_static_control(destination)


def _stable_digest(*parts: object) -> str:
    digest = hashlib.sha256()
    for part in parts:
        encoded = str(part).encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _assert_deterministic_plan(path: Path, expected_count: int) -> list[dict[str, Any]]:
    first_campaign = orchestrator.load_campaign(path)
    second_campaign = orchestrator.load_campaign(path)
    first = orchestrator.plan_campaign(first_campaign)
    second = orchestrator.plan_campaign(second_campaign)
    assert first == second
    assert len(first) == expected_count
    assert len({sample["sample_id"] for sample in first}) == expected_count
    for sample in first:
        seed_digest = _stable_digest(
            "sample-seed",
            first_campaign.seed,
            sample["workload_id"],
            sample["request_policy"],
            sample["visit"],
            sample["defense"],
        )
        expected_seed = int(seed_digest[:16], 16)
        assert sample["seed"] == expected_seed
        assert sample["sample_id"] == _stable_digest(
            "sample",
            first_campaign.name,
            sample["workload_id"],
            sample["request_policy"],
            sample["visit"],
            sample["defense"],
            expected_seed,
        )
    preflight = orchestrator.preflight_campaign(path)
    assert preflight["sample_count"] == expected_count
    assert preflight["execution_order"] == [sample["sample_id"] for sample in first]
    return first


def test_research_preparation_rejects_legacy_but_smoke_still_accepts(tmp_path: Path) -> None:
    workload_dir = tmp_path / "config/workloads"
    workload_dir.mkdir(parents=True)
    (workload_dir / "legacy.json").write_text(
        json.dumps(
            {
                "resources": [
                    {
                        "id": 0,
                        "url": "https://legacy.test/",
                        "depends_on": [],
                        "headers": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    campaign = {
        "schema": 1,
        "name": "legacy-contract",
        "purpose": "smoke",
        "seed": 1,
        "profile": "research-1200",
        "workloads": {"legacy": 1},
        "request_policies": ["as-defined"],
        "defenses": ["undefended"],
    }
    path = _write_campaign(tmp_path, "legacy.yml", campaign)

    assert orchestrator.load_campaign(path).purpose == "smoke"
    for purpose in ("fitting", "evaluation"):
        changed = {**campaign, "purpose": purpose}
        path.write_text(yaml.safe_dump(changed, sort_keys=False), encoding="utf-8")
        with pytest.raises(ValueError, match=r"\./qcsd-lab prepare.*research-grade provenance"):
            orchestrator.load_campaign(path)


def test_checked_in_smoke_names_the_mechanical_control_and_remains_14_samples() -> None:
    path = Path(__file__).parents[1] / "config/campaigns/smoke.yml"
    campaign = orchestrator.load_campaign(path)
    static = next(defense for defense in campaign.defenses if defense.kind == "static")

    assert len(orchestrator.plan_campaign(campaign)) == 14
    assert static.name == "static-control"
    assert static.schedule_path is not None
    assert static.schedule_path.name == "static-control-1200.csv"


def test_exact_research_expansions_and_seeded_order_are_deterministic(
    research_workspace: tuple[Path, Path],
) -> None:
    base, _bundle = research_workspace
    fitting_path = base / "config/campaigns/fitting.yml"
    rehearsal_value = _evaluation_campaign(name="research-rehearsal", seed=4_242, visits=1)
    final_value = _evaluation_campaign(name="research-final", seed=9_999, visits=3)
    rehearsal_path = _write_campaign(base, "rehearsal.yml", rehearsal_value)
    final_path = _write_campaign(base, "final.yml", final_value)

    fitting = _assert_deterministic_plan(fitting_path, 120)
    rehearsal = _assert_deterministic_plan(rehearsal_path, 42)
    final = _assert_deterministic_plan(final_path, 126)

    fitting_groups = [
        (workload_id, policy, visit)
        for workload_id in WORKLOADS
        for policy in ("as-defined", "half-duplex")
        for visit in range(10)
    ]
    assert [
        (sample["workload_id"], sample["request_policy"], sample["visit"]) for sample in fitting
    ] == fitting_groups
    for plan, visits in ((rehearsal, 1), (final, 3)):
        chunks = [plan[index : index + len(DEFENSES)] for index in range(0, len(plan), 7)]
        assert [
            (chunk[0]["workload_id"], chunk[0]["request_policy"], chunk[0]["visit"])
            for chunk in chunks
        ] == [
            (workload_id, "as-defined", visit)
            for workload_id in WORKLOADS
            for visit in range(visits)
        ]
        assert all({sample["defense"] for sample in chunk} == set(DEFENSES) for chunk in chunks)

    normalized_rehearsal = deepcopy(rehearsal_value)
    normalized_final = deepcopy(final_value)
    assert {key for key in rehearsal_value if rehearsal_value[key] != final_value[key]} == {
        "name",
        "seed",
        "workloads",
    }
    for value in (normalized_rehearsal, normalized_final):
        value.pop("name")
        value.pop("seed")
        value["workloads"] = list(value["workloads"])
    assert normalized_rehearsal == normalized_final

    expected_workloads = [
        (workload_id, sha256_file(base / f"config/workloads/{workload_id}.json"))
        for workload_id in WORKLOADS
    ]
    for path in (fitting_path, rehearsal_path, final_path):
        campaign = orchestrator.load_campaign(path)
        assert [(workload.id, workload.sha256) for workload in campaign.workloads] == (
            expected_workloads
        )


def test_evaluation_missing_bundle_error_is_stable_and_actionable(
    tmp_path: Path, research_workspace: tuple[Path, Path]
) -> None:
    source, _bundle = research_workspace
    _copy_prepared_inputs(source, tmp_path)
    path = _write_campaign(
        tmp_path,
        "missing.yml",
        _evaluation_campaign(name="missing-bundle", seed=7, visits=1),
    )

    with pytest.raises(
        ValueError,
        match=r"evaluation campaign requires a sealed research bundle at .*"
        r"run \./qcsd-lab fit <fitting-result> first",
    ):
        orchestrator.load_campaign(path)


@pytest.mark.parametrize("mutation", ["partial", "extra", "tampered"])
def test_evaluation_rejects_inexact_research_bundles(
    tmp_path: Path,
    research_workspace: tuple[Path, Path],
    mutation: str,
) -> None:
    source, valid_bundle = research_workspace
    _copy_prepared_inputs(source, tmp_path)
    bundle = tmp_path / "artifacts/research-1200"
    shutil.copytree(valid_bundle, bundle)
    if mutation == "partial":
        (bundle / "walkie-talkie.json").unlink()
    elif mutation == "extra":
        (bundle / "unexpected.json").write_text("{}\n", encoding="utf-8")
    else:
        with (bundle / "traffic-morphing.json").open("ab") as output:
            output.write(b" ")
    path = _write_campaign(
        tmp_path,
        f"{mutation}.yml",
        _evaluation_campaign(name=f"{mutation}-bundle", seed=8, visits=1),
    )

    with pytest.raises(ValueError, match="evaluation campaign research bundle is invalid"):
        orchestrator.load_campaign(path)


def test_evaluation_rejects_mixed_research_bundle_roots(
    tmp_path: Path, research_workspace: tuple[Path, Path]
) -> None:
    source, valid_bundle = research_workspace
    _copy_prepared_inputs(source, tmp_path)
    first = tmp_path / "bundle-one"
    second = tmp_path / "bundle-two"
    shutil.copytree(valid_bundle, first)
    shutil.copytree(valid_bundle, second)
    paths = {
        "traffic-morphing": first / "traffic-morphing.json",
        "wtf-pad": second / "wtf-pad.json",
        "walkie-talkie": first / "walkie-talkie.json",
    }
    path = _write_campaign(
        tmp_path,
        "mixed.yml",
        _evaluation_campaign(name="mixed-bundles", seed=9, visits=1, bundle_paths=paths),
    )

    with pytest.raises(ValueError, match="one common sealed research bundle"):
        orchestrator.load_campaign(path)


def test_evaluation_freezes_one_common_bundle_and_revalidates_preparation(
    tmp_path: Path, research_workspace: tuple[Path, Path]
) -> None:
    base, _bundle = research_workspace
    campaign_path = base / "config/campaigns/rehearsal.yml"
    campaign = orchestrator.load_campaign(campaign_path)
    root = tmp_path / "materialized"
    runtime, configuration = orchestrator._materialize_inputs(root, campaign, {})

    frozen_bundle = root / "inputs/defense-parameters/research-1200"
    assert {path.name for path in frozen_bundle.iterdir()} == EXACT_BUNDLE_FILES
    assert list((root / "inputs/defense-parameters").rglob("provenance.json")) == [
        frozen_bundle / "provenance.json"
    ]
    parameter_files = [
        path for path in frozen_bundle.glob("*.json") if path.name != "provenance.json"
    ]
    assert {path.name for path in parameter_files} == EXACT_BUNDLE_FILES - {"provenance.json"}

    parameterized = [
        record for record in configuration["defenses"] if record["kind"] in PARAMETER_FLAG_BY_KIND
    ]
    expected_receipt = "inputs/defense-parameters/research-1200/provenance.json"
    assert len(parameterized) == 3
    assert {record["provenance"] for record in parameterized} == {expected_receipt}
    assert len({record["provenance_sha256"] for record in parameterized}) == 1
    assert {record["parameters"] for record in parameterized} == {
        f"inputs/defense-parameters/research-1200/{name}"
        for name in ("traffic-morphing.json", "wtf-pad.json", "walkie-talkie.json")
    }

    frozen = orchestrator._load_campaign(
        root / "inputs/campaign.yml",
        frozen_inputs=root / "inputs",
    )
    assert orchestrator.plan_campaign(frozen) == orchestrator.plan_campaign(runtime)

    workload_path = root / f"inputs/workloads/{WORKLOADS[0]}.json"
    workload = json.loads(workload_path.read_text(encoding="utf-8"))
    workload.pop("preparation")
    workload_path.write_text(json.dumps(workload), encoding="utf-8")
    with pytest.raises(ValueError, match=r"\./qcsd-lab prepare.*research-grade provenance"):
        orchestrator._load_campaign(
            root / "inputs/campaign.yml",
            frozen_inputs=root / "inputs",
        )
