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
FROZEN_RESEARCH_WORKLOADS = (
    "getbootstrap-home-r3",
    "bootstrap-introduction-r3",
    "apache-traffic-server-docs-r3",
    "nginx-quic-r3",
    "cloudflare-quiche-r3",
    "nghttp2-ngtcp2-r3",
)
CHECKED_IN_SMOKE_WORKLOADS = (
    "cloudflare-quiche-r3",
    "bootstrap-introduction-r3",
)
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
STATIC_CONTROL_ROWS = (
    ("0.025000", 1200),
    ("0.030000", -1200),
    ("0.035000", 1200),
    ("0.040000", -1200),
)


def _clean_runtime_source() -> dict[str, Any]:
    return {
        "image_digest": "sha256:" + "a" * 64,
        "lab_commit": "b" * 40,
        "lab_dirty": False,
        "lab_patch_sha256": EMPTY_SHA256,
        "neqo_commit": "c" * 40,
        "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False,
        "neqo_patch_sha256": EMPTY_SHA256,
    }


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
        "# seconds,signed_size\n"
        + "".join(f"{seconds},{size}\n" for seconds, size in STATIC_CONTROL_ROWS),
        encoding="utf-8",
    )


def test_static_control_has_startup_lead_and_exact_alternating_sequence() -> None:
    root = Path(__file__).parents[1]
    for name in ("static-control-1200.csv", "static-migration.csv"):
        rows = tuple(
            (seconds, int(signed_size))
            for seconds, signed_size in (
                line.split(",")
                for line in (root / "config/defense-params" / name)
                .read_text(encoding="utf-8")
                .splitlines()
                if line and not line.startswith("#")
            )
        )
        assert rows == STATIC_CONTROL_ROWS


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


def _copy_checked_in_smoke_inputs(destination: Path) -> Path:
    source = Path(__file__).parents[1]
    campaigns = destination / "config/campaigns"
    workloads = destination / "config/workloads"
    parameters = destination / "config/defense-params"
    campaigns.mkdir(parents=True)
    workloads.mkdir()
    parameters.mkdir()
    shutil.copy2(source / "config/campaigns/smoke.yml", campaigns / "smoke.yml")
    shutil.copy2(
        source / "config/defense-params/static-control-1200.csv",
        parameters / "static-control-1200.csv",
    )
    for workload_id in CHECKED_IN_SMOKE_WORKLOADS:
        shutil.copy2(
            source / f"config/workloads/{workload_id}.json",
            workloads / f"{workload_id}.json",
        )
    return campaigns / "smoke.yml"


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


def test_checked_in_smoke_is_post_fit_evaluation_and_requires_the_sealed_bundle(
    tmp_path: Path,
) -> None:
    checked_in = Path(__file__).parents[1] / "config/campaigns/smoke.yml"
    value = yaml.safe_load(checked_in.read_text(encoding="utf-8"))
    static = next(
        defense
        for defense in value["defenses"]
        if isinstance(defense, dict) and defense.get("kind") == "static"
    )
    parameter_paths = {
        defense["name"]: defense["parameters"]
        for defense in value["defenses"]
        if isinstance(defense, dict) and "parameters" in defense
    }

    assert value["name"] == "research-smoke-1200"
    assert value["purpose"] == "evaluation"
    assert value["seed"] == 2_026_081_204
    assert value["profile"] == "research-1200"
    assert list(value["workloads"]) == list(CHECKED_IN_SMOKE_WORKLOADS)
    assert value["request_policies"] == ["as-defined"]
    assert len(value["workloads"]) * len(value["request_policies"]) * len(value["defenses"]) == 14
    assert static["name"] == "static-control"
    assert Path(static["schedule"]).name == "static-control-1200.csv"
    assert parameter_paths == {
        "traffic-morphing": "../../artifacts/research-1200/traffic-morphing.json",
        "wtf-pad": "../../artifacts/research-1200/wtf-pad.json",
        "walkie-talkie": "../../artifacts/research-1200/walkie-talkie.json",
    }
    assert value["limits"]["capture_megabytes"] == 64

    path = _copy_checked_in_smoke_inputs(tmp_path)
    with pytest.raises(
        ValueError,
        match=r"evaluation campaign requires a sealed research bundle at .*"
        r"run \./qcsd-lab fit <fitting-result> first",
    ):
        orchestrator.load_campaign(path)


def test_checked_in_smoke_loads_with_a_temporary_production_bundle(tmp_path: Path) -> None:
    fitting_result = _make_fitting_result(
        tmp_path / "fitting-source",
        workloads=FROZEN_RESEARCH_WORKLOADS,
    )
    bundle = fit_result(fitting_result, artifacts_root=tmp_path / "fitted-artifacts")
    campaign_root = tmp_path / "campaign"
    path = _copy_checked_in_smoke_inputs(campaign_root)
    shutil.copytree(bundle, campaign_root / "artifacts/research-1200")

    campaign = orchestrator.load_campaign(path)
    plan = orchestrator.plan_campaign(campaign)
    assert campaign.name == "research-smoke-1200"
    assert campaign.purpose == "evaluation"
    assert campaign.seed == 2_026_081_204
    assert campaign.profile == "research-1200"
    assert [workload.id for workload in campaign.workloads] == list(CHECKED_IN_SMOKE_WORKLOADS)
    assert len(plan) == 14
    assert {sample["defense"] for sample in plan} == set(DEFENSES)
    assert {
        (sample["workload_id"], sample["request_policy"], sample["visit"]) for sample in plan
    } == {(workload_id, "as-defined", 0) for workload_id in CHECKED_IN_SMOKE_WORKLOADS}


def test_checked_in_fitting_campaign_freezes_six_prepared_workloads_and_120_samples() -> None:
    root = Path(__file__).parents[1]
    path = root / "config/campaigns/fitting.yml"
    campaign = orchestrator.load_campaign(path)

    assert campaign.name == "research-fitting-1200"
    assert campaign.seed == 2_026_081_201
    assert campaign.profile == "research-1200"
    assert campaign.request_policies == ("as-defined", "half-duplex")
    assert [workload.id for workload in campaign.workloads] == list(FROZEN_RESEARCH_WORKLOADS)
    assert all(workload.visits == 10 for workload in campaign.workloads)
    assert len(orchestrator.plan_campaign(campaign)) == 120
    for workload in campaign.workloads:
        validate_research_preparation(workload.data, workload_id=workload.id)


def test_exact_research_expansions_and_seeded_order_are_deterministic(
    research_workspace: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, _bundle = research_workspace
    monkeypatch.setattr(orchestrator, "source_metadata", _clean_runtime_source)
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


@pytest.mark.parametrize(
    "mutation",
    [
        "name",
        "seed",
        "profile",
        "workload-count",
        "visit-count",
        "policy-order",
        "defense-count",
        "defense-alias",
        "missing-limit",
        "changed-limit",
    ],
)
def test_fitting_campaign_load_rejects_every_contract_deviation(
    tmp_path: Path,
    research_workspace: tuple[Path, Path],
    mutation: str,
) -> None:
    source, _bundle = research_workspace
    _copy_prepared_inputs(source, tmp_path)
    value = yaml.safe_load((source / "config/campaigns/fitting.yml").read_text(encoding="utf-8"))
    if mutation == "name":
        value["name"] = "alternate-fitting-name"
    elif mutation == "seed":
        value["seed"] += 1
    elif mutation == "profile":
        value["profile"] = "published"
    elif mutation == "workload-count":
        value["workloads"].pop(next(iter(value["workloads"])))
    elif mutation == "visit-count":
        value["workloads"][next(iter(value["workloads"]))] = 9
    elif mutation == "policy-order":
        value["request_policies"].reverse()
    elif mutation == "defense-count":
        value["defenses"].append("front")
    elif mutation == "defense-alias":
        value["defenses"] = [{"name": "fitting-baseline", "kind": "none"}]
    elif mutation == "missing-limit":
        value["limits"].pop("capture_megabytes")
    else:
        value["limits"]["capture_seconds"] = 181
    path = _write_campaign(tmp_path, "invalid-fitting.yml", value)

    with pytest.raises(ValueError, match="research fitting campaigns require"):
        orchestrator.load_campaign(path)


@pytest.mark.parametrize(
    "mutation",
    ["missing-field", "image", "dirty", "patch", "commit", "unpinned"],
)
def test_fitting_preflight_and_run_reject_invalid_runtime_provenance_before_result_creation(
    tmp_path: Path,
    research_workspace: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    source, _bundle = research_workspace
    _copy_prepared_inputs(source, tmp_path)
    value = yaml.safe_load((source / "config/campaigns/fitting.yml").read_text(encoding="utf-8"))
    path = _write_campaign(tmp_path, "fitting.yml", value)
    provenance = _clean_runtime_source()
    if mutation == "missing-field":
        provenance.pop("image_digest")
    elif mutation == "image":
        provenance["image_digest"] = None
    elif mutation == "dirty":
        provenance["lab_dirty"] = True
    elif mutation == "patch":
        provenance["neqo_patch_sha256"] = "d" * 64
    elif mutation == "commit":
        provenance["lab_commit"] = "not-a-commit"
    else:
        provenance["neqo_pinned_commit"] = "d" * 40
    monkeypatch.setattr(orchestrator, "source_metadata", lambda: provenance)

    with pytest.raises(ValueError, match="research fitting capture requires"):
        orchestrator.preflight_campaign(path)
    results = tmp_path / "results"
    with pytest.raises(ValueError, match="research fitting capture requires"):
        orchestrator.run_campaign(path, results)
    assert not results.exists()


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
