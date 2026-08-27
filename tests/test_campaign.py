from __future__ import annotations

import json
from collections import Counter
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

import qcsd_lab.chaff_qualification as chaff_qualification
import qcsd_lab.orchestrator as orchestrator
from qcsd_lab.capture import split_endpoint, tuple_filter
from qcsd_lab.capture_session import (
    Defense,
    Limits,
    _client_command,
    _process_scheduler_valid,
    _runner_result_complete,
    _validate_chaff_response_receipts,
    _validate_run_binding,
)
from qcsd_lab.orchestrator import (
    load_campaign,
    plan_campaign,
    preflight_campaign,
    run_campaign,
)
from qcsd_lab.manifest import canonical_bytes
from qcsd_lab.util import atomic_json, load_json, sha256_bytes, sha256_file
from qcsd_lab.verification import verify_result


def _resource(
    identifier: int,
    url: str,
    *,
    depends_on: list[int] | None = None,
    headers: list[list[str]] | None = None,
) -> dict[str, Any]:
    return {
        "id": identifier,
        "url": url,
        "type": "Document" if identifier == 0 else "Other",
        "content_length": 64,
        "data_length": 64,
        "chaff_priority": identifier == 0,
        "known_valid": True,
        "depends_on": depends_on or [],
        "headers": headers or [],
    }


def _configuration(
    tmp_path: Path,
    *,
    workloads: dict[str, tuple[int, list[dict[str, Any]]]] | None = None,
    policies: list[str] | None = None,
    defenses: list[str | dict[str, Any]] | None = None,
    max_attempts: int = 2,
    profile: str = "live",
) -> Path:
    config = tmp_path / "config"
    campaign_dir = config / "campaigns"
    workload_dir = config / "workloads"
    campaign_dir.mkdir(parents=True)
    workload_dir.mkdir()
    workloads = workloads or {
        "alpha": (
            1,
            [_resource(0, "https://alpha.test/", headers=[["accept", "text/html"]])],
        )
    }
    visits: dict[str, int] = {}
    for identifier, (visit_count, resources) in workloads.items():
        visits[identifier] = visit_count
        (workload_dir / f"{identifier}.json").write_text(
            json.dumps({"resources": resources}, sort_keys=True),
            encoding="utf-8",
        )
    campaign = {
        "schema": 1,
        "name": "contract-test",
        "purpose": "smoke",
        "seed": 7_331,
        "profile": profile,
        "workloads": visits,
        "request_policies": policies or ["as-defined"],
        "defenses": defenses or ["undefended"],
        "limits": {
            "timeout_seconds": 1,
            "max_response_bytes": 4096,
            "capture_seconds": 2,
            "capture_megabytes": 1,
            "max_attempts": max_attempts,
            "per_origin_cooldown_seconds": 0,
            "settle_seconds": 0,
        },
    }
    path = campaign_dir / "campaign.yml"
    path.write_text(yaml.safe_dump(campaign, sort_keys=False), encoding="utf-8")
    return path


def _schema_six_qualification_materialization_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, dict[str, Any], dict[str, dict[str, Any]]]:
    source = tmp_path / "config"
    inputs = tmp_path / "result/inputs"
    for directory in (
        source / "workloads",
        source / "chaff-qualification-store/v2",
        source / "chaff-prefix-specs/v2",
    ):
        directory.mkdir(parents=True)
    inputs.mkdir(parents=True)

    records: list[dict[str, Any]] = []
    manifests: dict[str, dict[str, Any]] = {}
    for index, workload_id in enumerate(chaff_qualification.SEALED_WORKLOAD_IDS):
        application = source / "workloads" / f"{workload_id}.json"
        sidecar = source / "chaff-qualification-store/v2" / f"{workload_id}.json"
        spec = source / "chaff-prefix-specs/v2" / f"{workload_id}.json"
        atomic_json(
            application,
            {"resources": [_resource(0, f"https://{workload_id}.test/")]},
        )
        atomic_json(sidecar, {"sidecar": workload_id})
        atomic_json(spec, {"spec": workload_id})
        manifest = {"qualified": workload_id, "resource_index": index}
        manifests[workload_id] = manifest
        records.append(
            {
                "workload_id": workload_id,
                "application_workload_sha256": sha256_file(application),
                "chaff_qualification_sidecar": {
                    "path": f"config/chaff-qualification-store/v2/{workload_id}.json",
                    "sha256": sha256_file(sidecar),
                },
                "prefix_pack_spec": {
                    "path": f"config/chaff-prefix-specs/v2/{workload_id}.json",
                    "sha256": sha256_file(spec),
                },
                "qualified_chaff_manifest_sha256": sha256_bytes(canonical_bytes(manifest)),
            }
        )

    def load_qualified_chaff(
        sidecar_path: Path,
        *,
        workload_id: str,
        base_manifest_path: Path,
        prefix_spec_path: Path,
        require_current_implementation: bool = True,
    ) -> SimpleNamespace:
        assert require_current_implementation is True
        assert prefix_spec_path.is_file()
        manifest = manifests[workload_id]
        return SimpleNamespace(
            application_manifest_sha256=sha256_file(base_manifest_path),
            sidecar_sha256=sha256_file(sidecar_path),
            manifest=manifest,
            manifest_sha256=sha256_bytes(canonical_bytes(manifest)),
        )

    monkeypatch.setattr(chaff_qualification, "load_qualified_chaff", load_qualified_chaff)
    provenance = {"runtime_qualification_inputs": {"workloads": records}}
    return source, inputs, provenance, manifests


def test_schema_six_materialization_freezes_exact_cohort_without_expanding_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, inputs, provenance, manifests = _schema_six_qualification_materialization_inputs(
        tmp_path,
        monkeypatch,
    )
    selected = chaff_qualification.SEALED_WORKLOAD_IDS[1:3]
    existing: set[Path] = set()
    for source_directory, frozen_directory in (
        (source / "workloads", inputs / "workloads"),
        (source / "chaff-qualification-store/v2", inputs / "chaff-qualifications"),
        (source / "chaff-prefix-specs/v2", inputs / "chaff-prefix-specs"),
    ):
        frozen_directory.mkdir(exist_ok=True)
        for workload_id in selected:
            destination = frozen_directory / f"{workload_id}.json"
            destination.write_bytes((source_directory / destination.name).read_bytes())
            existing.add(destination)
    manifest_directory = inputs / "chaff-manifests"
    manifest_directory.mkdir()
    for workload_id in selected:
        destination = manifest_directory / f"{workload_id}.json"
        destination.write_bytes(canonical_bytes(manifests[workload_id]))
        existing.add(destination)

    original_write_bytes = Path.write_bytes

    def reject_selected_rewrite(path: Path, data: bytes) -> int:
        if path in existing:
            raise AssertionError(f"selected campaign evidence was recopied: {path}")
        return original_write_bytes(path, data)

    monkeypatch.setattr(Path, "write_bytes", reject_selected_rewrite)
    orchestrator._materialize_schema_six_qualification_evidence(
        inputs,
        qualification_inputs_root=source,
        provenance=provenance,
    )

    expected = set(chaff_qualification.SEALED_WORKLOAD_IDS)
    for directory in (
        "workloads",
        "chaff-qualifications",
        "chaff-prefix-specs",
        "chaff-manifests",
    ):
        assert {path.stem for path in (inputs / directory).iterdir()} == expected
    assert not (inputs / "runtime-workloads").exists()


def test_schema_six_materialization_rejects_a_changed_selected_frozen_input(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, inputs, provenance, _manifests = _schema_six_qualification_materialization_inputs(
        tmp_path,
        monkeypatch,
    )
    workload_id = chaff_qualification.SEALED_WORKLOAD_IDS[0]
    frozen_workloads = inputs / "workloads"
    frozen_workloads.mkdir()
    changed = frozen_workloads / f"{workload_id}.json"
    atomic_json(changed, {"changed": True})
    before = changed.read_bytes()

    with pytest.raises(ValueError, match=f"{workload_id} frozen workload changed"):
        orchestrator._materialize_schema_six_qualification_evidence(
            inputs,
            qualification_inputs_root=source,
            provenance=provenance,
        )
    assert changed.read_bytes() == before


def test_schema_six_materialization_rejects_symlinked_directory_without_external_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, inputs, provenance, _manifests = _schema_six_qualification_materialization_inputs(
        tmp_path,
        monkeypatch,
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (inputs / "chaff-qualifications").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="directory is not regular"):
        orchestrator._materialize_schema_six_qualification_evidence(
            inputs,
            qualification_inputs_root=source,
            provenance=provenance,
        )
    assert list(outside.iterdir()) == []


def test_schema_six_materialization_rejects_source_copy_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, inputs, provenance, _manifests = _schema_six_qualification_materialization_inputs(
        tmp_path,
        monkeypatch,
    )
    workload_id = chaff_qualification.SEALED_WORKLOAD_IDS[0]
    raced_source = source / "workloads" / f"{workload_id}.json"
    original_sha256_file = orchestrator.sha256_file
    raced = False

    def mutate_after_hash(path: Path) -> str:
        nonlocal raced
        digest = original_sha256_file(path)
        if Path(path) == raced_source and not raced:
            raced_source.write_bytes(b'{"changed":"during-copy"}\n')
            raced = True
        return digest

    monkeypatch.setattr(orchestrator, "sha256_file", mutate_after_hash)
    with pytest.raises(ValueError, match=f"{workload_id} frozen workload changed"):
        orchestrator._materialize_schema_six_qualification_evidence(
            inputs,
            qualification_inputs_root=source,
            provenance=provenance,
        )
    assert raced is True
    assert not (inputs.parent / "experiment.json").exists()


def test_schema_six_materialization_rejects_unexpected_frozen_evidence_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, inputs, provenance, _manifests = _schema_six_qualification_materialization_inputs(
        tmp_path,
        monkeypatch,
    )
    frozen_workloads = inputs / "workloads"
    frozen_workloads.mkdir()
    unexpected = frozen_workloads / "unexpected.json"
    unexpected.write_bytes(b"unexpected\n")

    with pytest.raises(ValueError, match="unsafe file set"):
        orchestrator._materialize_schema_six_qualification_evidence(
            inputs,
            qualification_inputs_root=source,
            provenance=provenance,
        )
    assert unexpected.read_bytes() == b"unexpected\n"


def test_schema_six_bundle_materialization_preserves_two_workload_fourteen_sample_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, _unused_inputs, provenance, manifests = (
        _schema_six_qualification_materialization_inputs(
            tmp_path / "source-fixture",
            monkeypatch,
        )
    )
    selected = ("cloudflare-quiche-r3", "bootstrap-introduction-r3")
    workloads: list[orchestrator.Workload] = []
    for workload_id in selected:
        application = source / "workloads" / f"{workload_id}.json"
        sidecar = source / "chaff-qualification-store/v2" / f"{workload_id}.json"
        spec = source / "chaff-prefix-specs/v2" / f"{workload_id}.json"
        data = load_json(application)
        runtime_bytes = canonical_bytes(orchestrator.runtime_manifest(data))
        manifest_bytes = canonical_bytes(manifests[workload_id])
        workloads.append(
            orchestrator.Workload(
                id=workload_id,
                visits=1,
                path=application,
                source_bytes=application.read_bytes(),
                sha256=sha256_file(application),
                data=data,
                resource_count=1,
                origin_count=1,
                runtime_sha256=sha256_bytes(runtime_bytes),
                chaff_qualification_path=sidecar,
                chaff_qualification_sha256=sha256_file(sidecar),
                chaff_qualification_scope=orchestrator.FULL_CHAFF_SCOPE,
                chaff_prefix_spec_path=spec,
                chaff_prefix_spec_sha256=sha256_file(spec),
                chaff_manifest_sha256=sha256_bytes(manifest_bytes),
                chaff_manifest_data=manifests[workload_id],
            )
        )

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    for name in (
        "provenance.json",
        "traffic-morphing.json",
        "walkie-talkie.json",
        "wtf-pad.json",
    ):
        atomic_json(bundle / name, {"file": name})
    parameter = bundle / "walkie-talkie.json"
    receipt = bundle / "provenance.json"
    parameter_sha256 = sha256_file(parameter)
    receipt_sha256 = sha256_file(receipt)
    artifact_hashes = {"walkie_talkie": parameter_sha256}
    source_bundle = SimpleNamespace(
        root=bundle,
        provenance={
            "fitting_contract": {"contract_version": 6},
            **provenance,
        },
        artifact_hashes=artifact_hashes,
    )

    import qcsd_lab.fitting as fitting

    monkeypatch.setattr(
        fitting,
        "_verify_current_artifact_bundle_at",
        lambda *_args, **_kwargs: source_bundle,
    )

    def verify_frozen(
        root: Path,
        *,
        qualification_inputs_root: Path,
    ) -> SimpleNamespace:
        assert root.name == "research-1200"
        expected = {f"{item}.json" for item in chaff_qualification.SEALED_WORKLOAD_IDS}
        for directory in (
            "workloads",
            "chaff-qualifications",
            "chaff-prefix-specs",
            "chaff-manifests",
        ):
            assert {path.name for path in (qualification_inputs_root / directory).iterdir()} == (
                expected
            )
        return SimpleNamespace(artifact_hashes=artifact_hashes)

    monkeypatch.setattr(fitting, "verify_frozen_artifact_bundle", verify_frozen)
    monkeypatch.setattr(
        orchestrator,
        "validate_frozen_parameter_artifact",
        lambda path, **_kwargs: SimpleNamespace(
            path=path,
            sha256=parameter_sha256,
            provenance_path=path.parent / "provenance.json",
            provenance_sha256=receipt_sha256,
            input_policy="sealed-fitting-result-v1",
        ),
    )

    defenses = (
        Defense("undefended", "none", True),
        Defense("static-control", "static", False),
        Defense("front", "front", False),
        Defense("tamaraw", "tamaraw", False),
        Defense("traffic-morphing", "traffic_morphing", False),
        Defense("wtf-pad", "wtf_pad", False),
        Defense(
            "walkie-talkie",
            "walkie_talkie",
            False,
            parameters="../../artifacts/research-1200/walkie-talkie.json",
            parameters_path=parameter,
            parameters_sha256=parameter_sha256,
            parameters_provenance_path=receipt,
            parameters_provenance_sha256=receipt_sha256,
            parameters_input_policy="sealed-fitting-result-v1",
        ),
    )
    campaign_path = source / "campaigns/smoke.yml"
    campaign_path.parent.mkdir()
    campaign = orchestrator.Campaign(
        path=campaign_path,
        source_bytes=b"frozen synthetic campaign\n",
        name="research-smoke-1200",
        purpose="evaluation",
        seed=2_026_081_204,
        profile="research-1200",
        workloads=tuple(workloads),
        request_policies=("as-defined",),
        defenses=defenses,
        limits=Limits(),
    )
    result = tmp_path / "materialized"
    runtime, _configuration = orchestrator._materialize_inputs(result, campaign, {})

    assert [workload.id for workload in runtime.workloads] == list(selected)
    assert len(orchestrator.plan_campaign(runtime)) == 14
    assert not (result / "experiment.json").exists()


def test_walkie_talkie_resource_preflight_accepts_one_initial_same_origin_candidate() -> None:
    resource = _resource(0, "https://alpha.test/")
    resource["content_length"] = 1_200
    resource["data_length"] = 1_200

    orchestrator._validate_walkie_talkie_resource_precondition(
        {"resources": [resource]},
        workload_id="alpha",
        endpoint_origins={"https://alpha.test"},
    )


def test_walkie_talkie_current_contract_classifier_accepts_only_schema_six(
    tmp_path: Path,
) -> None:
    schema_five = tmp_path / "schema-five.json"
    schema_six = tmp_path / "schema-six.json"
    atomic_json(schema_five, {"schema_version": 5})
    atomic_json(schema_six, {"schema_version": 6})

    assert not orchestrator._uses_schema_six_walkie_talkie(
        Defense("historical", "walkie_talkie", False, parameters_path=schema_five)
    )
    assert orchestrator._uses_schema_six_walkie_talkie(
        Defense("current", "walkie_talkie", False, parameters_path=schema_six)
    )
    assert not orchestrator._uses_schema_six_walkie_talkie(Defense("front", "front", False))


@pytest.mark.parametrize(
    ("defenses", "scope"),
    [
        ((Defense("undefended", "none", True),), None),
        (
            (
                Defense("undefended", "none", True),
                Defense("front-pilot", "front", False),
                Defense("tamaraw-pilot", "tamaraw", False),
            ),
            orchestrator.RESPONSE_ONLY_CHAFF_SCOPE,
        ),
        (
            (
                Defense("undefended", "none", True),
                Defense("front", "front", False),
                Defense("static", "static", False),
            ),
            orchestrator.FULL_CHAFF_SCOPE,
        ),
    ],
)
def test_campaign_selects_qualification_contract_only_from_runtime_kinds(
    defenses: tuple[Defense, ...], scope: str | None
) -> None:
    assert orchestrator._required_chaff_qualification_scope(defenses) == scope


def test_response_only_loader_requires_no_prefix_spec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign_path = _configuration(tmp_path)
    workload = load_campaign(campaign_path).workloads[0]
    sidecar = tmp_path / "config/chaff-response-qualification-store/v2/alpha.json"
    atomic_json(sidecar, {"response-only": True})
    manifest = {"schema_version": 4, "qualification_scope": "response-only"}

    def load_response(
        sidecar_path: Path,
        *,
        workload_id: str,
        base_manifest_path: Path,
        expected_sidecar_schema_version: int | None,
        require_current_implementation: bool = True,
    ) -> SimpleNamespace:
        assert sidecar_path.name == sidecar.name
        assert sidecar_path.read_bytes() == sidecar.read_bytes()
        assert workload_id == "alpha"
        assert base_manifest_path.name == workload.path.name
        assert base_manifest_path.read_bytes() == workload.source_bytes
        assert expected_sidecar_schema_version == 2
        assert require_current_implementation is True
        return SimpleNamespace(
            sidecar_sha256=sha256_file(sidecar_path),
            manifest_sha256=sha256_bytes(canonical_bytes(manifest)),
            manifest=manifest,
        )

    monkeypatch.setattr(chaff_qualification, "load_response_qualified_chaff", load_response)
    qualified = orchestrator._load_qualified_chaff_inputs(
        campaign_path,
        (workload,),
        frozen_inputs=None,
        qualification_scope=orchestrator.RESPONSE_ONLY_CHAFF_SCOPE,
    )[0]

    assert qualified.chaff_qualification_scope == "response-only"
    assert qualified.chaff_prefix_spec_path is None
    assert qualified.chaff_prefix_spec_sha256 is None
    assert qualified.chaff_manifest_data == manifest

    campaign = orchestrator.Campaign(
        path=campaign_path,
        source_bytes=campaign_path.read_bytes(),
        name="response-only-materialization",
        purpose="smoke",
        seed=7,
        profile="live",
        workloads=(qualified,),
        request_policies=("as-defined",),
        defenses=(
            Defense("undefended", "none", True),
            Defense("front-pilot", "front", False),
        ),
        limits=Limits(),
    )
    result = tmp_path / "response-result"
    runtime, configuration = orchestrator._materialize_inputs(result, campaign, {})

    assert not (result / "inputs/chaff-prefix-specs").exists()
    assert runtime.workloads[0].chaff_prefix_spec_path is None
    frozen = configuration["workloads"][0]
    assert "chaff_qualification_set" not in configuration
    assert frozen["chaff_qualification_scope"] == "response-only"
    assert "chaff_prefix_spec" not in frozen
    assert "chaff_prefix_spec_sha256" not in frozen


def test_explicit_response_qualification_set_routes_and_freezes_selected_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign_path = _configuration(tmp_path)
    workload = load_campaign(campaign_path).workloads[0]
    value = yaml.safe_load(campaign_path.read_text(encoding="utf-8"))
    value["chaff_qualification_set"] = "cohort-v1"
    value["defenses"] = ["undefended", "front"]
    campaign_path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    selected = tmp_path / "config/chaff-response-qualification-store/sets/cohort-v1"
    selected.mkdir(parents=True)
    sidecar = selected / "alpha.json"
    atomic_json(sidecar, {"response-only": "named-set"})
    manifest = {
        "schema_version": 4,
        "qualification_scope": "response-only",
        "resources": workload.data["resources"],
    }
    calls: list[tuple[Path, bool]] = []

    def load_response(
        sidecar_path: Path,
        *,
        workload_id: str,
        base_manifest_path: Path,
        expected_sidecar_schema_version: int | None,
        require_current_implementation: bool = True,
    ) -> SimpleNamespace:
        assert workload_id == "alpha"
        assert base_manifest_path.name == "alpha.json"
        assert expected_sidecar_schema_version == 2
        calls.append((sidecar_path, require_current_implementation))
        return SimpleNamespace(
            sidecar_sha256=sha256_file(sidecar_path),
            manifest_sha256=sha256_bytes(canonical_bytes(manifest)),
            manifest=manifest,
        )

    monkeypatch.setattr(chaff_qualification, "load_response_qualified_chaff", load_response)
    qualified = orchestrator._load_qualified_chaff_inputs(
        campaign_path,
        (workload,),
        frozen_inputs=None,
        qualification_scope=orchestrator.RESPONSE_ONLY_CHAFF_SCOPE,
        qualification_set="cohort-v1",
    )[0]
    assert qualified.chaff_qualification_path == sidecar.resolve()
    assert calls == [(sidecar.resolve(), True)]

    campaign = orchestrator.Campaign(
        path=campaign_path,
        source_bytes=campaign_path.read_bytes(),
        name="named-set-materialization",
        purpose="smoke",
        seed=7,
        profile="live",
        workloads=(qualified,),
        request_policies=("as-defined",),
        defenses=(
            Defense("undefended", "none", True),
            Defense("front", "front", False),
        ),
        limits=Limits(),
        chaff_qualification_set="cohort-v1",
    )
    result = tmp_path / "named-set-result"
    runtime, configuration = orchestrator._materialize_inputs(result, campaign, {})

    frozen_sidecar = result / "inputs/chaff-qualifications/alpha.json"
    assert frozen_sidecar.read_bytes() == sidecar.read_bytes()
    assert configuration["chaff_qualification_set"] == "cohort-v1"
    assert (
        yaml.safe_load((result / "inputs/campaign.yml").read_text(encoding="utf-8"))[
            "chaff_qualification_set"
        ]
        == "cohort-v1"
    )

    sidecar.unlink()
    selected.rmdir()
    frozen = orchestrator._load_qualified_chaff_inputs(
        result / "inputs/campaign.yml",
        runtime.workloads,
        frozen_inputs=result / "inputs",
        qualification_scope=orchestrator.RESPONSE_ONLY_CHAFF_SCOPE,
        qualification_set="cohort-v1",
    )[0]
    assert frozen.chaff_qualification_path == frozen_sidecar.resolve()
    assert calls[-1] == (frozen_sidecar.resolve(), False)


def test_explicit_response_qualification_set_rejects_missing_symlinked_or_mixed_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign_path = _configuration(tmp_path)
    workload = load_campaign(campaign_path).workloads[0]
    sets = tmp_path / "config/chaff-response-qualification-store/sets"

    with pytest.raises(ValueError, match="selected response qualification set is not"):
        orchestrator._load_qualified_chaff_inputs(
            campaign_path,
            (workload,),
            frozen_inputs=None,
            qualification_scope=orchestrator.RESPONSE_ONLY_CHAFF_SCOPE,
            qualification_set="cohort-v1",
        )

    sets.mkdir(parents=True)
    external = tmp_path / "external-set"
    external.mkdir()
    (sets / "cohort-v1").symlink_to(external, target_is_directory=True)
    with pytest.raises(ValueError, match="selected response qualification set is not"):
        orchestrator._load_qualified_chaff_inputs(
            campaign_path,
            (workload,),
            frozen_inputs=None,
            qualification_scope=orchestrator.RESPONSE_ONLY_CHAFF_SCOPE,
            qualification_set="cohort-v1",
        )
    (sets / "cohort-v1").unlink()

    selected = sets / "cohort-v1"
    selected.mkdir()
    atomic_json(selected / "alpha.json", {"response-only": True})
    atomic_json(selected / "foreign.json", {"response-only": True})
    monkeypatch.setattr(
        chaff_qualification,
        "load_response_qualified_chaff",
        lambda *_args, **_kwargs: pytest.fail("mixed set reached a sidecar loader"),
    )
    with pytest.raises(ValueError, match="exact campaign workload cohort"):
        orchestrator._load_qualified_chaff_inputs(
            campaign_path,
            (workload,),
            frozen_inputs=None,
            qualification_scope=orchestrator.RESPONSE_ONLY_CHAFF_SCOPE,
            qualification_set="cohort-v1",
        )


@pytest.mark.parametrize(
    "qualification_set",
    [None, "", "../escape", "two/levels", ".hidden", "Mixed-Case"],
)
def test_campaign_rejects_present_invalid_qualification_set(
    tmp_path: Path, qualification_set: object
) -> None:
    campaign_path = _configuration(tmp_path)
    value = yaml.safe_load(campaign_path.read_text(encoding="utf-8"))
    value["chaff_qualification_set"] = qualification_set
    campaign_path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match="filesystem-safe slug"):
        load_campaign(campaign_path)


def test_campaign_passes_named_set_only_to_response_only_loader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign_path = _configuration(tmp_path)
    workload = replace(
        load_campaign(campaign_path).workloads[0],
        data={"preparation": {}, "resources": [_resource(0, "https://alpha.test/")]},
    )
    value = yaml.safe_load(campaign_path.read_text(encoding="utf-8"))
    value["chaff_qualification_set"] = "cohort-v1"
    value["defenses"] = ["undefended", "front"]
    campaign_path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    defenses = (
        Defense("undefended", "none", True),
        Defense("front", "front", False),
    )
    observed: list[str | None] = []
    monkeypatch.setattr(orchestrator, "_load_workloads", lambda *_args, **_kwargs: (workload,))
    monkeypatch.setattr(
        orchestrator,
        "_load_defenses",
        lambda _base, raw, *_args, **_kwargs: (
            defenses if "front" in raw else (Defense("undefended", "none", True),)
        ),
    )

    def load_qualified(
        _path: Path,
        workloads: tuple[orchestrator.Workload, ...],
        *,
        frozen_inputs: Path | None,
        qualification_scope: str,
        qualification_set: str | None,
        config_root: Path | None,
    ) -> tuple[orchestrator.Workload, ...]:
        assert frozen_inputs is None
        assert config_root == tmp_path / "config"
        assert qualification_scope == orchestrator.RESPONSE_ONLY_CHAFF_SCOPE
        observed.append(qualification_set)
        return workloads

    monkeypatch.setattr(orchestrator, "_load_qualified_chaff_inputs", load_qualified)
    campaign = load_campaign(campaign_path)

    assert campaign.chaff_qualification_set == "cohort-v1"
    assert preflight_campaign(campaign_path)["chaff_qualification_set"] == "cohort-v1"
    assert observed == ["cohort-v1", "cohort-v1"]

    value["defenses"] = ["undefended"]
    campaign_path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="requires a response-only"):
        load_campaign(campaign_path)


def test_frozen_pre_response_front_result_keeps_full_v2_and_structural_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign_path = _configuration(tmp_path)
    workload = load_campaign(campaign_path).workloads[0]
    frozen = tmp_path / "frozen-full"
    for directory in ("chaff-qualifications", "chaff-prefix-specs", "chaff-manifests"):
        (frozen / directory).mkdir(parents=True)
    sidecar = frozen / "chaff-qualifications/alpha.json"
    spec = frozen / "chaff-prefix-specs/alpha.json"
    manifest_path = frozen / "chaff-manifests/alpha.json"
    atomic_json(sidecar, {"schema_version": 2})
    atomic_json(spec, {"schema_version": 2})
    manifest = {"schema_version": 2, "artifact_type": "qcsd-qualified-chaff-manifest"}
    atomic_json(manifest_path, manifest)
    full_calls: list[bool] = []

    def load_full(
        sidecar_path: Path,
        *,
        workload_id: str,
        base_manifest_path: Path,
        prefix_spec_path: Path,
        require_current_implementation: bool = True,
    ) -> SimpleNamespace:
        assert sidecar_path == sidecar.resolve()
        assert prefix_spec_path == spec.resolve()
        assert workload_id == workload.id
        assert base_manifest_path == workload.path
        full_calls.append(require_current_implementation)
        return SimpleNamespace(
            sidecar_sha256=sha256_file(sidecar_path),
            manifest_sha256=sha256_file(manifest_path),
            manifest=manifest,
        )

    monkeypatch.setattr(chaff_qualification, "load_qualified_chaff", load_full)
    monkeypatch.setattr(
        chaff_qualification,
        "load_response_qualified_chaff",
        lambda *_args, **_kwargs: pytest.fail("frozen full-v2 result used response-only loader"),
    )
    qualified = orchestrator._load_qualified_chaff_inputs(
        campaign_path,
        (workload,),
        frozen_inputs=frozen,
        qualification_scope=orchestrator.RESPONSE_ONLY_CHAFF_SCOPE,
    )[0]

    assert full_calls == [False]
    assert qualified.chaff_qualification_scope == orchestrator.FULL_CHAFF_SCOPE
    assert qualified.chaff_prefix_spec_path == spec.resolve()


@pytest.mark.parametrize("prefix_present", [False, True])
@pytest.mark.parametrize(("manifest_schema", "sidecar_schema"), [(3, 1), (4, 2)])
def test_frozen_response_scope_requires_explicit_unambiguous_schema_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    prefix_present: bool,
    manifest_schema: int,
    sidecar_schema: int,
) -> None:
    campaign_path = _configuration(tmp_path)
    workload = load_campaign(campaign_path).workloads[0]
    frozen = tmp_path / "frozen-response"
    for directory in ("chaff-qualifications", "chaff-manifests"):
        (frozen / directory).mkdir(parents=True)
    atomic_json(frozen / "chaff-qualifications/alpha.json", {"schema_version": sidecar_schema})
    manifest = {
        "schema_version": manifest_schema,
        "artifact_type": "qcsd-qualified-chaff-manifest",
        "qualification_scope": "response-only",
    }
    manifest_path = frozen / "chaff-manifests/alpha.json"
    atomic_json(manifest_path, manifest)
    if prefix_present:
        prefix = frozen / "chaff-prefix-specs"
        prefix.mkdir()
        atomic_json(prefix / "alpha.json", {"schema_version": 2})
        with pytest.raises(ValueError, match="ambiguously contains"):
            orchestrator._load_qualified_chaff_inputs(
                campaign_path,
                (workload,),
                frozen_inputs=frozen,
                qualification_scope=orchestrator.RESPONSE_ONLY_CHAFF_SCOPE,
            )
        return

    calls: list[tuple[bool, int | None]] = []

    def load_response(*_args: object, **kwargs: object) -> SimpleNamespace:
        calls.append(
            (
                kwargs["require_current_implementation"],
                kwargs["expected_sidecar_schema_version"],
            )
        )
        return SimpleNamespace(
            sidecar_sha256=sha256_file(frozen / "chaff-qualifications/alpha.json"),
            manifest_sha256=sha256_file(manifest_path),
            manifest=manifest,
        )

    monkeypatch.setattr(chaff_qualification, "load_response_qualified_chaff", load_response)
    qualified = orchestrator._load_qualified_chaff_inputs(
        campaign_path,
        (workload,),
        frozen_inputs=frozen,
        qualification_scope=orchestrator.RESPONSE_ONLY_CHAFF_SCOPE,
    )[0]
    assert calls == [(False, sidecar_schema)]
    assert qualified.chaff_qualification_scope == orchestrator.RESPONSE_ONLY_CHAFF_SCOPE
    assert qualified.chaff_prefix_spec_path is None


def test_frozen_response_layout_rejects_missing_schema_three_scope_marker(
    tmp_path: Path,
) -> None:
    campaign_path = _configuration(tmp_path)
    workload = load_campaign(campaign_path).workloads[0]
    frozen = tmp_path / "frozen-unscoped"
    for directory in ("chaff-qualifications", "chaff-manifests"):
        (frozen / directory).mkdir(parents=True)
    atomic_json(frozen / "chaff-qualifications/alpha.json", {"schema_version": 1})
    atomic_json(frozen / "chaff-manifests/alpha.json", {"schema_version": 2})

    with pytest.raises(ValueError, match="explicit schema-three scope markers"):
        orchestrator._load_qualified_chaff_inputs(
            campaign_path,
            (workload,),
            frozen_inputs=frozen,
            qualification_scope=orchestrator.RESPONSE_ONLY_CHAFF_SCOPE,
        )


def test_frozen_response_cohort_rejects_mixed_schema_three_and_four(tmp_path: Path) -> None:
    frozen = tmp_path / "frozen-mixed-response"
    manifests = frozen / "chaff-manifests"
    manifests.mkdir(parents=True)
    workloads = (SimpleNamespace(id="alpha"), SimpleNamespace(id="bravo"))
    for workload, schema_version in zip(workloads, (3, 4), strict=True):
        atomic_json(
            manifests / f"{workload.id}.json",
            {
                "schema_version": schema_version,
                "qualification_scope": "response-only",
            },
        )

    with pytest.raises(ValueError, match="mixes schema-three and schema-four"):
        orchestrator._frozen_chaff_qualification_scope(
            frozen,
            workloads,
            defense_derived_scope=orchestrator.RESPONSE_ONLY_CHAFF_SCOPE,
        )

    atomic_json(
        manifests / "bravo.json",
        {"schema_version": 3, "qualification_scope": "response-only"},
    )
    assert (
        orchestrator._frozen_chaff_qualification_scope(
            frozen,
            workloads,
            defense_derived_scope=orchestrator.RESPONSE_ONLY_CHAFF_SCOPE,
        )
        == orchestrator.RESPONSE_ONLY_CHAFF_SCOPE
    )


def test_loaded_schema_six_binding_cross_links_resource_and_cohort_fields(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provenance = tmp_path / "provenance.json"
    atomic_json(provenance, {"fitting_contract": {"contract_version": 6}})
    manifest = {
        "application_resource_id": 0,
        "selected_chaff_resource_id": 6,
        "qualified_parallel_chaff_streams": 20,
        "walkie_talkie_required_chaff_streams": 20,
    }
    workload = orchestrator.Workload(
        id="alpha",
        visits=1,
        path=tmp_path / "alpha.json",
        source_bytes=b"{}\n",
        sha256="a" * 64,
        data={},
        resource_count=1,
        origin_count=1,
        chaff_qualification_sha256="b" * 64,
        chaff_prefix_spec_sha256="c" * 64,
        chaff_manifest_sha256="d" * 64,
        chaff_manifest_data=manifest,
    )
    defense = Defense(
        "walkie-talkie",
        "walkie_talkie",
        False,
        parameters_provenance_path=provenance,
    )
    binding = {
        "workload_id": "alpha",
        "chaff_qualification_sidecar_sha256": "b" * 64,
        "prefix_pack_spec_sha256": "c" * 64,
        "qualified_chaff_manifest_sha256": "d" * 64,
        **manifest,
    }
    monkeypatch.setattr(
        "qcsd_lab.fitting._qualification_bindings_from_provenance",
        lambda _value: [binding],
    )
    orchestrator._validate_loaded_qualification_bindings((defense,), (workload,))

    binding["walkie_talkie_required_chaff_streams"] = 19
    with pytest.raises(ValueError, match="do not match schema-six"):
        orchestrator._validate_loaded_qualification_bindings((defense,), (workload,))


@pytest.mark.parametrize("failure", ["unknown", "dependent", "empty", "origin-mismatch"])
def test_walkie_talkie_resource_preflight_rejects_ineligible_or_wrong_origin_candidate(
    failure: str,
) -> None:
    resource = _resource(0, "https://alpha.test/")
    endpoint_origins = {"https://alpha.test"}
    if failure == "unknown":
        resource["known_valid"] = False
    elif failure == "dependent":
        resource["depends_on"] = [1]
    elif failure == "empty":
        resource["content_length"] = 0
        resource["data_length"] = 0
    else:
        endpoint_origins = {"https://other.test"}

    with pytest.raises(ValueError, match="matching a request endpoint origin"):
        orchestrator._validate_walkie_talkie_resource_precondition(
            {"resources": [resource]},
            workload_id="alpha",
            endpoint_origins=endpoint_origins,
        )


@pytest.mark.parametrize("effective_length, accepted", [(1_199, False), (1_200, True)])
def test_walkie_talkie_resource_preflight_enforces_raw_headroom_boundary(
    effective_length: int,
    accepted: bool,
) -> None:
    resource = _resource(0, "https://alpha.test/")
    resource["content_length"] = effective_length
    resource["data_length"] = effective_length

    def validate() -> None:
        orchestrator._validate_walkie_talkie_resource_precondition(
            {"resources": [resource]},
            workload_id="alpha",
            endpoint_origins={"https://alpha.test"},
        )

    if accepted:
        validate()
    else:
        with pytest.raises(ValueError, match="effective length at least 1200 bytes"):
            validate()


def test_walkie_talkie_resource_preflight_mirrors_priority_before_largest_selection() -> None:
    short_priority = _resource(0, "https://alpha.test/priority")
    short_priority["content_length"] = 1_199
    short_priority["data_length"] = 1_199
    large_nonpriority = _resource(1, "https://alpha.test/large")
    large_nonpriority["content_length"] = 2_400
    large_nonpriority["data_length"] = 2_400

    with pytest.raises(ValueError, match="effective length at least 1200 bytes"):
        orchestrator._validate_walkie_talkie_resource_precondition(
            {"resources": [large_nonpriority, short_priority]},
            workload_id="alpha",
            endpoint_origins={"https://alpha.test"},
        )


def _write_successful_attempt(
    attempt: Path,
    workload_id: str,
    defense_name: str,
    *,
    body_sha256: str = "a" * 64,
) -> dict[str, Any]:
    captures = attempt / "captures"
    neqo = attempt / "neqo"
    captures.mkdir(parents=True)
    neqo.mkdir()
    (captures / "direct-quic.pcapng").write_bytes(
        b"controlled-capture:" + workload_id.encode() + b":" + defense_name.encode()
    )
    (neqo / "packets.csv").write_text(
        "direction,monotonic_us,connection,observed_udp_length,"
        "scheduled_target,satisfaction,slot_id\n"
        "outgoing,1,0,64,,unshaped,\n",
        encoding="utf-8",
    )
    (neqo / "events.csv").write_text(
        "monotonic_us,connection,event,phase,details\n",
        encoding="utf-8",
    )
    (neqo / "schedule.csv").write_text(
        "direction,satisfaction,miss_reason,size,observed_size\n",
        encoding="utf-8",
    )
    (neqo / "run.json").write_text(
        json.dumps(
            {
                "completion_status": "complete",
                "responses": [
                    {
                        "resource_id": 0,
                        "status": 200,
                        "bytes": 64,
                        "body_sha256": body_sha256,
                        "complete": True,
                        "outcome": "succeeded",
                    }
                ],
                "endpoints": [
                    {
                        "id": 0,
                        "local_address": "192.0.2.1:50000",
                        "remote_address": "198.51.100.1:443",
                    }
                ],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return {
        "success": True,
        "views": [
            {
                "id": "direct-quic",
                "primary": True,
                "timestamp_type": "host",
                "valid": True,
                "capture_clock_anchors": {
                    "start_monotonic_ns": 1_000_000_000,
                    "end_monotonic_ns": 2_000_000_000,
                    "start_realtime_unix_ns": 10_000_000_000,
                    "end_realtime_unix_ns": 11_000_000_000,
                    "start_pairing_uncertainty_ns": 100,
                    "end_pairing_uncertainty_ns": 100,
                },
                "direct_runner_reconciliation": {
                    "direct_clock_model": "constant-offset",
                    "direct_clock_segment_count": 1,
                    "direct_clock_segments": [{"index": 0}],
                    "direct_clock_step_count": 0,
                    "direct_clock_steps": [],
                    "direct_runner_reconciled": True,
                    "evidence_eligible": True,
                    "direct_timestamp_error_max_ns": 0,
                    "direct_timestamp_tolerance_ns": 10_000_000,
                },
            }
        ],
        "offloads": [{"interface": "eth0", "verified": True}],
        "endpoint_count": 1,
        "endpoint_count_valid": True,
        "operationally_valid": True,
        "defense_diagnostics": (
            {}
            if defense_name == "undefended"
            else {
                "scheduled_incoming_requested_bytes": 0,
                "scheduled_incoming_consumed_bytes": 0,
                "scheduled_incoming_retired_bytes": 0,
                "scheduled_incoming_unresolved_bytes": 0,
            }
        ),
    }


def _write_pacing_miss(attempt: Path) -> None:
    (attempt / "neqo/schedule.csv").write_text(
        "direction,satisfaction,miss_reason,size,observed_size\noutgoing,missed,pacing,1200,\n",
        encoding="utf-8",
    )


class _Collector:
    def __init__(
        self,
        *,
        fail_once: set[str] | None = None,
        mismatched: set[str] | None = None,
    ) -> None:
        self.fail_once = fail_once or set()
        self.mismatched = mismatched or set()
        self.calls: list[tuple[str, str, int, Path]] = []
        self.counts: Counter[str] = Counter()

    def __call__(
        self,
        attempt: Path,
        _manifest: Path,
        workload_id: str,
        defense: Any,
        seed: int,
        _campaign: Any,
    ) -> dict[str, Any]:
        self.calls.append((workload_id, defense.name, seed, attempt))
        self.counts[defense.name] += 1
        if defense.name in self.fail_once and self.counts[defense.name] == 1:
            attempt.mkdir(parents=True)
            failure = {
                "stage": "runner",
                "type": "ControlledFailure",
                "message": "first attempt failed",
            }
            (attempt / "failure.json").write_text(
                json.dumps(failure, sort_keys=True), encoding="utf-8"
            )
            return {"success": False, "failure": failure}
        digest = "b" * 64 if defense.name in self.mismatched else "a" * 64
        return _write_successful_attempt(
            attempt,
            workload_id,
            defense.name,
            body_sha256=digest,
        )


class _PacingMissCollector:
    def __init__(self, miss_front_attempts: set[int]) -> None:
        self.miss_front_attempts = miss_front_attempts
        self.counts: Counter[str] = Counter()

    def __call__(
        self,
        attempt: Path,
        _manifest: Path,
        workload_id: str,
        defense: Any,
        _seed: int,
        _campaign: Any,
    ) -> dict[str, Any]:
        self.counts[defense.name] += 1
        result = _write_successful_attempt(attempt, workload_id, defense.name)
        if defense.name == "front" and self.counts[defense.name] in self.miss_front_attempts:
            _write_pacing_miss(attempt)
        return result


def test_endpoint_parser_and_exact_filter_support_both_ip_versions() -> None:
    assert split_endpoint("172.17.0.2:50000") == ("172.17.0.2", 50000)
    assert split_endpoint("[2001:db8::1]:443") == ("2001:db8::1", 443)
    display_filter = tuple_filter(
        [
            {
                "id": 0,
                "local_address": "172.17.0.2:50000",
                "remote_address": "203.0.113.1:443",
            },
            {
                "id": 1,
                "local_address": "[2001:db8::2]:50001",
                "remote_address": "[2001:db8::1]:443",
            },
        ]
    )
    assert "udp.srcport==50000" in display_filter
    assert "ip.src==172.17.0.2" in display_filter
    assert "ipv6.src==2001:db8::2" in display_filter


def test_capture_session_requires_a_complete_successful_runner_result() -> None:
    response = {"resource_id": 0, "complete": True, "outcome": "succeeded"}
    assert _runner_result_complete({"completion_status": "complete", "responses": [response]}, {0})
    assert not _runner_result_complete(
        {"completion_status": "partial", "responses": [response]}, {0}
    )
    assert not _runner_result_complete(
        {
            "completion_status": "complete",
            "responses": [{**response, "complete": False, "outcome": "failed"}],
        },
        {0},
    )
    assert not _runner_result_complete(
        {
            "completion_status": "complete",
            "responses": [response],
            "defense_diagnostics": {"padding_event_guard_triggered": True},
        },
        {0},
    )
    assert not _runner_result_complete(
        {"completion_status": "complete", "responses": [response]}, {0, 1}
    )
    assert not _runner_result_complete(
        {
            "completion_status": "complete",
            "responses": [response, response],
        },
        {0, 1},
    )
    assert not _runner_result_complete(
        {
            "completion_status": "complete",
            "responses": [{**response, "resource_id": 999}],
        },
        {0},
    )


def test_capture_clock_anchor_uses_narrowest_linux_monotonic_bracket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert orchestrator.capture_engine._DIRECT_CAPTURE_VIEW.as_dict()["timestamp_type"] == "host"
    monotonic = iter((1_000, 1_100, 2_000, 2_080, 3_000, 3_020, 4_000, 4_060, 5_000, 5_040))
    realtime = iter((10_000, 20_000, 30_000, 40_000, 50_000))
    monkeypatch.setattr(orchestrator.capture_engine.time, "monotonic_ns", lambda: next(monotonic))
    monkeypatch.setattr(orchestrator.capture_engine.time, "time_ns", lambda: next(realtime))

    assert orchestrator.capture_engine._clock_anchor() == {
        "monotonic_ns": 3_010,
        "realtime_unix_ns": 30_000,
        "pairing_uncertainty_ns": 10,
    }


def test_capture_clock_end_anchor_requires_stopped_dumpcap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = SimpleNamespace(poll=lambda: None)
    monkeypatch.setattr(
        orchestrator.capture_engine,
        "_clock_anchor",
        lambda: pytest.fail("end anchor sampled while dumpcap was still running"),
    )

    with pytest.raises(RuntimeError, match="requires stopped dumpcap"):
        orchestrator.capture_engine._capture_clock_anchors_after_stop(
            {
                "monotonic_ns": 1_000_000_000,
                "realtime_unix_ns": 10_000_000_000,
                "pairing_uncertainty_ns": 100,
            },
            process,
        )


def test_capture_clock_post_stop_anchor_rejects_settle_tail_wall_clock_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = SimpleNamespace(poll=lambda: 0)
    monkeypatch.setattr(
        orchestrator.capture_engine,
        "_clock_anchor",
        lambda: {
            "monotonic_ns": 2_000_000_000,
            "realtime_unix_ns": 11_050_000_000,
            "pairing_uncertainty_ns": 100,
        },
    )
    anchors = orchestrator.capture_engine._capture_clock_anchors_after_stop(
        {
            "monotonic_ns": 1_000_000_000,
            "realtime_unix_ns": 10_000_000_000,
            "pairing_uncertainty_ns": 100,
        },
        process,
    )
    capture = {
        "primary": True,
        "capture_clock_anchors": anchors,
        "direct_runner_reconciliation": {
            "direct_clock_model": "constant-offset",
            "direct_clock_segment_count": 1,
            "direct_clock_segments": [{"index": 0}],
            "direct_clock_step_count": 0,
            "direct_clock_steps": [],
            "direct_runner_reconciled": True,
            "evidence_eligible": True,
            "direct_timestamp_error_max_ns": 0,
            "direct_timestamp_tolerance_ns": 10_000_000,
        },
    }

    with pytest.raises(ValueError, match="elapsed difference exceeds 10 ms"):
        orchestrator.capture_engine.validate_primary_capture_clock_integrity(
            capture,
            require_pairing_uncertainty=True,
        )


def _runtime_chaff_fixture(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    manifest = tmp_path / "chaff.json"
    headers = [["accept", "text/html"], ["accept-encoding", "gzip"], ["accept-language", "en"]]
    atomic_json(
        manifest,
        {
            "resources": [
                {
                    "id": 0,
                    "url": "https://site.test/",
                    "headers": headers,
                    "chaff_qualification": {
                        "request_stream_bytes": 123,
                        "expected_response": {
                            "status": 200,
                            "content_encoding": "gzip",
                            "body_bytes": 1_200,
                            "body_sha256": "a" * 64,
                        },
                    },
                }
            ]
        },
    )
    receipt: dict[str, object] = {
        "resource_id": 0,
        "request_id": 0,
        "url": "https://site.test/",
        "request_headers": headers,
        "request_stream_bytes": 123,
        "expected_request_stream_bytes": 123,
        "response_headers": [[":status", "200"], ["content-encoding", "gzip"]],
        "status": 200,
        "content_encoding": "gzip",
        "bytes": 1_200,
        "body_sha256": "a" * 64,
        "complete": True,
        "status_match": True,
        "content_encoding_match": True,
        "body_bytes_match": True,
        "body_sha256_match": True,
        "identity_verified": True,
        "outcome": "succeeded",
    }
    return manifest, receipt


def test_runtime_chaff_receipts_accept_verified_complete_and_truthful_reset(
    tmp_path: Path,
) -> None:
    manifest, receipt = _runtime_chaff_fixture(tmp_path)
    _validate_chaff_response_receipts({"chaff_responses": [receipt]}, manifest)

    partial = {
        **receipt,
        "status": None,
        "content_encoding": None,
        "bytes": 81,
        "body_sha256": None,
        "complete": False,
        "status_match": None,
        "content_encoding_match": None,
        "body_bytes_match": None,
        "body_sha256_match": None,
        "identity_verified": None,
        "outcome": "reset",
    }
    _validate_chaff_response_receipts({"chaff_responses": [partial]}, manifest)
    partial["outcome"] = "endpoint_closed"
    _validate_chaff_response_receipts({"chaff_responses": [partial]}, manifest)


@pytest.mark.parametrize(
    ("outcome", "mutation"),
    [
        ("response_limit", {"bytes": 1_201, "body_sha256": "b" * 64}),
        (
            "identity_mismatch",
            {"content_encoding": "identity", "content_encoding_match": False},
        ),
        ("request_size_mismatch", {"request_stream_bytes": 124}),
    ],
)
def test_runtime_chaff_receipts_reject_known_contradictions(
    tmp_path: Path, outcome: str, mutation: dict[str, object]
) -> None:
    manifest, receipt = _runtime_chaff_fixture(tmp_path)
    receipt.update(mutation)
    receipt["outcome"] = outcome

    with pytest.raises(ValueError, match="qualified|contradicts"):
        _validate_chaff_response_receipts({"chaff_responses": [receipt]}, manifest)


@pytest.mark.parametrize(
    "mutation",
    [
        {"bytes": 1_201},
        {"response_headers": [[":status", "404"], ["content-encoding", "gzip"]]},
        {"response_headers": [[":status", "200"], ["content-encoding", "br"]]},
    ],
)
def test_partial_runtime_chaff_receipts_reject_raw_identity_contradictions(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    manifest, receipt = _runtime_chaff_fixture(tmp_path)
    receipt.update(
        {
            "status": None,
            "content_encoding": None,
            "bytes": 81,
            "body_sha256": None,
            "complete": False,
            "status_match": None,
            "content_encoding_match": None,
            "body_bytes_match": None,
            "body_sha256_match": None,
            "identity_verified": None,
            "outcome": "incomplete",
            **mutation,
        }
    )

    with pytest.raises(ValueError, match="contradict|invalid identity claim"):
        _validate_chaff_response_receipts({"chaff_responses": [receipt]}, manifest)


def test_runner_receipt_is_bound_to_frozen_launch_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "workload.json"
    manifest.write_text('{"resources":[]}\n', encoding="utf-8")
    context = SimpleNamespace(
        request_policy="as-defined",
        udp_payload_ceiling=1200,
        limits=Limits(max_response_bytes=4096),
    )
    run = {
        "seed": 7,
        "request_policy": "as-defined",
        "workload_hash_sha256": sha256_file(manifest),
        "max_response_bytes": 4096,
        "client_resource_usage": {
            "schema_version": 1,
            "source": "test-fixture",
            "user_cpu_seconds": 0.1,
            "system_cpu_seconds": 0.05,
            "wall_time_seconds": 0.2,
            "maximum_rss_bytes": 4_096,
            "voluntary_context_switches": 1,
            "involuntary_context_switches": 0,
            "timer_wakeups": None,
            "timer_wakeups_unavailable_reason": "not measured in unit test",
            "rapl_energy_joules": None,
            "rapl_unavailable_reason": "not measured in unit test",
        },
        "resolved_configuration": {
            "max_udp_payload_size": 1200,
            "defense": {"kind": "none"},
        },
        "defense_parameters": None,
    }
    _validate_run_binding(
        run,
        manifest=manifest,
        workload_id="site",
        defense=Defense("undefended", "none", True),
        seed=7,
        context=context,
    )
    run["process_scheduler"] = {
        "schema_version": 1,
        "contract": None,
        "contract_valid": True,
    }
    _validate_run_binding(
        run,
        manifest=manifest,
        workload_id="site",
        defense=Defense("undefended", "none", True),
        seed=7,
        context=context,
    )
    run.pop("process_scheduler")
    monkeypatch.setenv(
        "QCSD_CAPTURE_SCHEDULER_CONTRACT", "qcsd-client-rr1-cpu10-v1"
    )
    with pytest.raises(ValueError, match="frozen sample inputs"):
        _validate_run_binding(
            run,
            manifest=manifest,
            workload_id="site",
            defense=Defense("undefended", "none", True),
            seed=7,
            context=context,
        )
    scheduler = {
        "schema_version": 1,
        "source": "linux-sched-and-procfs-v1",
        "policy": "SCHED_RR",
        "priority": 1,
        "affinity_cpus": [10],
        "rlimit_rtprio": {"soft": 1, "hard": 1},
        "no_new_privileges": True,
        "effective_capabilities_hex": "0000000000000000",
        "cgroup_effective_cpuset": "10-11",
        "affinity_scope": (
            "qcsd_container_affinity_partition_not_physical_cpu_isolation"
        ),
        "contract": "qcsd-client-rr1-cpu10-v1",
        "contract_valid": True,
    }
    assert _process_scheduler_valid(scheduler)
    run["process_scheduler"] = scheduler
    _validate_run_binding(
        run,
        manifest=manifest,
        workload_id="site",
        defense=Defense("undefended", "none", True),
        seed=7,
        context=context,
    )
    run["process_scheduler"] = {
        **scheduler,
        "effective_capabilities_hex": "0000000000003000",
    }
    assert not _process_scheduler_valid(run["process_scheduler"])
    with pytest.raises(ValueError, match="frozen sample inputs"):
        _validate_run_binding(
            run,
            manifest=manifest,
            workload_id="site",
            defense=Defense("undefended", "none", True),
            seed=7,
            context=context,
        )
    run["process_scheduler"] = scheduler
    run["workload_hash_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="frozen sample inputs"):
        _validate_run_binding(
            run,
            manifest=manifest,
            workload_id="site",
            defense=Defense("undefended", "none", True),
            seed=7,
            context=context,
        )


def test_controlled_regression_parameters_bind_loaded_chaff_evidence(tmp_path: Path) -> None:
    parameter = tmp_path / "walkie-talking-controlled.json"
    provenance = tmp_path / "walkie-talking-controlled.json.provenance.json"
    binding = {
        "workload_id": "simple",
        "chaff_qualification_sidecar_sha256": "a" * 64,
        "prefix_pack_spec_sha256": "b" * 64,
        "qualified_chaff_manifest_sha256": "c" * 64,
        "application_resource_id": 0,
        "selected_chaff_resource_id": 1,
        "qualified_parallel_chaff_streams": 5,
        "walkie_talkie_required_chaff_streams": 2,
    }
    atomic_json(parameter, {"qualification_bindings": [binding]})
    atomic_json(
        provenance,
        {"artifact_type": "qcsd-controlled-regression-parameters"},
    )
    defense = SimpleNamespace(
        parameters_path=parameter,
        parameters_provenance_path=provenance,
    )
    workload = SimpleNamespace(
        id="simple",
        chaff_qualification_sha256="a" * 64,
        chaff_prefix_spec_sha256="b" * 64,
        chaff_manifest_sha256="c" * 64,
        chaff_manifest_data={
            "application_resource_id": 0,
            "selected_chaff_resource_id": 1,
            "qualified_parallel_chaff_streams": 5,
            "walkie_talkie_required_chaff_streams": 2,
        },
    )

    orchestrator._validate_loaded_qualification_bindings((defense,), (workload,))
    atomic_json(
        parameter,
        {
            "qualification_bindings": [
                {**binding, "qualified_chaff_manifest_sha256": "d" * 64}
            ]
        },
    )
    with pytest.raises(ValueError, match="loaded chaff qualifications"):
        orchestrator._validate_loaded_qualification_bindings((defense,), (workload,))


@pytest.mark.parametrize(
    "kind",
    ["static", "front", "tamaraw", "traffic_morphing", "wtf_pad", "walkie_talkie"],
)
@pytest.mark.parametrize("missing", ["application", "chaff"])
def test_every_defended_client_command_requires_both_application_source_and_chaff(
    tmp_path: Path,
    kind: str,
    missing: str,
) -> None:
    manifest = tmp_path / "runtime.json"
    application = tmp_path / "application.json"
    chaff = tmp_path / "chaff.json"
    context = SimpleNamespace(
        qcsd_profile="live",
        request_policy="as-defined",
        limits=Limits(max_response_bytes=4_096),
    )
    defense = Defense(kind.replace("_", "-"), kind, False)

    with pytest.raises(ValueError, match="prepared source and qualified chaff"):
        _client_command(
            manifest,
            None if missing == "chaff" else chaff,
            "site",
            defense,
            7,
            context,
            tmp_path / "output",
            application_workload_source=None if missing == "application" else application,
        )


def test_baseline_client_command_forbids_application_source_and_chaff(tmp_path: Path) -> None:
    context = SimpleNamespace(
        qcsd_profile="live",
        request_policy="as-defined",
        limits=Limits(max_response_bytes=4_096),
    )
    with pytest.raises(ValueError, match="baseline run forbids"):
        _client_command(
            tmp_path / "runtime.json",
            tmp_path / "chaff.json",
            "site",
            Defense("undefended", "none", True),
            7,
            context,
            tmp_path / "output",
            application_workload_source=tmp_path / "application.json",
        )


def test_campaign_rejects_symlinked_application_workload_before_parsing(tmp_path: Path) -> None:
    campaign_path = _configuration(tmp_path)
    workload = tmp_path / "config/workloads/alpha.json"
    external = tmp_path / "external-workload.json"
    external.write_bytes(workload.read_bytes())
    workload.unlink()
    workload.symlink_to(external)

    with pytest.raises(ValueError, match="workload manifest is not a regular file"):
        load_campaign(campaign_path)


@pytest.mark.parametrize("symlinked", ["sidecar", "spec"])
def test_current_qualified_chaff_loader_rejects_symlinked_evidence(
    tmp_path: Path, symlinked: str
) -> None:
    campaign_path = _configuration(tmp_path)
    workload = load_campaign(campaign_path).workloads[0]
    config = tmp_path / "config"
    sidecar = config / "chaff-qualification-store/v2/alpha.json"
    spec = config / "chaff-prefix-specs/v2/alpha.json"
    sidecar.parent.mkdir(parents=True)
    spec.parent.mkdir(parents=True)
    sidecar.write_text("{}\n", encoding="utf-8")
    spec.write_text("{}\n", encoding="utf-8")
    selected = sidecar if symlinked == "sidecar" else spec
    external = tmp_path / f"external-{symlinked}.json"
    external.write_bytes(selected.read_bytes())
    selected.unlink()
    selected.symlink_to(external)

    with pytest.raises(ValueError, match="is not a regular file"):
        orchestrator._load_qualified_chaff_inputs(
            campaign_path,
            (workload,),
            frozen_inputs=None,
        )


def test_frozen_qualified_chaff_loader_rejects_symlinked_derived_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    campaign_path = _configuration(tmp_path)
    workload = load_campaign(campaign_path).workloads[0]
    frozen = tmp_path / "inputs"
    for directory in ("chaff-qualifications", "chaff-prefix-specs", "chaff-manifests"):
        (frozen / directory).mkdir(parents=True, exist_ok=True)
    (frozen / "chaff-qualifications/alpha.json").write_text("{}\n", encoding="utf-8")
    (frozen / "chaff-prefix-specs/alpha.json").write_text("{}\n", encoding="utf-8")
    external = tmp_path / "external-chaff.json"
    external.write_text("{}\n", encoding="utf-8")
    (frozen / "chaff-manifests/alpha.json").symlink_to(external)
    monkeypatch.setattr(
        "qcsd_lab.chaff_qualification.load_qualified_chaff",
        lambda *args, **kwargs: SimpleNamespace(
            sidecar_sha256="a" * 64,
            manifest_sha256=sha256_file(external),
            manifest={},
        ),
    )

    with pytest.raises(ValueError, match="is not a regular file"):
        orchestrator._load_qualified_chaff_inputs(
            campaign_path,
            (workload,),
            frozen_inputs=frozen,
        )


def test_expansion_is_deterministic_and_keeps_multi_origin_work_in_one_sample(
    tmp_path: Path,
) -> None:
    path = _configuration(
        tmp_path,
        workloads={
            "simple": (2, [_resource(0, "https://one.test/")]),
            "complex": (
                1,
                [
                    _resource(0, "https://one.test/"),
                    _resource(1, "https://one.test/app.js", depends_on=[0]),
                    _resource(3, "https://ONE.test:443/default.js", depends_on=[0]),
                    _resource(2, "https://two.test/lib.js", depends_on=[0]),
                ],
            ),
        },
        policies=["as-defined", "half-duplex"],
    )
    first = plan_campaign(load_campaign(path))
    second = plan_campaign(load_campaign(path))

    assert first == second
    assert len(first) == (2 + 1) * 2
    groups: list[tuple[str, str, int]] = []
    for sample in first:
        group = (sample["workload_id"], sample["request_policy"], sample["visit"])
        if not groups or groups[-1] != group:
            groups.append(group)
    assert groups == [
        ("simple", "as-defined", 0),
        ("simple", "as-defined", 1),
        ("simple", "half-duplex", 0),
        ("simple", "half-duplex", 1),
        ("complex", "as-defined", 0),
        ("complex", "half-duplex", 0),
    ]
    complex_workload = next(item for item in load_campaign(path).workloads if item.id == "complex")
    assert complex_workload.origin_count == 2
    assert all(sample["workload_id"] == "complex" for sample in first[-2:])
    assert len({sample["path"].split("/")[1] for sample in first[-2:]}) == 1

    preflight = preflight_campaign(path)
    assert preflight["valid"] is True
    assert preflight["sample_count"] == 6
    assert preflight["execution_order"] == [sample["sample_id"] for sample in first]
    assert next(item for item in preflight["workloads"] if item["id"] == "complex")["origins"] == 2


def test_resume_epoch_restarts_cooldown_for_previously_attempted_origins(tmp_path: Path) -> None:
    path = _configuration(tmp_path)
    campaign = load_campaign(path)
    samples = plan_campaign(campaign)
    samples[0]["attempts"] = 1

    history = orchestrator._prior_origin_completion(campaign, {"samples": samples})

    assert history.keys() == {"https://alpha.test"}
    assert all(value > 0 for value in history.values())


def test_campaign_accepts_only_the_exact_research_1200_profile_token(tmp_path: Path) -> None:
    path = _configuration(tmp_path, profile="research-1200")

    campaign = load_campaign(path)
    assert campaign.profile == "research-1200"
    assert campaign.udp_payload_ceiling == 1_200
    assert preflight_campaign(path)["valid"] is True

    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    for invalid in ("research_1200", "research1200", "Research-1200"):
        value["profile"] = invalid
        path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
        with pytest.raises(ValueError, match="campaign profile must be one of"):
            load_campaign(path)


@pytest.mark.parametrize(
    "obsolete",
    [
        {"monitored": {"alpha": 1}},
        {"unmonitored": {"alpha": 1}},
        {"split": {"train": 0.8}},
        {"classifier": "df"},
        {"header_policy": {"mode": "minimal"}},
    ],
)
def test_campaign_rejects_obsolete_dataset_and_header_policy_layers(
    tmp_path: Path, obsolete: dict[str, Any]
) -> None:
    path = _configuration(tmp_path)
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    value.update(obsolete)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported fields"):
        load_campaign(path)


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        ("", "at least one packet"),
        ("not-a-record\n", "seconds,signed_size"),
        ("nan,1200\n", "finite and non-negative"),
        ("0,0\n", "must not be zero"),
        ("0,1201\n", "1200-byte QCSD profile ceiling"),
    ],
)
def test_campaign_preflight_rejects_invalid_static_schedules(
    tmp_path: Path, contents: str, message: str
) -> None:
    path = _configuration(
        tmp_path,
        defenses=[
            "undefended",
            {"name": "static", "kind": "static", "schedule": "schedule.csv", "mode": "chaff-only"},
        ],
    )
    (path.parent / "schedule.csv").write_text(contents, encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        preflight_campaign(path)


def test_campaign_preflight_accepts_a_valid_static_schedule(tmp_path: Path) -> None:
    path = _configuration(
        tmp_path,
        defenses=[
            "undefended",
            {"name": "static", "kind": "static", "schedule": "schedule.csv", "mode": "chaff-only"},
        ],
    )
    (path.parent / "schedule.csv").write_text(
        "# seconds,signed_size\n0.000000,1200\n0.005000,-1200\n",
        encoding="utf-8",
    )

    orchestrator._validate_static_schedule(path.parent / "schedule.csv", udp_payload_ceiling=1_200)
    with pytest.raises(ValueError, match="research-prepared workloads and qualified chaff"):
        preflight_campaign(path)


def test_multi_defense_campaign_requires_one_response_baseline(tmp_path: Path) -> None:
    path = _configuration(tmp_path, defenses=["front", "tamaraw"])

    with pytest.raises(ValueError, match="requires one undefended baseline"):
        load_campaign(path)


@pytest.mark.parametrize("identifier", ["campaign", "workload", "defense"])
def test_preflight_rejects_unicode_identifiers_before_materializing_result(
    tmp_path: Path, identifier: str
) -> None:
    path = _configuration(tmp_path)
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if identifier == "campaign":
        value["name"] = "café"
    elif identifier == "workload":
        value["workloads"] = {"café": 1}
    else:
        value["defenses"] = ["undefended", {"name": "frönt", "kind": "front"}]
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")

    with pytest.raises(ValueError, match="filesystem-safe"):
        run_campaign(path, tmp_path / "results")
    assert not (tmp_path / "results").exists()


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("front", "tamaraw"),
        ("front", "none"),
        ("undefended", "front"),
        ("traffic-morphing", "wtf-pad"),
    ],
)
def test_campaign_preflight_rejects_canonical_defense_bound_to_wrong_runtime(
    tmp_path: Path, name: str, kind: str
) -> None:
    path = _configuration(tmp_path, defenses=[{"name": name, "kind": kind}])

    with pytest.raises(ValueError, match=r"is not bound to runtime kind"):
        preflight_campaign(path)


def test_campaign_preflight_allows_custom_defense_alias_for_runtime_kind(tmp_path: Path) -> None:
    path = _configuration(
        tmp_path,
        defenses=["undefended", {"name": "front-experiment", "kind": "front"}],
    )

    defenses = orchestrator._load_defenses(
        path.parent,
        yaml.safe_load(path.read_text(encoding="utf-8"))["defenses"],
        "smoke",
        "live",
        {"alpha": "a" * 64},
    )
    assert [(defense.name, defense.kind) for defense in defenses] == [
        ("undefended", "none"),
        ("front-experiment", "front"),
    ]
    with pytest.raises(ValueError, match="research-prepared workloads and qualified chaff"):
        preflight_campaign(path)


def test_run_writes_only_the_canonical_result_and_retains_failed_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _configuration(tmp_path, max_attempts=2)
    collector = _Collector(fail_once={"undefended"})
    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", collector)

    root = run_campaign(path, tmp_path / "results")
    verified = verify_result(root)
    experiment = verified.experiment

    assert experiment["status"] == "complete"
    assert experiment["summary"] == {
        "planned": 1,
        "accepted": 1,
        "failed": 0,
        "eligible": 1,
        "passed": True,
    }
    assert set(path.name for path in root.iterdir()) == {
        "experiment.json",
        "evidence.sha256",
        "inputs",
        "samples",
        "failures",
        "derived",
    }
    assert not list(root.rglob("sample.json"))
    assert not list(root.rglob("*.jsonl"))
    assert not list(root.rglob("qlog"))
    assert list((root / "derived").iterdir()) == []

    expected_artifacts = {
        "capture.pcapng",
        "neqo/run.json",
        "neqo/packets.csv",
        "neqo/events.csv",
        "neqo/schedule.csv",
    }
    for sample in experiment["samples"]:
        sample_root = root / sample["path"]
        actual = {
            artifact.relative_to(sample_root).as_posix()
            for artifact in sample_root.rglob("*")
            if artifact.is_file()
        }
        assert actual == expected_artifacts
        assert sample["diagnostics"]["response_match"] is True
        assert sample["eligible"] is True

    baseline = experiment["samples"][0]
    assert baseline["attempts"] == 2
    retained = root / "failures" / baseline["sample_id"] / "attempt-001/failure.json"
    assert load_json(retained)["message"] == "first attempt failed"
    assert not (retained.parents[1] / "attempt-002").exists()
    assert str(retained.relative_to(root)) in verified.checksums


def test_collection_success_with_pacing_miss_is_quarantined_then_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _configuration(tmp_path, max_attempts=2, defenses=["undefended", "front"])
    with pytest.raises(ValueError, match="research-prepared workloads and qualified chaff"):
        run_campaign(path, tmp_path / "results")
    assert not (tmp_path / "results").exists()


def test_collection_success_with_clock_step_is_quarantined_then_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _configuration(tmp_path, max_attempts=2)
    calls = 0

    def collect(
        attempt: Path,
        _manifest: Path,
        workload_id: str,
        defense: Any,
        _seed: int,
        _campaign: Any,
    ) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        result = _write_successful_attempt(attempt, workload_id, defense.name)
        if calls == 1:
            reconciliation = result["views"][0]["direct_runner_reconciliation"]
            reconciliation.update(
                direct_clock_model="positive-abrupt-steps",
                direct_clock_segment_count=2,
                direct_clock_segments=[{"index": 0}, {"index": 1}],
                direct_clock_step_count=1,
                direct_clock_steps=[{"index": 0}],
            )
        return result

    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", collect)

    root = run_campaign(path, tmp_path / "results")
    experiment = verify_result(root).experiment
    [sample] = experiment["samples"]
    assert sample["state"] == "accepted"
    assert sample["eligible"] is True
    assert sample["attempts"] == 2
    retained = load_json(root / "failures" / sample["sample_id"] / "attempt-001/attempt.json")
    assert retained["failure"]["type"] == "StrictCaptureClockIntegrityFailure"
    assert "constant-offset" in retained["failure"]["details"][0]["error"]


def test_collection_success_with_multiple_primary_views_is_quarantined(
    tmp_path: Path,
) -> None:
    attempt = tmp_path / "attempt"
    result = _write_successful_attempt(attempt, "alpha", "undefended")
    result["views"].append(dict(result["views"][0]))

    failure = orchestrator._intrinsic_fidelity_failure(
        {"sample_id": "sample", "defense": "undefended", "runtime_kind": "none"},
        result,
        attempt,
    )

    assert failure is not None
    assert failure["type"] == "StrictCaptureClockIntegrityFailure"
    assert "exactly one primary" in failure["details"][0]["error"]


def test_prepared_response_identity_drift_is_quarantined_then_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _configuration(tmp_path, max_attempts=2)
    expected_signature = [(0, 200, 64, "a" * 64, "succeeded")]
    monkeypatch.setattr(
        orchestrator,
        "_prepared_response_signature",
        lambda _manifest: expected_signature,
    )
    calls = 0

    def collect(
        attempt: Path,
        _manifest: Path,
        workload_id: str,
        defense: Any,
        _seed: int,
        _campaign: Any,
    ) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return _write_successful_attempt(
            attempt,
            workload_id,
            defense.name,
            body_sha256=("b" if calls == 1 else "a") * 64,
        )

    monkeypatch.setattr(orchestrator.capture_engine, "_collect_attempt", collect)

    root = run_campaign(path, tmp_path / "results")

    verified = verify_result(root)
    [sample] = verified.experiment["samples"]
    assert sample["state"] == "accepted"
    assert sample["eligible"] is True
    assert sample["attempts"] == 2
    retained_path = root / "failures" / sample["sample_id"] / "attempt-001" / "attempt.json"
    retained = load_json(retained_path)
    assert retained["success"] is False
    assert retained["failure"]["stage"] == "fidelity"
    assert retained["failure"]["type"] == "StrictPreparedResponseIdentityFailure"
    assert retained["failure"]["details"][0]["differing_resource_ids"] == [0]
    assert retained_path.relative_to(root).as_posix() in verified.checksums


def test_prepared_response_identity_gate_is_absent_for_legacy_workloads(
    tmp_path: Path,
) -> None:
    attempt = tmp_path / "attempt"
    _write_successful_attempt(attempt, "alpha", "undefended", body_sha256="b" * 64)
    workload = SimpleNamespace(id="alpha", data={})

    assert orchestrator._prepared_response_identity_failure(workload, attempt) is None


def test_all_collection_successes_with_fidelity_misses_end_terminally_without_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _configuration(tmp_path, max_attempts=2, defenses=["undefended", "front"])
    with pytest.raises(ValueError, match="research-prepared workloads and qualified chaff"):
        run_campaign(path, tmp_path / "results")
    assert not (tmp_path / "results").exists()


def test_paired_response_mismatch_makes_the_terminal_result_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _configuration(tmp_path, defenses=["undefended", "front"])
    with pytest.raises(ValueError, match="research-prepared workloads and qualified chaff"):
        run_campaign(path, tmp_path / "results")
    assert not (tmp_path / "results").exists()


def test_materialization_uses_the_exact_campaign_bytes_that_were_parsed(
    tmp_path: Path,
) -> None:
    path = _configuration(tmp_path)
    campaign = load_campaign(path)
    validated_bytes = path.read_bytes()
    workload = campaign.workloads[0]
    validated_workload_bytes = workload.path.read_bytes()
    changed = yaml.safe_load(path.read_text(encoding="utf-8"))
    changed["purpose"] = "evaluation"
    changed["seed"] += 1
    path.write_text(yaml.safe_dump(changed, sort_keys=False), encoding="utf-8")
    workload.path.write_bytes(validated_workload_bytes + b"\n")

    root = tmp_path / "materialized"
    runtime, configuration = orchestrator._materialize_inputs(root, campaign, {})

    assert (root / "inputs/campaign.yml").read_bytes() == validated_bytes
    frozen_workload = root / "inputs/workloads" / f"{workload.id}.json"
    assert frozen_workload.read_bytes() == validated_workload_bytes
    assert configuration["workloads"][0]["sha256"] == sha256_file(frozen_workload)
    assert runtime.purpose == "smoke"
    assert runtime.seed == 7_331
    assert configuration["campaign_sha256"] == sha256_file(root / "inputs/campaign.yml")
    assert not (root / "experiment.json").exists()


@pytest.mark.parametrize(
    ("artifact", "message"),
    [
        ("schedule", "Static schedule changed during input materialization"),
        ("parameters", "parameter artifact changed during input materialization"),
        ("provenance", "parameter artifact changed during input materialization"),
    ],
)
def test_materialization_rejects_artifact_copy_races_before_initialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact: str,
    message: str,
) -> None:
    fixture_root = Path(__file__).parents[1] / "config/defense-params"
    if artifact == "schedule":
        defenses: list[str | dict[str, Any]] = [
            "undefended",
            {
                "name": "static-control",
                "kind": "static",
                "schedule": str(fixture_root / "static-control-1200.csv"),
                "mode": "chaff-only",
            },
        ]
    else:
        defenses = [
            "undefended",
            {
                "name": "traffic-morphing",
                "kind": "traffic_morphing",
                "parameters": str(fixture_root / "traffic-morphing-live.json"),
            },
        ]
    path = _configuration(
        tmp_path / "source",
        workloads={
            "cloudflare-quiche": (
                1,
                [_resource(0, "https://cloudflare-quiche.test/")],
            )
        },
        defenses=defenses,
    )
    with pytest.raises(ValueError, match="research-prepared workloads and qualified chaff"):
        load_campaign(path)
    assert not (tmp_path / "materialized/experiment.json").exists()
