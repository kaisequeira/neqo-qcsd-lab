from __future__ import annotations

import json
from pathlib import Path

import pytest

from qcsd_lab.class_build_admission import _parser, resolve_action_admission
from qcsd_lab.class_study import canonical_json_bytes
from qcsd_lab.util import sha256_file
from tests.test_class_build_admission_successor import _binding, _publish
from tests.test_cli import _class_build_admission_fixture, _class_build_pinned_cdp_receipt


AUTHORITY = "qcsd-class-study-acquisition-authority"
PROVENANCE = "qcsd-class-study-acquisition-provenance"
COMPLETION = "qcsd-class-study-acquisition-completion"


@pytest.fixture
def authority_fixture(tmp_path: Path):
    fixture = _class_build_admission_fixture(tmp_path)
    build = fixture.admitted
    prepare_source = {**dict(build.source), "image_digest": build.prepare_image}
    fixture.pinned = _class_build_pinned_cdp_receipt(fixture, schema=13)
    fixture.browser = fixture.root / "artifacts/browser-egress-qualification-v62"
    browser_foundation = _publish(
        fixture.browser / "foundation.json",
        "qcsd-browser-egress-qualification-foundation",
        {
            "schema_version": 4,
            "cohort_version": 62,
            "source": prepare_source,
            "build_execution": {
                **_binding(fixture.build),
                "completion_path": build.identity["completion_path"],
                "completion_sha256": build.completion_sha256,
                "collection_image_id": build.collection_image,
                "prepare_image_id": build.prepare_image,
                "reference_image_id": build.reference_image,
            },
        },
    )
    _publish(
        fixture.browser / "final.json",
        "qcsd-browser-egress-qualification-final",
        {
            "schema_version": 1,
            "cohort_version": 62,
            "verdict": "passed",
            "foundation": {
                "path": "foundation.json",
                "sha256": sha256_file(browser_foundation),
                "payload_sha256": json.loads(browser_foundation.read_bytes())["payload_sha256"],
            },
        },
    )
    study = fixture.root / "config/class-study/v1/study.json"
    study.parent.mkdir(parents=True)
    study.write_bytes(canonical_json_bytes({"study_id": "classifier-multiorigin100-v1"}))
    fixture.authority = _publish(
        fixture.root / "artifacts/class-study-acquisition-authority-v62.json",
        AUTHORITY,
        {
            "attestation_schema_version": 1,
            "artifact_type": AUTHORITY,
            "cohort_version": 62,
            "authority_scope": "public-page-acquisition-only",
            "promotion_authority": False,
            "no_waivers": True,
            "source": build.source,
            "prepare_source": prepare_source,
            "build_execution_identity": build.identity,
            "study_contract": _binding(study),
            "evidence": {
                "build_execution": _binding(fixture.build),
                "pinned_cdp_probe": _binding(fixture.pinned),
                "browser_egress_qualification": {"root": str(fixture.browser)},
            },
            "acquisition_correctness": {
                "source": build.source,
                "build_execution_identity": build.identity,
                "study_contract": _binding(study),
            },
        },
    )
    return fixture


def _resolve(fixture, action: str, **options):
    return resolve_action_admission(
        fixture.root,
        action=action,
        cohort_version=62,
        options={key: str(value) for key, value in options.items()},
        build_loader=fixture.load,
    )


def _rewrite(path: Path, change) -> None:
    value = json.loads(path.read_bytes())
    change(value["payload"])
    _publish(path, value["receipt_type"], value["payload"])


def _use_authority(fixture) -> None:
    provenance = fixture.acquisition / "provenance.json"
    _rewrite(
        provenance,
        lambda payload: payload.update(acquisition_authority=_binding(fixture.authority)),
    )
    _rewrite(
        fixture.acquisition_completion,
        lambda payload: payload.update(provenance_sha256=sha256_file(provenance)),
    )


def test_authority_creation_needs_only_build_cdp_and_egress(authority_fixture) -> None:
    fixture = authority_fixture
    assert _resolve(
        fixture,
        "acquisition-authority",
        build=fixture.build,
        pinned_cdp=fixture.pinned,
        browser_egress=fixture.browser,
    ) == fixture.admitted


@pytest.mark.parametrize("missing", ("build", "pinned_cdp", "browser_egress"))
def test_authority_creation_requires_all_three_inputs(authority_fixture, missing: str) -> None:
    fixture = authority_fixture
    options = dict(build=fixture.build, pinned_cdp=fixture.pinned, browser_egress=fixture.browser)
    del options[missing]
    with pytest.raises(ValueError, match="requires"):
        _resolve(fixture, "acquisition-authority", **options)


@pytest.mark.parametrize("action", ("acquisition-init", "status"))
def test_authority_argument_is_explicitly_routed(authority_fixture, action: str) -> None:
    fixture = authority_fixture
    assert _resolve(fixture, action, acquisition_authority=fixture.authority) == fixture.admitted


def test_verify_authority_ignores_unconsumed_later_stage_inputs(authority_fixture) -> None:
    fixture = authority_fixture
    assert _resolve(
        fixture, "verify", target=fixture.authority, foundation=fixture.root / "absent.json"
    ) == fixture.admitted


def test_init_keeps_explicit_full_foundation_fallback(authority_fixture) -> None:
    fixture = authority_fixture
    assert _resolve(fixture, "acquisition-init", foundation=fixture.foundation) == fixture.admitted


@pytest.mark.parametrize("action", ("acquisition-init", "status"))
def test_new_authority_flag_requires_narrow_receipt_type(authority_fixture, action: str) -> None:
    fixture = authority_fixture
    with pytest.raises(ValueError, match="acquisition authority hash envelope"):
        _resolve(fixture, action, acquisition_authority=fixture.foundation)


@pytest.mark.parametrize("action", ("acquisition-run", "acquisition-status", "acquisition-complete"))
def test_schema6_keeps_previously_bound_full_foundation_fallback(
    authority_fixture, action: str
) -> None:
    fixture = authority_fixture
    assert _resolve(fixture, action, acquisition_root=fixture.acquisition) == fixture.admitted


def test_init_rejects_ambiguous_authorities(authority_fixture) -> None:
    fixture = authority_fixture
    with pytest.raises(ValueError, match="exactly one"):
        _resolve(
            fixture,
            "acquisition-init",
            acquisition_authority=fixture.authority,
            foundation=fixture.foundation,
        )


@pytest.mark.parametrize("action", ("acquisition-init", "capture", "resume", "readiness"))
def test_narrow_authority_is_never_accepted_as_foundation(authority_fixture, action: str) -> None:
    with pytest.raises(ValueError, match="foundation hash envelope"):
        _resolve(authority_fixture, action, foundation=authority_fixture.authority)


@pytest.mark.parametrize(
    "action", ("acquisition-run", "acquisition-status", "acquisition-complete", "status")
)
def test_schema6_acquisition_uses_its_bound_authority(authority_fixture, action: str) -> None:
    fixture = authority_fixture
    _use_authority(fixture)
    assert _resolve(fixture, action, acquisition_root=fixture.acquisition) == fixture.admitted


def test_schema6_completion_uses_bound_provenance_and_authority(authority_fixture) -> None:
    fixture = authority_fixture
    _use_authority(fixture)
    assert _resolve(
        fixture, "cohort", acquisition_completion=fixture.acquisition_completion
    ) == fixture.admitted


@pytest.mark.parametrize("schema", (1, 2, 3, 4, 5))
def test_legacy_acquisition_is_inspectable_but_not_current_launch_authority(
    authority_fixture, schema: int
) -> None:
    fixture = authority_fixture
    _rewrite(
        fixture.acquisition / "provenance.json",
        lambda payload: payload.update(acquisition_schema_version=schema),
    )
    assert _resolve(fixture, "status", acquisition_root=fixture.acquisition) is None
    with pytest.raises(ValueError, match="historical"):
        _resolve(fixture, "acquisition-run", acquisition_root=fixture.acquisition)


@pytest.mark.parametrize(
    "field,value",
    (
        ("attestation_schema_version", True),
        ("attestation_schema_version", 1.0),
        ("authority_scope", "all-captures"),
        ("promotion_authority", True),
        ("no_waivers", False),
        ("source", {}),
        ("prepare_source", {}),
        ("build_execution_identity", {}),
        ("acquisition_correctness", {}),
    ),
)
def test_resealed_authority_cannot_drift_from_its_build(authority_fixture, field, value) -> None:
    fixture = authority_fixture
    _rewrite(fixture.authority, lambda payload: payload.update({field: value}))
    with pytest.raises(ValueError):
        _resolve(fixture, "acquisition-init", acquisition_authority=fixture.authority)


@pytest.mark.parametrize("missing", ("pinned_cdp_probe", "browser_egress_qualification"))
def test_authority_requires_both_linked_proofs(authority_fixture, missing: str) -> None:
    fixture = authority_fixture
    _rewrite(fixture.authority, lambda payload: payload["evidence"].pop(missing))
    with pytest.raises((TypeError, ValueError), match="binding"):
        _resolve(fixture, "verify", target=fixture.authority)


def test_current_provenance_rejects_legacy_binding(authority_fixture) -> None:
    fixture = authority_fixture
    _rewrite(
        fixture.acquisition / "provenance.json",
        lambda payload: payload.update(foundation_attestation=_binding(fixture.foundation)),
    )
    with pytest.raises(ValueError, match="legacy foundation"):
        _resolve(fixture, "acquisition-run", acquisition_root=fixture.acquisition)


@pytest.mark.parametrize("field,value", (
    ("acquisition_schema_version", 6.0),
    ("completion_schema_version", 3.0),
    ("completion_schema_version", True),
))
def test_current_completion_rejects_schema_aliases(authority_fixture, field, value) -> None:
    fixture = authority_fixture
    _rewrite(fixture.acquisition_completion, lambda payload: payload.update({field: value}))
    with pytest.raises(ValueError, match="not current build authority"):
        _resolve(fixture, "cohort", acquisition_completion=fixture.acquisition_completion)


def test_bound_study_contract_drift_rejects_current_authority(authority_fixture) -> None:
    fixture = authority_fixture
    study = fixture.root / "config/class-study/v1/study.json"
    study.write_text("changed protocol\n", encoding="utf-8")
    with pytest.raises(ValueError, match="binding changed"):
        _resolve(fixture, "verify", target=fixture.authority)


def test_bound_pinned_cdp_source_drift_rejects_current_authority(authority_fixture) -> None:
    fixture = authority_fixture
    _rewrite(fixture.pinned, lambda payload: payload.update(prepare_source={}))
    _rewrite(
        fixture.authority,
        lambda payload: payload["evidence"].update(pinned_cdp_probe=_binding(fixture.pinned)),
    )
    with pytest.raises(ValueError, match="differs from its current build"):
        _resolve(fixture, "verify", target=fixture.authority)


def test_host_parser_accepts_explicit_acquisition_authority_flag() -> None:
    parsed = _parser().parse_args(
        [
            "--lab-root", "/lab", "--action", "acquisition-init",
            "--acquisition-authority", "proof.json",
        ]
    )
    assert parsed.acquisition_authority == "proof.json"
