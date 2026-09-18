from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import browser_egress_qualification as browser_producer
from qcsd_lab import class_acquisition as acquisition_producer
from qcsd_lab import class_build_admission as admission
from qcsd_lab import pinned_cdp as pinned_cdp_producer
from qcsd_lab.class_build_admission import _parser, resolve_action_admission
from qcsd_lab.class_study import canonical_json_bytes
from qcsd_lab.util import sha256_file
from tests.test_class_build_admission_successor import _binding, _publish
from tests.test_cli import _class_build_admission_fixture, _class_build_pinned_cdp_receipt


AUTHORITY = "qcsd-class-study-acquisition-authority"
PROVENANCE = "qcsd-class-study-acquisition-provenance"
COMPLETION = "qcsd-class-study-acquisition-completion"


def _browser_final(root: Path, foundation: Path, *, cohort: int) -> Path:
    """Publish only the final build-admission projection, not packet evidence."""

    return _publish(
        root / "final.json", browser_producer.FINAL_RECEIPT_TYPE,
        {
            "schema_version": browser_producer.FINAL_SCHEMA_VERSION,
            "cohort_version": cohort,
            "verdict": "passed",
            "foundation": {
                "path": "foundation.json",
                "sha256": sha256_file(foundation),
                "payload_sha256": json.loads(foundation.read_bytes())["payload_sha256"],
            },
        },
    )


@pytest.fixture
def authority_fixture(tmp_path: Path):
    fixture = _class_build_admission_fixture(tmp_path)
    build = fixture.admitted
    prepare_source = {**dict(build.source), "image_digest": build.prepare_image}
    fixture.pinned = _class_build_pinned_cdp_receipt(
        fixture, schema=pinned_cdp_producer.PROBE_SCHEMA_VERSION
    )
    fixture.browser = fixture.root / "artifacts/browser-egress-qualification-v62"
    browser_foundation = _publish(
        fixture.browser / "foundation.json",
        browser_producer.FOUNDATION_RECEIPT_TYPE,
        {
            "schema_version": browser_producer.FOUNDATION_SCHEMA_VERSION,
            "cohort_version": 62,
            "source": prepare_source,
            "build_execution": {
                **_binding(fixture.build),
                "path": fixture.build.relative_to(fixture.root).as_posix(),
                "size_bytes": fixture.build.stat().st_size,
                "completion_path": build.identity["completion_path"],
                "completion_sha256": build.completion_sha256,
                "collection_image_id": build.collection_image,
                "prepare_image_id": build.prepare_image,
                "reference_image_id": build.reference_image,
            },
        },
    )
    _browser_final(fixture.browser, browser_foundation, cohort=62)
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


def test_standalone_browser_schema_constants_match_the_producer() -> None:
    # The host stays stdlib-only; this test is the intentional cross-boundary import.
    assert admission._BROWSER_EGRESS_FOUNDATION_SCHEMA == browser_producer.FOUNDATION_SCHEMA_VERSION
    assert admission._HISTORICAL_BROWSER_EGRESS_FOUNDATION_SCHEMAS == (
        browser_producer.HISTORICAL_FOUNDATION_SCHEMA_VERSIONS
    )
    assert admission._BROWSER_EGRESS_FINAL_SCHEMA == browser_producer.FINAL_SCHEMA_VERSION
    assert admission._ACQUISITION_SCHEMA == acquisition_producer.SCHEMA_VERSION == 7
    assert (
        admission._ACQUISITION_COMPLETION_SCHEMA
        == acquisition_producer.COMPLETION_SCHEMA_VERSION
        == 4
    )
    assert (
        admission._ACQUISITION_CHECKPOINT_SCHEMA
        == acquisition_producer.CHECKPOINT_SCHEMA_VERSION
        == 3
    )
    assert admission._PINNED_CDP_SCHEMA == pinned_cdp_producer.PROBE_SCHEMA_VERSION == 15
    assert 14 in admission._HISTORICAL_PINNED_CDP_SCHEMAS


def test_authority_admission_accepts_production_built_browser_foundation(tmp_path: Path) -> None:
    from tests.test_browser_egress_qualification import _lab

    # _lab invokes the real build_foundation_payload and its validator. It
    # supplies deterministic source files/daemon data, without executing Docker.
    root, payload = _lab(tmp_path)
    browser_producer.validate_foundation_payload(payload)
    build_binding = payload["build_execution"]
    build_path = root / build_binding["path"]
    source = {**payload["source"], "image_digest": build_binding["collection_image_id"]}
    identity = {
        "cohort_version": payload["cohort_version"], "sha256": sha256_file(build_path),
        "completion_path": build_binding["completion_path"],
        "completion_sha256": build_binding["completion_sha256"],
        "collection_image": build_binding["collection_image_id"],
        "started_at": "2026-09-07T00:00:00+00:00", "finished_at": "2026-09-07T00:01:00+00:00",
    }
    build = admission.BuildAdmission(
        receipt_path=build_path, receipt_sha256=sha256_file(build_path),
        cohort_version=payload["cohort_version"],
        collection_image=build_binding["collection_image_id"],
        prepare_image=build_binding["prepare_image_id"],
        reference_image=build_binding["reference_image_id"],
        completion_path=build_path.parent / "build-completion-v71.json",
        completion_sha256=build_binding["completion_sha256"],
        completion_payload_sha256="f" * 64, source=source, identity=identity,
    )
    fixture = SimpleNamespace(root=root, build=build_path, admitted=build)
    pinned = _class_build_pinned_cdp_receipt(
        fixture, schema=pinned_cdp_producer.PROBE_SCHEMA_VERSION
    )
    browser = root / "artifacts/browser-egress-qualification-v71"
    foundation = _publish(browser / "foundation.json", browser_producer.FOUNDATION_RECEIPT_TYPE, payload)
    _browser_final(browser, foundation, cohort=build.cohort_version)
    observed = []

    def load(path: Path, *, expected_cohort=None):
        observed.append((path, expected_cohort))
        assert path == build_path
        assert expected_cohort in (None, build.cohort_version)
        return build

    assert build_binding["size_bytes"] == build_path.stat().st_size
    assert resolve_action_admission(
        root, action="acquisition-authority", cohort_version=build.cohort_version,
        options={"build": str(build_path), "pinned_cdp": str(pinned), "browser_egress": str(browser)},
        build_loader=load,
    ) == build
    assert observed == [(build_path, build.cohort_version)]


@pytest.mark.parametrize("schema", (2, 3, 4, 5))
def test_browser_historical_foundations_are_not_current_authority(authority_fixture, schema) -> None:
    fixture = authority_fixture
    _rewrite(fixture.browser / "foundation.json", lambda value: value.update(schema_version=schema))
    with pytest.raises(admission._HistoricalAuthority, match="historical"):
        _resolve(fixture, "acquisition-authority", build=fixture.build,
                 pinned_cdp=fixture.pinned, browser_egress=fixture.browser)


@pytest.mark.parametrize(
    "schema", (True, False, 2.0, 3.0, 4.0, 5.0, 6.0, "6", None, 0, 1, 7)
)
def test_browser_foundation_schema_aliases_and_unknowns_are_invalid(authority_fixture, schema) -> None:
    fixture = authority_fixture
    _rewrite(fixture.browser / "foundation.json", lambda value: value.update(schema_version=schema))
    with pytest.raises(ValueError, match="current build authority") as error:
        _resolve(fixture, "acquisition-authority", build=fixture.build,
                 pinned_cdp=fixture.pinned, browser_egress=fixture.browser)
    assert not isinstance(error.value, admission._HistoricalAuthority)


@pytest.mark.parametrize("field,value", (
    ("schema_version", True), ("schema_version", False), ("schema_version", 1.0),
    ("schema_version", "1"), ("schema_version", None), ("schema_version", 0), ("schema_version", 2),
    ("cohort_version", 62.0), ("cohort_version", True), ("cohort_version", "62"),
    ("cohort_version", None), ("cohort_version", 63), ("verdict", "failed"),
))
def test_browser_final_payload_requires_exact_current_types(authority_fixture, field, value) -> None:
    fixture = authority_fixture
    _rewrite(fixture.browser / "final.json", lambda payload: payload.update({field: value}))
    with pytest.raises(ValueError, match="final receipt"):
        _resolve(fixture, "acquisition-authority", build=fixture.build,
                 pinned_cdp=fixture.pinned, browser_egress=fixture.browser)


@pytest.mark.parametrize("mutation", ("missing", "receipt-type", "path", "sha256", "payload_sha256"))
def test_browser_final_envelope_must_bind_the_exact_foundation(authority_fixture, mutation) -> None:
    fixture = authority_fixture
    final = fixture.browser / "final.json"
    if mutation == "missing":
        final.unlink()
    elif mutation == "receipt-type":
        _publish(final, browser_producer.FOUNDATION_RECEIPT_TYPE, json.loads(final.read_bytes())["payload"])
    else:
        _rewrite(final, lambda payload: payload["foundation"].update({
            mutation: "other.json" if mutation == "path" else "0" * 64,
        }))
    with pytest.raises(ValueError, match="final receipt"):
        _resolve(fixture, "acquisition-authority", build=fixture.build,
                 pinned_cdp=fixture.pinned, browser_egress=fixture.browser)


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
def test_current_acquisition_keeps_previously_bound_full_foundation_fallback(
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
def test_current_acquisition_uses_its_bound_authority(authority_fixture, action: str) -> None:
    fixture = authority_fixture
    _use_authority(fixture)
    assert _resolve(fixture, action, acquisition_root=fixture.acquisition) == fixture.admitted


def test_current_completion_uses_bound_provenance_and_authority(authority_fixture) -> None:
    fixture = authority_fixture
    _use_authority(fixture)
    assert _resolve(
        fixture, "cohort", acquisition_completion=fixture.acquisition_completion
    ) == fixture.admitted


@pytest.mark.parametrize("schema", (1, 2, 3, 4, 5, 6))
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


@pytest.mark.parametrize(
    "field,value",
    (
        ("acquisition_schema_version", float(acquisition_producer.SCHEMA_VERSION)),
        ("completion_schema_version", float(acquisition_producer.COMPLETION_SCHEMA_VERSION)),
        ("completion_schema_version", True),
    ),
)
def test_current_completion_rejects_schema_aliases(authority_fixture, field, value) -> None:
    fixture = authority_fixture
    _rewrite(fixture.acquisition_completion, lambda payload: payload.update({field: value}))
    with pytest.raises(ValueError, match="not current build authority"):
        _resolve(fixture, "cohort", acquisition_completion=fixture.acquisition_completion)


@pytest.mark.parametrize("checkpoint", (None, 2, True, 3.0))
def test_current_completion_requires_exact_checkpoint_schema(
    authority_fixture,
    checkpoint: object,
) -> None:
    fixture = authority_fixture

    def mutate(payload: dict[str, object]) -> None:
        if checkpoint is None:
            payload.pop("checkpoint_schema_version")
        else:
            payload["checkpoint_schema_version"] = checkpoint

    _rewrite(fixture.acquisition_completion, mutate)
    with pytest.raises(ValueError, match="not current build authority"):
        _resolve(fixture, "cohort", acquisition_completion=fixture.acquisition_completion)


def test_v96_authority_is_verify_only_and_never_current_admission(authority_fixture) -> None:
    fixture = authority_fixture
    _rewrite(
        fixture.pinned,
        lambda payload: payload.update(probe_schema_version=14),
    )
    _rewrite(
        fixture.authority,
        lambda payload: payload["evidence"].update(pinned_cdp_probe=_binding(fixture.pinned)),
    )

    assert _resolve(fixture, "verify", target=fixture.authority) is None
    assert _resolve(fixture, "status", acquisition_authority=fixture.authority) is None
    with pytest.raises(admission._HistoricalAuthority, match="historical"):
        _resolve(
            fixture,
            "acquisition-init",
            acquisition_authority=fixture.authority,
        )


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
