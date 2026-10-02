from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from qcsd_lab import browser_egress_qualification as browser_producer
from qcsd_lab import class_acquisition as acquisition_producer
from qcsd_lab import class_attestation as attestation_producer
from qcsd_lab import class_build_admission as admission
from qcsd_lab import pinned_cdp as pinned_cdp_producer
from qcsd_lab.class_build_admission import _parser, resolve_action_admission
from qcsd_lab.class_study import bind_receipt, canonical_json_bytes
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


def test_authority_creation_accepts_build_cdp_and_egress(authority_fixture) -> None:
    fixture = authority_fixture
    assert _resolve(
        fixture,
        "acquisition-authority",
        build=fixture.build,
        pinned_cdp=fixture.pinned,
        browser_egress=fixture.browser,
    ) == fixture.admitted


def test_authority_creation_accepts_build_and_cdp_without_browser(authority_fixture) -> None:
    fixture = authority_fixture
    assert _resolve(
        fixture,
        "acquisition-authority",
        build=fixture.build,
        pinned_cdp=fixture.pinned,
    ) == fixture.admitted


def test_standalone_browser_schema_constants_match_the_producer() -> None:
    # The host stays stdlib-only; this test is the intentional cross-boundary import.
    assert admission._BROWSER_EGRESS_FOUNDATION_SCHEMA == browser_producer.FOUNDATION_SCHEMA_VERSION
    assert admission._HISTORICAL_BROWSER_EGRESS_FOUNDATION_SCHEMAS == (
        browser_producer.HISTORICAL_FOUNDATION_SCHEMA_VERSIONS
    )
    assert admission._BROWSER_EGRESS_FINAL_SCHEMA == browser_producer.FINAL_SCHEMA_VERSION
    assert admission._ACQUISITION_SCHEMA == acquisition_producer.SCHEMA_VERSION == 14
    assert admission._V127_ACQUISITION_AUTHORITY_COHORT == (
        attestation_producer._V127_ACQUISITION_AUTHORITY_COHORT_VERSION
    )
    assert admission._V127_ACQUISITION_AUTHORITY_SHA256 == (
        attestation_producer._V127_ACQUISITION_AUTHORITY_SHA256
    )
    assert (
        admission._ACQUISITION_COMPLETION_SCHEMA
        == acquisition_producer.COMPLETION_SCHEMA_VERSION
        == 5
    )
    assert (
        admission._ACQUISITION_CHECKPOINT_SCHEMA
        == acquisition_producer.CHECKPOINT_SCHEMA_VERSION
        == 3
    )
    assert admission._PINNED_CDP_SCHEMA == pinned_cdp_producer.PROBE_SCHEMA_VERSION == 18
    assert {14, 16, 17}.issubset(admission._HISTORICAL_PINNED_CDP_SCHEMAS)


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


@pytest.mark.parametrize("missing", ("build", "pinned_cdp"))
def test_authority_creation_requires_build_and_pinned_cdp(authority_fixture, missing: str) -> None:
    fixture = authority_fixture
    options = dict(build=fixture.build, pinned_cdp=fixture.pinned, browser_egress=fixture.browser)
    del options[missing]
    with pytest.raises(ValueError, match="requires"):
        _resolve(fixture, "acquisition-authority", **options)


def test_v2_authority_admits_acquisition_without_browser_evidence(authority_fixture) -> None:
    fixture = authority_fixture

    def make_v2(payload) -> None:
        payload["attestation_schema_version"] = 2
        payload["evidence"].pop("browser_egress_qualification")

    _rewrite(fixture.authority, make_v2)
    (fixture.browser / "final.json").unlink()
    assert _resolve(
        fixture, "acquisition-init", acquisition_authority=fixture.authority
    ) == fixture.admitted
    _use_authority(fixture)
    assert _resolve(
        fixture, "acquisition-run", acquisition_root=fixture.acquisition
    ) == fixture.admitted


@pytest.mark.parametrize("extra", ("browser_egress_qualification", "unknown"))
def test_v2_authority_rejects_browser_or_unknown_evidence(authority_fixture, extra: str) -> None:
    fixture = authority_fixture

    def make_v2_with_extra(payload) -> None:
        payload["attestation_schema_version"] = 2
        if extra == "unknown":
            payload["evidence"].pop("browser_egress_qualification")
            payload["evidence"]["unknown"] = "unexpected"

    _rewrite(fixture.authority, make_v2_with_extra)
    with pytest.raises(ValueError, match="evidence inventory"):
        _resolve(fixture, "acquisition-init", acquisition_authority=fixture.authority)


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


@pytest.mark.parametrize("schema", (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12))
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


@pytest.mark.parametrize("schema", (9, 10, 11, 12))
def test_historical_completion_is_verify_only_and_cannot_publish_cohort(
    authority_fixture, schema: int,
) -> None:
    fixture = authority_fixture
    _rewrite(
        fixture.acquisition / "provenance.json",
        lambda payload: payload.update(acquisition_schema_version=schema),
    )
    _rewrite(
        fixture.acquisition_completion,
        lambda payload: payload.update(
            acquisition_schema_version=schema,
            provenance_sha256=sha256_file(fixture.acquisition / "provenance.json"),
        ),
    )
    assert _resolve(fixture, "verify", target=fixture.acquisition_completion) is None
    with pytest.raises(admission._HistoricalAuthority, match="historical"):
        _resolve(fixture, "cohort", acquisition_completion=fixture.acquisition_completion)


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
    with pytest.raises((TypeError, ValueError), match="binding|evidence inventory"):
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


def test_exact_v127_authority_is_verify_only_after_study_amendment(
    authority_fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = authority_fixture
    monkeypatch.setattr(admission, "_V127_ACQUISITION_AUTHORITY_COHORT", 62)
    monkeypatch.setattr(
        admission, "_V127_ACQUISITION_AUTHORITY_SHA256", sha256_file(fixture.authority)
    )
    study = fixture.root / "config/class-study/v1/study.json"
    study.write_text("prospective amended study\n", encoding="utf-8")

    assert _resolve(fixture, "verify", target=fixture.authority) is None
    with pytest.raises(admission._HistoricalAuthority, match="verify-only"):
        _resolve(fixture, "acquisition-init", acquisition_authority=fixture.authority)

    _rewrite(fixture.authority, lambda payload: payload.update(no_waivers=False))
    with pytest.raises(ValueError):
        _resolve(fixture, "verify", target=fixture.authority)


def test_v102_pinned_cdp_contract_is_verify_only_and_never_current_admission(
    authority_fixture,
) -> None:
    fixture = authority_fixture
    _rewrite(
        fixture.pinned,
        lambda payload: payload.update(probe_schema_version=17),
    )

    assert _resolve(fixture, "verify", target=fixture.pinned) is None
    with pytest.raises(admission._HistoricalAuthority, match="historical"):
        _resolve(
            fixture,
            "acquisition-authority",
            build=fixture.build,
            pinned_cdp=fixture.pinned,
            browser_egress=fixture.browser,
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
    selected = _parser().parse_args(
        ["--lab-root", "/lab", "--action", "acquisition-init",
         "--study-id", admission._CLASS20_STUDY_ID]
    )
    assert selected.study_id == admission._CLASS20_STUDY_ID


def _class20_fixture(fixture):
    source = Path(__file__).parents[1]
    for relative in (
        "config/class-study/v1/study.json",
        "config/class-study/v1/classifier-multiorigin100-v1-candidates.json",
        "config/class-study/v2/study.json",
    ):
        destination = fixture.root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, destination)
    profile = fixture.root / "config/class-study/v2/study.json"
    base = fixture.root / "config/class-study/v1/study.json"
    catalogue = fixture.root / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"
    payload = json.loads(fixture.authority.read_bytes())["payload"]
    payload["attestation_schema_version"] = 3
    payload["study_id"] = admission._CLASS20_STUDY_ID
    payload["study_contract"] = _binding(profile)
    payload["study_profile_sha256"] = sha256_file(profile)
    payload["study_profile_inputs"] = {
        "base_study": _binding(base),
        "candidate_catalogue": _binding(catalogue),
    }
    payload["evidence"].pop("browser_egress_qualification")
    payload["acquisition_correctness"]["study_contract"] = _binding(profile)
    fixture.authority = _publish(
        fixture.root / "artifacts/classifier-multiorigin20-v1-acquisition-authority-v62.json",
        AUTHORITY, payload,
    )
    v2_root = fixture.root / "artifacts/classifier-multiorigin20-v1-acquisition-v62"
    fixture.acquisition.rename(v2_root)
    fixture.acquisition = v2_root
    fixture.acquisition_completion = v2_root / "completion.json"
    _rewrite(
        v2_root / "provenance.json",
        lambda value: value.update(
            study_id=admission._CLASS20_STUDY_ID,
            study_profile_sha256=sha256_file(profile),
            candidate_catalogue_sha256=sha256_file(catalogue),
            acquisition_authority=_binding(fixture.authority),
        ),
    )
    selection = bind_receipt(
        {"study_id": admission._CLASS20_STUDY_ID, "complete": True},
        receipt_type="qcsd-class-study-acquisition-selection",
    )
    _rewrite(
        fixture.acquisition_completion,
        lambda value: value.update(
            study_id=admission._CLASS20_STUDY_ID,
            candidate_catalogue_sha256=sha256_file(catalogue),
            provenance_sha256=sha256_file(v2_root / "provenance.json"),
            selection=selection,
            operational_censor_summary={},
        ),
    )
    return fixture


def _class20_container_profile_paths(fixture) -> None:
    def use_container_paths(payload) -> None:
        bindings = (
            payload["study_contract"],
            payload["acquisition_correctness"]["study_contract"],
            *payload["study_profile_inputs"].values(),
        )
        for binding in bindings:
            relative = Path(binding["path"]).relative_to(fixture.root)
            binding["path"] = f"/lab/{relative.as_posix()}"

    _rewrite(fixture.authority, use_container_paths)


def test_class20_host_admits_exact_profile_authority_and_current_acquisition(authority_fixture) -> None:
    fixture = _class20_fixture(authority_fixture)
    selected = admission._CLASS20_STUDY_ID
    assert _resolve(
        fixture, "acquisition-authority", study_id=selected,
        build=fixture.build, pinned_cdp=fixture.pinned,
    ) == fixture.admitted
    assert _resolve(
        fixture, "acquisition-init", study_id=selected,
        acquisition_authority=fixture.authority,
    ) == fixture.admitted
    assert _resolve(
        fixture, "acquisition-run", study_id=selected,
        acquisition_root=fixture.acquisition,
    ) == fixture.admitted
    assert _resolve(
        fixture, "cohort", study_id=selected,
        acquisition_completion=fixture.acquisition_completion,
    ) == fixture.admitted


def test_class20_host_admits_container_profile_paths_across_acquisition_actions(
    authority_fixture,
) -> None:
    fixture = _class20_fixture(authority_fixture)
    _class20_container_profile_paths(fixture)
    selected = admission._CLASS20_STUDY_ID
    assert _resolve(
        fixture, "verify", study_id=selected, target=fixture.authority,
    ) == fixture.admitted
    assert _resolve(
        fixture, "acquisition-init", study_id=selected,
        acquisition_authority=fixture.authority,
    ) == fixture.admitted
    _use_authority(fixture)
    assert _resolve(
        fixture, "acquisition-run", study_id=selected,
        acquisition_root=fixture.acquisition,
    ) == fixture.admitted


@pytest.mark.parametrize("tampering", ("same_bytes_wrong_path", "wrong_sha256"))
def test_class20_host_rejects_tampered_container_profile_binding(
    authority_fixture, tampering: str,
) -> None:
    fixture = _class20_fixture(authority_fixture)
    _class20_container_profile_paths(fixture)
    if tampering == "same_bytes_wrong_path":
        duplicate = fixture.root / "config/class-study/v1/study-copy.json"
        shutil.copyfile(fixture.root / "config/class-study/v1/study.json", duplicate)
        _rewrite(
            fixture.authority,
            lambda payload: payload["study_profile_inputs"]["base_study"].update(
                path="/lab/config/class-study/v1/study-copy.json"
            ),
        )
    else:
        _rewrite(
            fixture.authority,
            lambda payload: payload["study_profile_inputs"]["base_study"].update(
                sha256="e" * 64
            ),
        )
    with pytest.raises(ValueError, match="profile inputs differ"):
        _resolve(
            fixture, "acquisition-init", study_id=admission._CLASS20_STUDY_ID,
            acquisition_authority=fixture.authority,
        )


def test_class20_host_rejects_changed_prefix_scope_even_with_matching_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = Path(__file__).resolve().parents[1]
    for relative in (
        "config/class-study/v2/study.json",
        "config/class-study/v1/study.json",
        "config/class-study/v1/classifier-multiorigin100-v1-candidates.json",
    ):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_root / relative, destination)
    profile_path = tmp_path / "config/class-study/v2/study.json"
    profile = json.loads(profile_path.read_bytes())
    profile["walkie_talkie_prefix_qualification"]["qualification_scope"] = "whole-page-capacity"
    profile_path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    monkeypatch.setattr(admission, "_CLASS20_OVERLAY_SHA256", sha256_file(profile_path))
    with pytest.raises(ValueError, match="overlay contract is invalid"):
        admission._class20_profile_bindings(tmp_path)


def test_class20_host_rejects_mixed_authority_or_completion(authority_fixture) -> None:
    fixture = _class20_fixture(authority_fixture)
    with pytest.raises(ValueError, match="another study profile"):
        _resolve(fixture, "acquisition-init", acquisition_authority=fixture.authority)
    with pytest.raises(ValueError, match="profile-specific authority"):
        _resolve(fixture, "acquisition-init", study_id=admission._CLASS20_STUDY_ID,
                 foundation=fixture.foundation)
    with pytest.raises(ValueError, match="another study profile"):
        _resolve(fixture, "cohort", acquisition_completion=fixture.acquisition_completion)


@pytest.mark.parametrize("field", ("study_profile_sha256", "candidate_catalogue_sha256"))
def test_class20_host_rejects_profile_or_catalogue_drift(authority_fixture, field: str) -> None:
    fixture = _class20_fixture(authority_fixture)
    if field == "study_profile_sha256":
        _rewrite(fixture.authority, lambda value: value.update({field: "0" * 64}))
        with pytest.raises(ValueError, match="profile inputs"):
            _resolve(fixture, "acquisition-init", study_id=admission._CLASS20_STUDY_ID,
                     acquisition_authority=fixture.authority)
    else:
        _rewrite(fixture.acquisition_completion, lambda value: value.update({field: "0" * 64}))
        with pytest.raises(ValueError, match="catalogue differs"):
            _resolve(fixture, "cohort", study_id=admission._CLASS20_STUDY_ID,
                     acquisition_completion=fixture.acquisition_completion)


def test_class20_host_rejects_mixed_100_site_cohort_carrier(authority_fixture) -> None:
    fixture = _class20_fixture(authority_fixture)
    mixed = _publish(
        fixture.root / "config/class-study/v2/mixed-cohort-assembly.json",
        "qcsd-class-study-cohort-assembly",
        {"study_id": admission._BASE_STUDY_ID},
    )
    with pytest.raises(ValueError, match="100-site study"):
        _resolve(fixture, "campaigns", study_id=admission._CLASS20_STUDY_ID,
                 acquisition_completion=fixture.acquisition_completion,
                 final_cohort_assembly=mixed)


def _class20_pilot_cohort_pair(fixture) -> tuple[Path, Path]:
    study_id = admission._CLASS20_STUDY_ID
    root = fixture.root / "config/class-study/v2"
    profile = root / "study.json"
    catalogue = fixture.root / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"
    candidate_ids = [f"candidate-{index:04d}" for index in range(600)]
    cohort = _publish(
        root / f"{study_id}-pilot-cohort.json",
        admission._CLASS20_COHORT,
        {
            "study_id": study_id,
            "cohort_schema_version": 1,
            "profile_sha256": sha256_file(profile),
            "stage": "pilot",
            "candidates": [{"candidate_id": item} for item in candidate_ids],
            "pilot_ids": candidate_ids[:30],
            "final_ids": [],
            "reserve_ids": [],
        },
    )
    completion = json.loads(fixture.acquisition_completion.read_bytes())
    catalogue_envelope = json.loads(catalogue.read_bytes())
    cohort_envelope = json.loads(cohort.read_bytes())
    assembly = _publish(
        root / f"{study_id}-pilot-cohort-assembly.json",
        admission._CLASS20_COHORT_ASSEMBLY,
        {
            "study_id": study_id,
            "assembly_schema_version": 1,
            "profile": {"path": admission._CLASS20_OVERLAY, "sha256": sha256_file(profile)},
            "candidate_catalogue": {
                "path": admission._BASE_CATALOGUE,
                "sha256": sha256_file(catalogue),
                "payload_sha256": catalogue_envelope["payload_sha256"],
            },
            "acquisition_completion": {
                "path": fixture.acquisition_completion.relative_to(fixture.root).as_posix(),
                "sha256": sha256_file(fixture.acquisition_completion),
                "payload_sha256": completion["payload_sha256"],
                "provenance_sha256": completion["payload"]["provenance_sha256"],
                "selection_payload_sha256": completion["payload"]["selection"]["payload_sha256"],
            },
            "selected_evidence_count": 30,
            "cohort": {
                "receipt_type": admission._CLASS20_COHORT,
                "payload_sha256": cohort_envelope["payload_sha256"],
                "canonical_file_sha256": sha256_file(cohort),
            },
        },
    )
    return cohort, assembly


def test_class20_host_admits_exact_30_site_pilot_cohort_before_campaigns(authority_fixture) -> None:
    fixture = _class20_fixture(authority_fixture)
    _cohort, assembly = _class20_pilot_cohort_pair(fixture)
    assert _resolve(
        fixture, "campaigns", study_id=admission._CLASS20_STUDY_ID,
        acquisition_completion=fixture.acquisition_completion,
        final_cohort_assembly=assembly,
    ) == fixture.admitted


def test_class20_host_rejects_100_site_count_in_20_site_cohort(authority_fixture) -> None:
    fixture = _class20_fixture(authority_fixture)
    cohort, assembly = _class20_pilot_cohort_pair(fixture)
    _rewrite(
        cohort,
        lambda value: value.update(pilot_ids=[f"candidate-{index:04d}" for index in range(120)]),
    )
    with pytest.raises(ValueError, match="20-site profile, cohort, or counts differ"):
        _resolve(
            fixture, "campaigns", study_id=admission._CLASS20_STUDY_ID,
            acquisition_completion=fixture.acquisition_completion,
            final_cohort_assembly=assembly,
        )


def test_class20_host_rejects_mixed_pilot_campaign_count_before_capture(authority_fixture) -> None:
    fixture = _class20_fixture(authority_fixture)
    _cohort, assembly = _class20_pilot_cohort_pair(fixture)
    study_id = admission._CLASS20_STUDY_ID
    root = fixture.root / f"config/{study_id}-campaigns"
    root.mkdir(parents=True)
    name = f"{study_id}-pilot-fitting-120-1200"
    campaign = root / f"{name}.yml"
    def write_campaign(count: int) -> None:
        workload_lines = "\n".join(
            f"  candidate-{index:04d}: {{}}" for index in range(count)
        )
        campaign.write_text(
            f"name: {name}\n"
            "evidence_role: pilot-fitting\n"
            f"class_study_cohort_assembly: ../class-study/v2/{assembly.name}\n"
            f"workloads:\n{workload_lines}\n",
            encoding="utf-8",
        )
    write_campaign(30)
    resolver = admission._Resolver(fixture.root, study_id=study_id, build_loader=fixture.load)
    assert admission._campaign_authorities(resolver, campaign) == (
        "pilot-fitting", [fixture.admitted]
    )
    write_campaign(120)
    with pytest.raises(ValueError, match="workload count differs"):
        admission._campaign_authorities(resolver, campaign)


def test_class20_host_rejects_forged_pilot_compatibility_campaign(authority_fixture) -> None:
    fixture = _class20_fixture(authority_fixture)
    _cohort, assembly = _class20_pilot_cohort_pair(fixture)
    study_id = admission._CLASS20_STUDY_ID
    root = fixture.root / f"config/{study_id}-campaigns"
    root.mkdir(parents=True)
    name = f"{study_id}-pilot-compatibility-270-1200"
    campaign = root / f"{name}.yml"
    workload_lines = "\n".join(
        f"  candidate-{index:04d}: {{}}" for index in range(30)
    )
    campaign.write_text(
        f"name: {name}\n"
        "evidence_role: pilot-compatibility\n"
        f"class_study_cohort_assembly: ../class-study/v2/{assembly.name}\n"
        f"workloads:\n{workload_lines}\n",
        encoding="utf-8",
    )
    resolver = admission._Resolver(fixture.root, study_id=study_id, build_loader=fixture.load)
    with pytest.raises(ValueError, match="campaign name is not canonical"):
        admission._campaign_authorities(resolver, campaign)
