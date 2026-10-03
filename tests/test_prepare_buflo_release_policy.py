from copy import deepcopy
import hashlib
import json

import pytest

from qcsd_lab import class_acquisition, prepare
from qcsd_lab.application_response_policy import (
    COMPLETED_TERMINAL_HTTP_ERRORS_POLICY as RESPONSE_POLICY,
    VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY as PRIMARY_POLICY,
    validate_application_responses,
)
from qcsd_lab.capture_acceptance_policy import FIELD, POLICY
from qcsd_lab.manifest import validate_manifest
from tests.test_prepare import install_fake_preparation
from tests.test_prepare_primary_document_identity import install_variable_preparation


def prepare_variable(root, *, policy=POLICY):
    return prepare.prepare_workload(
        "buflo-release-page", "https://page.test/", ["https://page.test", "https://cdn.test"],
        output_root=root, stability_interval_seconds=0, require_complete_coverage=True,
        application_response_policy=RESPONSE_POLICY,
        primary_document_identity_policy=PRIMARY_POLICY,
        buflo_incoming_credit_release_policy=policy,
    )


def class_validation_fixture(manifest):
    # Existing preparation fixtures use short placeholder provenance. Class
    # validation independently requires concrete research provenance fields.
    candidate = deepcopy(manifest)
    preparation = candidate["preparation"]
    image = "sha256:" + "1" * 64
    preparation["prepare_image_digest"] = image
    preparation["neqo_base_commit"] = "4" * 40
    preparation["published_qcsd_commit"] = "5" * 40
    preparation["lab_source"] = {
        "image_digest": image, "lab_commit": "2" * 40, "lab_dirty": False,
        "lab_patch_sha256": hashlib.sha256(b"").hexdigest(), "neqo_commit": "3" * 40,
        "neqo_pinned_commit": "3" * 40, "neqo_dirty": False,
        "neqo_patch_sha256": hashlib.sha256(b"").hexdigest(),
    }
    if "application_response_policy_evidence" in preparation:
        provenance = preparation["application_response_policy_evidence"]["client_provenance"]
        for key in ("neqo_base_commit", "published_qcsd_commit"):
            provenance[key] = preparation[key]
    return candidate


@pytest.mark.parametrize("negative", [False, True])
def test_opted_preparation_seals_policy_with_complete_graph_and_unchanged_raw_proof(
    tmp_path, monkeypatch, negative,
):
    commands = install_variable_preparation(monkeypatch, negative=negative)
    real_write = prepare.write_frozen_manifest
    at_seal = []

    def seal(path, manifest, **options):
        # The policy is part of the first exclusive publication, not added later.
        assert not path.exists()
        assert manifest["preparation"][FIELD] == POLICY
        at_seal.append(deepcopy(manifest))
        return real_write(path, manifest, **options)

    monkeypatch.setattr(prepare, "write_frozen_manifest", seal)
    result = prepare_variable(tmp_path)
    raw = result.path.read_bytes()
    manifest = json.loads(raw)
    validate_manifest(manifest)
    assert at_seal == [manifest]
    assert result.sha256 == hashlib.sha256(raw).hexdigest()
    assert [resource["id"] for resource in manifest["resources"]] == [0, 1]
    assert manifest["preparation"]["coverage_admission"]["required_resources"] == [
        {"id": resource["id"], "url": resource["url"]} for resource in manifest["resources"]
    ]
    retained = result.application_response_evidence_path
    inventory = json.loads((retained / "inventory.json").read_bytes())
    assert inventory["schema_version"] == 2
    assert FIELD not in inventory
    assert inventory["scientific_credit"] is False
    for index in range(3):
        relative = f"stability-{index}/run.json"
        actual = (retained / "artifacts" / relative).read_bytes()
        assert inventory["files"][relative]["sha256"] == hashlib.sha256(actual).hexdigest()
        validate_application_responses(manifest, json.loads(actual))
    assert [command[1] for command in commands] == ["probe", "run", "run", "run"]
    class_acquisition.validate_class_study_preparation(
        class_validation_fixture(manifest), workload_id="buflo-release-page", application_response_policy=RESPONSE_POLICY,
        primary_document_identity_policy=PRIMARY_POLICY, buflo_incoming_credit_release_policy=POLICY,
    )


@pytest.mark.parametrize("policy", [None, "omitted"])
def test_default_preparation_keeps_policy_absent(tmp_path, monkeypatch, policy):
    install_fake_preparation(monkeypatch)
    kwargs = {} if policy == "omitted" else {FIELD: None}
    result = prepare.prepare_workload(
        "legacy-release-page", "https://page.test/", ["https://page.test", "https://cdn.test"],
        output_root=tmp_path, stability_interval_seconds=0, require_complete_coverage=True, **kwargs,
    )
    manifest = json.loads(result.path.read_bytes())
    assert FIELD not in manifest["preparation"]
    assert result.application_response_evidence_path is None
    class_acquisition.validate_class_study_preparation(class_validation_fixture(manifest), workload_id="legacy-release-page")


@pytest.mark.parametrize("policy", [False, 10000, {}, "unknown"])
def test_prepare_rejects_malformed_policy_before_discovery(tmp_path, monkeypatch, policy):
    monkeypatch.setattr(prepare, "discover_page", lambda *_a, **_k: pytest.fail("unexpected discovery"))
    with pytest.raises(ValueError, match="release policy"):
        prepare_variable(tmp_path, policy=policy)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("change", ["coverage", "response-policy", "primary-policy"])
def test_prepare_rejects_unbound_opt_in_before_discovery(tmp_path, monkeypatch, change):
    monkeypatch.setattr(prepare, "discover_page", lambda *_a, **_k: pytest.fail("unexpected discovery"))
    kwargs = {"require_complete_coverage": True, "application_response_policy": RESPONSE_POLICY,
              "primary_document_identity_policy": PRIMARY_POLICY, FIELD: POLICY}
    if change == "coverage":
        kwargs["require_complete_coverage"] = False
    elif change == "response-policy":
        kwargs["application_response_policy"] = None
    else:
        kwargs["primary_document_identity_policy"] = None
    with pytest.raises(ValueError, match="release policy"):
        prepare.prepare_workload("unbound", "https://page.test/", ["https://page.test"],
                                 output_root=tmp_path, **kwargs)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("change", ["unregistered", "missing", "null", "wrong", "coverage"])
def test_class_preparation_requires_exact_registered_policy(tmp_path, monkeypatch, change):
    install_variable_preparation(monkeypatch)
    manifest = class_validation_fixture(json.loads(prepare_variable(tmp_path).path.read_bytes()))
    expected = POLICY
    if change == "unregistered":
        expected = None
    elif change == "missing":
        manifest["preparation"].pop(FIELD)
    elif change == "null":
        manifest["preparation"][FIELD] = None
    elif change == "wrong":
        manifest["preparation"][FIELD] = "unknown"
    else:
        manifest["preparation"].pop("coverage_admission")
    with pytest.raises(ValueError):
        class_acquisition.validate_class_study_preparation(
            manifest, workload_id="buflo-release-page", application_response_policy=RESPONSE_POLICY,
            primary_document_identity_policy=PRIMARY_POLICY, buflo_incoming_credit_release_policy=expected,
        )


@pytest.mark.parametrize("declared", [None, POLICY])
def test_legacy_class_authority_rejects_any_declared_field(tmp_path, monkeypatch, declared):
    install_fake_preparation(monkeypatch)
    result = prepare.prepare_workload(
        "legacy-class", "https://page.test/", ["https://page.test", "https://cdn.test"],
        output_root=tmp_path, stability_interval_seconds=0, require_complete_coverage=True,
    )
    manifest = json.loads(result.path.read_bytes())
    manifest["preparation"][FIELD] = declared
    with pytest.raises(ValueError, match="differs from its authority"):
        class_acquisition.validate_class_study_preparation(manifest, workload_id="legacy-class")


@pytest.mark.parametrize("policy", [None, POLICY])
def test_existing_backend_forwards_only_explicit_registered_policy(tmp_path, monkeypatch, policy):
    class ReachedPreparation(Exception):
        pass

    captured = []

    def actual_prepare(*_args, **kwargs):
        captured.append(kwargs)
        raise ReachedPreparation

    monkeypatch.setattr(class_acquisition, "prepare_workload", actual_prepare)
    kwargs = {} if policy is None else {
        "application_response_policy": RESPONSE_POLICY,
        "primary_document_identity_policy": PRIMARY_POLICY, FIELD: policy,
    }
    with pytest.raises(ReachedPreparation):
        class_acquisition.ExistingAcquisitionBackend().prepare(
            "backend-page", "https://page.test/", ["https://page.test"], tmp_path / "output",
            origin_ip_pins={"https://page.test": "8.8.8.8"}, **kwargs,
        )
    [arguments] = captured
    assert (arguments.get(FIELD) == POLICY) is (policy == POLICY)
    assert (FIELD in arguments) is (policy is not None)
    assert arguments["require_complete_coverage"] is True
    assert arguments["stability_runs"] == 3


@pytest.mark.parametrize("policy", [False, "unknown"])
def test_existing_backend_rejects_policy_before_dns_or_output(tmp_path, monkeypatch, policy):
    monkeypatch.setattr(class_acquisition, "public_origin_ip_pins",
                        lambda *_a: pytest.fail("unexpected DNS request"))
    with pytest.raises(ValueError, match="release policy"):
        class_acquisition.ExistingAcquisitionBackend().prepare(
            "backend-page", "https://page.test/", ["https://page.test"], tmp_path / "output",
            application_response_policy=RESPONSE_POLICY,
            primary_document_identity_policy=PRIMARY_POLICY, buflo_incoming_credit_release_policy=policy,
        )
    assert not list(tmp_path.iterdir())
