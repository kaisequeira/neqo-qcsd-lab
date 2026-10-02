from __future__ import annotations

import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qcsd_lab import browser_egress, rapid_browser_policy_evidence as evidence
from qcsd_lab import rapid_page_evidence as page, rapid_study_profile as rapid
from qcsd_lab.acquisition_errors import NonReplayableEgressPolicyError, RecoverableAcquisitionError
from qcsd_lab.class_acquisition import ExistingAcquisitionBackend, NavigationDiscovery

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "config/curated-sources/crux73-tranco600-rapid-v5.profile.json"
SOURCE = ROOT / "config/curated-sources/crux-73-v1.raw.json"
CATALOGUE = ROOT / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _guard_failure() -> NonReplayableEgressPolicyError:
    guard = browser_egress.NonReplayableEgressGuard()
    guard.mark_context_guards_installed()
    guard.bind_root_page(object())
    guard.record(api="WebSocket", mechanism="playwright-websocket-route", url="wss://onweeralarm.nl")
    try:
        guard.raise_if_failed()
    except NonReplayableEgressPolicyError as error:
        return error
    raise AssertionError("real guard did not reject the non-replayable request")


@pytest.fixture
def context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    source_manifest = {
        "image_digest": None, "lab_commit": "1" * 40, "lab_dirty": False,
        "lab_patch_sha256": _sha(b""), "neqo_commit": "2" * 40, "neqo_dirty": False,
        "neqo_patch_sha256": _sha(b""), "neqo_pinned_commit": "2" * 40,
    }
    runtime = tmp_path / "source.json"
    runtime.write_text(json.dumps(source_manifest))
    binding = {"source_manifest_sha256": _sha(runtime.read_bytes()),
               "admission_image_digest": "sha256:" + "d" * 64}
    monkeypatch.setenv("QCSD_LAB_SOURCE_METADATA", str(runtime))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", binding["admission_image_digest"])
    profile, source, catalogue = json.loads(PROFILE.read_bytes()), SOURCE.read_bytes(), CATALOGUE.read_bytes()
    candidate = rapid.validate_v5_profile_receipt(profile, source, catalogue)[1]
    error = _guard_failure()
    calls = []

    def navigation(domain):
        calls.append(domain)
        raise error

    kwargs = {
        "profile": PROFILE, "source": SOURCE, "catalogue": CATALOGUE,
        "candidate_id": candidate["candidate_id"], "execution_binding": binding,
        "policy_amendment_sha256": "e" * 64,
        "expected_implementation_hashes": evidence.implementation_hashes(),
        "not_before_utc": datetime.now(UTC) - timedelta(seconds=1),
    }
    verify = {key: value for key, value in kwargs.items() if key not in {"profile", "source", "catalogue"}}
    verify.update(profile_receipt=profile, source_bytes=source, catalogue_bytes=catalogue)
    return {"kwargs": kwargs, "verify": verify, "candidate": candidate, "runtime": runtime,
            "calls": calls, "error": error, "backend": ExistingAcquisitionBackend(navigation=navigation)}


def _produce(context: dict, path: Path) -> dict:
    return evidence.produce_navigation_policy_observation(
        output=path, backend=context["backend"], **context["kwargs"]
    )


def _rewrite(path: Path, receipt: dict) -> None:
    receipt["payload_sha256"] = _sha(page._json(receipt["payload"]))
    path.write_bytes(page._json(receipt))


def test_retains_real_guard_failure_once_without_success_credit(context: dict, tmp_path: Path) -> None:
    path = tmp_path / "policy-failure.json"
    receipt = _produce(context, path)
    facts = evidence.verify_browser_policy_failure(path, **context["verify"])
    assert context["calls"] == [context["candidate"]["domain"]]
    assert receipt["receipt_type"] == evidence.BROWSER_POLICY_FAILURE_RECEIPT_TYPE
    assert facts["raw_failure"]["evidence"] == context["error"].evidence
    assert facts["raw_failure"]["evidence"]["non_replayable_egress"]["attempt_count"] == 1
    assert facts["browser_policy_failure_receipt_sha256"] == _sha(path.read_bytes())
    assert facts["action"] == {
        "kind": "catalogue-boundary-navigation", "url": f"https://{context['candidate']['domain']}/",
        "scope": evidence.ACTION_SCOPE, "selected_page_ordinal": None,
    }
    assert facts["failure_page_attribution"] == "unavailable"
    assert facts["scientific_credit"] is False
    assert evidence.validate_browser_policy_failure_facts(
        facts, candidate=context["candidate"], execution_binding=context["kwargs"]["execution_binding"],
        policy_amendment_sha256=context["kwargs"]["policy_amendment_sha256"],
        not_before_utc=context["kwargs"]["not_before_utc"],
    ) == facts


def test_success_uses_ordinary_navigation_receipt_without_second_navigation(
    context: dict, tmp_path: Path,
) -> None:
    domain = context["candidate"]["domain"]

    def navigation(observed):
        context["calls"].append(observed)
        return NavigationDiscovery(domain, (), (f"https://{domain}",), (), ())

    path = tmp_path / "navigation.json"
    receipt = evidence.produce_navigation_policy_observation(
        output=path, backend=ExistingAcquisitionBackend(navigation=navigation), **context["kwargs"]
    )
    assert context["calls"] == [domain]
    assert receipt["receipt_type"] == page.NAVIGATION_RECEIPT_TYPE
    kwargs = dict(context["verify"])
    kwargs.pop("policy_amendment_sha256")
    kwargs["expected_implementation_hashes"] = page.implementation_hashes()
    assert page.verify_navigation_receipt(path, **kwargs)["pages"][0].url == f"https://{domain}/"
    with pytest.raises(ValueError, match="envelope"):
        evidence.verify_browser_policy_failure(path, **context["verify"])


def test_destination_is_create_only_before_browser_work(context: dict, tmp_path: Path) -> None:
    path = tmp_path / "failure.json"
    _produce(context, path)
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        _produce(context, path)
    assert path.read_bytes() == original
    assert len(context["calls"]) == 1


@pytest.mark.parametrize("error", [RuntimeError("infrastructure failure"),
                                  RecoverableAcquisitionError("temporary browser failure"),
                                  ValueError("unrelated policy error")])
def test_other_errors_are_operational_and_create_no_receipt(
    context: dict, tmp_path: Path, error: Exception,
) -> None:
    def navigation(_):
        raise error

    path = tmp_path / "absent.json"
    with pytest.raises(type(error), match=str(error)):
        evidence.produce_navigation_policy_observation(
            output=path, backend=ExistingAcquisitionBackend(navigation=navigation), **context["kwargs"]
        )
    assert not path.exists()


def test_typed_subclass_is_not_promoted(context: dict, tmp_path: Path) -> None:
    class DifferentPolicyError(NonReplayableEgressPolicyError):
        pass

    def navigation(_):
        raise DifferentPolicyError("subclass", evidence=context["error"].evidence)

    path = tmp_path / "absent.json"
    with pytest.raises(DifferentPolicyError):
        evidence.produce_navigation_policy_observation(
            output=path, backend=ExistingAcquisitionBackend(navigation=navigation), **context["kwargs"]
        )
    assert not path.exists()


@pytest.mark.parametrize("changed", ["module", "future-barrier", "dirty-runtime", "runtime-image"])
def test_prework_bindings_prevent_browser_work(
    context: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed: str,
) -> None:
    if changed == "module":
        context["kwargs"]["expected_implementation_hashes"]["qcsd_lab.browser_egress"] = "a" * 64
    elif changed == "future-barrier":
        context["kwargs"]["not_before_utc"] = datetime.now(UTC) + timedelta(days=1)
    elif changed == "runtime-image":
        monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "a" * 64)
    else:
        runtime = json.loads(context["runtime"].read_bytes())
        runtime["lab_dirty"] = True
        context["runtime"].write_text(json.dumps(runtime))
        context["kwargs"]["execution_binding"]["source_manifest_sha256"] = _sha(context["runtime"].read_bytes())
    path = tmp_path / "absent.json"
    with pytest.raises(ValueError):
        _produce(context, path)
    assert context["calls"] == []
    assert not path.exists()


@pytest.mark.parametrize("changed", [
    "candidate", "candidate-count-type", "amendment", "implementation", "action", "page-attribution", "exception-type",
    "runtime", "stale", "future", "credit", "raw-hash", "raw-guard-semantics", "raw-bool-count",
])
def test_rehashed_substitutions_do_not_verify(context: dict, tmp_path: Path, changed: str) -> None:
    path = tmp_path / "failure.json"
    receipt = _produce(context, path)
    payload = receipt["payload"]
    if changed == "candidate":
        payload["candidate"]["domain"] = "different.example"
    elif changed == "candidate-count-type":
        payload["candidate"]["listed_resource_group_count"] = float(
            payload["candidate"]["listed_resource_group_count"]
        )
    elif changed == "amendment":
        payload["policy_amendment_sha256"] = "a" * 64
    elif changed == "implementation":
        payload["implementation_hashes"]["qcsd_lab.browser_egress"] = "a" * 64
    elif changed == "action":
        payload["action"]["url"] += "optional-page"
    elif changed == "page-attribution":
        payload["failure_page_attribution"] = "root"
    elif changed == "exception-type":
        payload["raw_failure"]["exception_type"] = "RuntimeError"
    elif changed == "runtime":
        payload["runtime"]["source_manifest_text"] += "\n"
    elif changed == "stale":
        payload["started_at"] = "2026-01-01T00:00:00Z"
    elif changed == "future":
        payload["completed_at"] = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    elif changed == "credit":
        payload["scientific_credit"] = True
    else:
        raw = payload["raw_failure"]["evidence"]
        if changed == "raw-hash":
            raw["non_replayable_egress_sha256"] = "a" * 64
        else:
            guard = raw["non_replayable_egress"]
            if changed == "raw-guard-semantics":
                guard["attempts"][0]["url"]["scheme"] = "https"
                guard["attempts"][0]["url"]["origin"] = "https://onweeralarm.nl"
            else:
                guard["attempt_count"] = True
            raw["non_replayable_egress_sha256"] = _sha(browser_egress._canonical_json_bytes(guard))
    _rewrite(path, receipt)
    with pytest.raises(ValueError):
        evidence.verify_browser_policy_failure(path, **context["verify"])


def test_invalid_typed_evidence_is_not_retained(context: dict, tmp_path: Path) -> None:
    context["error"].evidence["non_replayable_egress"]["attempt_count"] = 0
    path = tmp_path / "absent.json"
    with pytest.raises(ValueError):
        _produce(context, path)
    assert not path.exists()


def test_runtime_changed_during_failure_is_operational(
    context: dict, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def navigation(_):
        monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "a" * 64)
        raise context["error"]

    path = tmp_path / "absent.json"
    with pytest.raises(ValueError, match="runtime image"):
        evidence.produce_navigation_policy_observation(
            output=path, backend=ExistingAcquisitionBackend(navigation=navigation), **context["kwargs"]
        )
    assert not path.exists()


def test_historical_diagnostic_type_cannot_gain_amendment_credit(context: dict, tmp_path: Path) -> None:
    path = tmp_path / "failure.json"
    receipt = _produce(context, path)
    receipt["receipt_type"] = "qcsd-non-evidentiary-browser-egress-diagnostic"
    _rewrite(path, receipt)
    with pytest.raises(ValueError, match="envelope"):
        evidence.verify_browser_policy_failure(path, **context["verify"])


@pytest.mark.parametrize("changed", ["dirty-source", "unknown-module", "page-credit", "amendment"])
def test_callback_facts_still_require_structural_and_raw_guard_checks(
    context: dict, tmp_path: Path, changed: str,
) -> None:
    path = tmp_path / "failure.json"
    _produce(context, path)
    facts = copy.deepcopy(evidence.verify_browser_policy_failure(path, **context["verify"]))
    if changed == "dirty-source":
        facts["runtime_source"]["lab_dirty"] = True
    elif changed == "unknown-module":
        facts["implementation_hashes"]["unknown-module"] = "a" * 64
    elif changed == "page-credit":
        facts["action"]["selected_page_ordinal"] = 0
    else:
        facts["policy_amendment_sha256"] = "a" * 64
    with pytest.raises(ValueError):
        evidence.validate_browser_policy_failure_facts(
            facts, candidate=context["candidate"],
            execution_binding=context["kwargs"]["execution_binding"],
            policy_amendment_sha256=context["kwargs"]["policy_amendment_sha256"],
            not_before_utc=context["kwargs"]["not_before_utc"],
        )
