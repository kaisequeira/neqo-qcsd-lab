from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qcsd_lab import rapid_page_evidence as evidence
from qcsd_lab import rapid_study_profile as rapid
from qcsd_lab.class_acquisition import ExistingAcquisitionBackend, NavigationDiscovery
from qcsd_lab.class_catalogue import DiscoveredLink

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "config/curated-sources/crux73-tranco600-rapid-v5.profile.json"
SOURCE = ROOT / "config/curated-sources/crux-73-v1.raw.json"
CATALOGUE = ROOT / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    image = "sha256:" + "d" * 64
    runtime = {
        "image_digest": None, "lab_commit": "1" * 40, "lab_dirty": False,
        "lab_patch_sha256": _sha(b""), "neqo_commit": "2" * 40,
        "neqo_dirty": False, "neqo_patch_sha256": _sha(b""),
        "neqo_pinned_commit": "2" * 40,
    }
    runtime_path = tmp_path / "runtime.json"
    runtime_path.write_text(json.dumps(runtime))
    client = tmp_path / "neqo-client"
    client.write_bytes(b"test exact executable bytes")
    monkeypatch.setenv("QCSD_LAB_SOURCE_METADATA", str(runtime_path))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", image)
    monkeypatch.setenv("QCSD_NEQO_CLIENT", str(client))
    profile = json.loads(PROFILE.read_bytes())
    source, catalogue = SOURCE.read_bytes(), CATALOGUE.read_bytes()
    candidate = rapid.validate_v5_profile_receipt(profile, source, catalogue)[1]
    domain = candidate["domain"]
    nav = NavigationDiscovery(
        domain,
        tuple(DiscoveredLink(f"https://{domain}/{name}", "text/html") for name in (
            "zeta", "alpha", "beta", "gamma", "delta", "epsilon"
        )) + (
            DiscoveredLink("https://outside.example/page", "text/html"),
            DiscoveredLink(f"https://{domain}/data.json", "application/json"),
        ),
        (f"https://{domain}",), (), ((f"https://{domain}/", (f"https://{domain}",)),),
    )
    return {
        "candidate": candidate, "profile": profile, "source": source,
        "catalogue": catalogue, "binding": {
            "source_manifest_sha256": _sha(runtime_path.read_bytes()),
            "admission_image_digest": image,
        },
        "backend": ExistingAcquisitionBackend(navigation=lambda _: nav),
        "barrier": datetime.now(UTC) - timedelta(seconds=1),
        "runtime_path": runtime_path,
    }


def _navigation(context: dict, output: Path) -> tuple[dict, dict]:
    receipt = evidence.produce_navigation_receipt(
        output=output, profile=PROFILE, source=SOURCE, catalogue=CATALOGUE,
        candidate_id=context["candidate"]["candidate_id"],
        execution_binding=context["binding"], backend=context["backend"],
    )
    args = {
        "profile_receipt": context["profile"], "source_bytes": context["source"],
        "catalogue_bytes": context["catalogue"],
        "candidate_id": context["candidate"]["candidate_id"],
        "execution_binding": context["binding"],
        "expected_implementation_hashes": evidence.implementation_hashes(),
        "not_before_utc": context["barrier"],
    }
    return receipt, args


def _probe(url: str, known_valid: bool = True) -> dict:
    output = json.dumps({"resources": [{
        "id": 0, "url": url, "type": "Unknown", "content_length": 42,
        "data_length": 42, "chaff_priority": False, "known_valid": known_valid,
        "depends_on": [], "headers": [],
    }]})
    return {
        "url": url, "started_at": datetime.now(UTC).isoformat(),
        "completed_at": datetime.now(UTC).isoformat(), "resolver_addresses": ["8.8.8.8"],
        "resolver_error": None, "exit_code": 0, "stdout_sha256": _sha(b""),
        "stdout_excerpt": "", "output_sha256": _sha(output.encode()),
        "output_text": output, "known_valid": known_valid,
        "outcome": "known-valid" if known_valid else "ambiguous",
    }


def _page(context: dict, tmp_path: Path, *, probe=_probe) -> tuple[Path, dict, dict]:
    nav = tmp_path / "nav.json"
    _, nav_args = _navigation(context, nav)
    output = tmp_path / "page.json"
    receipt = evidence.produce_selected_page_h3_receipt(
        output=output, navigation_receipt=nav, selected_page_ordinal=1,
        profile=PROFILE, source=SOURCE, catalogue=CATALOGUE,
        candidate_id=context["candidate"]["candidate_id"],
        execution_binding=context["binding"],
        expected_navigation_implementation_hashes=nav_args["expected_implementation_hashes"],
        not_before_utc=context["barrier"], probe=probe,
    )
    args = {
        **nav_args, "navigation_receipt": nav,
        "expected_navigation_implementation_hashes": nav_args["expected_implementation_hashes"],
        "expected_implementation_hashes": evidence.implementation_hashes("page-h3"),
    }
    return output, receipt, args


def _rewrite(path: Path, receipt: dict) -> None:
    receipt["payload_sha256"] = _sha(evidence._json(receipt["payload"]))
    path.write_bytes(evidence._json(receipt))


def test_navigation_derives_bounded_deterministic_pages(context: dict, tmp_path: Path) -> None:
    path = tmp_path / "navigation.json"
    _, args = _navigation(context, path)
    facts = evidence.verify_navigation_receipt(path, **args)
    assert len(facts["pages"]) == 5
    assert [page.ordinal for page in facts["pages"]] == list(range(5))
    assert facts["pages"][0].url == f"https://{context['candidate']['domain']}/"
    assert facts["navigation_receipt_sha256"] == _sha(path.read_bytes())


def test_navigation_is_create_only_before_browser_work(context: dict, tmp_path: Path) -> None:
    output = tmp_path / "nav.json"
    _navigation(context, output)
    original = output.read_bytes()
    with pytest.raises(FileExistsError):
        _navigation(context, output)
    assert output.read_bytes() == original


@pytest.mark.parametrize("change", ["page-order", "boundary", "candidate", "runtime", "implementation"])
def test_navigation_rejects_rehashed_substitution(
    context: dict, tmp_path: Path, change: str,
) -> None:
    path = tmp_path / "navigation.json"
    receipt, args = _navigation(context, path)
    payload = receipt["payload"]
    if change == "page-order":
        payload["selected_pages"][1], payload["selected_pages"][2] = (
            payload["selected_pages"][2], payload["selected_pages"][1]
        )
    elif change == "boundary":
        payload["raw_navigation"]["registrable_domain"] = "outside.example"
    elif change == "candidate":
        payload["candidate"]["domain"] = "outside.example"
    elif change == "runtime":
        payload["runtime"]["source_manifest_text"] += "\n"
    else:
        payload["implementation_hashes"]["qcsd_lab.class_catalogue"] = "a" * 64
    _rewrite(path, receipt)
    with pytest.raises(ValueError):
        evidence.verify_navigation_receipt(path, **args)


def test_navigation_rejects_old_timestamp_even_with_current_type(context: dict, tmp_path: Path) -> None:
    path = tmp_path / "navigation.json"
    receipt, args = _navigation(context, path)
    receipt["payload"]["started_at"] = "2026-01-01T00:00:00Z"
    _rewrite(path, receipt)
    with pytest.raises(ValueError, match="stale"):
        evidence.verify_navigation_receipt(path, **args)


def test_page_exact_h3_proof_matches_v5_contract(context: dict, tmp_path: Path) -> None:
    output, receipt, args = _page(context, tmp_path)
    proof = evidence.verify_selected_page_h3_receipt(output, **args)
    assert proof["url"] == receipt["payload"]["selected_page"]["url"]
    assert proof["selected_page_ordinal"] == 1
    assert proof["controls_passed"] is True
    assert rapid._validated_v5_selected_page_h3_proof(proof, context["candidate"]) == proof


@pytest.mark.parametrize("stage", ["control_before", "exact_page_probe", "control_after"])
def test_page_reclassifies_raw_failure(context: dict, tmp_path: Path, stage: str) -> None:
    output, receipt, args = _page(context, tmp_path)
    raw = receipt["payload"][stage]
    manifest = json.loads(raw["output_text"])
    manifest["resources"][0]["known_valid"] = False
    raw["output_text"] = json.dumps(manifest)
    raw["output_sha256"] = _sha(raw["output_text"].encode())
    raw["known_valid"] = False
    raw["outcome"] = "ambiguous"
    _rewrite(output, receipt)
    with pytest.raises(ValueError, match="did not"):
        evidence.verify_selected_page_h3_receipt(output, **args)


@pytest.mark.parametrize("change", ["exact-url", "ordinal", "navigation", "binary", "raw-order"])
def test_page_rejects_rehashed_substitution(context: dict, tmp_path: Path, change: str) -> None:
    output, receipt, args = _page(context, tmp_path)
    payload = receipt["payload"]
    if change == "exact-url":
        payload["exact_page_probe"]["url"] += "wrong"
    elif change == "ordinal":
        payload["selected_page"]["ordinal"] = 0
    elif change == "navigation":
        payload["navigation_receipt_sha256"] = "f" * 64
    elif change == "binary":
        payload["implementation_hashes"]["neqo-qcsd-client"] = "f" * 64
    else:
        payload["control_before"]["completed_at"] = payload["control_after"]["completed_at"]
    _rewrite(output, receipt)
    with pytest.raises(ValueError):
        evidence.verify_selected_page_h3_receipt(output, **args)


def test_dirty_runtime_rejected_before_navigation(context: dict, tmp_path: Path) -> None:
    runtime = json.loads(context["runtime_path"].read_bytes())
    runtime["lab_dirty"] = True
    context["runtime_path"].write_text(json.dumps(runtime))
    context["binding"]["source_manifest_sha256"] = _sha(context["runtime_path"].read_bytes())
    with pytest.raises(ValueError, match="clean and pinned"):
        _navigation(context, tmp_path / "navigation.json")


def test_legacy_receipt_type_rejected(context: dict, tmp_path: Path) -> None:
    path = tmp_path / "navigation.json"
    receipt, args = _navigation(context, path)
    receipt["receipt_type"] = "qcsd-non-evidentiary-h3-curated-root-survey"
    _rewrite(path, receipt)
    with pytest.raises(ValueError, match="envelope"):
        evidence.verify_navigation_receipt(path, **args)
