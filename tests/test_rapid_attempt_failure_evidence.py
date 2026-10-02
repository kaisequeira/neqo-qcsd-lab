from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qcsd_lab import class_acquisition, rapid_attempt_failure_evidence as evidence
from qcsd_lab import rapid_page_evidence as page


def backend_failure_fixture(tmp_path, monkeypatch, *, action_kind="catalogue-boundary-navigation", error=None):
    """Actual observer and reopening with unit-only clean image/client fixtures."""
    source = {"image_digest": None, "lab_commit": "1" * 40, "lab_dirty": False, "lab_patch_sha256": page._EMPTY_SHA,
              "neqo_commit": "2" * 40, "neqo_dirty": False, "neqo_patch_sha256": page._EMPTY_SHA,
              "neqo_pinned_commit": "2" * 40}
    source_path, client = tmp_path / "source.json", tmp_path / "client"
    source_path.write_bytes(page._json(source))
    client.write_bytes(b"retained immutable unit client\n")
    binding = {"source_manifest_sha256": page._sha(source_path.read_bytes()), "admission_image_digest": "sha256:" + "d" * 64}
    monkeypatch.setenv("QCSD_LAB_SOURCE_METADATA", str(source_path))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", binding["admission_image_digest"])
    monkeypatch.setenv("QCSD_NEQO_CLIENT", str(client))
    # Unit-only immutable sources prevent unrelated concurrent authoring from
    # invalidating this fixture. The actually invoked backend keeps its real
    # source path, so traceback/file ownership is still checked.
    frozen_sources = evidence.implementation_sources()
    snapshot = tmp_path / "unit-source-snapshot"
    snapshot.mkdir()
    for name, path in list(frozen_sources.items()):
        if name not in {"qcsd_lab.class_acquisition", "neqo-qcsd-client"}:
            frozen = snapshot / name
            frozen.write_bytes(path.read_bytes())
            frozen_sources[name] = frozen
    monkeypatch.setattr(evidence, "implementation_sources", lambda: dict(frozen_sources))
    barrier = datetime.now(UTC) - timedelta(seconds=1)
    hashes = evidence.implementation_hashes()
    runtime = evidence.begin_attempt_action(binding, hashes, barrier)
    attempt = tmp_path / "attempt"
    attempt.mkdir()
    (attempt / "intent.json").write_bytes(b"retained actual attempt intent\n")
    (attempt / "failed-response.bin").write_bytes(b"retained available unsuccessful response bytes\x00")
    scopes = {"catalogue-boundary-navigation": "catalogue-root-and-optional-link-navigation",
              "selected-page-h3-probe": "exact-selected-page-controlled-h3-probe",
              "complete-graph-preparation": "exact-selected-page-complete-resource-graph-preparation"}
    action = {"kind": action_kind, "url": "https://example.com/", "scope": scopes[action_kind],
              "selected_page_ordinal": None if action_kind == "catalogue-boundary-navigation" else 0}
    started = datetime.now(UTC).isoformat()
    if error is None:
        def failed_call(domain):
            raise RuntimeError("actual injected live backend call failed")
        backend = class_acquisition.ExistingAcquisitionBackend(navigation=failed_call)
        try:
            backend.discover_navigation("example.com")
        except RuntimeError as caught:
            error = caught
    path = attempt / "attempt-observation.json"
    common = {"execution_binding": binding, "expected_implementation_hashes": hashes, "not_before_utc": barrier}
    produce = {**common, "error": error, "action": action, "started_at": started, "runtime": runtime, "attempt_root": attempt}
    evidence.retain_attempt_failure(path, **produce)
    verify = {**common, "expected_action": action}
    facts = evidence.verify_attempt_failure(path, **verify)
    return {"path": path, "attempt": attempt, "facts": facts, "produce": produce, "verify": verify,
            "binding": binding, "barrier": barrier, "source": source_path, "client": client}


@pytest.mark.parametrize("kind", ["catalogue-boundary-navigation", "selected-page-h3-probe", "complete-graph-preparation"])
def test_failed_backend_receipt_reopens_source_client_existing_bytes_and_zero_credit(tmp_path, monkeypatch, kind):
    value = backend_failure_fixture(tmp_path, monkeypatch, action_kind=kind)
    facts = value["facts"]
    assert facts["raw_failure"]["exception_module"] == "builtins"
    assert facts["raw_failure"]["exception_type"] == "RuntimeError"
    assert "discover_navigation" in facts["raw_failure"]["traceback_text"]
    assert facts["evidence_scope"] == "actual-exception-and-retained-attempt-files-only"
    assert facts["whole_domain_ineligible"] is False and facts["retryable"] is True
    assert facts["scientific_credit"] is False and facts["actual_attempt_count"] == 1
    assert facts["formal_accepted_trace_count"] == facts["site_credit"] == 0
    assert "failed-response.bin" in facts["attempt_inventory"]
    assert len(facts["implementation_hashes"]) == 18
    assert {"tools.rapid_acquire", "qcsd_lab.rapid_selection_amendment"} <= facts["implementation_hashes"].keys()
    assert facts["implementation_hashes"]["neqo-qcsd-client"] == page._sha(value["client"].read_bytes())
    (value["attempt"] / "attempt-failure.json").write_bytes(b"later independently verified outer wrapper\n")
    assert evidence.verify_attempt_failure(value["path"], **value["verify"]) == facts
    with pytest.raises(ValueError, match="create-only"):
        evidence.retain_attempt_failure(value["path"], **value["produce"])


def test_actual_exception_chain_retained_even_when_python_suppresses_it(tmp_path, monkeypatch):
    try:
        raise LookupError("actual original backend cause")
    except LookupError:
        try:
            raise RuntimeError("actual replacement during cleanup") from None
        except RuntimeError as caught:
            error = caught
    value = backend_failure_fixture(tmp_path, monkeypatch, error=error)
    raw = value["facts"]["raw_failure"]
    assert raw["exception"]["suppress_context"] is True
    assert raw["exception"]["context"]["exception_type"] == "LookupError"
    assert "actual original backend cause" in raw["traceback_text"]
    assert "actual replacement during cleanup" in raw["traceback_text"]


@pytest.mark.parametrize("target", ["client", "trace", "existing", "extra", "source", "action", "stale"])
def test_reopening_rejects_changed_evidence_or_independent_authority(tmp_path, monkeypatch, target):
    value = backend_failure_fixture(tmp_path, monkeypatch)
    payload = page._open(value["path"], evidence.ATTEMPT_FAILURE_RECEIPT_TYPE)[0]
    verify = value["verify"]
    if target in {"client", "trace"}:
        reference = (payload["artifacts"]["sources"]["neqo-qcsd-client"] if target == "client"
                     else payload["artifacts"]["traceback"])
        (value["attempt"] / reference["path"]).write_bytes(b"changed retained artifact")
    elif target == "existing":
        (value["attempt"] / "failed-response.bin").write_bytes(b"changed prior response")
    elif target == "extra":
        (value["attempt"] / "unregistered.bin").write_bytes(b"new material")
    elif target == "source":
        verify = {**verify, "expected_implementation_hashes": {**verify["expected_implementation_hashes"],
                  "qcsd_lab.prepare": "a" * 64}}
    elif target == "action":
        verify = {**verify, "expected_action": {**verify["expected_action"], "url": "https://different.example/"}}
    else:
        verify = {**verify, "not_before_utc": datetime.now(UTC) + timedelta(seconds=1)}
    with pytest.raises(ValueError):
        evidence.verify_attempt_failure(value["path"], **verify)


@pytest.mark.parametrize("key,replacement", [("formal_accepted_trace_count", True), ("actual_attempt_count", True),
                                            ("site_credit", 1), ("whole_domain_ineligible", True),
                                            ("scientific_credit", True)])
def test_resealed_credit_or_domain_claim_is_rejected(tmp_path, monkeypatch, key, replacement):
    value = backend_failure_fixture(tmp_path, monkeypatch)
    payload = page._open(value["path"], evidence.ATTEMPT_FAILURE_RECEIPT_TYPE)[0]
    payload[key] = replacement
    value["path"].write_bytes(page._json(page._envelope(payload, evidence.ATTEMPT_FAILURE_RECEIPT_TYPE)))
    with pytest.raises(ValueError, match="credit|verdict"):
        evidence.verify_attempt_failure(value["path"], **value["verify"])


@pytest.mark.parametrize("changed_key,replacement", [("message", "invented different underlying reason"),
                                                    ("exception_module", "fictional.module")])
def test_resealed_exception_identity_must_match_retained_traceback(tmp_path, monkeypatch, changed_key, replacement):
    value = backend_failure_fixture(tmp_path, monkeypatch)
    payload = page._open(value["path"], evidence.ATTEMPT_FAILURE_RECEIPT_TYPE)[0]
    reference = payload["artifacts"]["exception"]
    target = value["attempt"] / reference["path"]
    raw = page._loads(target.read_bytes())
    raw[changed_key] = replacement
    target.write_bytes(page._json(raw))
    reference["sha256"] = page._sha(target.read_bytes())
    payload["attempt_inventory"][reference["path"]] = {"sha256": reference["sha256"], "size": target.stat().st_size}
    value["path"].write_bytes(page._json(page._envelope(payload, evidence.ATTEMPT_FAILURE_RECEIPT_TYPE)))
    with pytest.raises(ValueError, match="traceback"):
        evidence.verify_attempt_failure(value["path"], **value["verify"])


def test_runtime_or_client_change_blocks_observation_before_any_receipt(tmp_path, monkeypatch):
    value = backend_failure_fixture(tmp_path, monkeypatch)
    output = value["attempt"] / "second-observation.json"
    value["client"].write_bytes(b"different running client")
    with pytest.raises(ValueError, match="source/client"):
        evidence.retain_attempt_failure(output, **value["produce"])
    assert not output.exists()
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "c" * 64)
    with pytest.raises(ValueError):
        evidence.begin_attempt_action(value["binding"], value["verify"]["expected_implementation_hashes"], value["barrier"])


def test_unraised_error_and_validation_failure_do_not_become_backend_observations(tmp_path, monkeypatch):
    value = backend_failure_fixture(tmp_path, monkeypatch)
    attempt = tmp_path / "fresh-attempt"
    attempt.mkdir()
    produce = {**value["produce"], "error": RuntimeError("invented unraised error"), "attempt_root": attempt}
    with pytest.raises(ValueError, match="actual raised"):
        evidence.retain_attempt_failure(attempt / "attempt-observation.json", **produce)
    assert not (attempt / "attempt-observation.json").exists()
    bad_action = {**value["produce"]["action"], "selected_page_ordinal": True}
    with pytest.raises(ValueError, match="root"):
        evidence.retain_attempt_failure(attempt / "attempt-observation.json", **{**produce, "action": bad_action})


def test_compact_facts_require_independent_action_and_full_raw_consistency(tmp_path, monkeypatch):
    value = backend_failure_fixture(tmp_path, monkeypatch)
    facts = copy.deepcopy(value["facts"])
    facts["raw_failure"]["exception_module"] = "fictional.module"
    with pytest.raises(ValueError, match="identity"):
        evidence.validate_attempt_failure_facts(facts, execution_binding=value["binding"], not_before_utc=value["barrier"])
    with pytest.raises(ValueError, match="action"):
        evidence.validate_attempt_failure_facts(value["facts"], execution_binding=value["binding"],
            not_before_utc=value["barrier"], expected_action={**value["facts"]["action"], "url": "https://different.example/"})
