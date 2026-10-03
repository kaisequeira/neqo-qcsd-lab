"""Retained root screens keep their real runtime; new page work does not inherit it."""
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qcsd_lab import rapid_site_admission as admission
from tools import h3_rapid_fallback_survey as fallback
from tools import rapid_acquire
from tests.test_rapid_site_admission import (
    CATALOGUE, PROFILE, SOURCE, SOURCE_RECEIPT, _amended_context, _page_files, _probe, _root_logs, context,
)


def installed_proof(old, tmp_path):
    directory = tmp_path / "installed"
    directory.mkdir()
    image = old.execution_binding["admission_image_digest"]
    now = datetime.now(UTC)
    raw_source = admission._load(admission._read(admission._child(old.root,
        admission._unpack(admission._read(old.root / "provenance.json"), admission.PROVENANCE_TYPE)["inputs"]["source_manifest"])))
    observed = {"role": "prepare", "scope": "installed-runtime-byte-and-source-verification-only",
                "source": raw_source, "image_digest": image,
                "source_metadata_raw_sha256": old.execution_binding["source_manifest_sha256"],
                "client_sha256": old.mounted_module_hashes["page"]["neqo-qcsd-client"],
                "site_credit": 0, "formal_accepted_trace_count": 0}
    stdout = admission._json(observed)
    files = {
        "prepare-installed-verification-started.json": admission._json({
            "command": ["docker", "run", "--rm", "--network", "none", "--user", "1000:1000",
                        "--env", f"QCSD_LAB_IMAGE_DIGEST={image}", "--env", "QCSD_LAB_ROOT=/runtime-src",
                        "--entrypoint", "/opt/qcsd-venv/bin/python3", image, "-I", "/recipe/verify_installed.py", "prepare"],
            "started_at": (now - timedelta(seconds=2)).isoformat()}),
        "prepare-installed-verification-completed.json": admission._json({
            "returncode": 0, "completed_at": (now - timedelta(seconds=1)).isoformat(),
            "stdout_sha256": admission._sha(stdout), "stderr_sha256": admission._sha(b"")}),
        "prepare-installed-verification.stdout.log": stdout,
        "prepare-installed-verification.stderr.log": b"",
        "canonical-runtime.json": admission._json({
            "verified_at": now.isoformat(), "installed_byte_verification_completed": True,
            "prepare_image_digest": image,
            "exported_source_manifest_sha256": old.execution_binding["source_manifest_sha256"],
            "installed_client_sha256": observed["client_sha256"], "checks": {"prepare": observed},
            "scientific_credit": False, "admitted_site_count": 0, "formal_accepted_trace_count": 0}),
    }
    for name, raw in files.items():
        (directory / name).write_bytes(raw)
    return directory / "canonical-runtime.json"


def successor(old, tmp_path, *, proof=None, modules=None, barrier=None, retained=True, native_commit=None):
    original = admission._unpack(admission._read(old.root / "provenance.json"), admission.PROVENANCE_TYPE)
    paths = {key: admission._child(old.root, ref) for key, ref in original["inputs"].items()}
    sources = {group: {name: admission._child(old.root, ref) for name, ref in values.items()}
               for group, values in original["module_sources"].items()}
    runtime = admission._load(admission._read(paths["source_manifest"]))
    runtime["lab_commit"] = "3" * 40
    if native_commit is not None:
        runtime["neqo_commit"] = runtime["neqo_pinned_commit"] = native_commit
    source = tmp_path / "new-source.json"
    source.write_bytes(admission._json(runtime))
    kwargs = {} if not retained else {
        "root_screen_context": old.root, "root_screen_runtime_proof": proof,
        "root_screen_runtime_proof_sha256": admission._sha(admission._read(proof)),
    }
    return admission.initialize_acquisition(tmp_path / "successor", profile_path=paths["profile"],
        source=paths["source"], source_receipt=paths["source_receipt"], catalogue=paths["catalogue"],
        source_manifest=source, admission_image_digest="sha256:" + "e" * 64,
        not_before_utc=barrier or old.not_before_utc, module_sources=modules or sources,
        selection_amendment=paths.get("selection_amendment"), **kwargs)


@pytest.mark.parametrize("revision", [None, 6])
def test_retained_survey_runtime_reopens_both_groups_and_new_page_binding(context, tmp_path, monkeypatch, revision):
    if revision is not None:
        context = _amended_context(context, tmp_path, revision=revision)
    proof = installed_proof(context, tmp_path)
    old_logs = _root_logs(context, tmp_path, dns_missing=True)
    fallback_log = tmp_path / "fallback.jsonl"
    fallback.run_survey(profile=PROFILE, source=SOURCE, catalogue=CATALOGUE,
        output=fallback_log, start_index=0, count=2, study_version=5, probe=_probe)
    raw_logs = {path: admission._read(path) for path in [*old_logs, fallback_log]}
    new = successor(context, tmp_path, proof=proof)
    assert new.execution_binding != context.execution_binding
    assert new.expected_runtime_source["lab_commit"] == "3" * 40
    assert new.root_screen_verification_kwargs["execution_binding"] == context.execution_binding
    refs = [admission.import_evidence(new.root, path) for path in old_logs]
    first = new.candidates[0]
    assert admission.verify_root_screen(new, first["candidate_id"], refs)["root_screen"]["detail"] == "dns-name-not-found"
    fallback_candidate = next(row for row in new.candidates if row["source_kind"] == "tranco-fallback")
    fallback_refs = [admission.import_evidence(new.root, fallback_log)]
    assert admission.verify_root_screen(new, fallback_candidate["candidate_id"], fallback_refs)["root_screen"]["controls_passed"] is True
    terminal = admission.produce_site_terminal(new, candidate_id=first["candidate_id"], root_surveys=old_logs, defer_root=True)
    assert admission.verify_site_terminal(terminal, new)["execution_binding"] == new.execution_binding
    status = admission.acquisition_status(new)
    assert status["terminal_count"] == 1
    assert status["admitted_site_count"] == status["formal_accepted_trace_count"] == 0
    monkeypatch.setenv("QCSD_LAB_SOURCE_METADATA", str(tmp_path / "new-source.json"))
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", new.execution_binding["admission_image_digest"])
    candidate, navigation, h3, _ = _page_files(new, tmp_path, new.candidates[1])
    assert admission._page_facts(new, candidate["candidate_id"], navigation, h3)["receipt_sha256"] == admission._sha(admission._read(h3))
    observed = admission._load(admission._read(h3))["payload"]
    assert observed["execution_binding"] == new.execution_binding
    assert admission._sha(observed["runtime"]["source_manifest_text"].encode()) == new.execution_binding["source_manifest_sha256"]
    assert all(admission._read(path) == raw for path, raw in raw_logs.items())
    assert admission.load_admission_context(new.root).root_screen_verification_kwargs == new.root_screen_verification_kwargs


def test_legacy_no_option_still_rejects_changed_image_root_logs(context, tmp_path):
    logs = _root_logs(context, tmp_path)
    new = successor(context, tmp_path, retained=False)
    payload = admission._unpack(admission._read(new.root / "provenance.json"), admission.PROVENANCE_TYPE)
    assert "root_screen_runtime" not in payload
    refs = [admission.import_evidence(new.root, path) for path in logs]
    with pytest.raises(ValueError, match="source, image or protocol binding"):
        admission.verify_root_screen(new, new.candidates[0]["candidate_id"], refs)


@pytest.mark.parametrize("change", ["component", "client", "native-source", "exit", "stdout", "image", "claimed-only"])
def test_changed_component_or_unproved_runtime_rejected_before_claim(context, tmp_path, change):
    proof = installed_proof(context, tmp_path)
    original = admission._unpack(admission._read(context.root / "provenance.json"), admission.PROVENANCE_TYPE)
    modules = {group: {name: admission._child(context.root, ref) for name, ref in values.items()}
               for group, values in original["module_sources"].items()}
    if change in {"component", "client"}:
        altered = tmp_path / "altered"
        altered.write_bytes(b"different component")
        if change == "component":
            modules["curated"]["tools.h3_curated_survey"] = altered
        else:
            modules["page"]["neqo-qcsd-client"] = altered
    elif change == "native-source":
        # The independently bound main native commit must match the original.
        with pytest.raises(ValueError, match="same actual native client and Rust source"):
            successor(context, tmp_path, proof=proof, native_commit="4" * 40)
        return
    elif change == "exit":
        p = proof.parent / "prepare-installed-verification-completed.json"
        v = admission._load(p.read_bytes());v["returncode"] = 1;p.write_bytes(admission._json(v))
    elif change == "stdout":
        (proof.parent / "prepare-installed-verification.stdout.log").write_bytes(b"{}")
    elif change == "image":
        v = admission._load(proof.read_bytes());v["prepare_image_digest"] = "sha256:" + "a" * 64
        proof.write_bytes(admission._json(v))
    else:
        (proof.parent / "prepare-installed-verification-started.json").unlink()
    with pytest.raises((ValueError, KeyError)):
        successor(context, tmp_path, proof=proof, modules=modules)
    assert not (tmp_path / "successor").exists()


def test_retained_role_never_waives_new_publication_barrier(context, tmp_path):
    proof = installed_proof(context, tmp_path)
    logs = _root_logs(context, tmp_path)
    new = successor(context, tmp_path, proof=proof, barrier=datetime.now(UTC))
    refs = [admission.import_evidence(new.root, path) for path in logs]
    with pytest.raises(ValueError, match="predates the profile freeze"):
        admission.verify_root_screen(new, new.candidates[0]["candidate_id"], refs)


def test_retained_inputs_are_rehashed_after_semantic_cache(context, tmp_path):
    proof = installed_proof(context, tmp_path)
    new = successor(context, tmp_path, proof=proof)
    kwargs = new.root_screen_verification_kwargs
    role = new.root_screen_runtime
    retained = admission._child(new.root, role["installed_verification"]["stdout"])
    retained.write_bytes(b"different actual output")
    with pytest.raises(ValueError, match="bytes changed"):
        new.root_screen_verification_kwargs
    assert kwargs["execution_binding"] == context.execution_binding


def test_independently_selected_proof_cannot_change_during_snapshot(context, tmp_path, monkeypatch):
    proof = installed_proof(context, tmp_path)
    real_import = admission.import_evidence

    def changed_while_copying(root, path):
        if Path(path) == proof:
            value = admission._load(proof.read_bytes())
            value["verified_at"] = datetime.now(UTC).isoformat()
            proof.write_bytes(admission._json(value))
        return real_import(root, path)

    monkeypatch.setattr(admission, "import_evidence", changed_while_copying)
    with pytest.raises(ValueError, match="authority changed while retained inputs were copied"):
        successor(context, tmp_path, proof=proof)
    assert not (tmp_path / "successor/provenance.json").exists()


def test_cli_exposes_explicit_original_root_runtime_selection():
    args = rapid_acquire._parser().parse_args(["init", "/unused", "--profile", str(PROFILE),
        "--source", str(SOURCE), "--source-receipt", str(SOURCE_RECEIPT), "--catalogue", str(CATALOGUE),
        "--source-manifest", "/source", "--admission-image-digest", "sha256:" + "e" * 64,
        "--not-before-utc", datetime.now(UTC).isoformat(), "--root-screen-context", "/old",
        "--root-screen-runtime-proof", "/old-runtime/canonical-runtime.json", "--root-screen-runtime-proof-sha256", "a" * 64,
        *[item for group in sorted(admission.IMPLEMENTATION_GROUPS) for item in
          (f"--{group}-module", "test.module=/module")]])
    assert args.root_screen_context == Path("/old")
