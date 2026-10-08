"""Cold-policy and installed-reader controls; mocked Git/receipt boundaries only.

These temporary fixtures establish no actual installed runtime or live pilot.
"""
import copy
import io
import json
from pathlib import Path
import tarfile

import pytest

from qcsd_lab import rapid_portable_runtime as runtime

LIVE = "resource-domain-live-pilot-v1"
SOURCE_ROOT = Path(runtime.__file__).resolve().parents[2]
RAW = (SOURCE_ROOT / "Dockerfile").read_bytes()
NAMESPACE = "a" * 64


def test_default_full_recipe_and_native_gate_remain_identical():
    assert runtime.dockerfile_bytes(RAW, cache_namespace=NAMESPACE) == runtime.dockerfile_bytes(
        RAW, cache_namespace=NAMESPACE, check_policy="full")
    assert runtime._cold_check_recipe(RAW.decode(), "full") == RAW.decode()
    full = runtime.dockerfile_bytes(RAW, cache_namespace=NAMESPACE).decode()
    for command in ("cargo fmt --check", "cargo test -p neqo-bin", "cargo clippy --workspace"):
        assert command in full
    assert '"artifact_type": "qcsd-rust-code-gate"' in full


def test_live_recipe_omits_only_declared_checks_retains_compile_and_installed_surface():
    value = runtime.dockerfile_bytes(RAW, cache_namespace=NAMESPACE, check_policy=LIVE).decode()
    for command in ("cargo fmt --check", "cargo test -p", "cargo clippy --workspace"):
        assert command not in value
    for required in ("cargo build --locked --release", 'NEQO_QCSD_GIT_COMMIT="${neqo_commit}"',
                     "NSS_BUNDLE_SHA256=", "NSS_PREBUILT=1", "python3 -m qcsd_lab.runtime_provenance verify",
                     "COPY --from=rapid-recipe verify_installed.py /recipe/verify_installed.py",
                     "COPY --from=source-metadata /source /runtime-src"):
        assert required in value
    for field in ('"passed": False', '"rust_fmt_executed": False', '"rust_tests_executed": False',
                  '"rust_clippy_executed": False', '"commands": []', '"scientific_credit": False',
                  '"formal_accepted_trace_count": 0', '"policy": "' + LIVE + '"'):
        assert field in value
    assert '"artifact_type": "qcsd-resource-domain-native-build-policy-v1"' in value
    assert "20-resource-each-traffic-mode-on-actual-architecture-before-formal-credit" in value
    original_tail = RAW.decode().split("# Release artifacts are built only from the source that passed every gate.\n", 1)[1]
    assert runtime._cold_check_recipe(RAW.decode(), LIVE).endswith(original_tail)


@pytest.mark.parametrize("bad", [None, True, "skip", "full "])
def test_unknown_or_untyped_policy_refused(bad):
    with pytest.raises(ValueError):
        runtime.dockerfile_bytes(RAW, cache_namespace=NAMESPACE, check_policy=bad)


def test_mutated_gate_bytes_refuse_prospective_rewrite():
    changed = RAW.replace(b"cargo fmt --check", b"cargo fmt --check ", 1)
    with pytest.raises(ValueError, match="code-gate bytes"):
        runtime.dockerfile_bytes(changed, cache_namespace=NAMESPACE, check_policy=LIVE)


def test_prospective_policy_cannot_relabel_reuse_or_create_stage(tmp_path):
    images = {role: "sha256:" + "c" * 64 for role in ("collection", "prepare")}
    with pytest.raises(ValueError, match="reuse"):
        runtime.dockerfile_bytes(RAW, cache_namespace=NAMESPACE, original=images, check_policy=LIVE)
    destination = tmp_path / "never-created"
    with pytest.raises(ValueError, match="reuse"):
        runtime.stage(tmp_path / "absent", "a" * 40, "b" * 40, destination,
            selected_platform="linux/arm64", docker=tmp_path / "absent-docker",
            original_canonical={"path": "absent"}, cold_check_policy=LIVE)
    assert not destination.exists()


def _archive(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as handle:
        for name, raw in files.items():
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(raw), 0o644
            handle.addfile(member, io.BytesIO(raw))
    return output.getvalue()


@pytest.fixture
def staged(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    native = {"Cargo.lock": b"controlled Native lock"}
    lab = {name: (SOURCE_ROOT / name).read_bytes() for name in
           ("Dockerfile", runtime.SOURCE_PATH, runtime.CLI_PATH, runtime.VERIFIER_PATH)}
    lab["uv.lock"] = b"controlled Python lock"
    for prefix, files in (("", lab), ("neqo-qcsd/", native)):
        for name, raw in files.items():
            path = checkout / (prefix + name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o644)
    docker = tmp_path / "docker"
    docker.write_bytes(b"controlled executable; never executed")
    docker.chmod(0o755)
    archives = {"lab": _archive(lab), "native": _archive(native)}
    def git(repository, *args):
        is_native = Path(repository).name == "neqo-qcsd"
        if args == ("ls-files", "--cached", "-z"):
            names = list(native) if is_native else list(lab) + ["neqo-qcsd"]
            return b"\0".join(name.encode() for name in names) + b"\0"
        if "ls-files" in args:
            return ("160000 " + "b" * 40 + " 0\tneqo-qcsd\n").encode()
        assert "archive" in args
        return archives["native" if is_native else "lab"]
    def create(path, raw, *, mode=0o644):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as handle:
            handle.write(raw)
        path.chmod(mode)
    monkeypatch.setattr(runtime, "_git", git)
    monkeypatch.setattr(runtime, "_clean", lambda *args: None)
    monkeypatch.setattr(runtime, "_create", create)
    monkeypatch.setattr(runtime, "_flush_snapshot", lambda root: None)
    def stage(policy="full"):
        root = tmp_path / ("runtime-" + policy)
        runtime.stage(checkout, "a" * 40, "b" * 40, root, selected_platform="linux/arm64",
                      docker=docker, cold_check_policy=policy)
        return root
    return stage


@pytest.mark.parametrize("policy", ["full", LIVE])
def test_staged_policy_round_trips_complete_input_reader(staged, policy):
    root = staged(policy)
    inputs, sources, original = runtime._inputs(root)
    assert original is None and inputs["platform"] == "linux/arm64"
    assert inputs.get("cold_check_policy", "full") == policy
    assert ("cold_check_policy" in inputs) is (policy != "full")
    assert "neqo-qcsd/Cargo.lock" in sources
    assert inputs["scientific_credit"] is False
    assert inputs["formal_accepted_trace_count"] == 0


@pytest.mark.parametrize("change", ["unknown", "extra", "reuse", "recipe"])
def test_input_reader_refuses_policy_or_recipe_substitution(staged, change):
    root = staged(LIVE)
    inputs = json.loads((root / "build-inputs.json").read_text())
    if change == "unknown":
        inputs["cold_check_policy"] = "unchecked"
    elif change == "extra":
        inputs["other_policy"] = LIVE
    elif change == "reuse":
        inputs["mode"] = "authenticated-client-reuse"
    else:
        path = root / "image-context/Portable.Dockerfile"
        path.write_bytes(runtime.dockerfile_bytes(RAW, cache_namespace=runtime._sha(str(root).encode())))
    (root / "build-inputs.json").write_bytes(runtime._json(inputs))
    with pytest.raises(ValueError):
        runtime._inputs(root)


@pytest.mark.parametrize("policy", [None, LIVE])
def test_cli_default_and_explicit_policy_forwarded_without_operations(tmp_path, monkeypatch, capsys, policy):
    received = []
    monkeypatch.setattr(runtime, "stage", lambda *args, **kwargs: received.append(kwargs) or {"controlled": True})
    args = ["stage", "--checkout", str(tmp_path), "--build-root", str(tmp_path / "runtime"),
            "--lab-commit", "a" * 40, "--native-commit", "b" * 40, "--platform", "linux/arm64"]
    if policy is not None:
        args += ["--cold-check-policy", policy]
    assert runtime.main(args) == 0
    assert received[0]["cold_check_policy"] == (policy or "full")
    assert json.loads(capsys.readouterr().out)["scientific_credit"] is False


def test_public_original_dispatches_public_reader_with_cycle_tracking(tmp_path, monkeypatch):
    path = tmp_path / "canonical.json"
    value = {"artifact_type": runtime.TYPE}
    monkeypatch.setattr(runtime, "_open", lambda ref: path)
    monkeypatch.setattr(runtime, "_load", lambda actual: value)
    calls = []
    expected = ({"controlled": True}, {})
    def verify(root, actual, *, seen):
        calls.append((root, actual, seen))
        return expected
    monkeypatch.setattr(runtime, "_verify", verify)
    assert runtime._original({"controlled": True}, seen=frozenset({"earlier"})) == expected
    assert calls == [(path.parent, value, frozenset({"earlier", str(path)}))]


def test_public_original_cycle_refused_before_reader(tmp_path, monkeypatch):
    path = tmp_path / "canonical.json"
    monkeypatch.setattr(runtime, "_open", lambda ref: path)
    monkeypatch.setattr(runtime, "_load", lambda actual: {"artifact_type": runtime.TYPE})
    monkeypatch.setattr(runtime, "_verify", lambda *args, **kwargs: pytest.fail("cycle reached reader"))
    with pytest.raises(ValueError, match="cycle"):
        runtime._original({}, seen=frozenset({str(path)}))


def test_historical_original_retains_legacy_delegate(tmp_path, monkeypatch):
    from qcsd_lab import rapid_rolling_schedule as legacy
    path = tmp_path / "canonical.json"
    value = {"source_manifest": {"legacy": 1}, "client_binary": {"legacy": 2},
             "collection_image_digest": "sha256:" + "c" * 64}
    monkeypatch.setattr(runtime, "_open", lambda ref: path)
    monkeypatch.setattr(runtime, "_load", lambda actual: value)
    monkeypatch.setattr(runtime, "_verify", lambda *args, **kwargs: pytest.fail("legacy used public reader"))
    calls = []
    monkeypatch.setattr(legacy, "reopen_runtime", lambda *args, **kwargs: calls.append((args, kwargs)) or "legacy result")
    ref, seen = {"legacy": True}, frozenset({"earlier"})
    assert runtime._original(ref, seen=seen) == "legacy result"
    assert calls[0][0][0] is ref
    assert calls[0][0][1]["source_manifest"] == value["source_manifest"]
    assert calls[0][1] == {"_seen": seen, "_inspector": True}


@pytest.fixture
def installed(tmp_path, monkeypatch):
    from qcsd_lab import chaff_qualification as qualification, runtime_provenance as provenance
    from qcsd_lab import buflo_study as buflo
    root, installed_module = tmp_path / "runtime-src", tmp_path / "installed.py"
    module = "src/qcsd_lab/controlled.py"
    for name, raw in ((runtime.SOURCE_PATH, Path(runtime.__file__).read_bytes()),
                      (runtime.VERIFIER_PATH, b"controlled transport"), (module, b"module bytes")):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o644)
    installed_module.write_bytes(b"module bytes")
    installed_module.chmod(0o644)
    source = {"image_digest": None, "lab_commit": "a" * 40, "lab_dirty": False,
              "lab_patch_sha256": runtime._sha(b""), "neqo_commit": "b" * 40,
              "neqo_pinned_commit": "b" * 40, "neqo_dirty": False, "neqo_patch_sha256": runtime._sha(b"")}
    source_path, transport, client = tmp_path / "source.json", tmp_path / "transport.py", tmp_path / "client"
    source_path.write_bytes(runtime._json(source))
    transport.write_bytes(b"controlled transport")
    client.write_bytes(b"actual fixture client " + source["neqo_commit"].encode())
    client.chmod(0o755)
    rust_receipt = tmp_path / "rust-code-gate/receipt.json"
    rust_receipt.parent.mkdir()
    rust_receipt.write_bytes(runtime._json({"artifact_type": "qcsd-resource-domain-native-build-policy-v1",
                                          "policy": LIVE, "passed": False, "commands": []}))
    original_path = runtime._path
    mapped = {"/runtime-src": root, "/usr/share/qcsd-lab/source.json": source_path,
              "/recipe/verify_installed.py": transport, "/usr/local/bin/neqo-qcsd-client": client}
    def resolve(value, **kwargs):
        if "rust-code-gate" in str(value):
            pytest.fail("installed byte verifier tried to treat Rust non-pass receipt as authority")
        return original_path(mapped.get(str(value), value), **kwargs)
    monkeypatch.setattr(runtime, "_path", resolve)
    monkeypatch.setenv("QCSD_LAB_IMAGE_DIGEST", "sha256:" + "c" * 64)
    monkeypatch.setattr(runtime.platform, "machine", lambda: "aarch64")
    python = {"source": copy.deepcopy(source), "installed_modules": {
        module: {"path": str(installed_module), "sha256": runtime._sha(installed_module.read_bytes())}},
        "payload_sha256": "d" * 64}
    implementation = {"source": copy.deepcopy(source), "source_files": {module: runtime._sha(b"module bytes")},
                      "neqo_qcsd_client": {"sha256": runtime._sha(client.read_bytes())}, "sha256": "e" * 64}
    def validate(**kwargs):
        assert kwargs == {"required_schema_version": provenance.RUNTIME_RECEIPT_SCHEMA_VERSION}
        result = copy.deepcopy(python)
        result["installed_modules"][module]["sha256"] = runtime._sha(installed_module.read_bytes())
        return result
    def qualify(**kwargs):
        assert kwargs == {"executed_image": True}
        return implementation
    monkeypatch.setattr(provenance, "validate_runtime_receipt", validate)
    monkeypatch.setattr(qualification, "implementation_receipt", qualify)
    monkeypatch.setattr(buflo, "validate_rust_code_gate", lambda *a, **k: pytest.fail("legacy Rust pass gate used"))
    return root, installed_module, source_path, transport, client, python, implementation


@pytest.mark.parametrize("role", ["collection", "prepare"])
def test_real_installed_reader_uses_bytes_without_rust_pass_claim(installed, role):
    value = runtime.verify_installed(role)
    assert value["role"] == role and value["platform"] == "linux/arm64"
    assert value["scope"] == "installed-runtime-byte-and-source-verification-only"
    assert value["client_sha256"] == runtime._sha(installed[4].read_bytes())
    assert value["site_credit"] == value["formal_accepted_trace_count"] == 0
    assert "rust_code_gate" not in value and "passed" not in value


@pytest.mark.parametrize("change", ["source", "client-bytes", "client-mode", "module-bytes", "module-mode",
                                    "transport", "consumer", "qualification-source"])
def test_installed_reader_still_refuses_source_and_byte_mutation(installed, change):
    root, module, source_path, transport, client, python, implementation = installed
    if change == "source":
        python["source"]["lab_commit"] = "f" * 40
    elif change == "client-bytes":
        client.write_bytes(client.read_bytes() + b" altered")
    elif change == "client-mode":
        client.chmod(0o644)
    elif change == "module-bytes":
        module.write_bytes(b"different module bytes")
    elif change == "module-mode":
        module.chmod(0o755)
    elif change == "transport":
        transport.write_bytes(b"different transport")
    elif change == "consumer":
        (root / runtime.SOURCE_PATH).write_bytes(b"different verifier source")
    else:
        implementation["source_files"]["src/qcsd_lab/controlled.py"] = "f" * 64
    with pytest.raises(ValueError):
        runtime.verify_installed("collection")
