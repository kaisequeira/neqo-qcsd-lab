"""Connected public runtime identity controls with complete synthetic receipts.

No Git, Docker, network, Native process, qualification or scientific SQL runs.
The full canonical/input/archive/recipe/installed/export verifiers remain real.
"""
import hashlib
import io
import json
from pathlib import Path
import tarfile
from types import ModuleType

import pytest

from qcsd_lab import rapid_portable_runtime as runtime
from qcsd_lab import resource_study as study

SOURCE_ROOT = Path(runtime.__file__).resolve().parents[2]
RETAINED = Path(__file__).parent / "fixtures/rapid_portable_runtime_55a3836e.py"
RETAINED_SHA = "55a3836ef6010c19589945706ec5936d53b3c8c26953f96a8b9607de104c07df"
RECENT_RETAINED = Path(__file__).parent / "fixtures/rapid_portable_runtime_26ffe023.py"
RECENT_RETAINED_SHA = "26ffe0234f6f7682a0ac69a71e0181a00b9e2ae14ecfd27d60be816c6de98221"


def _put(path, raw, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(raw)
    path.chmod(mode)
    return path


def _archive(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as handle:
        for name, raw in files.items():
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(raw), 0o644
            handle.addfile(member, io.BytesIO(raw))
    return output.getvalue()


def _complete_runtime(tmp_path, monkeypatch, retained):
    """Stage real source inputs, then supply the mocked operation receipts."""
    checkout = tmp_path / "checkout"
    lab = {name: (SOURCE_ROOT / name).read_bytes() for name in
           ("Dockerfile", runtime.SOURCE_PATH, runtime.CLI_PATH, runtime.VERIFIER_PATH)}
    if retained:
        selected = RECENT_RETAINED if retained == "source131" else RETAINED
        raw = selected.read_bytes()
        expected_sha = RECENT_RETAINED_SHA if retained == "source131" else RETAINED_SHA
        expected_bytes = runtime.RETAINED_SOURCE131_PRODUCER_BYTES if retained == "source131" else 55191
        assert len(raw) == expected_bytes and hashlib.sha256(raw).hexdigest() == expected_sha
        lab[runtime.SOURCE_PATH] = raw
    lab["uv.lock"] = b"controlled Python dependency lock"
    native = {"Cargo.lock": b"controlled Native dependency lock"}
    for prefix, files in (("", lab), ("neqo-qcsd/", native)):
        for name, raw in files.items():
            _put(checkout / (prefix + name), raw)
    producer = runtime
    if retained:
        path = checkout / runtime.SOURCE_PATH
        producer = ModuleType("qcsd_lab._test_exact_retained_producer")
        producer.__file__, producer.__package__ = str(path), "qcsd_lab"
        exec(compile(path.read_bytes(), str(path), "exec"), producer.__dict__)
    docker = _put(tmp_path / "docker", b"controlled executable; never executed", 0o755)
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
    monkeypatch.setattr(producer, "_git", git)
    monkeypatch.setattr(producer, "_clean", lambda *args: None)
    monkeypatch.setattr(producer, "_create", lambda path, raw, *, mode=0o644: _put(path, raw, mode))
    monkeypatch.setattr(producer, "_flush_snapshot", lambda path: None, raising=False)
    root = tmp_path / "runtime"
    producer.stage(checkout, "a" * 40, "b" * 40, root,
                   selected_platform="linux/arm64", docker=docker)
    inputs = json.loads((root / "build-inputs.json").read_bytes())
    source = inputs["source"]
    source_raw = producer._json(source)
    client_raw = b"controlled exported Native binary " + source["neqo_commit"].encode()
    client = _put(root / "runtime-export/neqo-qcsd-client", client_raw, 0o755)
    source_path = _put(root / "runtime-export/source.json", source_raw)
    images = {"collection": "sha256:" + "c" * 64, "prepare": "sha256:" + "d" * 64}
    checks = {role: {
        "schema_version": 1, "artifact_type": "qcsd-public-portable-rapid-installed-check-v1",
        "scope": "installed-runtime-byte-and-source-verification-only", "role": role,
        "source": source, "image_digest": image, "platform": "linux/arm64",
        "client_sha256": producer._sha(client_raw),
        "source_metadata_raw_sha256": producer._sha(source_raw),
        "source_inventory_sha256": inputs["source_inventory_sha256"],
        "site_credit": 0, "formal_accepted_trace_count": 0,
        "python_runtime_payload_sha256": "e" * 64,
        "qualification_implementation_sha256": "f" * 64,
    } for role, image in images.items()}
    commands = producer._commands(root, inputs, images, None)
    completions = {}
    for role, image in images.items():
        _put(root / (role + "-image-id.txt"), (image + "\n").encode())
    for name, command in commands.items():
        output = b""
        if name == "docker-info":
            output = producer._json({"OSType": "linux", "Architecture": "arm64"})
        for role, image in images.items():
            if name == role + "-image-inspect":
                output = producer._json({"Id": image, "Os": "linux", "Architecture": "arm64",
                    "RootFS": {"Type": "layers", "Layers": ["sha256:" + "1" * 64]}})
            if name == role + "-installed-verification":
                output = producer._json(checks[role])
        _put(root / (name + ".stdout.log"), output)
        _put(root / (name + ".stderr.log"), b"")
        _put(root / (name + "-started.json"), producer._json({"command": command,
            "executable": str(docker), "cwd": None, "started_at": producer._now()}))
        _put(root / (name + "-completed.json"), producer._json({"returncode": 0,
            "invocation_error": None, "elapsed_seconds": 0.0, "completed_at": producer._now(),
            "stdout_sha256": producer._sha(output), "stderr_sha256": producer._sha(b"")}))
        completions[name] = {
            "record_sha256": producer.reference(root / (name + "-completed.json"))["sha256"],
            "started_record_sha256": producer.reference(root / (name + "-started.json"))["sha256"],
            "elapsed_seconds": 0.0,
        }
    value = {"schema_version": 1, "artifact_type": producer.TYPE,
        "contract": producer.CONTRACT, "scope": producer.SCOPE, "source": source,
        "platform": "linux/arm64", **{role + "_image_digest": image for role, image in images.items()},
        "source_manifest": str(source_path), "client_binary": str(client),
        "exported_source_manifest_sha256": producer._sha(source_raw),
        "installed_client_sha256": producer._sha(client_raw),
        "source_inventory_sha256": inputs["source_inventory_sha256"],
        "build_inputs_sha256": producer.reference(root / "build-inputs.json")["sha256"],
        "checks": checks, "actual_operation_completions": completions,
        "installed_byte_verification_completed": True, "native_artifact_action": "portable-source-build",
        "native_compilation_executed": True, "original_canonical": None,
        "verified_at": producer._now(), **producer.ZERO}
    # Validate the fixture through the complete actual producer before testing
    # the public consumer. No _original/_verify/retained-pin boundary is mocked.
    assert producer._verify(root, value)[0] == value
    path = _put(root / "canonical-runtime.json", producer._json(value))
    expected = {"collection_image_digest": images["collection"], "prepare_image_digest": images["prepare"],
        "client_sha256": value["installed_client_sha256"], "platform": value["platform"],
        "native_commit": source["neqo_commit"], "source": source,
        "canonical_sha256": producer.reference(path)["sha256"]}
    return path, expected


@pytest.mark.parametrize("retained", [False, True, "source131"],
                         ids=["current", "exact-retained-55a383", "exact-retained-26ffe023"])
def test_public_runtime_identity_reopens_complete_current_and_retained_runtime(tmp_path, monkeypatch, retained):
    path, expected = _complete_runtime(tmp_path, monkeypatch, retained)
    assert study.runtime_identity(path) == expected


@pytest.mark.parametrize("retained", [False, True, "source131"],
                         ids=["current", "exact-retained-55a383", "exact-retained-26ffe023"])
@pytest.mark.parametrize("change", ["producer", "client"])
def test_public_runtime_identity_rejects_tampered_producer_and_exported_client(
        tmp_path, monkeypatch, retained, change):
    path, _ = _complete_runtime(tmp_path, monkeypatch, retained)
    if change == "producer":
        target = path.parent / "image-context/source" / runtime.SOURCE_PATH
    else:
        target = path.parent / "runtime-export/neqo-qcsd-client"
    target.write_bytes(target.read_bytes() + b"\ncontrolled tampering\n")
    with pytest.raises(ValueError):
        study.runtime_identity(path)
