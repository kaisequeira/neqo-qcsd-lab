"""Public cold-build and authenticated-reuse closure for rapid runtimes.

This prospective contract does not reinterpret historical twelve-operation
receipts. Its actual Docker operations, installed bytes and exports grant no
site, qualification, canary or formal capture credit.
"""
from __future__ import annotations

import argparse
import ctypes
from datetime import UTC, datetime
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
from typing import Any, Mapping

TYPE = "qcsd-public-portable-rapid-runtime-v1"
CONTRACT = "clean-source-native-platform-actual-installed-export-closure-v1"
INPUT_TYPE = "qcsd-public-portable-rapid-runtime-inputs-v1"
SOURCE_PATH = "src/qcsd_lab/rapid_portable_runtime.py"
CLI_PATH = "tools/rapid_portable_runtime.py"
VERIFIER_PATH = "tools/rapid_runtime_verify_installed.py"
SCOPE = "actual-installed-runtime-bytes-not-live-study-qualification"
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
HEAD = re.compile(r"[0-9a-f]{40}\Z")
PLATFORMS = {"linux/amd64", "linux/arm64"}
ARCHITECTURES = {"amd64": "amd64", "x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}
ZERO = {"scientific_credit": False, "admitted_site_count": 0, "formal_accepted_trace_count": 0}
GIT_ENV = {**os.environ, "GIT_NO_REPLACE_OBJECTS": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"}
EXPORT_PROGRAM = """import os,shutil
from pathlib import Path
for source,name,mode in [('/usr/share/qcsd-lab/source.json','source.json',0o644),
                          ('/usr/local/bin/neqo-qcsd-client','neqo-qcsd-client',0o755)]:
    target=Path('/export')/name
    with target.open('xb') as output,Path(source).open('rb') as original:
        shutil.copyfileobj(original,output)
        os.fchmod(output.fileno(),mode);output.flush();os.fsync(output.fileno())
"""
INPUT_KEYS = {"schema_version", "artifact_type", "contract", "source", "platform", "actor", "docker", "docker_executable",
    "clean_checkout", "source_inventory_sha256", "lab_archive_sha256", "rust_archive_sha256",
    "cargo_lock_sha256", "uv_lock_sha256", "producer_files", "recipe_files", "mode", "original_canonical",
    "original_source_inventory", "staged_at", *ZERO}
CANONICAL_KEYS = {"schema_version", "artifact_type", "contract", "scope", "source", "platform",
    "collection_image_digest", "prepare_image_digest", "source_manifest", "client_binary",
    "exported_source_manifest_sha256", "installed_client_sha256", "source_inventory_sha256",
    "build_inputs_sha256", "checks", "actual_operation_completions", "installed_byte_verification_completed",
    "native_artifact_action", "native_compilation_executed", "original_canonical", "verified_at", *ZERO}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f"{label} fields differ")


def _exact(value, expected, label):
    if _json(value) != _json(expected):
        raise ValueError(f"{label} typed values differ")


def _path(value, *, directory=False):
    path = Path(value)
    if (not path.is_absolute() or ".." in path.parts
        or any(item.is_symlink() for item in (path, *path.parents))
        or (not path.is_dir() if directory else not path.is_file())):
        raise ValueError("portable runtime requires absolute regular unlinked paths")
    return path


def _read(path):
    path = _path(path)
    from .rapid_operation_facts import current_context
    context = current_context()
    return context.watch_file(path) if context is not None else path.read_bytes()


def _load(path):
    from .rapid_rolling_readiness import _json as parse
    return parse(_read(path))


def reference(path):
    path = _path(path)
    return {"path": str(path), "sha256": _sha(_read(path))}


def _open(ref):
    _keys(ref, {"path", "sha256"}, "portable runtime reference")
    path = _path(ref["path"])
    if type(ref["sha256"]) is not str or SHA.fullmatch(ref["sha256"]) is None or _sha(_read(path)) != ref["sha256"]:
        raise ValueError("portable runtime immutable reference changed")
    return path


def _create(path, raw, *, mode=0o644):
    from .util import durable_create
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("portable runtime destination contains a link")
    durable_create(path, raw)
    path.chmod(mode)


def _inventory(root):
    from .rapid_rolling_readiness import _inventory as inventory
    return inventory(_path(root, directory=True))


def architecture(value):
    if type(value) is not str or value not in ARCHITECTURES:
        raise ValueError("portable runtime supports only native Linux AMD64 and ARM64")
    return ARCHITECTURES[value]


def is_portable(value):
    return isinstance(value, Mapping) and value.get("artifact_type") == TYPE


def _git(checkout, *args):
    return subprocess.check_output(["git", "-C", str(checkout), *args], env=GIT_ENV)


def _clean(checkout, expected):
    if type(expected) is not str or HEAD.fullmatch(expected) is None:
        raise ValueError("portable runtime requires full clean source commits")
    if (_git(checkout, "rev-parse", "HEAD").decode().strip() != expected
        or _git(checkout, "status", "--porcelain", "--untracked-files=all")):
        raise ValueError("portable runtime checkout does not match its clean source commit")


def _archive_files(raw):
    try:
        return _archive_members(raw)
    except tarfile.TarError as error:
        raise ValueError("portable source archive is malformed") from error


def _archive_members(raw):
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            name = Path(member.name)
            if (name.is_absolute() or ".." in name.parts or ".git" in name.parts
                or not member.name or "\\" in member.name
                or name.as_posix() != member.name.rstrip("/") or name == Path(".")):
                raise ValueError("portable source archive member escapes its source root")
            if member.isdir():
                continue
            if not member.isfile() or member.name in files:
                raise ValueError("portable source archive contains a link, special file or duplicate")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("portable source archive member is unavailable")
            files[member.name] = (stream.read(), bool(member.mode & 0o111))
    if not files:
        raise ValueError("portable source archive is empty")
    return files


def _extract(raw, root):
    for name, (content, executable) in _archive_files(raw).items():
        path = root / name
        if any(item.is_symlink() for item in (path, *path.parents)):
            raise ValueError("portable source snapshot destination contains a link")
        path.parent.mkdir(parents=True, exist_ok=True)
        if any(item.is_symlink() for item in (path, *path.parents)):
            raise ValueError("portable source snapshot destination contains a link")
        with path.open("xb") as handle:
            handle.write(content)
            os.fchmod(handle.fileno(), 0o755 if executable else 0o644)


def _flush_snapshot(root):
    """Flush the complete filesystem once before publishing staged authority.

    Every extracted name is create-only. A failed or interrupted extraction
    has no build-input receipt and cannot be built. The final snapshot is
    hashed after this durability fence, then bound by the durable input receipt.
    """
    descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        library = ctypes.CDLL(None, use_errno=True)
        flush = getattr(library, "syncfs", None)
        if flush is None:
            for path in root.rglob("*"):
                if path.is_file():
                    with path.open("rb") as handle:
                        os.fsync(handle.fileno())
            for path in sorted((p for p in root.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
                nested = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(nested)
                finally:
                    os.close(nested)
            os.fsync(descriptor)
        else:
            flush.argtypes, flush.restype = [ctypes.c_int], ctypes.c_int
            if flush(descriptor) != 0:
                raise OSError(ctypes.get_errno(), "source snapshot syncfs failed")
    finally:
        os.close(descriptor)


def _defaults(dockerfile):
    value = {}
    for name in ("RUST_IMAGE", "DEBIAN_IMAGE"):
        matches = re.findall(r"^ARG " + name + r"=(\S+@sha256:[0-9a-f]{64})$", dockerfile, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError("tracked Dockerfile immutable base declaration differs")
        value[name] = matches[0]
    return value


def dockerfile_bytes(raw: bytes, *, cache_namespace: str, original=None) -> bytes:
    """Reuse tracked stages; substitute only authenticated snapshot metadata.

    Named contexts keep generated metadata outside the complete tracked source.
    The ordinary Dockerfile and every Native code gate remain unchanged.
    """
    value = raw.decode()
    _defaults(value)
    if SHA.fullmatch(cache_namespace) is None:
        raise ValueError("portable runtime cache namespace is malformed")
    # Every fresh build namespace receives empty Cargo registry/git caches.
    # These are download caches; all tracked Native gate/build commands remain.
    value = value.replace("id=qcsd-cargo-registry-${TARGETARCH},", "id=qcsd-cargo-registry-${TARGETARCH}-" + cache_namespace + ",")
    value = value.replace("id=qcsd-cargo-git-${TARGETARCH},", "id=qcsd-cargo-git-${TARGETARCH}-" + cache_namespace + ",")
    prefix = "WORKDIR /source\nCOPY . .\n"
    suffix = "\n\n# Hash the exact response-qualification execution surface."
    if value.count(prefix) != 1 or value.count(suffix) != 1:
        raise ValueError("tracked Dockerfile source metadata boundaries differ")
    start = value.index(prefix) + len(prefix)
    end = value.index(suffix, start)
    value = (value[:start] + "COPY --from=rapid-recipe source-metadata.json /source-metadata.json\n"
             "COPY --from=rapid-recipe study-build-inputs.json /study-build-inputs.json" + value[end:])
    common = ("COPY --from=source-metadata /source /runtime-src\n"
              "COPY --from=rapid-recipe verify_installed.py /recipe/verify_installed.py\n")
    if original is None:
        value += "\nFROM collection AS portable-collection\n" + common
        value += "\nFROM prepare AS portable-prepare\n" + common
    else:
        _keys(original, {"collection", "prepare"}, "portable reuse role images")
        begin = value.index("RUN python3 - <<'PY'\n", value.index("FROM lab-runtime AS collection"))
        end = value.index("\ndef package_version(name):", begin)
        qualification = value[begin:end] + "\nPY\n"
        renewal = (
            "WORKDIR /opt/qcsd-lab\n"
            "COPY --from=source-metadata /source/pyproject.toml /source/uv.lock /source/README.md ./\n"
            "RUN rm -rf /opt/qcsd-lab/src\n"
            "COPY --from=source-metadata /source/src ./src\n"
            "COPY --from=source-metadata /source-metadata.json /usr/share/qcsd-lab/source.json\n"
            "COPY --from=source-metadata /study-build-inputs.json /usr/share/qcsd-lab/study-build-inputs.json\n"
            "COPY --from=source-metadata /qualification-source-files.json /tmp/qualification-source-files.json\n"
            "COPY --from=source-metadata /python-runtime-source-files.json /tmp/python-runtime-source-files.json\n"
            "RUN uv lock --check && uv sync --frozen --no-dev --no-editable --reinstall-package neqo-qcsd-lab --extra test --extra evaluation@DISCOVERY@ && "
            "python3 -c 'import qcsd_lab; from pathlib import Path; [p.chmod(0o644) for p in Path(qcsd_lab.__file__).parent.rglob(\"*.py\") if p.is_file() and not p.is_symlink() and not p.stat().st_mode & 0o111]' && "
            "install -m 0755 /opt/qcsd-venv/bin/qcsd-lab-internal /usr/local/bin/qcsd-lab-internal && "
            "python3 -m qcsd_lab.runtime_provenance build --source-manifest /tmp/python-runtime-source-files.json "
            "--source-metadata /usr/share/qcsd-lab/source.json --destination /usr/share/qcsd-lab/python-runtime-implementation.json\n")
        for role in ("collection", "prepare"):
            if type(original[role]) is not str or IMAGE.fullmatch(original[role]) is None:
                raise ValueError("portable reuse needs actual immutable role image IDs")
            value += (f"\nFROM qcsd-portable-{role}-reuse:{cache_namespace} AS portable-{role}\n"
                      + renewal.replace("@DISCOVERY@", " --extra discovery" if role == "prepare" else "") + qualification + common)
    return value.encode()


def _original(ref, *, seen=frozenset()):
    from .rapid_rolling_schedule import reopen_runtime
    path = _open(ref)
    value = _load(path)
    source = path.parent / "image-context/source"
    runtime = {"runtime_source_root": str(source), "module_root": str(source),
        "base_launcher": str(source / "qcsd-lab"), "host_launcher": str(source / "qcsd-lab"),
        "source_manifest": value["source_manifest"], "client_binary": value["client_binary"],
        "collection_image_digest": value["collection_image_digest"]}
    return reopen_runtime(ref, runtime, _seen=seen, _inspector=True)


def _reuse_equal(before, after):
    # These files own Native binaries, Python dependencies, browser, capture OS
    # tools and build provenance. Lab modules may change under a new closure.
    protected = {name for name in set(before) | set(after) if name.startswith(("neqo-qcsd/", "config/", "docker/"))}
    protected.update({"Dockerfile", ".dockerignore", "pyproject.toml", "uv.lock",
        "tools/build_class_catalogue.py", "tools/browser_egress_qualification.py", "tools/qcsd_chromium_child_wrapper.sh",
        "tools/qcsd_osad.c"})
    if (not any(name.startswith("neqo-qcsd/") for name in protected)
        or any(name not in before or name not in after or before[name] != after[name] for name in protected)):
        raise ValueError("portable client reuse changed Native, dependencies, browser or capture build inputs")


def stage(checkout, lab_commit, native_commit, root, *, selected_platform, docker, original_canonical=None):
    checkout = _path(checkout, directory=True)
    if selected_platform not in PLATFORMS:
        raise ValueError("explicit native Linux runtime platform required")
    docker = _path(Path(docker).resolve(strict=True))
    if not os.access(docker, os.X_OK):
        raise ValueError("Docker executable is unavailable")
    _clean(checkout, lab_commit)
    _clean(checkout / "neqo-qcsd", native_commit)
    link = _git(checkout, "ls-files", "--stage", "--", "neqo-qcsd").decode().strip().split()
    if len(link) != 4 or link[:3] != ["160000", native_commit, "0"]:
        raise ValueError("portable runtime Native source differs from its Lab Gitlink")
    for relative in (SOURCE_PATH, CLI_PATH, VERIFIER_PATH):
        executing = Path(__file__).resolve().parents[2] / relative
        if _read(executing) != _read(checkout / relative):
            raise ValueError("portable runtime producer does not belong to the requested source")
    lab_archive = _git(checkout, "-c", "tar.umask=0022", "archive", "--format=tar", lab_commit)
    native_archive = _git(checkout / "neqo-qcsd", "-c", "tar.umask=0022", "archive", "--format=tar", native_commit)
    _clean(checkout, lab_commit)
    _clean(checkout / "neqo-qcsd", native_commit)
    source = {"image_digest": None, "lab_commit": lab_commit, "lab_dirty": False, "lab_patch_sha256": _sha(b""),
        "neqo_commit": native_commit, "neqo_pinned_commit": native_commit, "neqo_dirty": False, "neqo_patch_sha256": _sha(b"")}
    from .rapid_rolling_readiness import _clean_source
    _clean_source(source)
    original, _ = (None, None) if original_canonical is None else _original(original_canonical)
    root = Path(root)
    if not root.is_absolute() or ".." in root.parts or root.exists() or any(p.is_symlink() for p in (root, *root.parents)):
        raise ValueError("portable runtime build namespace is create-only and absolute")
    root.mkdir(parents=True)
    snapshot = root / "image-context/source"
    _extract(lab_archive, snapshot)
    _extract(native_archive, snapshot / "neqo-qcsd")
    _flush_snapshot(snapshot)
    inventory = _inventory(snapshot)
    if inventory != _inventory(checkout):
        raise ValueError("portable source archive differs from the exact clean checkout")
    original_inventory = None
    if original is not None:
        if original["source"]["neqo_commit"] != native_commit:
            raise ValueError("portable reuse changed Native source identity")
        original_inventory = reference(_open(original_canonical).parent / "source-inventory.json")
        _reuse_equal(_load(_open(original_inventory)), inventory)
    _create(root / "source-inventory.json", _json(inventory))
    _create(root / "docker-executable", _read(docker))
    _create(root / "lab-source.tar", lab_archive)
    _create(root / "native-source.tar", native_archive)
    recipe = root / "image-context/recipe"
    _create(recipe / "source-metadata.json", _json(source))
    defaults = _defaults(_read(snapshot / "Dockerfile").decode())
    build_inputs = {"artifact_type": "qcsd-study-build-inputs", "schema_version": 1,
        "cargo_lock_sha256": _sha(_read(snapshot / "neqo-qcsd/Cargo.lock")),
        "uv_lock_sha256": _sha(_read(snapshot / "uv.lock")),
        "debian_base_image": defaults["DEBIAN_IMAGE"], "rust_base_image": defaults["RUST_IMAGE"]}
    _create(recipe / "study-build-inputs.json", _json(build_inputs))
    _create(recipe / "verify_installed.py", _read(snapshot / VERIFIER_PATH))
    images = None if original is None else {role: original[role + "_image_digest"] for role in ("collection", "prepare")}
    _create(root / "image-context/Portable.Dockerfile", dockerfile_bytes(_read(snapshot / "Dockerfile"), cache_namespace=_sha(str(root).encode()), original=images))
    # Dockerfile-specific ignore takes precedence over the tracked root ignore.
    # The clean archive already excludes Git metadata and untracked caches.
    _create(root / "image-context/Portable.Dockerfile.dockerignore", b"")
    inputs = {"schema_version": 1, "artifact_type": INPUT_TYPE, "contract": CONTRACT, "source": source,
        "platform": selected_platform, "actor": f"{os.getuid()}:{os.getgid()}", "docker": reference(root / "docker-executable"),
        "docker_executable": str(docker),
        "clean_checkout": str(checkout), "source_inventory_sha256": reference(root / "source-inventory.json")["sha256"],
        "lab_archive_sha256": _sha(lab_archive), "rust_archive_sha256": _sha(native_archive),
        "cargo_lock_sha256": build_inputs["cargo_lock_sha256"], "uv_lock_sha256": build_inputs["uv_lock_sha256"],
        "producer_files": {name: reference(snapshot / name) for name in (SOURCE_PATH, CLI_PATH, VERIFIER_PATH)},
        "recipe_files": {str(path.relative_to(root)): reference(path)["sha256"] for path in (
            root / "image-context/Portable.Dockerfile", root / "image-context/Portable.Dockerfile.dockerignore",
            recipe / "source-metadata.json", recipe / "study-build-inputs.json", recipe / "verify_installed.py")},
        "mode": "cold-build" if original is None else "authenticated-client-reuse", "original_canonical": original_canonical,
        "original_source_inventory": original_inventory, "staged_at": _now(), **ZERO}
    _create(root / "build-inputs.json", _json(inputs))
    return reference(root / "build-inputs.json")


def _inputs(root, *, seen=frozenset()):
    root = _path(root, directory=True)
    inputs = _load(root / "build-inputs.json")
    _keys(inputs, INPUT_KEYS, "portable runtime inputs")
    _exact({key: inputs[key] for key in ("schema_version", "artifact_type", "contract", *ZERO)},
           {"schema_version": 1, "artifact_type": INPUT_TYPE, "contract": CONTRACT, **ZERO}, "portable input identity")
    if inputs["platform"] not in PLATFORMS or re.fullmatch(r"[0-9]+:[0-9]+", inputs["actor"]) is None:
        raise ValueError("portable runtime platform or actor differs")
    from .rapid_rolling_readiness import _clean_source, _timestamp
    _clean_source(inputs["source"])
    _timestamp(inputs["staged_at"])
    if (_open(inputs["docker"]) != root / "docker-executable" or type(inputs["docker_executable"]) is not str
        or not Path(inputs["docker_executable"]).is_absolute() or ".." in Path(inputs["docker_executable"]).parts):
        raise ValueError("portable runtime Docker executable snapshot or declared host path differs")
    snapshot = root / "image-context/source"
    inventory = _load(root / "source-inventory.json")
    if inputs["source_inventory_sha256"] != reference(root / "source-inventory.json")["sha256"] or inventory != _inventory(snapshot):
        raise ValueError("portable runtime complete source inventory changed")
    archives = {}
    for name, field, prefix in (("lab-source.tar", "lab_archive_sha256", ""), ("native-source.tar", "rust_archive_sha256", "neqo-qcsd/")):
        raw = _read(root / name)
        if _sha(raw) != inputs[field]:
            raise ValueError("portable runtime source archive changed")
        for path, (content, executable) in _archive_files(raw).items():
            key = prefix + path
            if key in archives:
                raise ValueError("portable runtime archives overlap")
            archives[key] = {"sha256": _sha(content), "executable": executable}
    _exact(archives, inventory, "portable tracked archive membership")
    if (_sha(_read(snapshot / "neqo-qcsd/Cargo.lock")) != inputs["cargo_lock_sha256"]
        or _sha(_read(snapshot / "uv.lock")) != inputs["uv_lock_sha256"]):
        raise ValueError("portable runtime dependency lock changed")
    _keys(inputs["producer_files"], {SOURCE_PATH, CLI_PATH, VERIFIER_PATH}, "portable producer sources")
    for relative, ref in inputs["producer_files"].items():
        if _open(ref) != snapshot / relative or ref["sha256"] != inventory[relative]["sha256"]:
            raise ValueError("portable runtime producer source changed")
    if _read(snapshot / SOURCE_PATH) != _read(Path(__file__).resolve()):
        raise ValueError("portable runtime executing consumer differs from its declared finite contract")
    original = None
    if inputs["mode"] == "authenticated-client-reuse":
        original, _ = _original(inputs["original_canonical"], seen=seen)
        old_inventory = _load(_open(inputs["original_source_inventory"]))
        if (inputs["original_source_inventory"] != reference(_open(inputs["original_canonical"]).parent / "source-inventory.json")
            or original["source"]["neqo_commit"] != inputs["source"]["neqo_commit"]):
            raise ValueError("portable runtime reuse substituted its original Native authority")
        _reuse_equal(old_inventory, inventory)
    elif inputs["mode"] != "cold-build" or inputs["original_canonical"] is not None or inputs["original_source_inventory"] is not None:
        raise ValueError("portable runtime has another build/reuse contract")
    images = None if original is None else {role: original[role + "_image_digest"] for role in ("collection", "prepare")}
    expected_files = {"image-context/Portable.Dockerfile", "image-context/Portable.Dockerfile.dockerignore", "image-context/recipe/source-metadata.json",
                      "image-context/recipe/study-build-inputs.json", "image-context/recipe/verify_installed.py"}
    _keys(inputs["recipe_files"], expected_files, "portable runtime generated recipe")
    for relative, digest in inputs["recipe_files"].items():
        if _sha(_read(root / relative)) != digest:
            raise ValueError("portable runtime recipe bytes changed")
    if (_read(root / "image-context/Portable.Dockerfile") != dockerfile_bytes(_read(snapshot / "Dockerfile"), cache_namespace=_sha(str(root).encode()), original=images)
        or _read(root / "image-context/Portable.Dockerfile.dockerignore") != b""
        or _load(root / "image-context/recipe/source-metadata.json") != inputs["source"]
        or _read(root / "image-context/recipe/verify_installed.py") != _read(snapshot / VERIFIER_PATH)):
        raise ValueError("portable runtime generated recipe differs from its tracked source")
    defaults = _defaults(_read(snapshot / "Dockerfile").decode())
    _exact(_load(root / "image-context/recipe/study-build-inputs.json"),
        {"artifact_type": "qcsd-study-build-inputs", "schema_version": 1, "cargo_lock_sha256": inputs["cargo_lock_sha256"],
         "uv_lock_sha256": inputs["uv_lock_sha256"], "debian_base_image": defaults["DEBIAN_IMAGE"], "rust_base_image": defaults["RUST_IMAGE"]},
        "portable installed build inputs")
    return inputs, {name: _read(snapshot / name) for name in inventory}, original


def _commands(root, inputs, images, original):
    docker, actor = "docker", inputs["actor"]
    commands = {"docker-info": [docker, "info", "--format", "{{json .}}"]}
    if original is not None:
        for role in ("collection", "prepare"):
            alias = "qcsd-portable-" + role + "-reuse:" + _sha(str(root).encode())
            commands["reuse-" + role + "-image-inspect"] = [docker, "image", "inspect", "--format", "{{json .}}", original[role + "_image_digest"]]
            commands["reuse-" + role + "-base-alias"] = [docker, "tag", original[role + "_image_digest"], alias]
            commands["reuse-" + role + "-base-inspect"] = [docker, "image", "inspect", "--format", "{{json .}}", alias]
    for role in ("collection", "prepare"):
        command = [docker, "build"] + (["--pull"] if original is None else [])
        if role == "collection" and inputs["mode"] == "cold-build":
            command.append("--no-cache")
        commands[role + "-image-build"] = command + ["--platform", inputs["platform"], "--build-context",
            "rapid-recipe=" + str(root / "image-context/recipe"), "--file", str(root / "image-context/Portable.Dockerfile"),
            "--iidfile", str(root / (role + "-image-id.txt")), "--target", "portable-" + role, str(root / "image-context/source")]
        if original is not None:
            commands["reuse-" + role + "-base-after"] = [docker, "image", "inspect", "--format", "{{json .}}",
                "qcsd-portable-" + role + "-reuse:" + _sha(str(root).encode())]
        image = images.get(role)
        if image is not None:
            if type(image) is not str or IMAGE.fullmatch(image) is None:
                raise ValueError("portable runtime role image ID is malformed")
            commands[role + "-image-inspect"] = [docker, "image", "inspect", "--format", "{{json .}}", image]
            commands[role + "-installed-verification"] = [docker, "run", "--rm", "--network", "none", "--user", actor,
                "--env", "QCSD_LAB_IMAGE_DIGEST=" + image, "--env", "QCSD_LAB_ROOT=/runtime-src",
                "--entrypoint", "/opt/qcsd-venv/bin/python3", image, "-I", "/recipe/verify_installed.py", role]
    if images.get("prepare") is not None:
        commands["actual-runtime-export"] = [docker, "run", "--rm", "--network", "none", "--read-only", "--user", actor,
            "--volume", str(root / "runtime-export") + ":/export:rw", "--entrypoint", "/opt/qcsd-venv/bin/python3",
            images["prepare"], "-I", "-c", EXPORT_PROGRAM]
    return commands


def _record(root, name, command, executable):
    _create(root / (name + "-started.json"), _json({"command": command, "executable": executable, "cwd": None, "started_at": _now()}))
    started = time.monotonic()
    error, returncode = None, None
    with (root / (name + ".stdout.log")).open("xb") as stdout, (root / (name + ".stderr.log")).open("xb") as stderr:
        try:
            returncode = subprocess.run(command, executable=executable, stdout=stdout, stderr=stderr, check=False).returncode
        except OSError as caught:
            error = type(caught).__name__
        for stream in (stdout, stderr):
            stream.flush(); os.fsync(stream.fileno())
    completed = {"returncode": returncode, "invocation_error": error, "elapsed_seconds": time.monotonic() - started,
        "completed_at": _now(), "stdout_sha256": _sha(_read(root / (name + ".stdout.log"))),
        "stderr_sha256": _sha(_read(root / (name + ".stderr.log")))}
    _create(root / (name + "-completed.json"), _json(completed))
    if returncode != 0 or error is not None:
        raise ValueError(f"portable runtime actual operation failed: {name}; preserve this namespace")


def _image(root, name, expected, selected_platform):
    observed = _load(root / (name + ".stdout.log"))
    if (observed.get("Id") != expected or observed.get("Os") != "linux"
        or architecture(observed.get("Architecture")) != selected_platform.split("/")[1]):
        raise ValueError("portable runtime inspected image identity or native architecture differs")
    _layers(observed)
    return observed


def _layers(image):
    rootfs = image.get("RootFS")
    _keys(rootfs, {"Type", "Layers"}, "portable runtime Linux image layers")
    layers = rootfs["Layers"]
    if (rootfs["Type"] != "layers" or not isinstance(layers, list) or not layers
        or any(type(layer) is not str or IMAGE.fullmatch(layer) is None for layer in layers)):
        raise ValueError("portable runtime Linux image layer identities are malformed")
    return layers


def execute(root):
    if not sys.platform.startswith("linux"):
        raise ValueError("portable rapid execution requires Linux; use a Linux VM on macOS")
    root = _path(root, directory=True)
    inputs, _, original = _inputs(root)
    if any(root.glob("*-started.json")) or (root / "canonical-runtime.json").exists():
        raise ValueError("portable runtime attempts are create-only; stage another namespace")
    _clean(Path(inputs["clean_checkout"]), inputs["source"]["lab_commit"])
    _clean(Path(inputs["clean_checkout"]) / "neqo-qcsd", inputs["source"]["neqo_commit"])
    commands = _commands(root, inputs, {}, original)
    executable = str(_open({"path": inputs["docker_executable"], "sha256": inputs["docker"]["sha256"]}))
    if not os.access(executable, os.X_OK) or inputs["actor"] != f"{os.getuid()}:{os.getgid()}":
        raise ValueError("portable runtime actual host executable or actor changed")
    _record(root, "docker-info", commands["docker-info"], executable)
    info = _load(root / "docker-info.stdout.log")
    if info.get("OSType") != "linux" or architecture(info.get("Architecture")) != inputs["platform"].split("/")[1]:
        raise ValueError("portable runtime requires its selected native Linux Docker engine")
    if original is not None:
        for role in ("collection", "prepare"):
            name = "reuse-" + role + "-image-inspect"
            _record(root, name, commands[name], executable); _image(root, name, original[role + "_image_digest"], inputs["platform"])
            _record(root, "reuse-" + role + "-base-alias", commands["reuse-" + role + "-base-alias"], executable)
            name = "reuse-" + role + "-base-inspect"
            _record(root, name, commands[name], executable); _image(root, name, original[role + "_image_digest"], inputs["platform"])
    images, checks = {}, {}
    for role in ("collection", "prepare"):
        _record(root, role + "-image-build", commands[role + "-image-build"], executable)
        if original is not None:
            name = "reuse-" + role + "-base-after"
            _record(root, name, commands[name], executable); _image(root, name, original[role + "_image_digest"], inputs["platform"])
        images[role] = _read(root / (role + "-image-id.txt")).decode().strip()
        commands = _commands(root, inputs, images, original)
        _record(root, role + "-image-inspect", commands[role + "-image-inspect"], executable)
        _image(root, role + "-image-inspect", images[role], inputs["platform"])
        _record(root, role + "-installed-verification", commands[role + "-installed-verification"], executable)
        checks[role] = _load(root / (role + "-installed-verification.stdout.log"))
    (root / "runtime-export").mkdir()
    _record(root, "actual-runtime-export", commands["actual-runtime-export"], executable)
    canonical = {"schema_version": 1, "artifact_type": TYPE, "contract": CONTRACT, "scope": SCOPE,
        "source": inputs["source"], "platform": inputs["platform"],
        **{role + "_image_digest": images[role] for role in images},
        "source_manifest": str(root / "runtime-export/source.json"), "client_binary": str(root / "runtime-export/neqo-qcsd-client"),
        "exported_source_manifest_sha256": reference(root / "runtime-export/source.json")["sha256"],
        "installed_client_sha256": reference(root / "runtime-export/neqo-qcsd-client")["sha256"],
        "source_inventory_sha256": inputs["source_inventory_sha256"], "build_inputs_sha256": reference(root / "build-inputs.json")["sha256"],
        "checks": checks, "actual_operation_completions": {}, "installed_byte_verification_completed": True,
        "native_artifact_action": "portable-source-build" if original is None else "portable-authenticated-client-reuse",
        "native_compilation_executed": original is None, "original_canonical": inputs["original_canonical"], "verified_at": _now(), **ZERO}
    for name in commands:
        end = _load(root / (name + "-completed.json"))
        canonical["actual_operation_completions"][name] = {
            "record_sha256": reference(root / (name + "-completed.json"))["sha256"],
            "started_record_sha256": reference(root / (name + "-started.json"))["sha256"], "elapsed_seconds": end["elapsed_seconds"]}
    # Validate before publication; the final immutable receipt is published only
    # after every actual operation and independently installed proof closes.
    _verify(root, canonical)
    _create(root / "canonical-runtime.json", _json(canonical))
    return reference(root / "canonical-runtime.json")


def _verify(root, value, *, seen=frozenset()):
    from .rapid_rolling_readiness import _clean_source, _timestamp
    _keys(value, CANONICAL_KEYS, "portable runtime canonical")
    _exact({key: value[key] for key in ("schema_version", "artifact_type", "contract", "scope", "installed_byte_verification_completed", *ZERO)},
        {"schema_version": 1, "artifact_type": TYPE, "contract": CONTRACT, "scope": SCOPE,
         "installed_byte_verification_completed": True, **ZERO}, "portable runtime canonical identity")
    inputs, sources, original = _inputs(root, seen=seen)
    if (value["build_inputs_sha256"] != reference(root / "build-inputs.json")["sha256"]
        or value["source_inventory_sha256"] != inputs["source_inventory_sha256"]
        or value["platform"] != inputs["platform"] or value["original_canonical"] != inputs["original_canonical"]):
        raise ValueError("portable runtime canonical changed its source, platform or input binding")
    _exact(value["source"], inputs["source"], "portable runtime source")
    _clean_source(value["source"])
    _exact({"action": value["native_artifact_action"], "compiled": value["native_compilation_executed"]},
        {"action": "portable-source-build" if original is None else "portable-authenticated-client-reuse", "compiled": original is None},
        "portable runtime actual Native build/reuse action")
    images = {role: value[role + "_image_digest"] for role in ("collection", "prepare")}
    commands = _commands(root, inputs, images, original)
    _keys(value["actual_operation_completions"], commands, "portable runtime actual operation set")
    if ({p.name.removesuffix("-started.json") for p in root.glob("*-started.json")} != set(commands)
        or {p.name.removesuffix("-completed.json") for p in root.glob("*-completed.json")} != set(commands)):
        raise ValueError("portable runtime actual operation inventory differs")
    previous = _timestamp(inputs["staged_at"])
    if original is not None and _timestamp(original["verified_at"]) > previous:
        raise ValueError("portable runtime reuse precedes its original runtime closure")
    verified = _timestamp(value["verified_at"])
    if verified > datetime.now(UTC):
        raise ValueError("portable runtime closure is in the future")
    for name, command in commands.items():
        started, completed = _load(root / (name + "-started.json")), _load(root / (name + "-completed.json"))
        _keys(started, {"command", "executable", "cwd", "started_at"}, "portable runtime actual start")
        _keys(completed, {"returncode", "invocation_error", "elapsed_seconds", "completed_at", "stdout_sha256", "stderr_sha256"}, "portable runtime actual completion")
        elapsed = completed["elapsed_seconds"]
        _exact(started["command"], command, "portable runtime actual command")
        if (started["executable"] != inputs["docker_executable"] or started["cwd"] is not None
            or type(completed["returncode"]) is not int or completed["returncode"] != 0
            or completed["invocation_error"] is not None or type(elapsed) not in {int, float} or not math.isfinite(elapsed) or elapsed < 0
            or not previous <= _timestamp(started["started_at"]) <= _timestamp(completed["completed_at"]) <= verified
            or completed["stdout_sha256"] != reference(root / (name + ".stdout.log"))["sha256"]
            or completed["stderr_sha256"] != reference(root / (name + ".stderr.log"))["sha256"]):
            raise ValueError("portable runtime actual operation failed, changed or moved in time")
        _exact(value["actual_operation_completions"][name], {
            "record_sha256": reference(root / (name + "-completed.json"))["sha256"],
            "started_record_sha256": reference(root / (name + "-started.json"))["sha256"], "elapsed_seconds": elapsed},
            "portable runtime actual completion binding")
        previous = _timestamp(completed["completed_at"])
    info = _load(root / "docker-info.stdout.log")
    if info.get("OSType") != "linux" or architecture(info.get("Architecture")) != value["platform"].split("/")[1]:
        raise ValueError("portable runtime native Docker engine differs")
    for role, image in images.items():
        if _read(root / (role + "-image-id.txt")).decode().strip() != image:
            raise ValueError("portable runtime build output image ID changed")
        installed_image = _image(root, role + "-image-inspect", image, value["platform"])
        if original is not None:
            baseline = _image(root, "reuse-" + role + "-image-inspect", original[role + "_image_digest"], value["platform"])
            for step in ("base-inspect", "base-after"):
                observed_base = _image(root, "reuse-" + role + "-" + step, original[role + "_image_digest"], value["platform"])
                _exact({key: observed_base.get(key) for key in ("Id", "Os", "Architecture", "RootFS")},
                       {key: baseline.get(key) for key in ("Id", "Os", "Architecture", "RootFS")},
                       "portable runtime stable authenticated base image inspection")
            old_layers, layers = _layers(baseline), _layers(installed_image)
            if layers[:len(old_layers)] != old_layers:
                raise ValueError("portable runtime reuse image does not retain its authenticated base layers")
        observed = _load(root / (role + "-installed-verification.stdout.log"))
        if _read(root / (role + "-installed-verification.stderr.log")) != b"":
            raise ValueError("portable runtime installed verifier emitted stderr")
        _exact(value["checks"][role], observed, "portable runtime actual installed proof")
        expected = {"schema_version": 1, "artifact_type": "qcsd-public-portable-rapid-installed-check-v1",
            "scope": "installed-runtime-byte-and-source-verification-only", "role": role,
            "source": value["source"], "image_digest": image, "platform": value["platform"],
            "client_sha256": value["installed_client_sha256"], "source_metadata_raw_sha256": value["exported_source_manifest_sha256"],
            "source_inventory_sha256": value["source_inventory_sha256"], "site_credit": 0, "formal_accepted_trace_count": 0,
            "python_runtime_payload_sha256": observed.get("python_runtime_payload_sha256"),
            "qualification_implementation_sha256": observed.get("qualification_implementation_sha256")}
        _exact(observed, expected, "portable runtime closed installed proof")
        if any(type(observed.get(key)) is not str or SHA.fullmatch(observed[key]) is None
               for key in ("python_runtime_payload_sha256", "qualification_implementation_sha256")):
            raise ValueError("portable runtime installed receipt identities are malformed")
    _keys(value["checks"], {"collection", "prepare"}, "portable runtime role checks")
    source_path, client_path = root / "runtime-export/source.json", root / "runtime-export/neqo-qcsd-client"
    if (value["source_manifest"] != str(source_path) or value["client_binary"] != str(client_path)
        or reference(source_path)["sha256"] != value["exported_source_manifest_sha256"]
        or reference(client_path)["sha256"] != value["installed_client_sha256"]
        or not client_path.stat().st_mode & 0o111
        or _load(source_path) != value["source"]
        or _read(source_path) != _read(root / "image-context/recipe/source-metadata.json")
        or value["source"]["neqo_commit"].encode() not in _read(client_path)
        or original is not None and value["installed_client_sha256"] != original["installed_client_sha256"]):
        raise ValueError("portable runtime actual executable/source export changed")
    return value, sources


def reopen_runtime(ref, runtime, *, seen=frozenset()):
    path = _open(ref)
    if str(path) in seen:
        raise ValueError("portable runtime reuse ancestry contains a cycle")
    value, sources = _verify(path.parent, _load(path), seen=seen | {str(path)})
    if (runtime["collection_image_digest"] != value["collection_image_digest"]
        or str(_path(runtime["source_manifest"])) != value["source_manifest"]
        or str(_path(runtime["client_binary"])) != value["client_binary"]
        or _inventory(runtime["runtime_source_root"]) != _load(path.parent / "source-inventory.json")
        or Path(runtime["module_root"]) != Path(runtime["runtime_source_root"])
        or _read(runtime["base_launcher"]) != sources["qcsd-lab"] or _read(runtime["host_launcher"]) != sources["qcsd-lab"]):
        raise ValueError("portable runtime consumer source, client, image or launcher differs")
    return value, sources


def verify_installed(role):
    """Executed inside the real role image, without source-package substitution."""
    from . import chaff_qualification as qualification
    from . import runtime_provenance as provenance
    from .rapid_rolling_readiness import _clean_source
    if role not in {"collection", "prepare"}:
        raise ValueError("portable runtime installed role differs")
    image = os.environ.get("QCSD_LAB_IMAGE_DIGEST")
    if type(image) is not str or IMAGE.fullmatch(image) is None:
        raise ValueError("portable installed verifier lacks an actual image identity")
    root = _path("/runtime-src", directory=True)
    source_path = Path("/usr/share/qcsd-lab/source.json")
    source = _clean_source(_load(source_path))
    inventory = _inventory(root)
    if _read(Path(__file__).resolve()) != _read(root / SOURCE_PATH):
        raise ValueError("portable installed verifier is not the declared source module")
    if _read("/recipe/verify_installed.py") != _read(root / VERIFIER_PATH):
        raise ValueError("portable installed verifier transport differs from its tracked source")
    python = provenance.validate_runtime_receipt(required_schema_version=provenance.RUNTIME_RECEIPT_SCHEMA_VERSION)
    implementation = qualification.implementation_receipt(executed_image=True)
    if python["source"] != source or implementation["source"] != source:
        raise ValueError("portable installed Python/qualification receipts differ from the current source")
    for path, record in python["installed_modules"].items():
        if record["sha256"] != inventory[path]["sha256"] or stat.S_IMODE(_path(record["path"]).stat().st_mode) != 0o644:
            raise ValueError("portable installed module bytes or full mode differ from clean source")
    for path, digest in implementation["source_files"].items():
        if inventory[path]["sha256"] != digest:
            raise ValueError("portable qualification source differs from complete source inventory")
    client = _path("/usr/local/bin/neqo-qcsd-client")
    client_sha = _sha(_read(client))
    if (not client.stat().st_mode & 0o111 or implementation["neqo_qcsd_client"]["sha256"] != client_sha
        or source["neqo_commit"].encode() not in _read(client)):
        raise ValueError("portable installed Native executable differs from its declared actual source")
    return {"schema_version": 1, "artifact_type": "qcsd-public-portable-rapid-installed-check-v1",
        "scope": "installed-runtime-byte-and-source-verification-only", "role": role, "source": source,
        "image_digest": image, "platform": "linux/" + architecture(platform.machine()), "client_sha256": client_sha,
        "source_metadata_raw_sha256": _sha(_read(source_path)), "source_inventory_sha256": _sha(_json(inventory)),
        "python_runtime_payload_sha256": python["payload_sha256"], "qualification_implementation_sha256": implementation["sha256"],
        "site_credit": 0, "formal_accepted_trace_count": 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    create = actions.add_parser("stage")
    for name in ("checkout", "build-root"):
        create.add_argument("--" + name, type=Path, required=True)
    create.add_argument("--lab-commit", required=True)
    create.add_argument("--native-commit", required=True)
    create.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    create.add_argument("--docker", type=Path, default=Path(shutil.which("docker") or "/usr/bin/docker"))
    create.add_argument("--reuse-canonical", type=Path)
    create.add_argument("--reuse-canonical-sha256")
    build = actions.add_parser("build")
    build.add_argument("--build-root", type=Path, required=True)
    verify = actions.add_parser("verify")
    verify.add_argument("--canonical", type=Path, required=True)
    verify.add_argument("--canonical-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "stage":
            if (args.reuse_canonical is None) != (args.reuse_canonical_sha256 is None):
                raise ValueError("portable reuse requires an explicit canonical file and digest")
            original = None if args.reuse_canonical is None else {"path": str(args.reuse_canonical), "sha256": args.reuse_canonical_sha256}
            result = stage(args.checkout, args.lab_commit, args.native_commit, args.build_root,
                           selected_platform=args.platform, docker=args.docker, original_canonical=original)
        elif args.action == "build":
            result = execute(args.build_root)
        else:
            ref = {"path": str(args.canonical), "sha256": args.canonical_sha256}
            path = _open(ref)
            value, _ = _verify(path.parent, _load(path), seen=frozenset({str(path)}))
            result = {"canonical": ref, "platform": value["platform"], "client_sha256": value["installed_client_sha256"], **ZERO}
        print(json.dumps({"operation": args.action, "status": "closed", "result": result, **ZERO}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({"operation": args.action, "status": "refused", "error_type": type(error).__name__, "error_message": str(error), **ZERO}, sort_keys=True))
        return 1
