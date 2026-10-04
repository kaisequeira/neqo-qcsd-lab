#!/usr/bin/env python3
"""Stage clean source, then explicitly build a cached native runtime successor.

The default staging action never runs Docker. Build actions retain actual
commands, exit codes and logs, and refuse to overwrite prior results.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parent
WORKSPACE = ROOT.parent.parent
TOOLCHAIN = "sha256:522f5fba4fb44c7fe43876385a6f94506b22106920b69d6eba72fd4431fe53f0"
COLLECTION = "sha256:fc3608b0919ee2486d2c6ad0cf03f77551972195b6800fd6c59f193a243b8ad4"
PREPARE = "sha256:bd992abbd054dd2ed1ce35c3af3fbd14dfb002c58b4cb03ac4e9df16e50ec6ab"
DEFAULT_TARGET = WORKSPACE / "neqo-qcsd-lab/artifacts/rapid-csbuflo-regression-20261002/target"
DEFAULT_REGISTRY = WORKSPACE / "diagnostic-rust-build/registry"
DEFAULT_GIT_CACHE = WORKSPACE / "diagnostic-rust-build/git"
EMPTY_SHA = hashlib.sha256(b"").hexdigest()
GIT_ENV = dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_CONFIG_GLOBAL="/dev/null",
               GIT_CONFIG_SYSTEM="/dev/null", GIT_OPTIONAL_LOCKS="0")


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def create(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def json_create(path, value):
    create(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def git(checkout, *args):
    return subprocess.run(["git", "-C", str(checkout), *args], env=GIT_ENV,
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def clean_identity(checkout, expected):
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise ValueError("expected source commit must be a full lowercase Git SHA")
    actual = git(checkout, "rev-parse", "HEAD").decode().strip()
    if actual != expected:
        raise ValueError(f"source HEAD does not match requested commit: {actual}")
    if git(checkout, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError(f"source checkout is dirty: {checkout}")
    return actual


def archive(checkout, commit, destination):
    """Extract exact tracked commit bytes; Git metadata and build caches excluded."""
    raw = git(checkout, "archive", "--format=tar", commit)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(raw)) as bundle:
        for member in bundle.getmembers():
            relative = Path(member.name)
            if relative.is_absolute() or ".." in relative.parts or member.isdev() or member.islnk():
                raise ValueError("source archive contains an unsupported member")
            if member.issym():
                # The Git archives used here have only in-tree links. Preserve
                # valid source links, but never permit an escape from the snapshot.
                target = relative.parent / member.linkname
                if Path(member.linkname).is_absolute() or ".." in target.parts:
                    raise ValueError("source archive contains an escaping symlink")
        bundle.extractall(destination)
    return hashlib.sha256(raw).hexdigest()


def require_directory(path, label):
    path = Path(path).resolve(strict=True)
    if not path.is_dir() or path.is_symlink():
        raise ValueError(f"{label} is not a regular directory")
    return path


def source_inventory(root):
    files = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            files[relative] = {"symlink": os.readlink(path)}
        elif path.is_file():
            files[relative] = {"sha256": sha(path), "executable": bool(path.stat().st_mode & 0o111)}
    return files


def check_context(root):
    inputs = json.loads((root / "build-inputs.json").read_bytes())
    context = root / "image-context"
    if (context / "build-inputs.json").read_bytes() != (root / "build-inputs.json").read_bytes():
        raise ValueError("staged image build inputs changed")
    inventory = json.loads((root / "source-inventory.json").read_bytes())
    if (sha(root / "source-inventory.json") != inputs["source_inventory_sha256"]
        or source_inventory(context / "source") != inventory):
        raise ValueError("staged clean source inventory changed after publication")
    if json.loads((context / "source-metadata.json").read_bytes()) != inputs["source"]:
        raise ValueError("staged source metadata differs from validated clean commits")
    for name, expected in inputs["recipe_files"].items():
        if sha(context / name) != expected:
            raise ValueError("staged derivative recipe changed")
    return inputs


def stage(args):
    checkout = Path(args.lab_checkout).resolve(strict=True)
    lab = clean_identity(checkout, args.lab_commit)
    rust_root = checkout / "neqo-qcsd"
    rust = clean_identity(rust_root, args.rust_commit)
    gitlink = git(checkout, "ls-files", "--stage", "--", "neqo-qcsd").decode().strip().split()
    if len(gitlink) != 4 or gitlink[0] != "160000" or gitlink[1] != rust or gitlink[2] != "0":
        raise ValueError("clean Lab Gitlink does not pin the supplied clean Rust commit")
    target = require_directory(args.target, "cached Cargo target")
    if not (target / "release/neqo-qcsd-client").is_file():
        raise ValueError("requested Cargo target does not contain the observed release cache")
    registry = require_directory(args.registry, "cached Cargo registry")
    git_cache = require_directory(args.git_cache, "cached Cargo Git dependencies")
    destination = Path(args.build_root).absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("build namespace is create-only; choose another build-root")
    # Check before creating any new namespace. Thin derivatives retain exact
    # dependencies from these bases; dependency changes require a different recipe.
    previous = WORKSPACE / "rapid-execution-csfix-20261002"
    for relative in ("pyproject.toml", "uv.lock"):
        if (checkout / relative).read_bytes() != (previous / relative).read_bytes():
            raise ValueError(f"thin runtime base dependencies differ: {relative}")
    destination.mkdir(parents=True)
    context = destination / "image-context"
    context.mkdir()
    lab_archive = archive(checkout, lab, context / "source")
    rust_archive = archive(rust_root, rust, context / "source/neqo-qcsd")
    clean_identity(checkout, lab)
    clean_identity(rust_root, rust)
    json_create(destination / "source-inventory.json", source_inventory(context / "source"))
    source = {
        "image_digest": None, "lab_commit": lab, "lab_dirty": False,
        "lab_patch_sha256": EMPTY_SHA, "neqo_commit": rust,
        "neqo_pinned_commit": rust, "neqo_dirty": False, "neqo_patch_sha256": EMPTY_SHA,
    }
    json_create(context / "source-metadata.json", source)
    recipe_names = ("Collection.Dockerfile", "Prepare.Dockerfile", "generate_receipts.py", "verify_installed.py")
    for name in recipe_names:
        create(context / name, (ROOT / name).read_bytes())
    record = {
        "artifact_type": "qcsd-application-response-runtime-build-inputs", "schema_version": 1,
        "staged_at": now(), "source": source,
        "clean_checkout": str(checkout), "lab_archive_sha256": lab_archive,
        "rust_archive_sha256": rust_archive, "toolchain_image": TOOLCHAIN,
        "source_inventory_sha256": sha(destination / "source-inventory.json"),
        "collection_base_image": COLLECTION, "prepare_base_image": PREPARE,
        "registry": str(registry), "git_cache": str(git_cache), "target": str(target),
        "cached_release_before_sha256": sha(target / "release/neqo-qcsd-client"),
        "cargo_lock_sha256": sha(context / "source/neqo-qcsd/Cargo.lock"),
        "uv_lock_sha256": sha(context / "source/uv.lock"),
        "recipe_files": {name: sha(context / name) for name in recipe_names},
        "recipe_driver_sha256": sha(__file__), "scientific_credit": False,
        "qualification_state": "not-executed", "formal_accepted_trace_count": 0,
    }
    json_create(destination / "build-inputs.json", record)
    create(context / "build-inputs.json", (destination / "build-inputs.json").read_bytes())
    release_command = [
        "docker", "run", "--rm", "--name", f"qcsd-response-release-{lab[:12]}",
        "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}",
        "--volume", f"{context / 'source/neqo-qcsd'}:/source:ro",
        "--volume", f"{registry}:/usr/local/cargo/registry",
        "--volume", f"{git_cache}:/usr/local/cargo/git",
        "--volume", f"{target}:/target", "--workdir", "/source",
        "--env", "CARGO_TARGET_DIR=/target", "--env", f"NEQO_QCSD_GIT_COMMIT={rust}",
        "--entrypoint", "/bin/sh", TOOLCHAIN, "-c",
        "cargo build --locked --offline --release -p neqo-bin --features qcsd --bin neqo-qcsd-client",
    ]
    json_create(destination / "release-command.json", release_command)
    print(json.dumps({"build_root": str(destination), "source": source, "docker_executed": False}, sort_keys=True))


def recorded_run(command, root, name, *, cwd=None):
    marker = root / f"{name}-started.json"
    json_create(marker, {"command": command, "started_at": now(), "cwd": str(cwd) if cwd else None})
    start = time.monotonic()
    with (root / f"{name}.stdout.log").open("xb") as stdout, (root / f"{name}.stderr.log").open("xb") as stderr:
        result = subprocess.run(command, cwd=cwd, stdout=stdout, stderr=stderr)
    json_create(root / f"{name}-completed.json", {
        "returncode": result.returncode, "completed_at": now(),
        "elapsed_seconds": time.monotonic() - start,
        "stdout_sha256": sha(root / f"{name}.stdout.log"),
        "stderr_sha256": sha(root / f"{name}.stderr.log"),
    })
    if result.returncode:
        raise RuntimeError(f"{name} failed with exit {result.returncode}; preserved logs are under {root}")


def build_client(args):
    root = Path(args.build_root).resolve(strict=True)
    inputs = check_context(root)
    context = root / "image-context"
    command = json.loads((root / "release-command.json").read_bytes())
    recorded_run(command, root, "release-build")
    binary = Path(inputs["target"]) / "release/neqo-qcsd-client"
    # This is a cheap embed check, not a claim of runtime response qualification.
    if inputs["source"]["neqo_commit"].encode() not in binary.read_bytes():
        raise ValueError("release binary does not contain the requested embedded source commit")
    create(context / "neqo-qcsd-client", binary.read_bytes())
    (context / "neqo-qcsd-client").chmod(0o755)
    record = {"artifact_type": "qcsd-application-response-client-build", "schema_version": 1,
              "source": inputs["source"], "toolchain_image": TOOLCHAIN,
              "client_sha256": sha(context / "neqo-qcsd-client"),
              "release_command_sha256": sha(root / "release-command.json"),
              "release_completion": json.loads((root / "release-build-completed.json").read_bytes()),
              "scientific_credit": False, "runtime_qualification": "not-executed"}
    json_create(root / "client-build.json", record)
    create(context / "client-build.json", (root / "client-build.json").read_bytes())
    print(json.dumps(record, sort_keys=True))


def build_images(args):
    root = Path(args.build_root).resolve(strict=True)
    inputs = check_context(root)
    client = json.loads((root / "client-build.json").read_bytes())
    context = root / "image-context"
    if sha(context / "neqo-qcsd-client") != client["client_sha256"] or client["source"] != inputs["source"]:
        raise ValueError("image context client/source differs from the actual recorded build")
    for role in ("collection", "prepare"):
        base = inputs[f"{role}_base_image"]
        alias = f"qcsd-response-base-{role}:{base.removeprefix('sha256:')}"
        recorded_run(["docker", "image", "tag", base, alias], root, f"{role}-base-alias")
        inspect = ["docker", "image", "inspect", "--format", "{{.Id}}", alias]
        recorded_run(inspect, root, f"{role}-base-before")
        if (root / f"{role}-base-before.stdout.log").read_text().strip() != base:
            raise ValueError("BuildKit local base alias differs from the immutable recorded base")
        imagefile = root / f"{role}-image-id.txt"
        command = ["docker", "build", "--pull=false", "--network", "none", "--file", f"{role.title()}.Dockerfile",
                   "--iidfile", str(imagefile), "--tag", f"qcsd-{role}:response-policy-{inputs['source']['lab_commit'][:12]}",
                   "--build-arg", f"LAB_COMMIT={inputs['source']['lab_commit']}",
                   "--build-arg", f"NEQO_COMMIT={inputs['source']['neqo_commit']}", "."]
        recorded_run(command, root, f"{role}-image-build", cwd=context)
        recorded_run(inspect, root, f"{role}-base-after")
        if (root / f"{role}-base-after.stdout.log").read_text().strip() != base:
            raise ValueError("BuildKit local base alias changed during derivative build")
        image = imagefile.read_text().strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise ValueError("Docker did not return an immutable runtime image identity")
        # Installed-byte verification is independent of response/chaff canaries.
        verify = ["docker", "run", "--rm", "--network", "none", "--user", "1000:1000",
                  "--env", f"QCSD_LAB_IMAGE_DIGEST={image}", "--env", "QCSD_LAB_ROOT=/runtime-src",
                  "--entrypoint", "/opt/qcsd-venv/bin/python3", image,
                  "-I", "/recipe/verify_installed.py", role]
        recorded_run(verify, root, f"{role}-installed-verification")
    print(json.dumps({"build_root": str(root), "state": "installed-bytes-verified",
                      "qualification_state": "not-executed", "scientific_credit": False}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    staged = actions.add_parser("stage", help="Create clean source/image context; never run Docker")
    staged.add_argument("--lab-checkout", required=True)
    staged.add_argument("--lab-commit", required=True)
    staged.add_argument("--rust-commit", required=True)
    staged.add_argument("--build-root", required=True)
    staged.add_argument("--target", default=str(DEFAULT_TARGET))
    staged.add_argument("--registry", default=str(DEFAULT_REGISTRY))
    staged.add_argument("--git-cache", default=str(DEFAULT_GIT_CACHE))
    staged.set_defaults(function=stage)
    for action, function in (("build-client", build_client), ("build-images", build_images)):
        command = actions.add_parser(action, help="Explicit Docker execution; retain actual commands/results")
        command.add_argument("--build-root", required=True)
        command.set_defaults(function=function)
    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
