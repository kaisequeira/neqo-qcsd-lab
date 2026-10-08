#!/usr/bin/env python3
"""Create and verify a source-only handoff; never build or launch a runtime."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import tarfile
from urllib.parse import urlsplit

TYPE = "qcsd-resource-study-source-handoff-v1"
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
ARTIFACTS = {"source.tar.gz", "supplied-resources.json", "CHECKOUT.md"}
FILES = ARTIFACTS | {"manifest.json", "SHA256SUMS"}
LIMIT = 512 * 1024 * 1024


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _load(raw):
    def nonfinite(_):
        raise ValueError("nonfinite JSON value")
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=nonfinite)


def _path(value, *, directory=False, fresh=False):
    value = Path(value)
    if ".." in value.parts:
        raise ValueError("path contains parent traversal")
    path = value.absolute()
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("path contains a symbolic link")
    if fresh:
        if path.exists() or not path.parent.is_dir():
            raise ValueError("output must be absent with an existing parent")
    elif not (path.is_dir() if directory else path.is_file()):
        raise ValueError("expected a regular file or directory")
    if not directory and not fresh and path.stat().st_nlink != 1:
        raise ValueError("input file has additional hard links")
    return path


def _git(root, *args):
    # Do not let a caller's GIT_DIR, alternate index or replacement objects
    # change the repository selected by the explicit checkout argument.
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0",
               GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env).stdout


def _remote(value):
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        raise ValueError("origin must be a portable remote without whitespace")
    if re.fullmatch(r"[A-Za-z0-9_.-]+@[A-Za-z0-9.-]+:[A-Za-z0-9_./-]+", value):
        return value
    parsed = urlsplit(value)
    if (parsed.scheme not in {"https", "ssh"} or not parsed.hostname or not parsed.path
            or parsed.password is not None or (parsed.scheme == "https" and parsed.username is not None)
            or parsed.query or parsed.fragment):
        raise ValueError("origin must be an HTTPS or SSH remote without embedded secrets")
    return value


def source_identity(root, lab_commit, native_commit):
    root = _path(root, directory=True)
    native = _path(root / "neqo-qcsd", directory=True)
    for directory, expected in ((root, lab_commit), (native, native_commit)):
        if not isinstance(expected, str) or COMMIT.fullmatch(expected) is None:
            raise ValueError("source commits must be full lowercase Git object IDs")
        if _git(directory, "rev-parse", "--show-toplevel").decode().strip() != str(directory):
            raise ValueError("source path is not its repository root")
        if _git(directory, "rev-parse", "HEAD").decode().strip() != expected:
            raise ValueError("source HEAD differs from the declared commit")
        if _git(directory, "status", "--porcelain=v1", "--untracked-files=all",
                "--ignore-submodules=none"):
            raise ValueError("source checkout is dirty, including untracked files")
    links = [line for line in _git(root, "ls-tree", "-r", lab_commit).splitlines()
             if line.startswith(b"160000 ")]
    expected = f"160000 commit {native_commit}\tneqo-qcsd".encode()
    if links != [expected] or any(line.startswith(b"160000 ") for line in
                                 _git(native, "ls-tree", "-r", native_commit).splitlines()):
        raise ValueError("Gitlink differs or an unarchived nested submodule exists")
    return {"lab": {"commit": lab_commit, "remote": _remote(_git(root, "remote", "get-url", "origin").decode().strip())},
            "native": {"commit": native_commit, "remote": _remote(_git(native, "remote", "get-url", "origin").decode().strip())},
            "gitlink": native_commit}


def _members(raw):
    """Inspect without extracting. Only ordinary committed files/directories."""
    inventory = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        total = 0
        for member in archive:
            name = member.name.rstrip("/")
            parts = PurePosixPath(name).parts
            if (not parts or parts[0] != "source" or ".." in parts or ".git" in parts
                    or name != PurePosixPath(name).as_posix() or "\\" in name
                    or not (member.isdir() or member.isfile())
                    or member.mode & ~0o777 or member.size < 0):
                raise ValueError("source archive contains an unsafe member")
            item = {"kind": "directory" if member.isdir() else "file", "mode": member.mode}
            if member.isfile():
                total += member.size
                if total > LIMIT:
                    raise ValueError("source archive exceeds its byte limit")
                content = archive.extractfile(member).read()
                if len(content) != member.size:
                    raise ValueError("source archive member is truncated")
                item.update(size=len(content), sha256=_sha(content))
            if name in inventory:
                raise ValueError("source archive repeats a member")
            inventory[name] = item
    if not any(name.startswith("source/neqo-qcsd/") and item["kind"] == "file"
               for name, item in inventory.items()):
        raise ValueError("Native source archive is missing")
    for name in inventory:
        for parent in PurePosixPath(name).parents:
            if parent.as_posix() in inventory and inventory[parent.as_posix()]["kind"] != "directory":
                raise ValueError("source archive places a member beneath a file")
    return inventory


def _archive(root, source):
    output = io.BytesIO()
    seen = set()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as target:
        for directory, commit, prefix in ((root, source["lab"]["commit"], "source/"),
                                         (root / "neqo-qcsd", source["native"]["commit"], "source/neqo-qcsd/")):
            raw = _git(directory, "archive", "--format=tar", "--prefix=" + prefix, commit)
            if len(raw) > LIMIT:
                raise ValueError("Git source archive exceeds its byte limit")
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                for member in archive:
                    name = member.name.rstrip("/")
                    if name in seen and member.isdir():
                        continue  # The Gitlink directory is supplied by both archives.
                    seen.add(name)
                    target.addfile(member, archive.extractfile(member) if member.isfile() else None)
    raw = output.getvalue()
    if len(raw) > LIMIT:
        raise ValueError("combined source archive exceeds its byte limit")
    inventory = _members(raw)
    return gzip.compress(raw, mtime=0), inventory


def _checkout(source):
    lab, native = source["lab"], source["native"]
    return f"""# Restore the Git checkout

This package is source and raw input only, with zero scientific credit.
`source.tar.gz` is a review/archive copy, NOT a Git checkout. Do not initialize
a new repository from the tar and claim the recorded commits. The runtime
producer requires the original clean Git commits and exact Native Gitlink.
The package contains no images, binary, environment, ledger or capture data.
The pinned commits must first be published and reachable from these remotes.

Run in a fresh Linux directory with Git/network access:

```sh
git clone --no-checkout -- {shlex.quote(lab['remote'])} qcsd-lab-source
git -C qcsd-lab-source checkout --detach {lab['commit']}
git -C qcsd-lab-source submodule update --init --recursive
test "$(git -C qcsd-lab-source rev-parse HEAD)" = {lab['commit']}
test "$(git -C qcsd-lab-source/neqo-qcsd rev-parse HEAD)" = {native['commit']}
test -z "$(git -C qcsd-lab-source status --porcelain --untracked-files=all)"
test -z "$(git -C qcsd-lab-source/neqo-qcsd status --porcelain --untracked-files=all)"
```

Declared Native origin: `{native['remote']}`. The Lab commit's `.gitmodules`
controls submodule cloning. If the pinned commits are unavailable, stop; this
archive alone cannot restore Git identity. Separately authenticated Git bundles
may be supplied by the owner if offline restoration is required.

Follow `qcsd-lab-source/docs/MAC-MIGRATION.md` for Linux ARM64 preparation and
a fresh capability/mode pilot. No Mac or runtime compatibility is certified by
this package. Keep the supplied JSON outside the source checkout.
""".encode()


def _write(path, raw):
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fchmod(handle.fileno(), 0o444)
        os.fsync(handle.fileno())


def _sums(manifest, raw_manifest):
    entries = {name: ref["sha256"] for name, ref in manifest["artifacts"].items()}
    entries["manifest.json"] = _sha(raw_manifest)
    return "".join(f"{entries[name]}  {name}\n" for name in sorted(entries)).encode()


def create(source_root, lab_commit, native_commit, resources, resources_sha256, output):
    root = _path(source_root, directory=True)
    resources = _path(resources)
    output = _path(output, fresh=True)
    if output == root or root in output.parents:
        raise ValueError("handoff output must be outside the source checkout")
    identity = source_identity(root, lab_commit, native_commit)
    raw_resources = resources.read_bytes()
    if (len(raw_resources) > 16 * 1024 * 1024 or SHA.fullmatch(resources_sha256 or "") is None
            or _sha(raw_resources) != resources_sha256):
        raise ValueError("supplied resource bytes differ from their declared digest")
    value = _load(raw_resources)
    if not isinstance(value, list) or not value:
        raise ValueError("supplied resources must be a nonempty JSON list")
    archive, inventory = _archive(root, identity)
    artifacts = {"source.tar.gz": archive, "supplied-resources.json": raw_resources,
                 "CHECKOUT.md": _checkout(identity)}
    # Reopen both repositories and input bytes before publishing any output.
    if source_identity(root, lab_commit, native_commit) != identity or resources.read_bytes() != raw_resources:
        raise ValueError("source or supplied input changed while packaging")
    manifest = {"schema_version": 1, "artifact_type": TYPE, "scientific_credit": False,
                "archive_is_git_checkout": False, "scope": "source-and-input-only",
                "source": identity, "source_members": inventory,
                "artifacts": {name: {"sha256": _sha(raw), "size": len(raw), "mode": 0o444}
                              for name, raw in artifacts.items()}}
    output.mkdir(mode=0o700)
    # A failed creation remains an incomplete claimed destination; never replace it.
    for name, raw in artifacts.items():
        _write(output / name, raw)
    raw_manifest = _json(manifest)
    _write(output / "manifest.json", raw_manifest)
    _write(output / "SHA256SUMS", _sums(manifest, raw_manifest))
    return {"package": str(output), "manifest_sha256": _sha(raw_manifest),
            "source": identity, "scientific_credit": False}


def verify(package, manifest_sha256):
    root = _path(package, directory=True)
    if SHA.fullmatch(manifest_sha256 or "") is None or {path.name for path in root.iterdir()} != FILES:
        raise ValueError("package inventory or expected manifest digest differs")
    raws = {}
    for name in FILES:
        path = _path(root / name)
        if stat.S_IMODE(path.stat().st_mode) != 0o444 or path.stat().st_size > LIMIT:
            raise ValueError("package artifact mode or byte limit differs")
        raws[name] = path.read_bytes()
    if _sha(raws["manifest.json"]) != manifest_sha256:
        raise ValueError("manifest differs from its externally recorded digest")
    manifest = _load(raws["manifest.json"])
    if (set(manifest) != {"schema_version", "artifact_type", "scientific_credit", "archive_is_git_checkout",
                         "scope", "source", "source_members", "artifacts"}
            or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1
            or manifest["artifact_type"] != TYPE or manifest["scientific_credit"] is not False
            or manifest["archive_is_git_checkout"] is not False or manifest["scope"] != "source-and-input-only"
            or set(manifest["artifacts"]) != ARTIFACTS):
        raise ValueError("source handoff contract differs")
    source = manifest["source"]
    if set(source) != {"lab", "native", "gitlink"}:
        raise ValueError("source identity fields differ")
    for role in ("lab", "native"):
        if (set(source[role]) != {"commit", "remote"} or COMMIT.fullmatch(source[role]["commit"]) is None):
            raise ValueError("source commit identity differs")
        _remote(source[role]["remote"])
    if source["gitlink"] != source["native"]["commit"]:
        raise ValueError("Native Gitlink differs")
    for name in ARTIFACTS:
        expected = {"sha256": _sha(raws[name]), "size": len(raws[name]), "mode": 0o444}
        if _json(manifest["artifacts"][name]) != _json(expected):
            raise ValueError("package artifact bytes or metadata differ")
    if raws["SHA256SUMS"] != _sums(manifest, raws["manifest.json"]) or raws["CHECKOUT.md"] != _checkout(source):
        raise ValueError("package checksums or checkout instructions differ")
    # Bound decompression before parsing; never extract a source archive here.
    with gzip.GzipFile(fileobj=io.BytesIO(raws["source.tar.gz"])) as zipped:
        raw_tar = zipped.read(LIMIT + 1)
    if len(raw_tar) > LIMIT or _json(_members(raw_tar)) != _json(manifest["source_members"]):
        raise ValueError("source member inventory differs")
    value = _load(raws["supplied-resources.json"])
    if not isinstance(value, list) or not value:
        raise ValueError("supplied resource JSON differs")
    return {"status": "verified", "manifest_sha256": manifest_sha256,
            "source": source, "scientific_credit": False, "runtime_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    create_parser = actions.add_parser("create")
    for name in ("source", "resources", "output"):
        create_parser.add_argument("--" + name, type=Path, required=True)
    for name in ("lab-commit", "native-commit", "resources-sha256"):
        create_parser.add_argument("--" + name, required=True)
    verify_parser = actions.add_parser("verify")
    verify_parser.add_argument("--package", type=Path, required=True)
    verify_parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        result = (create(args.source, args.lab_commit, args.native_commit, args.resources,
                         args.resources_sha256, args.output) if args.action == "create"
                  else verify(args.package, args.manifest_sha256))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "refused", "reason": str(error), "scientific_credit": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
