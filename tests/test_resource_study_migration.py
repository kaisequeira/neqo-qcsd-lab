"""Source handoff controls; Git/archives are controlled, no repository is changed."""
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tarfile

import pytest

SPEC = importlib.util.spec_from_file_location(
    "resource_study_migration", Path(__file__).resolve().parents[1] / "tools/resource_study_migration.py")
migration = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(migration)
LAB = "1" * 40
NATIVE = "2" * 40


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, content, mode in entries:
            member = tarfile.TarInfo(name)
            member.mode = mode
            if content is None:
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            else:
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


@pytest.fixture
def case(tmp_path, monkeypatch):
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "neqo-qcsd").mkdir()
    source = tmp_path / "resources.json"
    raw = b'[{"crUX_domain":"page.example","resources":[{"resource_domain":"cdn.example","resource_urls":["https://cdn.example/th?id=A&v=1"]}]}]\n'
    source.write_bytes(raw)
    commands = []

    def git(directory, *args):
        commands.append((directory, args))
        native = directory == root / "neqo-qcsd"
        commit = NATIVE if native else LAB
        if args == ("rev-parse", "--show-toplevel"):
            return (str(directory) + "\n").encode()
        if args == ("rev-parse", "HEAD"):
            return (commit + "\n").encode()
        if args[0] == "status":
            return b""
        if args[0] == "ls-tree":
            return (b"100644 blob " + b"a" * 40 + b"\tCargo.lock\n" if native else
                    f"160000 commit {NATIVE}\tneqo-qcsd\n".encode())
        if args == ("remote", "get-url", "origin"):
            return ("https://example.org/native.git\n" if native else
                    "git@example.org:lab.git\n").encode()
        if args[0] == "archive":
            prefix = args[2].removeprefix("--prefix=")
            if native:
                return tar_bytes([(prefix, None, 0o755),
                                  (prefix + "Cargo.lock", b"native lock\n", 0o644),
                                  (prefix + "client.rs", b"fn main() {}\n", 0o644)])
            return tar_bytes([(prefix, None, 0o755),
                              (prefix + "neqo-qcsd/", None, 0o755),
                              (prefix + "qcsd-lab", b"#!/bin/sh\n", 0o755),
                              (prefix + "uv.lock", b"python lock\n", 0o644)])
        raise AssertionError(f"unexpected Git command {args}")

    monkeypatch.setattr(migration, "_git", git)
    output = tmp_path / "handoff"
    return {"root": root, "source": source, "raw": raw, "output": output,
            "git": git, "commands": commands}


def create(case):
    return migration.create(case["root"], LAB, NATIVE, case["source"],
                            hashlib.sha256(case["raw"]).hexdigest(), case["output"])


def rewrite_manifest(case, mutate):
    path = case["output"] / "manifest.json"
    value = json.loads(path.read_bytes())
    mutate(value)
    raw = migration._json(value)
    path.chmod(0o644)
    path.write_bytes(raw)
    path.chmod(0o444)
    sums = case["output"] / "SHA256SUMS"
    sums.chmod(0o644)
    sums.write_bytes(migration._sums(value, raw))
    sums.chmod(0o444)
    return hashlib.sha256(raw).hexdigest()


def replace_artifact(case, name, raw):
    path = case["output"] / name
    path.chmod(0o644)
    path.write_bytes(raw)
    path.chmod(0o444)
    return rewrite_manifest(case, lambda manifest: manifest["artifacts"][name].update(
        sha256=hashlib.sha256(raw).hexdigest(), size=len(raw)))


def test_complete_package_is_source_only_preserves_input_and_executable_mode(case):
    result = create(case)
    checked = migration.verify(case["output"], result["manifest_sha256"])
    assert checked["scientific_credit"] is False and checked["runtime_verified"] is False
    assert checked["source"]["native"]["commit"] == NATIVE
    assert (case["output"] / "supplied-resources.json").read_bytes() == case["raw"]
    manifest = json.loads((case["output"] / "manifest.json").read_bytes())
    assert manifest["archive_is_git_checkout"] is False
    assert manifest["source_members"]["source/qcsd-lab"]["mode"] == 0o755
    assert manifest["source_members"]["source/neqo-qcsd/client.rs"]["sha256"] == (
        hashlib.sha256(b"fn main() {}\n").hexdigest())
    assert set(path.name for path in case["output"].iterdir()) == migration.FILES
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o444 for path in case["output"].iterdir())
    text = (case["output"] / "CHECKOUT.md").read_text()
    assert "NOT a Git checkout" in text and LAB in text and NATIVE in text
    assert "submodule update --init --recursive" in text
    assert all(command[0] in {"rev-parse", "status", "ls-tree", "remote", "archive"}
               for _, command in case["commands"])


def test_create_only_output_does_not_replace_previous_package(case):
    create(case)
    first = (case["output"] / "manifest.json").read_bytes()
    with pytest.raises(ValueError, match="output must be absent"):
        create(case)
    assert (case["output"] / "manifest.json").read_bytes() == first


@pytest.mark.parametrize("role,mutation", [
    ("lab", "dirty"), ("native", "dirty"), ("lab", "head"), ("native", "head"),
    ("lab", "root"), ("native", "root"), ("lab", "gitlink"), ("native", "nested"),
])
def test_source_refusals_before_output_creation(case, monkeypatch, role, mutation):
    def git(directory, *args):
        selected = (directory == case["root"] / "neqo-qcsd") == (role == "native")
        if selected:
            if args[0] == "status" and mutation == "dirty":
                return b"?? extra.py\n"
            if args == ("rev-parse", "HEAD") and mutation == "head":
                return b"3" * 40 + b"\n"
            if args == ("rev-parse", "--show-toplevel") and mutation == "root":
                return b"/other/checkout\n"
            if args[0] == "ls-tree" and mutation in {"gitlink", "nested"}:
                return b"160000 commit " + b"3" * 40 + b"\tother\n"
        return case["git"](directory, *args)
    monkeypatch.setattr(migration, "_git", git)
    with pytest.raises(ValueError):
        create(case)
    assert not case["output"].exists()


def test_final_source_reopen_refuses_mid_archive_change(case, monkeypatch):
    archived = False
    def git(directory, *args):
        nonlocal archived
        if args[0] == "archive":
            archived = True
        if archived and args[0] == "status":
            return b" M changed.py\n"
        return case["git"](directory, *args)
    monkeypatch.setattr(migration, "_git", git)
    with pytest.raises(ValueError, match="dirty"):
        create(case)
    assert not case["output"].exists()


def test_final_resource_reopen_refuses_mid_archive_change(case, monkeypatch):
    def git(directory, *args):
        if args[0] == "archive":
            case["source"].write_bytes(b"[]\n")
        return case["git"](directory, *args)
    monkeypatch.setattr(migration, "_git", git)
    with pytest.raises(ValueError, match="changed while packaging"):
        create(case)
    assert not case["output"].exists()


@pytest.mark.parametrize("raw", [b"[]", b"{}", b"[NaN]", b'[{"x":1,"x":2}]', b"bad"])
def test_input_digest_and_json_refusals(case, raw):
    case["source"].write_bytes(raw)
    with pytest.raises(ValueError):
        create(case)
    with pytest.raises(ValueError):
        migration.create(case["root"], LAB, NATIVE, case["source"],
                         hashlib.sha256(raw).hexdigest(), case["output"])
    assert not case["output"].exists()


@pytest.mark.parametrize("name", sorted(migration.FILES))
def test_changed_artifact_bytes_refused(case, name):
    result = create(case)
    path = case["output"] / name
    path.chmod(0o644)
    path.write_bytes(path.read_bytes() + b"changed")
    path.chmod(0o444)
    with pytest.raises(ValueError):
        migration.verify(case["output"], result["manifest_sha256"])


@pytest.mark.parametrize("mutation", ["mode", "symlink", "hardlink", "extra", "missing"])
def test_full_modes_links_and_exact_package_membership_refused(case, mutation):
    result = create(case)
    path = case["output"] / "supplied-resources.json"
    if mutation == "mode":
        path.chmod(0o644)
    elif mutation == "symlink":
        path.unlink()
        path.symlink_to(case["source"])
    elif mutation == "hardlink":
        import os
        os.link(path, case["output"].parent / "alias")
    elif mutation == "extra":
        (case["output"] / "extra").write_bytes(b"ignored?")
    else:
        path.unlink()
    with pytest.raises(ValueError):
        migration.verify(case["output"], result["manifest_sha256"])


@pytest.mark.parametrize("mutation", ["credit", "git_checkout", "schema_bool", "native", "inventory"])
def test_rehashed_metadata_still_enforces_contract(case, mutation):
    create(case)
    def mutate(manifest):
        if mutation == "credit":
            manifest["scientific_credit"] = True
        elif mutation == "git_checkout":
            manifest["archive_is_git_checkout"] = True
        elif mutation == "schema_bool":
            manifest["schema_version"] = True
        elif mutation == "native":
            manifest["source"]["gitlink"] = "3" * 40
        else:
            manifest["source_members"]["source/qcsd-lab"]["sha256"] = "0" * 64
    digest = rewrite_manifest(case, mutate)
    with pytest.raises(ValueError):
        migration.verify(case["output"], digest)


@pytest.mark.parametrize("name", ["source/../escape", "/source/escape", "source/.git/config", "source//bad"])
def test_archive_path_refusal_even_with_rehashed_artifact(case, name):
    create(case)
    raw = tar_bytes([("source/neqo-qcsd/client.rs", b"code", 0o644), (name, b"escape", 0o644)])
    digest = replace_artifact(case, "source.tar.gz", gzip.compress(raw, mtime=0))
    with pytest.raises(ValueError, match="unsafe member"):
        migration.verify(case["output"], digest)


def test_archive_symlink_is_never_extracted_or_followed(case):
    create(case)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        member = tarfile.TarInfo("source/neqo-qcsd/escape")
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
        archive.addfile(member)
    digest = replace_artifact(case, "source.tar.gz", gzip.compress(output.getvalue(), mtime=0))
    with pytest.raises(ValueError, match="unsafe member"):
        migration.verify(case["output"], digest)


@pytest.mark.parametrize("remote", ["/local/repo", "file:///repo", "https://token@example.org/r.git",
                                      "ssh://git:secret@example.org/r.git", "https://example.org/r.git\ncommand"])
def test_credentials_and_machine_local_remotes_are_refused(remote):
    with pytest.raises(ValueError):
        migration._remote(remote)


def test_unpinned_manifest_digest_is_required(case):
    create(case)
    with pytest.raises(ValueError):
        migration.verify(case["output"], "0" * 64)


def test_cli_verify_works_without_source_or_git(case, monkeypatch, capsys):
    result = create(case)
    monkeypatch.setattr(migration, "_git", lambda *_: pytest.fail("verification invoked Git"))
    assert migration.main(["verify", "--package", str(case["output"]),
                           "--manifest-sha256", result["manifest_sha256"]]) == 0
    assert json.loads(capsys.readouterr().out)["runtime_verified"] is False
