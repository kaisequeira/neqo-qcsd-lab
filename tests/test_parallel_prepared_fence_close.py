"""Close actual file/tree observations without postbirth scientific replay.

The existing release fixture explicitly controls the external scientific/image
proofs. Preparation, frame digest, real files/modes/membership, inspected worker
identity and create-only release records retain their production boundaries.
Full-mode records use the current ordinary capsule's genuine fence format; no
fixture result grants capture or scientific credit.
"""
from collections import Counter
import os
from pathlib import Path
import stat

import pytest

from qcsd_lab import rapid_formal_parallel as formal
from qcsd_lab import rapid_parallel_capture as shared
from tests.test_rapid_parallel_release_preparation import (
    _birth, _prepared, _unreleased, release_context,
)


def _full_mode_prepare(context):
    original = formal._release_fence

    def observe(*args, **kwargs):
        fence = original(*args, **kwargs)
        for name, record in fence["files"].items():
            record["mode"] = stat.S_IMODE(Path(name).stat().st_mode)
        for name, inventory in list(fence["trees"].items()):
            root = Path(name)
            if "shallow_files" in inventory:
                inventory["mode"] = stat.S_IMODE(root.stat().st_mode)
            else:
                fence["trees"][name] = {
                    "files": {relative: dict(fence["files"][str(root / relative)])
                              for relative in inventory},
                    "directories": {".": stat.S_IMODE(root.stat().st_mode), **{
                        item.relative_to(root).as_posix(): stat.S_IMODE(item.stat().st_mode)
                        for item in root.rglob("*") if item.is_dir()
                        and ".git" not in item.relative_to(root).parts}},
                }
        return fence

    context.monkeypatch.setattr(formal, "_release_fence", observe)
    digest = _prepared(context)

    def forbidden(*_args, **_kwargs):
        pytest.fail("postbirth closing fence must not derive semantic inputs again")

    context.monkeypatch.setattr(formal, "_release_fence", forbidden)
    return digest


def test_prepared_release_closes_each_unique_file_once_without_semantic_derivation(release_context):
    context = release_context
    digest = _full_mode_prepare(context)
    frame = shared.load(context.output / "release-prepared.json")
    actual = _birth(context, digest)
    original = formal._check_release_fence
    calls = Counter()

    def close(*args):
        read = shared.read

        def observed(path):
            calls[str(path)] += 1
            return read(path)

        with context.monkeypatch.context() as patch:
            patch.setattr(shared, "read", observed)
            original(*args)
        assert set(calls) == set(frame["input_fence"]["files"])
        assert set(calls.values()) == {1}

    context.monkeypatch.setattr(formal, "_check_release_fence", close)
    formal.release(context.path, context.output, actual, prepared_sha256=digest)
    assert shared.load(context.output / "batch-launch.json")["formal_accepted_trace_count"] == 0
    for index in range(2):
        assert (context.output / f"lane-{index+1}/gate/release.json").is_file()


@pytest.mark.parametrize("change", [
    "bytes", "file-mode", "file-added", "file-removed", "directory-added",
    "directory-mode", "linked-file", "special-file", "shallow-mode",
])
def test_full_mode_fence_changes_block_both_worker_releases(release_context, change):
    context = release_context
    digest = _full_mode_prepare(context)
    actual = _birth(context, digest)
    if change == "bytes":
        context.source_file.write_bytes(b"changed immutable Source")
    elif change == "file-mode":
        context.source_file.chmod(0o600)
    elif change == "file-added":
        (context.source_file.parent / "unexpected.py").write_bytes(b"unexpected")
    elif change == "file-removed":
        context.source_file.unlink()
    elif change == "directory-added":
        (context.source_file.parent / "unexpected-empty-directory").mkdir()
    elif change == "directory-mode":
        context.source_file.parent.chmod(0o700)
    elif change == "linked-file":
        target = context.source_file.with_name("linked.py")
        target.symlink_to(context.source_file)
    elif change == "special-file":
        os.mkfifo(context.source_file.parent / "unexpected-fifo")
    else:
        context.canonical.parent.chmod(0o700)
    with pytest.raises(ValueError, match="changed"):
        formal.release(context.path, context.output, actual, prepared_sha256=digest)
    _unreleased(context)


@pytest.mark.parametrize("change", ["tree-member-omitted", "inconsistent-tree-record", "required-anchor-omitted"])
def test_authenticated_fence_internal_omissions_or_conflicts_are_refused(release_context, change):
    context = release_context
    _full_mode_prepare(context)
    fence = shared.load(context.output / "release-prepared.json")["input_fence"]
    if change == "tree-member-omitted":
        del fence["files"][str(context.source_file)]
    elif change == "inconsistent-tree-record":
        relative = context.source_file.relative_to(context.spec.runtime_source_root).as_posix()
        fence["trees"][str(context.spec.runtime_source_root)]["files"][relative]["sha256"] = "0" * 64
    else:
        del fence["files"][str(context.path)]
    with pytest.raises(ValueError, match="input bytes or inventory changed"):
        formal._check_release_fence(fence, context.path, context.value, context.facts,
            shared.reopen_preflight(context.output, shared.sha(context.path.read_bytes())))
    _unreleased(context)
