from __future__ import annotations

import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import textwrap
import time
from contextlib import redirect_stderr, redirect_stdout
from types import ModuleType

import pytest

from tests.test_docker_signal_supervisor import (
    CONTAINER_ID,
    fake_environment,
)


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/docker_signal_supervisor.sh"
NATIVE = ROOT / "tools/docker_lifecycle_native.py"
GUARDIAN = ROOT / "tools/docker_lifecycle_lock_guardian.py"


def _load_native() -> ModuleType:
    name = f"qcsd_lifecycle_native_test_{os.urandom(8).hex()}"
    spec = importlib.util.spec_from_file_location(name, NATIVE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _run_bash(
    script: str,
    *,
    environment: dict[str, str],
    timeout: float = 20,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=timeout,
    )


def _native_retirement_op(
    base: Path,
    action: str,
    *arguments: object,
    payload: str = "",
) -> subprocess.CompletedProcess[str]:
    """Exercise the private native primitive harness without a CLI bypass."""

    native = _load_native()
    base_stat = base.stat(follow_symlinks=False)
    operation = (
            action,
            str(base),
            str(os.getuid()),
            str(base_stat.st_dev),
            str(base_stat.st_ino),
            *(str(argument) for argument in arguments),
    )
    stdout = io.StringIO()
    stderr = io.StringIO()
    original_stdin = sys.stdin
    sys.stdin = io.TextIOWrapper(io.BytesIO(payload.encode("ascii")), encoding="ascii")
    returncode = 0
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            native.run_unleased_for_test(operation)
    except SystemExit as error:
        returncode = int(error.code) if isinstance(error.code, int) else 1
    except (OSError, ValueError) as error:
        print(f"qcsd-lab lifecycle native: {error}", file=stderr)
        returncode = 1
    finally:
        sys.stdin = original_stdin
    return subprocess.CompletedProcess(operation, returncode, stdout.getvalue(), stderr.getvalue())


def _native_creation_hold(
    base: Path, root_name: str
) -> subprocess.CompletedProcess[str]:
    """Run the native creation holder in an isolated process with a dead parent."""

    source = r'''
import importlib.util
import os
from pathlib import Path
import sys

native_source = Path(sys.argv[1])
base = Path(sys.argv[2])
root_name = sys.argv[3]
spec = importlib.util.spec_from_file_location("qcsd_creation_bound_test", native_source)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
base_value = base.stat(follow_symlinks=False)
dead_pid = 999_900_000
module.run_unleased_for_test(
    (
        "hold-creation",
        str(base),
        str(os.getuid()),
        str(base_value.st_dev),
        str(base_value.st_ino),
        root_name,
        str(dead_pid),
        "1",
        str(dead_pid),
        str(dead_pid),
    )
)
'''
    return subprocess.run(
        [sys.executable, "-I", "-c", source, str(NATIVE), str(base), root_name],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
    )


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700)
    path.chmod(0o700)


def _private_file(path: Path, value: str) -> None:
    path.write_text(value, encoding="ascii")
    path.chmod(0o600)


def _run_localised_secure_lifecycle_base(parent: Path) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.update(
        QCSD_TEST_LIFECYCLE_PARENT=str(parent),
        QCSD_TEST_SUPERVISOR_SOURCE=str(HELPER),
    )
    return _run_bash(
        r'''
        source "$QCSD_TEST_SUPERVISOR_SOURCE"
        production_definition="$(declare -f _qcsd_secure_lifecycle_base)" || exit 90
        [[ "$production_definition" == *'/var/tmp'* &&
            "$production_definition" == *'"0:1777:directory"'* ]] || exit 91
        localised_definition="${production_definition//\/var\/tmp/${QCSD_TEST_LIFECYCLE_PARENT}}"
        localised_definition="${localised_definition//0:1777:directory/${EUID}:1777:directory}"
        [[ "$localised_definition" != *'/var/tmp'* &&
            "$localised_definition" == *"\"${EUID}:1777:directory\""* ]] || exit 92
        eval "$localised_definition"
        _QCSD_DOCKER_LIFECYCLE_PARENT="$QCSD_TEST_LIFECYCLE_PARENT"
        _qcsd_secure_lifecycle_base
        ''',
        environment=environment,
    )


def _authority_arguments(authority: Path) -> tuple[object, ...]:
    value = authority.stat(follow_symlinks=False)
    return (
        "--authority",
        authority.name,
        value.st_dev,
        value.st_ino,
        value.st_size,
        hashlib.sha256(authority.read_bytes()).hexdigest(),
    )


def _retirement_names(root: Path) -> tuple[Path, Path, Path]:
    kind, token = root.name.split(".", maxsplit=1)
    return (
        root.parent / f"retirement.{kind}.{token}.next",
        root.parent / f"retirement.{kind}.{token}",
        root.parent / f".retired.{kind}.{token}",
    )


def _tree_snapshot(root: Path) -> tuple[tuple[object, ...], ...]:
    snapshot: list[tuple[object, ...]] = []
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(root).as_posix()
        digest = ""
        if stat.S_ISREG(metadata.st_mode):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        elif stat.S_ISLNK(metadata.st_mode):
            digest = os.readlink(path)
        snapshot.append(
            (
                relative,
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_uid,
                stat.S_IFMT(metadata.st_mode),
                stat.S_IMODE(metadata.st_mode),
                metadata.st_nlink,
                metadata.st_size,
                digest,
            )
        )
    return tuple(snapshot)


def test_native_hold_creation_counts_logical_operations_before_mkdir(
    tmp_path: Path,
) -> None:
    base = tmp_path / "base"
    _private_directory(base)
    kinds = ("run", "network", "build", "transaction", "run", "network")
    tokens = tuple(f"{index:032x}" for index in range(1, 9))
    for kind, token in zip(kinds, tokens[:6], strict=True):
        _private_directory(base / f"{kind}.{token}")

    # These transition aliases are one logical operation, not two extra roots.
    aliased_kind, aliased_token = kinds[0], tokens[0]
    _private_directory(base / f".retired.{aliased_kind}.{aliased_token}")
    _private_file(
        base / f"retirement.{aliased_kind}.{aliased_token}",
        "authorised retirement\n",
    )

    seventh = base / f"build.{tokens[6]}"
    admitted = _native_creation_hold(base, seventh.name)

    assert admitted.returncode == 1, admitted.stderr
    assert "creation-holder lifecycle operation bound is exhausted" not in admitted.stderr
    assert "creation-holder control was rejected" in admitted.stderr
    assert seventh.is_dir() and not seventh.is_symlink()

    eighth = base / f"transaction.{tokens[7]}"
    rejected = _native_creation_hold(base, eighth.name)

    assert rejected.returncode == 1
    assert "creation-holder lifecycle operation bound is exhausted" in rejected.stderr
    assert rejected.stdout == ""
    assert not eighth.exists()


def test_shell_lifecycle_base_bounds_unique_tokens_across_retirement_phases(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "local-var-tmp"
    parent.mkdir(mode=0o700)
    parent.chmod(0o1777)
    base = parent / f"qcsd-docker-lifecycle-{os.getuid()}"
    _private_directory(base)
    tokens = tuple(f"{index:032x}" for index in range(1, 9))

    # One token may legitimately appear under every transition-phase name.
    _private_directory(base / f"run.{tokens[0]}")
    _private_directory(base / f".retired.run.{tokens[0]}")
    _private_file(base / f"retirement.run.{tokens[0]}", "authority\n")
    _private_file(base / f"retirement.run.{tokens[0]}.next", "staged\n")
    _private_directory(base / f".retired.network.{tokens[1]}")
    _private_file(base / f"retirement.build.{tokens[2]}", "authority\n")
    _private_file(base / f"retirement.transaction.{tokens[3]}.next", "staged\n")
    _private_directory(base / f"run.{tokens[4]}")
    _private_file(base / f"retirement.network.{tokens[5]}.next", "staged\n")
    _private_directory(base / f"build.{tokens[6]}")

    seven = _run_localised_secure_lifecycle_base(parent)

    assert seven.returncode == 0, seven.stderr

    eighth = base / f"retirement.transaction.{tokens[7]}"
    _private_file(eighth, "authority\n")
    eight = _run_localised_secure_lifecycle_base(parent)

    assert eight.returncode != 0
    eighth.unlink()

    cross_kind = base / f"retirement.network.{tokens[0]}.next"
    _private_file(cross_kind, "staged\n")
    changed_kind = _run_localised_secure_lifecycle_base(parent)

    assert changed_kind.returncode != 0


@pytest.fixture
def retirement_environment(fake_environment: dict[str, str]):
    """Reuse the Docker model but remove only retirement state created here."""

    state = Path(fake_environment["FAKE_DOCKER_STATE"])
    fixture_root = state.parent
    proof_root = fixture_root / "retirement-proof"
    proof_root.mkdir(mode=0o700)
    holder_source = r'''
import json
import os
from pathlib import Path
import sys

root = Path(sys.argv[1])
fields = Path("/proc/self/stat").read_text().rsplit(") ", 1)[1].split()
boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
boot = boot_id.replace("-", "")
docker = root / (
    f".qcsd-docker-config-{os.getuid()}.v2.{boot}."
    f"{int(fields[19])}.{'a' * 64}"
)
docker.mkdir(mode=0o500)
docker_fd = os.open(docker, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
buildx_parent = root / "buildx-parent"
buildx_parent.mkdir(mode=0o700)
buildx_name = f".qcsd-buildx-config-{os.getuid()}.{'a' * 64}"
buildx = buildx_parent / buildx_name
buildx.mkdir(mode=0o700)
buildx_parent_fd = os.open(
    buildx_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
)
docker_value = os.fstat(docker_fd)
buildx_value = buildx.stat(follow_symlinks=False)
record = {
    "boot_id": boot_id,
    "guardian_start": int(fields[19]),
    "buildx_device": buildx_value.st_dev,
    "buildx_inode": buildx_value.st_ino,
    "buildx_path": f"/proc/{os.getpid()}/fd/{buildx_parent_fd}/{buildx_name}",
    "docker_device": docker_value.st_dev,
    "docker_inode": docker_value.st_ino,
    "docker_path": str(docker),
}
(root / "proof.json").write_text(json.dumps(record), encoding="ascii")
print("READY", flush=True)
sys.stdin.buffer.read()
docker.rmdir()
'''
    holder = subprocess.Popen(
        [sys.executable, "-I", "-c", holder_source, str(proof_root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert holder.stdout is not None
    assert holder.stdout.readline() == "READY\n"
    proof = __import__("json").loads(
        (proof_root / "proof.json").read_text(encoding="ascii")
    )

    native_harness = fixture_root / "retirement-native-harness.py"
    native_harness.write_text(
        textwrap.dedent(
            '''\
            import importlib.util
            import os
            from pathlib import Path
            import sys

            source = Path(os.environ["RETIREMENT_NATIVE_SOURCE"])
            spec = importlib.util.spec_from_file_location(
                "qcsd_retirement_test_native", source
            )
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            result = module.run_unleased_for_test(tuple(sys.argv[1:]))
            raise SystemExit(0 if result is None else result)
            '''
        ),
        encoding="ascii",
    )
    native_harness.chmod(0o600)
    lock_path = proof_root / "retirement-lifecycle.lock"
    lock_path.touch(mode=0o600)
    lock_path.chmod(0o600)
    helper_wrapper = fixture_root / "retirement-helper-wrapper.sh"
    helper_wrapper.write_text(
        textwrap.dedent(
            r'''\
            source "$REAL_HELPER"
            source "$QCSD_TEST_LIFECYCLE_SHIM"

            _qcsd_test_source_binding() {
              local role="$1" path="$2" device inode digest
              IFS=: read -r device inode < <(stat -Lc '%d:%i' -- "$path") || return 1
              digest="$(sha256sum -- "$path" | awk '{print $1}')" || return 1
              case "$role" in
                guard)
                  _QCSD_LIFECYCLE_GUARD_SOURCE_PATH="$path"
                  _QCSD_LIFECYCLE_GUARD_SOURCE_DEVICE="$device"
                  _QCSD_LIFECYCLE_GUARD_SOURCE_INODE="$inode"
                  _QCSD_LIFECYCLE_GUARD_SOURCE_SHA256="$digest"
                  ;;
                qcsd)
                  _QCSD_LIFECYCLE_QCSD_SOURCE_PATH="$path"
                  _QCSD_LIFECYCLE_QCSD_SOURCE_DEVICE="$device"
                  _QCSD_LIFECYCLE_QCSD_SOURCE_INODE="$inode"
                  _QCSD_LIFECYCLE_QCSD_SOURCE_SHA256="$digest"
                  ;;
                native)
                  _QCSD_LIFECYCLE_NATIVE_PATH="$path"
                  _QCSD_LIFECYCLE_NATIVE_SOURCE_DEVICE="$device"
                  _QCSD_LIFECYCLE_NATIVE_SOURCE_INODE="$inode"
                  _QCSD_LIFECYCLE_NATIVE_SHA256="$digest"
                  ;;
              esac
            }
            _qcsd_test_source_binding guard "$RETIREMENT_GUARDIAN_SOURCE"
            _qcsd_test_source_binding qcsd "$RETIREMENT_QCSD_SOURCE"
            _qcsd_test_source_binding native "$RETIREMENT_NATIVE_SOURCE"
            _QCSD_LIFECYCLE_HELPER_SOURCE_PATH=$_QCSD_EXECUTED_HELPER_SOURCE_PATH
            _QCSD_LIFECYCLE_HELPER_SOURCE_DEVICE=$_QCSD_EXECUTED_HELPER_SOURCE_DEVICE
            _QCSD_LIFECYCLE_HELPER_SOURCE_INODE=$_QCSD_EXECUTED_HELPER_SOURCE_INODE
            _QCSD_LIFECYCLE_HELPER_SHA256=$_QCSD_EXECUTED_HELPER_SOURCE_SHA256
            _QCSD_LIFECYCLE_LOCK_PATH=$RETIREMENT_LOCK_PATH
            IFS=: read -r _QCSD_LIFECYCLE_LOCK_DEVICE \
              _QCSD_LIFECYCLE_LOCK_INODE < <(stat -Lc '%d:%i' -- "$RETIREMENT_LOCK_PATH")
            IFS=: read -r _QCSD_LIFECYCLE_LOCK_PARENT_DEVICE \
              _QCSD_LIFECYCLE_LOCK_PARENT_INODE < <(
                stat -Lc '%d:%i' -- "${RETIREMENT_LOCK_PATH%/*}"
              )
            _QCSD_LIFECYCLE_DOCKER_CONFIG_PATH=$RETIREMENT_DOCKER_CONFIG_PATH
            _QCSD_LIFECYCLE_DOCKER_CONFIG_DEVICE=$RETIREMENT_DOCKER_CONFIG_DEVICE
            _QCSD_LIFECYCLE_DOCKER_CONFIG_INODE=$RETIREMENT_DOCKER_CONFIG_INODE
            _QCSD_LIFECYCLE_BUILDX_CONFIG_PATH=$RETIREMENT_BUILDX_CONFIG_PATH
            _QCSD_LIFECYCLE_BUILDX_CONFIG_DEVICE=$RETIREMENT_BUILDX_CONFIG_DEVICE
            _QCSD_LIFECYCLE_BUILDX_CONFIG_INODE=$RETIREMENT_BUILDX_CONFIG_INODE
            _QCSD_LIFECYCLE_BOOT_ID=$RETIREMENT_BOOT_ID
            _QCSD_LIFECYCLE_GUARD_START=$RETIREMENT_GUARDIAN_START

            _qcsd_retirement_native_op() {
              /usr/bin/python3 -I "$RETIREMENT_NATIVE_HARNESS" "$@"
            }
            _qcsd_docker_api_service_with_timeout() {
              local duration="$1"
              shift
              [[ "$duration" =~ ^[1-9][0-9]*$ && $# -gt 0 ]] || return 125
              case "$1" in
                qcsd-native-docker-*)
                  /usr/bin/python3 "$QCSD_TEST_NATIVE_DOCKER_ADAPTER" "$@"
                  ;;
                *) "$@" ;;
              esac
            }
            _qcsd_create_lifecycle_root() {
              local kind="$1" token="$2"
              [[ "$kind" =~ ^(run|network|build|transaction)$ &&
                  "$token" =~ ^[0-9a-f]{32}$ ]] || return 1
              _qcsd_secure_lifecycle_base || return 1
              _qcsd_lifecycle_root="$_qcsd_lifecycle_base/$kind.$token"
              [[ ! -e "$_qcsd_lifecycle_root" &&
                  ! -L "$_qcsd_lifecycle_root" ]] || return 1
              mkdir -m 700 -- "$_qcsd_lifecycle_root" || return 1
              sync -f "$_qcsd_lifecycle_base" || return 1
              _qcsd_lifecycle_root_created_hook "$_qcsd_lifecycle_root"
            }
            _qcsd_commit_lifecycle_root_creation() { return 0; }
            _qcsd_cancel_lifecycle_root_creation() { return 0; }
            _qcsd_lifecycle_root_created_hook() {
              printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/supervisor-roots.log"
            }
            '''
        ),
        encoding="ascii",
    )
    helper_wrapper.chmod(0o600)
    environment = dict(fake_environment)
    environment.update(
        HELPER=str(helper_wrapper),
        REAL_HELPER=str(HELPER),
        RETIREMENT_BUILDX_CONFIG_DEVICE=str(proof["buildx_device"]),
        RETIREMENT_BUILDX_CONFIG_INODE=str(proof["buildx_inode"]),
        RETIREMENT_BUILDX_CONFIG_PATH=str(proof["buildx_path"]),
        RETIREMENT_BOOT_ID=str(proof["boot_id"]),
        RETIREMENT_DOCKER_CONFIG_DEVICE=str(proof["docker_device"]),
        RETIREMENT_DOCKER_CONFIG_INODE=str(proof["docker_inode"]),
        RETIREMENT_DOCKER_CONFIG_PATH=str(proof["docker_path"]),
        RETIREMENT_GUARDIAN_SOURCE=str(GUARDIAN),
        RETIREMENT_GUARDIAN_START=str(proof["guardian_start"]),
        RETIREMENT_CONFIG_HOLDER_PID=str(holder.pid),
        RETIREMENT_CONFIG_HOLDER_KILLED=str(fixture_root / "holder-killed"),
        RETIREMENT_LOCK_PATH=str(lock_path),
        RETIREMENT_NATIVE_HARNESS=str(native_harness),
        RETIREMENT_NATIVE_SOURCE=str(NATIVE),
        RETIREMENT_QCSD_SOURCE=str(ROOT / "qcsd-lab"),
    )
    try:
        yield environment
    finally:
        killed = Path(environment["RETIREMENT_CONFIG_HOLDER_KILLED"]).exists()
        if not killed and holder.stdin is not None:
            holder.stdin.close()
            holder.stdin = None
        _, holder_stderr = holder.communicate(timeout=3)
        if not killed:
            assert holder.returncode == 0, holder_stderr

    roots_log = state / "supervisor-roots.log"
    if not roots_log.exists():
        return
    lifecycle_base = Path(environment["QCSD_TEST_LIFECYCLE_BASE"])
    seen: set[Path] = set()
    for raw_root in roots_log.read_text(encoding="utf-8").splitlines():
        root = Path(raw_root)
        assert root.parent == lifecycle_base, root
        if root in seen:
            continue
        seen.add(root)
        staged, authority, retired = _retirement_names(root)
        for path in (staged, authority, retired):
            if path.is_symlink() or path.is_file():
                path.unlink(missing_ok=True)
            elif path.is_dir():
                shutil.rmtree(path)


@pytest.mark.parametrize("destination_kind", ["file", "directory", "symlink"])
def test_native_root_rename_is_no_replace(
    tmp_path: Path, destination_kind: str
) -> None:
    base = tmp_path / "base"
    _private_directory(base)
    source = base / f"run.{'a' * 32}"
    target = base / f".retired.run.{'a' * 32}"
    authority = base / f"retirement.run.{'a' * 32}"
    _private_directory(source)
    _private_file(authority, "authorised retirement\n")
    source_stat = source.stat(follow_symlinks=False)
    if destination_kind == "file":
        _private_file(target, "unrelated\n")
    elif destination_kind == "directory":
        _private_directory(target)
    else:
        target.symlink_to(tmp_path, target_is_directory=True)

    result = _native_retirement_op(
        base,
        "rename-root",
        *_authority_arguments(authority),
        source.name,
        target.name,
        source_stat.st_dev,
        source_stat.st_ino,
    )

    assert result.returncode != 0
    assert source.is_dir() and not source.is_symlink()
    if destination_kind == "symlink":
        assert target.is_symlink()
    elif destination_kind == "directory":
        assert target.is_dir()
    else:
        assert target.read_text(encoding="ascii") == "unrelated\n"


def test_native_root_rename_rejects_a_replaced_source_inode(tmp_path: Path) -> None:
    base = tmp_path / "base"
    _private_directory(base)
    source = base / f"run.{'b' * 32}"
    moved = base / "moved-original"
    target = base / f".retired.run.{'b' * 32}"
    authority = base / f"retirement.run.{'b' * 32}"
    _private_directory(source)
    _private_file(authority, "authorised retirement\n")
    expected = source.stat(follow_symlinks=False)
    source.rename(moved)
    _private_directory(source)

    result = _native_retirement_op(
        base,
        "rename-root",
        *_authority_arguments(authority),
        source.name,
        target.name,
        expected.st_dev,
        expected.st_ino,
    )

    assert result.returncode != 0
    assert source.is_dir() and moved.is_dir()
    assert not target.exists()


@pytest.mark.parametrize("replacement", ["file", "directory", "symlink"])
def test_native_child_unlink_rejects_replacement(
    tmp_path: Path, replacement: str
) -> None:
    base = tmp_path / "base"
    _private_directory(base)
    retired = base / f".retired.run.{'c' * 32}"
    authority = base / f"retirement.run.{'c' * 32}"
    _private_directory(retired)
    _private_file(authority, "authorised retirement\n")
    child = retired / "HANDOFF"
    _private_file(child, "original-ledger\n")
    retired_stat = retired.stat(follow_symlinks=False)
    child_stat = child.stat(follow_symlinks=False)
    child.unlink()
    if replacement == "file":
        _private_file(child, "replacement-ledger\n")
    elif replacement == "directory":
        _private_directory(child)
    else:
        child.symlink_to(tmp_path, target_is_directory=True)

    result = _native_retirement_op(
        base,
        "unlink",
        *_authority_arguments(authority),
        retired.name,
        child.name,
        retired_stat.st_dev,
        retired_stat.st_ino,
        child_stat.st_dev,
        child_stat.st_ino,
        oct(stat.S_IMODE(child_stat.st_mode))[2:],
        child_stat.st_nlink,
        child_stat.st_size,
        "0" * 64,
    )

    assert result.returncode != 0
    assert child.exists() or child.is_symlink()


def test_native_authority_unlink_rejects_replacement(tmp_path: Path) -> None:
    base = tmp_path / "base"
    _private_directory(base)
    authority = base / f"retirement.run.{'d' * 32}"
    moved = base / "moved-authority"
    _private_file(authority, "retirement_schema=1\n")
    expected = authority.stat(follow_symlinks=False)
    authority.rename(moved)
    _private_file(authority, "replacement\n")

    result = _native_retirement_op(
        base,
        "unlink-authority",
        authority.name,
        expected.st_dev,
        expected.st_ino,
        expected.st_size,
        hashlib.sha256(moved.read_bytes()).hexdigest(),
    )

    assert result.returncode != 0
    assert authority.read_text(encoding="ascii") == "replacement\n"
    assert moved.read_text(encoding="ascii") == "retirement_schema=1\n"


def test_native_authority_publish_is_create_only_and_durable_shape(
    tmp_path: Path,
) -> None:
    base = tmp_path / "base"
    _private_directory(base)
    staged = f"retirement.run.{'e' * 32}.next"
    final = f"retirement.run.{'e' * 32}"
    payload = "retirement_schema=1\n"

    first = _native_retirement_op(base, "publish", staged, final, payload=payload)
    second = _native_retirement_op(base, "publish", staged, final, payload=payload)

    assert first.returncode == 0, (first.stdout, first.stderr)
    assert second.returncode != 0
    authority = base / final
    metadata = authority.stat(follow_symlinks=False)
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1
    assert authority.read_text(encoding="ascii") == payload


@pytest.mark.parametrize("base_name", ["legacy", "renamed-lifecycle-base"])
def test_native_cli_rejects_every_unleased_mutation_base(
    tmp_path: Path, base_name: str
) -> None:
    base = tmp_path / base_name
    _private_directory(base)
    metadata = base.stat(follow_symlinks=False)
    staged = f"retirement.run.{'f' * 32}.next"
    final = f"retirement.run.{'f' * 32}"

    result = subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            str(NATIVE),
            "publish",
            str(base),
            str(os.getuid()),
            str(metadata.st_dev),
            str(metadata.st_ino),
            staged,
            final,
        ],
        input="retirement_schema=1\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
    )

    assert result.returncode != 0
    assert "requires authenticated guardian lease" in result.stderr
    assert not (base / staged).exists()
    assert not (base / final).exists()


def test_native_promotes_exact_staged_authority_and_active_root(tmp_path: Path) -> None:
    native = _load_native()
    base = tmp_path / "base"
    root = base / f"run.{'1' * 32}"
    _private_directory(base)
    _private_directory(root)
    _private_file(root / "HANDOFF", "immutable handoff\n")
    staged = base / f"retirement.run.{'1' * 32}.next"
    final = base / f"retirement.run.{'1' * 32}"
    payload = "retirement_schema=1\n"
    _private_file(staged, payload)
    base_value = base.stat(follow_symlinks=False)
    root_value = root.stat(follow_symlinks=False)
    staged_value = staged.stat(follow_symlinks=False)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        manifest = native._root_manifest_sha256(root_fd)
    finally:
        os.close(root_fd)

    native.run_unleased_for_test(
        (
            "promote-authority",
            str(base),
            str(os.getuid()),
            str(base_value.st_dev),
            str(base_value.st_ino),
            staged.name,
            final.name,
            str(staged_value.st_dev),
            str(staged_value.st_ino),
            str(staged_value.st_size),
            hashlib.sha256(payload.encode("ascii")).hexdigest(),
            root.name,
            str(root_value.st_dev),
            str(root_value.st_ino),
            manifest,
        )
    )

    assert not staged.exists()
    assert final.read_text(encoding="ascii") == payload
    assert root.is_dir()


def test_native_promote_rejects_a_replaced_staged_authority(tmp_path: Path) -> None:
    native = _load_native()
    base = tmp_path / "base"
    root = base / f"run.{'2' * 32}"
    _private_directory(base)
    _private_directory(root)
    _private_file(root / "HANDOFF", "immutable handoff\n")
    staged = base / f"retirement.run.{'2' * 32}.next"
    moved = base / "moved-staged"
    final = base / f"retirement.run.{'2' * 32}"
    _private_file(staged, "authorised\n")
    base_value = base.stat(follow_symlinks=False)
    root_value = root.stat(follow_symlinks=False)
    staged_value = staged.stat(follow_symlinks=False)
    expected_hash = hashlib.sha256(staged.read_bytes()).hexdigest()
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        manifest = native._root_manifest_sha256(root_fd)
    finally:
        os.close(root_fd)
    staged.rename(moved)
    _private_file(staged, "replacement\n")

    with pytest.raises(SystemExit):
        native.run_unleased_for_test(
            (
                "promote-authority",
                str(base),
                str(os.getuid()),
                str(base_value.st_dev),
                str(base_value.st_ino),
                staged.name,
                final.name,
                str(staged_value.st_dev),
                str(staged_value.st_ino),
                str(staged_value.st_size),
                expected_hash,
                root.name,
                str(root_value.st_dev),
                str(root_value.st_ino),
                manifest,
            )
        )

    assert staged.read_text(encoding="ascii") == "replacement\n"
    assert moved.read_text(encoding="ascii") == "authorised\n"
    assert not final.exists()


def test_native_authority_unlink_rechecks_path_after_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = _load_native()
    base = tmp_path / "base"
    _private_directory(base)
    authority = base / f"retirement.run.{'3' * 32}"
    moved = base / "moved-authority"
    _private_file(authority, "authorised\n")
    base_value = base.stat(follow_symlinks=False)
    authority_value = authority.stat(follow_symlinks=False)
    expected_hash = hashlib.sha256(authority.read_bytes()).hexdigest()
    real_hash = native._fd_sha256

    def replace_after_hash(descriptor: int) -> str:
        digest = real_hash(descriptor)
        authority.rename(moved)
        _private_file(authority, "replacement\n")
        return digest

    monkeypatch.setattr(native, "_fd_sha256", replace_after_hash)

    with pytest.raises(SystemExit):
        native.run_unleased_for_test(
            (
                "unlink-authority",
                str(base),
                str(os.getuid()),
                str(base_value.st_dev),
                str(base_value.st_ino),
                authority.name,
                str(authority_value.st_dev),
                str(authority_value.st_ino),
                str(authority_value.st_size),
                expected_hash,
            )
        )

    assert authority.read_text(encoding="ascii") == "replacement\n"
    assert moved.read_text(encoding="ascii") == "authorised\n"


@pytest.mark.parametrize("kind", ["build", "run"])
def test_real_retirement_selects_only_build_identity_allowance(
    retirement_environment: dict[str, str], kind: str,
) -> None:
    """Observe the real authority/reproof path, not a replacement retire call."""

    result = _run_bash(
        r'''
set -euo pipefail
source "$HELPER"
[[ "$_QCSD_DOCKER_API_TIMEOUT_SECONDS" == 3 &&
   "$_QCSD_DOCKER_BUILD_RETIREMENT_IDENTITY_TIMEOUT_SECONDS" == 10 &&
   "$_QCSD_DOCKER_DAEMON_IDENTITY_ATTEMPTS" == 2 &&
   "$_QCSD_DOCKER_SUPERVISOR_SIGNAL_ENVELOPE_SECONDS" == 120 ]]
eval "$(declare -f _qcsd_retirement_terminal_reproof | sed \
  '1s/_qcsd_retirement_terminal_reproof/_fixture_terminal_reproof/')"
_qcsd_retirement_terminal_reproof() {
  local -n fixture_values="$1"
  local fixture_retirement_kind="${fixture_values[kind]}"
  _fixture_terminal_reproof "$@"
}
eval "$(declare -f _qcsd_docker_api_service_with_timeout | sed \
  '1s/_qcsd_docker_api_service_with_timeout/_fixture_api_service/')"
_qcsd_docker_api_service_with_timeout() {
  local duration="$1"
  shift
  if [[ "${1:-}" == qcsd-native-docker-verify ]]; then
    printf '%s %s\n' "${fixture_retirement_kind:-ordinary}" "$duration" \
      >>"$FAKE_DOCKER_STATE/identity-durations.log"
  fi
  _fixture_api_service "$duration" "$@"
}
_qcsd_verify_pinned_docker_daemon
if [[ "$QCSD_TEST_RETIREMENT_KIND" == build ]]; then
  exec 9>"$RETIREMENT_LOCK_PATH"
  chmod 600 "$RETIREMENT_LOCK_PATH"
  flock -n 9
  _QCSD_DOCKER_BUILD_LOCK_FD=9
  qcsd_run_docker_build docker --context default build fake-context
else
  QCSD_DOCKER_IDS_RETIREMENT=()
  qcsd_run_detached_docker QCSD_DOCKER_IDS_RETIREMENT docker run fake-image
  docker rm --force "${QCSD_DOCKER_IDS_RETIREMENT[0]}" >/dev/null
  qcsd_retire_docker_handoff \
    run "${QCSD_DOCKER_IDS_RETIREMENT[0]}" QCSD_DOCKER_IDS_RETIREMENT
fi
_qcsd_verify_pinned_docker_daemon ordinary
[[ "$_QCSD_DOCKER_API_TIMEOUT_SECONDS" == 3 &&
   "$_QCSD_DOCKER_DAEMON_IDENTITY_ATTEMPTS" == 2 &&
   "$_QCSD_DOCKER_SUPERVISOR_SIGNAL_ENVELOPE_SECONDS" == 120 ]]
''',
        environment={
            **retirement_environment,
            "FAKE_BUILD_BEHAVIOR": "natural0",
            "QCSD_TEST_RETIREMENT_KIND": kind,
        },
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    state = Path(retirement_environment["FAKE_DOCKER_STATE"])
    rows = [
        line.split()
        for line in (state / "identity-durations.log").read_text(
            encoding="ascii"
        ).splitlines()
    ]
    assert rows[0] == rows[-1] == ["ordinary", "3"]
    retirement_rows = [row for row in rows if row[0] == kind]
    assert retirement_rows
    assert all(row == [kind, "10" if kind == "build" else "3"]
               for row in retirement_rows)
    assert all(row[0] in {"ordinary", kind} for row in rows)
    assert all(row == ["ordinary", "3"] for row in rows if row[0] == "ordinary")
    roots = {
        Path(line)
        for line in (state / "supervisor-roots.log").read_text(
            encoding="ascii"
        ).splitlines()
    }
    assert len(roots) == 1
    root = roots.pop()
    assert root.name.startswith(f"{kind}.")
    assert not root.exists()
    assert all(not path.exists() for path in _retirement_names(root))
    calls = (state / "calls.log").read_text(encoding="ascii").splitlines()
    assert sum(line.startswith("BUILD ") for line in calls) == (kind == "build")


@pytest.mark.parametrize("kind", ["run", "network"])
def test_handoff_retirement_retry_resumes_post_rename_authority_and_reproofs_absence(
    retirement_environment: dict[str, str], kind: str,
) -> None:
    result = _run_bash(
        r'''
set -euo pipefail
source "$HELPER"
QCSD_DOCKER_IDS_RETIREMENT=()
kind="$QCSD_TEST_RETIREMENT_KIND"
if [[ "$kind" == run ]]; then
  qcsd_run_detached_docker QCSD_DOCKER_IDS_RETIREMENT docker run fake-image
  object_state=container
else
  qcsd_create_docker_network QCSD_DOCKER_IDS_RETIREMENT \
    docker network create test-network
  object_state=network
fi
root=$_qcsd_lifecycle_root
object_id="${QCSD_DOCKER_IDS_RETIREMENT[0]}"
token="${root##*.}"
authority="${root%/*}/retirement.${kind}.${token}"
retired="${root%/*}/.retired.${kind}.${token}"
if [[ "$kind" == run ]]; then
  docker rm --force "$object_id" >/dev/null
else
  docker network rm "$object_id" >/dev/null
fi

eval "$(declare -f _qcsd_retirement_terminal_reproof | sed \
  '1s/_qcsd_retirement_terminal_reproof/_fixture_terminal_reproof/')"
fixture_reproof_count=0
_qcsd_retirement_terminal_reproof() {
  fixture_reproof_count=$((fixture_reproof_count + 1))
  if (( fixture_reproof_count == 2 )); then
    return 1
  fi
  _fixture_terminal_reproof "$@"
}

set +e
qcsd_retire_docker_handoff \
  "$kind" "$object_id" QCSD_DOCKER_IDS_RETIREMENT
first_status=$?
set -e
test "$first_status" -ne 0
test ! -e "$root"
test -f "$authority"
test -d "$retired"
test -f "$retired/HANDOFF"

# A durable continuation must reprove terminal Docker absence. Reappearance
# of the exact object remains terminal and must preserve every survivor.
printf '%s' "$object_id" >"$FAKE_DOCKER_STATE/$object_state"
printf '%s' "$token" >"$FAKE_DOCKER_STATE/$object_state-token"
set +e
qcsd_retire_docker_handoff \
  "$kind" "$object_id" QCSD_DOCKER_IDS_RETIREMENT
present_status=$?
set -e
test "$present_status" -ne 0
test -f "$authority"
test -d "$retired"
test -f "$retired/HANDOFF"

rm -f -- "$FAKE_DOCKER_STATE/$object_state" \
  "$FAKE_DOCKER_STATE/$object_state-token"
qcsd_retire_docker_handoff \
  "$kind" "$object_id" QCSD_DOCKER_IDS_RETIREMENT
test ! -e "$authority"
test ! -e "$retired"
printf 'REPROOFS %d\n' "$fixture_reproof_count"
''',
        environment={
            **retirement_environment,
            "QCSD_TEST_RETIREMENT_KIND": kind,
        },
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "REPROOFS 5\n" in result.stdout
    assert result.stderr.count("failed at durable-root-removal:") == 1
    assert result.stderr.count("failed at durable-authority-continuation:") == 1
    assert "failed at candidate-selection:" not in result.stderr


def test_browser_cleanup_retries_retained_id_through_post_rename_authority(
    retirement_environment: dict[str, str],
) -> None:
    """Exercise the production browser cleanup entry path for this recovery."""

    from tests.test_cli import _browser_egress_cleanup_lifetime_shell

    result = _run_bash(
        'set -euo pipefail\nsource "$HELPER"\n'
        + _browser_egress_cleanup_lifetime_shell()
        + r'''
QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS=()
QCSD_DOCKER_IDS_BROWSER_EGRESS_NETWORKS=()
QCSD_DOCKER_IDS_BROWSER_EGRESS_VOLUMES=()
qcsd_run_detached_docker \
  QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS docker run fake-image
object_id="${QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS[0]}"
root="$_qcsd_lifecycle_root"
token="${root##*.}"
authority="${root%/*}/retirement.run.${token}"
retired="${root%/*}/.retired.run.${token}"

eval "$(declare -f _qcsd_retirement_terminal_reproof | sed \
  '1s/_qcsd_retirement_terminal_reproof/_fixture_terminal_reproof/')"
fixture_reproof_count=0
_qcsd_retirement_terminal_reproof() {
  fixture_reproof_count=$((fixture_reproof_count + 1))
  if (( fixture_reproof_count == 2 )); then
    return 1
  fi
  _fixture_terminal_reproof "$@"
}

first_status=0
browser_egress_cleanup_topology || first_status=$?
test "$first_status" -ne 0
test "${QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS[*]}" = "$object_id"
test ! -e "$root"
test -f "$authority"
test -d "$retired"
test -f "$retired/HANDOFF"
test ! -e "$FAKE_DOCKER_STATE/container"

browser_egress_cleanup_topology
test "${#QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS[@]}" -eq 0
test ! -e "$authority"
test ! -e "$retired"
printf 'REPROOFS %d\n' "$fixture_reproof_count"
''',
        environment=retirement_environment,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout == "REPROOFS 4\n"
    assert result.stderr.count("failed at durable-root-removal:") == 1
    assert result.stderr.count("failed at durable-authority-continuation:") == 0
    assert "failed at candidate-selection:" not in result.stderr


def test_validate_is_non_mutating_for_a_handoff_ready_for_retirement(
    retirement_environment: dict[str, str],
) -> None:
    setup = _run_bash(
        r'''
set -euo pipefail
source "$HELPER"
QCSD_DOCKER_IDS_RETIREMENT=()
qcsd_run_detached_docker QCSD_DOCKER_IDS_RETIREMENT docker run fake-image
printf '%s\n' "$_qcsd_lifecycle_root" >"$FAKE_DOCKER_STATE/retiring-root"
docker rm --force "${QCSD_DOCKER_IDS_RETIREMENT[0]}" >/dev/null
''',
        environment=retirement_environment,
    )
    assert setup.returncode == 0, (setup.stdout, setup.stderr)
    state = Path(retirement_environment["FAKE_DOCKER_STATE"])
    root = Path((state / "retiring-root").read_text(encoding="ascii").strip())
    assert root.parent == Path(retirement_environment["QCSD_TEST_LIFECYCLE_BASE"])
    assert (
        f"supervisor_source_path={HELPER.resolve()}\n"
        in (root / "HANDOFF").read_text(encoding="ascii")
    )
    before = _tree_snapshot(root.parent)

    result = _run_bash(
        r'''
set -euo pipefail
source "$HELPER"
qcsd_reconcile_docker_lifecycle validate
''',
        environment=retirement_environment,
    )

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert _tree_snapshot(root.parent) == before
    assert (root / "HANDOFF").is_file()


@pytest.mark.parametrize("boundary", ["H3", "H13"])
def test_browser_egress_normal_cleanup_latches_term_through_native_retirement(
    retirement_environment: dict[str, str], boundary: str,
) -> None:
    """Keep real TERM/EXIT handling outside the publication-to-retirement gap."""

    from tests.test_cli import _browser_egress_cleanup_lifetime_shell

    environment = {
        **retirement_environment,
        "QCSD_TEST_RETIREMENT_BOUNDARY": boundary,
    }
    result = _run_bash(
        'set -euo pipefail\nsource "$HELPER"\n'
        + _browser_egress_cleanup_lifetime_shell()
        + r'''
QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS=()
QCSD_DOCKER_IDS_BROWSER_EGRESS_NETWORKS=()
QCSD_DOCKER_IDS_BROWSER_EGRESS_VOLUMES=()
qcsd_run_detached_docker QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS docker run fake-image
printf '%s\n' "$_qcsd_lifecycle_root" >"$FAKE_DOCKER_STATE/retiring-root"
_qcsd_retirement_boundary_hook() {
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/retirement-boundaries.log"
  if [[ "$1" == "$QCSD_TEST_RETIREMENT_BOUNDARY" ]]; then
    kill -TERM "$BASHPID"
  fi
}
_qcsd_cleanup_terminal_hook() {
  printf 'containers=%s\n' "${QCSD_DOCKER_IDS_BROWSER_EGRESS_CONTAINERS[*]}"
}
trap browser_egress_exit_cleanup EXIT
browser_egress_cleanup_topology || false
echo publication-must-not-run
''',
        environment=environment,
    )
    assert result.returncode == 143, (result.stdout, result.stderr)
    assert result.stdout == "containers=\n"
    assert "retirement failed" not in result.stderr
    state = Path(environment["FAKE_DOCKER_STATE"])
    visited = (state / "retirement-boundaries.log").read_text(encoding="ascii").splitlines()
    assert visited.count("H0") == visited.count("H3") == visited.count("H13") == 1
    root = Path((state / "retiring-root").read_text(encoding="ascii").strip())
    assert root.parent == Path(environment["QCSD_TEST_LIFECYCLE_BASE"])
    assert not root.exists()
    assert all(not path.exists() for path in _retirement_names(root))
    assert not (state / "container").exists()


@pytest.mark.parametrize("boundary", [f"H{index}" for index in range(14)])
def test_sigkill_at_every_retirement_boundary_converges_on_restart(
    retirement_environment: dict[str, str], boundary: str
) -> None:
    environment = {
        **retirement_environment,
        "QCSD_TEST_RETIREMENT_BOUNDARY": boundary,
    }
    script = r'''
set -euo pipefail
source "$HELPER"
_qcsd_retirement_boundary_hook() {
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/retirement-boundaries.log"
  if [[ "$1" == "$QCSD_TEST_RETIREMENT_BOUNDARY" ]]; then
    kill -KILL "$BASHPID"
  fi
}
QCSD_DOCKER_IDS_RETIREMENT=()
qcsd_run_detached_docker QCSD_DOCKER_IDS_RETIREMENT docker run fake-image
printf '%s\n' "$_qcsd_lifecycle_root" >"$FAKE_DOCKER_STATE/retiring-root"
docker rm --force "${QCSD_DOCKER_IDS_RETIREMENT[0]}" >/dev/null
qcsd_retire_docker_handoff \
  run "${QCSD_DOCKER_IDS_RETIREMENT[0]}" QCSD_DOCKER_IDS_RETIREMENT
'''
    process = subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=20,
    )
    observed = Path(environment["FAKE_DOCKER_STATE"]) / "retirement-boundaries.log"
    visited = (
        observed.read_text(encoding="ascii").splitlines()
        if observed.exists()
        else []
    )
    if boundary in visited:
        assert process.returncode == -signal.SIGKILL, (process.stdout, process.stderr)
    else:
            pytest.fail(
                f"production did not expose required retirement boundary {boundary}; "
                f"stdout={process.stdout!r}, stderr={process.stderr!r}"
            )


def test_retirement_authority_resumes_with_successor_guardian_configs(
    retirement_environment: dict[str, str], tmp_path: Path
) -> None:
    environment = {
        **retirement_environment,
        "QCSD_TEST_RETIREMENT_BOUNDARY": "H3",
    }
    script = r'''
set -euo pipefail
source "$HELPER"
_qcsd_retirement_boundary_hook() {
  if [[ "$1" == H3 ]]; then kill -KILL "$BASHPID"; fi
}
QCSD_DOCKER_IDS_RETIREMENT=()
qcsd_run_detached_docker QCSD_DOCKER_IDS_RETIREMENT docker run fake-image
printf '%s\n' "$_qcsd_lifecycle_root" >"$FAKE_DOCKER_STATE/retiring-root"
docker rm --force "${QCSD_DOCKER_IDS_RETIREMENT[0]}" >/dev/null
qcsd_retire_docker_handoff \
  run "${QCSD_DOCKER_IDS_RETIREMENT[0]}" QCSD_DOCKER_IDS_RETIREMENT
'''
    crashed = subprocess.run(
        ["/bin/bash", "--noprofile", "--norc", "-c", textwrap.dedent(script)],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert crashed.returncode == -signal.SIGKILL, crashed.stderr
    state = Path(environment["FAKE_DOCKER_STATE"])
    root = Path((state / "retiring-root").read_text(encoding="ascii").strip())
    authority = root.parent / f"retirement.{root.name}"
    authority_text = authority.read_text(encoding="ascii")
    assert authority_text.count("=current-guardian\n") == 6
    assert environment["RETIREMENT_DOCKER_CONFIG_PATH"] not in authority_text
    assert environment["RETIREMENT_BUILDX_CONFIG_PATH"] not in authority_text
    old_holder = int(environment["RETIREMENT_CONFIG_HOLDER_PID"])
    os.kill(old_holder, signal.SIGKILL)
    waited_pid, waited_status = os.waitpid(old_holder, 0)
    assert waited_pid == old_holder
    assert os.waitstatus_to_exitcode(waited_status) == -signal.SIGKILL
    Path(environment["RETIREMENT_CONFIG_HOLDER_KILLED"]).touch()
    Path(environment["RETIREMENT_DOCKER_CONFIG_PATH"]).rmdir()
    deadline = time.monotonic() + 3
    while Path(environment["RETIREMENT_DOCKER_CONFIG_PATH"]).exists():
        assert time.monotonic() < deadline
        time.sleep(0.01)

    successor_source = r'''
import json, os, pathlib, sys
base = pathlib.Path(sys.argv[1])
lock_parent = pathlib.Path(sys.argv[2])
fields = pathlib.Path("/proc/self/stat").read_text().rsplit(") ", 1)[1].split()
boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
boot = boot_id.replace("-", "")
docker = lock_parent / (
    f".qcsd-docker-config-{os.getuid()}.v2.{boot}."
    f"{int(fields[19])}.{'b' * 64}"
)
buildx = base / "buildx"
docker.mkdir(mode=0o500)
buildx.mkdir(mode=0o700)
(buildx / "instances").mkdir(mode=0o700)
docker_fd = os.open(docker, os.O_RDONLY | os.O_DIRECTORY)
base_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
buildx_fd = os.open(buildx, os.O_RDONLY | os.O_DIRECTORY)
proof = {
    "boot_id": boot_id,
    "guardian_start": int(fields[19]),
    "docker_path": str(docker),
    "docker_device": os.fstat(docker_fd).st_dev,
    "docker_inode": os.fstat(docker_fd).st_ino,
    "buildx_path": f"/proc/{os.getpid()}/fd/{base_fd}/buildx",
    "buildx_device": os.fstat(buildx_fd).st_dev,
    "buildx_inode": os.fstat(buildx_fd).st_ino,
}
print(json.dumps(proof), flush=True)
sys.stdin.buffer.read()
docker.rmdir()
'''
    successor_root = tmp_path / "successor"
    successor_root.mkdir(mode=0o700)
    successor = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-c",
            successor_source,
            str(successor_root),
            str(Path(environment["RETIREMENT_LOCK_PATH"]).parent),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert successor.stdout is not None
    proof = __import__("json").loads(successor.stdout.readline())
    successor_environment = {
        **retirement_environment,
        "RETIREMENT_DOCKER_CONFIG_PATH": proof["docker_path"],
        "RETIREMENT_DOCKER_CONFIG_DEVICE": str(proof["docker_device"]),
        "RETIREMENT_DOCKER_CONFIG_INODE": str(proof["docker_inode"]),
        "RETIREMENT_BOOT_ID": str(proof["boot_id"]),
        "RETIREMENT_GUARDIAN_START": str(proof["guardian_start"]),
        "RETIREMENT_BUILDX_CONFIG_PATH": proof["buildx_path"],
        "RETIREMENT_BUILDX_CONFIG_DEVICE": str(proof["buildx_device"]),
        "RETIREMENT_BUILDX_CONFIG_INODE": str(proof["buildx_inode"]),
    }
    try:
        recovered = subprocess.run(
            [
                "/bin/bash", "--noprofile", "--norc", "-c",
                'set -euo pipefail; source "$HELPER"; '
                "qcsd_reconcile_docker_lifecycle recover",
            ],
            cwd=ROOT,
            env=successor_environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        assert recovered.returncode == 0, recovered.stderr
        assert not root.exists()
        assert not authority.exists()
    finally:
        assert successor.stdin is not None
        successor.stdin.close()
        successor.stdin = None
        _, stderr = successor.communicate(timeout=3)
        assert successor.returncode == 0, stderr

    recovery = _run_bash(
        r'''
set -euo pipefail
source "$HELPER"
qcsd_reconcile_docker_lifecycle validate
qcsd_reconcile_docker_lifecycle recover
''',
        environment=retirement_environment,
        timeout=25,
    )

    assert recovery.returncode == 0, (recovery.stdout, recovery.stderr)
    root = Path(
        (Path(environment["FAKE_DOCKER_STATE"]) / "retiring-root").read_text(
            encoding="ascii"
        ).strip()
    )
    staged, authority, retired = _retirement_names(root)
    assert not root.exists() and not root.is_symlink()
    assert not staged.exists() and not staged.is_symlink()
    assert not authority.exists() and not authority.is_symlink()
    assert not retired.exists() and not retired.is_symlink()
    assert not (Path(environment["FAKE_DOCKER_STATE"]) / "container").exists()


_PRIOR_BOOT_ID = "00000000-0000-4000-8000-000000000001"


def _crash_retirement_at_boundary(
    environment: dict[str, str], boundary: str
) -> tuple[Path, Path]:
    """Create a genuine interrupted authority solely in the isolated fixture."""

    crashed = _run_bash(
        r'''
set -euo pipefail
source "$HELPER"
_qcsd_retirement_boundary_hook() {
  if [[ "$1" == "$QCSD_TEST_RETIREMENT_BOUNDARY" ]]; then
    kill -KILL "$BASHPID"
  fi
}
QCSD_DOCKER_IDS_RETIREMENT=()
qcsd_run_detached_docker QCSD_DOCKER_IDS_RETIREMENT docker run fake-image
printf '%s\n' "$_qcsd_lifecycle_root" >"$FAKE_DOCKER_STATE/retiring-root"
docker rm --force "${QCSD_DOCKER_IDS_RETIREMENT[0]}" >/dev/null
qcsd_retire_docker_handoff \
  run "${QCSD_DOCKER_IDS_RETIREMENT[0]}" QCSD_DOCKER_IDS_RETIREMENT
''',
        environment={
            **environment,
            "QCSD_TEST_RETIREMENT_BOUNDARY": "H3" if boundary == "staged" else boundary,
        },
    )
    assert crashed.returncode == -signal.SIGKILL, (crashed.stdout, crashed.stderr)
    state = Path(environment["FAKE_DOCKER_STATE"])
    root = Path((state / "retiring-root").read_text(encoding="ascii").strip())
    assert root.parent == Path(environment["QCSD_TEST_LIFECYCLE_BASE"])
    staged, authority, _ = _retirement_names(root)
    assert authority.is_file()
    if boundary == "staged":
        # H2 precedes publish entirely; model a crash after the native staged
        # file was fsynced but before its no-replace rename to final authority.
        authority.rename(staged)
        authority = staged
    return root, authority


def _replace_fixture_authority_fields(authority: Path, **fields: str) -> None:
    """Model changed boot/PID observations, never touch real lifecycle evidence."""

    lines = authority.read_text(encoding="ascii").splitlines(keepends=True)
    for field, value in fields.items():
        matching = [i for i, line in enumerate(lines) if line.startswith(f"{field}=")]
        assert len(matching) == 1, field
        lines[matching[0]] = f"{field}={value}\n"
    authority.write_text("".join(lines), encoding="ascii")


@pytest.mark.parametrize("boundary", ["staged", "H3", "H6", "H9", "H11", "H12"])
def test_prior_boot_retirement_boundaries_converge_without_pid_reuse_checks(
    retirement_environment: dict[str, str], boundary: str
) -> None:
    root, authority = _crash_retirement_at_boundary(retirement_environment, boundary)
    assert retirement_environment["_QCSD_DOCKER_PINNED_BOOT_ID"] != _PRIOR_BOOT_ID
    _replace_fixture_authority_fields(authority, host_boot_id=_PRIOR_BOOT_ID)
    before = _tree_snapshot(root.parent)
    validate = _run_bash(
        r'''
set -euo pipefail
source "$HELPER"
_qcsd_bound_process_is_gone() {
  echo prior-boot-pid-must-not-be-compared >&2
  return 1
}
qcsd_reconcile_docker_lifecycle validate
''',
        environment=retirement_environment,
    )
    assert validate.returncode == 0, (validate.stdout, validate.stderr)
    assert _tree_snapshot(root.parent) == before
    recovered = _run_bash(
        r'''
set -euo pipefail
source "$HELPER"
_qcsd_bound_process_is_gone() {
  echo prior-boot-pid-must-not-be-compared >&2
  return 1
}
qcsd_reconcile_docker_lifecycle recover
qcsd_reconcile_docker_lifecycle validate
''',
        environment=retirement_environment,
    )
    assert recovered.returncode == 0, (recovered.stdout, recovered.stderr)
    assert not root.exists()
    assert all(not path.exists() for path in _retirement_names(root))


@pytest.mark.parametrize(
    "contradiction",
    ["exact-id-present", "token-present", "boot-drift", "daemon-mismatch", "scope-present"],
)
def test_prior_boot_retirement_keeps_live_boundary_checks_fail_closed(
    retirement_environment: dict[str, str], contradiction: str
) -> None:
    root, authority = _crash_retirement_at_boundary(retirement_environment, "H11")
    _replace_fixture_authority_fields(authority, host_boot_id=_PRIOR_BOOT_ID)
    fields = dict(
        line.split("=", 1)
        for line in authority.read_text(encoding="ascii").splitlines()
        if not line.startswith("child\t")
    )
    state = Path(retirement_environment["FAKE_DOCKER_STATE"])
    environment = dict(retirement_environment)
    probe = ""
    if contradiction in {"exact-id-present", "token-present"}:
        # The exact ID and the unique ownership token are separate absence proofs.
        (state / "container").write_text(
            fields["object_id"] if contradiction == "exact-id-present" else "f" * 64,
            encoding="ascii",
        )
        (state / "container-token").write_text(
            "e" * 32 if contradiction == "exact-id-present" else fields["token"],
            encoding="ascii",
        )
    elif contradiction == "boot-drift":
        environment["_QCSD_DOCKER_PINNED_BOOT_ID"] = _PRIOR_BOOT_ID
    elif contradiction == "daemon-mismatch":
        environment["FAKE_DOCKER_SERVER_ID"] = "changed-daemon-id"
    else:
        probe = r'''
_qcsd_query_user_scope() {
  printf '%s\n' "$1" >>"$FAKE_DOCKER_STATE/scope-reproof.log"
  _qcsd_scope_state=active
  return 0
}
'''
    before = _tree_snapshot(root.parent)
    calls_before = (state / "calls.log").read_text(encoding="ascii").splitlines()
    recovered = _run_bash(
        'set -euo pipefail\nsource "$HELPER"\n'
        + probe
        + "qcsd_reconcile_docker_lifecycle recover\n",
        environment=environment,
    )
    assert recovered.returncode != 0, (recovered.stdout, recovered.stderr)
    assert _tree_snapshot(root.parent) == before
    if contradiction in {"exact-id-present", "token-present"}:
        assert (state / "container").is_file()
        calls = (state / "calls.log").read_text(encoding="ascii").splitlines()
        assert not any(line.startswith("RM ") for line in calls[len(calls_before):])
    elif contradiction == "scope-present":
        assert (state / "scope-reproof.log").read_text(encoding="ascii").strip() == fields["scope_unit"]


def test_same_boot_retirement_refuses_live_launcher_identity(
    retirement_environment: dict[str, str],
) -> None:
    root, authority = _crash_retirement_at_boundary(retirement_environment, "H11")
    launcher = subprocess.Popen(
        [sys.executable, "-I", "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        identity = Path(f"/proc/{launcher.pid}/stat").read_text().rsplit(") ", 1)[1].split()
        assert identity[2] == identity[3] == str(launcher.pid)
        _replace_fixture_authority_fields(
            authority,
            launcher_pid=str(launcher.pid),
            launcher_start_time=identity[19],
            launcher_session=identity[3],
            launcher_process_group=identity[2],
        )
        before = _tree_snapshot(root.parent)
        recovered = _run_bash(
            'set -euo pipefail\nsource "$HELPER"\n'
            "qcsd_reconcile_docker_lifecycle recover\n",
            environment=retirement_environment,
        )
        assert recovered.returncode != 0, (recovered.stdout, recovered.stderr)
        assert _tree_snapshot(root.parent) == before
        assert launcher.poll() is None
    finally:
        launcher.terminate()
        launcher.wait(timeout=3)


@pytest.mark.parametrize("prior_boot", [False, True])
def test_new_retirement_authority_never_rebinds_prior_boot_launcher(
    retirement_environment: dict[str, str], prior_boot: bool
) -> None:
    root, authority = _crash_retirement_at_boundary(retirement_environment, "H3")
    handoff = root / "HANDOFF"
    original = dict(
        line.split("=", 1) for line in handoff.read_text(encoding="ascii").splitlines()
    )
    if prior_boot:
        # Simulate an intact older-boot root before preparing its new authority.
        for name in ("SUPERVISION", "HANDOFF"):
            if (root / name).is_file():
                _replace_fixture_authority_fields(root / name, host_boot_id=_PRIOR_BOOT_ID)
    before = _tree_snapshot(root.parent)
    prepared = _run_bash(
        r'''
set -euo pipefail
source "$HELPER"
_qcsd_secure_lifecycle_base
_qcsd_retirement_prepare_authority \
  "$QCSD_TEST_RETIRING_ROOT" handoff-retired 0 "$QCSD_TEST_RETIRING_AUTHORITY"
''',
        environment={
            **retirement_environment,
            "QCSD_TEST_RETIRING_ROOT": str(root),
            "QCSD_TEST_RETIRING_AUTHORITY": str(authority),
        },
    )
    assert prepared.returncode == 0, (prepared.stdout, prepared.stderr)
    fields = dict(
        line.split("=", 1)
        for line in prepared.stdout.splitlines()
        if not line.startswith("child\t")
    )
    assert fields["host_boot_id"] == retirement_environment["_QCSD_DOCKER_PINNED_BOOT_ID"]
    for name in ("pid", "start_time", "session", "process_group"):
        assert fields[f"launcher_{name}"] == (
            "unavailable" if prior_boot else original[f"scope_launcher_{name}"]
        )
    assert fields["scope_unit"] == original["scope_unit"]
    assert fields["record_sha256"] == hashlib.sha256(handoff.read_bytes()).hexdigest()
    assert _tree_snapshot(root.parent) == before


@pytest.mark.parametrize(
    ("prior_boot", "scope_absent", "expected_pass"),
    [(True, True, True), (True, False, False), (False, True, False)],
)
def test_recovery_boundary_limits_launcher_checks_to_recorded_boot(
    retirement_environment: dict[str, str], prior_boot: bool,
    scope_absent: bool, expected_pass: bool,
) -> None:
    result = _run_bash(
        r'''
set -euo pipefail
source "$HELPER"
_qcsd_bound_process_is_gone() {
  printf 'launcher\n' >>"$FAKE_DOCKER_STATE/recovery-boundary.log"
  return 1
}
_qcsd_wait_user_scope_inactive() {
  printf 'scope\n' >>"$FAKE_DOCKER_STATE/recovery-boundary.log"
  [[ "$QCSD_TEST_SCOPE_ABSENT" == 1 ]]
}
declare -A candidate=(
  [host_boot_id]="$QCSD_TEST_RECORD_BOOT"
  [scope_launcher_pid]=999999
  [scope_launcher_start_time]=123
  [scope_launcher_session]=999999
  [scope_launcher_process_group]=999999
  [scope_unit]=qcsd-docker-run-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope
)
_qcsd_lifecycle_reprove_recovery_boundary \
  run candidate "$_QCSD_DOCKER_PINNED_BOOT_ID"
''',
        environment={
            **retirement_environment,
            "QCSD_TEST_RECORD_BOOT": (
                _PRIOR_BOOT_ID if prior_boot
                else retirement_environment["_QCSD_DOCKER_PINNED_BOOT_ID"]
            ),
            "QCSD_TEST_SCOPE_ABSENT": "1" if scope_absent else "0",
        },
    )
    assert (result.returncode == 0) == expected_pass, (result.stdout, result.stderr)
    observed = (Path(retirement_environment["FAKE_DOCKER_STATE"]) / "recovery-boundary.log").read_text(
        encoding="ascii"
    ).splitlines()
    assert observed == (["scope"] if prior_boot else ["launcher"])


@pytest.mark.parametrize("same_boot", [False, True])
def test_retirement_launcher_collision_identity_includes_boot(
    retirement_environment: dict[str, str], same_boot: bool,
) -> None:
    first_root, first_authority = _crash_retirement_at_boundary(
        retirement_environment, "H11"
    )
    _, second_authority = _crash_retirement_at_boundary(
        {**retirement_environment, "FAKE_DOCKER_CONTAINER_ID": "b" * 64}, "H11"
    )
    for authority, boot in (
        (first_authority, _PRIOR_BOOT_ID),
        (
            second_authority,
            _PRIOR_BOOT_ID if same_boot else "00000000-0000-4000-8000-000000000002",
        ),
    ):
        _replace_fixture_authority_fields(
            authority,
            host_boot_id=boot,
            launcher_pid="999999",
            launcher_start_time="123",
            launcher_session="999999",
            launcher_process_group="999999",
        )
    before = _tree_snapshot(first_root.parent)
    validated = _run_bash(
        'set -euo pipefail\nsource "$HELPER"\n'
        "qcsd_reconcile_docker_lifecycle validate\n",
        environment=retirement_environment,
    )
    assert (validated.returncode == 0) == (not same_boot), (
        validated.stdout, validated.stderr
    )
    assert _tree_snapshot(first_root.parent) == before
