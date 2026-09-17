#!/usr/bin/python3
"""Own the QCSD Docker lifecycle flock outside the mutable launcher.

The guardian is intentionally host-only and narrowly scoped to lifecycle
authority and recovery.  It is the sole process that retains the lifecycle
lock descriptor and, for an evidentiary build, the cohort-allocation lock
descriptor.  The inner qcsd-lab process receives a
parent/start-time/source/lock handshake, an initial readiness/admission pair,
and a separate recovery/final-admission pair, but never either lock descriptor
itself.
"""

from __future__ import annotations

from dataclasses import dataclass
import array
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import struct
import sys
import time
from typing import Callable, NoReturn, Sequence


SCHEMA = "1"
ENV_PREFIX = "QCSD_DOCKER_LOCK_GUARDIAN_"
ACQUISITION_LOCK_ENV = "QCSD_CLASS_ACQUISITION_LOCK_FD"
COHORT_REGISTRY_RELATIVE = Path("artifacts/buflo-study/cohort-claims-v1")
COHORT_LOCK_NAME = ".allocation.lock"
COHORT_OPERATION_LOCK_NAME = ".allocation-operation.lock"
READY_TIMEOUT_SECONDS = 30.0
RECOVERY_TIMEOUT_SECONDS = 1500.0
RECOVERY_IDLE_TIMEOUT_SECONDS = 360.0
LEASE_SERVICE_SECONDS = 0.25
INTEGRITY_CHECK_SECONDS = 0.25
FAILURE_CLEANUP_SECONDS = 120.0
GROUP_DRAIN_SECONDS = 5.0
FINAL_CONFIG_DRAIN_SECONDS = 2.0
CURRENT_CONFIG_DRAIN_SECONDS = 5.0
BUILDX_CENSUS_ATTEMPTS = 4
BUILDX_CENSUS_RETRY_SECONDS = 0.005
CHILD_EXIT_CONFIRM_ATTEMPTS = 20
CHILD_EXIT_CONFIRM_RETRY_SECONDS = 0.001
DOCKER_CONFIG_MODE = 0o500
MAX_RECOVERABLE_CONFIG_RESIDUES = 8
LOCK_PARENT = Path("/var/tmp")
FORWARDED_SIGNALS = (
    signal.SIGHUP,
    signal.SIGINT,
    signal.SIGQUIT,
    signal.SIGTERM,
)
PR_SET_PDEATHSIG = 1
LEASE_MESSAGE = b"QCSD-LOCK-LEASE-V1\n"
LEASE_ACTIONS = frozenset(
    {
        "publish",
        "hold-creation",
        "hold-api-service",
        "promote-authority",
        "rename-root",
        "unlink",
        "rmdir",
        "unlink-authority",
    }
)
HEX_64 = re.compile(r"[0-9a-f]{64}")
CAP_DAC_OVERRIDE = 1 << 1
_UNSAFE_ENVIRONMENT = frozenset(
    {
        "BASHOPTS",
        "BASH_COMPAT",
        "BASH_ENV",
        "BASH_XTRACEFD",
        "CDPATH",
        "DOCKER_CONFIG",
        "ENV",
        "GLOBIGNORE",
        "IFS",
        "POSIXLY_CORRECT",
        "SHELLOPTS",
        "DBUS_SESSION_BUS_ADDRESS",
        "TEMP",
        "TMP",
        "TMPDIR",
        "XDG_RUNTIME_DIR",
    }
)
_SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_POWERSHELL_PATH = Path(
    "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
)
HANDSHAKE_FIELDS = frozenset(
    {
        "SCHEMA",
        "PID",
        "START_TIME",
        "BOOT_ID",
        "LOCK_PATH",
        "LOCK_DEVICE",
        "LOCK_INODE",
        "LOCK_FD",
        "SOURCE_PATH",
        "SOURCE_FD",
        "SOURCE_DEVICE",
        "SOURCE_INODE",
        "SOURCE_SHA256",
        "QCSD_SOURCE_PATH",
        "QCSD_SOURCE_FD",
        "QCSD_SOURCE_DEVICE",
        "QCSD_SOURCE_INODE",
        "QCSD_SOURCE_SHA256",
        "HELPER_SOURCE_PATH",
        "HELPER_SOURCE_DEVICE",
        "HELPER_SOURCE_INODE",
        "HELPER_SOURCE_SHA256",
        "NATIVE_SOURCE_PATH",
        "NATIVE_SOURCE_DEVICE",
        "NATIVE_SOURCE_INODE",
        "NATIVE_SOURCE_SHA256",
        "INNER_PID",
        "INNER_START_TIME",
        "INNER_SESSION",
        "INNER_PROCESS_GROUP",
        "NONCE",
        "READY_FD",
        "GO_FD",
        "GO_NONCE",
        "RECOVERY_READY_FD",
        "RECOVERY_NONCE",
        "FINAL_GO_FD",
        "FINAL_GO_NONCE",
        "LEASE_SOCKET",
        "LEASE_NONCE",
        "DOCKER_CONFIG_PATH",
        "DOCKER_CONFIG_DEVICE",
        "DOCKER_CONFIG_INODE",
        "BUILDX_CONFIG_PATH",
        "BUILDX_CONFIG_DEVICE",
        "BUILDX_CONFIG_INODE",
        "COHORT_LOCK_REQUIRED",
        "COHORT_VERSION",
        "COHORT_LOCK_FD",
        "COHORT_LOCK_PATH",
        "COHORT_LOCK_DEVICE",
        "COHORT_LOCK_INODE",
        "COHORT_LOCK_PARENT_DEVICE",
        "COHORT_LOCK_PARENT_INODE",
    }
)


class GuardianError(RuntimeError):
    """The guardian cannot safely transfer or retain lock authority."""


class _CensusRestart(RuntimeError):
    """A numeric PID changed class while one procfs census was being bound."""


def _require_unprivileged_identity() -> None:
    """Require one non-root identity with no path-write override capability."""

    required = {"Uid", "Gid", "CapInh", "CapPrm", "CapEff", "CapAmb"}
    observed: dict[str, list[str]] = {}
    try:
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            key, separator, tail = line.partition(":")
            if key not in required:
                continue
            if not separator or key in observed:
                _fail("guardian privilege identity is malformed")
            observed[key] = tail.split()
    except (OSError, UnicodeError) as error:
        raise GuardianError("guardian privilege identity is unavailable") from error
    if set(observed) != required:
        _fail("guardian privilege identity is incomplete")
    try:
        uid = tuple(int(value, 10) for value in observed["Uid"])
        gid = tuple(int(value, 10) for value in observed["Gid"])
        capabilities = tuple(
            int(observed[key][0], 16)
            for key in ("CapInh", "CapPrm", "CapEff", "CapAmb")
        )
    except (IndexError, ValueError) as error:
        raise GuardianError("guardian privilege identity is malformed") from error
    if (
        len(uid) != 4
        or len(gid) != 4
        or any(len(observed[key]) != 1 for key in required - {"Uid", "Gid"})
        or len(set(uid)) != 1
        or len(set(gid)) != 1
        or uid[0] == 0
        or gid[0] == 0
        or uid[:3] != os.getresuid()
        or gid[:3] != os.getresgid()
        or os.getuid() != uid[0]
        or os.geteuid() != uid[0]
        or os.getgid() != gid[0]
        or os.getegid() != gid[0]
        or any(value & CAP_DAC_OVERRIDE for value in capabilities)
    ):
        _fail(
            "guardian requires one matching non-root UID/GID identity "
            "without CAP_DAC_OVERRIDE"
        )


@dataclass(frozen=True)
class FileIdentity:
    path: Path
    device: int
    inode: int
    owner: int
    mode: int
    links: int
    sha256: str


@dataclass(frozen=True)
class LockIdentity:
    path: Path
    parent_device: int
    parent_inode: int
    device: int
    inode: int
    owner: int
    mode: int
    links: int


@dataclass(frozen=True)
class ChildIdentity:
    pid: int
    start_time: int
    session: int
    process_group: int
    command: tuple[str, ...]


@dataclass(frozen=True)
class InheritedLockIdentity:
    descriptor: int
    device: int
    inode: int
    owner: int
    mode: int
    links: int


@dataclass(frozen=True)
class CohortDirectoryIdentity:
    path: Path
    device: int
    inode: int
    owner: int
    mode: int


@dataclass
class CohortLockLease:
    cohort_version: int
    root_fd: int
    artifacts_fd: int
    study_fd: int
    registry_fd: int
    lock_fd: int
    root: CohortDirectoryIdentity
    artifacts: CohortDirectoryIdentity
    study: CohortDirectoryIdentity
    registry: CohortDirectoryIdentity
    lock: LockIdentity
    operation_fd: int = -1
    operation_lock: LockIdentity | None = None
    operation_locked: bool = False


@dataclass(frozen=True)
class ConfigDirectoryIdentity:
    path: Path
    device: int
    inode: int
    owner: int
    mode: int
    links: int


@dataclass
class DockerConfigResidue:
    descriptor: int
    config: ConfigDirectoryIdentity
    boot_token: str
    guardian_start: int
    census_start: int
    quarantined: bool = False
    removed: bool = False


@dataclass
class DockerConfigCleanupResidue:
    descriptor: int
    config: ConfigDirectoryIdentity


@dataclass(frozen=True)
class RecordIdentity:
    name: str
    device: int
    inode: int


@dataclass(frozen=True)
class BuildxLedger:
    token: str
    root_name: str
    root_path: Path
    exported_path: Path
    config: ConfigDirectoryIdentity
    authority: RecordIdentity
    authority_value: dict[str, object]


@dataclass(frozen=True)
class PathIdentity:
    path: Path
    device: int
    inode: int
    owner: int
    mode: int
    kind: int


@dataclass(frozen=True)
class RuntimeEnvironmentIdentity:
    run: PathIdentity
    run_user: PathIdentity
    user_runtime: PathIdentity
    bus: PathIdentity
    temporary: PathIdentity


class _SignalLatch:
    def __init__(self) -> None:
        self.first: int | None = None

    def handler(self, requested: int, _frame: object) -> None:
        if self.first is None:
            self.first = requested


def _fail(message: str) -> NoReturn:
    raise GuardianError(message)


def _process_start_time(pid: int) -> int:
    return _process_identity(pid)[3]


def _process_identity(pid: int) -> tuple[int, int, int, int]:
    state, parent, process_group, session, start_time = _process_record(pid)
    del state
    return parent, process_group, session, start_time


def _process_record(pid: int) -> tuple[str, int, int, int, int]:
    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise GuardianError("cannot read guardian process identity") from error
    try:
        fields = value.rsplit(") ", maxsplit=1)[1].split()
        state = fields[0]
        parent = int(fields[1])
        process_group = int(fields[2])
        session = int(fields[3])
        start_time = int(fields[19])
    except (IndexError, ValueError) as error:
        raise GuardianError("guardian process identity is malformed") from error
    if (
        len(state) != 1
        or min(parent, process_group, session, start_time) < 0
        or start_time == 0
    ):
        _fail("guardian process start time is invalid")
    return state, parent, process_group, session, start_time


def _boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii"
        ).strip()
    except (OSError, UnicodeError) as error:
        raise GuardianError("cannot bind the guardian host boot") from error
    fields = value.split("-")
    if [len(field) for field in fields] != [8, 4, 4, 4, 12] or any(
        not field or any(character not in "0123456789abcdef" for character in field)
        for field in fields
    ):
        _fail("guardian host boot identity is malformed")
    return value


def _boot_token() -> str:
    """Return the validated boot identity in pathname-safe canonical form."""

    return _boot_id().replace("-", "")


def _docker_config_name_pattern(uid: int) -> re.Pattern[str]:
    """Recognise the versioned, boot-bound published Docker config name."""

    return re.compile(
        rf"[.]qcsd-docker-config-{uid}[.]v2[.]"
        rf"(?P<boot>[0-9a-f]{{32}})[.]"
        rf"(?P<start>[1-9][0-9]*)[.]"
        rf"(?P<nonce>[0-9a-f]{{64}})"
    )


def _docker_config_construction_name_pattern(uid: int) -> re.Pattern[str]:
    """Recognise a v2 root that was never published to a Docker client."""

    return re.compile(
        rf"[.]qcsd-docker-config-{uid}[.]construct[.]v2[.]"
        rf"(?P<boot>[0-9a-f]{{32}})[.]"
        rf"(?P<start>[1-9][0-9]*)[.]"
        rf"(?P<nonce>[0-9a-f]{{64}})"
    )


def _docker_config_quarantine_name_pattern(uid: int) -> re.Pattern[str]:
    """Recognise a published root atomically closed to future users."""

    return re.compile(
        rf"[.]qcsd-docker-config-{uid}[.]retiring[.]v2[.]"
        rf"(?P<boot>[0-9a-f]{{32}})[.]"
        rf"(?P<start>[1-9][0-9]*)[.]"
        rf"(?P<nonce>[0-9a-f]{{64}})"
    )


def _read_and_hash(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        block = os.read(fd, 65536)
        if not block:
            break
        digest.update(block)
    return digest.hexdigest()


def _capture_source_identity(source_path: Path) -> tuple[int, FileIdentity]:
    if not source_path.is_absolute():
        _fail("guardian source path must be absolute")
    try:
        lexical = source_path.absolute()
        canonical = source_path.resolve(strict=True)
    except OSError as error:
        raise GuardianError("cannot resolve guardian source") from error
    if canonical != lexical:
        _fail("guardian source cannot be a symlink")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(source_path, flags)
    except OSError as error:
        raise GuardianError("cannot open guardian source") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_nlink != 1
        ):
            _fail("guardian source identity is unsafe")
        digest = _read_and_hash(descriptor)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_mode,
            before.st_nlink,
            before.st_size,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_mode,
            after.st_nlink,
            after.st_size,
        ):
            _fail("guardian source changed while it was hashed")
        identity = FileIdentity(
            path=canonical,
            device=after.st_dev,
            inode=after.st_ino,
            owner=after.st_uid,
            mode=stat.S_IMODE(after.st_mode),
            links=after.st_nlink,
            sha256=digest,
        )
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _capture_bound_source_identity(
    descriptor: int, source_path: Path
) -> FileIdentity:
    if descriptor <= 2 or not source_path.is_absolute():
        _fail("bound guardian source descriptor is unsafe")
    try:
        lexical = source_path.absolute()
        canonical = source_path.resolve(strict=True)
        opened = os.fstat(descriptor)
        path_value = os.stat(source_path, follow_symlinks=False)
    except OSError as error:
        raise GuardianError("cannot bind held guardian source") from error
    wanted = (
        opened.st_dev,
        opened.st_ino,
        opened.st_uid,
        stat.S_IMODE(opened.st_mode),
        opened.st_nlink,
        opened.st_size,
    )
    observed = (
        path_value.st_dev,
        path_value.st_ino,
        path_value.st_uid,
        stat.S_IMODE(path_value.st_mode),
        path_value.st_nlink,
        path_value.st_size,
    )
    if (
        canonical != lexical
        or source_path.is_symlink()
        or not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(path_value.st_mode)
        or wanted != observed
        or opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) & 0o022
        or opened.st_nlink != 1
    ):
        _fail("bound guardian source identity is unsafe")
    return FileIdentity(
        canonical,
        opened.st_dev,
        opened.st_ino,
        opened.st_uid,
        stat.S_IMODE(opened.st_mode),
        opened.st_nlink,
        _read_and_hash(descriptor),
    )


def _verify_source_identity(descriptor: int, expected: FileIdentity) -> None:
    try:
        path_value = os.stat(expected.path, follow_symlinks=False)
        opened = os.fstat(descriptor)
    except OSError as error:
        raise GuardianError("guardian source identity is unavailable") from error
    observed = (
        opened.st_dev,
        opened.st_ino,
        opened.st_uid,
        stat.S_IMODE(opened.st_mode),
        opened.st_nlink,
    )
    path_observed = (
        path_value.st_dev,
        path_value.st_ino,
        path_value.st_uid,
        stat.S_IMODE(path_value.st_mode),
        path_value.st_nlink,
    )
    expected_value = (
        expected.device,
        expected.inode,
        expected.owner,
        expected.mode,
        expected.links,
    )
    if observed != expected_value or path_observed != expected_value:
        _fail("guardian source path changed")
    if _read_and_hash(descriptor) != expected.sha256:
        _fail("guardian source content changed")


def _open_lock_parent(parent: Path) -> tuple[int, os.stat_result]:
    if not parent.is_absolute():
        _fail("lifecycle lock parent must be absolute")
    try:
        lexical = parent.absolute()
        canonical = parent.resolve(strict=True)
        descriptor = os.open(
            parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
    except OSError as error:
        raise GuardianError("cannot open lifecycle lock parent") from error
    try:
        value = os.fstat(descriptor)
        if canonical != lexical or not stat.S_ISDIR(value.st_mode):
            _fail("lifecycle lock parent identity is unsafe")
        if parent == LOCK_PARENT and (
            value.st_uid != 0 or stat.S_IMODE(value.st_mode) != 0o1777
        ):
            _fail("/var/tmp has an unsafe identity")
        if parent != LOCK_PARENT and (
            value.st_uid != os.getuid() or stat.S_IMODE(value.st_mode) != 0o700
        ):
            _fail("test lifecycle lock parent is not private")
        return descriptor, value
    except BaseException:
        os.close(descriptor)
        raise


def _open_lock(parent_fd: int, parent: Path) -> tuple[int, LockIdentity]:
    uid = os.getuid()
    name = f"qcsd-docker-lifecycle-{uid}.lock"
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_fd,
            )
            os.fsync(descriptor)
            os.fsync(parent_fd)
        except OSError as error:
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise GuardianError("cannot create lifecycle lock") from error
    except OSError as error:
        raise GuardianError("cannot open lifecycle lock") from error
    try:
        value = os.fstat(descriptor)
        parent_value = os.fstat(parent_fd)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != uid
            or stat.S_IMODE(value.st_mode) != 0o600
            or value.st_nlink != 1
            or value.st_size != 0
        ):
            _fail("lifecycle lock identity is unsafe")
        identity = LockIdentity(
            path=parent / name,
            parent_device=parent_value.st_dev,
            parent_inode=parent_value.st_ino,
            device=value.st_dev,
            inode=value.st_ino,
            owner=value.st_uid,
            mode=stat.S_IMODE(value.st_mode),
            links=value.st_nlink,
        )
        _verify_lock_identity(parent_fd, descriptor, identity)
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _verify_lock_identity(
    parent_fd: int, descriptor: int, expected: LockIdentity
) -> None:
    try:
        parent = os.fstat(parent_fd)
        opened = os.fstat(descriptor)
        path_value = os.stat(
            expected.path.name, dir_fd=parent_fd, follow_symlinks=False
        )
    except OSError as error:
        raise GuardianError("lifecycle lock identity is unavailable") from error
    if (parent.st_dev, parent.st_ino) != (
        expected.parent_device,
        expected.parent_inode,
    ):
        _fail("lifecycle lock parent changed")
    wanted = (
        expected.device,
        expected.inode,
        expected.owner,
        expected.mode,
        expected.links,
        0,
    )
    for value in (opened, path_value):
        observed = (
            value.st_dev,
            value.st_ino,
            value.st_uid,
            stat.S_IMODE(value.st_mode),
            value.st_nlink,
            value.st_size,
        )
        if not stat.S_ISREG(value.st_mode) or observed != wanted:
            _fail("lifecycle lock path changed")


def _requested_build_cohort(command: Sequence[str]) -> int | None:
    """Return the cohort selected by one exact evidentiary-build argv."""

    if len(command) < 2 or command[1] != "build":
        return None
    arguments = tuple(command[2:])
    value = ""
    if len(arguments) == 2 and arguments[0] == "--cohort-version":
        value = arguments[1]
    elif len(arguments) == 1 and arguments[0].startswith("--cohort-version="):
        value = arguments[0].partition("=")[2]
    if re.fullmatch(r"[1-9][0-9]*", value) is None:
        _fail("evidentiary build argv does not select one exact cohort")
    return int(value)


def _cohort_directory_identity(
    descriptor: int,
    path: Path,
    *,
    parent_fd: int | None = None,
    name: str | None = None,
    exact_mode: int | None = None,
) -> CohortDirectoryIdentity:
    try:
        opened = os.fstat(descriptor)
        entry = (
            os.stat(path, follow_symlinks=False)
            if parent_fd is None
            else os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        )
    except OSError as error:
        raise GuardianError("cohort-allocation directory is unavailable") from error
    mode = stat.S_IMODE(opened.st_mode)
    observed = (opened.st_dev, opened.st_ino, opened.st_uid, mode)
    path_observed = (
        entry.st_dev,
        entry.st_ino,
        entry.st_uid,
        stat.S_IMODE(entry.st_mode),
    )
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(entry.st_mode)
        or observed != path_observed
        or opened.st_uid != os.getuid()
        or mode & 0o022
        or (exact_mode is not None and mode != exact_mode)
        or opened.st_nlink < 2
        or entry.st_nlink < 2
    ):
        _fail("cohort-allocation directory identity is unsafe")
    return CohortDirectoryIdentity(
        path=path,
        device=opened.st_dev,
        inode=opened.st_ino,
        owner=opened.st_uid,
        mode=mode,
    )


def _open_or_create_cohort_directory(
    parent_fd: int,
    parent_path: Path,
    name: str,
    *,
    exact_mode: int | None = None,
) -> tuple[int, CohortDirectoryIdentity]:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    created = False
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            pass
        except OSError as error:
            raise GuardianError(
                "cannot create cohort-allocation directory"
            ) from error
        if created:
            os.fsync(parent_fd)
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
        except OSError as error:
            raise GuardianError(
                "cannot open cohort-allocation directory"
            ) from error
    except OSError as error:
        raise GuardianError("cannot open cohort-allocation directory") from error
    try:
        if created:
            os.fsync(descriptor)
        identity = _cohort_directory_identity(
            descriptor,
            parent_path / name,
            parent_fd=parent_fd,
            name=name,
            exact_mode=exact_mode,
        )
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _open_cohort_lock_lease(
    command: Sequence[str],
    qcsd: FileIdentity,
    latch: "_SignalLatch",
    acquisition_lock: InheritedLockIdentity | None = None,
) -> CohortLockLease | None:
    cohort_version = _requested_build_cohort(command)
    if cohort_version is None:
        return None
    root_path = qcsd.path.parent
    try:
        canonical_root = root_path.resolve(strict=True)
    except OSError as error:
        raise GuardianError(
            "cohort-allocation root is unavailable"
        ) from error
    if not root_path.is_absolute() or canonical_root != root_path:
        _fail("cohort-allocation root is not canonical")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    root_fd = artifacts_fd = study_fd = registry_fd = lock_fd = -1
    try:
        root_fd = os.open(root_path, flags)
        root = _cohort_directory_identity(root_fd, root_path)
        artifacts_fd, artifacts = _open_or_create_cohort_directory(
            root_fd, root_path, "artifacts"
        )
        study_fd, study = _open_or_create_cohort_directory(
            artifacts_fd, artifacts.path, "buflo-study"
        )
        registry_fd, registry = _open_or_create_cohort_directory(
            study_fd,
            study.path,
            "cohort-claims-v1",
            exact_mode=0o700,
        )
        lock_flags = (
            os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        )
        created = False
        try:
            lock_fd = os.open(COHORT_LOCK_NAME, lock_flags, dir_fd=registry_fd)
        except FileNotFoundError:
            try:
                lock_fd = os.open(
                    COHORT_LOCK_NAME,
                    lock_flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=registry_fd,
                )
                created = True
            except OSError as error:
                raise GuardianError(
                    "cannot create cohort-allocation lock"
                ) from error
        except OSError as error:
            raise GuardianError("cannot open cohort-allocation lock") from error
        if created:
            os.fchmod(lock_fd, 0o600)
            os.fsync(lock_fd)
            os.fsync(registry_fd)
        lock_value = os.fstat(lock_fd)
        registry_value = os.fstat(registry_fd)
        lock = LockIdentity(
            path=registry.path / COHORT_LOCK_NAME,
            parent_device=registry_value.st_dev,
            parent_inode=registry_value.st_ino,
            device=lock_value.st_dev,
            inode=lock_value.st_ino,
            owner=lock_value.st_uid,
            mode=stat.S_IMODE(lock_value.st_mode),
            links=lock_value.st_nlink,
        )
        _verify_lock_identity(registry_fd, lock_fd, lock)
        if (
            lock.owner != os.getuid()
            or lock.mode != 0o600
            or lock.links != 1
            or lock_value.st_size != 0
        ):
            _fail("cohort-allocation lock identity is unsafe")
        if acquisition_lock is not None and (
            acquisition_lock.device,
            acquisition_lock.inode,
        ) == (lock.device, lock.inode):
            _fail("acquisition lock aliases the cohort-allocation lock")
        _acquire_lock(lock_fd, latch)
        lease = CohortLockLease(
            cohort_version=cohort_version,
            root_fd=root_fd,
            artifacts_fd=artifacts_fd,
            study_fd=study_fd,
            registry_fd=registry_fd,
            lock_fd=lock_fd,
            root=root,
            artifacts=artifacts,
            study=study,
            registry=registry,
            lock=lock,
        )
        _verify_cohort_lock_lease(lease, os.getpid())
        return lease
    except BaseException:
        for descriptor in (lock_fd, registry_fd, study_fd, artifacts_fd, root_fd):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        raise


def _drain_cohort_operation_lock(
    lease: CohortLockLease,
    lifecycle_lock: LockIdentity,
    latch: "_SignalLatch",
    acquisition_lock: InheritedLockIdentity | None = None,
) -> None:
    """Drain an allocator that may outlive the preceding guardian.

    The guardian already owns the durable allocation lock (A) when it opens
    and acquires this distinct operation lock (B).  A remote allocator holds B
    for each registry operation.  Consequently a successor cannot launch its
    qcsd child until any allocator orphaned by guardian death has stopped
    mutating the registry.  B is released before the child is forked and is
    never inherited by qcsd.
    """

    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    descriptor = -1
    acquired = False
    try:
        created = False
        try:
            descriptor = os.open(
                COHORT_OPERATION_LOCK_NAME,
                flags,
                dir_fd=lease.registry_fd,
            )
        except FileNotFoundError:
            try:
                descriptor = os.open(
                    COHORT_OPERATION_LOCK_NAME,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=lease.registry_fd,
                )
                created = True
            except OSError as error:
                raise GuardianError(
                    "cannot create cohort-allocation operation lock"
                ) from error
        except OSError as error:
            raise GuardianError(
                "cannot open cohort-allocation operation lock"
            ) from error
        if created:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(lease.registry_fd)
        opened = os.fstat(descriptor)
        registry = os.fstat(lease.registry_fd)
        operation_lock = LockIdentity(
            path=lease.registry.path / COHORT_OPERATION_LOCK_NAME,
            parent_device=registry.st_dev,
            parent_inode=registry.st_ino,
            device=opened.st_dev,
            inode=opened.st_ino,
            owner=opened.st_uid,
            mode=stat.S_IMODE(opened.st_mode),
            links=opened.st_nlink,
        )
        aliases = {
            (lease.lock.device, lease.lock.inode),
            (lifecycle_lock.device, lifecycle_lock.inode),
        }
        if acquisition_lock is not None:
            aliases.add((acquisition_lock.device, acquisition_lock.inode))
        if (operation_lock.device, operation_lock.inode) in aliases:
            _fail("cohort-allocation operation lock aliases another authority lock")
        if (
            not stat.S_ISREG(opened.st_mode)
            or operation_lock.owner != os.getuid()
            or operation_lock.mode != 0o600
            or operation_lock.links != 1
            or opened.st_size != 0
        ):
            _fail("cohort-allocation operation lock identity is unsafe")
        _verify_lock_identity(lease.registry_fd, descriptor, operation_lock)
        while True:
            if latch.first is not None:
                _fail("signal received before cohort-allocation operation drain")
            _verify_cohort_lock_lease(lease, os.getpid())
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                time.sleep(0.02)
            except OSError as error:
                if error.errno != errno.EINTR:
                    raise GuardianError(
                        "cannot drain cohort-allocation operation lock"
                    ) from error
        _verify_cohort_lock_lease(lease, os.getpid())
        _verify_lock_identity(lease.registry_fd, descriptor, operation_lock)
        _verify_descriptor_lock(
            operation_lock.device,
            operation_lock.inode,
            os.getpid(),
            descriptor,
            failure=(
                "guardian does not exclusively own the cohort-allocation "
                "operation flock"
            ),
            owner=os.getpid(),
        )
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        acquired = False
        lease.operation_fd = descriptor
        lease.operation_lock = operation_lock
        descriptor = -1
        _verify_cohort_lock_lease(lease, os.getpid())
    finally:
        if descriptor >= 0:
            try:
                if acquired:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def _verify_cohort_directory(
    descriptor: int,
    expected: CohortDirectoryIdentity,
    *,
    parent_fd: int | None = None,
    name: str | None = None,
    exact_mode: int | None = None,
) -> None:
    observed = _cohort_directory_identity(
        descriptor,
        expected.path,
        parent_fd=parent_fd,
        name=name,
        exact_mode=exact_mode,
    )
    if observed != expected:
        _fail("cohort-allocation directory path changed")


def _verify_cohort_lock_lease(
    lease: CohortLockLease, guardian_pid: int
) -> None:
    _verify_cohort_directory(lease.root_fd, lease.root)
    _verify_cohort_directory(
        lease.artifacts_fd,
        lease.artifacts,
        parent_fd=lease.root_fd,
        name="artifacts",
    )
    _verify_cohort_directory(
        lease.study_fd,
        lease.study,
        parent_fd=lease.artifacts_fd,
        name="buflo-study",
    )
    _verify_cohort_directory(
        lease.registry_fd,
        lease.registry,
        parent_fd=lease.study_fd,
        name="cohort-claims-v1",
        exact_mode=0o700,
    )
    _verify_lock_identity(lease.registry_fd, lease.lock_fd, lease.lock)
    _verify_descriptor_lock(
        lease.lock.device,
        lease.lock.inode,
        guardian_pid,
        lease.lock_fd,
        failure="guardian does not exclusively own the cohort-allocation flock",
        owner=guardian_pid,
    )
    if (lease.operation_fd >= 0) != (lease.operation_lock is not None):
        _fail("cohort-allocation operation lock binding is incomplete")
    if lease.operation_lock is not None:
        _verify_lock_identity(
            lease.registry_fd,
            lease.operation_fd,
            lease.operation_lock,
        )
        if lease.operation_locked:
            _verify_descriptor_lock(
                lease.operation_lock.device,
                lease.operation_lock.inode,
                guardian_pid,
                lease.operation_fd,
                failure=(
                    "guardian does not exclusively own the terminal "
                    "cohort-allocation operation flock"
                ),
                owner=guardian_pid,
            )


def _lock_cohort_operation_for_cleanup(
    lease: CohortLockLease, *, deadline: float
) -> None:
    """Prove allocator quiescence after qcsd/session drain, before releasing A."""

    if (
        lease.operation_fd < 0
        or lease.operation_lock is None
        or lease.operation_locked
    ):
        _fail("cohort-allocation operation lock is unavailable for terminal drain")
    while True:
        _verify_cohort_lock_lease(lease, os.getpid())
        try:
            fcntl.flock(
                lease.operation_fd,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
            lease.operation_locked = True
            break
        except BlockingIOError:
            if time.monotonic() >= deadline:
                _fail("cohort-allocation operation lock did not drain at cleanup")
            time.sleep(0.02)
        except OSError as error:
            if error.errno != errno.EINTR:
                raise GuardianError(
                    "cannot drain cohort-allocation operation lock at cleanup"
                ) from error
    _verify_cohort_lock_lease(lease, os.getpid())


def _close_cohort_lock_lease(lease: CohortLockLease) -> None:
    first_error: OSError | None = None
    for descriptor in (
        lease.operation_fd,
        lease.lock_fd,
        lease.registry_fd,
        lease.study_fd,
        lease.artifacts_fd,
        lease.root_fd,
    ):
        try:
            if descriptor >= 0:
                os.close(descriptor)
        except OSError as error:
            if first_error is None:
                first_error = error
    if first_error is not None:
        raise first_error


def _prepare_private_config(
    parent_fd: int,
    guardian_pid: int,
    *,
    continuation_check: Callable[[], None] | None = None,
) -> tuple[int, ConfigDirectoryIdentity, list[DockerConfigResidue]]:
    """Create an empty linked read-only Docker config.

    A distinct ``construct.v2`` basename marks state that was never published;
    it can be mode 0700, or mode 0500 after ``fchmod`` but before the atomic
    rename.  The live root remains pathname-linked at mode 0500: Docker can
    read and traverse it, while BuildKit's optional token-seed lock/write
    receives a permission failure and uses its upstream in-memory fallback.
    Exact published and ``retiring.v2`` residues are bound and retained while
    the trusted inner process performs stale-lifecycle recovery.  A retiring
    basename is the durable admission barrier: cooperative clients know only
    published names, while recovery can still find and census the exact inode.
    Every residue must drain and be removed before the inner process can cross
    the separate final-admission boundary.
    """

    uid = os.getuid()
    label = "Docker"
    prefix = f".qcsd-docker-config-{uid}."
    name_pattern = _docker_config_name_pattern(uid)
    construction_pattern = _docker_config_construction_name_pattern(uid)
    quarantine_pattern = _docker_config_quarantine_name_pattern(uid)
    transitional_pattern = re.compile(
        re.escape(prefix) + r"[1-9][0-9]*[.][0-9a-f]{64}"
    )
    legacy_pattern = re.compile(re.escape(prefix) + r"[0-9a-f]{64}")
    parent_path = Path(f"/proc/self/fd/{parent_fd}").resolve(strict=True)
    guardian_start = _process_start_time(guardian_pid)
    current_boot_token = _boot_token()
    residues: list[DockerConfigResidue] = []
    cleanup_residues: list[DockerConfigCleanupResidue] = []
    scanned_names: set[str] = set()
    config_fd = -1
    created_identity: ConfigDirectoryIdentity | None = None
    published_name: str | None = None
    residue_generations: set[tuple[str, str, str]] = set()
    try:
        try:
            with os.scandir(parent_fd) as entries:
                for entry in entries:
                    if not entry.name.startswith(prefix):
                        continue
                    scanned_names.add(entry.name)
                    if len(scanned_names) > MAX_RECOVERABLE_CONFIG_RESIDUES:
                        _fail(
                            "Docker config residue count exceeds its recovery bound"
                        )
        except OSError as error:
            raise GuardianError(
                "cannot enumerate the Docker config residue namespace"
            ) from error
        for name in sorted(scanned_names):
            name_match = name_pattern.fullmatch(name)
            construction_match = construction_pattern.fullmatch(name)
            quarantine_match = quarantine_pattern.fullmatch(name)
            transitional_match = transitional_pattern.fullmatch(name)
            legacy_match = legacy_pattern.fullmatch(name)
            if (
                name_match is None
                and construction_match is None
                and quarantine_match is None
                and transitional_match is None
                and legacy_match is None
            ):
                _fail(f"{label} config residue name is malformed")
            generation_match = (
                name_match or construction_match or quarantine_match
            )
            if generation_match is not None:
                generation = (
                    generation_match.group("boot"),
                    generation_match.group("start"),
                    generation_match.group("nonce"),
                )
                if generation in residue_generations:
                    _fail(f"{label} config residue generation is duplicated")
                residue_generations.add(generation)
            residue_fd = -1
            try:
                value = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                residue_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent_fd,
                )
            except OSError as error:
                raise GuardianError(
                    f"cannot bind {label} config residue"
                ) from error
            try:
                opened = os.fstat(residue_fd)
                residue_mode = stat.S_IMODE(value.st_mode)
                if construction_match is not None:
                    allowed_modes = {DOCKER_CONFIG_MODE, 0o700}
                elif name_match is not None or quarantine_match is not None:
                    allowed_modes = {DOCKER_CONFIG_MODE}
                else:
                    allowed_modes = {0o700}
                if (
                    not stat.S_ISDIR(value.st_mode)
                    or not stat.S_ISDIR(opened.st_mode)
                    or (value.st_dev, value.st_ino)
                    != (opened.st_dev, opened.st_ino)
                    or value.st_uid != uid
                    or opened.st_uid != uid
                    or residue_mode not in allowed_modes
                    or stat.S_IMODE(opened.st_mode) != residue_mode
                    or value.st_nlink != 2
                    or opened.st_nlink != 2
                    or os.listdir(residue_fd)
                ):
                    _fail(
                        f"{label} config residue is not an exact empty directory"
                    )
                linked_match = name_match or quarantine_match
                if linked_match is not None:
                    residue_boot_token = linked_match.group("boot")
                    residue_start = int(linked_match.group("start"))
                    quarantined = quarantine_match is not None
                    if (
                        residue_boot_token == current_boot_token
                        and residue_start > guardian_start
                    ):
                        _fail(
                            "published Docker config residue start time is "
                            "newer than the current guardian in this boot"
                        )
                    identity = ConfigDirectoryIdentity(
                        path=parent_path / name,
                        device=opened.st_dev,
                        inode=opened.st_ino,
                        owner=opened.st_uid,
                        mode=residue_mode,
                        links=opened.st_nlink,
                    )
                    _verify_private_config(
                        parent_fd,
                        residue_fd,
                        identity,
                        require_empty=True,
                        quarantined=quarantined,
                    )
                    residues.append(
                        DockerConfigResidue(
                            descriptor=residue_fd,
                            config=identity,
                            boot_token=residue_boot_token,
                            guardian_start=residue_start,
                            census_start=(
                                residue_start
                                if residue_boot_token == current_boot_token
                                else guardian_start
                            ),
                            quarantined=quarantined,
                        )
                    )
                    residue_fd = -1
                    continue
                cleanup_residues.append(
                    DockerConfigCleanupResidue(
                        descriptor=residue_fd,
                        config=ConfigDirectoryIdentity(
                            path=parent_path / name,
                            device=opened.st_dev,
                            inode=opened.st_ino,
                            owner=opened.st_uid,
                            mode=residue_mode,
                            links=opened.st_nlink,
                        ),
                    )
                )
                residue_fd = -1
            finally:
                if residue_fd >= 0:
                    try:
                        os.close(residue_fd)
                    except OSError as error:
                        raise GuardianError(
                            f"cannot close {label} config residue"
                        ) from error

        _verify_private_config_residues(parent_fd, residues)
        for residue in cleanup_residues:
            _verify_unpublished_private_config(parent_fd, residue)
        if continuation_check is not None:
            continuation_check()
        try:
            observed_names = {
                item
                for item in os.listdir(parent_fd)
                if item.startswith(prefix)
            }
        except OSError as error:
            raise GuardianError(
                "cannot re-enumerate the Docker config residue namespace"
            ) from error
        if observed_names != scanned_names:
            _fail("Docker config residue namespace changed before cleanup")
        for residue in cleanup_residues:
            if continuation_check is not None:
                continuation_check()
            _remove_unpublished_private_config(parent_fd, residue)
        cleanup_residues.clear()
        expected_remaining = {
            residue.config.path.name for residue in residues
        }
        try:
            remaining_names = {
                item
                for item in os.listdir(parent_fd)
                if item.startswith(prefix)
            }
        except OSError as error:
            raise GuardianError(
                "cannot verify the cleaned Docker config residue namespace"
            ) from error
        if remaining_names != expected_remaining:
            _fail("Docker config residue namespace changed during cleanup")
        # Reserve one namespace slot for the root about to be published.  A
        # crash after publication must never leave more roots than a successor
        # is itself permitted to bind and recover.
        while len(residues) >= MAX_RECOVERABLE_CONFIG_RESIDUES:
            if continuation_check is not None:
                continuation_check()
            residue = residues[0]
            residue_deadline = time.monotonic() + GROUP_DRAIN_SECONDS
            _retire_private_config_residue(
                parent_fd,
                residue,
                deadline=residue_deadline,
                continuation_check=continuation_check,
            )
            os.close(residue.descriptor)
            del residues[0]
        expected_remaining = {
            residue.config.path.name for residue in residues
        }
        try:
            remaining_names = {
                item
                for item in os.listdir(parent_fd)
                if item.startswith(prefix)
            }
        except OSError as error:
            raise GuardianError(
                "cannot verify the bounded Docker config residue namespace"
            ) from error
        if remaining_names != expected_remaining:
            _fail("Docker config residue namespace changed while reserving capacity")
        if continuation_check is not None:
            continuation_check()
        nonce = os.urandom(32).hex()
        name = (
            prefix
            + f"construct.v2.{current_boot_token}.{guardian_start}.{nonce}"
        )
        published_name = (
            prefix + f"v2.{current_boot_token}.{guardian_start}.{nonce}"
        )
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        config_fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        opened = os.fstat(config_fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino, opened.st_uid)
            != (current.st_dev, current.st_ino, uid)
            or stat.S_IMODE(opened.st_mode) != 0o700
            or opened.st_nlink != 2
            or os.listdir(config_fd)
        ):
            _fail(f"new {label} config directory has an unsafe identity")
        created_identity = ConfigDirectoryIdentity(
            path=parent_path / name,
            device=opened.st_dev,
            inode=opened.st_ino,
            owner=opened.st_uid,
            mode=0o700,
            links=opened.st_nlink,
        )
        os.fchmod(config_fd, DOCKER_CONFIG_MODE)
        created_identity = ConfigDirectoryIdentity(
            path=created_identity.path,
            device=created_identity.device,
            inode=created_identity.inode,
            owner=created_identity.owner,
            mode=DOCKER_CONFIG_MODE,
            links=created_identity.links,
        )
        os.fsync(config_fd)
        if continuation_check is not None:
            continuation_check()
        _rename_noreplace(
            parent_fd,
            name,
            published_name,
            context="Docker config root",
        )
        name = published_name
        created_identity = ConfigDirectoryIdentity(
            path=parent_path / name,
            device=created_identity.device,
            inode=created_identity.inode,
            owner=created_identity.owner,
            mode=created_identity.mode,
            links=created_identity.links,
        )
        linked = os.fstat(config_fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(linked.st_mode)
            or (linked.st_dev, linked.st_ino, linked.st_uid)
            != (opened.st_dev, opened.st_ino, uid)
            or (current.st_dev, current.st_ino, current.st_uid)
            != (linked.st_dev, linked.st_ino, uid)
            or stat.S_IMODE(linked.st_mode) != DOCKER_CONFIG_MODE
            or stat.S_IMODE(current.st_mode) != DOCKER_CONFIG_MODE
            or linked.st_nlink != 2
            or current.st_nlink != 2
            or os.listdir(config_fd)
        ):
            _fail(f"linked {label} config directory has an unsafe identity")
        assert created_identity is not None
        identity = created_identity
        _verify_private_config(parent_fd, config_fd, identity, require_empty=True)
        _verify_private_config_residues(parent_fd, residues)
        _verify_private_config_namespace(parent_fd, identity, residues)
        if continuation_check is not None:
            continuation_check()
        current_key = (identity.device, identity.inode)
        if current_key in {
            (item.config.device, item.config.inode) for item in residues
        }:
            _fail("current Docker config aliases a published residue")
        return config_fd, identity, residues
    except BaseException as error:
        cleanup_error: GuardianError | None = None
        if config_fd >= 0 and created_identity is not None:
            cleanup_identity = created_identity
            if (
                published_name is not None
                and cleanup_identity.path.name != published_name
            ):
                try:
                    construction_value = os.stat(
                        cleanup_identity.path.name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    construction_value = None
                except OSError:
                    cleanup_error = GuardianError(
                        "cannot locate failed Docker config construction"
                    )
                try:
                    published_value = os.stat(
                        published_name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    published_value = None
                except OSError:
                    if cleanup_error is None:
                        cleanup_error = GuardianError(
                            "cannot locate failed Docker config publication"
                        )
                    published_value = None
                published_matches = published_value is not None and (
                    published_value.st_dev,
                    published_value.st_ino,
                ) == (cleanup_identity.device, cleanup_identity.inode)
                if published_matches and construction_value is None:
                    cleanup_identity = ConfigDirectoryIdentity(
                        path=cleanup_identity.path.with_name(published_name),
                        device=cleanup_identity.device,
                        inode=cleanup_identity.inode,
                        owner=cleanup_identity.owner,
                        mode=cleanup_identity.mode,
                        links=cleanup_identity.links,
                    )
                elif construction_value is None and cleanup_error is None:
                    cleanup_error = GuardianError(
                        "failed Docker config construction path is unavailable"
                    )
                elif published_matches and cleanup_error is None:
                    cleanup_error = GuardianError(
                        "failed Docker config has two linked path identities"
                    )
            if cleanup_error is None:
                try:
                    _cleanup_failed_private_config(
                        parent_fd, config_fd, cleanup_identity
                    )
                except GuardianError as observed:
                    cleanup_error = observed
        if config_fd >= 0:
            try:
                os.close(config_fd)
            except OSError:
                if cleanup_error is None:
                    cleanup_error = GuardianError(
                        "cannot close failed Docker config construction"
                    )
        for residue in residues:
            try:
                os.close(residue.descriptor)
            except OSError:
                pass
        for residue in cleanup_residues:
            if residue.descriptor < 0:
                continue
            try:
                os.close(residue.descriptor)
            except OSError:
                pass
        if cleanup_error is not None:
            raise GuardianError(
                "failed Docker config construction could not be retired: "
                f"{cleanup_error}"
            ) from error
        if isinstance(error, OSError):
            raise GuardianError("cannot prepare exact Docker config") from error
        raise


def _verify_unpublished_private_config(
    parent_fd: int, residue: DockerConfigCleanupResidue
) -> None:
    """Re-prove one never-published config without mutating its namespace."""

    expected = residue.config
    try:
        parent_path = Path(f"/proc/self/fd/{parent_fd}").resolve(strict=True)
        opened = os.fstat(residue.descriptor)
        path_value = os.stat(
            expected.path.name, dir_fd=parent_fd, follow_symlinks=False
        )
        children = os.listdir(residue.descriptor)
    except OSError as error:
        raise GuardianError(
            "unpublished Docker config residue is unavailable"
        ) from error
    name = expected.path.name
    construction = _docker_config_construction_name_pattern(
        os.getuid()
    ).fullmatch(name)
    prefix = f".qcsd-docker-config-{os.getuid()}."
    transitional = re.fullmatch(
        re.escape(prefix) + r"[1-9][0-9]*[.][0-9a-f]{64}", name
    )
    legacy = re.fullmatch(re.escape(prefix) + r"[0-9a-f]{64}", name)
    allowed_modes = (
        {DOCKER_CONFIG_MODE, 0o700}
        if construction is not None
        else {0o700}
    )
    wanted = (
        expected.device,
        expected.inode,
        expected.owner,
        expected.mode,
        expected.links,
    )
    if (
        residue.descriptor < 0
        or expected.path.parent != parent_path
        or (
            construction is None
            and transitional is None
            and legacy is None
        )
        or expected.owner != os.getuid()
        or expected.mode not in allowed_modes
        or expected.links != 2
        or children
    ):
        _fail("unpublished Docker config residue identity changed")
    for observed in (opened, path_value):
        actual = (
            observed.st_dev,
            observed.st_ino,
            observed.st_uid,
            stat.S_IMODE(observed.st_mode),
            observed.st_nlink,
        )
        if not stat.S_ISDIR(observed.st_mode) or actual != wanted:
            _fail("unpublished Docker config residue identity changed")


def _remove_unpublished_private_config(
    parent_fd: int, residue: DockerConfigCleanupResidue
) -> None:
    """Remove an already validated never-published root by exact identity."""

    _verify_unpublished_private_config(parent_fd, residue)
    expected = residue.config
    try:
        os.rmdir(expected.path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        opened = os.fstat(residue.descriptor)
        children = os.listdir(residue.descriptor)
    except OSError as error:
        raise GuardianError(
            "cannot remove unpublished Docker config residue"
        ) from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (
            opened.st_dev,
            opened.st_ino,
            opened.st_uid,
            stat.S_IMODE(opened.st_mode),
            opened.st_nlink,
        )
        != (
            expected.device,
            expected.inode,
            expected.owner,
            expected.mode,
            0,
        )
        or children
    ):
        _fail("removed unpublished Docker config residue identity changed")
    try:
        os.close(residue.descriptor)
    except OSError as error:
        raise GuardianError(
            "cannot close unpublished Docker config residue"
        ) from error
    residue.descriptor = -1


def _verify_private_config(
    parent_fd: int,
    descriptor: int,
    expected: ConfigDirectoryIdentity,
    *,
    require_empty: bool,
    quarantined: bool = False,
) -> None:
    try:
        parent_path = Path(f"/proc/self/fd/{parent_fd}").resolve(strict=True)
        opened = os.fstat(descriptor)
        path_value = os.stat(expected.path, follow_symlinks=False)
        parent_value = os.stat(
            expected.path.name, dir_fd=parent_fd, follow_symlinks=False
        )
        children = os.listdir(descriptor)
    except OSError as error:
        raise GuardianError("guardian private config is unavailable") from error
    wanted = (
        expected.device,
        expected.inode,
        expected.owner,
        expected.mode,
        expected.links,
    )
    expected_pattern = (
        _docker_config_quarantine_name_pattern(os.getuid())
        if quarantined
        else _docker_config_name_pattern(os.getuid())
    )
    if (
        expected.path.parent != parent_path
        or expected_pattern.fullmatch(expected.path.name) is None
    ):
        _fail("guardian Docker config pathname changed")
    for observed in (opened, path_value, parent_value):
        actual = (
            observed.st_dev,
            observed.st_ino,
            observed.st_uid,
            stat.S_IMODE(observed.st_mode),
            observed.st_nlink,
        )
        if not stat.S_ISDIR(observed.st_mode) or actual != wanted:
            _fail("guardian private config identity changed")
    if (
        wanted[2] != os.getuid()
        or wanted[3] != DOCKER_CONFIG_MODE
        or wanted[4] != 2
    ):
        _fail("guardian Docker config is not linked, read-only, and private")
    if require_empty and children:
        _fail("guardian config root is not empty before admission")


def _verify_private_config_residues(
    parent_fd: int, residues: Sequence[DockerConfigResidue]
) -> None:
    """Re-prove every held published root without trusting its pathname."""

    identities: set[tuple[int, int]] = set()
    paths: set[Path] = set()
    descriptors: set[int] = set()
    published_pattern = _docker_config_name_pattern(os.getuid())
    quarantine_pattern = _docker_config_quarantine_name_pattern(os.getuid())
    generations: set[tuple[str, str, str]] = set()
    current_boot_token = _boot_token()
    current_guardian_start = _process_start_time(os.getpid())
    for residue in residues:
        pattern = quarantine_pattern if residue.quarantined else published_pattern
        matched = pattern.fullmatch(residue.config.path.name)
        identity = (residue.config.device, residue.config.inode)
        generation = (
            matched.group("boot"),
            matched.group("start"),
            matched.group("nonce"),
        ) if matched is not None else None
        if (
            residue.descriptor < 0
            or residue.removed
            or residue.descriptor in descriptors
            or identity in identities
            or residue.config.path in paths
            or matched is None
            or generation in generations
            or matched.group("boot") != residue.boot_token
            or int(matched.group("start")) != residue.guardian_start
            or residue.census_start
            != (
                residue.guardian_start
                if residue.boot_token == current_boot_token
                else current_guardian_start
            )
            or (
                residue.boot_token == current_boot_token
                and residue.guardian_start > current_guardian_start
            )
        ):
            _fail("published Docker config residue set changed")
        _verify_private_config(
            parent_fd,
            residue.descriptor,
            residue.config,
            require_empty=True,
            quarantined=residue.quarantined,
        )
        descriptors.add(residue.descriptor)
        identities.add(identity)
        paths.add(residue.config.path)
        assert generation is not None
        generations.add(generation)


def _verify_private_config_namespace(
    parent_fd: int,
    current: ConfigDirectoryIdentity,
    residues: Sequence[DockerConfigResidue],
) -> None:
    """Reject additions or disappearances in the reserved Docker namespace."""

    prefix = f".qcsd-docker-config-{os.getuid()}."
    try:
        observed = {
            name for name in os.listdir(parent_fd) if name.startswith(prefix)
        }
    except OSError as error:
        raise GuardianError(
            "cannot enumerate the reserved Docker config namespace"
        ) from error
    expected = {current.path.name}
    expected.update(residue.config.path.name for residue in residues)
    if observed != expected:
        _fail("reserved Docker config namespace changed")


def _wait_for_private_config_drain(
    parent_fd: int,
    residue: DockerConfigResidue,
    *,
    drain_seconds: float = GROUP_DRAIN_SECONDS,
    deadline: float | None = None,
    continuation_check: Callable[[], None] | None = None,
) -> None:
    """Require two consecutive reference-free procfs censuses.

    Published roots are checked by their usable path and environment value.
    Once a root is quarantined, only exact inode references matter: a stale
    environment string for the now-absent published name cannot reopen it.
    """

    if deadline is None:
        deadline = time.monotonic() + drain_seconds
    clear_passes = 0
    last_reference: int | None = None
    phase = "quarantined" if residue.quarantined else "published"

    def fail_deadline() -> NoReturn:
        if last_reference is not None:
            _fail(
                f"{phase} Docker config still has a live reference "
                f"from PID {last_reference}"
            )
        _fail(
            f"{phase} Docker config did not reach two stable clear censuses"
        )

    while clear_passes < 2:
        if continuation_check is not None:
            continuation_check()
        if time.monotonic() >= deadline:
            fail_deadline()
        _verify_private_config(
            parent_fd,
            residue.descriptor,
            residue.config,
            require_empty=True,
            quarantined=residue.quarantined,
        )
        try:
            if residue.quarantined:
                referenced = _process_references_unlinked_docker_config(
                    residue.config,
                    residue.census_start,
                    deadline=deadline,
                    continuation_check=continuation_check,
                )
            else:
                referenced = _process_references_docker_config(
                    residue.config.path,
                    residue.census_start,
                    deadline=deadline,
                    continuation_check=continuation_check,
                )
        except GuardianError:
            if time.monotonic() >= deadline and last_reference is not None:
                fail_deadline()
            raise
        if referenced is None:
            clear_passes += 1
        else:
            clear_passes = 0
            last_reference = referenced
        if continuation_check is not None:
            continuation_check()
        if time.monotonic() >= deadline:
            fail_deadline()
        if clear_passes == 2:
            return
        time.sleep(0.01)


def _quarantine_private_config_residue(
    parent_fd: int, residue: DockerConfigResidue
) -> None:
    """Atomically close one published root to future cooperative users."""

    if residue.quarantined or residue.removed:
        _fail("Docker config residue has already crossed its quarantine boundary")
    _verify_private_config(
        parent_fd,
        residue.descriptor,
        residue.config,
        require_empty=True,
    )
    matched = _docker_config_name_pattern(os.getuid()).fullmatch(
        residue.config.path.name
    )
    if (
        matched is None
        or matched.group("boot") != residue.boot_token
        or int(matched.group("start")) != residue.guardian_start
    ):
        _fail("published Docker config residue identity changed before quarantine")
    destination_name = (
        f".qcsd-docker-config-{os.getuid()}.retiring.v2."
        f"{matched.group('boot')}.{matched.group('start')}."
        f"{matched.group('nonce')}"
    )
    published_path = residue.config.path
    quarantined_config = ConfigDirectoryIdentity(
        path=published_path.with_name(destination_name),
        device=residue.config.device,
        inode=residue.config.inode,
        owner=residue.config.owner,
        mode=residue.config.mode,
        links=residue.config.links,
    )

    def bind_quarantined_name() -> None:
        # This callback is intentionally assignment-only.  It runs after the
        # rename syscall and before the fallible durability barrier so a retry
        # always carries the pathname that actually owns the held inode.
        residue.config = quarantined_config
        residue.quarantined = True

    try:
        _rename_noreplace(
            parent_fd,
            published_path.name,
            destination_name,
            context="Docker config retirement",
            after_rename=bind_quarantined_name,
        )
    except OSError as error:
        raise GuardianError(
            "cannot persist quarantined Docker config root"
        ) from error
    try:
        os.stat(published_path.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise GuardianError(
            "cannot prove the published Docker config name was retired"
        ) from error
    else:
        _fail("published Docker config name remained after quarantine")
    _verify_private_config(
        parent_fd,
        residue.descriptor,
        residue.config,
        require_empty=True,
        quarantined=True,
    )


def _verify_removed_private_config(residue: DockerConfigResidue) -> None:
    """Re-prove an exact empty inode after its retiring link was removed."""

    try:
        opened = os.fstat(residue.descriptor)
        children = os.listdir(residue.descriptor)
    except OSError as error:
        raise GuardianError(
            "removed Docker config descriptor is unavailable"
        ) from error
    if (
        not residue.quarantined
        or not residue.removed
        or not stat.S_ISDIR(opened.st_mode)
        or (
            opened.st_dev,
            opened.st_ino,
            opened.st_uid,
            stat.S_IMODE(opened.st_mode),
            opened.st_nlink,
        )
        != (
            residue.config.device,
            residue.config.inode,
            residue.config.owner,
            residue.config.mode,
            0,
        )
        or children
    ):
        _fail("removed Docker config descriptor identity changed")


def _retire_private_config_residue(
    parent_fd: int,
    residue: DockerConfigResidue,
    *,
    drain_seconds: float = GROUP_DRAIN_SECONDS,
    deadline: float | None = None,
    continuation_check: Callable[[], None] | None = None,
) -> None:
    if deadline is None:
        deadline = time.monotonic() + drain_seconds
    if residue.removed:
        _verify_removed_private_config(residue)
        try:
            os.fsync(parent_fd)
        except OSError as error:
            raise GuardianError(
                "cannot persist removed Docker config root"
            ) from error
        _verify_removed_private_config(residue)
        return
    _wait_for_private_config_drain(
        parent_fd,
        residue,
        drain_seconds=drain_seconds,
        deadline=deadline,
        continuation_check=continuation_check,
    )
    if continuation_check is not None:
        continuation_check()
    if deadline is not None and time.monotonic() >= deadline:
        _fail("published Docker config retirement exceeded its deadline")
    if not residue.quarantined:
        _quarantine_private_config_residue(parent_fd, residue)
        if continuation_check is not None:
            continuation_check()
        if time.monotonic() >= deadline:
            _fail("Docker config quarantine exceeded its deadline")
        _wait_for_private_config_drain(
            parent_fd,
            residue,
            drain_seconds=drain_seconds,
            deadline=deadline,
            continuation_check=continuation_check,
        )
    if continuation_check is not None:
        continuation_check()
    if time.monotonic() >= deadline:
        _fail("quarantined Docker config retirement exceeded its deadline")

    def mark_removed() -> None:
        residue.removed = True

    _cleanup_private_config(
        parent_fd,
        residue.descriptor,
        residue.config,
        quarantined=True,
        after_remove=mark_removed,
    )
    _verify_removed_private_config(residue)


def _cleanup_private_config(
    parent_fd: int,
    descriptor: int,
    expected: ConfigDirectoryIdentity,
    *,
    quarantined: bool = False,
    after_remove: Callable[[], None] | None = None,
) -> None:
    """Remove the exact empty Docker config after every supervised user drains."""

    _verify_private_config(
        parent_fd,
        descriptor,
        expected,
        require_empty=True,
        quarantined=quarantined,
    )
    try:
        os.rmdir(expected.path.name, dir_fd=parent_fd)
        if after_remove is not None:
            after_remove()
        os.fsync(parent_fd)
        opened = os.fstat(descriptor)
        children = os.listdir(descriptor)
    except OSError as error:
        raise GuardianError("cannot remove exact Docker config root") from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (
            opened.st_dev,
            opened.st_ino,
            opened.st_uid,
            stat.S_IMODE(opened.st_mode),
            opened.st_nlink,
        )
        != (
            expected.device,
            expected.inode,
            expected.owner,
            expected.mode,
            0,
        )
        or children
    ):
        _fail("removed Docker config descriptor identity changed")


def _cleanup_failed_private_config(
    parent_fd: int,
    descriptor: int,
    expected: ConfigDirectoryIdentity,
) -> None:
    """Retire only the exact empty root created by a failed preparation."""

    try:
        parent_path = Path(f"/proc/self/fd/{parent_fd}").resolve(strict=True)
        opened = os.fstat(descriptor)
        path_value = os.stat(
            expected.path.name, dir_fd=parent_fd, follow_symlinks=False
        )
        children = os.listdir(descriptor)
    except OSError as error:
        raise GuardianError(
            "failed Docker config construction is unavailable"
        ) from error
    wanted = (
        expected.device,
        expected.inode,
        expected.owner,
        expected.mode,
        expected.links,
    )
    published = _docker_config_name_pattern(os.getuid()).fullmatch(
        expected.path.name
    )
    construction = _docker_config_construction_name_pattern(
        os.getuid()
    ).fullmatch(expected.path.name)
    allowed_modes = (
        {DOCKER_CONFIG_MODE}
        if published is not None
        else {0o700, DOCKER_CONFIG_MODE}
    )
    if (
        expected.path.parent != parent_path
        or (published is None and construction is None)
        or expected.mode not in allowed_modes
        or wanted[2] != os.getuid()
        or wanted[4] != 2
        or children
    ):
        _fail("failed Docker config construction identity is unsafe")
    for observed in (opened, path_value):
        actual = (
            observed.st_dev,
            observed.st_ino,
            observed.st_uid,
            stat.S_IMODE(observed.st_mode),
            observed.st_nlink,
        )
        if not stat.S_ISDIR(observed.st_mode) or actual != wanted:
            _fail("failed Docker config construction identity changed")
    try:
        os.rmdir(expected.path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        removed = os.fstat(descriptor)
    except OSError as error:
        raise GuardianError(
            "cannot remove failed Docker config construction"
        ) from error
    if (
        not stat.S_ISDIR(removed.st_mode)
        or (
            removed.st_dev,
            removed.st_ino,
            removed.st_uid,
            stat.S_IMODE(removed.st_mode),
            removed.st_nlink,
        )
        != (
            expected.device,
            expected.inode,
            expected.owner,
            expected.mode,
            0,
        )
    ):
        _fail("removed failed Docker config construction changed")


def _remove_config_contents(descriptor: int, device: int) -> None:
    """Remove an exact private config tree without following any child."""

    for name in sorted(os.listdir(descriptor)):
        if not name or "/" in name or name in {".", ".."}:
            _fail("Buildx config contains an invalid child name")
        try:
            value = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except OSError as error:
            raise GuardianError("cannot bind Buildx config child") from error
        if value.st_uid != os.getuid() or value.st_dev != device:
            _fail("Buildx config contains an unowned or mounted child")
        if stat.S_ISDIR(value.st_mode):
            try:
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=descriptor,
                )
            except OSError as error:
                raise GuardianError("cannot open Buildx config child") from error
            try:
                opened = os.fstat(child_fd)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino, opened.st_uid)
                    != (value.st_dev, value.st_ino, os.getuid())
                ):
                    _fail("Buildx config child identity changed")
                _remove_config_contents(child_fd, device)
                current = os.stat(
                    name, dir_fd=descriptor, follow_symlinks=False
                )
                if (
                    not stat.S_ISDIR(current.st_mode)
                    or (current.st_dev, current.st_ino, current.st_uid)
                    != (opened.st_dev, opened.st_ino, os.getuid())
                ):
                    _fail("Buildx config child path changed")
                os.rmdir(name, dir_fd=descriptor)
                os.fsync(descriptor)
            finally:
                os.close(child_fd)
        else:
            try:
                current = os.stat(
                    name, dir_fd=descriptor, follow_symlinks=False
                )
                if (
                    current.st_dev,
                    current.st_ino,
                    current.st_uid,
                    stat.S_IFMT(current.st_mode),
                ) != (
                    value.st_dev,
                    value.st_ino,
                    os.getuid(),
                    stat.S_IFMT(value.st_mode),
                ):
                    _fail("Buildx config child path changed")
                os.unlink(name, dir_fd=descriptor)
                os.fsync(descriptor)
            except OSError as error:
                raise GuardianError("cannot remove Buildx config child") from error


def _verify_buildx_config(
    parent_fd: int,
    descriptor: int,
    expected: ConfigDirectoryIdentity,
    *,
    require_empty: bool,
) -> None:
    try:
        parent = os.fstat(parent_fd)
        opened = os.fstat(descriptor)
        current = os.stat(
            expected.path.name, dir_fd=parent_fd, follow_symlinks=False
        )
        children = os.listdir(descriptor) if require_empty else ()
    except OSError as error:
        raise GuardianError("guardian Buildx config is unavailable") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or current.st_dev != parent.st_dev
        or not re.fullmatch(
            rf"[.]qcsd-buildx-config-{os.getuid()}[.][0-9a-f]{{64}}",
            expected.path.name,
        )
    ):
        _fail("guardian Buildx config parent is not a directory")
    for value in (opened, current):
        if (
            not stat.S_ISDIR(value.st_mode)
            or (value.st_dev, value.st_ino, value.st_uid)
            != (expected.device, expected.inode, expected.owner)
            or stat.S_IMODE(value.st_mode) != expected.mode
            or value.st_nlink < 2
        ):
            _fail("guardian Buildx config identity changed")
    if expected.owner != os.getuid() or expected.mode != 0o700:
        _fail("guardian Buildx config is not private")
    if require_empty and (
        opened.st_nlink != 2 or current.st_nlink != 2 or children
    ):
        _fail("guardian Buildx config is not empty before admission")


def _canonical_json(value: dict[str, object]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")


def _write_exact_record(
    parent_fd: int, name: str, value: dict[str, object]
) -> RecordIdentity:
    payload = _canonical_json(value)
    if len(payload) > 8192:
        _fail("Buildx config ledger is oversized")
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
            dir_fd=parent_fd,
        )
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                _fail("Buildx config ledger write was incomplete")
            written += count
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino, opened.st_uid)
            != (current.st_dev, current.st_ino, os.getuid())
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size != len(payload)
        ):
            _fail("Buildx config ledger identity changed during publication")
        os.fsync(parent_fd)
        return RecordIdentity(name, opened.st_dev, opened.st_ino)
    except OSError as error:
        raise GuardianError("cannot publish Buildx config ledger") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_exact_record(
    parent_fd: int, name: str
) -> tuple[dict[str, object], RecordIdentity]:
    descriptor = -1
    try:
        descriptor = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > 8192
        ):
            _fail("Buildx config ledger identity is unsafe")
        payload = b""
        while len(payload) <= 8192:
            block = os.read(descriptor, 8193 - len(payload))
            if not block:
                break
            payload += block
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            len(payload) > 8192
            or (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (after.st_dev, after.st_ino, after.st_uid)
            != (current.st_dev, current.st_ino, os.getuid())
        ):
            _fail("Buildx config ledger changed while it was read")
        value = json.loads(payload.decode("ascii"))
        if not isinstance(value, dict) or _canonical_json(value) != payload:
            _fail("Buildx config ledger is not canonical")
        return value, RecordIdentity(name, after.st_dev, after.st_ino)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GuardianError("cannot read Buildx config ledger") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _unlink_exact_record(parent_fd: int, expected: RecordIdentity) -> None:
    try:
        current = os.stat(
            expected.name, dir_fd=parent_fd, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino, current.st_uid)
            != (expected.device, expected.inode, os.getuid())
        ):
            _fail("Buildx config ledger path changed before unlink")
        os.unlink(expected.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as error:
        raise GuardianError("cannot unlink exact Buildx config ledger") from error


def _rename_noreplace(
    parent_fd: int,
    source: str,
    destination: str,
    *,
    context: str = "Buildx config authority",
    after_rename: Callable[[], None] | None = None,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = libc.renameat2
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    if renameat2(
        parent_fd,
        os.fsencode(source),
        parent_fd,
        os.fsencode(destination),
        1,
    ) != 0:
        error = ctypes.get_errno()
        raise GuardianError(f"cannot promote {context}") from OSError(
            error, os.strerror(error)
        )
    if after_rename is not None:
        after_rename()
    os.fsync(parent_fd)


def _intent_value(
    token: str,
    root_name: str,
    parent: os.stat_result,
    lock: LockIdentity,
    source: FileIdentity,
) -> dict[str, object]:
    return {
        "boot_id": _boot_id(),
        "guardian_pid": os.getpid(),
        "guardian_start_time": _process_start_time(os.getpid()),
        "guardian_source_device": source.device,
        "guardian_source_inode": source.inode,
        "guardian_source_path": str(source.path),
        "guardian_source_sha256": source.sha256,
        "lock_device": lock.device,
        "lock_inode": lock.inode,
        "lock_path": str(lock.path),
        "parent_device": parent.st_dev,
        "parent_inode": parent.st_ino,
        "phase": "intent",
        "root_name": root_name,
        "schema": 1,
        "token": token,
        "uid": os.getuid(),
    }


def _authority_value(
    token: str,
    root_name: str,
    exported_path: Path,
    parent: os.stat_result,
    lock: LockIdentity,
    source: FileIdentity,
    config: ConfigDirectoryIdentity,
) -> dict[str, object]:
    value = _intent_value(token, root_name, parent, lock, source)
    value.update(
        {
            "exported_path": str(exported_path),
            "phase": "authority",
            "root_device": config.device,
            "root_inode": config.inode,
        }
    )
    return value


def _validate_buildx_record_common(
    value: dict[str, object],
    *,
    phase: str,
    token: str,
    root_name: str,
    parent: os.stat_result,
    lock: LockIdentity,
) -> None:
    common = {
        "guardian_source_device",
        "guardian_source_inode",
        "guardian_source_path",
        "guardian_source_sha256",
        "boot_id",
        "guardian_pid",
        "guardian_start_time",
        "lock_device",
        "lock_inode",
        "lock_path",
        "parent_device",
        "parent_inode",
        "phase",
        "root_name",
        "schema",
        "token",
        "uid",
    }
    expected_keys = common | (
        {"exported_path", "root_device", "root_inode"}
        if phase == "authority"
        else set()
    )
    integer_keys = expected_keys - {
        "exported_path",
        "boot_id",
        "guardian_source_path",
        "guardian_source_sha256",
        "lock_path",
        "phase",
        "root_name",
        "token",
    }
    if (
        set(value) != expected_keys
        or any(type(value[key]) is not int for key in integer_keys)
        or value["schema"] != 1
        or value["phase"] != phase
        or value["token"] != token
        or value["root_name"] != root_name
        or value["uid"] != os.getuid()
        or value["parent_device"] != parent.st_dev
        or value["parent_inode"] != parent.st_ino
        or value["lock_device"] != lock.device
        or value["lock_inode"] != lock.inode
        or value["lock_path"] != str(lock.path)
        or not isinstance(value["guardian_source_path"], str)
        or not Path(str(value["guardian_source_path"])).is_absolute()
        or not isinstance(value["guardian_source_sha256"], str)
        or HEX_64.fullmatch(value["guardian_source_sha256"]) is None
        or type(value["guardian_source_device"]) is not int
        or type(value["guardian_source_inode"]) is not int
        or int(value["guardian_source_device"]) <= 0
        or int(value["guardian_source_inode"]) <= 0
        or not isinstance(value["boot_id"], str)
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}",
            str(value["boot_id"]),
        )
        is None
        or type(value["guardian_pid"]) is not int
        or int(value["guardian_pid"]) <= 1
        or type(value["guardian_start_time"]) is not int
        or int(value["guardian_start_time"]) <= 0
    ):
        _fail("Buildx config ledger differs from schema 1")


def _open_buildx_root(
    parent_fd: int,
    guardian_pid: int,
    root_name: str,
) -> tuple[int, ConfigDirectoryIdentity]:
    descriptor = -1
    try:
        descriptor = os.open(
            root_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_fd,
        )
        opened = os.fstat(descriptor)
    except OSError as error:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise GuardianError("cannot bind Buildx config root") from error
    identity = ConfigDirectoryIdentity(
        path=Path(f"/proc/{guardian_pid}/fd/{parent_fd}") / root_name,
        device=opened.st_dev,
        inode=opened.st_ino,
        owner=opened.st_uid,
        mode=stat.S_IMODE(opened.st_mode),
        links=opened.st_nlink,
    )
    try:
        _verify_buildx_config(
            parent_fd, descriptor, identity, require_empty=False
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, identity


def _ledger_from_authority(
    parent_fd: int,
    guardian_pid: int,
    token: str,
    authority_name: str,
    parent: os.stat_result,
    lock: LockIdentity,
) -> BuildxLedger | None:
    value, record = _read_exact_record(parent_fd, authority_name)
    root_name = f".qcsd-buildx-config-{os.getuid()}.{token}"
    _validate_buildx_record_common(
        value,
        phase="authority",
        token=token,
        root_name=root_name,
        parent=parent,
        lock=lock,
    )
    try:
        root_fd, config = _open_buildx_root(
            parent_fd, guardian_pid, root_name
        )
    except GuardianError:
        try:
            os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            _unlink_exact_record(parent_fd, record)
            return None
        raise
    try:
        exported = value["exported_path"]
        if (
            value["root_device"] != config.device
            or value["root_inode"] != config.inode
            or not isinstance(exported, str)
            or re.fullmatch(
                rf"/proc/{value['guardian_pid']}/fd/[1-9][0-9]*/"
                rf"{re.escape(root_name)}",
                exported,
            )
            is None
        ):
            _fail("Buildx config authority root binding changed")
        exported_path = Path(str(value["exported_path"]))
        return BuildxLedger(
            token=token,
            root_name=root_name,
            root_path=Path(f"/proc/self/fd/{parent_fd}").resolve(strict=True)
            / root_name,
            exported_path=exported_path,
            config=config,
            authority=record,
            authority_value=value,
        )
    finally:
        os.close(root_fd)


def _recover_buildx_ledgers(
    parent_fd: int,
    guardian_pid: int,
    lock: LockIdentity,
) -> list[BuildxLedger]:
    uid = os.getuid()
    parent = os.fstat(parent_fd)
    patterns = {
        "root": re.compile(rf"[.]qcsd-buildx-config-{uid}[.]([0-9a-f]{{64}})"),
        "intent": re.compile(rf"[.]qcsd-buildx-intent-{uid}[.]([0-9a-f]{{64}})"),
        "authority": re.compile(rf"[.]qcsd-buildx-authority-{uid}[.]([0-9a-f]{{64}})"),
        "staged": re.compile(rf"[.]qcsd-buildx-authority-{uid}[.]([0-9a-f]{{64}})[.]next"),
    }
    census: dict[str, dict[str, str]] = {}
    for name in sorted(os.listdir(parent_fd)):
        if not name.startswith(".qcsd-buildx-"):
            continue
        matches = [(role, pattern.fullmatch(name)) for role, pattern in patterns.items()]
        matched = [(role, found) for role, found in matches if found is not None]
        if len(matched) != 1:
            _fail("Buildx config ledger namespace is malformed")
        role, found = matched[0]
        assert found is not None
        token = found.group(1)
        if role in census.setdefault(token, {}):
            _fail("Buildx config ledger namespace is duplicated")
        census[token][role] = name
    ledgers: list[BuildxLedger] = []
    for token, names in sorted(census.items()):
        root_name = f".qcsd-buildx-config-{uid}.{token}"
        if "authority" in names and "staged" in names:
            _fail("Buildx config has duplicate final and staged authority")
        if "staged" in names:
            value, staged_record = _read_exact_record(parent_fd, names["staged"])
            _validate_buildx_record_common(
                value,
                phase="authority",
                token=token,
                root_name=root_name,
                parent=parent,
                lock=lock,
            )
            root_fd, config = _open_buildx_root(parent_fd, guardian_pid, root_name)
            try:
                if (
                    value["root_device"],
                    value["root_inode"],
                ) != (config.device, config.inode):
                    _fail("staged Buildx authority root binding changed")
            finally:
                os.close(root_fd)
            final_name = names["staged"].removesuffix(".next")
            current = os.stat(
                names["staged"], dir_fd=parent_fd, follow_symlinks=False
            )
            if (current.st_dev, current.st_ino) != (
                staged_record.device,
                staged_record.inode,
            ):
                _fail("staged Buildx authority path changed before promotion")
            _rename_noreplace(parent_fd, names["staged"], final_name)
            names["authority"] = final_name
            del names["staged"]
        if "authority" in names:
            ledger = _ledger_from_authority(
                parent_fd,
                guardian_pid,
                token,
                names["authority"],
                parent,
                lock,
            )
            if ledger is not None:
                ledgers.append(ledger)
            if "intent" in names:
                intent, intent_record = _read_exact_record(parent_fd, names["intent"])
                _validate_buildx_record_common(
                    intent,
                    phase="intent",
                    token=token,
                    root_name=root_name,
                    parent=parent,
                    lock=lock,
                )
                _unlink_exact_record(parent_fd, intent_record)
            continue
        if "intent" not in names:
            _fail("Buildx config root has no durable authority")
        intent, intent_record = _read_exact_record(parent_fd, names["intent"])
        _validate_buildx_record_common(
            intent,
            phase="intent",
            token=token,
            root_name=root_name,
            parent=parent,
            lock=lock,
        )
        if "root" in names:
            root_fd, config = _open_buildx_root(
                parent_fd, guardian_pid, root_name
            )
            try:
                _verify_buildx_config(
                    parent_fd, root_fd, config, require_empty=True
                )
                os.rmdir(root_name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            finally:
                os.close(root_fd)
        _unlink_exact_record(parent_fd, intent_record)
    identities = [(item.config.device, item.config.inode) for item in ledgers]
    roots = [item.root_name for item in ledgers]
    if len(identities) != len(set(identities)) or len(roots) != len(set(roots)):
        _fail("Buildx config authorities contain duplicate roots")
    return ledgers


def _prepare_buildx_config(
    parent_fd: int,
    guardian_pid: int,
    lock: LockIdentity,
    source: FileIdentity,
) -> tuple[int, ConfigDirectoryIdentity, list[BuildxLedger]]:
    """Publish a crash-recoverable linked private Buildx config."""

    ledgers = _recover_buildx_ledgers(parent_fd, guardian_pid, lock)
    parent = os.fstat(parent_fd)
    token = os.urandom(32).hex()
    root_name = f".qcsd-buildx-config-{os.getuid()}.{token}"
    intent_name = f".qcsd-buildx-intent-{os.getuid()}.{token}"
    staged_name = f".qcsd-buildx-authority-{os.getuid()}.{token}.next"
    final_name = staged_name.removesuffix(".next")
    intent = _write_exact_record(
        parent_fd,
        intent_name,
        _intent_value(token, root_name, parent, lock, source),
    )
    del intent
    config_fd = -1
    try:
        os.mkdir(root_name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        config_fd, config = _open_buildx_root(
            parent_fd, guardian_pid, root_name
        )
        _verify_buildx_config(
            parent_fd, config_fd, config, require_empty=True
        )
        exported_path = config.path
        authority_value = _authority_value(
            token,
            root_name,
            exported_path,
            parent,
            lock,
            source,
            config,
        )
        staged = _write_exact_record(parent_fd, staged_name, authority_value)
        current = os.stat(staged_name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (staged.device, staged.inode):
            _fail("staged Buildx authority changed before promotion")
        _rename_noreplace(parent_fd, staged_name, final_name)
        final_value, final = _read_exact_record(parent_fd, final_name)
        if final_value != authority_value:
            _fail("final Buildx authority content changed")
        intent_value, intent_record = _read_exact_record(parent_fd, intent_name)
        _validate_buildx_record_common(
            intent_value,
            phase="intent",
            token=token,
            root_name=root_name,
            parent=parent,
            lock=lock,
        )
        _unlink_exact_record(parent_fd, intent_record)
        ledgers.append(
            BuildxLedger(
                token=token,
                root_name=root_name,
                root_path=Path(f"/proc/self/fd/{parent_fd}").resolve(strict=True)
                / root_name,
                exported_path=exported_path,
                config=config,
                authority=final,
                authority_value=authority_value,
            )
        )
        return config_fd, config, ledgers
    except BaseException:
        if config_fd >= 0:
            os.close(config_fd)
        raise


def _path_is_within(value: str, root: Path) -> bool:
    root_text = str(root)
    clean = value.removesuffix(" (deleted)")
    return clean == root_text or clean.startswith(root_text + "/")


def _open_process_pidfd(pid: int) -> int | None:
    """Bind one numeric census candidate, or report that no such task exists."""

    opener = getattr(os, "pidfd_open", None)
    if opener is None:
        _fail("Buildx process census requires pidfd support")
    try:
        return opener(pid, 0)
    except OSError as error:
        if error.errno == errno.ESRCH:
            return None
        if error.errno == errno.EINVAL:
            # Flags are fixed at zero and candidates came from /proc getdents,
            # which yields thread-group leaders.  EINVAL therefore means that
            # this numeric slot was reused as a non-leader TID after enumeration.
            # Restart the complete census so its TGID is considered instead.
            raise _CensusRestart from error
        raise GuardianError(
            f"cannot bind a possible Buildx config user PID {pid} (errno {error.errno})"
        ) from error


def _pidfd_is_terminal(pidfd: int, timeout_ms: int = 0) -> bool:
    """Return true only when the kernel marks this exact task as exited."""

    poller = select.poll()
    try:
        poller.register(
            pidfd,
            select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
        )
        events = poller.poll(timeout_ms)
    except OSError as error:
        raise GuardianError("cannot poll a possible Buildx config user") from error
    for observed_fd, flags in events:
        if observed_fd != pidfd or flags & select.POLLNVAL:
            _fail("Buildx process census pidfd became invalid")
        # POLLIN is the documented pidfd indication that the exact task exited.
        # HUP/ERR without POLLIN are not sufficient termination evidence.
        if flags & select.POLLIN:
            return True
        if flags:
            _fail("Buildx process census pidfd is indeterminate")
    return False


def _replacement_pidfd_after_terminal(pid: int) -> int | None:
    """Rebind the numeric slot once so PID reuse is not hidden by an old pidfd."""

    replacement = _open_process_pidfd(pid)
    if replacement is None:
        return None
    try:
        terminal = _pidfd_is_terminal(replacement)
    except BaseException:
        try:
            os.close(replacement)
        except OSError:
            pass
        raise
    if terminal:
        os.close(replacement)
        return None
    return replacement


def _read_config_process_references(
    candidate: Path,
    paths: Sequence[Path],
    path_bytes: Sequence[bytes],
    environment_name: bytes,
) -> bool:
    """Take one all-or-nothing procfs reference snapshot for a live task."""

    command = (candidate / "cmdline").read_bytes()
    environment = (candidate / "environ").read_bytes().split(b"\0")
    cwd = os.readlink(candidate / "cwd")
    process_root = os.readlink(candidate / "root")
    descriptors = tuple((candidate / "fd").iterdir())
    descriptor_targets = tuple(os.readlink(descriptor) for descriptor in descriptors)
    if any(path in command for path in path_bytes):
        return True
    for path in path_bytes:
        if environment_name + b"=" + path in environment:
            return True
    if any(
        _path_is_within(observed, root)
        for observed in (cwd, process_root)
        for root in paths
    ):
        return True
    return any(
        _path_is_within(target, root)
        for target in descriptor_targets
        for root in paths
    )


def _read_buildx_process_references(
    candidate: Path,
    paths: Sequence[Path],
    path_bytes: Sequence[bytes],
) -> bool:
    return _read_config_process_references(
        candidate, paths, path_bytes, b"BUILDX_CONFIG"
    )


def _read_docker_process_references(
    candidate: Path,
    paths: Sequence[Path],
    path_bytes: Sequence[bytes],
) -> bool:
    return _read_config_process_references(
        candidate, paths, path_bytes, b"DOCKER_CONFIG"
    )


def _read_config_process_inode_references(
    candidate: Path,
    expected: tuple[int, int],
) -> bool:
    """Detect an open/cwd/root reference after its pathname was unlinked."""

    references = (
        candidate / "cwd",
        candidate / "root",
        *tuple((candidate / "fd").iterdir()),
    )
    observed = tuple(os.stat(reference) for reference in references)
    return any((value.st_dev, value.st_ino) == expected for value in observed)


def _process_references_buildx_candidate(
    pid: int,
    candidate: Path,
    *,
    threshold: int,
    paths: Sequence[Path],
    path_bytes: Sequence[bytes],
    reference_reader: Callable[[Path, Sequence[Path], Sequence[bytes]], bool]
    | None = None,
    deadline: float | None = None,
    continuation_check: Callable[[], None] | None = None,
) -> bool:
    """Inspect one numeric PID through a stable, exit-aware pidfd binding."""

    pidfd = _open_process_pidfd(pid)
    if pidfd is None:
        return False
    live_failures = 0
    terminal_transitions = 0
    try:
        while True:
            if continuation_check is not None:
                continuation_check()
            if deadline is not None and time.monotonic() >= deadline:
                _fail("Docker config process census exceeded its deadline")
            if _pidfd_is_terminal(pidfd):
                terminal_transitions += 1
                if terminal_transitions > BUILDX_CENSUS_ATTEMPTS:
                    _fail("Buildx process census did not reach a stable PID binding")
                os.close(pidfd)
                pidfd = None
                pidfd = _replacement_pidfd_after_terminal(pid)
                if pidfd is None:
                    return False
                live_failures = 0
                continue

            snapshot_error: BaseException | None = None
            try:
                before_state, _, _, _, before_start = _process_record(pid)
                before_owner = _process_uid(pid)
                referenced = False
                eligible = before_owner == os.getuid() and before_start >= threshold
                if eligible:
                    reader = (
                        _read_buildx_process_references
                        if reference_reader is None
                        else reference_reader
                    )
                    referenced = reader(
                        candidate,
                        paths,
                        path_bytes,
                    )
                after_state, _, _, _, after_start = _process_record(pid)
                after_owner = _process_uid(pid)
            except (GuardianError, OSError) as error:
                snapshot_error = error

            if deadline is not None and time.monotonic() >= deadline:
                _fail("Docker config process census exceeded its deadline")
            if continuation_check is not None:
                continuation_check()
            if snapshot_error is not None:
                wait_ms = max(1, round(BUILDX_CENSUS_RETRY_SECONDS * 1000))
                if _pidfd_is_terminal(pidfd, wait_ms):
                    terminal_transitions += 1
                    if terminal_transitions > BUILDX_CENSUS_ATTEMPTS:
                        _fail("Buildx process census did not reach a stable PID binding")
                    os.close(pidfd)
                    pidfd = None
                    pidfd = _replacement_pidfd_after_terminal(pid)
                    if pidfd is None:
                        return False
                    live_failures = 0
                    continue
                live_failures += 1
                if live_failures >= BUILDX_CENSUS_ATTEMPTS:
                    raise GuardianError(
                        "cannot inspect a possible Buildx config user "
                        f"PID {pid}: {snapshot_error}"
                    ) from snapshot_error
                time.sleep(BUILDX_CENSUS_RETRY_SECONDS)
                continue

            if before_start != after_start or before_owner != after_owner:
                _fail("Buildx process census identity changed")
            # A zombie thread-group leader need not make its pidfd readable
            # while other threads remain alive. Candidates already excluded by
            # owner/birth need no exit proof, but still undergo the identity
            # and terminal-binding/replacement checks on either side here.
            if eligible and (
                before_state in {"X", "x", "Z"} or after_state in {"X", "x", "Z"}
            ):
                if not _pidfd_is_terminal(pidfd, 1):
                    _fail(
                        "Buildx process census terminal state is indeterminate: "
                        f"PID {pid}, UID {before_owner}, start {before_start}, "
                        f"threshold {threshold}, states {before_state}/{after_state}"
                    )
            if _pidfd_is_terminal(pidfd):
                terminal_transitions += 1
                if terminal_transitions > BUILDX_CENSUS_ATTEMPTS:
                    _fail("Buildx process census did not reach a stable PID binding")
                os.close(pidfd)
                pidfd = None
                pidfd = _replacement_pidfd_after_terminal(pid)
                if pidfd is None:
                    return False
                live_failures = 0
                continue
            return referenced
    finally:
        if pidfd is not None:
            os.close(pidfd)


def _process_references_buildx(ledger: BuildxLedger) -> bool:
    """Conservatively detect surviving users of one authorised config root."""

    if ledger.authority_value["boot_id"] != _boot_id():
        return False
    threshold = int(ledger.authority_value["guardian_start_time"])
    paths = (ledger.root_path, ledger.exported_path)
    path_bytes = tuple(os.fsencode(path) for path in paths)
    for census_attempt in range(BUILDX_CENSUS_ATTEMPTS):
        try:
            candidates = tuple(Path("/proc").iterdir())
        except OSError as error:
            raise GuardianError("cannot census Buildx config users") from error
        try:
            for candidate in candidates:
                if not candidate.name.isdigit() or int(candidate.name) == os.getpid():
                    continue
                pid = int(candidate.name)
                if _process_references_buildx_candidate(
                    pid,
                    candidate,
                    threshold=threshold,
                    paths=paths,
                    path_bytes=path_bytes,
                ):
                    return True
        except _CensusRestart:
            if census_attempt + 1 >= BUILDX_CENSUS_ATTEMPTS:
                _fail("Buildx process census did not reach a stable process list")
            time.sleep(BUILDX_CENSUS_RETRY_SECONDS)
            continue
        return False
    raise AssertionError("unreachable Buildx census retry state")


def _process_references_docker_config(
    root: Path,
    threshold: int,
    *,
    deadline: float | None = None,
    continuation_check: Callable[[], None] | None = None,
    reference_reader: Callable[
        [Path, Sequence[Path], Sequence[bytes]], bool
    ] = _read_docker_process_references,
) -> int | None:
    """Conservatively detect any surviving user of a Docker config root."""

    paths = (root,)
    path_bytes = (os.fsencode(root),)
    for census_attempt in range(BUILDX_CENSUS_ATTEMPTS):
        try:
            candidates = tuple(Path("/proc").iterdir())
        except OSError as error:
            raise GuardianError("cannot census Docker config users") from error
        try:
            for candidate in candidates:
                if continuation_check is not None:
                    continuation_check()
                if deadline is not None and time.monotonic() >= deadline:
                    _fail("Docker config process census exceeded its deadline")
                if not candidate.name.isdigit() or int(candidate.name) == os.getpid():
                    continue
                pid = int(candidate.name)
                if _process_references_buildx_candidate(
                    pid,
                    candidate,
                    threshold=threshold,
                    paths=paths,
                    path_bytes=path_bytes,
                    reference_reader=reference_reader,
                    deadline=deadline,
                    continuation_check=continuation_check,
                ):
                    return pid
        except _CensusRestart:
            if census_attempt + 1 >= BUILDX_CENSUS_ATTEMPTS:
                _fail("Docker config census did not reach a stable process list")
            time.sleep(BUILDX_CENSUS_RETRY_SECONDS)
            continue
        if deadline is not None and time.monotonic() >= deadline:
            _fail("Docker config process census exceeded its deadline")
        return None
    raise AssertionError("unreachable Docker config census retry state")


def _process_references_unlinked_docker_config(
    config: ConfigDirectoryIdentity,
    threshold: int,
    *,
    deadline: float | None = None,
    continuation_check: Callable[[], None] | None = None,
) -> int | None:
    """Census the exact directory inode after its public name is gone."""

    expected = (config.device, config.inode)

    def read_inode_reference(
        candidate: Path,
        _paths: Sequence[Path],
        _path_bytes: Sequence[bytes],
    ) -> bool:
        return _read_config_process_inode_references(candidate, expected)

    return _process_references_docker_config(
        config.path,
        threshold,
        deadline=deadline,
        continuation_check=continuation_check,
        reference_reader=read_inode_reference,
    )


def _cleanup_one_buildx_ledger(
    parent_fd: int,
    guardian_pid: int,
    lock: LockIdentity,
    ledger: BuildxLedger,
) -> None:
    parent = os.fstat(parent_fd)
    current_value, current_record = _read_exact_record(
        parent_fd, ledger.authority.name
    )
    if current_record != ledger.authority or current_value != ledger.authority_value:
        _fail("Buildx config authority changed before cleanup")
    _validate_buildx_record_common(
        current_value,
        phase="authority",
        token=ledger.token,
        root_name=ledger.root_name,
        parent=parent,
        lock=lock,
    )
    root_fd, config = _open_buildx_root(
        parent_fd, guardian_pid, ledger.root_name
    )
    try:
        if (config.device, config.inode) != (
            ledger.config.device,
            ledger.config.inode,
        ):
            _fail("Buildx config root changed before cleanup")
        # After the qcsd process group is drained, repeat the conservative
        # pidfd-bound census to cover a stable inherited reference transfer at
        # the first boundary.  Procfs is not a global atomic snapshot: any live
        # identity or inspection ambiguity remains fail-closed.
        if _process_references_buildx(ledger):
            _fail("Buildx config still has a live process reference")
        time.sleep(0.01)
        if _process_references_buildx(ledger):
            _fail("Buildx config gained a live process reference")
        _remove_config_contents(root_fd, config.device)
        _verify_buildx_config(
            parent_fd, root_fd, config, require_empty=True
        )
        os.rmdir(ledger.root_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as error:
        raise GuardianError("cannot remove exact Buildx config root") from error
    finally:
        os.close(root_fd)
    _unlink_exact_record(parent_fd, current_record)


def _cleanup_buildx_ledgers(
    parent_fd: int,
    guardian_pid: int,
    lock: LockIdentity,
    ledgers: Sequence[BuildxLedger],
) -> None:
    for ledger in ledgers:
        _cleanup_one_buildx_ledger(parent_fd, guardian_pid, lock, ledger)


def _descriptor_lock_rows(process: int, descriptor: int) -> list[list[str]]:
    if process <= 1 or descriptor <= 2:
        _fail("lifecycle lock descriptor binding is invalid")
    try:
        lines = Path(f"/proc/{process}/fdinfo/{descriptor}").read_text(
            encoding="ascii"
        ).splitlines()
    except (OSError, UnicodeError) as error:
        raise GuardianError("cannot verify the kernel lifecycle flock") from error
    rows: list[list[str]] = []
    for line in lines:
        key, separator, value = line.partition(":")
        if key == "lock" and separator:
            rows.append(value.split())
    return rows


def _verify_descriptor_lock(
    device: int,
    inode: int,
    process: int,
    descriptor: int,
    *,
    failure: str,
    owner: int | None = None,
) -> None:
    reconstructed = os.makedev(os.major(device), os.minor(device))
    if reconstructed != device:
        _fail("lifecycle lock device identity is invalid")
    lock_key = (
        f"{os.major(device):02x}:"
        f"{os.minor(device):02x}:{inode}"
    )
    rows = _descriptor_lock_rows(process, descriptor)
    owner_pattern = (
        r"(?:0|[1-9][0-9]*)" if owner is None else r"[1-9][0-9]*"
    )
    if len(rows) != 1 or (
        len(rows[0]) != 8
        or re.fullmatch(r"[1-9][0-9]*:", rows[0][0]) is None
        or rows[0][1:4] != ["FLOCK", "ADVISORY", "WRITE"]
        or re.fullmatch(owner_pattern, rows[0][4]) is None
        or (owner is not None and rows[0][4] != str(owner))
        or rows[0][5:] != [lock_key, "0", "EOF"]
    ):
        _fail(failure)


def _verify_guardian_lock(
    expected: LockIdentity, guardian_pid: int, descriptor: int
) -> None:
    _verify_descriptor_lock(
        expected.device,
        expected.inode,
        guardian_pid,
        descriptor,
        failure="guardian does not exclusively own the lifecycle flock",
        owner=guardian_pid,
    )


def _capture_inherited_acquisition_lock() -> InheritedLockIdentity | None:
    raw = os.environ.get(ACQUISITION_LOCK_ENV)
    if raw is None:
        return None
    if re.fullmatch(r"[0-9]+", raw) is None:
        _fail("inherited acquisition lock descriptor is malformed")
    descriptor = int(raw)
    if descriptor <= 2:
        _fail("inherited acquisition lock descriptor is unsafe")
    try:
        opened = os.fstat(descriptor)
        proc_value = os.stat(f"/proc/self/fd/{descriptor}")
    except OSError as error:
        raise GuardianError("inherited acquisition lock is unavailable") from error
    wanted = (
        opened.st_dev,
        opened.st_ino,
        opened.st_uid,
        stat.S_IMODE(opened.st_mode),
        opened.st_nlink,
        opened.st_size,
    )
    observed = (
        proc_value.st_dev,
        proc_value.st_ino,
        proc_value.st_uid,
        stat.S_IMODE(proc_value.st_mode),
        proc_value.st_nlink,
        proc_value.st_size,
    )
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(proc_value.st_mode)
        or wanted != observed
        or opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) != 0o600
        or opened.st_nlink != 1
        or opened.st_size != 0
    ):
        _fail("inherited acquisition lock identity is unsafe")
    _verify_descriptor_lock(
        opened.st_dev,
        opened.st_ino,
        os.getpid(),
        descriptor,
        failure="inherited acquisition descriptor is not exclusively locked",
    )
    return InheritedLockIdentity(
        descriptor=descriptor,
        device=opened.st_dev,
        inode=opened.st_ino,
        owner=opened.st_uid,
        mode=stat.S_IMODE(opened.st_mode),
        links=opened.st_nlink,
    )


def _acquire_lock(descriptor: int, latch: _SignalLatch) -> None:
    while True:
        if latch.first is not None:
            _fail("signal received before lifecycle admission")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            time.sleep(0.02)
        except OSError as error:
            if error.errno != errno.EINTR:
                raise GuardianError("cannot acquire lifecycle lock") from error


def _capture_inner_sources(
    command: Sequence[str], guardian: FileIdentity
) -> tuple[
    tuple[str, ...],
    int,
    FileIdentity,
    int,
    FileIdentity,
    int,
    FileIdentity,
]:
    if not command:
        _fail("guardian requires an inner qcsd-lab command")
    requested = Path(command[0])
    expected = guardian.path.parent.parent / "qcsd-lab"
    if not requested.is_absolute():
        _fail("inner qcsd-lab path must be absolute")
    try:
        canonical = requested.resolve(strict=True)
    except OSError as error:
        raise GuardianError("inner qcsd-lab path is unavailable") from error
    if requested.absolute() != canonical or canonical != expected:
        _fail("inner qcsd-lab identity is unsafe")
    qcsd_fd, qcsd_identity = _capture_source_identity(expected)
    helper_path = guardian.path.parent / "docker_signal_supervisor.sh"
    try:
        helper_fd, helper_identity = _capture_source_identity(helper_path)
    except BaseException:
        os.close(qcsd_fd)
        raise
    native_path = guardian.path.parent / "docker_lifecycle_native.py"
    try:
        native_fd, native_identity = _capture_source_identity(native_path)
    except BaseException:
        os.close(qcsd_fd)
        os.close(helper_fd)
        raise
    return (
        tuple(command),
        qcsd_fd,
        qcsd_identity,
        helper_fd,
        helper_identity,
        native_fd,
        native_identity,
    )


def _close_descriptors_except(keep: set[int]) -> None:
    try:
        descriptors = [int(path.name) for path in Path("/proc/self/fd").iterdir()]
    except OSError:
        descriptors = list(range(3, 1024))
    for descriptor in descriptors:
        if descriptor <= 2 or descriptor in keep:
            continue
        try:
            os.close(descriptor)
        except OSError:
            pass


def _capture_fixed_path(
    path: Path,
    *,
    owner: int,
    mode: int,
    kind: int,
) -> PathIdentity:
    try:
        lexical = path.absolute()
        canonical = path.resolve(strict=True)
        value = path.stat(follow_symlinks=False)
    except OSError as error:
        raise GuardianError("fixed runtime path is unavailable") from error
    if (
        lexical != canonical
        or path.is_symlink()
        or stat.S_IFMT(value.st_mode) != kind
        or value.st_uid != owner
        or stat.S_IMODE(value.st_mode) != mode
    ):
        _fail("fixed runtime path has an unsafe identity")
    return PathIdentity(
        path=path,
        device=value.st_dev,
        inode=value.st_ino,
        owner=value.st_uid,
        mode=stat.S_IMODE(value.st_mode),
        kind=stat.S_IFMT(value.st_mode),
    )


def _capture_runtime_environment() -> RuntimeEnvironmentIdentity:
    uid = os.getuid()
    run = _capture_fixed_path(
        Path("/run"), owner=0, mode=0o755, kind=stat.S_IFDIR
    )
    run_user = _capture_fixed_path(
        Path("/run/user"), owner=0, mode=0o755, kind=stat.S_IFDIR
    )
    user_runtime = _capture_fixed_path(
        Path(f"/run/user/{uid}"), owner=uid, mode=0o700, kind=stat.S_IFDIR
    )
    bus = _capture_fixed_path(
        user_runtime.path / "bus",
        owner=uid,
        mode=0o666,
        kind=stat.S_IFSOCK,
    )
    temporary = _capture_fixed_path(
        Path("/tmp"), owner=0, mode=0o1777, kind=stat.S_IFDIR
    )
    identity = RuntimeEnvironmentIdentity(
        run=run,
        run_user=run_user,
        user_runtime=user_runtime,
        bus=bus,
        temporary=temporary,
    )
    _verify_runtime_environment(identity)
    return identity


def _verify_runtime_environment(expected: RuntimeEnvironmentIdentity) -> None:
    for item in (
        expected.run,
        expected.run_user,
        expected.user_runtime,
        expected.bus,
        expected.temporary,
    ):
        try:
            value = item.path.stat(follow_symlinks=False)
            canonical = item.path.resolve(strict=True)
        except OSError as error:
            raise GuardianError("fixed runtime path changed") from error
        if (
            canonical != item.path
            or item.path.is_symlink()
            or (
                value.st_dev,
                value.st_ino,
                value.st_uid,
                stat.S_IMODE(value.st_mode),
                stat.S_IFMT(value.st_mode),
            )
            != (
                item.device,
                item.inode,
                item.owner,
                item.mode,
                item.kind,
            )
        ):
            _fail("fixed runtime path identity changed")


def _sanitized_environment(
    runtime: RuntimeEnvironmentIdentity,
) -> dict[str, str]:
    environment = {}
    for key, value in os.environ.items():
        if (
            key.startswith(ENV_PREFIX)
            or key.startswith("_QCSD_")
            or key in _UNSAFE_ENVIRONMENT
            or key.startswith("BASH_FUNC_")
            or key.startswith("LD_")
            or key.startswith("LC_")
            or key.startswith("PYTHON")
            or key.startswith("GIT_")
            or key.startswith("DOCKER_")
            or key.startswith("BUILDX_")
            or key.startswith("BUILDKIT_")
            or key.startswith("DBUS_")
            or key.startswith("SYSTEMD_")
            or key.startswith("XDG_")
        ):
            continue
        environment[key] = value
    safe_path = _SAFE_PATH
    if _POWERSHELL_PATH.exists():
        try:
            canonical = _POWERSHELL_PATH.resolve(strict=True)
            value = _POWERSHELL_PATH.stat(follow_symlinks=False)
        except OSError as error:
            raise GuardianError(
                "cannot validate the fixed WSL PowerShell path"
            ) from error
        if (
            canonical != _POWERSHELL_PATH
            or _POWERSHELL_PATH.is_symlink()
            or not stat.S_ISREG(value.st_mode)
            or value.st_uid not in {0, os.getuid()}
            or stat.S_IMODE(value.st_mode) & 0o022
            or not stat.S_IMODE(value.st_mode) & 0o111
        ):
            _fail("fixed WSL PowerShell path has an unsafe identity")
        safe_path += f":{_POWERSHELL_PATH.parent}"
    environment["PATH"] = safe_path
    environment["LANG"] = "C"
    environment["LC_ALL"] = "C"
    environment["XDG_RUNTIME_DIR"] = str(runtime.user_runtime.path)
    environment["DBUS_SESSION_BUS_ADDRESS"] = (
        f"unix:path={runtime.bus.path}"
    )
    environment["TMPDIR"] = str(runtime.temporary.path)
    return environment


def _child_exec(
    command: tuple[str, ...],
    environment: dict[str, str],
    ready_fd: int,
    go_fd: int,
    recovery_ready_fd: int,
    final_go_fd: int,
    acquisition_lock: InheritedLockIdentity | None,
    guardian_pid: int,
) -> NoReturn:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        os._exit(125)
    if os.getppid() != guardian_pid:
        os._exit(125)
    try:
        os.setsid()
        child_pid = os.getpid()
        child_start = _process_start_time(child_pid)
        environment[f"{ENV_PREFIX}INNER_PID"] = str(child_pid)
        environment[f"{ENV_PREFIX}INNER_START_TIME"] = str(child_start)
        environment[f"{ENV_PREFIX}INNER_SESSION"] = str(child_pid)
        environment[f"{ENV_PREFIX}INNER_PROCESS_GROUP"] = str(child_pid)
        os.set_inheritable(ready_fd, True)
        os.set_inheritable(go_fd, True)
        os.set_inheritable(recovery_ready_fd, True)
        os.set_inheritable(final_go_fd, True)
        kept = {ready_fd, go_fd, recovery_ready_fd, final_go_fd}
        if acquisition_lock is not None:
            os.set_inheritable(acquisition_lock.descriptor, True)
            kept.add(acquisition_lock.descriptor)
        _close_descriptors_except(kept)
        for requested in FORWARDED_SIGNALS:
            signal.signal(requested, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, FORWARDED_SIGNALS)
        os.execve(
            "/bin/bash",
            ("/bin/bash", "--noprofile", "--norc", "-p", *command),
            environment,
        )
    except BaseException:
        os._exit(125)


def _status_code(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 125


def _kill_child_group(child: int, requested: int) -> None:
    try:
        os.killpg(child, requested)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            os.kill(child, requested)
        except ProcessLookupError:
            pass


def _abstract_lease_socket(latch: _SignalLatch) -> tuple[socket.socket, str]:
    encoded = f"qcsd-docker-lifecycle-guardian-{os.getuid()}"
    while True:
        if latch.first is not None:
            _fail("signal received before lifecycle singleton admission")
        listener = socket.socket(
            socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC
        )
        try:
            listener.bind(f"\0{encoded}")
        except OSError as error:
            listener.close()
            if error.errno == errno.EADDRINUSE:
                time.sleep(0.02)
                continue
            raise GuardianError("cannot bind lifecycle singleton") from error
        try:
            listener.listen(8)
            listener.setblocking(False)
        except BaseException:
            listener.close()
            raise
        return listener, f"@{encoded}"


def _process_uid(pid: int) -> int:
    try:
        return Path(f"/proc/{pid}").stat().st_uid
    except OSError as error:
        raise GuardianError("lease requester identity disappeared") from error


def _read_cmdline_payload(pid: int) -> bytes:
    try:
        payload = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError as error:
        raise GuardianError("inner qcsd command identity is unavailable") from error
    if not payload or not payload.endswith(b"\0") or b"\0\0" in payload:
        _fail("inner qcsd command line is malformed")
    return payload


def _read_cmdline(pid: int) -> tuple[str, ...]:
    try:
        return tuple(
            item.decode("utf-8", errors="strict")
            for item in _read_cmdline_payload(pid)[:-1].split(b"\0")
        )
    except UnicodeError as error:
        raise GuardianError("inner qcsd command identity is unavailable") from error


def _verify_inner_process(expected: ChildIdentity) -> bool:
    state, _, process_group, session, start_time = _process_record(expected.pid)
    if (
        start_time != expected.start_time
        or process_group != expected.process_group
        or session != expected.session
        or _process_uid(expected.pid) != os.getuid()
    ):
        _fail("inner qcsd process identity changed")
    if state == "Z":
        return False
    try:
        observed = _read_cmdline(expected.pid)
    except GuardianError:
        # Linux can clear an exiting task's cmdline after the live identity
        # sample above but just before waitid exposes the unreaped zombie.  Only
        # accept that narrow transition when the kernel proves this exact child
        # waitable; a live process with an unavailable cmdline still fails
        # closed with the original integrity error.
        for attempt in range(CHILD_EXIT_CONFIRM_ATTEMPTS):
            if _observe_child_exit(expected):
                _verify_exited_child_anchor(expected)
                return False
            if attempt + 1 < CHILD_EXIT_CONFIRM_ATTEMPTS:
                time.sleep(CHILD_EXIT_CONFIRM_RETRY_SECONDS)
        raise
    exact = ("/bin/bash", "--noprofile", "--norc", "-p", *expected.command)
    if observed != exact:
        _fail("inner qcsd command line changed")
    return True


def _verify_requester_descends_from(
    peer: int, requester_start_time: int, child: ChildIdentity
) -> None:
    current = peer
    for _ in range(64):
        if _process_uid(current) != os.getuid():
            _fail("lease requester is foreign")
        parent, process_group, session, start_time = _process_identity(current)
        if current == peer and start_time != requester_start_time:
            _fail("lease requester process identity changed")
        if process_group != child.process_group or session != child.session:
            _fail("lease requester escaped the qcsd session")
        if current == child.pid:
            return
        if parent <= 1 or parent == current:
            break
        current = parent
    _fail("lease requester is not an exact qcsd descendant")


def _validate_native_operation(operation: tuple[str, ...]) -> None:
    if not operation:
        _fail("retirement native operation is absent")
    expected_counts: dict[str, int | None] = {
        "publish": 7,
        "hold-creation": 10,
        "hold-api-service": None,
        "promote-authority": 15,
        "rename-root": 15,
        "unlink": 21,
        "rmdir": 14,
        "unlink-authority": 10,
    }
    action = operation[0]
    if action not in LEASE_ACTIONS:
        _fail("retirement native operation shape is invalid")
    if action == "hold-api-service":
        if len(operation) < 14 or operation[12] != "--" or not operation[13:]:
            _fail("retirement native operation shape is invalid")
    elif len(operation) != expected_counts[action]:
        _fail("retirement native operation shape is invalid")
    if not operation[1].startswith("/") or "\0" in operation[1]:
        _fail("retirement native base path is invalid")
    for value in operation[2:5]:
        if re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None:
            _fail("retirement native base identity is invalid")
    if action in {"rename-root", "unlink", "rmdir"}:
        if operation[5] != "--authority":
            _fail("retirement native authority is absent")
        if (
            re.fullmatch(
                r"retirement\.(?:run|network|build|transaction)\.[0-9a-f]{32}",
                operation[6],
            )
            is None
            or any(
                re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None
                for value in operation[7:10]
            )
            or HEX_64.fullmatch(operation[10]) is None
        ):
            _fail("retirement native authority binding is invalid")
    elif action != "hold-api-service" and "--authority" in operation[5:]:
        _fail("retirement native authority is unexpected")


def _verify_native_requester(
    peer: int,
    requester_start: int,
    child: ChildIdentity,
    native_identity: FileIdentity,
    lease_socket: str,
    lease_nonce: str,
    helper_identity: FileIdentity,
    lock_identity: LockIdentity,
) -> tuple[bytes, tuple[str, ...]]:
    state, parent, process_group, session, start_time = _process_record(peer)
    if (
        state == "Z"
        or start_time != requester_start
        or process_group != child.process_group
        or session != child.session
        or _process_uid(peer) != os.getuid()
    ):
        _fail("lease requester is not the exact qcsd native child")
    payload = _read_cmdline_payload(peer)
    command = _read_cmdline(peer)
    prefix = (
        "/usr/bin/python3",
        "-I",
        str(native_identity.path),
        "--lease",
        lease_socket,
        lease_nonce,
        str(child.pid),
        str(child.start_time),
        helper_identity.sha256,
        str(lock_identity.device),
        str(lock_identity.inode),
    )
    if command[: len(prefix)] != prefix:
        _fail("lease requester is not the pinned lifecycle native")
    operation = command[len(prefix) :]
    _validate_native_operation(operation)
    if operation[0] == "hold-api-service":
        _verify_requester_descends_from(peer, requester_start, child)
    elif parent != child.pid:
        _fail("lease requester is not the exact qcsd native child")
    if operation[0] == "hold-creation" and operation[6:] != (
        str(child.pid),
        str(child.start_time),
        str(child.session),
        str(child.process_group),
    ):
        _fail("creation-holder qcsd binding differs from guardian")
    if operation[0] == "hold-creation" and re.fullmatch(
        r"(?:run|network|build|transaction)[.][0-9a-f]{32}", operation[5]
    ) is None:
        _fail("creation-holder root binding is invalid")
    if operation[0] == "hold-api-service":
        if (
            re.fullmatch(
                r"qcsd-docker-api-[0-9a-f]{32}[.]service", operation[5]
            )
            is None
            or re.fullmatch(r"[1-9][0-9]*", operation[6]) is None
            or not 1 <= int(operation[6]) <= 86400
            or operation[7:11]
            != (
                str(child.pid),
                str(child.start_time),
                str(child.session),
                str(child.process_group),
            )
            or operation[11] != native_identity.sha256
            or operation[12] != "--"
            or not operation[13:]
        ):
            _fail("API-service holder binding differs from guardian")
    return payload, operation


def _canonical_lease_request(payload: bytes) -> dict[str, object]:
    if not payload.endswith(b"\n") or len(payload) > 4096:
        _fail("retirement lease request framing is invalid")
    try:
        text = payload.decode("ascii")
        value = json.loads(text)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GuardianError("retirement lease request is malformed") from error
    keys = {
        "action",
        "argv_sha256",
        "helper_source_sha256",
        "lease_nonce",
        "qcsd_pid",
        "qcsd_start_time",
        "requester_pid",
        "requester_start_time",
        "schema",
    }
    if not isinstance(value, dict) or set(value) != keys:
        _fail("retirement lease request fields differ from schema 1")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    if text != canonical:
        _fail("retirement lease request is not canonical")
    if (
        type(value["schema"]) is not int
        or value["schema"] != 1
        or any(
            type(value[key]) is not int or value[key] <= 0
            for key in (
                "qcsd_pid",
                "qcsd_start_time",
                "requester_pid",
                "requester_start_time",
            )
        )
        or not isinstance(value["action"], str)
        or value["action"] not in LEASE_ACTIONS
        or not isinstance(value["argv_sha256"], str)
        or HEX_64.fullmatch(value["argv_sha256"]) is None
        or not isinstance(value["helper_source_sha256"], str)
        or HEX_64.fullmatch(value["helper_source_sha256"]) is None
        or not isinstance(value["lease_nonce"], str)
        or HEX_64.fullmatch(value["lease_nonce"]) is None
    ):
        _fail("retirement lease request values differ from schema 1")
    return value


def _serve_one_lease(
    listener: socket.socket,
    *,
    lease_socket: str,
    lease_nonce: str,
    child: ChildIdentity,
    parent_fd: int,
    lock_fd: int,
    lock_identity: LockIdentity,
    source_fd: int,
    source_identity: FileIdentity,
    qcsd_fd: int,
    qcsd_identity: FileIdentity,
    helper_fd: int,
    helper_identity: FileIdentity,
    native_fd: int,
    native_identity: FileIdentity,
    docker_config_fd: int,
    docker_config_identity: ConfigDirectoryIdentity,
    docker_config_residues: Sequence[DockerConfigResidue],
    buildx_config_fd: int,
    buildx_config_identity: ConfigDirectoryIdentity,
    runtime_identity: RuntimeEnvironmentIdentity,
    deadline: float | None = None,
    cohort_lease: CohortLockLease | None = None,
) -> str:
    """Service at most one lease within one non-renewable time budget."""

    try:
        connection, _ = listener.accept()
    except BlockingIOError:
        return "none"
    with connection:
        service_deadline = time.monotonic() + LEASE_SERVICE_SECONDS
        if deadline is not None:
            service_deadline = min(service_deadline, deadline)
        try:
            credentials = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            peer_pid, peer_uid, _ = struct.unpack("3i", credentials)
            blocks: list[bytes] = []
            size = 0
            while True:
                remaining = service_deadline - time.monotonic()
                if remaining <= 0:
                    _fail("retirement lease service deadline expired")
                connection.settimeout(remaining)
                block = connection.recv(4097 - size)
                if not block:
                    break
                blocks.append(block)
                size += len(block)
                if size > 4096:
                    _fail("retirement lease request is oversized")
            request = _canonical_lease_request(b"".join(blocks))
            if (
                peer_uid != os.getuid()
                or type(request["schema"]) is not int
                or request["schema"] != 1
                or type(request["requester_pid"]) is not int
                or request["requester_pid"] != peer_pid
                or type(request["requester_start_time"]) is not int
                or request["requester_start_time"] <= 0
                or type(request["qcsd_pid"]) is not int
                or request["qcsd_pid"] != child.pid
                or type(request["qcsd_start_time"]) is not int
                or request["qcsd_start_time"] != child.start_time
                or not isinstance(request["lease_nonce"], str)
                or request["lease_nonce"] != lease_nonce
                or not isinstance(request["helper_source_sha256"], str)
                or request["helper_source_sha256"] != helper_identity.sha256
                or not isinstance(request["action"], str)
                or request["action"] not in LEASE_ACTIONS
                or not isinstance(request["argv_sha256"], str)
                or HEX_64.fullmatch(request["argv_sha256"]) is None
            ):
                _fail("retirement lease request identity is invalid")
            requester_start = int(request["requester_start_time"])
            observed_argv, operation = _verify_native_requester(
                peer_pid,
                requester_start,
                child,
                native_identity,
                lease_socket,
                lease_nonce,
                helper_identity,
                lock_identity,
            )
            if request["action"] != operation[0]:
                _fail("retirement lease action differs from native command")
            if hashlib.sha256(observed_argv).hexdigest() != request["argv_sha256"]:
                _fail("retirement lease requester command line changed")
            if not _verify_inner_process(child):
                _fail("inner qcsd exited during retirement lease admission")
            _verify_lock_identity(parent_fd, lock_fd, lock_identity)
            _verify_guardian_lock(lock_identity, os.getpid(), lock_fd)
            if cohort_lease is not None:
                _verify_cohort_lock_lease(cohort_lease, os.getpid())
            _verify_source_identity(source_fd, source_identity)
            _verify_source_identity(qcsd_fd, qcsd_identity)
            _verify_source_identity(helper_fd, helper_identity)
            _verify_source_identity(native_fd, native_identity)
            _verify_private_config(
                parent_fd,
                docker_config_fd,
                docker_config_identity,
                require_empty=True,
            )
            _verify_private_config_residues(
                parent_fd, docker_config_residues
            )
            _verify_private_config_namespace(
                parent_fd,
                docker_config_identity,
                docker_config_residues,
            )
            _verify_buildx_config(
                parent_fd,
                buildx_config_fd,
                buildx_config_identity,
                require_empty=False,
            )
            _verify_runtime_environment(runtime_identity)
            final_argv, final_operation = _verify_native_requester(
                peer_pid,
                requester_start,
                child,
                native_identity,
                lease_socket,
                lease_nonce,
                helper_identity,
                lock_identity,
            )
            if final_argv != observed_argv or final_operation != operation:
                _fail("retirement lease requester command line raced")
            if time.monotonic() >= service_deadline:
                _fail("retirement lease service deadline expired")
            lease_descriptors = [lock_fd, listener.fileno()]
            if operation[0] == "hold-api-service":
                lease_descriptors.extend([docker_config_fd, buildx_config_fd])
            descriptors = array.array("i", lease_descriptors)
            connection.sendmsg(
                [LEASE_MESSAGE],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)],
            )
        except (GuardianError, OSError, TimeoutError, ValueError):
            return "rejected"
    return "admitted"


def _session_processes(child: ChildIdentity) -> tuple[int, ...]:
    members: list[int] = []
    try:
        entries = tuple(Path("/proc").iterdir())
    except OSError as error:
        raise GuardianError("cannot census the inner qcsd session") from error
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            state, _, process_group, session, _ = _process_record(pid)
            uid = _process_uid(pid)
        except GuardianError:
            if not entry.exists():
                continue
            raise
        if (
            uid == os.getuid()
            and process_group == child.process_group
            and session == child.session
            and pid != child.pid
            and state != "Z"
        ):
            members.append(pid)
    return tuple(sorted(members))


def _verify_exited_child_anchor(child: ChildIdentity) -> None:
    state, _, process_group, session, start_time = _process_record(child.pid)
    if (
        state != "Z"
        or start_time != child.start_time
        or process_group != child.process_group
        or session != child.session
        or _process_uid(child.pid) != os.getuid()
    ):
        _fail("inner qcsd exit identity changed before process-group drain")


def _drain_child_group(child: ChildIdentity) -> None:
    confirmations = 0
    escalation = time.monotonic() + GROUP_DRAIN_SECONDS
    while True:
        try:
            _verify_exited_child_anchor(child)
            members = _session_processes(child)
            _verify_exited_child_anchor(child)
        except GuardianError:
            # Releasing the singleton/lock after losing the exact zombie anchor
            # could target a recycled PGID.  Keep authority instead.
            time.sleep(0.01)
            continue
        if members:
            confirmations = 0
            _kill_child_group(child.pid, signal.SIGKILL)
        else:
            confirmations += 1
            if confirmations >= 2:
                return
        # A process that cannot be proved absent must keep the guardian and its
        # lock alive.  The escalation interval merely repeats SIGKILL; it is
        # deliberately not a deadline that would release authority unsafely.
        if time.monotonic() >= escalation:
            _kill_child_group(child.pid, signal.SIGKILL)
            escalation = time.monotonic() + GROUP_DRAIN_SECONDS
        time.sleep(0.01)


def _observe_child_exit(child: ChildIdentity) -> bool:
    try:
        observed = os.waitid(
            os.P_PID,
            child.pid,
            os.WEXITED | os.WNOHANG | os.WNOWAIT,
        )
    except ChildProcessError as error:
        raise GuardianError("inner qcsd was reaped before safe drain") from error
    return observed is not None


def _publish_admission_decision(
    go_write: int,
    go_nonce: str,
    latch: _SignalLatch,
    child: ChildIdentity,
    forwarded: bool,
    *,
    ready: bool,
    failed: bool,
) -> tuple[bool, bool, bool, bool]:
    """Linearise admission and resolve it or retain it for a forwarded signal.

    Entry to the blocked-signal section is the admission linearisation point.
    A signal delivered before that point is either already latched or visible
    as pending immediately after the mask transition, so it cannot race the
    final latch check and GO write.  Signals arriving after the pending
    snapshot remain blocked until the decision is published; after unblocking
    they follow the ordinary post-admission forwarding path.  A signal already
    visible at the linearisation point is enqueued to a ready child and leaves
    the decision channel unresolved.  Keeping the writer open makes the signal
    the child's only wake-up: publishing ABORT as a fallback would race a
    deferred Bash trap and could let the child exit before servicing the
    forwarded signal.  The guardian retains all authority while it waits for
    the signalled child; ordinary non-signal failures still publish ABORT.

    The final return value states whether GO or ABORT resolved the channel and
    the caller may close its writer.  It must be derived inside this blocked
    critical section because a signal arriving after the pending snapshot is a
    post-linearisation signal and may validly follow a published GO.
    """

    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, FORWARDED_SIGNALS)
    try:
        pending = signal.sigpending()
        if latch.first is None:
            for requested in FORWARDED_SIGNALS:
                if requested in pending:
                    latch.handler(requested, None)
                    break
        signal_before_admission = latch.first is not None
        if ready and not failed and not signal_before_admission:
            token = f"{go_nonce}\n".encode("ascii")
            try:
                written = os.write(go_write, token)
            except OSError:
                return False, True, forwarded, True
            if written == len(token):
                return True, False, forwarded, True
            return False, True, forwarded, True
        if ready and signal_before_admission and not forwarded:
            assert latch.first is not None
            _kill_child_group(child.pid, latch.first)
            forwarded = True
        if ready and signal_before_admission:
            return False, failed, forwarded, False
        try:
            os.write(go_write, b"ABORT\n")
        except OSError:
            pass
        return False, failed, forwarded, True
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def _reap_drained_child(child: ChildIdentity) -> int:
    _drain_child_group(child)
    try:
        waited, status = os.waitpid(child.pid, 0)
    except ChildProcessError as error:
        raise GuardianError("inner qcsd disappeared before final reap") from error
    if waited != child.pid:
        _fail("inner qcsd final reap returned another process")
    return _status_code(status)


def _emergency_reap_child(
    pid: int,
    child: ChildIdentity | None,
    command: tuple[str, ...],
) -> None:
    if child is None:
        try:
            child = _bind_child_identity(pid, command)
        except GuardianError:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            return
    try:
        state, _, process_group, session, start_time = _process_record(child.pid)
    except GuardianError:
        state = ""
        process_group = -1
        session = -1
        start_time = -1
    if (
        state != "Z"
        and process_group == child.process_group
        and session == child.session
        and start_time == child.start_time
    ):
        _kill_child_group(child.pid, signal.SIGKILL)
    while True:
        try:
            if _observe_child_exit(child):
                break
        except GuardianError:
            pass
        time.sleep(0.01)
    _reap_drained_child(child)


def _wait_for_child(
    child: ChildIdentity,
    ready_read: int,
    nonce: str,
    go_write: int,
    go_nonce: str,
    recovery_read: int,
    recovery_nonce: str,
    final_go_write: int,
    final_go_nonce: str,
    lease_listener: socket.socket,
    lease_socket: str,
    lease_nonce: str,
    latch: _SignalLatch,
    parent_fd: int,
    lock_fd: int,
    lock_identity: LockIdentity,
    source_fd: int,
    source_identity: FileIdentity,
    qcsd_fd: int,
    qcsd_identity: FileIdentity,
    helper_fd: int,
    helper_identity: FileIdentity,
    native_fd: int,
    native_identity: FileIdentity,
    docker_config_fd: int,
    docker_config_identity: ConfigDirectoryIdentity,
    docker_config_residues: list[DockerConfigResidue],
    buildx_config_fd: int,
    buildx_config_identity: ConfigDirectoryIdentity,
    runtime_identity: RuntimeEnvironmentIdentity,
    cohort_lease: CohortLockLease | None = None,
) -> int:
    os.set_blocking(ready_read, False)
    os.set_blocking(recovery_read, False)
    ready = False
    admitted = False
    recovery_ready = False
    final_admitted = False
    forwarded = False
    signal_denial_pending = False
    buffer = b""
    recovery_buffer = b""
    ready_deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    recovery_deadline: float | None = None
    recovery_idle_deadline: float | None = None
    integrity_deadline = time.monotonic()
    failure_deadline: float | None = None
    failed = False
    while True:
        now = time.monotonic()
        if admitted and not recovery_ready and not failed:
            recovery_failure = ""
            if recovery_deadline is not None and now >= recovery_deadline:
                recovery_failure = "lifecycle recovery exceeded its deadline"
            elif (
                recovery_idle_deadline is not None
                and now >= recovery_idle_deadline
            ):
                recovery_failure = "lifecycle recovery made no bounded progress"
            if recovery_failure:
                print(
                    "qcsd-lab Docker lifecycle guardian: "
                    f"final admission integrity check failed: {recovery_failure}",
                    file=sys.stderr,
                )
                failed = True
                failure_deadline = now + FAILURE_CLEANUP_SECONDS
                _kill_child_group(child.pid, signal.SIGKILL)
        if admitted and not failed and not signal_denial_pending:
            # A hostile same-UID peer can occupy one request until the socket
            # timeout.  Service at most one request per scheduler turn so
            # signals, child exit, and integrity checks retain bounded
            # liveness even while the public abstract address is flooded.
            lease_deadline = None
            if not recovery_ready:
                active_deadlines = tuple(
                    value
                    for value in (recovery_deadline, recovery_idle_deadline)
                    if value is not None
                )
                if active_deadlines:
                    lease_deadline = min(active_deadlines)
            lease_outcome = _serve_one_lease(
                lease_listener,
                lease_socket=lease_socket,
                lease_nonce=lease_nonce,
                child=child,
                parent_fd=parent_fd,
                lock_fd=lock_fd,
                lock_identity=lock_identity,
                source_fd=source_fd,
                source_identity=source_identity,
                qcsd_fd=qcsd_fd,
                qcsd_identity=qcsd_identity,
                helper_fd=helper_fd,
                helper_identity=helper_identity,
                native_fd=native_fd,
                native_identity=native_identity,
                docker_config_fd=docker_config_fd,
                docker_config_identity=docker_config_identity,
                docker_config_residues=docker_config_residues,
                buildx_config_fd=buildx_config_fd,
                buildx_config_identity=buildx_config_identity,
                runtime_identity=runtime_identity,
                deadline=lease_deadline,
                cohort_lease=cohort_lease,
            )
            lease_completed = time.monotonic()
            if not recovery_ready:
                recovery_failure = ""
                if (
                    recovery_deadline is not None
                    and lease_completed >= recovery_deadline
                ):
                    recovery_failure = "lifecycle recovery exceeded its deadline"
                elif (
                    recovery_idle_deadline is not None
                    and lease_completed >= recovery_idle_deadline
                ):
                    recovery_failure = (
                        "lifecycle recovery made no bounded progress"
                    )
                if recovery_failure:
                    print(
                        "qcsd-lab Docker lifecycle guardian: "
                        "final admission integrity check failed: "
                        f"{recovery_failure}",
                        file=sys.stderr,
                    )
                    failed = True
                    failure_deadline = (
                        lease_completed + FAILURE_CLEANUP_SECONDS
                    )
                    _kill_child_group(child.pid, signal.SIGKILL)
                elif (
                    lease_outcome == "admitted"
                    and recovery_idle_deadline is not None
                ):
                    recovery_idle_deadline = (
                        lease_completed + RECOVERY_IDLE_TIMEOUT_SECONDS
                    )
        if _observe_child_exit(child):
            try:
                if cohort_lease is not None:
                    _verify_cohort_lock_lease(cohort_lease, os.getpid())
                _verify_private_config(
                    parent_fd,
                    docker_config_fd,
                    docker_config_identity,
                    require_empty=True,
                )
                _verify_private_config_residues(
                    parent_fd, docker_config_residues
                )
                _verify_private_config_namespace(
                    parent_fd,
                    docker_config_identity,
                    docker_config_residues,
                )
            except GuardianError as error:
                print(
                    "qcsd-lab Docker lifecycle guardian: "
                    f"terminal integrity check failed: {error}",
                    file=sys.stderr,
                )
                failed = True
            child_status = _reap_drained_child(child)
            try:
                if cohort_lease is not None:
                    _verify_cohort_lock_lease(cohort_lease, os.getpid())
            except GuardianError as error:
                print(
                    "qcsd-lab Docker lifecycle guardian: "
                    f"terminal integrity check failed: {error}",
                    file=sys.stderr,
                )
                failed = True
            if failed or not final_admitted:
                if latch.first is not None:
                    return 128 + latch.first
                return 125
            if latch.first is not None and child_status == 0:
                return 128 + latch.first
            return child_status
        now = time.monotonic()
        if now >= integrity_deadline:
            try:
                _verify_lock_identity(parent_fd, lock_fd, lock_identity)
                _verify_guardian_lock(lock_identity, os.getpid(), lock_fd)
                if cohort_lease is not None:
                    _verify_cohort_lock_lease(cohort_lease, os.getpid())
                _verify_source_identity(source_fd, source_identity)
                _verify_source_identity(qcsd_fd, qcsd_identity)
                _verify_source_identity(helper_fd, helper_identity)
                _verify_source_identity(native_fd, native_identity)
                _verify_private_config(
                    parent_fd,
                    docker_config_fd,
                    docker_config_identity,
                    require_empty=True,
                )
                _verify_private_config_residues(
                    parent_fd, docker_config_residues
                )
                _verify_private_config_namespace(
                    parent_fd,
                    docker_config_identity,
                    docker_config_residues,
                )
                _verify_buildx_config(
                    parent_fd,
                    buildx_config_fd,
                    buildx_config_identity,
                    require_empty=not admitted,
                )
                _verify_runtime_environment(runtime_identity)
                if not _verify_inner_process(child):
                    child_status = _reap_drained_child(child)
                    if cohort_lease is not None:
                        try:
                            _verify_cohort_lock_lease(
                                cohort_lease, os.getpid()
                            )
                        except GuardianError as error:
                            print(
                                "qcsd-lab Docker lifecycle guardian: "
                                f"terminal integrity check failed: {error}",
                                file=sys.stderr,
                            )
                            failed = True
                    if failed or not final_admitted:
                        if latch.first is not None:
                            return 128 + latch.first
                        return 125
                    if latch.first is not None and child_status == 0:
                        return 128 + latch.first
                    return child_status
            except GuardianError as error:
                if not failed:
                    print(
                        "qcsd-lab Docker lifecycle guardian: "
                        f"runtime integrity check failed: {error}",
                        file=sys.stderr,
                    )
                failed = True
                if (
                    failure_deadline is None
                    and not signal_denial_pending
                ):
                    failure_deadline = now + FAILURE_CLEANUP_SECONDS
                    _kill_child_group(
                        child.pid, signal.SIGTERM if ready else signal.SIGKILL
                    )
            integrity_deadline = now + INTEGRITY_CHECK_SECONDS
        if not ready and not failed:
            try:
                block = os.read(ready_read, 4096)
            except BlockingIOError:
                block = None
            except OSError as error:
                raise GuardianError(
                    "cannot read the lifecycle readiness channel"
                ) from error
            if block:
                buffer += block
                if len(buffer) > 65:
                    failed = True
                    if failure_deadline is None:
                        failure_deadline = now + FAILURE_CLEANUP_SECONDS
                        _kill_child_group(child.pid, signal.SIGKILL)
            elif block == b"":
                if buffer == f"{nonce}\n".encode("ascii"):
                    ready = True
                else:
                    failed = True
                if ready:
                    try:
                        _verify_lock_identity(parent_fd, lock_fd, lock_identity)
                        _verify_guardian_lock(lock_identity, os.getpid(), lock_fd)
                        if cohort_lease is not None:
                            _verify_cohort_lock_lease(
                                cohort_lease, os.getpid()
                            )
                        _verify_source_identity(source_fd, source_identity)
                        _verify_source_identity(qcsd_fd, qcsd_identity)
                        _verify_source_identity(helper_fd, helper_identity)
                        _verify_source_identity(native_fd, native_identity)
                        _verify_private_config(
                            parent_fd,
                            docker_config_fd,
                            docker_config_identity,
                            require_empty=True,
                        )
                        _verify_private_config_residues(
                            parent_fd, docker_config_residues
                        )
                        _verify_private_config_namespace(
                            parent_fd,
                            docker_config_identity,
                            docker_config_residues,
                        )
                        _verify_buildx_config(
                            parent_fd,
                            buildx_config_fd,
                            buildx_config_identity,
                            require_empty=True,
                        )
                        _verify_runtime_environment(runtime_identity)
                        if not _verify_inner_process(child):
                            _fail("inner qcsd exited before lifecycle admission")
                    except GuardianError as error:
                        print(
                            "qcsd-lab Docker lifecycle guardian: "
                            f"admission integrity check failed: {error}",
                            file=sys.stderr,
                        )
                        failed = True
                (
                    admitted,
                    failed,
                    forwarded,
                    decision_channel_resolved,
                ) = _publish_admission_decision(
                    go_write,
                    go_nonce,
                    latch,
                    child,
                    forwarded,
                    ready=ready,
                    failed=failed,
                )
                signal_denial_pending = not decision_channel_resolved
                if signal_denial_pending and failure_deadline is None:
                    failure_deadline = (
                        time.monotonic() + FAILURE_CLEANUP_SECONDS
                    )
                if decision_channel_resolved:
                    try:
                        os.close(go_write)
                    except OSError:
                        pass
                    go_write = -1
                if admitted:
                    recovery_deadline = (
                        time.monotonic() + RECOVERY_TIMEOUT_SECONDS
                    )
                    recovery_idle_deadline = (
                        time.monotonic() + RECOVERY_IDLE_TIMEOUT_SECONDS
                    )
                if (
                    failed
                    and failure_deadline is None
                    and not signal_denial_pending
                ):
                    failure_deadline = now + FAILURE_CLEANUP_SECONDS
                    _kill_child_group(child.pid, signal.SIGKILL)
            if now >= ready_deadline and not ready:
                failed = True
                if failure_deadline is None:
                    failure_deadline = now + FAILURE_CLEANUP_SECONDS
                    _kill_child_group(child.pid, signal.SIGKILL)
        if admitted and not recovery_ready and not failed:
            try:
                block = os.read(recovery_read, 4096)
            except BlockingIOError:
                block = None
            except OSError as error:
                raise GuardianError(
                    "cannot read the lifecycle recovery channel"
                ) from error
            if block:
                recovery_buffer += block
                if len(recovery_buffer) > 65:
                    failed = True
            elif block == b"":
                if recovery_buffer == f"{recovery_nonce}\n".encode("ascii"):
                    recovery_ready = True
                else:
                    failed = True
                if recovery_ready:
                    try:
                        if (
                            recovery_deadline is None
                            or time.monotonic() >= recovery_deadline
                        ):
                            _fail("lifecycle recovery exceeded its deadline")
                        _verify_lock_identity(
                            parent_fd, lock_fd, lock_identity
                        )
                        _verify_guardian_lock(lock_identity, os.getpid(), lock_fd)
                        if cohort_lease is not None:
                            _verify_cohort_lock_lease(
                                cohort_lease, os.getpid()
                            )
                        _verify_source_identity(source_fd, source_identity)
                        _verify_source_identity(qcsd_fd, qcsd_identity)
                        _verify_source_identity(helper_fd, helper_identity)
                        _verify_source_identity(native_fd, native_identity)
                        _verify_private_config(
                            parent_fd,
                            docker_config_fd,
                            docker_config_identity,
                            require_empty=True,
                        )
                        _verify_private_config_residues(
                            parent_fd, docker_config_residues
                        )
                        _verify_private_config_namespace(
                            parent_fd,
                            docker_config_identity,
                            docker_config_residues,
                        )
                        _verify_buildx_config(
                            parent_fd,
                            buildx_config_fd,
                            buildx_config_identity,
                            require_empty=False,
                        )
                        _verify_runtime_environment(runtime_identity)
                        if not _verify_inner_process(child):
                            _fail(
                                "inner qcsd exited before final lifecycle admission"
                            )
                        active_recovery_deadline = recovery_deadline
                        active_idle_deadline = recovery_idle_deadline

                        def recovery_continues(
                            deadline: float | None = active_recovery_deadline,
                            idle_deadline: float | None = active_idle_deadline,
                        ) -> None:
                            if (
                                deadline is None
                                or time.monotonic() >= deadline
                            ):
                                _fail("lifecycle recovery exceeded its deadline")
                            if (
                                idle_deadline is None
                                or time.monotonic() >= idle_deadline
                            ):
                                _fail("lifecycle recovery made no bounded progress")
                            if latch.first is not None:
                                _fail(
                                    "signal received before final lifecycle admission"
                                )
                            if cohort_lease is not None:
                                _verify_cohort_lock_lease(
                                    cohort_lease, os.getpid()
                                )
                            if not _verify_inner_process(child):
                                _fail(
                                    "inner qcsd exited while Docker residues drained"
                                )

                        recovery_continues()
                        while docker_config_residues:
                            recovery_continues()
                            residue = docker_config_residues[0]
                            residue_deadline = (
                                time.monotonic() + GROUP_DRAIN_SECONDS
                            )
                            if recovery_deadline is not None:
                                residue_deadline = min(
                                    residue_deadline, recovery_deadline
                                )
                            _retire_private_config_residue(
                                parent_fd,
                                residue,
                                deadline=residue_deadline,
                                continuation_check=recovery_continues,
                            )
                            os.close(residue.descriptor)
                            del docker_config_residues[0]
                        _verify_lock_identity(
                            parent_fd, lock_fd, lock_identity
                        )
                        _verify_guardian_lock(lock_identity, os.getpid(), lock_fd)
                        if cohort_lease is not None:
                            _verify_cohort_lock_lease(
                                cohort_lease, os.getpid()
                            )
                        _verify_source_identity(source_fd, source_identity)
                        _verify_source_identity(qcsd_fd, qcsd_identity)
                        _verify_source_identity(helper_fd, helper_identity)
                        _verify_source_identity(native_fd, native_identity)
                        _verify_private_config(
                            parent_fd,
                            docker_config_fd,
                            docker_config_identity,
                            require_empty=True,
                        )
                        _verify_buildx_config(
                            parent_fd,
                            buildx_config_fd,
                            buildx_config_identity,
                            require_empty=False,
                        )
                        _verify_runtime_environment(runtime_identity)
                        if not _verify_inner_process(child):
                            _fail(
                                "inner qcsd exited at final lifecycle admission"
                            )
                        _verify_private_config_namespace(
                            parent_fd, docker_config_identity, ()
                        )
                        recovery_continues()
                    except (GuardianError, OSError) as error:
                        print(
                            "qcsd-lab Docker lifecycle guardian: "
                            f"final admission integrity check failed: {error}",
                            file=sys.stderr,
                        )
                        failed = True
                (
                    final_admitted,
                    failed,
                    forwarded,
                    decision_channel_resolved,
                ) = _publish_admission_decision(
                    final_go_write,
                    final_go_nonce,
                    latch,
                    child,
                    forwarded,
                    ready=recovery_ready,
                    failed=failed,
                )
                signal_denial_pending = not decision_channel_resolved
                if signal_denial_pending and failure_deadline is None:
                    failure_deadline = (
                        time.monotonic() + FAILURE_CLEANUP_SECONDS
                    )
                if decision_channel_resolved:
                    try:
                        os.close(final_go_write)
                    except OSError:
                        pass
                    final_go_write = -1
            if (
                recovery_deadline is not None
                and now >= recovery_deadline
                and not recovery_ready
            ):
                failed = True
            if (
                recovery_idle_deadline is not None
                and now >= recovery_idle_deadline
                and not recovery_ready
            ):
                failed = True
            if (
                failed
                and failure_deadline is None
                and not signal_denial_pending
            ):
                failure_deadline = now + FAILURE_CLEANUP_SECONDS
                _kill_child_group(child.pid, signal.SIGKILL)
        if ready and latch.first is not None and not forwarded:
            _kill_child_group(child.pid, latch.first)
            forwarded = True
            if failure_deadline is None:
                failure_deadline = now + FAILURE_CLEANUP_SECONDS
        if failure_deadline is not None and now >= failure_deadline:
            _kill_child_group(child.pid, signal.SIGKILL)
            failure_deadline = now + 1.0
        time.sleep(0.01)


def _bind_child_identity(pid: int, command: tuple[str, ...]) -> ChildIdentity:
    deadline = time.monotonic() + 2.0
    expected_command = ("/bin/bash", "--noprofile", "--norc", "-p", *command)
    start_identity: int | None = None
    private_session = False
    while True:
        try:
            state, _, process_group, session, start_time = _process_record(pid)
            owner = _process_uid(pid)
        except GuardianError:
            if time.monotonic() >= deadline:
                raise
        else:
            if start_identity is None:
                start_identity = start_time
            elif start_time != start_identity:
                _fail("inner qcsd process identity changed during command binding")
            if owner != os.getuid():
                _fail("inner qcsd owner changed during command binding")
            if state == "Z":
                _fail("inner qcsd exited before exact command binding")
            if process_group == pid and session == pid:
                private_session = True
                child = ChildIdentity(
                    pid, start_time, session, process_group, command
                )
                if _observe_child_exit(child):
                    _fail("inner qcsd exited before exact command binding")
                try:
                    observed_command = _read_cmdline(pid)
                except GuardianError:
                    # Linux exposes a short empty/malformed cmdline window
                    # while exec replaces the post-setsid child image.  This
                    # process is not admitted yet, so retain every other bound
                    # identity and wait for the exact Bash argv rather than
                    # treating that kernel transition as runtime drift.
                    observed_command = ()
                if observed_command == expected_command:
                    return child
        if time.monotonic() >= deadline:
            if private_session:
                _fail("inner qcsd did not establish its exact command")
            _fail("inner qcsd did not establish its private session")
        time.sleep(0.005)


def _required_handshake() -> dict[str, str]:
    observed = {
        key.removeprefix(ENV_PREFIX): value
        for key, value in os.environ.items()
        if key.startswith(ENV_PREFIX)
    }
    if set(observed) != HANDSHAKE_FIELDS or any(
        not value or "\0" in value for value in observed.values()
    ):
        _fail("inner guardian handshake fields differ from schema 1")
    return observed


def _handshake_integer(values: dict[str, str], key: str) -> int:
    value = values[key]
    if re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None:
        _fail(f"inner guardian {key.lower()} is malformed")
    return int(value)


def _verify_handshake_source(
    values: dict[str, str], prefix: str
) -> FileIdentity:
    path = Path(values[f"{prefix}_PATH"])
    descriptor, observed = _capture_source_identity(path)
    try:
        expected = (
            _handshake_integer(values, f"{prefix}_DEVICE"),
            _handshake_integer(values, f"{prefix}_INODE"),
            values[f"{prefix}_SHA256"],
        )
        if (observed.device, observed.inode, observed.sha256) != expected:
            _fail(f"inner guardian {prefix.lower()} identity changed")
        return observed
    finally:
        os.close(descriptor)


def _open_guardian_pidfd(guardian_pid: int) -> int:
    """Bind the exact remote guardian task for the complete inner proof."""

    opener = getattr(os, "pidfd_open", None)
    if opener is None:
        _fail("inner guardian proof requires pidfd support")
    try:
        return opener(guardian_pid, 0)
    except OSError as error:
        if error.errno == errno.ESRCH:
            _fail("guardian process identity changed")
        raise GuardianError(
            "cannot bind the guardian process identity "
            f"(errno {error.errno})"
        ) from error


def _guardian_pidfd_is_terminal(pidfd: int) -> bool:
    """Return true only when the bound guardian task has exited."""

    poller = select.poll()
    try:
        poller.register(
            pidfd,
            select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL,
        )
        events = poller.poll(0)
    except OSError as error:
        raise GuardianError("cannot poll the guardian process identity") from error
    for observed_fd, flags in events:
        if observed_fd != pidfd or flags & select.POLLNVAL:
            _fail("guardian process pidfd became invalid")
        if flags & select.POLLIN:
            return True
        if flags:
            _fail("guardian process pidfd is indeterminate")
    return False


def _verify_guardian_process_identity(
    guardian_pid: int, guardian_start: int
) -> None:
    try:
        _, _, _, observed_start = _process_identity(guardian_pid)
        observed_owner = _process_uid(guardian_pid)
    except GuardianError as error:
        raise GuardianError("guardian process identity changed") from error
    if observed_start != guardian_start or observed_owner != os.getuid():
        _fail("guardian process identity changed")


def _run_guardian_bound_proof(
    guardian_pid: int,
    guardian_start: int,
    proof: Callable[[], dict[str, object]],
) -> dict[str, object]:
    """Run one remote guardian proof while its exact task remains live."""

    guardian_pidfd = _open_guardian_pidfd(guardian_pid)
    try:
        if _guardian_pidfd_is_terminal(guardian_pidfd):
            _fail("guardian process identity changed")
        _verify_guardian_process_identity(guardian_pid, guardian_start)
        result = proof()
        _verify_guardian_process_identity(guardian_pid, guardian_start)
        if _guardian_pidfd_is_terminal(guardian_pidfd):
            _fail("guardian process identity changed")
        return result
    finally:
        os.close(guardian_pidfd)


def _verify_inner_guardian_proof(
    values: dict[str, str], guardian_pid: int, guardian_start: int
) -> dict[str, object]:
    source_fd = _handshake_integer(values, "SOURCE_FD")
    qcsd_source_fd = _handshake_integer(values, "QCSD_SOURCE_FD")
    qcsd_pid = _handshake_integer(values, "INNER_PID")
    qcsd_start = _handshake_integer(values, "INNER_START_TIME")
    qcsd_session = _handshake_integer(values, "INNER_SESSION")
    qcsd_group = _handshake_integer(values, "INNER_PROCESS_GROUP")
    lock_device = _handshake_integer(values, "LOCK_DEVICE")
    lock_inode = _handshake_integer(values, "LOCK_INODE")
    docker_config_device = _handshake_integer(values, "DOCKER_CONFIG_DEVICE")
    docker_config_inode = _handshake_integer(values, "DOCKER_CONFIG_INODE")
    buildx_config_device = _handshake_integer(values, "BUILDX_CONFIG_DEVICE")
    buildx_config_inode = _handshake_integer(values, "BUILDX_CONFIG_INODE")
    lock_fd = _handshake_integer(values, "LOCK_FD")
    ready_fd = _handshake_integer(values, "READY_FD")
    go_fd = _handshake_integer(values, "GO_FD")
    recovery_ready_fd = _handshake_integer(values, "RECOVERY_READY_FD")
    final_go_fd = _handshake_integer(values, "FINAL_GO_FD")
    lock_path = Path(values["LOCK_PATH"])
    docker_config_path = Path(values["DOCKER_CONFIG_PATH"])
    buildx_config_path = Path(values["BUILDX_CONFIG_PATH"])
    docker_config_match = _docker_config_name_pattern(os.getuid()).fullmatch(
        docker_config_path.name
    )
    buildx_config_match = re.fullmatch(
        rf"/proc/{guardian_pid}/fd/([1-9][0-9]*)/"
        rf"[.]qcsd-buildx-config-{os.getuid()}[.][0-9a-f]{{64}}",
        buildx_config_path.as_posix(),
    )
    buildx_parent_fd = (
        int(buildx_config_match.group(1))
        if buildx_config_match is not None
        else -1
    )
    if (
        values["SCHEMA"] != SCHEMA
        or guardian_pid <= 1
        or source_fd <= 2
        or qcsd_source_fd <= 2
        or qcsd_pid != os.getppid()
        or qcsd_session != qcsd_pid
        or qcsd_group != qcsd_pid
        or values["BOOT_ID"] != _boot_id()
        or HEX_64.fullmatch(values["NONCE"]) is None
        or HEX_64.fullmatch(values["LEASE_NONCE"]) is None
        or HEX_64.fullmatch(values["GO_NONCE"]) is None
        or HEX_64.fullmatch(values["RECOVERY_NONCE"]) is None
        or HEX_64.fullmatch(values["FINAL_GO_NONCE"]) is None
        or values["LEASE_SOCKET"]
        != f"@qcsd-docker-lifecycle-guardian-{os.getuid()}"
        or not lock_path.is_absolute()
        or not docker_config_path.is_absolute()
        or docker_config_path.parent != lock_path.parent
        or docker_config_match is None
        or docker_config_match.group("boot")
        != values["BOOT_ID"].replace("-", "")
        or int(docker_config_match.group("start")) != guardian_start
        or buildx_config_match is None
    ):
        _fail("inner guardian process binding is invalid")
    qcsd_state, qcsd_parent, observed_group, observed_session, observed_start = (
        _process_record(qcsd_pid)
    )
    if (
        qcsd_state == "Z"
        or qcsd_parent != guardian_pid
        or observed_group != qcsd_group
        or observed_session != qcsd_session
        or observed_start != qcsd_start
        or _process_uid(qcsd_pid) != os.getuid()
    ):
        _fail("inner qcsd identity differs from guardian handshake")
    guardian_source = _verify_handshake_source(values, "SOURCE")
    qcsd_source = _verify_handshake_source(values, "QCSD_SOURCE")
    helper_source = _verify_handshake_source(values, "HELPER_SOURCE")
    native_source = _verify_handshake_source(values, "NATIVE_SOURCE")
    qcsd_command = _read_cmdline(qcsd_pid)
    guardian_command = _read_cmdline(guardian_pid)
    verifier_command = _read_cmdline(os.getpid())
    expected_qcsd_prefix = (
        "/bin/bash",
        "--noprofile",
        "--norc",
        "-p",
        f"/proc/{guardian_pid}/fd/{qcsd_source_fd}",
    )
    expected_guardian_prefix = (
        "/usr/bin/python3",
        "-I",
        f"/proc/self/fd/{source_fd}",
        "--entry-source-fd",
        str(source_fd),
        "--entry-source-path",
        str(guardian_source.path),
        "--",
    )
    expected_verifier = (
        "/usr/bin/python3",
        "-I",
        f"/proc/{guardian_pid}/fd/{source_fd}",
        "--verify-inner",
    )
    if (
        qcsd_command[:5] != expected_qcsd_prefix
        or guardian_command[:8] != expected_guardian_prefix
        or len(guardian_command) < 9
        or guardian_command[8] != str(qcsd_source.path)
        or guardian_command[9:] != qcsd_command[5:]
        or verifier_command != expected_verifier
        or helper_source.path
        != guardian_source.path.parent / "docker_signal_supervisor.sh"
        or native_source.path
        != guardian_source.path.parent / "docker_lifecycle_native.py"
    ):
        _fail("guardian/qcsd command correspondence changed")
    requested_cohort = _requested_build_cohort(
        (str(qcsd_source.path), *qcsd_command[5:])
    )
    cohort_value_fields = (
        "COHORT_VERSION",
        "COHORT_LOCK_FD",
        "COHORT_LOCK_PATH",
        "COHORT_LOCK_DEVICE",
        "COHORT_LOCK_INODE",
        "COHORT_LOCK_PARENT_DEVICE",
        "COHORT_LOCK_PARENT_INODE",
    )
    cohort_required_raw = values["COHORT_LOCK_REQUIRED"]
    if requested_cohort is None:
        if cohort_required_raw != "0" or any(
            values[key] != "unavailable" for key in cohort_value_fields
        ):
            _fail("non-build guardian cohort-lock authority is invalid")
        cohort_required = False
        cohort_version: int | str = "unavailable"
        cohort_lock_fd: int | str = "unavailable"
        cohort_lock_path: Path | str = "unavailable"
        cohort_lock_device: int | str = "unavailable"
        cohort_lock_inode: int | str = "unavailable"
        cohort_parent_device: int | str = "unavailable"
        cohort_parent_inode: int | str = "unavailable"
    else:
        if cohort_required_raw != "1":
            _fail("build guardian cohort-lock authority is absent")
        cohort_required = True
        cohort_version = _handshake_integer(values, "COHORT_VERSION")
        cohort_lock_fd = _handshake_integer(values, "COHORT_LOCK_FD")
        cohort_lock_device = _handshake_integer(
            values, "COHORT_LOCK_DEVICE"
        )
        cohort_lock_inode = _handshake_integer(values, "COHORT_LOCK_INODE")
        cohort_parent_device = _handshake_integer(
            values, "COHORT_LOCK_PARENT_DEVICE"
        )
        cohort_parent_inode = _handshake_integer(
            values, "COHORT_LOCK_PARENT_INODE"
        )
        cohort_lock_path = Path(values["COHORT_LOCK_PATH"])
        expected_cohort_path = (
            qcsd_source.path.parent
            / COHORT_REGISTRY_RELATIVE
            / COHORT_LOCK_NAME
        )
        if (
            cohort_version != requested_cohort
            or cohort_lock_fd <= 2
            or not cohort_lock_path.is_absolute()
            or cohort_lock_path != expected_cohort_path
        ):
            _fail("build guardian cohort-lock binding is invalid")
    if (
        lock_fd <= 2
        or ready_fd <= 2
        or go_fd <= 2
        or recovery_ready_fd <= 2
        or final_go_fd <= 2
        or len(
            {
                lock_fd,
                ready_fd,
                go_fd,
                recovery_ready_fd,
                final_go_fd,
            }
        )
        != 5
        or buildx_parent_fd <= 2
        or len(
            {
                lock_fd,
                source_fd,
                qcsd_source_fd,
                buildx_parent_fd,
            }
        )
        != 4
    ):
        _fail("inner guardian descriptor binding is invalid")
    try:
        path_value = os.stat(lock_path, follow_symlinks=False)
        guardian_value = os.stat(f"/proc/{guardian_pid}/fd/{lock_fd}")
        guardian_source_value = os.stat(f"/proc/{guardian_pid}/fd/{source_fd}")
        guardian_qcsd_value = os.stat(
            f"/proc/{guardian_pid}/fd/{qcsd_source_fd}"
        )
        docker_config_value = os.stat(
            docker_config_path, follow_symlinks=False
        )
        docker_config_children = os.listdir(docker_config_path)
        buildx_config_value = os.stat(buildx_config_path)
        buildx_config_children = os.listdir(buildx_config_path)
        buildx_parent_value = os.stat(buildx_config_path.parent)
        ready_value = os.fstat(ready_fd)
        go_value = os.fstat(go_fd)
        recovery_ready_value = os.fstat(recovery_ready_fd)
        final_go_value = os.fstat(final_go_fd)
        if cohort_required:
            assert isinstance(cohort_lock_fd, int)
            assert isinstance(cohort_lock_path, Path)
            cohort_path_value = os.stat(
                cohort_lock_path, follow_symlinks=False
            )
            cohort_guardian_value = os.stat(
                f"/proc/{guardian_pid}/fd/{cohort_lock_fd}"
            )
            cohort_guardian_path = os.readlink(
                f"/proc/{guardian_pid}/fd/{cohort_lock_fd}"
            )
            cohort_parent_value = os.stat(
                cohort_lock_path.parent, follow_symlinks=False
            )
    except OSError as error:
        raise GuardianError("inner guardian descriptor is unavailable") from error
    wanted = (lock_device, lock_inode, os.getuid(), 0o600, 1, 0)
    for observed in (path_value, guardian_value):
        actual = (
            observed.st_dev,
            observed.st_ino,
            observed.st_uid,
            stat.S_IMODE(observed.st_mode),
            observed.st_nlink,
            observed.st_size,
        )
        if not stat.S_ISREG(observed.st_mode) or actual != wanted:
            _fail("inner guardian lock identity changed")
    if (
        not stat.S_ISDIR(docker_config_value.st_mode)
        or (
            docker_config_value.st_dev,
            docker_config_value.st_ino,
            docker_config_value.st_uid,
            stat.S_IMODE(docker_config_value.st_mode),
            docker_config_value.st_nlink,
        )
        != (
            docker_config_device,
            docker_config_inode,
            os.getuid(),
            DOCKER_CONFIG_MODE,
            2,
        )
        or docker_config_children
    ):
        _fail("inner guardian Docker config is not private and empty")
    if (
        not stat.S_ISDIR(buildx_config_value.st_mode)
        or (
            buildx_config_value.st_dev,
            buildx_config_value.st_ino,
            buildx_config_value.st_uid,
            stat.S_IMODE(buildx_config_value.st_mode),
            buildx_config_value.st_nlink,
        )
        != (
            buildx_config_device,
            buildx_config_inode,
            os.getuid(),
            0o700,
            2,
        )
        or buildx_config_children
    ):
        _fail("inner guardian Buildx config is not private and empty")
    if (
        guardian_source_value.st_dev,
        guardian_source_value.st_ino,
        guardian_source_value.st_uid,
        stat.S_IMODE(guardian_source_value.st_mode),
        guardian_source_value.st_nlink,
    ) != (
        guardian_source.device,
        guardian_source.inode,
        guardian_source.owner,
        guardian_source.mode,
        guardian_source.links,
    ):
        _fail("inner guardian held source identity changed")
    if (
        guardian_qcsd_value.st_dev,
        guardian_qcsd_value.st_ino,
        guardian_qcsd_value.st_uid,
        stat.S_IMODE(guardian_qcsd_value.st_mode),
        guardian_qcsd_value.st_nlink,
    ) != (
        qcsd_source.device,
        qcsd_source.inode,
        qcsd_source.owner,
        qcsd_source.mode,
        qcsd_source.links,
    ):
        _fail("inner guardian held qcsd source identity changed")
    channel_bindings = (
        (ready_fd, ready_value, os.O_WRONLY),
        (go_fd, go_value, os.O_RDONLY),
        (recovery_ready_fd, recovery_ready_value, os.O_WRONLY),
        (final_go_fd, final_go_value, os.O_RDONLY),
    )
    channel_identities = {
        (value.st_dev, value.st_ino) for _, value, _ in channel_bindings
    }
    try:
        channel_modes = tuple(
            fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
            for descriptor, _, _ in channel_bindings
        )
    except OSError as error:
        raise GuardianError(
            "inner guardian lifecycle channel mode is unavailable"
        ) from error
    if (
        len(channel_identities) != len(channel_bindings)
        or any(
            not stat.S_ISFIFO(value.st_mode) or value.st_uid != os.getuid()
            for _, value, _ in channel_bindings
        )
        or channel_modes
        != tuple(expected_mode for _, _, expected_mode in channel_bindings)
    ):
        _fail("inner guardian lifecycle channel descriptors are invalid")
    parent_value = lock_path.parent.stat()
    if (
        (buildx_parent_value.st_dev, buildx_parent_value.st_ino)
        != (parent_value.st_dev, parent_value.st_ino)
        or docker_config_path.parent != lock_path.parent
    ):
        _fail("inner guardian config parent changed")
    lock_identity = LockIdentity(
        lock_path,
        parent_value.st_dev,
        parent_value.st_ino,
        lock_device,
        lock_inode,
        os.getuid(),
        0o600,
        1,
    )
    _verify_guardian_lock(lock_identity, guardian_pid, lock_fd)
    if cohort_required:
        assert isinstance(cohort_lock_fd, int)
        assert isinstance(cohort_lock_path, Path)
        assert isinstance(cohort_lock_device, int)
        assert isinstance(cohort_lock_inode, int)
        assert isinstance(cohort_parent_device, int)
        assert isinstance(cohort_parent_inode, int)
        cohort_wanted = (
            cohort_lock_device,
            cohort_lock_inode,
            os.getuid(),
            0o600,
            1,
            0,
        )
        for observed in (cohort_path_value, cohort_guardian_value):
            cohort_actual = (
                observed.st_dev,
                observed.st_ino,
                observed.st_uid,
                stat.S_IMODE(observed.st_mode),
                observed.st_nlink,
                observed.st_size,
            )
            if not stat.S_ISREG(observed.st_mode) or cohort_actual != cohort_wanted:
                _fail("inner guardian cohort-allocation lock identity changed")
        if (
            cohort_guardian_path != str(cohort_lock_path)
            or not stat.S_ISDIR(cohort_parent_value.st_mode)
            or (
                cohort_parent_value.st_dev,
                cohort_parent_value.st_ino,
                cohort_parent_value.st_uid,
                stat.S_IMODE(cohort_parent_value.st_mode),
            )
            != (
                cohort_parent_device,
                cohort_parent_inode,
                os.getuid(),
                0o700,
            )
        ):
            _fail("inner guardian cohort-allocation parent identity changed")
        _verify_descriptor_lock(
            cohort_lock_device,
            cohort_lock_inode,
            guardian_pid,
            cohort_lock_fd,
            failure=(
                "guardian does not exclusively own the cohort-allocation flock"
            ),
            owner=guardian_pid,
        )
    proof = {
        "boot_id": values["BOOT_ID"],
        "guardian_pid": guardian_pid,
        "guardian_source_device": guardian_source.device,
        "guardian_source_inode": guardian_source.inode,
        "guardian_source_path": str(guardian_source.path),
        "guardian_source_sha256": guardian_source.sha256,
        "guardian_start_time": guardian_start,
        "docker_config_path": str(docker_config_path),
        "docker_config_device": docker_config_device,
        "docker_config_inode": docker_config_inode,
        "buildx_config_path": str(buildx_config_path),
        "buildx_config_device": buildx_config_device,
        "buildx_config_inode": buildx_config_inode,
        "cohort_lock_required": cohort_required,
        "cohort_version": cohort_version,
        "cohort_lock_fd": cohort_lock_fd,
        "cohort_lock_path": str(cohort_lock_path),
        "cohort_lock_device": cohort_lock_device,
        "cohort_lock_inode": cohort_lock_inode,
        "cohort_lock_parent_device": cohort_parent_device,
        "cohort_lock_parent_inode": cohort_parent_inode,
        "go_fd": go_fd,
        "go_nonce": values["GO_NONCE"],
        "recovery_ready_fd": recovery_ready_fd,
        "recovery_nonce": values["RECOVERY_NONCE"],
        "final_go_fd": final_go_fd,
        "final_go_nonce": values["FINAL_GO_NONCE"],
        "helper_source_device": helper_source.device,
        "helper_source_inode": helper_source.inode,
        "helper_source_path": str(helper_source.path),
        "helper_source_sha256": helper_source.sha256,
        "lease_nonce": values["LEASE_NONCE"],
        "lease_socket": values["LEASE_SOCKET"],
        "lock_device": lock_device,
        "lock_inode": lock_inode,
        "lock_parent_device": parent_value.st_dev,
        "lock_parent_inode": parent_value.st_ino,
        "lock_path": str(lock_path),
        "native_source_device": native_source.device,
        "native_source_inode": native_source.inode,
        "native_source_path": str(native_source.path),
        "native_source_sha256": native_source.sha256,
        "qcsd_pid": qcsd_pid,
        "qcsd_source_fd": qcsd_source_fd,
        "qcsd_source_device": qcsd_source.device,
        "qcsd_source_inode": qcsd_source.inode,
        "qcsd_source_path": str(qcsd_source.path),
        "qcsd_source_sha256": qcsd_source.sha256,
        "qcsd_start_time": qcsd_start,
        "schema": 1,
    }
    return proof


def verify_inner() -> int:
    _require_unprivileged_identity()
    values = _required_handshake()
    guardian_pid = _handshake_integer(values, "PID")
    guardian_start = _handshake_integer(values, "START_TIME")
    if guardian_pid <= 1:
        _fail("inner guardian process binding is invalid")
    proof = _run_guardian_bound_proof(
        guardian_pid,
        guardian_start,
        lambda: _verify_inner_guardian_proof(
            values, guardian_pid, guardian_start
        ),
    )
    ready_fd = _handshake_integer(values, "READY_FD")
    os.write(ready_fd, f"{values['NONCE']}\n".encode("ascii"))
    os.close(ready_fd)
    print(json.dumps(proof, sort_keys=True, separators=(",", ":")), flush=True)
    return 0


def guard(
    command: Sequence[str],
    *,
    source_path: Path | None = None,
    source_descriptor: int | None = None,
    lock_parent: Path = LOCK_PARENT,
) -> int:
    _require_unprivileged_identity()
    previous_umask = os.umask(0o077)
    try:
        return _guard_with_private_umask(
            command,
            source_path=source_path,
            source_descriptor=source_descriptor,
            lock_parent=lock_parent,
        )
    finally:
        os.umask(previous_umask)


def _guard_with_private_umask(
    command: Sequence[str],
    *,
    source_path: Path | None = None,
    source_descriptor: int | None = None,
    lock_parent: Path = LOCK_PARENT,
) -> int:
    source = (
        Path(__file__).absolute()
        if source_path is None
        else source_path.absolute()
    )
    acquisition_lock: InheritedLockIdentity | None = None
    source_fd = -1
    qcsd_fd = -1
    helper_fd = -1
    native_fd = -1
    docker_config_fd = -1
    docker_config_identity: ConfigDirectoryIdentity | None = None
    docker_config_residues: list[DockerConfigResidue] = []
    buildx_config_fd = -1
    buildx_ledgers: list[BuildxLedger] = []
    parent_fd = -1
    lock_fd = -1
    cohort_lease: CohortLockLease | None = None
    ready_read = -1
    ready_write = -1
    go_read = -1
    go_write = -1
    recovery_read = -1
    recovery_write = -1
    final_go_read = -1
    final_go_write = -1
    lease_listener: socket.socket | None = None
    child_pid = -1
    guardian_start = 0
    child_identity: ChildIdentity | None = None
    child_reaped = False
    result = 125
    final_result = 125
    child_command = tuple(command)
    latch = _SignalLatch()
    saved_handlers = {
        requested: signal.getsignal(requested) for requested in FORWARDED_SIGNALS
    }
    previous_mask: set[signal.Signals] | None = None
    try:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, FORWARDED_SIGNALS)
        for requested in FORWARDED_SIGNALS:
            signal.signal(requested, latch.handler)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, FORWARDED_SIGNALS)
        acquisition_lock = _capture_inherited_acquisition_lock()
        kept = (
            {acquisition_lock.descriptor}
            if acquisition_lock is not None
            else set()
        )
        if source_descriptor is not None:
            kept.add(source_descriptor)
        _close_descriptors_except(kept)
        if source_descriptor is None:
            source_fd, source_identity = _capture_source_identity(source)
        else:
            source_fd = source_descriptor
            source_identity = _capture_bound_source_identity(source_fd, source)
        (
            inner,
            qcsd_fd,
            qcsd_identity,
            helper_fd,
            helper_identity,
            native_fd,
            native_identity,
        ) = _capture_inner_sources(command, source_identity)
        lease_listener, lease_socket = _abstract_lease_socket(latch)
        parent_fd, _ = _open_lock_parent(lock_parent.absolute())
        lock_fd, lock_identity = _open_lock(parent_fd, lock_parent.absolute())
        if acquisition_lock is not None and (
            acquisition_lock.device,
            acquisition_lock.inode,
        ) == (lock_identity.device, lock_identity.inode):
            _fail("acquisition lock aliases the Docker lifecycle lock")
        _acquire_lock(lock_fd, latch)
        _verify_lock_identity(parent_fd, lock_fd, lock_identity)
        _verify_source_identity(source_fd, source_identity)
        _verify_source_identity(qcsd_fd, qcsd_identity)
        _verify_source_identity(helper_fd, helper_identity)
        _verify_source_identity(native_fd, native_identity)
        guardian_pid = os.getpid()
        guardian_start = _process_start_time(guardian_pid)
        cohort_lease = _open_cohort_lock_lease(
            inner,
            qcsd_identity,
            latch,
            acquisition_lock,
        )
        if cohort_lease is not None:
            _drain_cohort_operation_lock(
                cohort_lease,
                lock_identity,
                latch,
                acquisition_lock,
            )

        def config_preparation_continues() -> None:
            if latch.first is not None:
                _fail("signal received during Docker config preparation")
            if cohort_lease is not None:
                _verify_cohort_lock_lease(cohort_lease, guardian_pid)

        (
            docker_config_fd,
            docker_config_identity,
            docker_config_residues,
        ) = _prepare_private_config(
            parent_fd,
            guardian_pid,
            continuation_check=config_preparation_continues,
        )
        (
            buildx_config_fd,
            buildx_config_identity,
            buildx_ledgers,
        ) = _prepare_buildx_config(
            parent_fd,
            guardian_pid,
            lock_identity,
            source_identity,
        )
        child_command = (
            f"/proc/{guardian_pid}/fd/{qcsd_fd}",
            *inner[1:],
        )
        _verify_guardian_lock(lock_identity, guardian_pid, lock_fd)
        if cohort_lease is not None:
            _verify_cohort_lock_lease(cohort_lease, guardian_pid)
        if _process_start_time(guardian_pid) != guardian_start:
            _fail("guardian start time changed during config preparation")
        nonce = os.urandom(32).hex()
        lease_nonce = os.urandom(32).hex()
        go_nonce = os.urandom(32).hex()
        ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
        go_read, go_write = os.pipe2(os.O_CLOEXEC)
        recovery_read, recovery_write = os.pipe2(os.O_CLOEXEC)
        final_go_read, final_go_write = os.pipe2(os.O_CLOEXEC)
        runtime_identity = _capture_runtime_environment()
        environment = _sanitized_environment(runtime_identity)
        if cohort_lease is None:
            cohort_handshake = {
                "COHORT_LOCK_REQUIRED": "0",
                "COHORT_VERSION": "unavailable",
                "COHORT_LOCK_FD": "unavailable",
                "COHORT_LOCK_PATH": "unavailable",
                "COHORT_LOCK_DEVICE": "unavailable",
                "COHORT_LOCK_INODE": "unavailable",
                "COHORT_LOCK_PARENT_DEVICE": "unavailable",
                "COHORT_LOCK_PARENT_INODE": "unavailable",
            }
        else:
            cohort_handshake = {
                "COHORT_LOCK_REQUIRED": "1",
                "COHORT_VERSION": str(cohort_lease.cohort_version),
                "COHORT_LOCK_FD": str(cohort_lease.lock_fd),
                "COHORT_LOCK_PATH": str(cohort_lease.lock.path),
                "COHORT_LOCK_DEVICE": str(cohort_lease.lock.device),
                "COHORT_LOCK_INODE": str(cohort_lease.lock.inode),
                "COHORT_LOCK_PARENT_DEVICE": str(
                    cohort_lease.lock.parent_device
                ),
                "COHORT_LOCK_PARENT_INODE": str(
                    cohort_lease.lock.parent_inode
                ),
            }
        handshake = {
            "SCHEMA": SCHEMA,
            "PID": str(guardian_pid),
            "START_TIME": str(guardian_start),
            "BOOT_ID": _boot_id(),
            "LOCK_PATH": str(lock_identity.path),
            "LOCK_DEVICE": str(lock_identity.device),
            "LOCK_INODE": str(lock_identity.inode),
            "LOCK_FD": str(lock_fd),
            "SOURCE_PATH": str(source_identity.path),
            "SOURCE_FD": str(source_fd),
            "SOURCE_DEVICE": str(source_identity.device),
            "SOURCE_INODE": str(source_identity.inode),
            "SOURCE_SHA256": source_identity.sha256,
            "QCSD_SOURCE_PATH": str(qcsd_identity.path),
            "QCSD_SOURCE_FD": str(qcsd_fd),
            "QCSD_SOURCE_DEVICE": str(qcsd_identity.device),
            "QCSD_SOURCE_INODE": str(qcsd_identity.inode),
            "QCSD_SOURCE_SHA256": qcsd_identity.sha256,
            "HELPER_SOURCE_PATH": str(helper_identity.path),
            "HELPER_SOURCE_DEVICE": str(helper_identity.device),
            "HELPER_SOURCE_INODE": str(helper_identity.inode),
            "HELPER_SOURCE_SHA256": helper_identity.sha256,
            "NATIVE_SOURCE_PATH": str(native_identity.path),
            "NATIVE_SOURCE_DEVICE": str(native_identity.device),
            "NATIVE_SOURCE_INODE": str(native_identity.inode),
            "NATIVE_SOURCE_SHA256": native_identity.sha256,
            "NONCE": nonce,
            "READY_FD": str(ready_write),
            "GO_FD": str(go_read),
            "GO_NONCE": go_nonce,
            "RECOVERY_READY_FD": str(recovery_write),
            "RECOVERY_NONCE": os.urandom(32).hex(),
            "FINAL_GO_FD": str(final_go_read),
            "FINAL_GO_NONCE": os.urandom(32).hex(),
            "LEASE_SOCKET": lease_socket,
            "LEASE_NONCE": lease_nonce,
            "DOCKER_CONFIG_PATH": str(docker_config_identity.path),
            "DOCKER_CONFIG_DEVICE": str(docker_config_identity.device),
            "DOCKER_CONFIG_INODE": str(docker_config_identity.inode),
            "BUILDX_CONFIG_PATH": str(buildx_config_identity.path),
            "BUILDX_CONFIG_DEVICE": str(buildx_config_identity.device),
            "BUILDX_CONFIG_INODE": str(buildx_config_identity.inode),
            **cohort_handshake,
        }
        environment.update(
            {f"{ENV_PREFIX}{key}": value for key, value in handshake.items()}
        )
        signal.pthread_sigmask(signal.SIG_BLOCK, FORWARDED_SIGNALS)
        child = os.fork()
        child_pid = child
        if child == 0:
            os.close(ready_read)
            _child_exec(
                child_command,
                environment,
                ready_write,
                go_read,
                recovery_write,
                final_go_read,
                acquisition_lock,
                guardian_pid,
            )
        os.close(ready_write)
        ready_write = -1
        os.close(go_read)
        go_read = -1
        os.close(recovery_write)
        recovery_write = -1
        os.close(final_go_read)
        final_go_read = -1
        if acquisition_lock is not None:
            os.close(acquisition_lock.descriptor)
            acquisition_lock = None
        child_identity = _bind_child_identity(child, child_command)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, FORWARDED_SIGNALS)
        assert lease_listener is not None
        result = _wait_for_child(
            child_identity,
            ready_read,
            nonce,
            go_write,
            go_nonce,
            recovery_read,
            handshake["RECOVERY_NONCE"],
            final_go_write,
            handshake["FINAL_GO_NONCE"],
            lease_listener,
            lease_socket,
            lease_nonce,
            latch,
            parent_fd,
            lock_fd,
            lock_identity,
            source_fd,
            source_identity,
            qcsd_fd,
            qcsd_identity,
            helper_fd,
            helper_identity,
            native_fd,
            native_identity,
            docker_config_fd,
            docker_config_identity,
            docker_config_residues,
            buildx_config_fd,
            buildx_config_identity,
            runtime_identity,
            cohort_lease,
        )
        child_reaped = True
    finally:
        cleanup_error: GuardianError | None = None

        def record_cleanup_error(error: Exception, context: str) -> None:
            nonlocal cleanup_error
            if cleanup_error is not None:
                return
            cleanup_error = (
                error
                if isinstance(error, GuardianError)
                else GuardianError(f"{context}: {type(error).__name__}")
            )

        if child_pid > 0 and not child_reaped:
            _emergency_reap_child(child_pid, child_identity, child_command)
        buildx_cleanup_complete = not buildx_ledgers
        if buildx_ledgers:
            if parent_fd < 0 or lock_fd < 0:
                record_cleanup_error(
                    GuardianError("Buildx cleanup authority is unavailable"),
                    "cannot clean Buildx state",
                )
            else:
                try:
                    _cleanup_buildx_ledgers(
                        parent_fd,
                        os.getpid(),
                        lock_identity,
                        buildx_ledgers,
                    )
                except Exception as error:
                    record_cleanup_error(error, "cannot clean Buildx state")
                else:
                    buildx_cleanup_complete = True
        if (
            buildx_cleanup_complete
            and parent_fd >= 0
            and docker_config_residues
        ):
            retained_residues: list[DockerConfigResidue] = []
            for residue in docker_config_residues:
                try:
                    residue_cleanup_deadline = (
                        time.monotonic() + FINAL_CONFIG_DRAIN_SECONDS
                    )
                    _retire_private_config_residue(
                        parent_fd, residue, deadline=residue_cleanup_deadline
                    )
                    os.close(residue.descriptor)
                except Exception as error:
                    retained_residues.append(residue)
                    record_cleanup_error(
                        error, "cannot retire Docker config residue"
                    )
            docker_config_residues[:] = retained_residues
        if (
            buildx_cleanup_complete
            and
            parent_fd >= 0
            and docker_config_fd >= 0
            and docker_config_identity is not None
        ):
            try:
                current_cleanup_deadline = (
                    time.monotonic() + CURRENT_CONFIG_DRAIN_SECONDS
                )
                current_match = _docker_config_name_pattern(
                    os.getuid()
                ).fullmatch(
                    docker_config_identity.path.name,
                )
                if (
                    current_match is None
                    or current_match.group("boot") != _boot_token()
                    or int(current_match.group("start")) != guardian_start
                ):
                    _fail("current Docker config name changed before cleanup")
                _retire_private_config_residue(
                    parent_fd,
                    DockerConfigResidue(
                        descriptor=docker_config_fd,
                        config=docker_config_identity,
                        boot_token=current_match.group("boot"),
                        guardian_start=int(current_match.group("start")),
                        census_start=int(current_match.group("start")),
                    ),
                    deadline=current_cleanup_deadline,
                )
            except Exception as error:
                record_cleanup_error(error, "cannot retire current Docker config")
        if parent_fd >= 0:
            try:
                prefix = f".qcsd-docker-config-{os.getuid()}."
                leftovers = tuple(
                    name
                    for name in os.listdir(parent_fd)
                    if name.startswith(prefix)
                )
            except Exception as error:
                record_cleanup_error(
                    error, "cannot verify the retired Docker config namespace"
                )
            else:
                if leftovers:
                    record_cleanup_error(
                        GuardianError(
                            "retired Docker config namespace is not empty"
                        ),
                        "cannot verify the retired Docker config namespace",
                    )
        if cohort_lease is not None:
            try:
                _lock_cohort_operation_for_cleanup(
                    cohort_lease,
                    deadline=time.monotonic() + GROUP_DRAIN_SECONDS,
                )
                _verify_cohort_lock_lease(cohort_lease, os.getpid())
            except Exception as error:
                record_cleanup_error(
                    error, "cannot verify the cohort-allocation lock at cleanup"
                )
            try:
                _close_cohort_lock_lease(cohort_lease)
            except OSError as error:
                record_cleanup_error(
                    error, "cannot close the cohort-allocation lock"
                )
            cohort_lease = None
        if acquisition_lock is not None:
            try:
                os.close(acquisition_lock.descriptor)
            except OSError as error:
                record_cleanup_error(
                    error, "cannot close inherited acquisition lock"
                )
        if lease_listener is not None:
            try:
                lease_listener.close()
            except OSError as error:
                record_cleanup_error(error, "cannot close lifecycle lease listener")
        for residue in docker_config_residues:
            try:
                os.close(residue.descriptor)
            except OSError as error:
                record_cleanup_error(
                    error, "cannot close Docker config residue descriptor"
                )
        for descriptor, context in (
            (docker_config_fd, "cannot close current Docker config descriptor"),
            (buildx_config_fd, "cannot close current Buildx config descriptor"),
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError as error:
                    record_cleanup_error(error, context)
        docker_config_fd = -1
        buildx_config_fd = -1
        for descriptor in (
            ready_read,
            ready_write,
            go_read,
            go_write,
            recovery_read,
            recovery_write,
            final_go_read,
            final_go_write,
            lock_fd,
            parent_fd,
            source_fd,
            qcsd_fd,
            helper_fd,
            native_fd,
            docker_config_fd,
            buildx_config_fd,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if previous_mask is not None:
            signal.pthread_sigmask(signal.SIG_BLOCK, FORWARDED_SIGNALS)
        # Keep the owned handlers active through authority/config cleanup and
        # descriptor release, then close status selection atomically by
        # blocking before sampling the latch and kernel-pending set.
        terminal = latch.first
        pending = signal.sigpending().intersection(FORWARDED_SIGNALS)
        if terminal is None and pending:
            terminal = min(pending, key=int)
        while pending:
            signal.sigwait(pending)
            pending = signal.sigpending().intersection(FORWARDED_SIGNALS)
        final_result = 128 + terminal if result == 0 and terminal else result
        for requested, handler in saved_handlers.items():
            signal.signal(requested, handler)
        if previous_mask is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        if cleanup_error is not None:
            print(
                "qcsd-lab Docker lifecycle guardian: "
                f"terminal cleanup incomplete: {cleanup_error}",
                file=sys.stderr,
            )
            final_result = 125
    return final_result


def main(arguments: Sequence[str] | None = None) -> int:
    values = list(sys.argv[1:] if arguments is None else arguments)
    if values == ["--verify-inner"]:
        try:
            return verify_inner()
        except GuardianError as error:
            print(f"qcsd-lab Docker lifecycle guardian: {error}", file=sys.stderr)
            return 125
    if (
        len(values) < 6
        or values[0] != "--entry-source-fd"
        or re.fullmatch(r"[0-9]+", values[1]) is None
        or values[2] != "--entry-source-path"
        or values[4] != "--"
    ):
        print(
            "usage: python3 -I /proc/self/fd/N "
            "--entry-source-fd N --entry-source-path /absolute/guardian "
            "-- /absolute/path/qcsd-lab [args...]",
            file=sys.stderr,
        )
        return 2
    source_descriptor = int(values[1])
    source_path = Path(values[3])
    if Path(__file__).as_posix() != f"/proc/self/fd/{source_descriptor}":
        print(
            "qcsd-lab Docker lifecycle guardian: entry source FD differs",
            file=sys.stderr,
        )
        return 125
    try:
        return guard(
            values[5:],
            source_path=source_path,
            source_descriptor=source_descriptor,
        )
    except GuardianError as error:
        print(f"qcsd-lab Docker lifecycle guardian: {error}", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
