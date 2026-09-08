#!/usr/bin/python3
"""Execute one dirfd-bound QCSD lifecycle retirement mutation.

Production mutations first obtain a duplicate of the guardian's flock OFD.
This pinned helper deliberately imports no flock API: the received descriptor
is held through the mutation and its durability barrier, then closed normally.
"""

from __future__ import annotations

import array
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import stat
import subprocess
import sys
import time
from typing import NoReturn, Sequence


LEASE_MESSAGE = b"QCSD-LOCK-LEASE-V1\n"
RENAME_NOREPLACE = 1
HEX_64 = re.compile(r"[0-9a-f]{64}")
DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)")
SAFE_NAME = re.compile(r"[A-Za-z0-9_.-]+")
MAX_AUTHORITY_BYTES = 65536
MAX_LIFECYCLE_OPERATIONS = 7
PR_SET_PDEATHSIG = 1
CREATION_READY = b"QCSD-CREATION-HOLD-READY-V1\n"
CREATION_COMMIT = b"QCSD-CREATION-HOLD-COMMIT-V1\n"
CREATION_CANCEL = b"QCSD-CREATION-HOLD-CANCEL-V1\n"
CREATION_COMMITTED = b"QCSD-CREATION-HOLD-COMMITTED-V1\n"
CREATION_CANCELLED = b"QCSD-CREATION-HOLD-CANCELLED-V1\n"
CREATION_REJECTED = b"QCSD-CREATION-HOLD-REJECTED-V1\n"
API_LEASE_MESSAGE = b"QCSD-API-SERVICE-LEASE-V1\n"
API_LEASE_ACK = b"QCSD-API-SERVICE-LEASE-ACK-V1\n"
API_REQUEST_LIMIT = 4096
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMD_RUN = "/usr/bin/systemd-run"
TIMEOUT = "/usr/bin/timeout"
DOCKER_CONFIG_MODE = 0o500
BUILDX_CONFIG_MODE = 0o700

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


def _die(message: str) -> NoReturn:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def _safe_name(value: str) -> str:
    if (
        SAFE_NAME.fullmatch(value) is None
        or value in {".", ".."}
        or "/" in value
        or "\0" in value
    ):
        _die("unsafe retirement path component")
    return value


def _integer(value: str) -> int:
    if DECIMAL.fullmatch(value) is None:
        _die("invalid retirement integer")
    return int(value)


def _process_start_time(pid: int) -> int:
    try:
        payload = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = payload.rsplit(") ", maxsplit=1)[1].split()
        observed = _integer(fields[19])
    except (OSError, UnicodeError, IndexError) as error:
        raise SystemExit("cannot bind native requester process identity") from error
    if observed <= 0:
        _die("native requester process identity is invalid")
    return observed


def _process_record(pid: int) -> tuple[str, int, int, int, int]:
    try:
        payload = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        state, parent, process_group, session, *tail = payload.rsplit(
            ") ", maxsplit=1
        )[1].split()
        start_time = _integer(tail[15])
    except (OSError, UnicodeError, IndexError, ValueError) as error:
        raise RuntimeError("cannot bind creation-holder process") from error
    return state, _integer(parent), _integer(process_group), _integer(session), start_time


def _process_uid(pid: int) -> int:
    try:
        return Path(f"/proc/{pid}").stat().st_uid
    except OSError as error:
        raise RuntimeError("cannot bind creation-holder owner") from error


def _exact_creation_parent(
    pid: int, start: int, session: int, process_group: int
) -> str | None:
    try:
        state, _, observed_group, observed_session, observed_start = (
            _process_record(pid)
        )
        owner = _process_uid(pid)
    except RuntimeError:
        return False
    return (
        state != "Z"
        and observed_start == start
        and observed_session == session
        and observed_group == process_group
        and owner == os.getuid()
        and os.getppid() == pid
    )


def _exact_qcsd_ancestor(
    pid: int, start: int, session: int, process_group: int
) -> bool:
    try:
        state, _, observed_group, observed_session, observed_start = (
            _process_record(pid)
        )
        if (
            state == "Z"
            or observed_start != start
            or observed_session != session
            or observed_group != process_group
            or _process_uid(pid) != os.getuid()
        ):
            return False
        current = os.getpid()
        for _ in range(64):
            _, parent, current_group, current_session, _ = _process_record(current)
            if current_group != process_group or current_session != session:
                return False
            if parent == pid:
                return True
            if parent <= 1 or parent == current:
                return False
            current = parent
    except RuntimeError:
        return False
    return False


def _creation_session_members(
    session: int, process_group: int, holder_pid: int
) -> tuple[int, ...] | None:
    try:
        entries = tuple(Path("/proc").iterdir())
    except OSError:
        return None
    members: list[int] = []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == holder_pid:
            continue
        try:
            if entry.stat().st_uid != os.getuid():
                continue
            state, _, observed_group, observed_session, _ = _process_record(pid)
        except RuntimeError:
            if entry.exists():
                return None
            continue
        except OSError:
            if entry.exists():
                return None
            continue
        if (
            state != "Z"
            and observed_session == session
            and observed_group == process_group
        ):
            members.append(pid)
    return tuple(sorted(members))


def _write_creation_result(result: bytes) -> None:
    try:
        sys.stdout.buffer.write(result)
        sys.stdout.buffer.flush()
    except (BrokenPipeError, OSError):
        # A disappearing reader is not authority to release either lease.
        pass


def _durable_initial_supervision(
    base_fd: int,
    base: str,
    uid: int,
    root_name: str,
    root_device: int,
    root_inode: int,
) -> bool:
    match = re.fullmatch(
        r"(run|network|build|transaction)[.]([0-9a-f]{32})", root_name
    )
    if match is None:
        return False
    kind, token = match.groups()
    expected_object = {
        "run": "docker-run-scope-launcher",
        "network": "network",
        "build": "docker-build-scope-launcher",
        "transaction": "docker-build-transaction",
    }[kind]
    try:
        root_fd = os.open(
            root_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=base_fd,
        )
    except OSError:
        return False
    try:
        root_value = os.fstat(root_fd)
        root_path = os.stat(root_name, dir_fd=base_fd, follow_symlinks=False)
        root_identity = (
            root_value.st_dev,
            root_value.st_ino,
            root_value.st_uid,
            stat.S_IMODE(root_value.st_mode),
        )
        if (
            not stat.S_ISDIR(root_value.st_mode)
            or root_identity
            != (
                root_device,
                root_inode,
                uid,
                0o700,
            )
            or (root_path.st_dev, root_path.st_ino)
            != (root_device, root_inode)
        ):
            return False
        supervision_fd = os.open(
            "SUPERVISION",
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
        try:
            supervision = os.fstat(supervision_fd)
            supervision_path = os.stat(
                "SUPERVISION", dir_fd=root_fd, follow_symlinks=False
            )
            wanted = (
                supervision.st_dev,
                supervision.st_ino,
                uid,
                0o600,
                1,
                supervision.st_size,
            )
            observed = (
                supervision_path.st_dev,
                supervision_path.st_ino,
                supervision_path.st_uid,
                stat.S_IMODE(supervision_path.st_mode),
                supervision_path.st_nlink,
                supervision_path.st_size,
            )
            if (
                not stat.S_ISREG(supervision.st_mode)
                or wanted != observed
                or not 0 < supervision.st_size <= MAX_AUTHORITY_BYTES
            ):
                return False
            os.lseek(supervision_fd, 0, os.SEEK_SET)
            payload = os.read(supervision_fd, MAX_AUTHORITY_BYTES + 1)
            try:
                text = payload.decode("ascii")
            except UnicodeError:
                return False
            expected_root = f"{Path(base).absolute()}/{root_name}"
            lines = text.splitlines()
            if (
                len(payload) != supervision.st_size
                or not text.endswith("\n")
                or "\r" in text
                or "\0" in text
                or not lines
                or lines[0] != f"object={expected_object}"
                or lines.count(f"lifecycle_token={token}") != 1
                or lines.count(f"lifecycle_root={expected_root}") != 1
            ):
                return False
            os.fsync(supervision_fd)
            current = os.stat(
                "SUPERVISION", dir_fd=root_fd, follow_symlinks=False
            )
            if (current.st_dev, current.st_ino) != (
                supervision.st_dev,
                supervision.st_ino,
            ) or _fd_sha256(supervision_fd) != hashlib.sha256(payload).hexdigest():
                return False
        finally:
            os.close(supervision_fd)
        os.fsync(root_fd)
        os.fsync(base_fd)
        current_root = os.stat(root_name, dir_fd=base_fd, follow_symlinks=False)
        return (current_root.st_dev, current_root.st_ino) == root_identity[:2]
    except OSError:
        return False
    finally:
        os.close(root_fd)


def _cancel_initial_root(
    base_fd: int,
    root_fd: int,
    uid: int,
    root_name: str,
    root_device: int,
    root_inode: int,
) -> bool:
    allowed = {
        "SUPERVISION.next": stat.S_IFREG,
        "stdout": stat.S_IFREG,
        "wait.pipe": stat.S_IFIFO,
    }
    try:
        root_value = os.fstat(root_fd)
        root_path = os.stat(root_name, dir_fd=base_fd, follow_symlinks=False)
        if (
            not stat.S_ISDIR(root_value.st_mode)
            or (root_value.st_dev, root_value.st_ino, root_value.st_uid)
            != (root_device, root_inode, uid)
            or stat.S_IMODE(root_value.st_mode) != 0o700
            or (root_path.st_dev, root_path.st_ino) != (root_device, root_inode)
        ):
            return False
        children = sorted(os.listdir(root_fd))
        if any(name not in allowed for name in children):
            return False
        for name in children:
            value = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if (
                stat.S_IFMT(value.st_mode) != allowed[name]
                or value.st_uid != uid
                or stat.S_IMODE(value.st_mode) != 0o600
                or value.st_nlink != 1
            ):
                return False
            os.unlink(name, dir_fd=root_fd)
        os.fsync(root_fd)
        current = os.stat(root_name, dir_fd=base_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (root_device, root_inode):
            return False
        os.rmdir(root_name, dir_fd=base_fd)
        os.fsync(base_fd)
        return True
    except OSError:
        return False


def _hold_creation(
    base_fd: int, base: str, uid: int, arguments: Sequence[str]
) -> None:
    root_name = _safe_name(arguments[0])
    if re.fullmatch(
        r"(?:run|network|build|transaction)[.][0-9a-f]{32}", root_name
    ) is None:
        _die("creation-holder root identity is invalid")
    qcsd_pid, qcsd_start, qcsd_session, qcsd_group = map(
        _integer, arguments[1:]
    )
    if (
        qcsd_pid <= 1
        or qcsd_start <= 0
        or qcsd_session != qcsd_pid
        or qcsd_group != qcsd_pid
    ):
        _die("creation-holder qcsd identity is invalid")
    operation_match = re.fullmatch(
        r"(run|network|build|transaction)[.]([0-9a-f]{32})", root_name
    )
    assert operation_match is not None
    _, requested_token = operation_match.groups()
    try:
        entries = tuple(os.listdir(base_fd))
    except OSError as error:
        raise RuntimeError("cannot census lifecycle operations") from error
    operation_kinds: dict[str, str] = {}
    patterns = (
        re.compile(r"(run|network|build|transaction)[.]([0-9a-f]{32})"),
        re.compile(
            r"[.]retired[.](run|network|build|transaction)[.]([0-9a-f]{32})"
        ),
        re.compile(
            r"retirement[.](run|network|build|transaction)[.]"
            r"([0-9a-f]{32})(?:[.]next)?"
        ),
    )
    for entry in entries:
        matched = None
        for pattern in patterns:
            matched = pattern.fullmatch(entry)
            if matched is not None:
                break
        if matched is None:
            _die("creation-holder lifecycle namespace is malformed")
        kind, token = matched.group(1), matched.group(2)
        previous = operation_kinds.get(token)
        if previous is not None and previous != kind:
            _die("creation-holder lifecycle token changes kind")
        operation_kinds[token] = kind
    if (
        requested_token in operation_kinds
        or len(operation_kinds) >= MAX_LIFECYCLE_OPERATIONS
    ):
        _die("creation-holder lifecycle operation bound is exhausted")
    try:
        os.mkdir(root_name, 0o700, dir_fd=base_fd)
        os.fsync(base_fd)
        root_fd = os.open(
            root_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=base_fd,
        )
    except OSError as error:
        raise RuntimeError("cannot create bound lifecycle root") from error
    root_value = os.fstat(root_fd)
    root_path = os.stat(root_name, dir_fd=base_fd, follow_symlinks=False)
    root_device, root_inode = root_value.st_dev, root_value.st_ino
    if (
        not stat.S_ISDIR(root_value.st_mode)
        or (root_value.st_uid, stat.S_IMODE(root_value.st_mode)) != (uid, 0o700)
        or (root_path.st_dev, root_path.st_ino) != (root_device, root_inode)
    ):
        os.close(root_fd)
        _die("bound lifecycle root identity changed")
    parent_died = [False]

    def parent_signal(_requested: int, _frame: object) -> None:
        parent_died[0] = True

    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
    previous_handler = signal.getsignal(signal.SIGTERM)
    try:
        signal.signal(signal.SIGTERM, parent_signal)
        if libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        parent_exact = _exact_creation_parent(
            qcsd_pid, qcsd_start, qcsd_session, qcsd_group
        )
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        if not parent_exact:
            parent_died[0] = True
        if not parent_died[0]:
            ready = CREATION_READY.rstrip(b"\n") + (
                f" {root_device} {root_inode}\n".encode("ascii")
            )
            sys.stdout.buffer.write(ready)
            sys.stdout.buffer.flush()
            control = sys.stdin.buffer.readline(
                max(len(CREATION_COMMIT), len(CREATION_CANCEL)) + 1
            )
            extra = sys.stdin.buffer.read(1)
            if (
                control == CREATION_COMMIT
                and extra == b""
                and not parent_died[0]
                and _durable_initial_supervision(
                    base_fd,
                    base,
                    uid,
                    root_name,
                    root_device,
                    root_inode,
                )
                and _exact_creation_parent(
                    qcsd_pid, qcsd_start, qcsd_session, qcsd_group
                )
            ):
                _write_creation_result(CREATION_COMMITTED)
                return
            if (
                control == CREATION_CANCEL
                and extra == b""
                and not parent_died[0]
                and _exact_creation_parent(
                    qcsd_pid, qcsd_start, qcsd_session, qcsd_group
                )
                and _cancel_initial_root(
                    base_fd,
                    root_fd,
                    uid,
                    root_name,
                    root_device,
                    root_inode,
                )
            ):
                _write_creation_result(CREATION_CANCELLED)
                return

        _write_creation_result(CREATION_REJECTED)

        # EOF, malformed control, or parent death is never authority to drop
        # the lease while any initial-root writer can remain.  Retain both
        # guardian descriptors until the exact qcsd and every same-session,
        # same-process-group descendant are absent in two consecutive censuses.
        confirmations = 0
        holder_pid = os.getpid()
        while confirmations < 2:
            parent_present = _exact_creation_parent(
                qcsd_pid, qcsd_start, qcsd_session, qcsd_group
            )
            members = _creation_session_members(
                qcsd_session, qcsd_group, holder_pid
            )
            if not parent_present and members == ():
                confirmations += 1
            else:
                confirmations = 0
            time.sleep(0.01)
        _die("creation-holder control was rejected")
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        signal.signal(signal.SIGTERM, previous_handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        os.close(root_fd)


def _read_process_cmdline(pid: int) -> bytes:
    try:
        payload = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError as error:
        raise RuntimeError("cannot bind API-service wrapper command") from error
    if not payload or not payload.endswith(b"\0") or b"\0\0" in payload:
        raise RuntimeError("API-service wrapper command is malformed")
    return payload


def _api_listener() -> tuple[socket.socket, str]:
    encoded = f"qcsd-api-lease-{os.getuid()}-{os.urandom(16).hex()}"
    listener = socket.socket(
        socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC
    )
    listener.bind("\0" + encoded)
    listener.listen(1)
    listener.setblocking(False)
    return listener, f"@{encoded}"


def _singleton_endpoint(singleton_fd: int) -> str:
    singleton = socket.socket(fileno=singleton_fd)
    try:
        value = singleton.getsockname()
        if (
            singleton.family != socket.AF_UNIX
            or singleton.type & socket.SOCK_STREAM != socket.SOCK_STREAM
            or singleton.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            or not isinstance(value, bytes)
            or not value.startswith(b"\0")
        ):
            raise RuntimeError("API holder singleton identity changed")
        return "@" + value[1:].decode("ascii")
    except UnicodeError as error:
        raise RuntimeError("API holder singleton name is malformed") from error
    finally:
        singleton.detach()


def _validate_api_lease_descriptors(
    descriptors: array.array[int],
    *,
    lock_device: int,
    lock_inode: int,
    singleton_endpoint: str,
) -> tuple[int, int]:
    if len(descriptors) != 2:
        for descriptor in descriptors:
            os.close(descriptor)
        raise RuntimeError("invalid API-service lease descriptor count")
    lock_fd, singleton_fd = descriptors
    try:
        value = os.fstat(lock_fd)
        observed = (
            value.st_dev,
            value.st_ino,
            value.st_uid,
            stat.S_IMODE(value.st_mode),
            value.st_nlink,
            value.st_size,
        )
        if (
            not stat.S_ISREG(value.st_mode)
            or observed
            != (lock_device, lock_inode, os.getuid(), 0o600, 1, 0)
            or os.get_inheritable(lock_fd)
        ):
            raise RuntimeError("API-service lock lease identity changed")
        singleton = socket.socket(fileno=singleton_fd)
        try:
            if (
                singleton.family != socket.AF_UNIX
                or singleton.type & socket.SOCK_STREAM != socket.SOCK_STREAM
                or singleton.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                != 1
                or singleton.getsockname()
                != b"\0" + singleton_endpoint[1:].encode("ascii")
                or singleton.get_inheritable()
            ):
                raise RuntimeError("API-service singleton lease identity changed")
        finally:
            singleton.detach()
    except BaseException:
        os.close(lock_fd)
        os.close(singleton_fd)
        raise
    return lock_fd, singleton_fd


def _api_service_wrapper(arguments: Sequence[str]) -> int:
    if len(arguments) < 9 or arguments[7] != "--":
        _die("API-service wrapper arguments are malformed")
    endpoint, nonce = arguments[0], arguments[1]
    watcher_pid, watcher_start, lock_device, lock_inode = map(
        _integer, arguments[2:6]
    )
    singleton_endpoint = arguments[6]
    command = tuple(arguments[8:])
    if (
        not endpoint.startswith("@")
        or len(endpoint) > 100
        or HEX_64.fullmatch(nonce) is None
        or not singleton_endpoint.startswith("@")
        or not command
        or watcher_pid <= 1
        or watcher_start <= 0
        or _process_start_time(watcher_pid) != watcher_start
        or _process_uid(watcher_pid) != os.getuid()
    ):
        _die("API-service wrapper binding is invalid")
    request = {
        "argv_sha256": _cmdline_sha256(),
        "nonce": nonce,
        "pid": os.getpid(),
        "schema": 1,
        "start_time": _process_start_time(os.getpid()),
        "watcher_pid": watcher_pid,
        "watcher_start_time": watcher_start,
    }
    payload = (
        json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    connection = socket.socket(
        socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC
    )
    descriptors = array.array("i")
    lock_fd = singleton_fd = docker_config_fd = buildx_config_fd = -1
    try:
        connection.settimeout(5.0)
        connection.connect("\0" + endpoint[1:])
        connection.sendall(payload)
        message, ancillary, flags, _ = connection.recvmsg(
            64,
            socket.CMSG_SPACE(4 * descriptors.itemsize),
            socket.MSG_CMSG_CLOEXEC,
        )
        if (
            message != API_LEASE_MESSAGE
            or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)
            or len(ancillary) != 1
            or ancillary[0][0:2] != (socket.SOL_SOCKET, socket.SCM_RIGHTS)
        ):
            raise RuntimeError("invalid API-service lease response")
        rights = ancillary[0][2]
        descriptors.frombytes(
            rights[: len(rights) - len(rights) % descriptors.itemsize]
        )
        if len(descriptors) != 4:
            raise RuntimeError("invalid API-service lease descriptor count")
        lock_fd, singleton_fd = _validate_api_lease_descriptors(
            descriptors[:2],
            lock_device=lock_device,
            lock_inode=lock_inode,
            singleton_endpoint=singleton_endpoint,
        )
        docker_config_fd, buildx_config_fd = descriptors[2:]
        if len({(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in descriptors}) != 4:
            raise RuntimeError("API-service lease descriptors alias")
        for descriptor, expected_mode, expected_links, exact_links, require_empty in (
            (docker_config_fd, DOCKER_CONFIG_MODE, 2, True, True),
            (buildx_config_fd, BUILDX_CONFIG_MODE, 2, False, False),
        ):
            if not _exact_configuration_descriptor(
                descriptor,
                expected_mode=expected_mode,
                expected_links=expected_links,
                exact_links=exact_links,
                require_empty=require_empty,
            ):
                raise RuntimeError("API-service configuration lease changed")
        connection.sendall(API_LEASE_ACK)
    finally:
        connection.close()
    try:
        command_environment = dict(os.environ)
        command_environment["DOCKER_CONFIG"] = f"/proc/self/fd/{docker_config_fd}"
        command_environment["BUILDX_CONFIG"] = f"/proc/self/fd/{buildx_config_fd}"
        result = subprocess.run(
            command,
            close_fds=True,
            pass_fds=(docker_config_fd, buildx_config_fd),
            env=command_environment,
            check=False,
        )
        return result.returncode if result.returncode >= 0 else 128 - result.returncode
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        if singleton_fd >= 0:
            os.close(singleton_fd)
        if docker_config_fd >= 0:
            os.close(docker_config_fd)
        if buildx_config_fd >= 0:
            os.close(buildx_config_fd)


def _exact_configuration_descriptor(
    descriptor: int,
    *,
    expected_mode: int,
    expected_links: int,
    exact_links: bool,
    require_empty: bool,
) -> bool:
    """Validate one Docker/Buildx config descriptor without path fallback."""

    value = os.fstat(descriptor)
    links_match = (
        value.st_nlink == expected_links
        if exact_links
        else value.st_nlink >= expected_links
    )
    return (
        stat.S_ISDIR(value.st_mode)
        and value.st_uid == os.getuid()
        and stat.S_IMODE(value.st_mode) == expected_mode
        and links_match
        and not os.get_inheritable(descriptor)
        and (not require_empty or not os.listdir(descriptor))
    )


def _api_request(payload: bytes) -> dict[str, object]:
    if not payload.endswith(b"\n") or len(payload) > API_REQUEST_LIMIT:
        raise RuntimeError("API-service lease request framing is invalid")
    try:
        text = payload.decode("ascii")
        value = json.loads(text)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError("API-service lease request is malformed") from error
    keys = {
        "argv_sha256",
        "nonce",
        "pid",
        "schema",
        "start_time",
        "watcher_pid",
        "watcher_start_time",
    }
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or text != canonical
        or type(value["schema"]) is not int
        or value["schema"] != 1
        or any(
            type(value[key]) is not int or value[key] <= 0
            for key in ("pid", "start_time", "watcher_pid", "watcher_start_time")
        )
        or not isinstance(value["nonce"], str)
        or HEX_64.fullmatch(value["nonce"]) is None
        or not isinstance(value["argv_sha256"], str)
        or HEX_64.fullmatch(value["argv_sha256"]) is None
    ):
        raise RuntimeError("API-service lease request differs from schema 1")
    return value


def _transfer_api_lease(
    listener: socket.socket,
    *,
    unit: str,
    expected_command: tuple[str, ...],
    nonce: str,
    watcher_pid: int,
    watcher_start: int,
    lease_fd: int,
    singleton_fd: int,
    docker_config_fd: int,
    buildx_config_fd: int,
) -> bool:
    try:
        connection, _ = listener.accept()
    except BlockingIOError:
        return None
    with connection:
        connection.settimeout(1.0)
        credentials = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, 12
        )
        peer_pid = int.from_bytes(credentials[0:4], sys.byteorder, signed=True)
        peer_uid = int.from_bytes(credentials[4:8], sys.byteorder, signed=True)
        blocks: list[bytes] = []
        size = 0
        while True:
            block = connection.recv(API_REQUEST_LIMIT + 1 - size)
            if not block:
                break
            blocks.append(block)
            size += len(block)
            if size > API_REQUEST_LIMIT:
                raise RuntimeError("API-service lease request is oversized")
            if b"\n" in block:
                break
        request = _api_request(b"".join(blocks))
        peer_start = _process_start_time(peer_pid)
        observed_command = _read_process_cmdline(peer_pid)
        expected_payload = b"\0".join(
            value.encode("utf-8") for value in expected_command
        ) + b"\0"
        if (
            peer_uid != os.getuid()
            or type(request["pid"]) is not int
            or request["pid"] != peer_pid
            or type(request["start_time"]) is not int
            or request["start_time"] != peer_start
            or request["watcher_pid"] != watcher_pid
            or request["watcher_start_time"] != watcher_start
            or request["nonce"] != nonce
            or request["argv_sha256"]
            != hashlib.sha256(observed_command).hexdigest()
            or observed_command != expected_payload
        ):
            raise RuntimeError("API-service wrapper identity changed")
        before = _systemd_unit_snapshot(unit)
        if before is None:
            raise RuntimeError("API-service manager identity is unavailable")
        load_state, active_state, control_group, main_pid = before
        expected_control_group = (
            f"/user.slice/user-{os.getuid()}.slice/"
            f"user@{os.getuid()}.service/app.slice/{unit}"
        )
        if (
            load_state != "loaded"
            or active_state not in {"activating", "active"}
            or main_pid != peer_pid
            or control_group != expected_control_group
            or "\0" in control_group
            or any(
                part in {"", ".", ".."}
                for part in control_group.split("/")[1:]
            )
        ):
            raise RuntimeError("API-service wrapper is outside its exact unit")
        try:
            cgroup_lines = Path(f"/proc/{peer_pid}/cgroup").read_text(
                encoding="ascii"
            ).splitlines()
        except (OSError, UnicodeError) as error:
            raise RuntimeError("API-service wrapper cgroup is unavailable") from error
        if cgroup_lines != [f"0::{control_group}"]:
            raise RuntimeError("API-service wrapper cgroup identity changed")
        after = _systemd_unit_snapshot(unit)
        if after != before or _process_start_time(peer_pid) != peer_start:
            raise RuntimeError("API-service wrapper raced manager validation")
        rights = array.array(
            "i", [lease_fd, singleton_fd, docker_config_fd, buildx_config_fd]
        )
        connection.sendmsg(
            [API_LEASE_MESSAGE],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
        )
        acknowledgement = connection.recv(len(API_LEASE_ACK) + 1)
        if acknowledgement != API_LEASE_ACK:
            raise RuntimeError("API-service wrapper did not accept its lease")
    return control_group


def _systemd_unit_snapshot(unit: str) -> tuple[str, str, str, int] | None:
    try:
        result = subprocess.run(
            [
                SYSTEMCTL,
                "--user",
                "show",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=ControlGroup",
                "--property=MainPID",
                "--",
                unit,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=3.0,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            return None
        values[key] = value
    if result.returncode != 0 or set(values) != {
        "LoadState",
        "ActiveState",
        "ControlGroup",
        "MainPID",
    }:
        return None
    try:
        main_pid = _integer(values["MainPID"])
    except SystemExit:
        return None
    return (
        values["LoadState"],
        values["ActiveState"],
        values["ControlGroup"],
        main_pid,
    )


def _cgroup_terminal(control_group: str) -> bool:
    if not control_group:
        return True
    if (
        not control_group.startswith("/")
        or "\0" in control_group
        or any(part in {"", ".", ".."} for part in control_group.split("/")[1:])
    ):
        return False
    root = Path("/sys/fs/cgroup")
    candidate = root.joinpath(*control_group.split("/")[1:])
    try:
        if not candidate.exists():
            return True
        for directory, _, names in os.walk(candidate):
            if "cgroup.procs" not in names:
                return False
            if Path(directory, "cgroup.procs").read_text(encoding="ascii").strip():
                return False
        return True
    except (OSError, UnicodeError):
        return False


def _forever() -> NoReturn:
    while True:
        time.sleep(3600)


def _watch_api_service(
    *,
    unit: str,
    duration: int,
    command: tuple[str, ...],
    native_source_fd: int,
    native_source_hash: str,
    lease_fd: int,
    singleton_fd: int,
    docker_config_fd: int,
    buildx_config_fd: int,
) -> int:
    initial = _systemd_unit_snapshot(unit)
    if initial != ("not-found", "inactive", "", 0):
        return 125
    listener, endpoint = _api_listener()
    nonce = os.urandom(32).hex()
    watcher_pid = os.getpid()
    watcher_start = _process_start_time(watcher_pid)
    singleton_endpoint = _singleton_endpoint(singleton_fd)
    source_path = f"/proc/{watcher_pid}/fd/{native_source_fd}"
    docker_config_path = f"/proc/{watcher_pid}/fd/{docker_config_fd}"
    buildx_config_path = f"/proc/{watcher_pid}/fd/{buildx_config_fd}"
    wrapper = (
        "/usr/bin/python3",
        "-I",
        source_path,
        "--api-service-wrapper",
        endpoint,
        nonce,
        str(watcher_pid),
        str(watcher_start),
        str(os.fstat(lease_fd).st_dev),
        str(os.fstat(lease_fd).st_ino),
        singleton_endpoint,
        "--",
        *command,
    )
    environment_arguments = tuple(
        f"--setenv={name}"
        for name in sorted(os.environ)
        if name not in {"DOCKER_CONFIG", "BUILDX_CONFIG"}
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
        and not name.startswith("QCSD_DOCKER_LOCK_GUARDIAN_")
        and not name.startswith("_QCSD_")
    ) + (
        f"--setenv=DOCKER_CONFIG={docker_config_path}",
        f"--setenv=BUILDX_CONFIG={buildx_config_path}",
    )
    launch = (
        TIMEOUT,
        "--signal=KILL",
        "--kill-after=1",
        f"{duration + 3}s",
        SYSTEMD_RUN,
        "--user",
        "--wait",
        "--pipe",
        "--collect",
        "--quiet",
        "--same-dir",
        "--expand-environment=no",
        "--service-type=exec",
        f"--unit={unit}",
        "--property=ExitType=cgroup",
        "--property=KillMode=control-group",
        "--property=KillSignal=SIGKILL",
        "--property=TimeoutStopSec=1s",
        f"--property=RuntimeMaxSec={duration}s",
        *environment_arguments,
        "--",
        *wrapper,
    )

    def reset_child_signals() -> None:
        signal.pthread_sigmask(signal.SIG_SETMASK, set())
        for requested in (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM):
            signal.signal(requested, signal.SIG_DFL)

    try:
        launcher = subprocess.Popen(
            launch,
            close_fds=True,
            preexec_fn=reset_child_signals,
        )
    except OSError:
        listener.close()
        return 125
    transferred = False
    control_group = ""
    try:
        while not transferred:
            readable, _, _ = select.select((listener,), (), (), 0.05)
            if readable:
                try:
                    transferred_control_group = _transfer_api_lease(
                        listener,
                        unit=unit,
                        expected_command=wrapper,
                        nonce=nonce,
                        watcher_pid=watcher_pid,
                        watcher_start=watcher_start,
                        lease_fd=lease_fd,
                        singleton_fd=singleton_fd,
                        docker_config_fd=docker_config_fd,
                        buildx_config_fd=buildx_config_fd,
                    )
                    if transferred_control_group is not None:
                        if (
                            control_group
                            and control_group != transferred_control_group
                        ):
                            _forever()
                        control_group = transferred_control_group
                        transferred = True
                except RuntimeError as error:
                    # A malformed or racing peer is not authority to release.
                    print(
                        f"qcsd-lab API-service lease rejected: {error}",
                        file=sys.stderr,
                    )
                    continue
            snapshot = _systemd_unit_snapshot(unit)
            if snapshot is not None and snapshot[2]:
                if control_group and control_group != snapshot[2]:
                    _forever()
                control_group = snapshot[2]
            returncode = launcher.poll()
            # A short service can finish after its authenticated transfer but
            # before this same scheduler turn reaches poll().  Once authority
            # moved, completion belongs to the post-transfer path below.
            if (
                not transferred
                and returncode is not None
                and 0 <= returncode < 128
                and returncode != 124
            ):
                confirmations = 0
                while confirmations < 2:
                    terminal = _systemd_unit_snapshot(unit)
                    if (
                        terminal == ("not-found", "inactive", "", 0)
                        and _cgroup_terminal(control_group)
                    ):
                        confirmations += 1
                    else:
                        confirmations = 0
                    time.sleep(0.05)
                return 125
        while launcher.poll() is None:
            snapshot = _systemd_unit_snapshot(unit)
            if snapshot is not None and snapshot[2]:
                if control_group and control_group != snapshot[2]:
                    _forever()
                control_group = snapshot[2]
            time.sleep(0.05)
        confirmations = 0
        while confirmations < 2:
            snapshot = _systemd_unit_snapshot(unit)
            if (
                snapshot == ("not-found", "inactive", "", 0)
                and _cgroup_terminal(control_group)
            ):
                confirmations += 1
            else:
                confirmations = 0
            time.sleep(0.05)
        returncode = launcher.returncode
        return returncode if returncode is not None and returncode >= 0 else 125
    finally:
        listener.close()


def _hold_api_service(
    lease_fd: int,
    singleton_fd: int,
    docker_config_fd: int,
    buildx_config_fd: int,
    arguments: Sequence[str],
) -> int:
    if len(arguments) < 9 or arguments[7] != "--":
        _die("API-service holder arguments are malformed")
    unit, duration_value = arguments[0], arguments[1]
    qcsd_pid, qcsd_start, qcsd_session, qcsd_group = map(
        _integer, arguments[2:6]
    )
    native_source_hash = arguments[6]
    command = tuple(arguments[8:])
    duration = _integer(duration_value)
    if (
        re.fullmatch(r"qcsd-docker-api-[0-9a-f]{32}[.]service", unit) is None
        or duration <= 0
        or duration > 86400
        or HEX_64.fullmatch(native_source_hash) is None
        or not command
        or docker_config_fd < 0
        or buildx_config_fd < 0
        or qcsd_pid <= 1
        or qcsd_start <= 0
        or qcsd_session != qcsd_pid
        or qcsd_group != qcsd_pid
        or not _exact_qcsd_ancestor(
            qcsd_pid, qcsd_start, qcsd_session, qcsd_group
        )
    ):
        _die("API-service holder binding is invalid")
    native_source_fd = os.open(
        __file__, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        source_value = os.fstat(native_source_fd)
        if (
            not stat.S_ISREG(source_value.st_mode)
            or source_value.st_uid != os.getuid()
            or _fd_sha256(native_source_fd) != native_source_hash
        ):
            _die("API-service native source identity changed")
        previous_mask = signal.pthread_sigmask(
            signal.SIG_BLOCK,
            {signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM},
        )
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        watcher = os.fork()
        if watcher == 0:
            os.close(read_fd)
            try:
                os.setsid()
                result = _watch_api_service(
                    unit=unit,
                    duration=duration,
                    command=command,
                    native_source_fd=native_source_fd,
                    native_source_hash=native_source_hash,
                    lease_fd=lease_fd,
                    singleton_fd=singleton_fd,
                    docker_config_fd=docker_config_fd,
                    buildx_config_fd=buildx_config_fd,
                )
                try:
                    os.write(write_fd, f"{result}\n".encode("ascii"))
                except BrokenPipeError:
                    # Terminal launcher/unit/cgroup proof has already completed;
                    # a dead qcsd-side reader is no longer a reason to retain.
                    pass
                os.close(write_fd)
                os._exit(0)
            except BaseException:
                _forever()
        os.close(write_fd)
        try:
            _, status = os.waitpid(watcher, 0)
            payload = os.read(read_fd, 32)
        except BaseException:
            _forever()
        finally:
            os.close(read_fd)
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            _forever()
        try:
            text = payload.decode("ascii")
        except UnicodeError:
            _forever()
        if re.fullmatch(r"(?:0|[1-9][0-9]*)\n", text) is None:
            _forever()
        result = int(text)
        if result > 255:
            _forever()
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        return result
    finally:
        os.close(native_source_fd)


def _cmdline_sha256() -> str:
    try:
        payload = Path("/proc/self/cmdline").read_bytes()
    except OSError as error:
        raise SystemExit("cannot bind native requester command line") from error
    if not payload or not payload.endswith(b"\0") or b"\0\0" in payload:
        _die("native requester command line is malformed")
    return hashlib.sha256(payload).hexdigest()


def _fd_sha256(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        block = os.read(fd, 65536)
        if not block:
            return digest.hexdigest()
        digest.update(block)


def _open_dir(path: str) -> int:
    return os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )


def _exact_dir(fd: int, uid: int, device: int, inode: int) -> bool:
    value = os.fstat(fd)
    return (
        stat.S_ISDIR(value.st_mode)
        and value.st_uid == uid
        and stat.S_IMODE(value.st_mode) == 0o700
        and value.st_dev == device
        and value.st_ino == inode
    )


def _root_manifest_sha256(root_fd: int) -> str:
    root = os.fstat(root_fd)
    if not stat.S_ISDIR(root.st_mode):
        _die("retirement manifest root is not a directory")
    digest = hashlib.sha256()
    digest.update(
        f".\t{root.st_dev}:{root.st_ino}:{root.st_uid}:"
        f"{stat.S_IMODE(root.st_mode):o}:directory\tdirectory\n".encode("ascii")
    )
    for name in sorted(os.listdir(root_fd)):
        _safe_name(name)
        value = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if stat.S_ISREG(value.st_mode):
            kind = "regular file" if value.st_size else "regular empty file"
            child_fd = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
            try:
                child_hash = _fd_sha256(child_fd)
            finally:
                os.close(child_fd)
        elif stat.S_ISFIFO(value.st_mode):
            kind = "fifo"
            child_hash = "non-regular"
        else:
            _die("retirement manifest child type is unsupported")
        metadata = (
            f"{value.st_dev}:{value.st_ino}:{value.st_uid}:"
            f"{stat.S_IMODE(value.st_mode):o}:{value.st_nlink}:"
            f"{value.st_size}:{kind}"
        )
        digest.update(f"{name}\t{metadata}\t{child_hash}\n".encode("ascii"))
    return digest.hexdigest()


def _acquire_lease(
    values: Sequence[str],
) -> tuple[int, int, int, int, tuple[str, ...]]:
    if not values or values[0] != "--lease":
        return -1, -1, -1, -1, tuple(values)
    if len(values) < 9:
        _die("incomplete lifecycle lease binding")
    endpoint, nonce = values[1], values[2]
    qcsd_pid, qcsd_start = _integer(values[3]), _integer(values[4])
    helper_hash = values[5]
    lock_device, lock_inode = _integer(values[6]), _integer(values[7])
    operation = tuple(values[8:])
    if (
        not endpoint.startswith("@")
        or len(endpoint) > 255
        or HEX_64.fullmatch(nonce) is None
        or HEX_64.fullmatch(helper_hash) is None
        or not operation
    ):
        _die("invalid lifecycle lease binding")
    requester_pid = os.getpid()
    request = {
        "action": operation[0],
        "argv_sha256": _cmdline_sha256(),
        "helper_source_sha256": helper_hash,
        "lease_nonce": nonce,
        "qcsd_pid": qcsd_pid,
        "qcsd_start_time": qcsd_start,
        "requester_pid": requester_pid,
        "requester_start_time": _process_start_time(requester_pid),
        "schema": 1,
    }
    payload = (
        json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    connection = socket.socket(
        socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC
    )
    try:
        connection.connect("\0" + endpoint[1:])
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        descriptors = array.array("i")
        message, ancillary, flags, _ = connection.recvmsg(
            64,
            socket.CMSG_SPACE(4 * descriptors.itemsize),
            socket.MSG_CMSG_CLOEXEC,
        )
    finally:
        connection.close()
    if (
        message != LEASE_MESSAGE
        or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)
        or len(ancillary) != 1
        or ancillary[0][0:2] != (socket.SOL_SOCKET, socket.SCM_RIGHTS)
    ):
        _die("invalid lifecycle lease response")
    rights = ancillary[0][2]
    descriptors.frombytes(
        rights[: len(rights) - len(rights) % descriptors.itemsize]
    )
    expected_descriptor_count = 4 if operation[0] == "hold-api-service" else 2
    if len(descriptors) != expected_descriptor_count:
        for descriptor in descriptors:
            os.close(descriptor)
        _die("invalid lifecycle lease descriptor count")
    descriptor, singleton_descriptor = descriptors[:2]
    docker_config_descriptor = buildx_config_descriptor = -1
    if expected_descriptor_count == 4:
        docker_config_descriptor, buildx_config_descriptor = descriptors[2:]
        if len(
            {(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in descriptors}
        ) != 4:
            for received in descriptors:
                os.close(received)
            _die("lifecycle lease descriptors alias")
    value = os.fstat(descriptor)
    expected = (lock_device, lock_inode, os.getuid(), 0o600, 1, 0)
    observed = (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        stat.S_IMODE(value.st_mode),
        value.st_nlink,
        value.st_size,
    )
    if (
        not stat.S_ISREG(value.st_mode)
        or observed != expected
        or os.get_inheritable(descriptor)
    ):
        os.close(descriptor)
        os.close(singleton_descriptor)
        _die("lifecycle lease identity changed")
    singleton = socket.socket(fileno=singleton_descriptor)
    try:
        if (
            singleton.family != socket.AF_UNIX
            or singleton.type & socket.SOCK_STREAM != socket.SOCK_STREAM
            or singleton.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            or singleton.getsockname()
            != b"\0" + endpoint[1:].encode("ascii")
            or singleton.get_inheritable()
        ):
            _die("lifecycle singleton lease identity changed")
    except BaseException:
        singleton.close()
        os.close(descriptor)
        raise
    singleton.detach()
    for config_descriptor, expected_mode, expected_links, exact_links, require_empty in (
        (docker_config_descriptor, DOCKER_CONFIG_MODE, 2, True, True),
        (buildx_config_descriptor, BUILDX_CONFIG_MODE, 2, False, False),
    ):
        if config_descriptor < 0:
            continue
        if not _exact_configuration_descriptor(
            config_descriptor,
            expected_mode=expected_mode,
            expected_links=expected_links,
            exact_links=exact_links,
            require_empty=require_empty,
        ):
            for received in descriptors:
                os.close(received)
            _die("lifecycle configuration lease identity changed")
    return (
        descriptor,
        singleton_descriptor,
        docker_config_descriptor,
        buildx_config_descriptor,
        operation,
    )


def _verify_authority(
    base_fd: int, uid: int, arguments: Sequence[str]
) -> tuple[str, ...]:
    if not arguments or arguments[0] != "--authority" or len(arguments) < 6:
        _die("incomplete retirement authority binding")
    name = _safe_name(arguments[1])
    device, inode, size = map(_integer, arguments[2:5])
    expected_hash = arguments[5]
    if HEX_64.fullmatch(expected_hash) is None:
        _die("invalid retirement authority hash")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=base_fd)
    try:
        value = os.fstat(fd)
        path_value = os.stat(name, dir_fd=base_fd, follow_symlinks=False)
        wanted = (device, inode, uid, 0o600, 1, size)
        for observed in (value, path_value):
            actual = (
                observed.st_dev,
                observed.st_ino,
                observed.st_uid,
                stat.S_IMODE(observed.st_mode),
                observed.st_nlink,
                observed.st_size,
            )
            if not stat.S_ISREG(observed.st_mode) or actual != wanted:
                _die("retirement authority identity changed")
        if _fd_sha256(fd) != expected_hash:
            _die("retirement authority content changed")
        current = os.stat(name, dir_fd=base_fd, follow_symlinks=False)
        if current.st_dev != device or current.st_ino != inode:
            _die("retirement authority path changed")
    finally:
        os.close(fd)
    return tuple(arguments[6:])


def _validate_operation_shape(operation: Sequence[str]) -> None:
    if len(operation) < 5 or operation[0] not in {
        "publish",
        "hold-creation",
        "hold-api-service",
        "promote-authority",
        "rename-root",
        "unlink",
        "rmdir",
        "unlink-authority",
    }:
        _die("unknown retirement native action")
    action = operation[0]
    expected: int | None = {
        "publish": 7,
        "hold-creation": 10,
        "hold-api-service": None,
        "promote-authority": 15,
        "rename-root": 15,
        "unlink": 21,
        "rmdir": 14,
        "unlink-authority": 10,
    }[action]
    if action == "hold-api-service":
        if len(operation) < 14 or operation[12] != "--" or not operation[13:]:
            _die("retirement native action has an invalid argument count")
    elif len(operation) != expected:
        _die("retirement native action has an invalid argument count")
    if action in {"rename-root", "unlink", "rmdir"} and operation[5] != "--authority":
        _die("retirement native action lacks authority")
    if (
        action in {
            "publish",
            "hold-creation",
            "promote-authority",
            "unlink-authority",
        }
        and "--authority" in operation[5:]
    ):
        _die("retirement native action has unexpected authority")


def _run(values: Sequence[str], *, require_lease: bool) -> int:
    lease_fd, singleton_fd, docker_config_fd, buildx_config_fd, operation = (
        _acquire_lease(values)
    )
    try:
        _validate_operation_shape(operation)
        action, base = operation[0], operation[1]
        uid, base_device, base_inode = map(_integer, operation[2:5])
        if require_lease and (lease_fd < 0 or singleton_fd < 0):
            _die("lifecycle mutation requires authenticated guardian lease")
        base_fd = _open_dir(base)
        try:
            if not _exact_dir(base_fd, uid, base_device, base_inode):
                _die("retirement base identity changed")
            arguments = tuple(operation[5:])
            if action in {"rename-root", "unlink", "rmdir"}:
                arguments = _verify_authority(base_fd, uid, arguments)
            if action == "hold-creation":
                _hold_creation(base_fd, base, uid, arguments)
            elif action == "hold-api-service":
                return _hold_api_service(
                    lease_fd,
                    singleton_fd,
                    docker_config_fd,
                    buildx_config_fd,
                    arguments,
                )
            elif action == "publish":
                staged, final = map(_safe_name, arguments)
                payload = sys.stdin.buffer.read(MAX_AUTHORITY_BYTES + 1)
                if len(payload) > MAX_AUTHORITY_BYTES:
                    _die("retirement authority exceeds size bound")
                fd = os.open(
                    staged,
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    0o600,
                    dir_fd=base_fd,
                )
                try:
                    view = memoryview(payload)
                    while view:
                        written = os.write(fd, view)
                        if written <= 0:
                            _die("short retirement authority write")
                        view = view[written:]
                    os.fsync(fd)
                    created = os.fstat(fd)
                    staged_path = os.stat(
                        staged, dir_fd=base_fd, follow_symlinks=False
                    )
                    if (
                        created.st_dev,
                        created.st_ino,
                        created.st_uid,
                        stat.S_IMODE(created.st_mode),
                        created.st_nlink,
                        created.st_size,
                    ) != (
                        staged_path.st_dev,
                        staged_path.st_ino,
                        uid,
                        0o600,
                        1,
                        len(payload),
                    ) or _fd_sha256(fd) != hashlib.sha256(payload).hexdigest():
                        _die("fresh retirement authority changed before publication")
                    if renameat2(
                        base_fd,
                        os.fsencode(staged),
                        base_fd,
                        os.fsencode(final),
                        RENAME_NOREPLACE,
                    ) != 0:
                        error = ctypes.get_errno()
                        raise OSError(error, os.strerror(error))
                    os.fsync(base_fd)
                    final_path = os.stat(
                        final, dir_fd=base_fd, follow_symlinks=False
                    )
                    if (
                        final_path.st_dev,
                        final_path.st_ino,
                        final_path.st_uid,
                        stat.S_IMODE(final_path.st_mode),
                        final_path.st_nlink,
                        final_path.st_size,
                    ) != (
                        created.st_dev,
                        created.st_ino,
                        uid,
                        0o600,
                        1,
                        len(payload),
                    ) or _fd_sha256(fd) != hashlib.sha256(payload).hexdigest():
                        _die("fresh retirement authority changed across publication")
                    try:
                        os.stat(staged, dir_fd=base_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        _die("staged retirement authority remains after publication")
                finally:
                    os.close(fd)
            elif action == "promote-authority":
                staged, final = map(_safe_name, arguments[:2])
                staged_device, staged_inode, staged_size = map(
                    _integer, arguments[2:5]
                )
                staged_hash = arguments[5]
                active = _safe_name(arguments[6])
                root_device, root_inode = map(_integer, arguments[7:9])
                root_manifest = arguments[9]
                if (
                    staged != f"{final}.next"
                    or HEX_64.fullmatch(staged_hash) is None
                    or HEX_64.fullmatch(root_manifest) is None
                ):
                    _die("staged retirement authority binding is invalid")
                staged_fd = os.open(
                    staged,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=base_fd,
                )
                root_fd = os.open(
                    active,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=base_fd,
                )
                try:
                    staged_value = os.fstat(staged_fd)
                    staged_path = os.stat(
                        staged, dir_fd=base_fd, follow_symlinks=False
                    )
                    wanted = (
                        staged_device,
                        staged_inode,
                        uid,
                        0o600,
                        1,
                        staged_size,
                    )
                    for observed in (staged_value, staged_path):
                        actual = (
                            observed.st_dev,
                            observed.st_ino,
                            observed.st_uid,
                            stat.S_IMODE(observed.st_mode),
                            observed.st_nlink,
                            observed.st_size,
                        )
                        if not stat.S_ISREG(observed.st_mode) or actual != wanted:
                            _die("staged retirement authority identity changed")
                    if _fd_sha256(staged_fd) != staged_hash:
                        _die("staged retirement authority content changed")
                    if (
                        not _exact_dir(root_fd, uid, root_device, root_inode)
                        or _root_manifest_sha256(root_fd) != root_manifest
                    ):
                        _die(
                            "active retirement root changed before authority promotion"
                        )
                    os.fsync(staged_fd)
                    staged_current = os.stat(
                        staged, dir_fd=base_fd, follow_symlinks=False
                    )
                    active_current = os.stat(
                        active, dir_fd=base_fd, follow_symlinks=False
                    )
                    if (staged_current.st_dev, staged_current.st_ino) != (
                        staged_device,
                        staged_inode,
                    ) or (active_current.st_dev, active_current.st_ino) != (
                        root_device,
                        root_inode,
                    ):
                        _die("retirement promotion names changed before rename")
                    if renameat2(
                        base_fd,
                        os.fsencode(staged),
                        base_fd,
                        os.fsencode(final),
                        RENAME_NOREPLACE,
                    ) != 0:
                        error = ctypes.get_errno()
                        raise OSError(error, os.strerror(error))
                    os.fsync(base_fd)
                    final_value = os.stat(
                        final, dir_fd=base_fd, follow_symlinks=False
                    )
                    active_value = os.stat(
                        active, dir_fd=base_fd, follow_symlinks=False
                    )
                    if (
                        final_value.st_dev,
                        final_value.st_ino,
                        final_value.st_uid,
                        stat.S_IMODE(final_value.st_mode),
                        final_value.st_nlink,
                        final_value.st_size,
                    ) != wanted or _fd_sha256(staged_fd) != staged_hash:
                        _die("retirement authority changed across promotion")
                    if (active_value.st_dev, active_value.st_ino) != (
                        root_device,
                        root_inode,
                    ):
                        _die("active retirement root path changed across promotion")
                    if (
                        not _exact_dir(root_fd, uid, root_device, root_inode)
                        or _root_manifest_sha256(root_fd) != root_manifest
                    ):
                        _die(
                            "active retirement root changed across authority promotion"
                        )
                finally:
                    os.close(root_fd)
                    os.close(staged_fd)
            elif action == "rename-root":
                source, target = map(_safe_name, arguments[:2])
                root_device, root_inode = map(_integer, arguments[2:])
                root_fd = os.open(
                    source,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=base_fd,
                )
                try:
                    if not _exact_dir(root_fd, uid, root_device, root_inode):
                        _die("retirement source identity changed")
                    before = os.stat(source, dir_fd=base_fd, follow_symlinks=False)
                    if (before.st_dev, before.st_ino) != (root_device, root_inode):
                        _die("retirement source path changed")
                    if renameat2(
                        base_fd,
                        os.fsencode(source),
                        base_fd,
                        os.fsencode(target),
                        RENAME_NOREPLACE,
                    ) != 0:
                        error = ctypes.get_errno()
                        raise OSError(error, os.strerror(error))
                    os.fsync(base_fd)
                    if not _exact_dir(root_fd, uid, root_device, root_inode):
                        _die("retirement source changed across rename")
                    after = os.stat(target, dir_fd=base_fd, follow_symlinks=False)
                    if (after.st_dev, after.st_ino) != (root_device, root_inode):
                        _die("retirement target path changed")
                    try:
                        os.stat(source, dir_fd=base_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        _die("retirement source still exists after rename")
                finally:
                    os.close(root_fd)
            elif action == "unlink":
                directory, child = map(_safe_name, arguments[:2])
                root_device, root_inode, child_device, child_inode = map(
                    _integer, arguments[2:6]
                )
                if re.fullmatch(r"[0-7]{3,4}", arguments[6]) is None:
                    _die("invalid retirement child mode")
                child_mode = int(arguments[6], 8)
                child_links, child_size = map(_integer, arguments[7:9])
                expected_hash = arguments[9]
                if HEX_64.fullmatch(expected_hash) is None and expected_hash != "fifo":
                    _die("invalid retirement child digest")
                directory_fd = os.open(
                    directory,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=base_fd,
                )
                try:
                    if not _exact_dir(directory_fd, uid, root_device, root_inode):
                        _die("retirement directory identity changed")
                    value = os.stat(child, dir_fd=directory_fd, follow_symlinks=False)
                    observed = (
                        value.st_dev,
                        value.st_ino,
                        value.st_uid,
                        stat.S_IMODE(value.st_mode),
                        value.st_nlink,
                        value.st_size,
                    )
                    expected = (
                        child_device,
                        child_inode,
                        uid,
                        child_mode,
                        child_links,
                        child_size,
                    )
                    if observed != expected:
                        _die("retirement child identity changed")
                    if stat.S_ISREG(value.st_mode):
                        fd = os.open(
                            child,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory_fd,
                        )
                        try:
                            opened = os.fstat(fd)
                            if (opened.st_dev, opened.st_ino) != (
                                child_device,
                                child_inode,
                            ):
                                _die("retirement child changed before hashing")
                            digest = _fd_sha256(fd)
                        finally:
                            os.close(fd)
                        if digest != expected_hash:
                            _die("retirement child content changed")
                    elif not stat.S_ISFIFO(value.st_mode) or expected_hash != "fifo":
                        _die("unsupported retirement child type")
                    current = os.stat(child, dir_fd=directory_fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) != (child_device, child_inode):
                        _die("retirement child changed before unlink")
                    os.unlink(child, dir_fd=directory_fd)
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            elif action == "rmdir":
                directory = _safe_name(arguments[0])
                root_device, root_inode = map(_integer, arguments[1:])
                directory_fd = os.open(
                    directory,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=base_fd,
                )
                try:
                    if not _exact_dir(directory_fd, uid, root_device, root_inode):
                        _die("retirement directory identity changed")
                    current = os.stat(directory, dir_fd=base_fd, follow_symlinks=False)
                    if (current.st_dev, current.st_ino) != (root_device, root_inode):
                        _die("retirement directory path changed")
                    os.rmdir(directory, dir_fd=base_fd)
                    os.fsync(base_fd)
                finally:
                    os.close(directory_fd)
            elif action == "unlink-authority":
                authority = _safe_name(arguments[0])
                auth_device, auth_inode, auth_size = map(_integer, arguments[1:4])
                auth_hash = arguments[4]
                if HEX_64.fullmatch(auth_hash) is None:
                    _die("invalid retirement authority hash")
                value = os.stat(authority, dir_fd=base_fd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(value.st_mode)
                    or value.st_dev != auth_device
                    or value.st_ino != auth_inode
                    or value.st_uid != uid
                    or stat.S_IMODE(value.st_mode) != 0o600
                    or value.st_nlink != 1
                    or value.st_size != auth_size
                ):
                    _die("retirement authority identity changed")
                fd = os.open(
                    authority,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=base_fd,
                )
                try:
                    digest = _fd_sha256(fd)
                finally:
                    os.close(fd)
                if digest != auth_hash:
                    _die("retirement authority content changed")
                current = os.stat(authority, dir_fd=base_fd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(current.st_mode)
                    or current.st_dev != auth_device
                    or current.st_ino != auth_inode
                    or current.st_uid != uid
                    or stat.S_IMODE(current.st_mode) != 0o600
                    or current.st_nlink != 1
                    or current.st_size != auth_size
                ):
                    _die("retirement authority changed before unlink")
                os.unlink(authority, dir_fd=base_fd)
                os.fsync(base_fd)
        finally:
            os.close(base_fd)
    finally:
        if lease_fd >= 0:
            os.close(lease_fd)
        if singleton_fd >= 0:
            os.close(singleton_fd)
        if docker_config_fd >= 0:
            os.close(docker_config_fd)
        if buildx_config_fd >= 0:
            os.close(buildx_config_fd)
    return 0


def main(arguments: Sequence[str] | None = None) -> int:
    values = tuple(sys.argv[1:] if arguments is None else arguments)
    if values and values[0] == "--api-service-wrapper":
        try:
            return _api_service_wrapper(values[1:])
        except (OSError, RuntimeError, ValueError) as error:
            print(f"qcsd-lab lifecycle native: {error}", file=sys.stderr)
            return 125
    try:
        return _run(values, require_lease=True)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"qcsd-lab lifecycle native: {error}", file=sys.stderr)
        return 1
    return 0


def run_unleased_for_test(arguments: Sequence[str]) -> None:
    """Exercise dirfd primitives without exposing an unleased CLI operation."""

    _run(tuple(arguments), require_lease=False)


if __name__ == "__main__":
    raise SystemExit(main())
