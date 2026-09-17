"""Fresh Engine identity reads inside the existing leased API boundary.

These tests use private Unix sockets and stub CLI invocations, never Docker.
The supervisor's outer request deadline remains authoritative; the native
socket timeout is not permission to extend that deadline.
"""

from __future__ import annotations

import array
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
from types import ModuleType
from typing import Iterator

import pytest


NATIVE = Path(__file__).resolve().parents[1] / "tools/docker_lifecycle_native.py"
DAEMON_ID = "01234567-89ab-cdef-0123-456789abcdef"
OTHER_ID = "12345678-1234-1234-1234-123456789abc"
NPIPE = "npipe:////./pipe/dockerDesktopLinuxEngine"
OVERRIDE_VARIABLES = (
    "DOCKER_CONTEXT", "DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
)


@pytest.fixture
def native() -> Iterator[ModuleType]:
    name = f"qcsd_daemon_identity_test_{os.urandom(8).hex()}"
    spec = importlib.util.spec_from_file_location(name, NATIVE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.modules.pop(name, None)


def _response(
    body: bytes,
    *,
    status: bytes = b"200 OK",
    headers: tuple[bytes, ...] = (),
    content_length: bool = True,
) -> bytes:
    framing = (f"Content-Length: {len(body)}".encode("ascii"),) if content_length else ()
    return b"\r\n".join((b"HTTP/1.1 " + status, *framing, *headers, b"", body))


def _info(identifier: str = DAEMON_ID) -> bytes:
    return json.dumps({"ID": identifier, "Containers": 3}).encode("utf-8")


@contextmanager
def _unix_engine(*responses: bytes) -> Iterator[tuple[str, list[bytes]]]:
    # Keep AF_UNIX paths short even when pytest's working directory is long.
    with tempfile.TemporaryDirectory(prefix="qcsd-id-") as directory:
        path = str(Path(directory) / "engine.sock")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(1)
        listener.settimeout(2)
        requests: list[bytes] = []
        failures: list[BaseException] = []

        def serve() -> None:
            try:
                for response in responses:
                    with listener.accept()[0] as connection:
                        connection.settimeout(2)
                        request = b""
                        while b"\r\n\r\n" not in request:
                            piece = connection.recv(4096)
                            if not piece:
                                raise AssertionError("identity client closed before request")
                            request += piece
                            assert len(request) <= 16384
                        requests.append(request)
                        try:
                            connection.sendall(response)
                        except (BrokenPipeError, ConnectionResetError):
                            # A deliberate malformed response may be rejected early.
                            pass
            except BaseException as error:
                failures.append(error)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            yield "unix://" + path, requests
        finally:
            worker.join(timeout=3)
            listener.close()
            assert not worker.is_alive(), "private identity server did not retire"
            assert not failures, failures


def _forbid_cli(*args: object, **kwargs: object) -> None:
    pytest.fail("Unix Engine identity must not launch a Docker CLI subprocess")


@pytest.mark.parametrize("content_type", [None, b"application/json", b"application/json; charset=utf-8"])
def test_unix_engine_reads_exact_id_without_cli(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch, content_type: bytes | None,
) -> None:
    monkeypatch.setattr(native.subprocess, "run", _forbid_cli)
    headers = () if content_type is None else (b"Content-Type: " + content_type,)
    with _unix_engine(_response(_info(), headers=headers)) as (host, requests):
        assert native._docker_daemon_id(host) == DAEMON_ID
    assert len(requests) == 1
    assert requests[0].split(b"\r\n", 1)[0] == b"GET /info HTTP/1.1"
    assert requests[0].endswith(b"\r\n\r\n")


def test_unix_engine_never_caches_identity(native: ModuleType) -> None:
    with _unix_engine(_response(_info()), _response(_info(OTHER_ID))) as (host, requests):
        assert native._docker_daemon_id(host) == DAEMON_ID
        assert native._docker_daemon_id(host) == OTHER_ID
    assert len(requests) == 2


def test_unix_engine_accepts_valid_chunked_json(native: ModuleType) -> None:
    body = _info()
    pieces = (body[:7], body[7:])
    chunked = b"".join(f"{len(piece):x}\r\n".encode() + piece + b"\r\n" for piece in pieces)
    chunked += b"0\r\n\r\n"
    wire = _response(chunked, headers=(b"Transfer-Encoding: chunked",), content_length=False)
    with _unix_engine(wire) as (host, _):
        assert native._docker_daemon_id(host) == DAEMON_ID


@pytest.mark.parametrize("body", [
    b"", b"{", b"null", b"[]", b"true", b'"daemon-id"', b"{}",
    b'{"id":"wrong-case"}', b'{"ID":null}', b'{"ID":42}', b'{"ID":true}',
    b'{"ID":[]}', b'{"ID":{}}', b'{"ID":""}', b'{"ID":"unavailable"}',
    b'{"ID":"has space"}', b'{"ID":"line\\nbreak"}', b'{"ID":"slash/id"}',
    b'{"ID":"nul\\u0000byte"}', b'{"ID":"\\u00e9"}', b'{"ID":"\xff"}',
    b'{"ID":"first","ID":"second"}',
    b'{"ID":"first","Containers":1,"Containers":2}',
    b'{"ID":"first","nested":{"field":1,"field":2}}',
    b'{"ID":"first","Containers":NaN}',
    b'{"ID":"first","Containers":Infinity}',
    b'{"ID":"first"}{"ID":"second"}',
])
def test_unix_engine_rejects_invalid_json_or_identity(native: ModuleType, body: bytes) -> None:
    with _unix_engine(_response(body)) as (host, _):
        with pytest.raises((RuntimeError, OSError)):
            native._docker_daemon_id(host)


@pytest.mark.parametrize("wire", [
    _response(_info(), status=b"404 Not Found"),
    _response(_info(), status=b"500 Internal Server Error"),
    _response(_info(), status=b"302 Found", headers=(b"Location: http://localhost/info",)),
    _response(_info(), headers=(b"Content-Type: text/html",)),
    _response(_info(), headers=(b"Content-Encoding: gzip",)),
    _response(_info(), headers=(b"Content-Length: 1",)),
    _response(_info(), headers=(b"Transfer-Encoding: chunked",)),
    _response(_info(), headers=(b"Transfer-Encoding: gzip",), content_length=False),
    _response(_info(), headers=(b"Transfer-Encoding: chunked", b"Transfer-Encoding: chunked"), content_length=False),
    _response(_info(), headers=(b"Content-Length: -1",), content_length=False),
    _response(_info(), headers=(b"Content-Length: invalid",), content_length=False),
    _response(_info(), headers=(b"Content-Length: 999",), content_length=False),
    _response(b"7\r\n{}\r\n", headers=(b"Transfer-Encoding: chunked",), content_length=False),
    b"not HTTP\r\n\r\n{}",
])
def test_unix_engine_rejects_response_and_framing_failures(native: ModuleType, wire: bytes) -> None:
    with _unix_engine(wire) as (host, _):
        with pytest.raises((RuntimeError, OSError)):
            native._docker_daemon_id(host)


@pytest.mark.parametrize("framing", ["length", "chunked", "eof"])
def test_unix_engine_rejects_oversize_body(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch, framing: str,
) -> None:
    monkeypatch.setattr(native, "DOCKER_INFO_MAX_BYTES", 128)
    body = json.dumps({"ID": DAEMON_ID, "padding": "x" * 200}).encode()
    if framing == "chunked":
        payload = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
        wire = _response(payload, headers=(b"Transfer-Encoding: chunked",), content_length=False)
    else:
        wire = _response(body, content_length=framing == "length")
    with _unix_engine(wire) as (host, _):
        with pytest.raises((RuntimeError, OSError)):
            native._docker_daemon_id(host)


@pytest.mark.parametrize("host", [
    "", "tcp://localhost:2375", "http://localhost:2375", "https://localhost:2376",
    "ssh://localhost", "unix://relative.sock", "unix:///tmp/../engine.sock",
    "unix:///tmp/./engine.sock", "unix:///tmp//engine.sock", "unix:///tmp/engine.sock?x=1",
    "unix:///tmp/engine.sock\x00", "npipe:////./pipe/docker_engine", NPIPE + "/extra",
])
def test_identity_rejects_unpinned_transports_before_io(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch, host: str,
) -> None:
    monkeypatch.setattr(native.subprocess, "run", _forbid_cli)
    monkeypatch.setattr(native.socket, "socket", lambda *a, **k: pytest.fail("unexpected socket"))
    with pytest.raises((RuntimeError, OSError, ValueError)):
        native._docker_daemon_id(host)


def test_unix_connection_failure_is_finitely_bounded_and_never_falls_back(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = []

    class UnavailableConnection:
        def __enter__(self) -> UnavailableConnection:
            return self

        def __exit__(self, *args: object) -> None:
            events.append("close")

        def settimeout(self, seconds: float) -> None:
            events.append(("timeout", seconds))

        def connect(self, path: str) -> None:
            events.append(("connect", path))
            raise TimeoutError("fixture connect timeout")

    monkeypatch.setattr(native.socket, "socket", lambda *a, **k: UnavailableConnection())
    monkeypatch.setattr(native.subprocess, "run", _forbid_cli)
    with pytest.raises(TimeoutError):
        native._docker_daemon_id("unix:///var/run/docker.sock")
    assert events == [("timeout", 10), ("connect", "/var/run/docker.sock"), "close"]


def test_supported_npipe_fallback_is_explicit_sanitised_and_fd_bound(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    environment = {name: "hostile" for name in OVERRIDE_VARIABLES}
    environment.update(DOCKER_CONFIG="/proc/self/fd/51", BUILDX_CONFIG="/proc/self/fd/52", KEEP="yes")
    original = dict(environment)

    def run(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, (DAEMON_ID + "\n").encode(), b"")

    monkeypatch.setattr(native.subprocess, "run", run)
    assert native._docker_daemon_id(NPIPE, environment=environment, pass_fds=(51, 52)) == DAEMON_ID
    assert environment == original
    assert len(calls) == 1
    command, options = calls[0]
    assert tuple(command) == ("docker", "--host", NPIPE, "info", "--format", "{{.ID}}")
    assert options["pass_fds"] == (51, 52)
    assert options["close_fds"] is True
    assert options["check"] is False
    assert options["timeout"] == 10
    assert options["stdout"] == subprocess.PIPE and options["stderr"] == subprocess.PIPE
    assert options["env"] == {k: v for k, v in original.items() if k not in OVERRIDE_VARIABLES}


@pytest.mark.parametrize(("returncode", "stdout"), [
    (1, DAEMON_ID + "\n"), (0, ""), (0, "unavailable\n"),
    (0, DAEMON_ID + "\n" + OTHER_ID + "\n"), (0, "bad identifier\n"),
])
def test_npipe_fallback_rejects_failure_and_malformed_id_without_retry(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str,
) -> None:
    calls = []

    def run(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(command)
        return subprocess.CompletedProcess(command, returncode, stdout.encode(), b"diagnostic")

    monkeypatch.setattr(native.subprocess, "run", run)
    with pytest.raises((RuntimeError, OSError)):
        native._docker_daemon_id(NPIPE)
    assert len(calls) == 1


def test_npipe_timeout_is_not_retried_or_changed_to_another_host(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def run(command: tuple[str, ...], **kwargs: object) -> None:
        calls.append(command)
        raise subprocess.TimeoutExpired(command, 10)

    monkeypatch.setattr(native.subprocess, "run", run)
    assert native._dispatch_docker_request(
        ("qcsd-native-docker-verify", NPIPE, DAEMON_ID), environment={}, pass_fds=(),
    ) == 125
    assert calls == [("docker", "--host", NPIPE, "info", "--format", "{{.ID}}")]


@pytest.mark.parametrize(("operation", "expected_status"), [("verify", 42), ("exec", 125)])
def test_dispatch_exact_id_mismatch_blocks_commands(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch, operation: str, expected_status: int,
) -> None:
    calls = []

    def identifier(host: str, **kwargs: object) -> str:
        calls.append(host)
        return OTHER_ID

    monkeypatch.setattr(native, "_docker_daemon_id", identifier)
    monkeypatch.setattr(native.subprocess, "run", _forbid_cli)
    command = (f"qcsd-native-docker-{operation}", "unix:///var/run/docker.sock", DAEMON_ID)
    if operation == "exec":
        command += ("--", "rm", "exact-container")
    assert native._dispatch_docker_request(command, environment={}, pass_fds=()) == expected_status
    assert calls == ["unix:///var/run/docker.sock"]


@pytest.mark.parametrize("operation", ["id", "verify", "exec"])
def test_dispatch_unavailable_identity_never_executes_or_retries(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch, operation: str,
) -> None:
    calls = []

    def unavailable(host: str, **kwargs: object) -> str:
        calls.append(host)
        raise OSError("fixture daemon unavailable")

    monkeypatch.setattr(native, "_docker_daemon_id", unavailable)
    monkeypatch.setattr(native.subprocess, "run", _forbid_cli)
    command = (f"qcsd-native-docker-{operation}", "unix:///var/run/docker.sock")
    if operation != "id":
        command += (DAEMON_ID,)
    if operation == "exec":
        command += ("--", "rm", "exact-container")
    assert native._dispatch_docker_request(command, environment={}, pass_fds=()) == 125
    assert len(calls) == 1


def test_dispatch_id_prints_only_identity_and_verify_does_not_print(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(native, "_docker_daemon_id", lambda *a, **k: DAEMON_ID)
    assert native._dispatch_docker_request(("qcsd-native-docker-id", NPIPE), environment={}, pass_fds=()) == 0
    assert capsys.readouterr().out == DAEMON_ID + "\n"
    assert native._dispatch_docker_request(("qcsd-native-docker-verify", NPIPE, DAEMON_ID), environment={}, pass_fds=()) == 0
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("returncode", [0, 7, 125, -9, -15])
def test_dispatch_exec_runs_exactly_once_after_fresh_identity_and_preserves_fds(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch, returncode: int,
) -> None:
    events = []
    environment = {name: "hostile" for name in OVERRIDE_VARIABLES}
    environment.update(DOCKER_CONFIG="/proc/self/fd/31", BUILDX_CONFIG="/proc/self/fd/32", KEEP="yes")
    original = dict(environment)

    def identifier(host: str, **kwargs: object) -> str:
        events.append(("identity", host, kwargs))
        return DAEMON_ID

    def run(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        events.append(("execute", command, kwargs))
        return subprocess.CompletedProcess(command, returncode)

    monkeypatch.setattr(native, "_docker_daemon_id", identifier)
    monkeypatch.setattr(native.subprocess, "run", run)
    arguments = ("container", "rm", "exact-container")
    command = ("qcsd-native-docker-exec", NPIPE, DAEMON_ID, "--", *arguments)
    observed = native._dispatch_docker_request(command, environment=environment, pass_fds=(31, 32))
    assert observed == (returncode if returncode >= 0 else 128 - returncode)
    assert environment == original
    assert [event[0] for event in events] == ["identity", "execute"]
    assert events[0][1] == NPIPE
    assert events[0][2]["pass_fds"] == (31, 32)
    assert tuple(events[1][1]) == ("docker", "--host", NPIPE, *arguments)
    options = events[1][2]
    assert options["pass_fds"] == (31, 32) and options["close_fds"] is True
    assert options["check"] is False
    assert options["env"] == {k: v for k, v in original.items() if k not in OVERRIDE_VARIABLES}


@pytest.mark.parametrize("outcome", ["success", "mismatch", "unavailable", "exec-error"])
def test_dispatch_retains_signal_policy_and_restores_it_on_every_terminal_path(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch, outcome: str,
) -> None:
    signals = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)
    original = {number: signal.getsignal(number) for number in signals}
    calls = []

    def identity(*args: object, **kwargs: object) -> str:
        calls.append("identity")
        assert all(signal.getsignal(number) == signal.SIG_IGN for number in signals)
        if outcome == "unavailable":
            raise OSError("fixture identity unavailable")
        return OTHER_ID if outcome == "mismatch" else DAEMON_ID

    def run(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess:
        calls.append("execute")
        assert all(signal.getsignal(number) == signal.SIG_IGN for number in signals)
        if outcome == "exec-error":
            raise OSError("fixture command failed to start")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(native, "_docker_daemon_id", identity)
    monkeypatch.setattr(native.subprocess, "run", run)
    try:
        observed = native._dispatch_docker_request(
            ("qcsd-native-docker-exec", NPIPE, DAEMON_ID, "--", "rm", "exact-container"),
            environment={}, pass_fds=(),
        )
        assert observed == (0 if outcome == "success" else 125)
        assert calls == (["identity", "execute"] if outcome in {"success", "exec-error"} else ["identity"])
        assert {number: signal.getsignal(number) for number in signals} == original
    finally:
        for number, disposition in original.items():
            signal.signal(number, disposition)


@pytest.mark.parametrize("command", [
    ("qcsd-native-docker-id",), ("qcsd-native-docker-id", NPIPE, "extra"),
    ("qcsd-native-docker-verify", NPIPE),
    ("qcsd-native-docker-verify", NPIPE, DAEMON_ID, "extra"),
    ("qcsd-native-docker-exec", NPIPE, DAEMON_ID),
    ("qcsd-native-docker-exec", NPIPE, DAEMON_ID, "--"),
    ("qcsd-native-docker-exec", NPIPE, DAEMON_ID, "not-separator", "rm"),
    ("qcsd-native-docker-exec", NPIPE, DAEMON_ID, "--", "--host", "tcp://other"),
    ("qcsd-native-docker-exec", NPIPE, "bad expected identity", "--", "rm"),
    ("qcsd-native-docker-verify", NPIPE, "bad expected identity"),
    ("qcsd-native-docker-unknown", NPIPE),
])
def test_dispatch_rejects_malformed_reserved_commands_before_identity_or_cli(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch, command: tuple[str, ...],
) -> None:
    monkeypatch.setattr(native, "_docker_daemon_id", lambda *a, **k: pytest.fail("unexpected identity read"))
    monkeypatch.setattr(native.subprocess, "run", _forbid_cli)
    assert native._dispatch_docker_request(command, environment={}, pass_fds=()) == 125


def test_dispatch_leaves_ordinary_command_to_existing_wrapper(native: ModuleType) -> None:
    assert native._dispatch_docker_request(("docker", "context", "inspect"), environment={}, pass_fds=()) is None


@pytest.mark.parametrize("valid_configuration", [True, False])
def test_wrapper_dispatch_occurs_only_after_lease_validation_and_acknowledgement(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
    valid_configuration: bool,
) -> None:
    events = []
    descriptors = []
    for index in range(4):
        path = tmp_path / str(index)
        path.mkdir()
        descriptors.append(os.open(path, os.O_RDONLY | os.O_DIRECTORY))
    rights = array.array("i", descriptors)

    class LeaseConnection:
        def settimeout(self, value: float) -> None:
            assert value == 5

        def connect(self, endpoint: str) -> None:
            events.append("connect")

        def sendall(self, payload: bytes) -> None:
            events.append("ack" if payload == native.API_LEASE_ACK else "request")

        def recvmsg(self, *args: object) -> tuple[bytes, list, int, None]:
            return native.API_LEASE_MESSAGE, [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes())], 0, None

        def close(self) -> None:
            events.append("lease-channel-close")

    def validate(*args: object, **kwargs: object) -> tuple[int, int]:
        events.append("validate-lease")
        return descriptors[0], descriptors[1]

    def configuration(*args: object, **kwargs: object) -> bool:
        events.append("validate-config")
        return valid_configuration

    def dispatch(command: tuple[str, ...], *, environment: dict, pass_fds: tuple) -> int:
        assert events[-1] == "lease-channel-close" and "ack" in events
        assert events.count("validate-config") == 2
        assert pass_fds == tuple(descriptors[2:])
        for fd in descriptors:
            os.fstat(fd)  # Both guardian descriptors are still held during dispatch.
        assert environment["DOCKER_CONFIG"] == f"/proc/self/fd/{descriptors[2]}"
        assert environment["BUILDX_CONFIG"] == f"/proc/self/fd/{descriptors[3]}"
        assert command == ("qcsd-native-docker-id", NPIPE)
        events.append("dispatch")
        return 42

    monkeypatch.setattr(native.socket, "socket", lambda *a, **k: LeaseConnection())
    monkeypatch.setattr(native, "_validate_api_lease_descriptors", validate)
    monkeypatch.setattr(native, "_exact_configuration_descriptor", configuration)
    monkeypatch.setattr(native, "_process_start_time", lambda pid: 1)
    monkeypatch.setattr(native, "_process_uid", lambda pid: os.getuid())
    monkeypatch.setattr(native, "_cmdline_sha256", lambda: "a" * 64)
    monkeypatch.setattr(native, "_dispatch_docker_request", dispatch)
    monkeypatch.setattr(native.subprocess, "run", _forbid_cli)
    arguments = ("@fixture", "b" * 64, "123", "1", "1", "2", "@singleton", "--", "qcsd-native-docker-id", NPIPE)
    try:
        if valid_configuration:
            assert native._api_service_wrapper(arguments) == 42
            assert events[-1] == "dispatch"
            for fd in descriptors:
                with pytest.raises(OSError):
                    os.fstat(fd)
        else:
            with pytest.raises(RuntimeError, match="configuration"):
                native._api_service_wrapper(arguments)
            assert "ack" not in events and "dispatch" not in events
    finally:
        for fd in descriptors:
            try:
                os.close(fd)
            except OSError:
                pass
