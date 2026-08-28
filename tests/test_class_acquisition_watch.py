from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import signal
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tools import class_acquisition_watch as watch

_REAL_VALIDATE_HOST_SOURCE = watch._validate_host_source


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def _receipt(receipt_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "receipt_type": receipt_type,
        "payload_sha256": hashlib.sha256(_canonical(payload)).hexdigest(),
        "payload": copy.deepcopy(payload),
    }


def _write_receipt(path: Path, receipt_type: str, payload: dict[str, Any]) -> None:
    path.write_bytes(_canonical(_receipt(receipt_type, payload)))


@dataclass
class Fixture:
    paths: watch.WatchPaths
    image: str
    candidate_ids: list[str]

    def advance_checkpoint(self) -> None:
        value = json.loads(self.paths.checkpoint.read_text(encoding="utf-8"))
        payload = copy.deepcopy(value["payload"])
        first = payload["candidates"][self.candidate_ids[0]]
        first["watch_test_revision"] = first.get("watch_test_revision", 0) + 1
        _write_receipt(self.paths.checkpoint, watch.CHECKPOINT_TYPE, payload)


@pytest.fixture
def acquisition(tmp_path: Path) -> Fixture:
    paths = watch.WatchPaths.from_lab_root(tmp_path)
    paths.candidate_catalogue.parent.mkdir(parents=True)
    paths.acquisition_root.mkdir(parents=True)
    paths.mutation_lock.write_bytes(b"")
    paths.stability_root.mkdir(parents=True)
    paths.workload_root.mkdir(parents=True)
    paths.launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    paths.launcher.chmod(0o755)

    candidate_ids = [f"tranco-{rank:07d}" for rank in range(1, watch.CANDIDATE_COUNT + 1)]
    catalogue_payload = {
        "study_id": watch.STUDY_ID,
        "catalogue_schema_version": 1,
        "tranco": {},
        "selection": {},
        "candidates": [
            {
                "candidate_id": candidate_id,
                "domain": f"site-{rank}.example",
                "rank": rank,
                "stratum": "test",
                "eligible": False,
            }
            for rank, candidate_id in enumerate(candidate_ids, 1)
        ],
    }
    _write_receipt(paths.candidate_catalogue, watch.CATALOGUE_TYPE, catalogue_payload)
    catalogue = json.loads(paths.candidate_catalogue.read_text(encoding="utf-8"))
    catalogue_sha256 = hashlib.sha256(paths.candidate_catalogue.read_bytes()).hexdigest()

    foundation_path = paths.lab_root / "artifacts/class-study-foundation-v23.json"
    _write_receipt(
        foundation_path,
        watch.FOUNDATION_TYPE,
        {"study_id": watch.STUDY_ID, "gate": "passed"},
    )
    image = "sha256:" + "a" * 64
    provenance_payload = {
        "study_id": watch.STUDY_ID,
        "acquisition_schema_version": 1,
        "candidate_catalogue_sha256": catalogue_sha256,
        "candidate_catalogue_payload_sha256": catalogue["payload_sha256"],
        "candidate_count": watch.CANDIDATE_COUNT,
        "foundation_attestation": {
            "path": "/lab/artifacts/class-study-foundation-v23.json",
            "sha256": hashlib.sha256(foundation_path.read_bytes()).hexdigest(),
        },
        "started_at": "2026-08-29T00:00:00Z",
        "image_digest": image,
        "source": {
            "image_digest": image,
            "lab_commit": "b" * 40,
            "lab_dirty": False,
            "lab_patch_sha256": watch.EMPTY_SHA256,
            "neqo_commit": "c" * 40,
            "neqo_pinned_commit": "c" * 40,
            "neqo_dirty": False,
            "neqo_patch_sha256": watch.EMPTY_SHA256,
        },
        "browser_tool": "playwright-chromium",
        "navigation_implementation": "playwright-cdp-catalogue-domain-boundary-v1",
        "registrable_domain_policy": "exact-frozen-tranco-candidate-domain",
        "domain_safety_policy": {},
        "domain_safety_policy_sha256": "d" * 64,
        "origin_policy": copy.deepcopy(watch._ORIGIN_POLICY),
        "eligibility_inputs": ["page-safety", "three-window-technical-stability"],
        "prohibited_inputs": ["classifier", "defence", "latency", "bandwidth", "privacy"],
    }
    _write_receipt(paths.provenance, watch.PROVENANCE_TYPE, provenance_payload)
    provenance_sha256 = hashlib.sha256(paths.provenance.read_bytes()).hexdigest()
    checkpoint_payload = {
        "provenance_sha256": provenance_sha256,
        "candidate_catalogue_sha256": catalogue_sha256,
        "candidates": {
            candidate_id: {"state": "pending", "pages": [], "terminal": None}
            for candidate_id in candidate_ids
        },
    }
    _write_receipt(paths.checkpoint, watch.CHECKPOINT_TYPE, checkpoint_payload)
    return Fixture(paths, image, candidate_ids)


@pytest.fixture(autouse=True)
def _accept_fixture_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(watch, "_validate_host_source", lambda _paths, _binding: None)


def _details(
    *,
    terminal: int = 0,
    probing: int = 0,
    due: int = 0,
    missed: int = 0,
    recovery: int = 0,
    blocked: bool = False,
    next_due: str | None = None,
) -> dict[str, Any]:
    pending = watch.CANDIDATE_COUNT - terminal - probing
    complete = terminal == watch.CANDIDATE_COUNT
    work_due = bool(due or missed or (pending and not blocked))
    return {
        "candidate_count": watch.CANDIDATE_COUNT,
        "terminal_count": terminal,
        "pending_count": pending,
        "probing_count": probing,
        "due_now_count": due,
        "missed_window_count": missed,
        "recovery_required_count": recovery,
        "pending_start_blocked": blocked,
        "work_due_now": work_due,
        "complete": complete,
        "next_due": next_due,
    }


def _result(action: str, details: dict[str, Any], *, runner_root: str | None = None) -> dict:
    payload = copy.deepcopy(details)
    payload.update(
        {
            "valid": True,
            "runner_root": runner_root or watch.CONTAINER_ACQUISITION_ROOT,
        }
    )
    if action == "acquisition-status":
        payload["gate"] = {
            "required_windows": copy.deepcopy(watch._EXPECTED_WINDOWS),
            "labels": ["t+30s", "t+24h", "t+72h"],
            "all_three_required_per_page_receipt": True,
            "acquisition_owner": "resumable-qcsd-class-study-production-runner",
            "runner_sleeps_between_windows": False,
        }
        status = "complete"
        blockers: list[str] = []
    else:
        payload["bounded_candidates"] = watch.MAX_CANDIDATES
        payload["runner_slept"] = False
        status = "ready" if payload["complete"] else "pending"
        blockers = [] if payload["complete"] else ["rerun from coordinator state"]
    return {
        "schema_version": 1,
        "artifact_type": watch.ACTION_RESULT_TYPE,
        "action": action,
        "status": status,
        "details": payload,
        "blockers": blockers,
    }


def _completed(value: Any, *, returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    stdout = value if isinstance(value, str) else json.dumps(value)
    return subprocess.CompletedProcess((), returncode, stdout, stderr)


class FakeRunner:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[tuple[str, ...], Path, dict[str, str]]] = []

    def __call__(self, command, *, cwd, env, lock_fd):
        assert env[watch.LOCK_ENV] == str(lock_fd)
        self.calls.append((tuple(command), cwd, dict(env)))
        if not self.responses:
            raise AssertionError("unexpected coordinator call")
        response = self.responses.pop(0)
        if callable(response):
            response = response(tuple(command), cwd, dict(env))
        return response


class FakeClock:
    def __init__(self, value: datetime) -> None:
        self.value = value
        self.sleeps: list[float] = []

    def __call__(self) -> datetime:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += timedelta(seconds=seconds)


class FakeMonotonic:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value


def test_due_work_uses_exact_command_environment_and_paths(acquisition: Fixture) -> None:
    expected_run_command = (
        str(acquisition.paths.launcher),
        "class-study",
        "acquisition-run",
        "--candidate-catalogue",
        str(acquisition.paths.candidate_catalogue),
        "--acquisition-root",
        str(acquisition.paths.acquisition_root),
        "--stability-root",
        str(acquisition.paths.stability_root),
        "--workload-root",
        str(acquisition.paths.workload_root),
        "--acquisition-max-candidates",
        str(watch.CANDIDATE_COUNT),
        "--acquisition-timeout-ms",
        str(watch.ACQUISITION_TIMEOUT_MS),
    )
    assert watch._run_command(acquisition.paths) == expected_run_command
    assert watch._run_command(acquisition.paths).count("acquisition-run") == 1
    due = _details(probing=1, due=1, blocked=True)
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def run_response(command, _cwd, _env):
        assert command[2] == "acquisition-run"
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-run", complete))

    runner = FakeRunner(
        [
            _completed(_result("acquisition-status", due)),
            run_response,
            _completed(_result("acquisition-status", complete)),
        ]
    )
    result = watch.watch_acquisition(
        paths=acquisition.paths,
        runner=runner,
        environment={
            "PATH": "/usr/bin:/bin",
            "BASH_ENV": "/tmp/untrusted-shell-hook",
            "PYTHONPATH": "/tmp/untrusted-python",
            "PRESERVED": "no",
            watch.PREPARE_IMAGE_ENV: "wrong",
        },
    )

    assert result["details"]["complete"] is True
    assert [call[0] for call in runner.calls] == [
        watch._status_command(acquisition.paths),
        watch._run_command(acquisition.paths),
        watch._status_command(acquisition.paths),
    ]
    assert all(call[1] == acquisition.paths.lab_root for call in runner.calls)
    assert all(call[2]["PATH"] == "/usr/bin:/bin" for call in runner.calls)
    assert all("PRESERVED" not in call[2] for call in runner.calls)
    assert all("BASH_ENV" not in call[2] for call in runner.calls)
    assert all("PYTHONPATH" not in call[2] for call in runner.calls)
    assert all(
        call[2][watch.PREPARE_IMAGE_ENV] == acquisition.image for call in runner.calls
    )
    assert all(call[2][watch.LOCK_ENV].isdigit() for call in runner.calls)


def test_complete_exits_without_creating_completion_receipt(acquisition: Fixture) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    runner = FakeRunner([_completed(_result("acquisition-status", complete))])

    watch.watch_acquisition(paths=acquisition.paths, runner=runner)

    assert not (acquisition.paths.acquisition_root / "completion.json").exists()
    assert len(runner.calls) == 1


def test_waits_to_target_with_five_second_heartbeats_and_no_busy_spin(
    acquisition: Fixture,
) -> None:
    start = datetime(2026, 8, 29, tzinfo=UTC)
    target = start + timedelta(seconds=12)
    target_text = target.isoformat().replace("+00:00", "Z")
    waiting = _details(probing=1, blocked=True, next_due=target_text)
    due = _details(probing=1, due=1, blocked=True)
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def run_response(_command, _cwd, _env):
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-run", complete))

    runner = FakeRunner(
        [
            _completed(_result("acquisition-status", waiting)),
            run_response,
            _completed(_result("acquisition-status", complete)),
        ]
    )
    clock = FakeClock(start)

    watch.watch_acquisition(
        paths=acquisition.paths,
        runner=runner,
        clock=clock,
        sleeper=clock.sleep,
    )

    assert clock.sleeps == [5.0, 5.0, 2.0]
    assert clock.value == target
    assert [call[0][2] for call in runner.calls] == [
        "acquisition-status",
        "acquisition-run",
        "acquisition-status",
    ]


def test_wait_revalidates_host_source_without_polling_status_containers(
    acquisition: Fixture,
) -> None:
    start = datetime(2026, 8, 29, tzinfo=UTC)
    target = start + timedelta(seconds=65)
    waiting = _details(
        probing=1,
        blocked=True,
        next_due=target.isoformat().replace("+00:00", "Z"),
    )
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    clock = FakeClock(start)
    monotonic = FakeMonotonic()
    validations: list[float] = []

    def sleep(seconds: float) -> None:
        clock.sleep(seconds)
        monotonic.value += seconds

    def validate(_paths, _binding) -> None:
        validations.append(monotonic.value)

    def run_response(_command, _cwd, _env):
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-run", complete))

    runner = FakeRunner(
        [
            _completed(_result("acquisition-status", waiting)),
            run_response,
            _completed(_result("acquisition-status", complete)),
        ]
    )
    watch.watch_acquisition(
        paths=acquisition.paths,
        runner=runner,
        clock=clock,
        sleeper=sleep,
        monotonic=monotonic,
        source_validator=validate,
    )

    assert validations == [0.0, 60.0, 65.0]
    assert [call[0][2] for call in runner.calls] == [
        "acquisition-status",
        "acquisition-run",
        "acquisition-status",
    ]


def test_resume_uses_existing_checkpoint_and_releases_lock_on_interrupt(
    acquisition: Fixture,
) -> None:
    start = datetime(2026, 8, 29, tzinfo=UTC)
    future = (start + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    waiting = _details(probing=1, blocked=True, next_due=future)
    interrupted = FakeRunner([_completed(_result("acquisition-status", waiting))])

    with pytest.raises(KeyboardInterrupt):
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=interrupted,
            clock=lambda: start,
            sleeper=lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt),
        )

    due = _details(probing=1, missed=1, blocked=True)
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def run_response(_command, _cwd, _env):
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-run", complete))

    resumed = FakeRunner(
        [
            _completed(_result("acquisition-status", due)),
            run_response,
            _completed(_result("acquisition-status", complete)),
        ]
    )
    assert watch.watch_acquisition(paths=acquisition.paths, runner=resumed)["details"][
        "complete"
    ]


def test_clock_jump_delegates_missed_terminalisation_to_existing_runner(
    acquisition: Fixture,
) -> None:
    start = datetime(2026, 8, 29, tzinfo=UTC)
    target = (start + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
    waiting = _details(probing=1, blocked=True, next_due=target)
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    clock = FakeClock(start)

    def jump(_seconds: float) -> None:
        clock.sleeps.append(_seconds)
        clock.value += timedelta(seconds=40)

    def run_response(command, _cwd, _env):
        assert command == watch._run_command(acquisition.paths)
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-run", complete))

    runner = FakeRunner(
        [
            _completed(_result("acquisition-status", waiting)),
            run_response,
            _completed(_result("acquisition-status", complete)),
        ]
    )

    watch.watch_acquisition(
        paths=acquisition.paths,
        runner=runner,
        clock=clock,
        sleeper=jump,
    )

    assert clock.sleeps == [5.0]
    assert sum(call[0][2] == "acquisition-run" for call in runner.calls) == 1


def test_lock_contention_fails_before_calling_coordinator(acquisition: Fixture) -> None:
    descriptor = os.open(acquisition.paths.mutation_lock, os.O_RDWR)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    runner = FakeRunner([])
    try:
        with pytest.raises(watch.WatchError, match="another class-study acquisition"):
            watch.watch_acquisition(paths=acquisition.paths, runner=runner)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)
    assert runner.calls == []


def test_incomplete_status_without_due_or_next_due_fails(acquisition: Fixture) -> None:
    stuck = _details(terminal=watch.CANDIDATE_COUNT - 1, probing=1, blocked=False)
    runner = FakeRunner([_completed(_result("acquisition-status", stuck))])

    with pytest.raises(watch.WatchError, match="no due work and no next_due"):
        watch.watch_acquisition(paths=acquisition.paths, runner=runner)


@pytest.mark.parametrize(
    "response,match",
    [
        (_completed("not-json"), "not exactly one JSON"),
        (
            _completed(
                _result(
                    "acquisition-status",
                    _details(terminal=watch.CANDIDATE_COUNT),
                    runner_root="/lab/artifacts/another-acquisition",
                )
            ),
            "another acquisition root",
        ),
        (
            _completed(
                _result("acquisition-run", _details(terminal=watch.CANDIDATE_COUNT))
            ),
            "identity is mismatched",
        ),
    ],
)
def test_malformed_or_mismatched_result_fails(acquisition: Fixture, response, match) -> None:
    with pytest.raises(watch.WatchError, match=match):
        watch.watch_acquisition(paths=acquisition.paths, runner=FakeRunner([response]))


def test_mismatched_prepare_image_and_child_failure_fail_closed(acquisition: Fixture) -> None:
    provenance = json.loads(acquisition.paths.provenance.read_text(encoding="utf-8"))
    payload = copy.deepcopy(provenance["payload"])
    payload["image_digest"] = "neqo-qcsd-lab-prepare:local"
    payload["source"]["image_digest"] = payload["image_digest"]
    _write_receipt(acquisition.paths.provenance, watch.PROVENANCE_TYPE, payload)
    with pytest.raises(watch.WatchError, match="exact prepare image"):
        watch.watch_acquisition(paths=acquisition.paths, runner=FakeRunner([]))

    # Restore a fully bound fixture, then exercise an actual child failure.
    acquisition = _restore_provenance_binding(acquisition)
    failed = _completed("", returncode=17, stderr="docker unavailable")
    with pytest.raises(watch.WatchError, match="exit 17: docker unavailable"):
        watch.watch_acquisition(paths=acquisition.paths, runner=FakeRunner([failed]))


def _restore_provenance_binding(acquisition: Fixture) -> Fixture:
    provenance = json.loads(acquisition.paths.provenance.read_text(encoding="utf-8"))
    payload = copy.deepcopy(provenance["payload"])
    payload["image_digest"] = acquisition.image
    payload["source"]["image_digest"] = acquisition.image
    _write_receipt(acquisition.paths.provenance, watch.PROVENANCE_TYPE, payload)
    checkpoint = json.loads(acquisition.paths.checkpoint.read_text(encoding="utf-8"))
    checkpoint_payload = copy.deepcopy(checkpoint["payload"])
    checkpoint_payload["provenance_sha256"] = hashlib.sha256(
        acquisition.paths.provenance.read_bytes()
    ).hexdigest()
    _write_receipt(acquisition.paths.checkpoint, watch.CHECKPOINT_TYPE, checkpoint_payload)
    return acquisition


def test_due_run_must_advance_checkpoint(acquisition: Fixture) -> None:
    due = _details(probing=1, due=1, blocked=True)
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    runner = FakeRunner(
        [
            _completed(_result("acquisition-status", due)),
            _completed(_result("acquisition-run", complete)),
        ]
    )

    with pytest.raises(watch.WatchError, match="did not advance the checkpoint"):
        watch.watch_acquisition(paths=acquisition.paths, runner=runner)


def test_expired_next_due_runs_immediately_without_redundant_status(
    acquisition: Fixture,
) -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    expired = (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    waiting = _details(probing=1, blocked=True, next_due=expired)
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def run_response(_command, _cwd, _env):
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-run", complete))

    runner = FakeRunner(
        [
            _completed(_result("acquisition-status", waiting)),
            run_response,
            _completed(_result("acquisition-status", complete)),
        ]
    )

    watch.watch_acquisition(paths=acquisition.paths, runner=runner, clock=lambda: now)

    assert [call[0][2] for call in runner.calls] == [
        "acquisition-status",
        "acquisition-run",
        "acquisition-status",
    ]


def test_main_maps_keyboard_interrupt_and_sigterm_handler_to_resume_exit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        watch,
        "watch_acquisition",
        lambda **_arguments: (_ for _ in ()).throw(KeyboardInterrupt),
    )

    assert watch.main([]) == 130
    assert "resume from checkpoint" in capsys.readouterr().err
    with pytest.raises(KeyboardInterrupt):
        watch._raise_keyboard_interrupt(signal.SIGTERM, None)


def test_subprocess_runner_terminates_the_entire_child_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signals: list[tuple[int, signal.Signals]] = []
    popen_keywords: dict[str, Any] = {}

    class InterruptedProcess:
        pid = 4242
        returncode = -signal.SIGTERM
        calls = 0

        def communicate(self, timeout=None):
            self.calls += 1
            if self.calls == 1:
                raise KeyboardInterrupt
            assert timeout == 10
            return "", ""

    process = InterruptedProcess()

    def popen(*_args, **kwargs):
        popen_keywords.update(kwargs)
        return process

    monkeypatch.setattr(watch.subprocess, "Popen", popen)
    monkeypatch.setattr(
        watch.os,
        "killpg",
        lambda pid, signum: signals.append((pid, signum)),
    )

    with pytest.raises(KeyboardInterrupt):
        watch._subprocess_runner(
            ("ignored-child",),
            cwd=tmp_path,
            env={"PATH": "/usr/bin:/bin"},
            lock_fd=3,
        )

    assert signals == [(4242, signal.SIGTERM)]
    assert popen_keywords["pass_fds"] == (3,)
    assert popen_keywords["start_new_session"] is True


@pytest.mark.parametrize("heartbeat", (0.5, float("inf"), float("nan")))
def test_heartbeat_rejects_subsecond_and_nonfinite_values(
    acquisition: Fixture, heartbeat: float
) -> None:
    with pytest.raises(watch.WatchError, match=r"finite number in \[1, 5\]"):
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=FakeRunner([]),
            heartbeat_seconds=heartbeat,
        )


def test_orphan_cleanup_requires_exact_labels_image_and_mounts(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = watch._validate_acquisition_binding(acquisition.paths)
    present = True
    calls: list[tuple[str, ...]] = []

    def inspect_value() -> dict[str, Any]:
        return {
            "Id": "1" * 64,
            "Name": f"/{watch.CONTAINER_NAME}",
            "Image": binding.prepare_image,
            "Config": {
                "Labels": {
                    **watch.CONTAINER_LABELS,
                    "org.qcsd.image-id": binding.prepare_image,
                }
            },
            "Mounts": [
                {
                    "Source": str(acquisition.paths.acquisition_root),
                    "Destination": watch.CONTAINER_ACQUISITION_ROOT,
                    "RW": True,
                },
                {
                    "Source": str(acquisition.paths.stability_root),
                    "Destination": (
                        f"/lab/artifacts/{watch.STUDY_ID}-stability"
                    ),
                    "RW": True,
                },
                {
                    "Source": str(acquisition.paths.workload_root),
                    "Destination": "/lab/config/workloads",
                    "RW": True,
                },
            ],
        }

    def docker(_paths, *arguments):
        nonlocal present
        calls.append(tuple(arguments))
        if arguments[:2] == ("container", "inspect"):
            if not present:
                return _completed("", returncode=1, stderr="No such container")
            return _completed([inspect_value()])
        if arguments[:2] == ("container", "ls"):
            assert not present
            return _completed("")
        if arguments[:2] == ("container", "stop"):
            present = False
            return _completed(watch.CONTAINER_NAME)
        raise AssertionError(arguments)

    monkeypatch.setattr(watch, "_docker_command", docker)
    watch._cleanup_orphan_container(acquisition.paths, binding)

    assert any(call[:2] == ("container", "stop") for call in calls)
    assert not any(call[:2] == ("container", "rm") for call in calls)


def test_orphan_cleanup_never_touches_a_mismatched_container(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = watch._validate_acquisition_binding(acquisition.paths)
    calls: list[tuple[str, ...]] = []
    wrong = {
        "Id": "2" * 64,
        "Name": f"/{watch.CONTAINER_NAME}",
        "Image": binding.prepare_image,
        "Config": {"Labels": {**watch.CONTAINER_LABELS, "org.qcsd.image-id": "wrong"}},
        "Mounts": [],
    }

    def docker(_paths, *arguments):
        calls.append(tuple(arguments))
        return _completed([wrong])

    monkeypatch.setattr(watch, "_docker_command", docker)
    with pytest.raises(watch.WatchError, match="refusing to manage"):
        watch._cleanup_orphan_container(acquisition.paths, binding)
    assert calls == [("container", "inspect", watch.CONTAINER_NAME)]


def test_startup_stops_orphan_before_checkpoint_and_source_validation(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = watch._validate_immutable_binding(acquisition.paths)
    events: list[str] = []

    monkeypatch.setattr(
        watch,
        "_validate_immutable_binding",
        lambda _paths: events.append("immutable") or binding,
    )
    monkeypatch.setattr(
        watch,
        "_cleanup_orphan_container",
        lambda _paths, _binding: events.append("cleanup"),
    )
    monkeypatch.setattr(
        watch,
        "_validate_checkpoint",
        lambda _paths, _binding: events.append("checkpoint") or "a" * 64,
    )

    def drifted(_paths, _binding) -> None:
        events.append("source")
        raise watch.WatchError("source drift")

    monkeypatch.setattr(watch, "_validate_host_source", drifted)
    with pytest.raises(watch.WatchError, match="source drift"):
        watch.watch_acquisition(paths=acquisition.paths)

    assert events == ["immutable", "cleanup", "checkpoint", "source", "cleanup"]


def test_host_source_validator_rejects_checkout_drift(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = watch._validate_acquisition_binding(acquisition.paths)

    def git_text(_paths, *arguments, cwd=None):
        if arguments == ("rev-parse", "HEAD"):
            return (
                binding.source["neqo_commit"]
                if cwd == acquisition.paths.lab_root / "neqo-qcsd"
                else binding.source["lab_commit"]
            )
        if arguments == ("ls-files", "--stage", "--", "neqo-qcsd"):
            return f"160000 {binding.source['neqo_pinned_commit']} 0\tneqo-qcsd"
        if arguments == ("status", "--porcelain", "--untracked-files=all"):
            return " M drifted.py" if cwd is None else ""
        raise AssertionError((arguments, cwd))

    monkeypatch.setattr(watch, "_git_text", git_text)
    with pytest.raises(watch.WatchError, match="drifted"):
        _REAL_VALIDATE_HOST_SOURCE(acquisition.paths, binding)
