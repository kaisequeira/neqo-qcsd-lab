from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
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


def _batch(prefix: str, body: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(body)
    value["batch_id"] = f"{prefix}-{hashlib.sha256(_canonical(body)).hexdigest()}"
    return value


def _checkpoint_payload(acquisition: Fixture) -> dict[str, Any]:
    return copy.deepcopy(
        json.loads(acquisition.paths.checkpoint.read_text(encoding="utf-8"))["payload"]
    )


def _replace_checkpoint(acquisition: Fixture, payload: dict[str, Any]) -> None:
    _write_receipt(acquisition.paths.checkpoint, watch.CHECKPOINT_TYPE, payload)


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
    paths = watch.WatchPaths.from_lab_root(
        tmp_path,
        state_base=tmp_path / "host-watch-state",
    )
    paths.candidate_catalogue.parent.mkdir(parents=True)
    paths.acquisition_root.mkdir(parents=True)
    paths.action_lock.write_bytes(b"")
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
        "acquisition_schema_version": watch.ACQUISITION_SCHEMA_VERSION,
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
        "navigation_implementation": (
            "playwright-cdp-catalogue-domain-boundary-redirect-pin-convergence-v3"
        ),
        "cdp_target_instrumentation_policy": watch._CDP_TARGET_INSTRUMENTATION_POLICY,
        "passive_render_contract": copy.deepcopy(watch._PASSIVE_RENDER_CONTRACT),
        "passive_render_contract_sha256": watch._PASSIVE_RENDER_CONTRACT_SHA256,
        "browser_navigation_timeout_ms": watch.BROWSER_NAVIGATION_TIMEOUT_MS,
        "passive_render_hard_cap_after_load_ms": watch.PASSIVE_RENDER_HARD_CAP_MS,
        "acquisition_action_timing_contract": copy.deepcopy(
            watch._ACQUISITION_ACTION_TIMING_CONTRACT
        ),
        "baseline_scheduling_contract": copy.deepcopy(
            watch._BASELINE_SCHEDULING_CONTRACT
        ),
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
        "checkpoint_schema_version": watch.CHECKPOINT_SCHEMA_VERSION,
        "provenance_sha256": provenance_sha256,
        "candidate_catalogue_sha256": catalogue_sha256,
        "baseline_batches": [],
        "active_batch": None,
        "candidates": {
            candidate_id: {"state": "pending", "pages": [], "terminal": None}
            for candidate_id in candidate_ids
        },
    }
    _write_receipt(paths.checkpoint, watch.CHECKPOINT_TYPE, checkpoint_payload)
    watch._ensure_state_namespace(paths)
    return Fixture(paths, image, candidate_ids)


@pytest.fixture(autouse=True)
def _accept_fixture_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(watch, "_validate_host_source", lambda _paths, _binding: None)


def _details(
    *,
    terminal: int = 0,
    probing: int = 0,
    due: int = 0,
    finalisable: int = 0,
    missed: int = 0,
    recovery: int = 0,
    blocked: bool = False,
    next_due: str | None = None,
    active_batch: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pending = watch.CANDIDATE_COUNT - terminal - probing
    complete = (
        terminal == watch.CANDIDATE_COUNT
        and finalisable == 0
        and recovery == 0
        and active_batch is None
    )
    work_due = bool(
        recovery or due or finalisable or missed or (pending and not blocked)
    )
    return {
        "acquisition_schema_version": watch.ACQUISITION_SCHEMA_VERSION,
        "checkpoint_schema_version": watch.CHECKPOINT_SCHEMA_VERSION,
        "maximum_candidates_per_action": watch.MAX_CANDIDATES,
        "global_live_page_cap": watch.GLOBAL_LIVE_PAGE_CAP,
        "active_batch": copy.deepcopy(active_batch),
        "candidate_count": watch.CANDIDATE_COUNT,
        "terminal_count": terminal,
        "pending_count": pending,
        "probing_count": probing,
        "due_now_count": due,
        "finalisable_count": finalisable,
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
            "batching": {
                "maximum_candidates_per_action": watch.MAX_CANDIDATES,
                "global_live_page_cap": watch.GLOBAL_LIVE_PAGE_CAP,
            },
            "runner_wait_policy": copy.deepcopy(watch._RUN_WAIT_POLICY),
        }
        status = "complete"
        blockers: list[str] = []
    else:
        payload["bounded_candidates"] = watch.MAX_CANDIDATES
        payload["runner_wait_policy"] = copy.deepcopy(watch._RUN_WAIT_POLICY)
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


def _admission() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_type": watch.DOCKER_ADMISSION_TYPE,
        "docker_context": "default",
        "docker_host": "unix:///var/run/docker.sock",
        "docker_server_id": "test-daemon-01",
        "host_boot_id": watch._host_boot_id(),
    }


class FakeRunner:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[tuple[str, ...], Path, dict[str, str]]] = []

    def __call__(
        self,
        command,
        *,
        cwd,
        env,
        authority_fd,
        state_root,
        source_binding_sha256,
    ):
        assert watch.LOCK_ENV not in env
        assert state_root.name == self._paths(command).namespace_sha256
        assert re.fullmatch(r"[0-9a-f]{64}", source_binding_sha256)
        self.calls.append((tuple(command), cwd, dict(env)))
        if tuple(command) == watch._admission_command(self._paths(command)):
            return _completed(_admission())
        if not self.responses:
            raise AssertionError("unexpected coordinator call")
        response = self.responses.pop(0)
        if callable(response):
            response = response(tuple(command), cwd, dict(env))
        return response

    @staticmethod
    def _paths(command: tuple[str, ...] | list[str]) -> watch.WatchPaths:
        launcher = Path(command[1] if command[0] == "/usr/bin/bash" else command[0])
        return watch.WatchPaths.from_lab_root(launcher.parent)


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
    assert watch.ACQUISITION_SCHEMA_VERSION == 4
    assert watch.CHECKPOINT_SCHEMA_VERSION == 2
    assert watch.ACQUISITION_TIMEOUT_MS == 60_000
    assert watch.PENDING_BASELINE_GUARD_MS == 2_400_000
    assert watch.MAX_CANDIDATES == 2
    assert watch.GLOBAL_LIVE_PAGE_CAP == 5
    assert watch.ACQUISITION_ACTION_TIMEOUT_SECONDS == 1_800
    assert watch.ACQUISITION_ACTION_CLEANUP_SECONDS == 120
    assert watch.RUN_RUNTIME_SECONDS == 1_920
    expected_run_command = (
        "/usr/bin/bash",
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
        str(watch.MAX_CANDIDATES),
        "--acquisition-timeout-ms",
        str(watch.ACQUISITION_TIMEOUT_MS),
    )
    assert watch._run_command(acquisition.paths) == expected_run_command
    assert watch._run_command(acquisition.paths).count("acquisition-run") == 1
    due = _details(probing=1, due=1, blocked=True)
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def run_response(command, _cwd, _env):
        assert command[3] == "acquisition-run"
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
        watch._admission_command(acquisition.paths),
        watch._status_command(acquisition.paths),
        watch._run_command(acquisition.paths),
        watch._status_command(acquisition.paths),
    ]
    assert all(call[1] == acquisition.paths.lab_root for call in runner.calls)
    assert all(call[2]["PATH"] == "/usr/bin:/bin" for call in runner.calls)
    assert all("PRESERVED" not in call[2] for call in runner.calls)
    assert all("BASH_ENV" not in call[2] for call in runner.calls)
    assert all("PYTHONPATH" not in call[2] for call in runner.calls)
    assert all(watch.SCOPE_ROOT_ENV not in call[2] for call in runner.calls)
    coordinator_calls = [
        call for call in runner.calls if call[0] != watch._admission_command(acquisition.paths)
    ]
    assert all(
        call[2][watch.PREPARE_IMAGE_ENV] == acquisition.image for call in coordinator_calls
    )
    assert all(watch.LOCK_ENV not in call[2] for call in runner.calls)


def test_action_status_validates_transactional_active_batch_summary() -> None:
    active = {
        "batch_id": "active-" + "a" * 64,
        "stage": "navigation",
        "published_at": "2026-08-29T01:00:00Z",
        "candidate_ids": ["tranco-0000001", "tranco-0000002"],
        "live_page_count": 2,
        "attempt_count": 2,
    }
    details = _details(recovery=2, active_batch=active)
    watch._validate_action_result(
        _result("acquisition-status", details), action="acquisition-status"
    )

    probe_active = copy.deepcopy(active)
    probe_active.update(
        {"stage": "probe", "live_page_count": 5, "attempt_count": 5}
    )
    watch._validate_action_result(
        _result(
            "acquisition-status",
            _details(
                terminal=watch.CANDIDATE_COUNT - 2,
                probing=2,
                recovery=5,
                active_batch=probe_active,
            ),
        ),
        action="acquisition-status",
    )

    for field, value in (("stage", "baseline"), ("attempt_count", 1)):
        invalid = copy.deepcopy(details)
        invalid["active_batch"][field] = value
        with pytest.raises(watch.WatchError, match="active batch"):
            watch._validate_action_result(
                _result("acquisition-status", invalid),
                action="acquisition-status",
            )


def test_action_status_validates_finalisable_work_as_disjoint_and_due() -> None:
    finalisable = _details(
        terminal=watch.CANDIDATE_COUNT - 1,
        probing=1,
        finalisable=1,
    )
    watch._validate_action_result(
        _result("acquisition-status", finalisable),
        action="acquisition-status",
    )

    overlapping = _details(
        terminal=watch.CANDIDATE_COUNT - 1,
        probing=1,
        due=1,
        finalisable=1,
    )
    with pytest.raises(watch.WatchError, match="counts are inconsistent"):
        watch._validate_action_result(
            _result("acquisition-status", overlapping),
            action="acquisition-status",
        )

    false_due_flag = copy.deepcopy(finalisable)
    false_due_flag["work_due_now"] = False
    with pytest.raises(watch.WatchError, match="due-work flag"):
        watch._validate_action_result(
            _result("acquisition-status", false_due_flag),
            action="acquisition-status",
        )


def test_complete_exits_without_creating_completion_receipt(acquisition: Fixture) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    runner = FakeRunner([_completed(_result("acquisition-status", complete))])

    watch.watch_acquisition(paths=acquisition.paths, runner=runner)

    assert not (acquisition.paths.acquisition_root / "completion.json").exists()
    assert len(runner.calls) == 2


def test_waits_to_target_with_five_second_heartbeats_and_no_busy_spin(
    acquisition: Fixture,
) -> None:
    start = datetime(2026, 8, 29, tzinfo=UTC)
    target = start + timedelta(seconds=12)
    target_text = target.isoformat().replace("+00:00", "Z")
    waiting = _details(probing=1, blocked=True, next_due=target_text)
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
    assert [call[0][3] for call in runner.calls[1:]] == [
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

    assert validations == [0.0, 0.0, 0.0, 0.0, 0.0, 60.0, 65.0, 65.0, 65.0, 65.0, 65.0]
    assert [call[0][3] for call in runner.calls[1:]] == [
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
    assert sum(call[0][3] == "acquisition-run" for call in runner.calls[1:]) == 1


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


@pytest.mark.parametrize(
    "field",
    [
        "acquisition_schema_version",
        "navigation_implementation",
        "cdp_target_instrumentation_policy",
        "passive_render_contract",
        "passive_render_contract_sha256",
        "browser_navigation_timeout_ms",
        "passive_render_hard_cap_after_load_ms",
        "acquisition_action_timing_contract",
        "baseline_scheduling_contract",
        "origin_policy",
    ],
)
def test_watcher_rejects_discovery_contract_drift(
    acquisition: Fixture, field: str
) -> None:
    provenance = json.loads(acquisition.paths.provenance.read_text(encoding="utf-8"))
    payload = copy.deepcopy(provenance["payload"])
    if field == "passive_render_contract":
        payload[field]["minimum_after_load_ms"] += 1
    elif field == "acquisition_action_timing_contract":
        payload[field]["inner_timeout"]["soft_deadline_ms"] -= 1
    elif field == "baseline_scheduling_contract":
        payload[field]["minimum_baseline_spacing_ms"] -= 1
    elif field.endswith("_ms") or field == "acquisition_schema_version":
        payload[field] -= 1
    else:
        payload[field] = "stale-contract"
    _write_receipt(acquisition.paths.provenance, watch.PROVENANCE_TYPE, payload)

    with pytest.raises(watch.WatchError, match="another study or catalogue"):
        watch._validate_immutable_binding(acquisition.paths)


def test_watcher_reconciles_baseline_batches_with_candidate_state(
    acquisition: Fixture,
) -> None:
    payload = _checkpoint_payload(acquisition)
    candidate_ids = acquisition.candidate_ids[:2]
    baseline_started_at = "2026-08-29T01:00:00Z"
    for index, candidate_id in enumerate(candidate_ids):
        payload["candidates"][candidate_id] = {
            "state": "probing",
            "pages": [{"page": {"ordinal": index}}],
            "terminal": None,
            "baseline_started_at": baseline_started_at,
        }
    payload["baseline_batches"] = [
        _batch(
            "baseline",
            {
                "baseline_started_at": baseline_started_at,
                "candidate_ids": candidate_ids,
                "live_page_count": 2,
            },
        )
    ]
    _replace_checkpoint(acquisition, payload)
    binding = watch._validate_immutable_binding(acquisition.paths)
    watch._validate_checkpoint(acquisition.paths, binding)

    mutations = (
        lambda value: value["baseline_batches"][0].__setitem__(
            "live_page_count", 1
        ),
        lambda value: value["candidates"][candidate_ids[0]].__setitem__(
            "baseline_started_at", "2026-08-29T01:00:01Z"
        ),
        lambda value: value["baseline_batches"].append(
            copy.deepcopy(value["baseline_batches"][0])
        ),
        lambda value: value["baseline_batches"][0]["candidate_ids"].reverse(),
        lambda value: value["baseline_batches"].clear(),
    )
    for mutate in mutations:
        invalid = copy.deepcopy(payload)
        mutate(invalid)
        # Recompute content addressing only when the mutation is intended to
        # exercise cross-ledger truth rather than the ID check itself.
        if len(invalid["baseline_batches"]) == 1:
            body = {
                name: item
                for name, item in invalid["baseline_batches"][0].items()
                if name != "batch_id"
            }
            invalid["baseline_batches"][0] = _batch("baseline", body)
        _replace_checkpoint(acquisition, invalid)
        with pytest.raises(watch.WatchError, match="baseline batch"):
            watch._validate_checkpoint(acquisition.paths, binding)


def test_watcher_rejects_cross_offset_baseline_batch_collision(
    acquisition: Fixture,
) -> None:
    payload = _checkpoint_payload(acquisition)
    candidate_ids = acquisition.candidate_ids[:2]
    starts = ("2026-08-29T01:00:00Z", "2026-08-31T01:00:00Z")
    batches = []
    for candidate_id, started_at in zip(candidate_ids, starts, strict=True):
        payload["candidates"][candidate_id] = {
            "state": "probing",
            "pages": [{"page": {"ordinal": 0}}],
            "terminal": None,
            "baseline_started_at": started_at,
        }
        batches.append(
            _batch(
                "baseline",
                {
                    "baseline_started_at": started_at,
                    "candidate_ids": [candidate_id],
                    "live_page_count": 1,
                },
            )
        )
    payload["baseline_batches"] = batches
    _replace_checkpoint(acquisition, payload)

    with pytest.raises(watch.WatchError, match="violate the serial schedule"):
        watch._validate_checkpoint(
            acquisition.paths,
            watch._validate_immutable_binding(acquisition.paths),
        )


def test_watcher_reconciles_transactional_navigation_batch(
    acquisition: Fixture,
) -> None:
    payload = _checkpoint_payload(acquisition)
    candidate_ids = acquisition.candidate_ids[:2]
    started_at = "2026-08-29T01:00:00Z"
    attempts = []
    for candidate_id in candidate_ids:
        payload["candidates"][candidate_id]["pending_navigation"] = {
            "attempt": 1,
            "started_at": started_at,
        }
        attempts.append(
            {
                "candidate_id": candidate_id,
                "page_ordinal": None,
                "probe_id": None,
                "workload_id": None,
                "attempt": 1,
                "started_at": started_at,
            }
        )
    payload["active_batch"] = _batch(
        "active",
        {
            "active_batch_schema_version": 1,
            "stage": "navigation",
            "published_at": started_at,
            "candidate_ids": candidate_ids,
            "live_page_count": 2,
            "attempts": attempts,
        },
    )
    _replace_checkpoint(acquisition, payload)
    binding = watch._validate_immutable_binding(acquisition.paths)
    watch._validate_checkpoint(acquisition.paths, binding)

    invalid = copy.deepcopy(payload)
    invalid["active_batch"]["stage"] = "baseline"
    body = {name: item for name, item in invalid["active_batch"].items() if name != "batch_id"}
    invalid["active_batch"] = _batch("active", body)
    _replace_checkpoint(acquisition, invalid)
    with pytest.raises(watch.WatchError, match="active batch stage"):
        watch._validate_checkpoint(acquisition.paths, binding)

    invalid = copy.deepcopy(payload)
    invalid["active_batch"]["published_at"] = "2026-08-29T01:00:00.000000Z"
    for attempt in invalid["active_batch"]["attempts"]:
        attempt["started_at"] = invalid["active_batch"]["published_at"]
        invalid["candidates"][attempt["candidate_id"]]["pending_navigation"][
            "started_at"
        ] = invalid["active_batch"]["published_at"]
    body = {
        name: item
        for name, item in invalid["active_batch"].items()
        if name != "batch_id"
    }
    invalid["active_batch"] = _batch("active", body)
    _replace_checkpoint(acquisition, invalid)
    with pytest.raises(watch.WatchError, match="canonical UTC timestamp"):
        watch._validate_checkpoint(acquisition.paths, binding)

    invalid = copy.deepcopy(payload)
    invalid["candidates"][candidate_ids[0]]["pending_navigation"]["attempt"] = 2
    _replace_checkpoint(acquisition, invalid)
    with pytest.raises(watch.WatchError, match="differ from pending candidate state"):
        watch._validate_checkpoint(acquisition.paths, binding)

def test_watcher_reconciles_transactional_probe_batch(
    acquisition: Fixture,
) -> None:
    payload = _checkpoint_payload(acquisition)
    candidate_id = acquisition.candidate_ids[0]
    baseline_started_at = "2026-08-29T00:59:30Z"
    started_at = "2026-08-29T01:00:00Z"
    workload_id = f"{candidate_id}-p00-t30s-a001"
    pending_probe = {
        "probe_id": "t+30s",
        "workload_id": workload_id,
        "attempt": 1,
        "observed_at": started_at,
    }
    payload["candidates"][candidate_id] = {
        "state": "probing",
        "pages": [{"page": {"ordinal": 0}, "pending_probe": pending_probe}],
        "terminal": None,
        "baseline_started_at": baseline_started_at,
    }
    payload["baseline_batches"] = [
        _batch(
            "baseline",
            {
                "baseline_started_at": baseline_started_at,
                "candidate_ids": [candidate_id],
                "live_page_count": 1,
            },
        )
    ]
    payload["active_batch"] = _batch(
        "active",
        {
            "active_batch_schema_version": 1,
            "stage": "probe",
            "published_at": started_at,
            "candidate_ids": [candidate_id],
            "live_page_count": 1,
            "attempts": [
                {
                    "candidate_id": candidate_id,
                    "page_ordinal": 0,
                    "probe_id": "t+30s",
                    "workload_id": workload_id,
                    "attempt": 1,
                    "started_at": started_at,
                }
            ],
        },
    )
    _replace_checkpoint(acquisition, payload)
    binding = watch._validate_immutable_binding(acquisition.paths)
    watch._validate_checkpoint(acquisition.paths, binding)

    invalid = copy.deepcopy(payload)
    invalid["active_batch"]["attempts"][0]["page_ordinal"] = 1
    body = {name: item for name, item in invalid["active_batch"].items() if name != "batch_id"}
    invalid["active_batch"] = _batch("active", body)
    _replace_checkpoint(acquisition, invalid)
    with pytest.raises(watch.WatchError, match="differ from pending candidate state"):
        watch._validate_checkpoint(acquisition.paths, binding)

    invalid = copy.deepcopy(payload)
    second_workload = f"{candidate_id}-p01-t24h-a001"
    invalid["candidates"][candidate_id]["pages"].append(
        {
            "page": {"ordinal": 1},
            "pending_probe": {
                "probe_id": "t+24h",
                "workload_id": second_workload,
                "attempt": 1,
                "observed_at": started_at,
            },
        }
    )
    baseline_body = {
        name: item
        for name, item in invalid["baseline_batches"][0].items()
        if name != "batch_id"
    }
    baseline_body["live_page_count"] = 2
    invalid["baseline_batches"][0] = _batch("baseline", baseline_body)
    invalid["active_batch"]["live_page_count"] = 2
    invalid["active_batch"]["attempts"].append(
        {
            "candidate_id": candidate_id,
            "page_ordinal": 1,
            "probe_id": "t+24h",
            "workload_id": second_workload,
            "attempt": 1,
            "started_at": started_at,
        }
    )
    body = {
        name: item
        for name, item in invalid["active_batch"].items()
        if name != "batch_id"
    }
    invalid["active_batch"] = _batch("active", body)
    _replace_checkpoint(acquisition, invalid)
    with pytest.raises(watch.WatchError, match="mixes identities or windows"):
        watch._validate_checkpoint(acquisition.paths, binding)


def test_watcher_rejects_pending_attempt_without_active_batch(
    acquisition: Fixture,
) -> None:
    payload = _checkpoint_payload(acquisition)
    payload["candidates"][acquisition.candidate_ids[0]]["pending_navigation"] = {
        "attempt": 1,
        "started_at": "2026-08-29T01:00:00Z",
    }
    _replace_checkpoint(acquisition, payload)
    with pytest.raises(watch.WatchError, match="without an active batch"):
        watch._validate_checkpoint(
            acquisition.paths,
            watch._validate_immutable_binding(acquisition.paths),
        )


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


def test_launch_drift_to_a_blocked_boundary_restatuses_without_fabrication(
    acquisition: Fixture,
) -> None:
    start = datetime(2026, 8, 29, tzinfo=UTC)
    target = start + timedelta(seconds=2)
    target_text = target.isoformat().replace("+00:00", "Z")
    due = _details(probing=1, due=1, blocked=True)
    drifted = _details(probing=1, blocked=True, next_due=target_text)
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def final_run(_command, _cwd, _env):
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-run", complete))

    runner = FakeRunner(
        [
            _completed(_result("acquisition-status", due)),
            _completed(_result("acquisition-run", drifted)),
            _completed(_result("acquisition-status", drifted)),
            final_run,
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

    assert clock.value == target
    assert [call[0][3] for call in runner.calls[1:]] == [
        "acquisition-status",
        "acquisition-run",
        "acquisition-status",
        "acquisition-run",
        "acquisition-status",
    ]


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

    assert [call[0][3] for call in runner.calls[1:]] == [
        "acquisition-status",
        "acquisition-run",
        "acquisition-status",
    ]


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


def test_trusted_environment_ignores_shell_python_docker_and_home_overrides() -> None:
    environment = watch._safe_host_environment(
        {
            "PATH": "/tmp/attacker",
            "HOME": "/tmp/attacker-home",
            "BASH_ENV": "/tmp/hook",
            "PYTHONPATH": "/tmp/imports",
            "DOCKER_HOST": "tcp://attacker.example:2376",
            "DOCKER_CONTEXT": "attacker",
            "DOCKER_CONFIG": "/tmp/docker",
            "XDG_RUNTIME_DIR": "/tmp/runtime",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/bus",
        }
    )

    assert environment["PATH"] == "/usr/bin:/bin"
    assert environment["HOME"] == "/nonexistent"
    assert environment["DOCKER_CONTEXT"] == "default"
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert environment["GIT_OPTIONAL_LOCKS"] == "0"
    assert environment["XDG_RUNTIME_DIR"] == f"/run/user/{os.getuid()}"
    assert environment["DBUS_SESSION_BUS_ADDRESS"] == (
        f"unix:path=/run/user/{os.getuid()}/bus"
    )
    assert not {
        "BASH_ENV",
        "PYTHONPATH",
        "DOCKER_HOST",
        "DOCKER_CONFIG",
    } & environment.keys()


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value.pop("host_boot_id"),
        lambda value: value.__setitem__("docker_context", "attacker"),
        lambda value: value.__setitem__("docker_host", "tcp://remote:2376"),
        lambda value: value.__setitem__("docker_server_id", "bad server id"),
        lambda value: value.__setitem__("artifact_type", "other"),
    ),
)
def test_docker_admission_requires_exact_local_binding(mutation) -> None:
    value = _admission()
    mutation(value)
    with pytest.raises(watch.WatchError, match="Docker admission"):
        watch._validate_docker_admission(value)


def test_admission_precedes_first_checkpoint_read_and_source_precedes_admission(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    events: list[str] = []
    real_checkpoint = watch._validate_checkpoint

    def checkpoint(paths, binding):
        events.append("checkpoint")
        return real_checkpoint(paths, binding)

    def source(_paths, _binding):
        events.append("source")

    def runner(
        command,
        *,
        cwd,
        env,
        authority_fd,
        state_root,
        source_binding_sha256,
    ):
        assert cwd == acquisition.paths.lab_root
        assert watch.LOCK_ENV not in env
        assert authority_fd >= 0
        assert state_root == acquisition.paths.state_root
        assert re.fullmatch(r"[0-9a-f]{64}", source_binding_sha256)
        action = command[3]
        events.append(action)
        if action == "acquisition-admission":
            return _completed(_admission())
        return _completed(_result("acquisition-status", complete))

    monkeypatch.setattr(watch, "_validate_checkpoint", checkpoint)
    watch.watch_acquisition(
        paths=acquisition.paths,
        runner=runner,
        source_validator=source,
    )

    assert events.index("source") < events.index("acquisition-admission")
    assert events.index("acquisition-admission") < events.index("checkpoint")
    assert events[-2:] == ["source", "checkpoint"]


def test_status_checkpoint_race_fails_closed_after_action(acquisition: Fixture) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def status_mutation(_command, _cwd, _env):
        acquisition.advance_checkpoint()
        return _completed(_result("acquisition-status", complete))

    with pytest.raises(watch.WatchError, match="mutated or raced"):
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=FakeRunner([status_mutation]),
        )


def test_source_binding_is_rechecked_after_action(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    calls = 0

    def source(_paths, _binding):
        nonlocal calls
        calls += 1
        if calls == 4:
            raise watch.WatchError("post-action source drift")

    with pytest.raises(watch.WatchError, match="post-action source drift"):
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=FakeRunner([_completed(_result("acquisition-status", complete))]),
            source_validator=source,
        )


def test_lock_path_replacement_during_action_fails_and_new_lock_is_reacquirable(
    acquisition: Fixture,
) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)

    def replace_lock(_command, _cwd, _env):
        staged = acquisition.paths.mutation_lock.with_suffix(".replacement")
        staged.write_bytes(b"")
        os.replace(staged, acquisition.paths.mutation_lock)
        return _completed(_result("acquisition-status", complete))

    with pytest.raises(watch.WatchError, match="lock pathname identity changed"):
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=FakeRunner([replace_lock]),
        )

    descriptor = os.open(acquisition.paths.mutation_lock, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)


def test_signal_is_latched_before_lock_acquisition_and_lock_is_reacquirable(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_acquire = watch._acquire_mutation_lock

    def acquire(path):
        descriptor = real_acquire(path)
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler)
        handler(signal.SIGTERM, None)
        return descriptor

    monkeypatch.setattr(watch, "_acquire_mutation_lock", acquire)
    with pytest.raises(watch.WatchSignalInterrupt) as interrupted:
        watch.watch_acquisition(paths=acquisition.paths, runner=FakeRunner([]))
    assert interrupted.value.signum == signal.SIGTERM

    descriptor = os.open(acquisition.paths.mutation_lock, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)


def test_signal_latched_after_final_success_check_is_not_swallowed(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    complete = _details(terminal=watch.CANDIDATE_COUNT)
    original_raise = watch._SignalLatch.raise_if_set
    checks = 0

    def latch_immediately_after_fourth_check(latch: watch._SignalLatch) -> None:
        nonlocal checks
        checks += 1
        original_raise(latch)
        if checks == 4:
            handler = signal.getsignal(signal.SIGTERM)
            assert callable(handler)
            handler(signal.SIGTERM, None)

    monkeypatch.setattr(
        watch._SignalLatch,
        "raise_if_set",
        latch_immediately_after_fourth_check,
    )
    with pytest.raises(watch.WatchSignalInterrupt) as interrupted:
        watch.watch_acquisition(
            paths=acquisition.paths,
            runner=FakeRunner([_completed(_result("acquisition-status", complete))]),
        )
    assert interrupted.value.signum == signal.SIGTERM
    assert checks == 4
    assert watch._active_signal_latch is None

    descriptor = os.open(acquisition.paths.mutation_lock, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)


def test_signal_latch_unblocks_watched_signal_and_restores_exact_prior_mask() -> None:
    original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
    entered_mask = set(original_mask) | {signal.SIGTERM}
    try:
        with pytest.raises(watch.WatchSignalInterrupt) as interrupted:
            with watch._SignalLatch() as latch:
                active_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
                assert active_mask == entered_mask.difference(latch.watched)
                os.kill(os.getpid(), signal.SIGTERM)
        assert interrupted.value.signum == signal.SIGTERM
        restored_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        assert restored_mask == entered_mask
    finally:
        if signal.SIGTERM in signal.sigpending():
            signal.sigwait({signal.SIGTERM})
        signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)


@pytest.mark.parametrize(
    ("signum", "status"),
    (
        (signal.SIGHUP, 129),
        (signal.SIGINT, 130),
        (signal.SIGQUIT, 131),
        (signal.SIGTERM, 143),
    ),
)
def test_main_maps_latched_terminal_signals_to_resume_status(
    signum: int,
    status: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        watch,
        "watch_acquisition",
        lambda **_kwargs: (_ for _ in ()).throw(watch.WatchSignalInterrupt(signum)),
    )
    assert watch.main([]) == status
    assert "resume from checkpoint" in capsys.readouterr().err


def test_stable_receipt_read_detects_path_replacement(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_read = watch.os.read
    replaced = False

    def racing_read(descriptor: int, length: int) -> bytes:
        nonlocal replaced
        content = real_read(descriptor, length)
        if content and not replaced:
            replaced = True
            replacement = acquisition.paths.checkpoint.with_suffix(".replacement")
            replacement.write_bytes(acquisition.paths.checkpoint.read_bytes())
            os.replace(replacement, acquisition.paths.checkpoint)
        return content

    monkeypatch.setattr(watch.os, "read", racing_read)
    with pytest.raises(watch.WatchError, match="changed while it was read"):
        watch._read_stable_file(
            acquisition.paths.checkpoint,
            root=acquisition.paths.lab_root,
            label="checkpoint",
        )


def test_host_source_validator_uses_two_identical_fixed_git_snapshots(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = watch._validate_acquisition_binding(acquisition.paths)
    calls: list[tuple[tuple[str, ...], Path | None]] = []

    def git_text(_paths, *arguments, cwd=None):
        calls.append((arguments, cwd))
        if arguments == ("rev-parse", "HEAD"):
            return (
                binding.source["neqo_commit"]
                if cwd == acquisition.paths.lab_root / "neqo-qcsd"
                else binding.source["lab_commit"]
            )
        if arguments == ("ls-files", "--stage", "--", "neqo-qcsd"):
            return f"160000 {binding.source['neqo_pinned_commit']} 0\tneqo-qcsd"
        if arguments == ("status", "--porcelain", "--untracked-files=all"):
            return ""
        raise AssertionError((arguments, cwd))

    monkeypatch.setattr(watch, "_git_text", git_text)
    monkeypatch.setattr(watch, "_verify_git_checkout_binding", lambda *_args: None)
    monkeypatch.setattr(watch, "_verify_git_index_bytes", lambda *_args: None)
    _REAL_VALIDATE_HOST_SOURCE(acquisition.paths, binding)
    assert len(calls) == 10


def test_host_source_validator_rejects_snapshot_race(
    acquisition: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = watch._validate_acquisition_binding(acquisition.paths)
    snapshots = iter(
        (
            ("a", "b", "c", "", ""),
            ("a", "b", "c", " M raced", ""),
        )
    )
    monkeypatch.setattr(watch, "_host_source_snapshot", lambda _paths: next(snapshots))
    with pytest.raises(watch.WatchError, match="changed while source was verified"):
        _REAL_VALIDATE_HOST_SOURCE(acquisition.paths, binding)


def test_watch_git_verifier_rejects_clean_filter_bytes(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    subprocess.run(("git", "-C", checkout, "init", "-q"), check=True)
    subprocess.run(("git", "-C", checkout, "config", "user.name", "test"), check=True)
    subprocess.run(("git", "-C", checkout, "config", "user.email", "test@example.invalid"), check=True)
    (checkout / "payload").write_bytes(b"clean")
    (checkout / ".gitattributes").write_text("payload filter=hide\n", encoding="ascii")
    subprocess.run(("git", "-C", checkout, "add", "."), check=True)
    subprocess.run(("git", "-C", checkout, "commit", "-qm", "initial"), check=True)
    subprocess.run(
        ("git", "-C", checkout, "config", "filter.hide.clean", "printf clean"),
        check=True,
    )
    (checkout / "payload").write_bytes(b"evil!")
    assert subprocess.check_output(
        ("git", "-C", checkout, "status", "--porcelain")
    ) == b""
    paths = watch.WatchPaths.from_lab_root(checkout, state_base=tmp_path / "state")
    watch._verify_git_checkout_binding(paths, checkout, checkout / ".git")
    with pytest.raises(watch.WatchError, match="raw bytes"):
        watch._verify_git_index_bytes(paths, checkout)


def test_watch_git_binding_rejects_local_exclude_and_worktree_redirect(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "checkout"
    alternate = tmp_path / "alternate"
    checkout.mkdir()
    alternate.mkdir()
    subprocess.run(("git", "-C", checkout, "init", "-q"), check=True)
    paths = watch.WatchPaths.from_lab_root(checkout, state_base=tmp_path / "state")
    (checkout / ".git/info/exclude").write_text("hidden.py\n", encoding="ascii")
    with pytest.raises(watch.WatchError, match="hide checkout bytes"):
        watch._verify_git_checkout_binding(paths, checkout, checkout / ".git")
    (checkout / ".git/info/exclude").write_text("# comments only\n", encoding="ascii")
    subprocess.run(
        ("git", "-C", checkout, "config", "core.worktree", str(alternate)), check=True
    )
    with pytest.raises(watch.WatchError, match="redirected worktree"):
        watch._verify_git_checkout_binding(paths, checkout, checkout / ".git")


def _scope_inventory(state_root: Path | None = None) -> tuple[set[Path], set[str]]:
    roots = set(state_root.glob("scope.*")) if state_root is not None else set()
    completed = subprocess.run(
        (
            "/usr/bin/systemctl",
            "--user",
            "list-units",
            "--all",
            "--plain",
            "--no-legend",
            "qcsd-class-watch-*.scope",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=5,
        env=watch._safe_host_environment(),
    )
    if completed.returncode != 0:
        pytest.skip("user systemd is unavailable")
    units = {line.split()[0] for line in completed.stdout.splitlines() if line.split()}
    return roots, units


def _force_remove_test_scope_root(root: Path, *, state_root: Path) -> None:
    """Remove a test-owned inert fixture, including deliberately corrupt records."""
    assert root.parent == state_root
    token = root.name.rsplit(".", 1)[-1]
    assert re.fullmatch(r"[0-9a-f]{32}", token)
    assert watch._wait_scope_absent(
        f"qcsd-class-watch-{token}.scope", watch._safe_host_environment()
    )
    for child in root.iterdir():
        assert child.is_file() and not child.is_symlink()
        child.unlink()
    root.rmdir()


def _scope_test_state(tmp_path: Path) -> tuple[Path, int]:
    paths = watch.WatchPaths.from_lab_root(
        tmp_path,
        state_base=tmp_path / "watch-state",
    )
    state_root = watch._ensure_state_namespace(paths)
    descriptor = watch._acquire_mutation_lock(paths.mutation_lock)
    return state_root, descriptor


def test_state_namespace_promotes_exact_interrupted_publication(tmp_path: Path) -> None:
    paths = watch.WatchPaths.from_lab_root(
        tmp_path / "lab",
        state_base=tmp_path / "watch-state",
    )
    watch._create_private_state_directory(paths.state_base, label="test state base")
    watch._create_private_state_directory(paths.state_root, label="test state namespace")
    expected = dict(watch._state_namespace_identity(paths))
    expected["namespace_sha256"] = paths.namespace_sha256
    staged = paths.state_root / "NAMESPACE.json.next"
    staged.write_bytes(_canonical(expected))
    staged.chmod(0o600)

    assert watch._ensure_state_namespace(paths) == paths.state_root
    assert (paths.state_root / "NAMESPACE.json").read_bytes() == _canonical(expected)
    assert not staged.exists()


def test_state_namespace_removes_only_safe_stale_publication(tmp_path: Path) -> None:
    paths = watch.WatchPaths.from_lab_root(
        tmp_path / "lab",
        state_base=tmp_path / "watch-state",
    )
    state_root = watch._ensure_state_namespace(paths)
    staged = state_root / "NAMESPACE.json.next"
    staged.write_bytes(b"interrupted publication")
    staged.chmod(0o600)

    assert watch._ensure_state_namespace(paths) == state_root
    assert not staged.exists()


def test_state_namespace_does_not_replace_unsafe_receipt_path(tmp_path: Path) -> None:
    paths = watch.WatchPaths.from_lab_root(
        tmp_path / "lab",
        state_base=tmp_path / "watch-state",
    )
    watch._create_private_state_directory(paths.state_base, label="test state base")
    watch._create_private_state_directory(paths.state_root, label="test state namespace")
    namespace = paths.state_root / "NAMESPACE.json"
    namespace.symlink_to(tmp_path / "missing-target")

    with pytest.raises(watch.WatchError, match="private single regular file"):
        watch._ensure_state_namespace(paths)
    assert namespace.is_symlink()


def _publish_test_scope_request(
    root: Path,
    supervision: dict[str, Any],
    *,
    wrapper_pid: int,
) -> None:
    request = {
        "action_sha256": supervision["action_sha256"],
        "artifact_type": "qcsd-class-watch-scope-request",
        "request_authority_sha256": supervision["request_authority_sha256"],
        "request_nonce": supervision["request_nonce"],
        "schema_version": 1,
        "scope_token": supervision["scope_token"],
        "scope_unit": supervision["scope_unit"],
        "source_binding_sha256": supervision["source_binding_sha256"],
        "state_namespace_sha256": supervision["state_namespace_sha256"],
        "wrapper_pid": wrapper_pid,
    }
    (root / "REQUEST").write_bytes(_canonical(request))
    (root / "REQUEST").chmod(0o600)


def _locked_descriptor(path: Path) -> int:
    path.write_bytes(b"")
    descriptor = os.open(path, os.O_RDWR)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return descriptor


def test_real_scope_gates_execution_authenticates_current_scope_and_leaves_no_residue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    marker = tmp_path / "action-started"
    lock_state = os.fstat(descriptor)
    lock_identity = f"{lock_state.st_dev}:{lock_state.st_ino}"
    real_publish = watch._publish_scope_go

    def publish(root: Path, *, authority: str) -> None:
        assert not marker.exists()
        record, _, recovery = watch._read_scope_record(root, state_root=state_root)
        assert recovery is False
        assert record["phase"] == "armed-for-exec"
        real_publish(root, authority=authority)

    monkeypatch.setattr(watch, "_publish_scope_go", publish)
    try:
        completed = watch._subprocess_runner(
            (
                "/usr/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                    (
                        f"birth_identity=$(/usr/bin/stat -Lc '%d:%i' "
                        f"\"${{{watch.SCOPE_ROOT_ENV}}}/BIRTH.lock\") || exit 89; "
                        "for fd_path in /proc/$$/fd/*; do "
                        "observed=$(/usr/bin/stat -Lc '%d:%i' -- \"${fd_path}\") || exit 90; "
                        f"test \"${{observed}}\" != {lock_identity} || exit 91; "
                        "test \"${observed}\" != \"${birth_identity}\" || exit 92; "
                        "done; "
                        f"test ! -e /proc/$$/fd/{descriptor} && "
                            "printf started >\"$1\""
                    ),
                    "acquisition-admission",
                    str(marker),
                ),
            cwd=tmp_path,
            env={},
            authority_fd=descriptor,
            state_root=state_root,
            source_binding_sha256="a" * 64,
        )
    finally:
        os.close(descriptor)
    assert completed.returncode == 0
    assert completed.stdout == ""
    assert completed.stderr == ""
    assert marker.read_text(encoding="ascii") == "started"
    assert _scope_inventory(state_root) == before


def test_pending_signal_at_scope_decision_never_publishes_go_or_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    marker = tmp_path / "action-started"
    published = False
    real_publish = watch._publish_scope_go

    def publish(root: Path, *, authority: str) -> None:
        nonlocal published
        published = True
        real_publish(root, authority=authority)

    monkeypatch.setattr(watch, "_publish_scope_go", publish)
    monkeypatch.setattr(watch.signal, "sigpending", lambda: {signal.SIGTERM})
    try:
        with pytest.raises(watch.WatchSignalInterrupt) as interrupted:
            watch._subprocess_runner(
                (
                    "/usr/bin/bash",
                    "--noprofile",
                    "--norc",
                    "-c",
                    'printf started >"$1"',
                    "acquisition-admission",
                    str(marker),
                ),
                cwd=tmp_path,
                env={},
                authority_fd=descriptor,
                state_root=state_root,
                source_binding_sha256="a" * 64,
            )
    finally:
        os.close(descriptor)
    assert interrupted.value.signum == signal.SIGTERM
    assert published is False
    assert not marker.exists()
    assert _scope_inventory(state_root) == before


@pytest.mark.parametrize("mismatch", ("action", "source"))
def test_internal_scope_admission_rejects_expected_binding_mismatch(
    tmp_path: Path,
    mismatch: str,
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    action_value = (
        "b" * 64 if mismatch == "action" else f"${{{watch.SCOPE_ACTION_ENV}}}"
    )
    source_value = (
        "b" * 64 if mismatch == "source" else f"${{{watch.SCOPE_SOURCE_ENV}}}"
    )
    script = (
        "exec /usr/bin/python3 -I \"$1\" "
        "--recover-stale-scopes-internal "
        f"--state-root-internal \"${{{watch.SCOPE_STATE_ROOT_ENV}}}\" "
        f"--current-scope-root-internal \"${{{watch.SCOPE_ROOT_ENV}}}\" "
        f"--current-authority-internal \"${{{watch.SCOPE_AUTHORITY_ENV}}}\" "
        f"--expected-action-sha256-internal \"{action_value}\" "
        f"--expected-source-binding-sha256-internal \"{source_value}\""
    )
    try:
        completed = watch._subprocess_runner(
            (
                "/usr/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                script,
                "acquisition-admission",
                str(Path(__file__).parents[1] / "tools/class_acquisition_watch.py"),
            ),
            cwd=tmp_path,
            env={},
            authority_fd=descriptor,
            state_root=state_root,
            source_binding_sha256="a" * 64,
        )
    finally:
        os.close(descriptor)
    assert completed.returncode == 1
    assert "scope recovery failed" in completed.stderr
    assert _scope_inventory(state_root) == before


@pytest.mark.parametrize(
    "omitted",
    ("--expected-action-sha256-internal", "--expected-source-binding-sha256-internal"),
)
def test_internal_recovery_cli_requires_both_expected_bindings(
    tmp_path: Path,
    omitted: str,
) -> None:
    arguments = [
        "--recover-stale-scopes-internal",
        "--state-root-internal",
        str(tmp_path / "state"),
        "--current-scope-root-internal",
        str(tmp_path / "scope"),
        "--current-authority-internal",
        "a" * 64,
        "--expected-action-sha256-internal",
        "b" * 64,
        "--expected-source-binding-sha256-internal",
        "c" * 64,
    ]
    index = arguments.index(omitted)
    del arguments[index : index + 2]

    assert watch.main(arguments) == 1


@pytest.mark.parametrize("redirect", (True, False), ids=("closed-stdio", "retained-stdio"))
def test_real_scope_kills_setsid_descendant_fails_and_releases_inherited_lock(
    tmp_path: Path,
    redirect: bool,
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    lock_path = state_root / "WATCH.lock"
    try:
        with pytest.raises(watch.WatchError, match="surviving cgroup descendant"):
            watch._subprocess_runner(
                (
                    "/usr/bin/bash",
                    "--noprofile",
                    "--norc",
                    "-c",
                    (
                        "/usr/bin/setsid /usr/bin/bash --noprofile --norc -c "
                        f"'{('exec >/dev/null 2>&1; ' if redirect else '')}"
                        "/usr/bin/sleep 60' & "
                        "printf 'parent-finished\\n'"
                    ),
                    "acquisition-status",
                ),
                cwd=tmp_path,
                env={},
                authority_fd=descriptor,
                state_root=state_root,
                source_binding_sha256="a" * 64,
            )
    finally:
        os.close(descriptor)

    reacquired = os.open(lock_path, os.O_RDWR)
    try:
        fcntl.flock(reacquired, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(reacquired)
    assert _scope_inventory(state_root) == before


def test_stale_durable_scope_record_is_sigkilled_recovered_and_removed(
    tmp_path: Path,
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    token = "f" * 32
    unit = f"qcsd-class-watch-{token}.scope"
    root, supervision, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit=unit,
        command=("/usr/bin/sleep", "60", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    os.close(birth_lock_fd)
    stale = dict(supervision)
    stale.update(
        {
            "supervisor_pid": 999_999_999,
            "supervisor_start_time": 1,
            "supervisor_session": 1,
            "supervisor_process_group": 1,
        }
    )
    environment = watch._safe_host_environment()
    process = subprocess.Popen(
        (
            "/usr/bin/systemd-run",
            "--user",
            "--scope",
            "--collect",
            "--quiet",
            "--expand-environment=no",
            f"--unit={unit}",
            "--property=KillMode=control-group",
            "--property=KillSignal=SIGKILL",
            "--",
            "/usr/bin/sleep",
            "60",
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
        start_new_session=True,
    )
    try:
        deadline = watch.time.monotonic() + 5
        while watch.time.monotonic() < deadline:
            state = watch._scope_state(unit, environment)
            if state.processes:
                break
            watch.time.sleep(0.05)
        else:
            pytest.fail("test scope did not become populated")
        wrapper_pid = next(pid for pid in state.processes if pid > 0)
        _publish_test_scope_request(root, stale, wrapper_pid=wrapper_pid)
        wrapper_process = watch._process_identity(wrapper_pid)
        assert wrapper_process is not None
        start_time, session, process_group = wrapper_process
        armed = watch._replace_scope_phase(
            root,
            stale,
            phase="request-authorised",
            wrapper_identity=(wrapper_pid, start_time, session, process_group),
            state_root=state_root,
        )
        watch._replace_scope_phase(
            root,
            armed,
            phase="armed-for-exec",
            wrapper_identity=(wrapper_pid, start_time, session, process_group),
            state_root=state_root,
        )

        assert watch._recover_stale_scope_roots(state_root=state_root) == 1
        process.communicate(timeout=5)
    finally:
        if process.poll() is None:
            subprocess.run(
                (
                    "/usr/bin/systemctl",
                    "--user",
                    "kill",
                    "--kill-whom=all",
                    "--signal=SIGKILL",
                    "--",
                    unit,
                ),
                env=environment,
                check=False,
                timeout=5,
            )
            process.kill()
            process.communicate(timeout=5)
        os.close(descriptor)
    assert not root.exists()
    assert _scope_inventory(state_root) == before


def test_sigkill_supervisor_releases_lock_and_restart_recovers_live_scope(
    tmp_path: Path,
) -> None:
    paths = watch.WatchPaths.from_lab_root(
        tmp_path,
        state_base=tmp_path / "watch-state",
    )
    state_root = watch._ensure_state_namespace(paths)
    before = _scope_inventory(state_root)
    marker = tmp_path / "action-started"
    repository = Path(__file__).parents[1]
    child_program = """
import os
import sys
from pathlib import Path
from tools import class_acquisition_watch as watch

paths = watch.WatchPaths.from_lab_root(Path(sys.argv[1]), state_base=Path(sys.argv[2]))
state_root = watch._ensure_state_namespace(paths)
descriptor = watch._acquire_mutation_lock(paths.mutation_lock)
command = (
    "/usr/bin/bash", "--noprofile", "--norc", "-c",
    f"printf started > {sys.argv[3]}; /usr/bin/sleep 60",
    "acquisition-status",
)
try:
    watch._subprocess_runner(
        command,
        cwd=Path(sys.argv[1]),
        env={},
        authority_fd=descriptor,
        state_root=state_root,
        source_binding_sha256="a" * 64,
    )
finally:
    os.close(descriptor)
"""
    supervisor = subprocess.Popen(
        (
            sys.executable,
            "-c",
            child_program,
            str(tmp_path),
            str(paths.state_base),
            str(marker),
        ),
        cwd=repository,
        env=watch._safe_host_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    recovered_descriptor: int | None = None
    environment = watch._safe_host_environment()
    try:
        deadline = watch.time.monotonic() + 10
        scope_root: Path | None = None
        while watch.time.monotonic() < deadline:
            roots = list(state_root.glob("scope.*"))
            if len(roots) == 1 and marker.exists():
                record, _, recovery = watch._read_scope_record(
                    roots[0],
                    state_root=state_root,
                )
                if not recovery and record["phase"] == "armed-for-exec":
                    scope_root = roots[0]
                    break
            watch.time.sleep(0.05)
        assert scope_root is not None, "supervised action did not become armed"

        supervisor.kill()
        assert supervisor.wait(timeout=5) == -signal.SIGKILL

        # The scoped action never inherited this supervisory lock, so a new
        # watcher can acquire it immediately and recover the still-live unit.
        recovered_descriptor = watch._acquire_mutation_lock(paths.mutation_lock)
        assert watch._recover_stale_scope_roots(state_root=state_root) == 1
        assert not scope_root.exists()
    finally:
        if supervisor.poll() is None:
            supervisor.kill()
            supervisor.wait(timeout=5)
        for scope_root in list(state_root.glob("scope.*")):
            token = scope_root.name.rsplit(".", 1)[1]
            unit = f"qcsd-class-watch-{token}.scope"
            subprocess.run(
                (
                    "/usr/bin/systemctl",
                    "--user",
                    "kill",
                    "--kill-whom=all",
                    "--signal=SIGKILL",
                    "--",
                    unit,
                ),
                env=environment,
                check=False,
                timeout=5,
            )
            watch._wait_scope_empty(
                unit,
                environment,
                deadline=watch.time.monotonic() + 5,
            )
            if scope_root.exists():
                _force_remove_test_scope_root(scope_root, state_root=state_root)
        if recovered_descriptor is not None:
            os.close(recovered_descriptor)
    assert _scope_inventory(state_root) == before


@pytest.mark.parametrize(
    "interruption_phase",
    ("after-popen-before-request", "request-authorised", "armed-for-exec"),
)
def test_sigkill_handshake_restart_closes_delayed_scope_birth(
    tmp_path: Path,
    interruption_phase: str,
) -> None:
    paths = watch.WatchPaths.from_lab_root(
        tmp_path,
        state_base=tmp_path / "watch-state",
    )
    state_root = watch._ensure_state_namespace(paths)
    before = _scope_inventory(state_root)
    marker = tmp_path / "interruption-point"
    repository = Path(__file__).parents[1]
    child_program = r'''
import os
import subprocess
import sys
import time
from pathlib import Path
from tools import class_acquisition_watch as watch

paths = watch.WatchPaths.from_lab_root(Path(sys.argv[1]), state_base=Path(sys.argv[2]))
state_root = watch._ensure_state_namespace(paths)
descriptor = watch._acquire_mutation_lock(paths.mutation_lock)
marker = Path(sys.argv[3])
phase = sys.argv[4]
if phase == "after-popen-before-request":
    watch._SCOPE_WRAPPER = (
        "/usr/bin/sleep 1\n" + watch._SCOPE_WRAPPER.replace("{1..300}", "{1..20}")
    )
    real_popen = subprocess.Popen
    def delayed_popen(command, **kwargs):
        process = real_popen(command, **kwargs)
        if isinstance(command, tuple) and watch._HOST_SCOPE_LAUNCHER in command:
            marker.write_text("after-popen-before-request", encoding="ascii")
        return process
    watch.subprocess.Popen = delayed_popen
else:
    watch._SCOPE_WRAPPER = watch._SCOPE_WRAPPER.replace("{1..300}", "{1..100}")
    real_replace = watch._replace_scope_phase
    def delayed_phase(root, supervision, *, phase: str, wrapper_identity, state_root):
        updated = real_replace(
            root,
            supervision,
            phase=phase,
            wrapper_identity=wrapper_identity,
            state_root=state_root,
        )
        if phase == sys.argv[4]:
            marker.write_text(phase, encoding="ascii")
            time.sleep(60)
        return updated
    watch._replace_scope_phase = delayed_phase
command = (
    "/usr/bin/bash", "--noprofile", "--norc", "-c", "/usr/bin/sleep 60",
    "acquisition-status",
)
try:
    watch._subprocess_runner(
        command,
        cwd=Path(sys.argv[1]),
        env={},
        authority_fd=descriptor,
        state_root=state_root,
        source_binding_sha256="a" * 64,
    )
finally:
    os.close(descriptor)
'''
    supervisor = subprocess.Popen(
        (
            sys.executable,
            "-c",
            child_program,
            str(tmp_path),
            str(paths.state_base),
            str(marker),
            interruption_phase,
        ),
        cwd=repository,
        env=watch._safe_host_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    recovered_descriptor: int | None = None
    environment = watch._safe_host_environment()
    try:
        deadline = watch.time.monotonic() + 10
        scope_root: Path | None = None
        while watch.time.monotonic() < deadline:
            roots = list(state_root.glob("scope.*"))
            if len(roots) == 1 and marker.exists():
                scope_root = roots[0]
                if interruption_phase == "after-popen-before-request":
                    assert not (scope_root / "REQUEST").exists()
                break
            if supervisor.poll() is not None:
                pytest.fail("test supervisor exited before the requested interruption")
            watch.time.sleep(0.05)
        assert scope_root is not None, "supervisor did not reach the interruption point"

        supervisor.kill()
        assert supervisor.wait(timeout=5) == -signal.SIGKILL
        recovered_descriptor = watch._acquire_mutation_lock(paths.mutation_lock)
        assert watch._recover_stale_scope_roots(state_root=state_root) == 1
        watch.time.sleep(0.2)
        assert not scope_root.exists()
    finally:
        if supervisor.poll() is None:
            supervisor.kill()
            supervisor.wait(timeout=5)
        for scope_root in list(state_root.glob("scope.*")):
            token = scope_root.name.rsplit(".", 1)[1]
            unit = f"qcsd-class-watch-{token}.scope"
            subprocess.run(
                (
                    "/usr/bin/systemctl",
                    "--user",
                    "kill",
                    "--kill-whom=all",
                    "--signal=SIGKILL",
                    "--",
                    unit,
                ),
                env=environment,
                check=False,
                timeout=5,
            )
            watch._wait_scope_empty(
                unit,
                environment,
                deadline=watch.time.monotonic() + 5,
            )
            try:
                birth_fd = watch._wait_scope_birth_lock(
                    scope_root,
                    record=None,
                    deadline=watch.time.monotonic() + 5,
                )
            except watch.WatchError:
                birth_fd = None
            if birth_fd is not None:
                os.close(birth_fd)
            if scope_root.exists():
                _force_remove_test_scope_root(scope_root, state_root=state_root)
        if recovered_descriptor is not None:
            os.close(recovered_descriptor)
    assert _scope_inventory(state_root) == before


def test_prelaunch_scope_publication_failure_removes_staged_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    real_replace = watch.os.replace
    calls = 0

    def replace(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected directory publication failure")
        return real_replace(source, destination)

    monkeypatch.setattr(watch.os, "replace", replace)
    try:
        with pytest.raises(watch.WatchError, match="durable acquisition scope root"):
            watch._create_scope_root(
                state_root=state_root,
                unit="qcsd-class-watch-" + "e" * 32 + ".scope",
                command=("ignored", "acquisition-status"),
                authority_fd=descriptor,
                source_binding_sha256="a" * 64,
            )
    finally:
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_unpublished_prelaunch_root_is_recovered_without_a_unit(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    token = "a" * 32
    root = state_root / f"scope.next.{token}"
    root.mkdir(mode=0o700)
    try:
        assert watch._recover_stale_scope_roots(state_root=state_root) == 1
    finally:
        if root.exists():
            _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_staged_prelaunch_record_is_recovered_without_a_unit(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    token = "9" * 32
    root = state_root / f"scope.next.{token}"
    root.mkdir(mode=0o700)
    (root / "SUPERVISION.next").write_bytes(b"interrupted pre-publication write")
    (root / "SUPERVISION.next").chmod(0o600)
    try:
        assert watch._recover_stale_scope_roots(state_root=state_root) == 1
    finally:
        if root.exists():
            _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_final_scope_root_without_durable_record_fails_closed(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    root = state_root / ("scope." + "8" * 32)
    root.mkdir(mode=0o700)
    (root / "SUPERVISION.next").write_bytes(b"interrupted write")
    (root / "SUPERVISION.next").chmod(0o600)
    try:
        with pytest.raises(watch.WatchError, match="no durable lifecycle record"):
            watch._recover_stale_scope_roots(state_root=state_root)
    finally:
        _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_stale_atomic_write_remnant_does_not_block_scope_recovery(
    tmp_path: Path,
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    root, supervision, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "c" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    os.close(birth_lock_fd)
    stale = dict(supervision)
    stale.update(
        {
            "supervisor_pid": 999_999_999,
            "supervisor_start_time": 1,
            "supervisor_session": 1,
            "supervisor_process_group": 1,
        }
    )
    watch._atomic_scope_record(root / "SUPERVISION", stale)
    staged = root / "SUPERVISION.next"
    staged.write_bytes(b"interrupted atomic write")
    staged.chmod(0o600)
    try:
        assert watch._recover_stale_scope_roots(state_root=state_root) == 1
    finally:
        if root.exists():
            _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_recovery_validates_every_root_before_mutating_any_root(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    first, supervision, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "1" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    os.close(birth_lock_fd)
    stale = dict(supervision)
    stale.update(
        {
            "supervisor_pid": 999_999_999,
            "supervisor_start_time": 1,
            "supervisor_session": 1,
            "supervisor_process_group": 1,
        }
    )
    watch._atomic_scope_record(first / "SUPERVISION", stale)
    first_before = (first / "SUPERVISION").read_bytes()
    malformed = state_root / ("scope." + "2" * 32)
    malformed.mkdir(mode=0o700)
    (malformed / "SUPERVISION").write_bytes(b"not canonical JSON\n")
    (malformed / "SUPERVISION").chmod(0o600)
    try:
        with pytest.raises(watch.WatchError, match="malformed"):
            watch._recover_stale_scope_roots(state_root=state_root)
        assert first.exists()
        assert (first / "SUPERVISION").read_bytes() == first_before
        assert not (first / "RECOVERY").exists()
    finally:
        for root in (first, malformed):
            if root.exists():
                _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_scope_record_token_unit_and_root_are_structurally_bound(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    root, _, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "3" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    os.close(birth_lock_fd)
    mismatched = state_root / ("scope." + "4" * 32)
    root.rename(mismatched)
    try:
        with pytest.raises(watch.WatchError, match="malformed identity"):
            watch._recover_stale_scope_roots(state_root=state_root)
    finally:
        _force_remove_test_scope_root(mismatched, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_scope_record_is_bound_to_exact_watch_lock_inode(tmp_path: Path) -> None:
    state_root, original_descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    root, supervision, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "5" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=original_descriptor,
        source_binding_sha256="a" * 64,
    )
    os.close(birth_lock_fd)
    stale = dict(supervision)
    stale.update(
        {
            "supervisor_pid": 999_999_999,
            "supervisor_start_time": 1,
            "supervisor_session": 1,
            "supervisor_process_group": 1,
        }
    )
    watch._atomic_scope_record(root / "SUPERVISION", stale)
    replacement = state_root / "WATCH.lock.replacement"
    replacement.write_bytes(b"")
    replacement.chmod(0o600)
    os.replace(replacement, state_root / "WATCH.lock")
    replacement_descriptor = watch._acquire_mutation_lock(state_root / "WATCH.lock")
    try:
        with pytest.raises(watch.WatchError, match="another supervisor lock"):
            watch._recover_stale_scope_roots(state_root=state_root)
    finally:
        _force_remove_test_scope_root(root, state_root=state_root)
        os.close(replacement_descriptor)
        os.close(original_descriptor)
    assert _scope_inventory(state_root) == before


def test_scope_record_is_bound_to_exact_birth_lock_inode(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    root, supervision, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "6" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    os.close(birth_lock_fd)
    stale = dict(supervision)
    stale.update(
        {
            "supervisor_pid": 999_999_999,
            "supervisor_start_time": 1,
            "supervisor_session": 1,
            "supervisor_process_group": 1,
        }
    )
    watch._atomic_scope_record(root / "SUPERVISION", stale)
    replacement = root / "replacement"
    replacement.write_bytes(b"")
    replacement.chmod(0o600)
    os.replace(replacement, root / "BIRTH.lock")
    try:
        with pytest.raises(watch.WatchError, match="birth lock identity"):
            watch._recover_stale_scope_roots(state_root=state_root)
        assert (root / "SUPERVISION").exists()
        assert not (root / "RECOVERY").exists()
    finally:
        _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_live_scope_supervision_record_blocks_unrelated_recovery(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    before = _scope_inventory(state_root)
    root, _, birth_lock_fd = watch._create_scope_root(
        state_root=state_root,
        unit="qcsd-class-watch-" + "b" * 32 + ".scope",
        command=("ignored", "acquisition-status"),
        authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    os.close(birth_lock_fd)
    try:
        with pytest.raises(watch.WatchError, match="another live acquisition scope"):
            watch._recover_stale_scope_roots(state_root=state_root)
    finally:
        _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
    assert _scope_inventory(state_root) == before


def test_subprocess_runner_latches_signal_without_async_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor = _locked_descriptor(tmp_path / "lock")

    def scoped(
        command,
        *,
        cwd,
        env,
        authority_fd,
        state_root,
        source_binding_sha256,
        latch,
    ):
        assert authority_fd == descriptor
        assert state_root == tmp_path
        assert source_binding_sha256 == "a" * 64
        handler = signal.getsignal(signal.SIGQUIT)
        assert callable(handler)
        handler(signal.SIGQUIT, None)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(watch, "_scope_completed", scoped)
    try:
        with pytest.raises(watch.WatchSignalInterrupt) as interrupted:
            watch._subprocess_runner(
                ("ignored", "acquisition-status"),
                cwd=tmp_path,
                env={},
                authority_fd=descriptor,
                state_root=tmp_path,
                source_binding_sha256="a" * 64,
            )
    finally:
        os.close(descriptor)
    assert interrupted.value.signum == signal.SIGQUIT


def test_scope_state_fails_closed_when_kernel_cgroup_is_unreadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit = "qcsd-class-watch-" + "d" * 32 + ".scope"
    monkeypatch.setattr(
        watch,
        "_systemctl",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            (),
            0,
            (
                "LoadState=loaded\n"
                "ActiveState=active\n"
                "SubState=running\n"
                f"ControlGroup=/definitely-missing/{unit}\n"
            ),
            "",
        ),
    )
    with pytest.raises(watch.WatchError, match="kernel path is unavailable"):
        watch._scope_state(unit, watch._safe_host_environment())


def test_qcsd_admission_rejects_extra_arguments_before_docker() -> None:
    root = Path(__file__).parents[1]
    completed = subprocess.run(
        (
            "/usr/bin/bash",
            str(root / "qcsd-lab"),
            "class-study",
            "acquisition-admission",
            "unexpected",
        ),
        cwd=root,
        env=watch._safe_host_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 2
    assert "rejects unsupported argument" in completed.stderr


@pytest.mark.parametrize("omitted", ("all", watch.SCOPE_ACTION_ENV, watch.SCOPE_SOURCE_ENV))
def test_qcsd_admission_requires_complete_scope_authority_before_docker(
    tmp_path: Path,
    omitted: str,
) -> None:
    root = Path(__file__).parents[1]
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    marker = tmp_path / "docker-was-called"
    docker.write_text(f"#!/bin/sh\n: > {marker}\nexit 97\n", encoding="utf-8")
    docker.chmod(0o755)
    environment = watch._safe_host_environment()
    environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"
    if omitted != "all":
        environment.update(
            {
                watch.SCOPE_STATE_ROOT_ENV: str(tmp_path / "state"),
                watch.SCOPE_ROOT_ENV: str(tmp_path / "scope"),
                watch.SCOPE_AUTHORITY_ENV: "a" * 64,
                watch.SCOPE_ACTION_ENV: "b" * 64,
                watch.SCOPE_SOURCE_ENV: "c" * 64,
            }
        )
        del environment[omitted]

    completed = subprocess.run(
        (
            "/usr/bin/bash",
            str(root / "qcsd-lab"),
            "class-study",
            "acquisition-admission",
        ),
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 1
    assert "requires scoped request authority" in completed.stderr
    assert not marker.exists()


def test_qcsd_rejects_cross_action_scope_digest_before_recovery_or_docker(
    tmp_path: Path,
) -> None:
    root = Path(__file__).parents[1]
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    marker = tmp_path / "docker-was-called"
    docker.write_text(f"#!/bin/sh\n: > {marker}\nexit 97\n", encoding="utf-8")
    docker.chmod(0o755)
    paths = watch.WatchPaths.from_lab_root(root)
    replayed_digest = watch._sha256_bytes(
        watch._canonical_json_bytes(list(watch._status_command(paths)))
    )
    environment = watch._safe_host_environment()
    environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"
    environment.update(
        {
            watch.SCOPE_STATE_ROOT_ENV: str(tmp_path / "state"),
            watch.SCOPE_ROOT_ENV: str(tmp_path / "scope"),
            watch.SCOPE_AUTHORITY_ENV: "a" * 64,
            watch.SCOPE_ACTION_ENV: replayed_digest,
            watch.SCOPE_SOURCE_ENV: "c" * 64,
        }
    )

    completed = subprocess.run(
        (
            "/usr/bin/bash",
            str(root / "qcsd-lab"),
            "class-study",
            "acquisition-admission",
        ),
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 1
    assert "scoped request action does not match current argv" in completed.stderr
    assert "could not validate scoped watcher authority" not in completed.stderr
    assert not marker.exists()


@pytest.mark.parametrize(
    ("action", "arguments"),
    (
        (
            "acquisition-run",
            ("--acquisition-max-candidates", "2", "--acquisition-timeout-ms", "60000"),
        ),
        ("acquisition-run", ("--acquisition-max-candidates", "1")),
        ("acquisition-run", ()),
        ("acquisition-status", ()),
    ),
)
def test_direct_qcsd_acquisition_action_has_no_watcher_authority_before_docker(
    tmp_path: Path,
    action: str,
    arguments: tuple[str, ...],
) -> None:
    root = Path(__file__).parents[1]
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    marker = tmp_path / "docker-was-called"
    docker.write_text(f"#!/bin/sh\n: > {marker}\nexit 97\n", encoding="utf-8")
    docker.chmod(0o755)
    environment = watch._safe_host_environment()
    environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"

    completed = subprocess.run(
        (
            "/usr/bin/bash",
            str(root / "qcsd-lab"),
            "class-study",
            action,
            *arguments,
        ),
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 1
    assert f"class-study {action} requires scoped request authority" in completed.stderr
    assert not marker.exists()


@pytest.mark.parametrize("value", ("0", "3", "true"))
def test_direct_qcsd_rejects_unbounded_acquisition_batch_before_authority_or_docker(
    tmp_path: Path,
    value: str,
) -> None:
    root = Path(__file__).parents[1]
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "docker-was-called"
    docker = fake_bin / "docker"
    docker.write_text(f"#!/bin/sh\n: > {marker}\nexit 97\n", encoding="utf-8")
    docker.chmod(0o755)
    environment = watch._safe_host_environment()
    environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"

    completed = subprocess.run(
        (
            "/usr/bin/bash",
            str(root / "qcsd-lab"),
            "class-study",
            "acquisition-run",
            "--acquisition-max-candidates",
            value,
        ),
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 2
    assert "accepts at most two candidates per action" in completed.stderr
    assert not marker.exists()


def test_watcher_has_no_direct_docker_discovery_or_cleanup() -> None:
    source = (Path(__file__).parents[1] / "tools/class_acquisition_watch.py").read_text(
        encoding="utf-8"
    )
    assert "subprocess.run((\"docker\"" not in source
    assert "container inspect" not in source
    assert "container rm" not in source
    assert "_cleanup_orphan_container" not in source
    assert "acquisition-admission" in source


def test_acquisition_run_has_nested_truthful_action_deadlines() -> None:
    from qcsd_lab.acquisition_timing import (
        ACTION_TIMING_CONTRACT,
        BASELINE_SCHEDULING_CONTRACT,
    )

    watcher_source = (
        Path(__file__).parents[1] / "tools/class_acquisition_watch.py"
    ).read_text(encoding="utf-8")
    launcher_source = (Path(__file__).parents[1] / "qcsd-lab").read_text(
        encoding="utf-8"
    )
    assert "MAX_CANDIDATES = 2" in watcher_source
    assert "GLOBAL_LIVE_PAGE_CAP = 5" in watcher_source
    assert 'kill_signal = "SIGINT" if graceful_run else "SIGKILL"' in watcher_source
    assert "ACQUISITION_ACTION_TIMEOUT_SECONDS = 1_800" in watcher_source
    assert "ACQUISITION_ACTION_CLEANUP_SECONDS = 120" in watcher_source
    assert watch.RUN_RUNTIME_SECONDS == 1_920
    assert watch.ACQUISITION_OUTER_HARD_SECONDS == 2_040
    assert watch.MINIMUM_BASELINE_SPACING_SECONDS == 2_400
    assert watch._ACQUISITION_ACTION_TIMING_CONTRACT[
        "direct_public_acquisition_run"
    ] == "forbidden-without-validated-watcher-scope-authority"
    assert watch._ACQUISITION_ACTION_TIMING_CONTRACT[
        "successful_ledger_attempt_duration_limit_ms"
    ] == 1_800_000
    assert watch._ACQUISITION_ACTION_TIMING_CONTRACT[
        "whole_action_duration_evidence"
    ] == "externally-enforced-process-status-no-per-action-duration-receipt"
    assert watch._ACQUISITION_ACTION_TIMING_CONTRACT == ACTION_TIMING_CONTRACT
    assert watch._BASELINE_SCHEDULING_CONTRACT == BASELINE_SCHEDULING_CONTRACT
    assert watch._BASELINE_SCHEDULING_CONTRACT == {
        "schema_version": 2,
        "policy": "serial-nonoverlapping-stability-window-batch-reservations-v2",
        "maximum_candidates_per_batch": 2,
        "global_live_page_cap": 5,
        "minimum_baseline_spacing_ms": 2_400_000,
        "window_start_reservation_ms": 2_400_000,
        "longest_probe_window_width_ms": 1_800_000,
        "acquisition_outer_configured_hard_cutoff_ms": 2_040_000,
        "status_configured_hard_cutoff_ms": 310_000,
        "scheduler_margin_ms": 50_000,
        "navigation_phase": "separate-bounded-action-before-baseline",
        "short_probe": "same-action-wait-until-t+30s-earliest",
        "outer_probes": "watcher-launches-acquisition-run-at-window-earliest",
        "within_batch_baseline": "one-equal-baseline-per-recorded-baseline-batch",
        "schedule_validation_unit": "baseline-batches-not-raw-candidate-timestamps",
        "unpaired_candidate_policy": "singleton-when-no-compatible-partner",
        "serial_action_start_offsets_ms": [0, 85_500_000, 258_300_000],
        "stability_window_earliest_offsets_ms": [
            25_000,
            85_500_000,
            258_300_000,
        ],
        "collision_scope": (
            "baseline-arming-and-t+24h-t+72h-action-starts-across-batches"
        ),
        "strict_serial_zero_duration_projection": {
            "candidate_count": 600,
            "maximum_candidates_per_batch": 2,
            "batch_count": 300,
            "algorithm": "greedy-earliest-safe-baseline-batches",
            "pairing_assumption": (
                "all-candidates-form-300-compatible-two-candidate-batches"
            ),
            "last_baseline_offset_ms": 2_784_000_000,
            "last_t+72h_earliest_offset_ms": 3_042_300_000,
        },
    }
    assert "-- /usr/bin/timeout --signal=INT --kill-after=120s 1800s" \
        in launcher_source
    assert "accepts at most two candidates per action" in launcher_source


@pytest.mark.parametrize("fault_label", (
    "acquisition scope output removal",
    "acquisition scope birth-lock removal",
    "acquisition scope recovery-record removal",
    "acquisition scope root removal",
))
def test_scope_teardown_crash_boundaries_are_restart_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault_label: str
) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    root, supervision, birth_fd = watch._create_scope_root(
        state_root=state_root, unit="qcsd-class-watch-" + "d" * 32 + ".scope",
        command=("ignored", "acquisition-status"), authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    (root / "stdout").write_text("complete", encoding="ascii")
    (root / "stdout").chmod(0o600)
    recovery = watch._publish_scope_recovery(root, supervision, state_root=state_root)
    real_fsync = watch._fsync_scope_directory
    faulted = False
    def inject(path: Path, *, label: str) -> None:
        nonlocal faulted
        real_fsync(path, label=label)
        if not faulted and label == fault_label:
            faulted = True
            raise watch.WatchError("injected teardown crash")
    monkeypatch.setattr(watch, "_fsync_scope_directory", inject)
    try:
        with pytest.raises(watch.WatchError, match="injected teardown crash"):
            watch._finish_scope_teardown(
                root, state_root=state_root, recovery=recovery,
                birth_lock_fd=birth_fd,
            )
    finally:
        os.close(birth_fd)
    assert faulted
    monkeypatch.setattr(watch, "_fsync_scope_directory", real_fsync)
    expected_recovered = 1 if root.exists() else 0
    assert watch._recover_stale_scope_roots(state_root=state_root) == expected_recovered
    assert not root.exists()
    os.close(descriptor)


@pytest.mark.parametrize(
    "command_factory",
    (watch._admission_command, watch._status_command, watch._run_command),
    ids=("admission", "status", "run"),
)
def test_internal_scope_accepts_each_current_canonical_action_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command_factory,
) -> None:
    paths = watch.WatchPaths.from_lab_root(tmp_path, state_base=tmp_path / "state")
    binding = watch.AcquisitionBinding(
        "image@sha256:" + "1" * 64, "2" * 64, "3" * 64, frozenset(),
        (),
        {"lab_commit": "4" * 40, "neqo_commit": "5" * 40, "neqo_pinned_commit": "5" * 40},
    )
    action = watch._sha256_bytes(
        watch._canonical_json_bytes(list(command_factory(paths)))
    )
    source = watch._source_binding_sha256(binding)
    monkeypatch.setattr(watch, "_paths_from_state_namespace", lambda _root: paths)
    monkeypatch.setattr(watch, "_validate_immutable_binding", lambda _paths: binding)
    monkeypatch.setattr(watch, "_validate_host_source", lambda *_args: None)
    monkeypatch.setattr(watch, "_validate_scope_root", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(watch, "_recover_stale_scope_roots", lambda **_kwargs: 0)
    assert watch.main((
        "--recover-stale-scopes-internal", "--state-root-internal", str(paths.state_root),
        "--current-scope-root-internal", str(paths.state_root / ("scope." + "e" * 32)),
        "--current-authority-internal", "6" * 64,
        "--expected-action-sha256-internal", action,
        "--expected-source-binding-sha256-internal", source,
    )) == 0
    assert json.loads(capsys.readouterr().out) == {"recovered_scope_roots": 0}


def test_recorded_watch_lock_holder_must_be_exact_supervisor(tmp_path: Path) -> None:
    state_root, descriptor = _scope_test_state(tmp_path)
    root, supervision, birth_fd = watch._create_scope_root(
        state_root=state_root, unit="qcsd-class-watch-" + "f" * 32 + ".scope",
        command=("ignored", "acquisition-status"), authority_fd=descriptor,
        source_binding_sha256="a" * 64,
    )
    other = subprocess.Popen(("/usr/bin/sleep", "10"))
    try:
        identity = watch._process_identity(other.pid)
        assert identity is not None
        forged = dict(supervision)
        forged.update(supervisor_pid=other.pid, supervisor_start_time=identity[0],
                      supervisor_session=identity[1], supervisor_process_group=identity[2])
        with pytest.raises(watch.WatchError, match="does not hold the exact watch lock"):
            watch._assert_recorded_watch_lock_holder(state_root, forged)
    finally:
        other.terminate()
        other.wait(timeout=5)
        os.close(birth_fd)
        _force_remove_test_scope_root(root, state_root=state_root)
        os.close(descriptor)
