"""Exercise the real collector stop/cleanup boundary with controlled I/O."""

from pathlib import Path
from types import SimpleNamespace
import signal
import subprocess

import pytest

from qcsd_lab import capture_session as capture
from qcsd_lab.fidelity import validate_primary_capture_clock_integrity


class AfterCleanup(RuntimeError):
    """Stop this HOST fixture before any capture decoding or promotion."""


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    events = []
    state = SimpleNamespace(mono=1_000_000_000, realtime=10_000_000_000,
                            settle_step=0, start_failure=False, client_failure=False,
                            end_failure=None, cleanup_failure=False, anchors=None)

    def advance(nanoseconds, step=0):
        state.mono += nanoseconds
        state.realtime += nanoseconds + step

    class Process:
        returncode = None
        stop_mode = "normal"

        def poll(self):
            return self.returncode

        def send_signal(self, value):
            assert value == signal.SIGINT and self.returncode is None
            events.append("sigint")

        def wait(self, timeout):
            events.append(f"wait-{timeout}")
            if self.stop_mode in {"terminate", "timeout"} and timeout == 10:
                raise subprocess.TimeoutExpired("controlled-dumpcap", timeout)
            if self.stop_mode == "timeout":
                raise subprocess.TimeoutExpired("controlled-dumpcap", timeout)
            self.returncode = 0
            advance(100_000_000)
            events.append("stopped")
            return 0

        def terminate(self):
            events.append("terminate")

    process = Process()

    class Router:
        def __init__(self, *_args):
            pass

        def start(self, **_kwargs):
            events.append("router-start")

        def stop(self):
            assert process.poll() is not None
            events.append("router-cleanup")
            advance(500_000_000, 20_000_000)
            return tmp_path / "controlled-router.pcapng", {}

    class Qdisc:
        def install(self):
            events.append("qdisc-install")

        def finish_observation(self):
            events.append("qdisc-cleanup")
            advance(500_000_000, 60_000_000)
            if state.cleanup_failure:
                raise RuntimeError("controlled qdisc cleanup failure")
            return {}

        def restore(self):
            events.append("qdisc-restore")

    def wait_for_start(*_args):
        events.append("capture-start")
        if state.start_failure:
            raise RuntimeError("controlled capture-start failure")

    def anchor():
        ending = "runner" in events
        events.append("anchor-end" if ending else "anchor-start")
        if ending:
            assert process.poll() is not None
            if state.end_failure is not None:
                raise state.end_failure
        return {"monotonic_ns": state.mono, "realtime_unix_ns": state.realtime,
                "pairing_uncertainty_ns": 100}

    original_end = capture._capture_clock_anchors_after_stop

    def end_anchor(start, stopped_process):
        state.anchors = original_end(start, stopped_process)
        return state.anchors

    def client(*_args, **_kwargs):
        events.append("runner")
        if state.client_failure:
            raise RuntimeError("controlled runner failure")
        return SimpleNamespace(returncode=0), False, 120.0

    def settle(seconds):
        assert seconds == 1 and process.poll() is None
        events.append("settle")
        advance(1_000_000_000, state.settle_step)
        if process.stop_mode == "already-stopped":
            process.returncode = 0

    def after_cleanup(**_kwargs):
        events.append("after-cleanup")
        raise AfterCleanup("stop before decoding")

    monkeypatch.setattr(capture, "_capture_scheduler_contract", lambda: None)
    monkeypatch.setattr(capture, "kernel_tx_lab_runtime_required", lambda **_kwargs: True)
    monkeypatch.setenv("QCSD_CAPTURE_ETF_INTERFACE", capture.KERNEL_TX_INTERFACE)
    monkeypatch.setenv("QCSD_CONTROLLED_ROUTER_CLIENT_IP", "127.0.0.1")
    monkeypatch.setattr(capture, "require_post_veth_capture_configuration",
                        lambda: ("127.0.0.1", 0, "controlled-only", tmp_path))
    monkeypatch.setattr(capture, "_offload_metadata", lambda _interface: {})
    monkeypatch.setattr(capture, "offload_evidence_is_valid", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(capture, "_public_study_network_condition", lambda *_args: None)
    monkeypatch.setattr(capture.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(capture, "KernelTxQdiscSession", Qdisc)
    monkeypatch.setattr(capture, "RouterCaptureClient", Router)
    monkeypatch.setattr(capture, "_wait_for_capture_start", wait_for_start)
    monkeypatch.setattr(capture, "_clock_anchor", anchor)
    monkeypatch.setattr(capture, "_capture_clock_anchors_after_stop", end_anchor)
    monkeypatch.setattr(capture, "_client_command", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(capture, "_run_neqo_client", client)
    monkeypatch.setattr(capture.time, "sleep", settle)
    monkeypatch.setattr(capture, "_persist_kernel_qdisc_observation", lambda *_args: None)
    monkeypatch.setattr(capture, "_finalize_router_capture", after_cleanup)

    def collect():
        return capture._collect_attempt(
            tmp_path / "attempt", tmp_path / "manifest.json", "controlled",
            capture.Defense(name="undefended", kind="none", baseline=True), 1,
            SimpleNamespace(limits=capture.Limits(settle_seconds=1)))

    return SimpleNamespace(collect=collect, state=state, events=events, process=process)


def clock_receipt(anchors):
    return {
        "primary": True, "timestamp_type": "host", "capture_clock_anchors": anchors,
        "direct_runner_reconciliation": {
            "direct_clock_model": "constant-offset", "direct_clock_segment_count": 1,
            "direct_clock_segments": [{"index": 0}], "direct_clock_step_count": 0,
            "direct_clock_steps": [], "direct_runner_reconciled": True,
            "evidence_eligible": True, "direct_timestamp_error_max_ns": 0,
            "direct_timestamp_tolerance_ns": 10_000_000,
        },
    }


@pytest.mark.parametrize("stop_mode", ["normal", "already-stopped", "terminate"])
def test_primary_end_anchor_closes_after_stop_before_cleanup_clock_jitter(boundary, stop_mode):
    boundary.process.stop_mode = stop_mode
    with pytest.raises(AfterCleanup):
        boundary.collect()
    events = boundary.events
    assert events.index("runner") < events.index("settle") < events.index("stopped")
    assert events.index("stopped") < events.index("anchor-end") < events.index("router-cleanup")
    assert events.index("router-cleanup") < events.index("qdisc-cleanup") < events.index("after-cleanup")
    assert events.count("anchor-start") == events.count("anchor-end") == 1
    if stop_mode == "terminate":
        assert events.index("wait-10") < events.index("terminate") < events.index("wait-5")
    if stop_mode == "already-stopped":
        assert "sigint" not in events
    anchors = boundary.state.anchors
    assert anchors["end_monotonic_ns"] == 2_100_000_000
    assert anchors["end_realtime_unix_ns"] == 11_100_000_000
    assert boundary.state.realtime - boundary.state.mono == 9_080_000_000
    receipt = validate_primary_capture_clock_integrity(
        clock_receipt(anchors), require_pairing_uncertainty=True, require_timestamp_type=True)
    assert receipt["realtime_monotonic_elapsed_error_bound_ns"] == 200


def test_settle_tail_clock_step_remains_inside_strict_envelope(boundary):
    boundary.state.settle_step = -12_000_000
    with pytest.raises(AfterCleanup):
        boundary.collect()
    with pytest.raises(ValueError, match="elapsed difference exceeds 10 ms"):
        validate_primary_capture_clock_integrity(
            clock_receipt(boundary.state.anchors), require_pairing_uncertainty=True)


def test_unstopped_dumpcap_after_timeout_cannot_create_end_anchor(boundary):
    boundary.process.stop_mode = "timeout"
    with pytest.raises(subprocess.TimeoutExpired) as failure:
        boundary.collect()
    assert failure.value.timeout == 5
    assert boundary.events[-3:] == ["wait-10", "terminate", "wait-5"]
    assert "anchor-end" not in boundary.events and boundary.state.anchors is None


def test_capture_start_failure_stops_dumpcap_without_invented_start_anchor(boundary):
    boundary.state.start_failure = True
    with pytest.raises(RuntimeError, match="controlled capture-start failure"):
        boundary.collect()
    assert "anchor-start" not in boundary.events and "anchor-end" not in boundary.events
    assert boundary.events[-3:] == ["sigint", "wait-10", "stopped"]
    assert "router-start" not in boundary.events and "qdisc-install" not in boundary.events


def test_runner_failure_is_preserved_after_stop_anchor_and_cleanup(boundary):
    boundary.state.client_failure = True
    with pytest.raises(RuntimeError, match="controlled runner failure"):
        boundary.collect()
    assert "settle" not in boundary.events
    assert boundary.events[-4:] == ["stopped", "anchor-end", "router-cleanup", "qdisc-cleanup"]


@pytest.mark.parametrize("failure", [RuntimeError("controlled anchor failure"), KeyboardInterrupt()])
def test_end_anchor_error_is_reraised_only_after_original_cleanup(boundary, failure):
    boundary.state.end_failure = failure
    with pytest.raises(type(failure)) as caught:
        boundary.collect()
    assert caught.value is failure
    assert boundary.events[-3:] == ["anchor-end", "router-cleanup", "qdisc-cleanup"]
    assert boundary.state.anchors is None


def test_cleanup_failure_still_refuses_even_with_a_valid_end_anchor(boundary):
    boundary.state.cleanup_failure = True
    with pytest.raises(RuntimeError, match="client qdisc finalisation failed: controlled"):
        boundary.collect()
    assert boundary.events[-4:] == ["anchor-end", "router-cleanup", "qdisc-cleanup", "qdisc-restore"]
    assert boundary.state.anchors is not None
    assert "after-cleanup" not in boundary.events
