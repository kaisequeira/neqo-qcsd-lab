"""Host failure retains the attempt without invoking a complete-lane helper.

Plan, image-proof parsing, intent, operation ownership and raw fences use the
existing real serial fixture. Image, host and physical deep actuation are
explicit synthetic boundaries; these cases confer no scientific credit.
"""
from pathlib import Path

import pytest

from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_operation_facts as operations
from qcsd_lab import rapid_rolling_capture as rolling
from tools import rapid_rolling_capture as cli
from tests.test_rapid_serial_launch_facts import (
    serial_case, operation_context_case, rolling_setup, scheduled, setup,
)


@pytest.mark.parametrize("returncode", [1, -15])
def test_nonzero_host_retains_original_attempt_without_complete_helper(serial_case, monkeypatch, returncode):
    case = serial_case
    retained = {}

    def host(spec, root, directory, command, environment, lock):
        case.host_calls.append(command)
        assert operations.current_context() is case.owners[-1]
        result = spec.execution_root / "results" / case.lane.campaign_name / "attempt-001"
        result.mkdir(parents=True)
        (result / "experiment.json").write_bytes(b'{"completion_status":"incomplete"}\n')
        (directory / "host.stdout.log").write_bytes(b"retained synthetic host stdout\n")
        (directory / "host.stderr.log").write_bytes(b"retained synthetic host failure\n")
        lanes._create(root, directory / "host-process.json", lanes.PROCESS_TYPE, {"returncode": returncode})
        for path in (directory / "intent.json", directory / "lineage.json",
                     directory / "host-process.json", directory / "host.stdout.log",
                     directory / "host.stderr.log", result / "experiment.json"):
            retained[path] = (path.read_bytes(), path.stat().st_mode)

    def forbidden(*args, **kwargs):
        pytest.fail("known nonzero host must not invoke any complete-lane helper")

    monkeypatch.setattr(lanes, "_actuate_host", host)
    monkeypatch.setattr(rolling, "check_lane_in_image", forbidden)
    monkeypatch.setattr(lanes, "complete_lane", forbidden)
    with pytest.raises(RuntimeError, match=f"host exit {returncode}; lane intent, process and results retained"):
        cli.run(case.args)
    assert len(case.image_calls) == len(case.host_calls) == 1
    assert not case.deep_calls
    assert operations.current_context() is None
    assert all((path.read_bytes(), path.stat().st_mode) == value for path, value in retained.items())
    directory = case.root / "lanes" / case.lane.campaign_name
    assert not (directory / "complete.json").exists()
    assert not (case.root / "lane-checks").exists()
    assert lanes._payload(directory / "intent.json", lanes.INTENT_TYPE)["scientific_credit"] is False
    # The failed namespace stays claimed; a retry requires its own recovery API.
    with pytest.raises(FileExistsError, match="already claimed"):
        cli.run(case.args)
    assert len(case.image_calls) == len(case.host_calls) == 1


def test_zero_host_keeps_the_existing_complete_lane_boundary_and_owner(serial_case):
    case = serial_case
    result = cli.run(case.args)
    assert Path(result["receipt"]).is_file()
    assert len(case.image_calls) == len(case.host_calls) == len(case.deep_calls) == 1
    assert case.owners[0] is not None and operations.current_context() is None
    assert case.counts["qualification"] == case.counts["canary"] == 1


def test_zero_host_still_closes_raw_fence_after_complete_boundary(serial_case):
    case = serial_case
    case.inject_after_deep = lambda: case.dependencies.canary_recipe.write_bytes(b"changed after deep boundary\n")
    with pytest.raises(ValueError, match="changed"):
        cli.run(case.args)
    assert len(case.host_calls) == len(case.deep_calls) == 1
    assert operations.current_context() is None
