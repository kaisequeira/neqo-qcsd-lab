"""Fail-closed launch policy for a measured study client process."""

from __future__ import annotations

import os
import resource

CAPTURE_SCHEDULER_CONTRACT = "qcsd-client-rr1-cpu10-v1"
CAPTURE_ORCHESTRATOR_CPU = 11
CAPTURE_CLIENT_CPU = 10


def capture_scheduler_contract() -> str | None:
    """Return the one supported measured-client scheduler contract, if selected."""

    value = os.environ.get("QCSD_CAPTURE_SCHEDULER_CONTRACT")
    if value in {None, ""}:
        return None
    if value != CAPTURE_SCHEDULER_CONTRACT:
        raise ValueError(f"unsupported capture scheduler contract: {value}")
    return value


def capture_scheduler_launch_prefix() -> list[str]:
    """Fail closed on the container partition before elevating only the client."""

    if capture_scheduler_contract() is None:
        return []
    affinity = os.sched_getaffinity(0)
    if affinity != {CAPTURE_ORCHESTRATOR_CPU}:
        raise ValueError(
            f"capture scheduler parent must be confined to orchestrator CPU "
            f"{CAPTURE_ORCHESTRATOR_CPU}"
        )
    rtprio = resource.getrlimit(resource.RLIMIT_RTPRIO)
    if rtprio != (1, 1):
        raise ValueError("capture scheduler requires RLIMIT_RTPRIO soft/hard 1")
    return [
        "/usr/bin/taskset",
        "--cpu-list",
        str(CAPTURE_CLIENT_CPU),
        "/usr/bin/chrt",
        "--rr",
        "1",
        "/usr/bin/setpriv",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--no-new-privs",
        "--",
    ]
