#!/usr/bin/env python3
"""Bounded, zero-credit HTTP/3 root survey of the frozen class catalogue.

``--start-index`` and ``--count`` address positions within *each* of the five
frozen strata. For example, 8/8 probes 40 roots. This is a search diagnostic:
it does not navigate pages, prepare workloads, or create scientific receipts.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from collections import Counter
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterator

from qcsd_lab.class_catalogue import load_candidate_catalogue_receipt
from qcsd_lab.h3_prebaseline import PREBASELINE_H3_SCREEN_CONTRACT, _run_one
from qcsd_lab.util import LAB_ROOT, sha256_file, source_metadata

STUDY_PATH = LAB_ROOT / "config/class-study/v1/study.json"
CATALOGUE_PATH = LAB_ROOT / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"
RECORD_TYPE = "qcsd-non-evidentiary-h3-catalogue-survey"
BATCH_SIZE = 40
MAX_TARGETS = 120
MAX_SECONDS = 1800


class SurveyDeadlineExceeded(Exception):
    """The complete survey exceeded its explicit wall-time budget."""


def _targets(start_index: int, count: int) -> tuple[tuple[dict[str, Any], ...], str]:
    if type(start_index) is not int or type(count) is not int or start_index < 0 or count < 1:
        raise ValueError("start-index must be nonnegative and count must be positive")
    if count * 5 > MAX_TARGETS or start_index + count > 120:
        raise ValueError("survey exceeds the 120-target or per-stratum catalogue limit")
    if STUDY_PATH.is_symlink() or not STUDY_PATH.is_file():
        raise ValueError("study contract must be a regular file")
    study = json.loads(STUDY_PATH.read_text(encoding="utf-8"))
    catalogue_binding = study["population"]["candidate_catalogue"]
    if (
        catalogue_binding["path"] != CATALOGUE_PATH.name
        or catalogue_binding["candidate_count"] != 600
    ):
        raise ValueError("study does not bind the frozen 600-candidate catalogue")
    digest = sha256_file(CATALOGUE_PATH)
    if digest != catalogue_binding["sha256"]:
        raise ValueError("frozen catalogue file differs from the study digest")
    receipt, candidates = load_candidate_catalogue_receipt(CATALOGUE_PATH)
    if receipt["payload"]["study_id"] != study["study_id"]:
        raise ValueError("catalogue and study IDs differ")
    strata = [row["id"] for row in study["population"]["rank_strata"]]
    by_stratum: dict[str, list[Any]] = {name: [] for name in strata}
    for candidate in candidates:
        by_stratum[candidate.stratum.id].append(candidate)
    if len(strata) != 5 or any(len(by_stratum[name]) != 120 for name in strata):
        raise ValueError("study strata differ from the frozen catalogue")
    rows = tuple(
        {
            "catalogue_index": index,
            "stratum": stratum,
            "candidate_id": by_stratum[stratum][index].candidate_id,
            "domain": by_stratum[stratum][index].domain,
            "rank": by_stratum[stratum][index].rank,
        }
        for index in range(start_index, start_index + count)
        for stratum in strata
    )
    return rows, digest


def _open_output(path: Path) -> Any:
    target = Path(os.path.abspath(path))
    parent = target.parent
    if not parent.is_dir() or any(part.is_symlink() for part in (parent, *parent.parents)):
        raise ValueError("output parent must be an existing directory without symlinks")
    resolved = target.resolve(strict=False)
    lab = LAB_ROOT.resolve()
    if resolved == lab or lab in resolved.parents:
        raise ValueError("survey output must be outside the Lab checkout")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o600)
    return os.fdopen(descriptor, "w", encoding="utf-8", buffering=1)


@contextmanager
def _deadline(seconds: int) -> Iterator[None]:
    if type(seconds) is not int or not 1 <= seconds <= MAX_SECONDS:
        raise ValueError(f"timeout-seconds must be 1..{MAX_SECONDS}")
    if not hasattr(signal, "setitimer") or signal.getitimer(signal.ITIMER_REAL)[0] > 0:
        raise RuntimeError("survey requires an unused POSIX wall timer")
    previous = signal.getsignal(signal.SIGALRM)

    def expire(_number: int, _frame: Any) -> None:
        raise SurveyDeadlineExceeded(f"survey exceeded {seconds} seconds")

    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def run_survey(
    *, output: Path, start_index: int, count: int,
    timeout_seconds: int = MAX_SECONDS,
    probe: Callable[[str], dict[str, Any]] = _run_one,
) -> dict[str, Any]:
    """Write one complete, create-only diagnostic stream; never grant credit."""

    targets, catalogue_digest = _targets(start_index, count)
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= MAX_SECONDS:
        raise ValueError(f"timeout-seconds must be 1..{MAX_SECONDS}")
    control_url = PREBASELINE_H3_SCREEN_CONTRACT["control_url"]
    started = time.monotonic()
    counts: Counter[str] = Counter()
    attempted = 0
    completed_batches = 0
    status = "complete"
    with _open_output(output) as stream:
        def emit(stage: str, **fields: Any) -> None:
            row = {
                "record_type": RECORD_TYPE,
                "schema_version": 1,
                "scientific_credit": False,
                "stage": stage,
                "at": datetime.now(UTC).isoformat(),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                **fields,
            }
            stream.write(json.dumps(row, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            print(stage, fields.get("candidate_id", ""), fields.get("outcome", ""), flush=True)

        emit(
            "start", catalogue_sha256=catalogue_digest,
            study_sha256=sha256_file(STUDY_PATH),
            image_digest=os.environ.get("QCSD_LAB_IMAGE_DIGEST", "native"),
            runtime_source=source_metadata(), start_index=start_index, count=count,
            runtime_source_role="underlying-image-build-metadata",
            mounted_module_hashes={
                "tools.h3_catalogue_survey": sha256_file(Path(__file__)),
                "qcsd_lab.h3_prebaseline": sha256_file(
                    Path(sys.modules["qcsd_lab.h3_prebaseline"].__file__)
                ),
            },
            selected_targets=len(targets), batch_size=BATCH_SIZE,
            timeout_seconds=timeout_seconds,
        )
        try:
            with _deadline(timeout_seconds):
                for offset in range(0, len(targets), BATCH_SIZE):
                    batch_index = offset // BATCH_SIZE
                    before = probe(control_url)
                    emit("control-before", batch_index=batch_index,
                         outcome=before["outcome"], detail=before)
                    batch_attempted = 0
                    if before["outcome"] == "known-valid":
                        for target in targets[offset:offset + BATCH_SIZE]:
                            detail = probe(f"https://{target['domain']}/")
                            attempted += 1
                            batch_attempted += 1
                            counts[detail["outcome"]] += 1
                            emit("candidate", batch_index=batch_index, **target,
                                 outcome=detail["outcome"], detail=detail)
                    after = probe(control_url)
                    emit("control-after", batch_index=batch_index,
                         outcome=after["outcome"], detail=after)
                    controls_pass = (
                        before["outcome"] == after["outcome"] == "known-valid"
                    )
                    completed_batches += 1
                    emit("batch-complete", batch_index=batch_index,
                         attempted_targets=batch_attempted, controls_pass=controls_pass)
                    if not controls_pass:
                        status = "control-failed"
                        break
        except SurveyDeadlineExceeded as error:
            status = "timed-out"
            emit("run-timeout", error=str(error))
        except Exception as error:
            status = "probe-error"
            emit("run-error", error_type=type(error).__name__, error=str(error))
        result = {
            "status": status,
            "selected_targets": len(targets),
            "attempted_targets": attempted,
            "completed_batches": completed_batches,
            "outcomes": dict(counts),
            "scientific_credit": False,
        }
        emit("complete", **result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="new JSONL path outside the Lab checkout")
    parser.add_argument("--start-index", type=int, default=0,
                        help="zero-based starting position within every stratum")
    parser.add_argument("--count", type=int, default=8,
                        help="candidate positions per stratum, maximum 24")
    parser.add_argument("--timeout-seconds", type=int, default=MAX_SECONDS)
    args = parser.parse_args(argv)
    try:
        result = run_survey(
            output=args.output, start_index=args.start_index,
            count=args.count, timeout_seconds=args.timeout_seconds,
        )
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        print(f"H3 catalogue survey failed: {error}", file=sys.stderr, flush=True)
        return 2
    return 0 if result["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
