#!/usr/bin/env python3
"""Bounded, zero-credit HTTP/3 root survey of rapid Tranco fallback sites.

``--start-index`` is zero-based within the fallback portion of the frozen
profile, whose first fallback candidate has global order 74. The default is
v4; ``--study-version 5`` selects the separately frozen v5 profile. This
only probes ``https://domain/``. It cannot admit a site, prepare a resource
graph, or count a formal trace. Each run writes a new JSONL file outside the
Lab checkout and brackets every ten candidates with known-good H3 controls.
"""

from __future__ import annotations

import argparse
import hashlib
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

from qcsd_lab import h3_prebaseline, rapid_study_profile
from qcsd_lab.class_acquisition import unsafe_catalogue_domain_reason
from qcsd_lab.util import LAB_ROOT, sha256_file, source_metadata

DEFAULT_PROFILE = LAB_ROOT / "config/curated-sources/crux73-tranco600-rapid-v4.profile.json"
DEFAULT_V5_PROFILE = LAB_ROOT / "config/curated-sources/crux73-tranco600-rapid-v5.profile.json"
DEFAULT_SOURCE = LAB_ROOT / "config/curated-sources/crux-73-v1.raw.json"
DEFAULT_CATALOGUE = (
    LAB_ROOT / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"
)
FROZEN_PROFILE_SHA256 = "ac40a338bf72c9062b4ece0d1f16de6476763c522295f668e2f5fe931f8c6a92"
FROZEN_V5_PROFILE_SHA256 = "f7eb0228a06429cc2ae91d0f9d52577399e15b68f4915d41cb60291445542b60"
RECORD_TYPE = "qcsd-non-evidentiary-h3-rapid-v4-fallback-root-survey"
V5_RECORD_TYPE = "qcsd-non-evidentiary-h3-rapid-v5-fallback-root-survey"
BATCH_SIZE = 10
MAX_TARGETS = 40
MAX_SECONDS = 900


class SurveyDeadlineExceeded(Exception):
    """The entire survey exceeded its declared wall-time budget."""


def _targets(
    profile: Path, source: Path, catalogue: Path, start_index: int, count: int,
    *, study_version: int = 4,
) -> tuple[tuple[dict[str, Any], ...], dict[str, Any]]:
    if type(study_version) is not int or study_version not in {4, 5}:
        raise ValueError("survey study version must be 4 or 5")
    if type(start_index) is not int or type(count) is not int or start_index < 0 or count < 1:
        raise ValueError("start-index must be nonnegative and count must be positive")
    if count > MAX_TARGETS:
        raise ValueError(f"survey accepts at most {MAX_TARGETS} targets per run")
    for path in (profile, source, catalogue):
        if path.is_symlink() or not path.is_file():
            raise ValueError("rapid survey inputs must be regular, nonlinked files")
    profile_bytes = profile.read_bytes()
    profile_sha256 = hashlib.sha256(profile_bytes).hexdigest()
    expected_sha256 = (
        FROZEN_V5_PROFILE_SHA256 if study_version == 5 else FROZEN_PROFILE_SHA256
    )
    if profile_sha256 != expected_sha256:
        raise ValueError(f"rapid-v{study_version} profile differs from its frozen SHA-256")
    source_bytes = source.read_bytes()
    catalogue_bytes = catalogue.read_bytes()
    profile_receipt = json.loads(profile_bytes)
    validate_profile = (
        rapid_study_profile.validate_v5_profile_receipt if study_version == 5
        else rapid_study_profile.validate_profile_receipt
    )
    ordered = validate_profile(
        profile_receipt, source_bytes, catalogue_bytes
    )
    fallback = tuple(
        candidate for candidate in ordered if candidate["source_kind"] == "tranco-fallback"
    )
    if len(fallback) != rapid_study_profile.FALLBACK_CANDIDATE_COUNT:
        raise ValueError(f"rapid-v{study_version} fallback population is incomplete")
    if start_index + count > len(fallback):
        raise ValueError("survey slice exceeds the frozen fallback population")
    selected = tuple(
        {
            "fallback_index": index,
            "candidate_order": candidate["candidate_order"],
            "source_position": candidate["source_position"],
            "candidate_id": candidate["candidate_id"],
            "domain": candidate["domain"],
            "tranco_rank": candidate["tranco_rank"],
            "tranco_stratum": candidate["tranco_stratum"],
            "pre_browser_safety_reason": unsafe_catalogue_domain_reason(candidate["domain"]),
        }
        for index, candidate in enumerate(fallback[start_index:start_index + count], start_index)
    )
    identity = {
        "profile_sha256": profile_sha256,
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "catalogue_sha256": hashlib.sha256(catalogue_bytes).hexdigest(),
        "profile_candidate_count": len(ordered),
        "fallback_candidate_count": len(fallback),
    }
    return selected, identity


def _open_output(path: Path) -> Any:
    target = Path(os.path.abspath(path))
    parent = target.parent
    if not parent.is_dir() or any(part.is_symlink() for part in (parent, *parent.parents)):
        raise ValueError("output parent must be an existing directory without symlinks")
    resolved = target.resolve(strict=False)
    lab = LAB_ROOT.resolve()
    if resolved == lab or lab in resolved.parents:
        raise ValueError("survey output must be outside the Lab checkout")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    return os.fdopen(os.open(target, flags, 0o600), "w", encoding="utf-8", buffering=1)


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
    *,
    output: Path,
    start_index: int,
    count: int,
    profile: Path | None = None,
    source: Path = DEFAULT_SOURCE,
    catalogue: Path = DEFAULT_CATALOGUE,
    timeout_seconds: int = MAX_SECONDS,
    probe: Callable[[str], dict[str, Any]] | None = None,
    study_version: int = 4,
) -> dict[str, Any]:
    """Survey one ordered fallback slice without granting any study credit."""

    if type(study_version) is not int or study_version not in {4, 5}:
        raise ValueError("survey study version must be 4 or 5")
    selected_profile = profile or (
        DEFAULT_V5_PROFILE if study_version == 5 else DEFAULT_PROFILE
    )
    targets, identity = _targets(
        selected_profile, source, catalogue, start_index, count,
        study_version=study_version,
    )
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= MAX_SECONDS:
        raise ValueError(f"timeout-seconds must be 1..{MAX_SECONDS}")
    if probe is None:
        if os.environ.get("QCSD_PUBLIC_ORIGIN_ONLY") != "1":
            raise ValueError("live survey requires QCSD_PUBLIC_ORIGIN_ONLY=1")
        probe = h3_prebaseline._run_one
    control_url = (
        rapid_study_profile.V5_TRIAGE_POLICY if study_version == 5
        else rapid_study_profile.TRIAGE_POLICY
    )["control_url"]
    record_type = V5_RECORD_TYPE if study_version == 5 else RECORD_TYPE
    started = time.monotonic()
    outcomes: Counter[str] = Counter()
    attempted = skipped_unsafe = completed_batches = 0
    status = "complete"
    with _open_output(output) as stream:
        def emit(stage: str, **fields: Any) -> None:
            row = {
                "record_type": record_type,
                "schema_version": 1,
                "scientific_credit": False,
                "stage": stage,
                "at": datetime.now(UTC).isoformat(),
                "elapsed_seconds": round(time.monotonic() - started, 3),
                **fields,
            }
            stream.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            print(stage, fields.get("candidate_id", ""), fields.get("outcome", ""), flush=True)

        emit(
            "start", **identity,
            image_digest=os.environ.get("QCSD_LAB_IMAGE_DIGEST", "native"),
            runtime_source=source_metadata(),
            runtime_source_role="underlying-image-build-metadata",
            mounted_module_hashes={
                "tools.h3_rapid_fallback_survey": sha256_file(Path(__file__)),
                "qcsd_lab.h3_prebaseline": sha256_file(Path(h3_prebaseline.__file__)),
                "qcsd_lab.rapid_study_profile": sha256_file(
                    Path(rapid_study_profile.__file__)
                ),
            },
            start_index=start_index,
            count=count,
            selected_targets=len(targets),
            batch_size=BATCH_SIZE,
            timeout_seconds=timeout_seconds,
            control_url=control_url,
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
                            reason = target["pre_browser_safety_reason"]
                            if reason is not None:
                                skipped_unsafe += 1
                                emit("candidate-skipped", batch_index=batch_index,
                                     **target, reason=reason)
                                continue
                            detail = probe(f"https://{target['domain']}/")
                            attempted += 1
                            batch_attempted += 1
                            outcomes[detail["outcome"]] += 1
                            emit("candidate", batch_index=batch_index, **target,
                                 outcome=detail["outcome"], detail=detail)
                    after = probe(control_url)
                    emit("control-after", batch_index=batch_index,
                         outcome=after["outcome"], detail=after)
                    controls_pass = before["outcome"] == after["outcome"] == "known-valid"
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
            "skipped_unsafe_targets": skipped_unsafe,
            "completed_batches": completed_batches,
            "outcomes": dict(outcomes),
            "scientific_credit": False,
        }
        emit("complete", **result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study-version", type=int, choices=(4, 5), default=4,
                        help="frozen study profile version (default: 4)")
    parser.add_argument("--output", required=True, type=Path,
                        help="new JSONL path outside the Lab checkout")
    parser.add_argument("--start-index", type=int, default=0,
                        help="zero-based position within the selected fallback sequence")
    parser.add_argument("--count", type=int, default=10,
                        help=f"consecutive fallback candidates, maximum {MAX_TARGETS}")
    parser.add_argument("--timeout-seconds", type=int, default=MAX_SECONDS)
    args = parser.parse_args(argv)
    try:
        result = run_survey(
            output=args.output, start_index=args.start_index, count=args.count,
            timeout_seconds=args.timeout_seconds, study_version=args.study_version,
        )
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        print(f"H3 rapid fallback survey failed: {error}", file=sys.stderr, flush=True)
        return 2
    return 0 if result["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
