#!/usr/bin/env python3
"""Bounded, zero-credit HTTP/3 root survey of the frozen curated source.

This checks only ``https://domain/`` reachability. It does not inspect the
supplied resource URLs, discover pages, prepare workloads, or select classes.
The create-only JSONL output is diagnostic evidence outside the Lab checkout.
The historical default is v4; ``--study-version 5`` binds fresh screens to the
separately frozen rapid v5 profile before any network probe.
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

from qcsd_lab import rapid_study_profile
from qcsd_lab.class_curated_source import load_curated_source_receipt
from qcsd_lab.h3_prebaseline import PREBASELINE_H3_SCREEN_V3_CONTRACT, _run_one
from qcsd_lab.util import LAB_ROOT, sha256_file, source_metadata

DEFAULT_RECEIPT = LAB_ROOT / "config/curated-sources/crux-73-v1.source.json"
DEFAULT_SOURCE = LAB_ROOT / "config/curated-sources/crux-73-v1.raw.json"
DEFAULT_V5_PROFILE = LAB_ROOT / "config/curated-sources/crux73-tranco600-rapid-v5.profile.json"
DEFAULT_CATALOGUE = (
    LAB_ROOT / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json"
)
RECORD_TYPE = "qcsd-non-evidentiary-h3-curated-root-survey"
V5_RECORD_TYPE = "qcsd-non-evidentiary-h3-rapid-v5-curated-root-survey"
BATCH_SIZE = 10
MAX_TARGETS = 40
MAX_SECONDS = 900


class SurveyDeadlineExceeded(Exception):
    """The complete survey exceeded its explicit wall-time budget."""


def _targets(
    source: Path, receipt: Path, start_index: int, count: int,
    *, study_version: int = 4, profile: Path | None = None,
    catalogue: Path = DEFAULT_CATALOGUE,
) -> tuple[tuple[dict[str, Any], ...], dict[str, Any]]:
    if type(study_version) is not int or study_version not in {4, 5}:
        raise ValueError("survey study version must be 4 or 5")
    if study_version == 4 and profile is not None:
        raise ValueError("an explicit rapid profile requires --study-version 5")
    if type(start_index) is not int or type(count) is not int or start_index < 0 or count < 1:
        raise ValueError("start-index must be nonnegative and count must be positive")
    if count > MAX_TARGETS:
        raise ValueError(f"survey accepts at most {MAX_TARGETS} targets per run")
    source_receipt, _domains = load_curated_source_receipt(receipt, source_path=source)
    payload = source_receipt["payload"]
    candidates = payload["candidates"]
    if start_index + count > len(candidates):
        raise ValueError("survey slice exceeds the validated curated source")
    unsafe = {
        row["domain"]: row["reason"]
        for row in payload["pre_browser_safety_matches"]
    }
    selected = tuple(
        {
            "source_index": candidate["source_index"],
            "candidate_id": candidate["candidate_id"],
            "domain": candidate["domain"],
            "observed_resource_url_count": candidate["observed_resource_url_count"],
            "origin_hint_count": len(candidate["origin_hints"]),
            "pre_browser_safety_reason": unsafe.get(candidate["domain"]),
        }
        for candidate in candidates[start_index:start_index + count]
    )
    identity = {
        "source_sha256": payload["source_sha256"],
        "receipt_sha256": sha256_file(receipt),
        "candidate_count": len(candidates),
    }
    if study_version == 5:
        profile_path = profile or DEFAULT_V5_PROFILE
        for path in (profile_path, catalogue):
            if path.is_symlink() or not path.is_file():
                raise ValueError("rapid v5 survey inputs must be regular, nonlinked files")
        profile_bytes = profile_path.read_bytes()
        digest = hashlib.sha256(profile_bytes).hexdigest()
        if digest != rapid_study_profile.FROZEN_V5_PROFILE_SHA256:
            raise ValueError("rapid-v5 profile differs from its frozen SHA-256")
        ordered = rapid_study_profile.validate_v5_profile_receipt(
            json.loads(profile_bytes), source.read_bytes(), catalogue.read_bytes(),
        )
        curated = sorted(
            (candidate for candidate in ordered if candidate["source_kind"] == "curated"),
            key=lambda candidate: candidate["source_position"],
        )
        if len(curated) != len(candidates) or any(
            (candidate["candidate_id"], candidate["domain"])
            != (frozen["candidate_id"], frozen["domain"])
            for candidate, frozen in zip(candidates, curated, strict=True)
        ):
            raise ValueError("curated source differs from the frozen v5 candidates")
        identity.update({"study_version": 5, "profile_sha256": digest})
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
    source: Path = DEFAULT_SOURCE,
    receipt: Path = DEFAULT_RECEIPT,
    output: Path,
    start_index: int,
    count: int,
    timeout_seconds: int = MAX_SECONDS,
    probe: Callable[[str], dict[str, Any]] | None = None,
    study_version: int = 4,
    profile: Path | None = None,
    catalogue: Path = DEFAULT_CATALOGUE,
) -> dict[str, Any]:
    """Survey one validated slice without granting scientific credit."""

    targets, identity = _targets(
        source, receipt, start_index, count,
        study_version=study_version, profile=profile, catalogue=catalogue,
    )
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= MAX_SECONDS:
        raise ValueError(f"timeout-seconds must be 1..{MAX_SECONDS}")
    if probe is None:
        if os.environ.get("QCSD_PUBLIC_ORIGIN_ONLY") != "1":
            raise ValueError("live survey requires QCSD_PUBLIC_ORIGIN_ONLY=1")
        probe = _run_one
    control_url = (
        rapid_study_profile.V5_TRIAGE_POLICY["control_url"] if study_version == 5
        else PREBASELINE_H3_SCREEN_V3_CONTRACT["control_url"]
    )
    record_type = V5_RECORD_TYPE if study_version == 5 else RECORD_TYPE
    module_hashes = {
        "tools.h3_curated_survey": sha256_file(Path(__file__)),
        "qcsd_lab.h3_prebaseline": sha256_file(
            Path(sys.modules["qcsd_lab.h3_prebaseline"].__file__)
        ),
    }
    if study_version == 5:
        module_hashes["qcsd_lab.rapid_study_profile"] = sha256_file(
            Path(rapid_study_profile.__file__)
        )
    started = time.monotonic()
    counts: Counter[str] = Counter()
    attempted = 0
    skipped_unsafe = 0
    completed_batches = 0
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
            mounted_module_hashes=module_hashes,
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
                            if target["pre_browser_safety_reason"] is not None:
                                skipped_unsafe += 1
                                emit("candidate-skipped", batch_index=batch_index,
                                     **target, reason=target["pre_browser_safety_reason"])
                                continue
                            detail = probe(f"https://{target['domain']}/")
                            attempted += 1
                            batch_attempted += 1
                            counts[detail["outcome"]] += 1
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
            "outcomes": dict(counts),
            "scientific_credit": False,
        }
        emit("complete", **result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study-version", type=int, choices=(4, 5), default=4,
                        help="prospective study identity (default: historical v4)")
    parser.add_argument("--profile", type=Path,
                        help="exact frozen v5 profile; required bytes are independently checked")
    parser.add_argument("--catalogue", type=Path, default=DEFAULT_CATALOGUE,
                        help="frozen fallback catalogue used to validate the v5 profile")
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE,
                        help="exact tracked CrUX JSON file")
    parser.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT,
                        help="validated curated-source receipt")
    parser.add_argument("--output", required=True, type=Path,
                        help="new JSONL path outside the Lab checkout")
    parser.add_argument("--start-index", type=int, default=0,
                        help="zero-based starting candidate position")
    parser.add_argument("--count", type=int, default=10,
                        help=f"candidate positions, maximum {MAX_TARGETS}")
    parser.add_argument("--timeout-seconds", type=int, default=MAX_SECONDS)
    args = parser.parse_args(argv)
    try:
        result = run_survey(
            source=args.source, receipt=args.receipt, output=args.output,
            start_index=args.start_index, count=args.count,
            timeout_seconds=args.timeout_seconds,
            study_version=args.study_version, profile=args.profile,
            catalogue=args.catalogue,
        )
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as error:
        print(f"H3 curated survey failed: {error}", file=sys.stderr, flush=True)
        return 2
    return 0 if result["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
