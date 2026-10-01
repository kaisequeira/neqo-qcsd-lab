#!/usr/bin/env python3
"""Bounded, non-evidentiary rehearsal of the live acquisition backend.

This intentionally does not initialise an acquisition runner or publish class
study receipts. Every generated file stays in a new diagnostic directory outside
the Lab checkout. A successful rehearsal is engineering evidence only.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterator, Sequence
from unittest.mock import patch

import qcsd_lab.prepare as preparation_module
from qcsd_lab.acquisition_errors import (
    RecoverableAcquisitionError,
    TerminalAcquisitionPolicyError,
)
from qcsd_lab.class_acquisition import (
    ExistingAcquisitionBackend,
    _converge_origins,
    _navigation_origins_by_page,
    _prepared_primary_response,
    _prepared_replay_identity_sha256,
    validate_class_study_preparation,
)
from qcsd_lab.class_catalogue import (
    MAX_PAGE_CANDIDATES,
    load_candidate_catalogue_receipt,
    select_page_candidates,
)
from qcsd_lab.class_study import canonical_domain
from qcsd_lab.discover import origin
from qcsd_lab.h3_prebaseline import (
    H3ScreenBlocked,
    H3SiteUnavailable,
    PREBASELINE_H3_SCREEN_CONTRACT,
    _run_one,
    validate_h3_screen_receipt,
)
from qcsd_lab.util import LAB_ROOT, load_json, sha256_file, source_metadata

MAX_TARGETS = 6
MAX_TOTAL_SECONDS = 1_800
DEFAULT_TOTAL_SECONDS = 900
DEFAULT_NAVIGATION_TIMEOUT_MS = 60_000
RECORD_TYPE = "qcsd-non-evidentiary-acquisition-rehearsal"
MAX_FAILED_PREPARE_FILES = 8
MAX_FAILED_PREPARE_FILE_BYTES = 128 * 1024
MAX_FAILED_PREPARE_TOTAL_BYTES = 512 * 1024
MAX_SELECTED_H3_DIAGNOSTIC_BYTES = 512 * 1024
MAX_ALL_SELECTED_H3_DIAGNOSTIC_BYTES = 1024 * 1024


class RehearsalTimeout(TimeoutError):
    """The complete diagnostic exceeded its explicit wall-time budget."""


@dataclass(frozen=True)
class Target:
    candidate_id: str
    domain: str
    selected_url: str | None = None
    kind: str = "catalogue-candidate"


def _preserve_failed_prepare_tempfiles(
    temporary: Path, output_root: Path, workload_id: str,
) -> dict[str, Any]:
    """Retain a small, create-only diagnostic subset before tempfile cleanup."""

    candidates: list[Path] = []
    for directory, subdirs, files in os.walk(temporary, followlinks=False):
        subdirs[:] = sorted(
            name for name in subdirs if not (Path(directory) / name).is_symlink()
        )[:8]
        for name in sorted(files):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            if name.endswith((".log", ".json")) or name.startswith("probe-head"):
                candidates.append(path)
            if len(candidates) >= 128:
                break
        if len(candidates) >= 128:
            break
    candidates.sort(key=lambda path: (
        0 if path.name == "probe.log" else
        1 if path.name.startswith("probe-head") else
        2 if path.name == "run.json" else
        3 if path.suffix == ".log" else 4,
        str(path.relative_to(temporary)),
    ))
    destination = output_root / "failed-prepare-artifacts" / workload_id
    selected = candidates[:MAX_FAILED_PREPARE_FILES]
    if selected:
        destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    retained = []
    total = 0
    for source in selected:
        remaining = MAX_FAILED_PREPARE_TOTAL_BYTES - total
        if remaining <= 0:
            break
        size = source.stat().st_size
        limit = min(MAX_FAILED_PREPARE_FILE_BYTES, remaining)
        offset = max(0, size - limit) if source.suffix == ".log" else 0
        with source.open("rb") as stream:
            stream.seek(offset)
            content = stream.read(limit)
        target = destination / source.relative_to(temporary)
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        target.chmod(0o600)
        total += len(content)
        retained.append({
            "path": str(target),
            "source_bytes": size,
            "preserved_bytes": len(content),
            "source_offset": offset,
            "truncated": len(content) != size,
            "preserved_sha256": sha256(content).hexdigest(),
        })
    return {
        "artifact_root": str(destination) if retained else None,
        "files": retained,
        "file_count": len(retained),
        "preserved_bytes": total,
        "candidate_files_truncated": len(candidates) > len(selected),
    }


@contextmanager
def _capture_failed_prepare_tempfiles(
    *, output_root: Path, prepare_root: Path, workload_id: str,
    events: Any, page_label: dict[str, Any],
) -> Iterator[None]:
    """Instrument only this rehearsal's production prepare tempfile call."""

    original_module = preparation_module.tempfile
    original_temporary_directory = original_module.TemporaryDirectory

    @contextmanager
    def diagnostic_temporary_directory(*args: Any, **kwargs: Any) -> Iterator[str]:
        with original_temporary_directory(*args, **kwargs) as temporary:
            try:
                yield temporary
            except Exception:
                if (
                    kwargs.get("dir") == prepare_root
                    and kwargs.get("prefix") == f".{workload_id}-prepare-"
                ):
                    try:
                        retained = _preserve_failed_prepare_tempfiles(
                            Path(temporary), output_root, workload_id,
                        )
                        events.emit(
                            "failed-prepare-artifacts-preserved",
                            **page_label, workload_id=workload_id, **retained,
                        )
                    except Exception:
                        # Diagnostics cannot replace the preparation failure.
                        pass
                raise

    proxy = SimpleNamespace(TemporaryDirectory=diagnostic_temporary_directory)
    with patch.object(preparation_module, "tempfile", proxy):
        yield


def _parse_target(value: str) -> Target:
    """Accept a catalogue pair, optionally naming one selected page URL."""

    identity, separator, page_url = value.partition("|")
    candidate_id, equals, domain = identity.partition("=")
    if (
        not equals
        or not candidate_id
        or not domain
        or "|" in page_url
        or (separator and not page_url)
    ):
        raise ValueError("target must be ID=DOMAIN or ID=DOMAIN|SELECTED_URL")
    return Target(candidate_id, domain, page_url if separator else None)


def _validated_targets(specs: Sequence[str], catalogue_path: Path) -> tuple[Target, ...]:
    if not 1 <= len(specs) <= MAX_TARGETS:
        raise ValueError(f"rehearsal requires between 1 and {MAX_TARGETS} targets")
    _, catalogue = load_candidate_catalogue_receipt(catalogue_path)
    by_id = {candidate.candidate_id: candidate.domain for candidate in catalogue}
    targets = tuple(_parse_target(spec) for spec in specs)
    if len({target.candidate_id for target in targets}) != len(targets):
        raise ValueError("rehearsal targets contain a repeated candidate ID")
    for target in targets:
        if by_id.get(target.candidate_id) != target.domain:
            raise ValueError(
                "rehearsal target ID/domain is not the exact frozen catalogue pair: "
                f"{target.candidate_id}={target.domain}"
            )
    return targets


def _validated_control(domain: str) -> Target:
    """Give a public control its own diagnostic identity, never a Tranco ID."""

    try:
        canonical_domain(domain)
    except ValueError as error:
        raise ValueError("control domain must be a canonical lower-case domain") from error
    return Target("diagnostic-control", domain, kind="diagnostic-control")


def _new_output_root(raw: Path | None) -> Path:
    if raw is None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        raw = Path(tempfile.gettempdir()) / (
            f"qcsd-acquisition-rehearsal-{stamp}-{uuid.uuid4().hex[:12]}"
        )
    target = Path(os.path.abspath(raw))
    parent = target.parent
    if parent.is_symlink() or not parent.is_dir():
        raise ValueError("diagnostic output parent must be an existing regular directory")
    lab = LAB_ROOT.resolve()
    resolved = target.resolve(strict=False)
    if resolved == lab or lab in resolved.parents:
        raise ValueError("diagnostic output must be outside the Lab checkout")
    if target.exists() or target.is_symlink():
        raise ValueError("diagnostic output must be a new create-only directory")
    target.mkdir(mode=0o700)
    return target


@contextmanager
def _wall_deadline(seconds: int) -> Iterator[None]:
    if not hasattr(signal, "setitimer"):
        raise RuntimeError("bounded rehearsal requires POSIX interval timers")
    if signal.getitimer(signal.ITIMER_REAL)[0] > 0:
        raise RuntimeError("bounded rehearsal cannot replace an existing process timer")
    previous = signal.getsignal(signal.SIGALRM)

    def expire(_number: int, _frame: Any) -> None:
        raise RehearsalTimeout(f"rehearsal exceeded {seconds} seconds")

    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class _EventLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.started = time.monotonic()
        self._stream = path.open("x", encoding="utf-8", buffering=1)

    def emit(self, stage: str, **fields: Any) -> None:
        row = {
            "record_type": RECORD_TYPE,
            "schema_version": 1,
            "scientific_credit": False,
            "at": datetime.now(UTC).isoformat(),
            "elapsed_seconds": round(time.monotonic() - self.started, 3),
            "stage": stage,
            **fields,
        }
        line = json.dumps(row, sort_keys=True, default=str)
        self._stream.write(line + "\n")
        self._stream.flush()
        os.fsync(self._stream.fileno())
        if len(line) > 4096:
            # Keep the complete trace in the fsynced JSONL file without
            # flooding an operator's terminal with bounded CDP event arrays.
            display = json.dumps(
                {
                    "record_type": RECORD_TYPE,
                    "scientific_credit": False,
                    "stage": stage,
                    "elapsed_seconds": row["elapsed_seconds"],
                    "detail_path": str(self.path),
                    "detail_sha256": sha256(line.encode("utf-8")).hexdigest(),
                    "detail_chars": len(line),
                },
                sort_keys=True,
            )
            print(display, flush=True)
        else:
            print(line, flush=True)

    def close(self) -> None:
        self._stream.close()


def _runtime_source() -> tuple[str, dict[str, Any]]:
    image = os.environ.get("QCSD_LAB_IMAGE_DIGEST", "native")
    source = dict(source_metadata())
    if image == "native" and source.get("image_digest") is None:
        source["image_digest"] = "native"
    return image, source


def _neqo_client_binding(backend_factory: Callable[..., Any]) -> dict[str, Any]:
    """Bind the real diagnostic runner binary separately from image metadata."""

    if backend_factory is not ExistingAcquisitionBackend:
        return {"kind": "injected-backend-test-double"}
    raw = os.environ.get("QCSD_NEQO_CLIENT", "/usr/local/bin/neqo-qcsd-client")
    path = Path(raw)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("diagnostic Neqo client must be an absolute regular file")
    if not os.access(path, os.X_OK):
        raise ValueError("diagnostic Neqo client is not executable")
    return {
        "kind": "real-neqo-client",
        "path": str(path.resolve()),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def _mounted_module_hashes() -> dict[str, dict[str, str]]:
    """Identify diagnostic Python files separately from the image build metadata."""

    names = (
        "tools.acquisition_rehearsal",
        "tools.acquisition_root_cdp_trace",
        "qcsd_lab.class_acquisition",
        "qcsd_lab.cdp_targets",
        "qcsd_lab.discover",
        "qcsd_lab.h3_prebaseline",
        "qcsd_lab.prepare",
        "qcsd_lab.playwright_driver",
    )
    hashes = {}
    for name in names:
        module = sys.modules.get(name)
        if module is None:
            continue
        path = Path(module.__file__).resolve()
        if not path.is_relative_to(LAB_ROOT) or not path.is_file():
            raise ValueError(f"diagnostic module is not from mounted Lab source: {name}")
        hashes[name] = {
            "path": str(path.relative_to(LAB_ROOT)),
            "sha256": sha256_file(path),
        }
    return hashes


def _error_classification(error: Exception) -> str:
    if isinstance(error, TerminalAcquisitionPolicyError):
        return "terminal-policy-rejection"
    if isinstance(error, RecoverableAcquisitionError):
        return "recoverable-external-failure"
    return "internal-or-infrastructure-error"


def _preserve_h3_screen_receipt(
    root: Path, *, attempt: int, receipt: Any,
) -> dict[str, str]:
    """Keep the complete screen receipt only inside this diagnostic root."""

    directory = root / "diagnostic-h3-screens"
    directory.mkdir(mode=0o700, exist_ok=True)
    destination = directory / f"screen-{attempt:02d}.json"
    data = (
        json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    with destination.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return {
        "h3_screen_diagnostic_path": str(destination),
        "h3_screen_diagnostic_sha256": sha256_file(destination),
    }


def _probe_selected_page_h3(
    root: Path, *, attempt: int, target: Target, pages: Sequence[Any], events: _EventLog,
) -> None:
    """Compare one canonical selected URL with its origin root, without admission credit."""

    selected = (
        next((page for page in pages if page.url == target.selected_url), None)
        if target.selected_url is not None else pages[0] if pages else None
    )
    if selected is None:
        events.emit(
            "selected-page-h3-diagnostic-skipped",
            candidate_id=target.candidate_id,
            reason="requested URL is absent from canonical selected pages",
        )
        return
    selected_url = selected.url
    selected_origin = origin(selected_url)
    if selected_origin is None or len(selected_url) > 4096:
        events.emit(
            "selected-page-h3-diagnostic-skipped",
            candidate_id=target.candidate_id,
            reason="canonical selected URL is not bounded HTTPS",
        )
        return
    root_url = selected_origin + "/"
    control_url = PREBASELINE_H3_SCREEN_CONTRACT["control_url"]
    events.emit(
        "selected-page-h3-diagnostic-start",
        candidate_id=target.candidate_id,
        root_url=root_url,
        selected_url=selected_url,
    )
    control_before = _run_one(control_url)
    root_probe = selected_probe = control_after = None
    if control_before["outcome"] == "known-valid":
        root_probe = _run_one(root_url)
        selected_probe = _run_one(selected_url)
        control_after = _run_one(control_url)
    controls_pass = (
        control_before["outcome"] == "known-valid"
        and control_after is not None
        and control_after["outcome"] == "known-valid"
    )
    payload = {
        "record_type": "qcsd-non-evidentiary-selected-page-h3-comparison",
        "schema_version": 1,
        "scientific_credit": False,
        "candidate_id": target.candidate_id,
        "domain": target.domain,
        "selected_page_ordinal": selected.ordinal,
        "root_url": root_url,
        "selected_url": selected_url,
        "control_before": control_before,
        "root_probe": root_probe,
        "selected_probe": selected_probe,
        "control_after": control_after,
        "bracketed_by_known_valid_controls": controls_pass,
        "formal_h3_admission_unchanged": True,
    }
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_SELECTED_H3_DIAGNOSTIC_BYTES:
        raise ValueError("selected-page H3 diagnostic exceeded its output bound")
    directory = root / "diagnostic-selected-page-h3"
    directory.mkdir(mode=0o700, exist_ok=True)
    destination = directory / f"comparison-{attempt:02d}.json"
    with destination.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    events.emit(
        "selected-page-h3-diagnostic-complete",
        candidate_id=target.candidate_id,
        root_url=root_url,
        selected_url=selected_url,
        control_before_outcome=control_before["outcome"],
        root_outcome=root_probe["outcome"] if root_probe is not None else None,
        selected_outcome=selected_probe["outcome"] if selected_probe is not None else None,
        control_after_outcome=(
            control_after["outcome"] if control_after is not None else None
        ),
        bracketed_by_known_valid_controls=controls_pass,
        formal_h3_admission_unchanged=True,
        diagnostic_path=str(destination),
        diagnostic_sha256=sha256_file(destination),
    )


def _probe_all_selected_pages_h3(
    root: Path, *, attempt: int, target: Target, pages: Sequence[Any], events: _EventLog,
) -> None:
    """Probe every canonical selected URL under one diagnostic control bracket."""

    if not 1 <= len(pages) <= MAX_PAGE_CANDIDATES:
        raise ValueError("all-page H3 diagnostic requires one to five selected pages")
    selected_pages = []
    for page in pages:
        selected_url = page.url
        selected_origin = origin(selected_url)
        if selected_origin is None or len(selected_url) > 4096:
            raise ValueError("all-page H3 diagnostic requires bounded canonical HTTPS URLs")
        selected_pages.append({
            "ordinal": page.ordinal,
            "url": selected_url,
            "root_url": selected_origin + "/",
            "probe": None,
        })
    control_url = PREBASELINE_H3_SCREEN_CONTRACT["control_url"]
    events.emit(
        "all-selected-pages-h3-diagnostic-start",
        candidate_id=target.candidate_id,
        selected_urls=[page["url"] for page in selected_pages],
    )
    control_before = _run_one(control_url)
    root_probes: dict[str, dict[str, Any]] = {}
    control_after = None
    if control_before["outcome"] == "known-valid":
        for page in selected_pages:
            root_url = page["root_url"]
            if root_url not in root_probes:
                root_probes[root_url] = _run_one(root_url)
            page["probe"] = _run_one(page["url"])
        control_after = _run_one(control_url)
    controls_pass = (
        control_before["outcome"] == "known-valid"
        and control_after is not None
        and control_after["outcome"] == "known-valid"
    )
    payload = {
        "record_type": "qcsd-non-evidentiary-all-selected-pages-h3-comparison",
        "schema_version": 1,
        "scientific_credit": False,
        "candidate_id": target.candidate_id,
        "domain": target.domain,
        "control_before": control_before,
        "root_probes": root_probes,
        "selected_pages": selected_pages,
        "control_after": control_after,
        "bracketed_by_known_valid_controls": controls_pass,
        "formal_h3_admission_unchanged": True,
    }
    data = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(data) > MAX_ALL_SELECTED_H3_DIAGNOSTIC_BYTES:
        raise ValueError("all-page H3 diagnostic exceeded its output bound")
    directory = root / "diagnostic-selected-page-h3"
    directory.mkdir(mode=0o700, exist_ok=True)
    destination = directory / f"comparison-{attempt:02d}.json"
    with destination.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    events.emit(
        "all-selected-pages-h3-diagnostic-complete",
        candidate_id=target.candidate_id,
        control_before_outcome=control_before["outcome"],
        control_after_outcome=(
            control_after["outcome"] if control_after is not None else None
        ),
        bracketed_by_known_valid_controls=controls_pass,
        page_outcomes=[{
            "ordinal": page["ordinal"],
            "url": page["url"],
            "root_url": page["root_url"],
            "root_outcome": (
                root_probes[page["root_url"]]["outcome"]
                if page["root_url"] in root_probes else None
            ),
            "selected_outcome": (
                page["probe"]["outcome"] if page["probe"] is not None else None
            ),
        } for page in selected_pages],
        formal_h3_admission_unchanged=True,
        diagnostic_path=str(destination),
        diagnostic_sha256=sha256_file(destination),
    )


def _validate_prepared(
    prepared: Any, *, workload_id: str,
    approved_origins: Sequence[str], origin_ip_pins: dict[str, str],
) -> dict[str, Any]:
    path = Path(prepared.prepared.path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("prepared manifest is not a regular file")
    manifest = load_json(path)
    validate_class_study_preparation(manifest, workload_id=workload_id)
    digest = sha256_file(path)
    primary = _prepared_primary_response(manifest)
    preparation = manifest["preparation"]
    if (
        digest != prepared.prepared.sha256
        or prepared.final_url != preparation["final_url"]
        or prepared.status != primary["status"]
        or prepared.body_bytes != primary["bytes"]
        or prepared.body_sha256 != primary["body_sha256"]
        or prepared.resource_graph_sha256 != _prepared_replay_identity_sha256(manifest)
        or preparation["approved_origins"] != list(approved_origins)
        or preparation["origin_ip_pins"] != origin_ip_pins
        or dict(prepared.preparation_origin_ip_pins or {})
        != origin_ip_pins
    ):
        raise ValueError("prepared result differs from deeply revalidated manifest")
    return {
        "manifest_path": str(path),
        "manifest_sha256": digest,
        "final_url": prepared.final_url,
        "status": prepared.status,
        "body_bytes": prepared.body_bytes,
        "body_sha256": prepared.body_sha256,
        "resource_graph_sha256": prepared.resource_graph_sha256,
        "approved_origins": preparation["approved_origins"],
    }


def run_rehearsal(
    targets: Sequence[Target],
    *,
    output_root: Path,
    max_pages: int = 1,
    navigation_timeout_ms: int = DEFAULT_NAVIGATION_TIMEOUT_MS,
    total_timeout_seconds: int = DEFAULT_TOTAL_SECONDS,
    backend_factory: Callable[..., Any] = ExistingAcquisitionBackend,
    trace_root_cdp: bool = False,
    continue_after_h3_screen: bool = False,
    probe_selected_page_h3: bool = False,
    probe_all_selected_pages_h3: bool = False,
) -> dict[str, Any]:
    """Run the real backend on bounded catalogue targets, without runner state."""

    if not 1 <= len(targets) <= MAX_TARGETS:
        raise ValueError("rehearsal target count is out of bounds")
    if type(max_pages) is not int or not 1 <= max_pages <= MAX_PAGE_CANDIDATES:
        raise ValueError("rehearsal max pages is out of bounds")
    if type(navigation_timeout_ms) is not int or not 1 <= navigation_timeout_ms <= 60_000:
        raise ValueError("rehearsal navigation timeout is out of bounds")
    if type(total_timeout_seconds) is not int or not 1 <= total_timeout_seconds <= MAX_TOTAL_SECONDS:
        raise ValueError("rehearsal total timeout is out of bounds")
    if probe_selected_page_h3 and probe_all_selected_pages_h3:
        raise ValueError("choose one selected-page H3 diagnostic mode")
    root = Path(output_root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("diagnostic output root is not a regular directory")
    neqo_client = _neqo_client_binding(backend_factory)
    prepared_root = root / "prepared"
    prepared_root.mkdir(mode=0o700)
    events = _EventLog(root / "events.jsonl")
    image, source = _runtime_source()
    attempts = 0
    successful_pages = 0
    failed_targets = 0
    h3_override_prepared_pages = 0
    screen_decision_counts = {"pass": 0, "site-rejection": 0, "blocked": 0}
    timed_out = False
    try:
        events.emit(
            "run-start",
            target_count=len(targets),
            max_pages=max_pages,
            navigation_timeout_ms=navigation_timeout_ms,
            total_timeout_seconds=total_timeout_seconds,
            image_digest=image,
            runtime_source=source,
            runtime_source_role="underlying-image-build-metadata",
            mounted_module_hashes=_mounted_module_hashes(),
            neqo_client=neqo_client,
            output_root=str(root),
            root_cdp_trace_enabled=trace_root_cdp,
            continue_after_h3_screen=continue_after_h3_screen,
            probe_selected_page_h3=probe_selected_page_h3,
            probe_all_selected_pages_h3=probe_all_selected_pages_h3,
        )
        try:
            with _wall_deadline(total_timeout_seconds):
                if trace_root_cdp:
                    from tools.acquisition_root_cdp_trace import install

                    install(events.emit)
                for target in targets:
                    attempts += 1
                    label = {
                        "target_kind": target.kind,
                        "domain": target.domain,
                        (
                            "catalogue_candidate_id"
                            if target.kind == "catalogue-candidate" else "diagnostic_label"
                        ): target.candidate_id,
                    }
                    events.emit("candidate-start", **label, requested_page_url=target.selected_url)
                    stage = "navigation"
                    screen_binding: dict[str, str] = {}
                    try:
                        backend = backend_factory(timeout_ms=navigation_timeout_ms)
                        navigation = backend.discover_navigation(target.domain)
                        pages = select_page_candidates(
                            target.domain,
                            registrable_domain=navigation.registrable_domain,
                            discovered_links=navigation.links,
                        )
                        seeds = _navigation_origins_by_page(navigation, pages)
                        events.emit(
                            "navigation-complete", **label,
                            selected_pages=[page.url for page in pages],
                            observed_origins=list(navigation.observed_origins),
                        )
                        if probe_selected_page_h3 or probe_all_selected_pages_h3:
                            try:
                                if probe_all_selected_pages_h3:
                                    _probe_all_selected_pages_h3(
                                        root, attempt=attempts, target=target,
                                        pages=pages, events=events,
                                    )
                                else:
                                    _probe_selected_page_h3(
                                        root, attempt=attempts, target=target,
                                        pages=pages, events=events,
                                    )
                            except RehearsalTimeout:
                                raise
                            except Exception as error:
                                events.emit(
                                    "selected-page-h3-diagnostic-error", **label,
                                    error_type=type(error).__name__, error=str(error),
                                    formal_h3_admission_unchanged=True,
                                )
                        stage = "h3-screen"
                        try:
                            receipt = backend.screen_h3(
                                target.candidate_id, target.domain, navigation, pages
                            )
                        except (H3SiteUnavailable, H3ScreenBlocked) as error:
                            receipt = error.receipt
                        screen_binding = _preserve_h3_screen_receipt(
                            root, attempt=attempts, receipt=receipt,
                        )
                        events.emit("h3-screen-receipt-preserved", **label, **screen_binding)
                        screen = validate_h3_screen_receipt(
                            receipt,
                            candidate_id=target.candidate_id,
                            domain=target.domain,
                            image_digest=image,
                            source=source,
                        )
                        screen_decision_counts[screen["decision"]] += 1
                        page_attempts = screen.get("page_attempts")
                        if isinstance(page_attempts, list):
                            screen_outcomes = {
                                "page_outcomes": [
                                    {
                                        "url": item["url"],
                                        "attempts": [
                                            attempt["outcome"] for attempt in item["attempts"]
                                        ],
                                    }
                                    for item in page_attempts
                                ]
                            }
                            eligible_page_urls = {
                                item["url"] for item in page_attempts
                                if all(
                                    attempt["outcome"] == "known-valid"
                                    for attempt in item["attempts"]
                                )
                            }
                        else:
                            screen_outcomes = {
                                "origin_outcomes": [
                                    {
                                        "origin": item["origin"],
                                        "attempts": [
                                            attempt["outcome"] for attempt in item["attempts"]
                                        ],
                                    }
                                    for item in screen["origin_attempts"]
                                ]
                            }
                            eligible_page_urls = {page.url for page in pages}
                        events.emit(
                            "h3-screen-complete", **label,
                            decision=screen["decision"],
                            continued_despite_nonpass=(
                                screen["decision"] != "pass" and continue_after_h3_screen
                            ),
                            **screen_binding,
                            control_before=screen["control_before"]["outcome"],
                            control_after=(
                                screen["control_after"]["outcome"]
                                if screen["control_after"] is not None else None
                            ),
                            **screen_outcomes,
                        )
                        if screen["decision"] != "pass" and not continue_after_h3_screen:
                            failed_targets += 1
                            continue
                        selected = (
                            [page for page in pages if page.url == target.selected_url]
                            if target.selected_url is not None else list(pages)
                        )
                        if screen["decision"] == "pass":
                            selected = [
                                page for page in selected if page.url in eligible_page_urls
                            ]
                        if target.selected_url is None:
                            selected = selected[:max_pages]
                        if not selected:
                            in_navigation = any(
                                page.url == target.selected_url for page in pages
                            ) if target.selected_url is not None else True
                            classification = (
                                "target-page-not-h3-eligible"
                                if in_navigation and screen["decision"] == "pass"
                                else "target-page-not-selected"
                            )
                            events.emit(
                                "candidate-error", **label, failed_stage="page-selection",
                                classification=classification,
                                error_type="ValueError",
                                error=(
                                    "selected page did not pass the exact-url H3 screen"
                                    if classification == "target-page-not-h3-eligible"
                                    else "requested page was absent from canonical navigation selection"
                                ),
                            )
                            failed_targets += 1
                            continue
                        candidate_succeeded = False
                        for page in selected:
                            page_label = {
                                **label,
                                "page_ordinal": page.ordinal,
                                "page_url": page.url,
                                "h3_screen_decision": screen["decision"],
                                "h3_policy_overridden": screen["decision"] != "pass",
                            }
                            stage = "origin-convergence"
                            events.emit("origin-convergence-start", **page_label)
                            approved, discovery = _converge_origins(
                                backend, page.url, seed_origins=seeds[page.url]
                            )
                            events.emit(
                                "origin-convergence-complete", **page_label,
                                approved_origins=list(approved),
                                observed_origins=list(discovery.observed_origins),
                                origin_ip_pins=dict(discovery.origin_ip_pins),
                            )
                            stage = "prepare"
                            workload_id = (
                                f"diagnostic-{target.candidate_id}-p{page.ordinal:02d}-"
                                f"{uuid.uuid4().hex[:8]}"
                            )
                            events.emit("prepare-start", **page_label, workload_id=workload_id)
                            prepare_output = prepared_root / workload_id
                            with _capture_failed_prepare_tempfiles(
                                output_root=root,
                                prepare_root=prepare_output,
                                workload_id=workload_id,
                                events=events,
                                page_label=page_label,
                            ):
                                prepared = backend.prepare(
                                    workload_id,
                                    page.url,
                                    approved,
                                    prepare_output,
                                    origin_ip_pins=discovery.origin_ip_pins,
                                )
                            events.emit(
                                "prepare-complete", **page_label, workload_id=workload_id,
                                prepared_manifest_path=str(prepared.prepared.path),
                            )
                            stage = "prepared-validation"
                            verified = _validate_prepared(
                                prepared, workload_id=workload_id,
                                approved_origins=approved,
                                origin_ip_pins=dict(discovery.origin_ip_pins),
                            )
                            successful_pages += 1
                            if screen["decision"] != "pass":
                                h3_override_prepared_pages += 1
                            candidate_succeeded = True
                            events.emit(
                                "prepared-validation-complete", **page_label,
                                workload_id=workload_id, **verified,
                            )
                        if not candidate_succeeded or screen["decision"] != "pass":
                            failed_targets += 1
                    except RehearsalTimeout:
                        raise
                    except Exception as error:  # diagnostic must retain every failed stage
                        failed_targets += 1
                        events.emit(
                            "candidate-error", **label, failed_stage=stage,
                            classification=_error_classification(error),
                            error_type=type(error).__name__, error=str(error),
                            **screen_binding,
                        )
        except RehearsalTimeout as error:
            timed_out = True
            events.emit("run-timeout", error_type=type(error).__name__, error=str(error))
        if _neqo_client_binding(backend_factory) != neqo_client:
            raise ValueError("diagnostic Neqo client changed during the rehearsal")
        summary = {
            "attempted_targets": attempts,
            "successful_pages": successful_pages,
            "h3_pass_prepared_pages": successful_pages - h3_override_prepared_pages,
            "h3_override_prepared_pages": h3_override_prepared_pages,
            "h3_screen_decision_counts": screen_decision_counts,
            "failed_targets": failed_targets,
            "timed_out": timed_out,
            "output_root": str(root),
            "neqo_client": neqo_client,
            "scientific_credit": False,
        }
        summary["diagnostic_outcome"] = (
            "timed-out" if timed_out else
            "passing-screen-prepare" if summary["h3_pass_prepared_pages"] else
            "bypassed-screen-prepare-only" if h3_override_prepared_pages else
            "no-prepared-page"
        )
        events.emit("run-complete", **summary)
        return summary
    finally:
        events.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Exit 0: H3 pass and prepared page; 3: prepared only after explicit H3 "
            "override; 1: no prepared page or timeout; 2: invocation/runtime error."
        ),
    )
    parser.add_argument(
        "--target", action="append", metavar="ID=DOMAIN[|SELECTED_URL]",
        help="exact candidate ID/domain pair from the frozen catalogue; repeat up to six times",
    )
    parser.add_argument(
        "--catalogue", type=Path,
        default=LAB_ROOT / "config/class-study/v1/classifier-multiorigin100-v1-candidates.json",
    )
    parser.add_argument(
        "--output-root", type=Path,
        help="new diagnostic directory outside the Lab checkout (default: new /tmp directory)",
    )
    parser.add_argument(
        "--control-domain", metavar="DOMAIN",
        help="run one explicitly labelled diagnostic control, separate from catalogue targets",
    )
    parser.add_argument(
        "--trace-root-cdp", action="store_true",
        help="emit extra diagnostic root CDP interception traces without changing production policy",
    )
    parser.add_argument(
        "--continue-after-h3-screen", action="store_true",
        help=(
            "diagnostic only: retain a rejected or blocked H3 decision, then still "
            "attempt origin convergence and preparation; never grants acquisition credit"
        ),
    )
    parser.add_argument(
        "--probe-selected-page-h3", action="store_true",
        help=(
            "diagnostic only: compare the origin root with one exact canonical "
            "selected page URL using Neqo probes bracketed by controls"
        ),
    )
    parser.add_argument(
        "--probe-all-selected-pages-h3", action="store_true",
        help=(
            "diagnostic only: compare up to five canonical selected URLs with "
            "their origin roots under one Neqo control bracket"
        ),
    )
    parser.add_argument("--max-pages", type=int, default=1)
    parser.add_argument(
        "--navigation-timeout-ms", type=int, default=DEFAULT_NAVIGATION_TIMEOUT_MS
    )
    parser.add_argument("--total-timeout-seconds", type=int, default=DEFAULT_TOTAL_SECONDS)
    args = parser.parse_args(argv)
    try:
        if bool(args.target) == bool(args.control_domain):
            raise ValueError("provide catalogue --target values or one --control-domain")
        if args.probe_selected_page_h3 and args.probe_all_selected_pages_h3:
            raise ValueError("choose one selected-page H3 diagnostic mode")
        targets = (
            _validated_targets(args.target, args.catalogue)
            if args.target else (_validated_control(args.control_domain),)
        )
        if not 1 <= args.max_pages <= MAX_PAGE_CANDIDATES:
            raise ValueError("rehearsal max pages is out of bounds")
        if not 1 <= args.navigation_timeout_ms <= 60_000:
            raise ValueError("rehearsal navigation timeout is out of bounds")
        if not 1 <= args.total_timeout_seconds <= MAX_TOTAL_SECONDS:
            raise ValueError("rehearsal total timeout is out of bounds")
        output_root = _new_output_root(args.output_root)
        result = run_rehearsal(
            targets,
            output_root=output_root,
            max_pages=args.max_pages,
            navigation_timeout_ms=args.navigation_timeout_ms,
            total_timeout_seconds=args.total_timeout_seconds,
            trace_root_cdp=args.trace_root_cdp,
            continue_after_h3_screen=args.continue_after_h3_screen,
            probe_selected_page_h3=args.probe_selected_page_h3,
            probe_all_selected_pages_h3=args.probe_all_selected_pages_h3,
        )
    except (OSError, RuntimeError, ValueError) as error:
        print(f"acquisition rehearsal failed: {error}", file=sys.stderr, flush=True)
        return 2
    if result["timed_out"]:
        return 1
    if result["h3_pass_prepared_pages"] > 0:
        return 0
    return 3 if result["h3_override_prepared_pages"] > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
