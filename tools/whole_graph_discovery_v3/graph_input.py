"""Create-only, zero-credit whole-graph discovery input production.

The physical ``discover`` entry point is for the root operator.  Declaration,
reopening and resource projection never launch a browser or make network calls.
This module neither imports nor modifies the historical static GET producers.
"""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
import traceback
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

PLAN_TYPE = "qcsd-external-navigation-seeded-whole-graph-catalogue-plan-v3"
INPUT_TYPE = "qcsd-external-browser-whole-graph-input-v3"
CONTRACT = "catalogue-homepage-navigation-seeded-complete-occurrence-graph-input-only-v3"
SELECTION = "next-unseen-frozen-catalogue-order-before-measurement-v3"
DISCOVERY_LAB = "2b990d930358e4a3ba499ae7090f0bd8edb4afeb"
DISCOVERY_NATIVE = "c24da2afeec2944a67c48b38eba957dcd543728d"
DISCOVERY_IMAGE = "sha256:abc21255157c4c6cc12b1941b8789c82642899b264e88539c2549b66259b10fa"
ANCHOR_PLAN = "7058c97e7b513e30d2d487348b66cbfc8d5a3f9196803fdeccf375f9e81e0164"
ANCHOR_BATCH = "8bcac17af57b45b8662b78707a9d5c9db39babbfead9d5781fba91602791562a"
ORIGINAL_PRODUCER_SHA256 = {
    "graph_input.py": "9477be712eaaa8bf4af5d1e39922516ee37cd9e608a875bd772e85a11363d0dc",
    "operator.py": "b5826b33a9c4f109764997bcb92979bb940cdf750cf09f411aac9369d03c3c68",
}
RETRY_INDICES = [1, 2]
RETRY_POLICY = "prospective-navigation-setup-repair-original-candidates-1-2-only-v2"
ADAPTER_TYPE = "qcsd-prospective-whole-graph-static-get-adapter-plan-v1"
LEGACY_PRODUCERS = {1: ORIGINAL_PRODUCER_SHA256, 2: {
    "graph_input.py": "6e73cb1678ff98396e1416cfce3127cf60122db5500281f5749201d1d23a2eba",
    "operator.py": "d980ad2581fbac7add9c13e5368ad9fd2ed16cefc38d4e0ab7dcd4279988ebb6"}}
MAX_BATCH = 5
MAX_CANDIDATE_SECONDS = 180
ZERO = {"scientific_credit": False, "site_credit": 0, "formal_accepted_trace_count": 0}
RESOURCE_KEYS = {"id", "url", "type", "content_length", "data_length",
                 "chaff_priority", "known_valid", "depends_on", "headers"}
PLAN_KEYS = {"schema_version", "artifact_type", "contract", "declared_at", "selection_policy",
    "catalogue", "catalogue_payload_sha256", "original_prefix", "previous_plans", "reserved_candidates", "source",
    "browser_image", "source_metadata", "producer_sources", "candidates", "candidate_deadline_seconds",
    "backend_navigation_timeout_ms", "max_origin_passes", "max_approved_origins", "passive_render_contract",
    "discovery_only", "calls_prepare", "root_resurvey", "browser_image_execution_verified", "history_batches", "history", *ZERO}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def pretty(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load(raw: bytes) -> Any:
    def invalid(_: str) -> None:
        raise ValueError("nonfinite JSON value")
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=invalid)


def regular(path: Path, *, directory: bool = False) -> Path:
    path = path.absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("symlink in bound path")
    if not (path.is_dir() if directory else path.is_file()):
        raise ValueError("bound path has the wrong type")
    return path


def read(path: Path) -> bytes:
    path = regular(path)
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("bound file changed while opening")
        raw = stream.read()
        after = path.lstat()
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns):
            raise ValueError("bound file changed while reading")
    return raw


def reference(path: Path) -> dict[str, str]:
    path = regular(path)
    return {"path": str(path), "sha256": sha(read(path)), "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}"}


def reopen(value: Any) -> tuple[Path, bytes]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "mode"}:
        raise ValueError("reference fields differ")
    path = regular(Path(value["path"]))
    raw = read(path)
    if reference(path) != value:
        raise ValueError("bound bytes or mode changed")
    return path, raw


def _fsync_directory(path: Path) -> None:
    fd = os.open(regular(path, directory=True), os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create(path: Path, raw: bytes) -> None:
    regular(path.parent, directory=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    _fsync_directory(path.parent)


def create_json(path: Path, value: Any) -> dict[str, str]:
    create(path, pretty(value))
    return reference(path)


def fresh_directory(path: Path, protected: list[Path]) -> Path:
    path = path.absolute()
    regular(path.parent, directory=True)
    for item in protected:
        item = item.absolute()
        if path == item or path.is_relative_to(item) or item.is_relative_to(path):
            raise ValueError("output overlaps a bound input")
    path.mkdir(mode=0o700, exist_ok=False)
    _fsync_directory(path.parent)
    return path


def _git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *args], check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
    return result.stdout


def source_snapshot(root: Path, expected_commit: str | None = None) -> dict[str, Any]:
    root = regular(root, directory=True)
    commit = _git(root, "rev-parse", "HEAD").decode().strip()
    if expected_commit is not None and commit != expected_commit:
        raise ValueError("discovery Source commit changed")
    if _git(root, "status", "--porcelain", "--untracked-files=no", "--ignore-submodules=untracked").strip():
        raise ValueError("discovery requires clean tracked Source")
    files = {}
    gitlinks = {}
    for item in _git(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not item:
            continue
        fields, name = item.split(b"\t", 1)
        mode, digest, stage = fields.decode().split()
        name = name.decode()
        if stage != "0" or Path(name).is_absolute() or ".." in Path(name).parts:
            raise ValueError("Source index has an unresolved or invalid entry")
        if mode == "160000":
            gitlinks[name] = digest
            if _git(root / name, "rev-parse", "HEAD").decode().strip() != digest:
                raise ValueError("discovery Source Gitlink differs")
        elif mode in {"100644", "100755"}:
            item_path = root / name
            files[name] = {"sha256": sha(read(item_path)),
                           "mode": f"{stat.S_IMODE(item_path.stat().st_mode):04o}"}
        else:
            raise ValueError("Source includes an unsupported tracked file type")
    return {"root": str(root), "lab_commit": commit, "gitlinks": gitlinks, "files": files}


def verify_snapshot(value: dict[str, Any]) -> None:
    """Reopen HOST-frozen bytes without requiring Git in the browser image."""
    if (set(value) != {"root", "lab_commit", "gitlinks", "files"}
            or not re.fullmatch(r"[0-9a-f]{40}", value["lab_commit"])
            or not value["files"] or set(value["gitlinks"]) != {"neqo-qcsd"}):
        raise ValueError("discovery Source inventory fields differ")
    root = regular(Path(value["root"]), directory=True)
    for name, bound in value["files"].items():
        if Path(name).is_absolute() or ".." in Path(name).parts:
            raise ValueError("Source inventory escapes its declared root")
        path = root / name
        if {"sha256": sha(read(path)), "mode": f"{stat.S_IMODE(path.stat().st_mode):04o}"} != bound:
            raise ValueError("discovery Source bytes or mode changed")


def zero_credit(value: dict[str, Any]) -> bool:
    return (value.get("scientific_credit") is False
            and type(value.get("site_credit")) is int and value["site_credit"] == 0
            and type(value.get("formal_accepted_trace_count")) is int and value["formal_accepted_trace_count"] == 0)


def validate_source_metadata(metadata: Any, snapshot: dict[str, Any], required_keys: set[str]) -> None:
    empty_patch = {None, sha(b"")}
    if (not isinstance(metadata, dict) or set(metadata) != required_keys
            or metadata["lab_commit"] != snapshot["lab_commit"] or metadata["lab_dirty"] is not False
            or metadata["neqo_dirty"] is not False or metadata["lab_patch_sha256"] not in empty_patch
            or metadata["neqo_patch_sha256"] not in empty_patch
            or metadata["neqo_commit"] != snapshot["gitlinks"].get("neqo-qcsd")
            or metadata["neqo_pinned_commit"] != metadata["neqo_commit"]):
        raise ValueError("browser runtime Source is not the declared clean discovery Source")


def _modules(root: Path) -> dict[str, Any]:
    sys.dont_write_bytecode = True
    source_path = str(root / "src")
    if source_path not in sys.path:
        sys.path.insert(0, source_path)
    names = ("class_catalogue", "class_acquisition", "discover", "discovery_evidence", "manifest", "util", "rapid_page_evidence")
    result = {name: importlib.import_module("qcsd_lab." + name) for name in names}
    for name, module in result.items():
        if Path(module.__file__).resolve() != (root / "src/qcsd_lab" / (name + ".py")).resolve():
            raise ValueError("discovery imported a different Source")
    return result


def parent_binding(context: Path, modules: dict[str, Any]) -> dict[str, Any]:
    """Bind only immutable input prefix; this is not an old GET revalidation."""
    context = regular(context, directory=True)
    provenance_ref = reference(context / "provenance.json")
    value = load(reopen(provenance_ref)[1])
    if (set(value) != {"schema_version", "receipt_type", "payload", "payload_sha256"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["receipt_type"] != "qcsd-static-fixed-resource-acquisition-v1"
            or value["payload_sha256"] != sha(pretty(value["payload"]))):
        raise ValueError("original context envelope is not authenticated")
    payload = value["payload"]
    source = reference(context / "source-list.json")
    order = reference(context / "candidate-order.json")
    profile = reference(context / "profile.json")
    for key, ref in [("source_list", source), ("candidate_order", order), ("profile", profile)]:
        if payload[key] != {k: ref[k] for k in ("path", "sha256")}:
            raise ValueError("original prefix changes its bound input")
    raw = reopen(source)[1]
    if payload["source_sha256"] != source["sha256"]:
        raise ValueError("original source digest differs")
    # Use the byte-exact old input parser, without reopening GET or active state.
    graph = importlib.import_module("qcsd_lab.supplied_static_graph")
    static = importlib.import_module("qcsd_lab.supplied_static_admission")
    rows = graph._source(raw, source["sha256"])
    candidates = static._candidate_rows(raw, source["sha256"], load(reopen(order)[1]))
    if list(candidates) != payload["candidates"] or payload["scientific_credit"] is not False:
        raise ValueError("original candidate prefix was changed")
    return {"role": "original-source-and-order-binding-only-no-admission-credit-v1",
            "context": provenance_ref, "source_list": source, "candidate_order": order,
            "profile": profile, "candidate_count": len(candidates),
            "candidates": list(candidates), "domains": [row["crUX_domain"] for row in rows], **ZERO}


def reserved_candidates(previous: list[dict[str, Any]]) -> list[dict[str, Any]]:
    identities = {}
    domains = {}
    for old in previous:
        for row in [*old.get("reserved_candidates", []), *old["candidates"]]:
            identity, domain = row["candidate_id"], row["domain"]
            if (identity in identities and identities[identity] != row
                    or domain in domains and domains[domain] != identity):
                raise ValueError("previous declarations conflict on a reserved identity")
            identities[identity] = row
            domains[domain] = identity
    return list(identities.values())


def select_candidates(catalogue: list[dict[str, Any]], original_domains: list[str],
                      previous: list[dict[str, Any]], count: int) -> list[dict[str, Any]]:
    if type(count) is not int or not 1 <= count <= MAX_BATCH:
        raise ValueError("bounded discovery batch count must be 1..5")
    blocked_domains = set(original_domains)
    blocked_ids = set()
    for row in reserved_candidates(previous):
        if row["domain"] in blocked_domains:
            raise ValueError("previous declaration repeats an original identity")
        blocked_ids.add(row["candidate_id"])
        blocked_domains.add(row["domain"])
    eligible = [(i, row) for i, row in enumerate(catalogue, 1)
                if row["domain"] not in blocked_domains and row["candidate_id"] not in blocked_ids]
    if len(eligible) < count:
        raise ValueError("frozen catalogue lacks enough unseen identities")
    return [{"catalogue_position": i, "candidate_id": row["candidate_id"],
             "domain": row["domain"], "rank": row["rank"], "stratum": row["stratum"],
             "source_url": "https://" + row["domain"] + "/"} for i, row in eligible[:count]]


def project_resources(resources: Any, approved_origins: list[str]) -> dict[str, Any]:
    """Retain every occurrence, edge and discovery-safe header without rewriting."""
    if not isinstance(resources, list) or not resources:
        raise ValueError("whole graph has no resources")
    approved = set(approved_origins)
    for index, row in enumerate(resources):
        if not isinstance(row, dict) or set(row) != RESOURCE_KEYS or type(row["id"]) is not int or row["id"] != index:
            raise ValueError("whole graph changes occurrence identities or fields")
        if not isinstance(row["url"], str):
            raise ValueError("whole graph resource URL is not a string")
        parts = urlsplit(row["url"])
        try:
            port = parts.port
        except ValueError as error:
            raise ValueError("invalid resource port") from error
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            raise ValueError("whole graph contains an unsupported resource URL")
        host = parts.hostname.lower()
        if ":" in host:
            host = "[" + host + "]"
        origin = "https://" + host + (":" + str(port) if port not in (None, 443) else "")
        if origin not in approved:
            raise ValueError("whole graph includes an unapproved resource origin")
        edges = row["depends_on"]
        if (not isinstance(edges, list)
                or any(type(edge) is not int or not 0 <= edge < index for edge in edges)
                or edges != sorted(set(edges))):
            raise ValueError("whole graph changes its preceding occurrence DAG")
        if (row["content_length"] is not None or type(row["data_length"]) is not int or row["data_length"] != 0
                or row["known_valid"] is not False or row["chaff_priority"] is not False
                or not isinstance(row["type"], str)):
            raise ValueError("discovery cannot claim GET response validity")
        headers = row["headers"]
        if (not isinstance(headers, list) or any(not isinstance(pair, list) or len(pair) != 2
                or any(not isinstance(item, str) for item in pair) for pair in headers)):
            raise ValueError("whole graph header representation differs")
    return {"resources": deepcopy(resources)}


def adapter_plan(parent: dict[str, Any]) -> dict[str, Any]:
    return {"schema_version": 1, "artifact_type": ADAPTER_TYPE,
        "status": "prospective-interface-plan-not-executable-get-or-admission-authority",
        "original_prefix": parent,
        "supplement_input_role": INPUT_TYPE,
        "lossless_projection": "exact-ordered-resources-including-repeated-URLs-DAG-and-safe-headers-v1",
        "legacy_branch": "unchanged-original-context-parser-producers-runtime-and-full-GET-reopening",
        "supplement_branch": "separate-typed-graph-producer-and-current-runtime-complete-GET-proof",
        "requirements": [
            "append immutable whole-graph references after the exact original ordered prefix",
            "bind every discovered pass and final successful convergence to declared catalogue identity and Source",
            "reopen complete raw current-Native GET outputs for every graph occurrence and resource origin",
            "require actual HTML primary and nonempty successful secondary-origin response",
            "retain redirects and all nodes; reject the whole candidate if current primary semantics cannot represent it",
            "record an actual failed GET as operational deferral; do not prune or grant browser-only admission",
            "bind distinct per-input producer/runtime roles explicitly; no historical runtime or Source promotion",
            "extend enrollment/read-only transport/fence through typed dispatch without rewriting original GET roots"],
        "source_seams": ["supplied_static_admission._candidate_rows/initialize_context/load_context",
            "supplied_static_bootstrap_get._inputs/build_proof",
            "supplied_static_preparation._prepared/validate_static_preparation",
            "rapid_rolling_capture enrollment/readiness roots", "rapid_formal_parallel._release_fence"],
        "original_producer_units_to_preserve": ["supplied_static_graph", "supplied_static_admission",
            "supplied_static_get", "supplied_static_bootstrap_get", "supplied_static_preparation"],
        "new_lab_adapter_implemented": False, "native_changes_required_by_graph_shape": False,
        "final_class_target": 50, "settings": 5, "visits_per_setting": 64,
        "formal_trace_target": 16000, **ZERO}


def _utc(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp is not text")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() != timezone.utc.utcoffset(result):
        raise ValueError("timestamp is not UTC")
    return result


def _original_plan(path: Path) -> dict[str, Any]:
    """Execute only the pinned, unchanged historical external HOST verifier."""
    value = load(read(path))
    refs = value.get("producer_sources", {})
    if set(refs) != set(ORIGINAL_PRODUCER_SHA256):
        raise ValueError("original producer pair differs")
    for name, expected in ORIGINAL_PRODUCER_SHA256.items():
        bound_path, raw = reopen(refs[name])
        if bound_path.name != name or sha(raw) != expected:
            raise ValueError("original producer bytes differ from the reviewed version")
    producer = Path(refs["graph_input.py"]["path"])
    if Path(refs["operator.py"]["path"]).parent != producer.parent:
        raise ValueError("original producer pair is split")
    spec = importlib.util.spec_from_file_location("pinned_original_whole_graph_discovery", producer)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.check_plan(path)


def _tree(root: Path, limit: int = 64) -> dict[str, Any]:
    root = regular(root, directory=True)
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("retained failed attempt contains an unsupported path")
        if path.is_file():
            result[str(path.relative_to(root))] = reference(path)
        if len(result) > limit:
            raise ValueError("retained failed attempt exceeds its bounded inventory")
    return result


def _retry_binding(original_path: Path, batch_path: Path, original: dict[str, Any]) -> dict[str, Any]:
    """Retain all original outcomes; only the two setup failures are retried."""
    batch = load(read(batch_path))
    if (set(batch) != {"candidates", "closed_at", "closed_whole_graph_inputs", "declared_candidates",
            "formal_credit", "ordinary_complete_get_and_typed_admission_still_required", "plan", "site_credit"}
            or batch["plan"] != {key: reference(original_path)[key] for key in ("path", "sha256")}
            or len(original["candidates"]) != 5 or type(batch["declared_candidates"]) is not int
            or batch["declared_candidates"] != 5 or type(batch["closed_whole_graph_inputs"]) is not int
            or batch["closed_whole_graph_inputs"] != 0
            or type(batch["formal_credit"]) is not int or batch["formal_credit"] != 0
            or type(batch["site_credit"]) is not int or batch["site_credit"] != 0
            or batch["ordinary_complete_get_and_typed_admission_still_required"] is not True
            or not isinstance(batch["candidates"], list) or len(batch["candidates"]) != 5):
        raise ValueError("original batch is not the retained five failed attempts")
    attempts = []
    last_end = _utc(original["declared_at"])
    for index, (row, candidate) in enumerate(zip(batch["candidates"], original["candidates"]), 1):
        if (set(row) != {"candidate_id", "discovery_returncode", "evidence_root", "formal_credit",
                "input_verification_returncode", "site_credit", "whole_graph_input"}
                or row["candidate_id"] != candidate["candidate_id"]
                or type(row["discovery_returncode"]) is not int or row["discovery_returncode"] != 1
                or row["input_verification_returncode"] is not None or row["whole_graph_input"] is not None
                or type(row["formal_credit"]) is not int or row["formal_credit"] != 0
                or type(row["site_credit"]) is not int or row["site_credit"] != 0):
            raise ValueError("original candidate closure was changed")
        root = regular(Path(row["evidence_root"]), directory=True)
        if root != batch_path.parent / "attempts" / f"candidate-{index:06d}":
            raise ValueError("failed attempt leaves the original batch namespace")
        failed, started = load(read(root / "failed.json")), load(read(root / "started.json"))
        expected_runtime = {"image_digest": original["browser_image"],
            "source_metadata": load(reopen(original["source_metadata"])[1]),
            "installed_metadata_sha256": sha(read(root / "image-source-metadata.json")),
            "execution_role": "actual-browser-image-graph-input-only-v1"}
        if (failed["plan"] != reference(original_path) or started["plan"] != reference(original_path)
                or failed["candidate"] != candidate or started["candidate"] != candidate
                or not zero_credit(failed) or not zero_credit(started)
                or failed["completed_passes"] != []
                or failed["outcome"] != "operational-discovery-failure-no-admission"
                or started["runtime"] != expected_runtime
                or load(read(root / "image-source-metadata.json")) != expected_runtime["source_metadata"]
                or (root / "whole-graph-input.json").exists()):
            raise ValueError("original failed attempt was changed or promoted")
        if index in RETRY_INDICES and (failed["error_type"] != "RecoverableAcquisitionError"
                or "net::ERR_BLOCKED_BY_CLIENT" not in failed["message"]):
            raise ValueError("retry is not the recorded navigation setup failure")
        prefix = batch_path.parent / "operations" / f"candidate-{index:06d}-discover"
        operation = {key: reference(Path(str(prefix) + suffix)) for key, suffix in [
            ("started", "-started.json"), ("completed", "-completed.json"),
            ("stdout", ".stdout.log"), ("stderr", ".stderr.log")]}
        begin, end = load(reopen(operation["started"])[1]), load(reopen(operation["completed"])[1])
        suffix = ["-I", "-B", original["producer_sources"]["operator.py"]["path"], "discover",
            "--plan", str(original_path), "--candidate-index", str(index), "--output", str(root)]
        command = begin.get("command")
        if (not isinstance(command, list) or any(not isinstance(arg, str) for arg in command)
                or command[-len(suffix):] != suffix or original["browser_image"] not in command
                or type(end["returncode"]) is not int or end["returncode"] != 1
                or end["stdout_sha256"] != operation["stdout"]["sha256"]
                or end["stderr_sha256"] != operation["stderr"]["sha256"]
                or type(end["elapsed_seconds"]) not in {int, float} or end["elapsed_seconds"] <= 0
                or not last_end <= _utc(begin["started_at"]) <= _utc(started["started_at"])
                    <= _utc(failed["completed_at"]) <= _utc(end["completed_at"])):
            raise ValueError("actual original failed operation binding differs")
        last_end = _utc(end["completed_at"])
        attempts.append({"original_index": index, "candidate": candidate,
            "attempt_files": _tree(root), "actual_operation": operation})
    if not last_end <= _utc(batch["closed_at"]) <= _utc(now()):
        raise ValueError("original batch closure chronology differs")
    return {"policy": RETRY_POLICY, "original_plan": reference(original_path),
        "original_producer_sources": original["producer_sources"], "failed_batch": reference(batch_path),
        "all_original_attempts": attempts, "retry_original_indices": RETRY_INDICES,
        "new_catalogue_reservations": False, "prior_outcomes_reclassified": False, **ZERO}


def evidence_ref(path: Path) -> dict[str, str]:
    """Raw history references use the recorder's existing path/SHA shape."""
    return {key: reference(path)[key] for key in ("path", "sha256")}


def open_evidence(ref: Any) -> tuple[Path, bytes]:
    if (not isinstance(ref, dict) or set(ref) != {"path", "sha256"}
            or not isinstance(ref["path"], str) or not Path(ref["path"]).is_absolute()
            or not isinstance(ref["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", ref["sha256"])):
        raise ValueError("history reference fields differ")
    path = regular(Path(ref["path"]))
    raw = read(path)
    if sha(raw) != ref["sha256"]:
        raise ValueError("history reference bytes changed")
    return path, raw


def _producer(value: dict[str, Any]):
    version = value.get("schema_version")
    if type(version) is not int or version not in {1, 2, 3}:
        raise ValueError("unknown historical producer version")
    refs = value.get("producer_sources", {})
    expected = (LEGACY_PRODUCERS[version] if version < 3 else
        {name: sha(read(Path(__file__).parent / name)) for name in ORIGINAL_PRODUCER_SHA256})
    if set(refs) != set(expected):
        raise ValueError("historical producer pair differs")
    for name, digest in expected.items():
        path, raw = reopen(refs[name])
        if path.name != name or sha(raw) != digest:
            raise ValueError("historical producer bytes changed")
    path = Path(refs["graph_input.py"]["path"])
    if Path(refs["operator.py"]["path"]).parent != path.parent:
        raise ValueError("historical producer pair is split")
    if version == 3:
        if path != Path(__file__).absolute():
            raise ValueError("v3 producer location differs")
        return sys.modules[__name__] if __name__ in sys.modules else None
    spec = importlib.util.spec_from_file_location(f"pinned_whole_graph_v{version}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _previous(path: Path, seen: frozenset[Path], memo: dict[Path, dict[str, Any]]) -> dict[str, Any]:
    path = regular(path)
    if path in seen:
        raise ValueError("catalogue declaration lineage contains a cycle")
    if path in memo:
        return memo[path]
    value = load(read(path))
    producer = _producer(value)
    result = (_check_plan(path, seen, memo) if value["schema_version"] == 3
              else producer.check_plan(path))
    memo[path] = result
    return result


def _ancestors(paths: list[Path], memo: dict[Path, dict[str, Any]]) -> dict[Path, dict[str, Any]]:
    result = {}
    def visit(path: Path, seen: frozenset[Path]) -> None:
        path = regular(path)
        if path in seen:
            raise ValueError("catalogue declaration ancestry contains a cycle")
        if path in result:
            return
        value = _previous(path, seen, memo)
        result[path] = value
        parents = [reopen(ref)[0] for ref in value["previous_plans"]]
        if value["schema_version"] == 2:
            parents.append(reopen(value["retry"]["original_plan"])[0])
        for parent in parents:
            visit(parent, seen | {path})
    for path in paths:
        visit(path, frozenset())
    return result


def _operation(batch: Path, index: int, action: str, plan_path: Path, plan: dict[str, Any],
               root: Path, expected_code: int) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    prefix = batch.parent / "operations" / f"candidate-{index:06d}-{action}"
    refs = {key: evidence_ref(Path(str(prefix) + suffix)) for key, suffix in [
        ("started", "-started.json"), ("completed", "-completed.json"),
        ("stdout", ".stdout.log"), ("stderr", ".stderr.log")]}
    begin, end = load(open_evidence(refs["started"])[1]), load(open_evidence(refs["completed"])[1])
    command = begin.get("command")
    suffix = (["-I", "-B", plan["producer_sources"]["operator.py"]["path"], "discover",
        "--plan", str(plan_path), "--candidate-index", str(index), "--output", str(root)]
        if action == "discover" else ["-I", "-B", plan["producer_sources"]["operator.py"]["path"],
        "verify-input", "--input", str(root / "whole-graph-input.json")])
    if (set(begin) != {"command", "cwd", "started_at"}
            or set(end) != {"completed_at", "elapsed_seconds", "returncode", "stderr_sha256", "stdout_sha256"}
            or not isinstance(command, list) or any(not isinstance(arg, str) for arg in command)
            or command[-len(suffix):] != suffix
            or (action == "discover" and (command[:6] != ["timeout", "--signal=TERM", "--kill-after=15s", "210s", "docker", "run"]
                or command.count(plan["browser_image"]) != 1))
            or type(end["returncode"]) is not int or end["returncode"] != expected_code
            or end["stdout_sha256"] != refs["stdout"]["sha256"]
            or end["stderr_sha256"] != refs["stderr"]["sha256"]
            or type(end["elapsed_seconds"]) not in {int, float} or not 0 < end["elapsed_seconds"] < float("inf")
            or (action == "discover" and end["elapsed_seconds"] > 230)
            or _utc(begin["started_at"]) > _utc(end["completed_at"])):
        raise ValueError("actual history operation command, status, raw bytes or chronology differs")
    return refs, begin, end


def _history_batch(path: Path, plans: dict[Path, dict[str, Any]]) -> dict[str, Any]:
    batch = load(read(path))
    plan_path, _ = open_evidence(batch["plan"])
    if plan_path not in plans:
        raise ValueError("history batch is outside declared ancestry")
    plan = plans[plan_path]
    common = {"candidates", "closed_at", "closed_whole_graph_inputs", "declared_candidates", "formal_credit",
        "ordinary_complete_get_and_typed_admission_still_required", "plan", "site_credit"}
    expected_keys = common if plan["schema_version"] == 1 else common | {
        "http3_get_performed", "prior_failures_reclassified", "scientific_credit"}
    if plan["schema_version"] == 2:
        expected_keys.add("retry_original_indices")
    if (set(batch) != expected_keys or type(batch["declared_candidates"]) is not int
            or batch["declared_candidates"] != len(plan["candidates"])
            or not isinstance(batch["candidates"], list) or len(batch["candidates"]) != len(plan["candidates"])
            or type(batch["formal_credit"]) is not int or batch["formal_credit"] != 0
            or type(batch["site_credit"]) is not int or batch["site_credit"] != 0
            or batch["ordinary_complete_get_and_typed_admission_still_required"] is not True
            or (plan["schema_version"] > 1 and (batch["scientific_credit"] is not False
                or batch["http3_get_performed"] is not False or batch["prior_failures_reclassified"] is not False))
            or (plan["schema_version"] == 2 and batch["retry_original_indices"] != [1, 2])):
        raise ValueError("historical batch changes declared attempts or input-only credit")
    attempts, successes = [], 0
    last = _utc(plan["declared_at"])
    for index, (row, candidate) in enumerate(zip(batch["candidates"], plan["candidates"]), 1):
        row_keys = {"candidate_id", "discovery_returncode", "evidence_root", "formal_credit",
            "input_verification_returncode", "site_credit", "whole_graph_input"}
        if plan["schema_version"] > 1:
            row_keys |= {"outcome", "producer_failure", "scientific_credit"}
        if plan["schema_version"] == 2:
            row_keys.add("original_index")
        if (set(row) != row_keys or row["candidate_id"] != candidate["candidate_id"]
                or type(row["discovery_returncode"]) is not int or row["discovery_returncode"] not in {0, 1}
                or type(row["formal_credit"]) is not int or row["formal_credit"] != 0
                or type(row["site_credit"]) is not int or row["site_credit"] != 0
                or (plan["schema_version"] > 1 and row["scientific_credit"] is not False)
                or (plan["schema_version"] == 2 and (type(row["original_index"]) is not int
                    or row["original_index"] != plan["retry"]["retry_original_indices"][index - 1]))):
            raise ValueError("historical candidate identity or status differs")
        root = regular(Path(row["evidence_root"]), directory=True)
        if root != path.parent / "attempts" / f"candidate-{index:06d}":
            raise ValueError("history attempt escapes its actual batch namespace")
        operation, begin, end = _operation(path, index, "discover", plan_path, plan, root, row["discovery_returncode"])
        started = load(read(root / "started.json"))
        metadata = read(root / "image-source-metadata.json")
        runtime = {"image_digest": plan["browser_image"], "source_metadata": load(metadata),
            "installed_metadata_sha256": sha(metadata), "execution_role": (
                "actual-browser-image-graph-input-only-v1" if plan["schema_version"] == 1 else
                f"actual-browser-image-navigation-seeded-graph-input-only-v{plan['schema_version']}")}
        if (started["plan"] != reference(plan_path) or started["candidate"] != candidate
                or started["runtime"] != runtime or not zero_credit(started)
                or load(metadata) != load(reopen(plan["source_metadata"])[1])
                or not last <= _utc(begin["started_at"]) <= _utc(started["started_at"]) <= _utc(end["completed_at"])):
            raise ValueError("actual history start, Source, runtime or serial order differs")
        last = _utc(end["completed_at"])
        verification = input_ref = None
        if row["discovery_returncode"] == 0:
            input_path, _ = open_evidence(row["whole_graph_input"])
            if (input_path != root / "whole-graph-input.json" or type(row["input_verification_returncode"]) is not int
                    or row["input_verification_returncode"] != 0 or (root / "failed.json").exists()):
                raise ValueError("successful graph lacks its real verification or conflicts with failure")
            producer = _producer(plan)
            (verify_input(input_path) if plan["schema_version"] == 3 else producer.verify_input(input_path))
            if not _utc(started["started_at"]) <= _utc(load(read(input_path))["completed_at"]) <= last:
                raise ValueError("successful input chronology differs")
            verification, vbegin, vend = _operation(path, index, "verify-input", plan_path, plan, root, 0)
            if last > _utc(vbegin["started_at"]):
                raise ValueError("input was verified before the actual discovery closed")
            last = _utc(vend["completed_at"])
            input_ref, successes = evidence_ref(input_path), successes + 1
        else:
            if row["whole_graph_input"] is not None or row["input_verification_returncode"] is not None or (root / "whole-graph-input.json").exists():
                raise ValueError("failed graph was relabeled or promoted")
            failed = load(read(root / "failed.json"))
            if (failed["plan"] != reference(plan_path) or failed["candidate"] != candidate
                    or failed["outcome"] != "operational-discovery-failure-no-admission" or not zero_credit(failed)
                    or not _utc(started["started_at"]) <= _utc(failed["completed_at"]) <= last):
                raise ValueError("failed graph identity, raw failure or chronology differs")
        if plan["schema_version"] > 1:
            closed = load(read(path.parent / f"candidate-{index:06d}-closed.json"))
            if (closed != row or row["outcome"] != ("verified-unqualified-graph-input" if input_ref else "operational-failure-no-site-classification")
                    or row["producer_failure"] != (None if input_ref else evidence_ref(root / "failed.json"))):
                raise ValueError("candidate closure differs from retained batch")
        attempts.append({"candidate": candidate, "root": str(root),
            "files": {name: evidence_ref(Path(ref["path"])) for name, ref in _tree(root).items()},
            "discovery_operation": operation, "verification_operation": verification, "input": input_ref,
            "discovery_returncode": row["discovery_returncode"],
            "input_verification_returncode": row["input_verification_returncode"]})
    if (type(batch["closed_whole_graph_inputs"]) is not int or batch["closed_whole_graph_inputs"] != successes
            or not last <= _utc(batch["closed_at"]) <= _utc(now())):
        raise ValueError("historical batch totals or closure chronology differs")
    return {"batch": evidence_ref(path), "plan": evidence_ref(plan_path), "closed_at": batch["closed_at"],
            "files": {name: evidence_ref(Path(ref["path"])) for name, ref in _tree(path.parent, 512).items()},
            "attempts": attempts, **ZERO}


def _history(paths: list[Path], previous: list[Path], memo: dict[Path, dict[str, Any]]) -> tuple[list[Any], list[Any]]:
    if len(paths) != len(set(map(regular, paths))) or len(previous) != len(set(map(regular, previous))):
        raise ValueError("declaration repeats a previous plan or history batch")
    plans = _ancestors(previous, memo)
    inherited = []
    for value in plans.values():
        if value["schema_version"] == 2:
            inherited.append(reopen(value["retry"]["failed_batch"])[0])
        elif value["schema_version"] == 3:
            inherited.extend(open_evidence(ref)[0] for ref in value["history_batches"])
    all_paths = list(dict.fromkeys([*inherited, *map(regular, paths)]))
    facts = [_history_batch(path, plans) for path in all_paths]
    facts.sort(key=lambda value: _utc(value["closed_at"]))
    if (not any(sha(read(path)) == ANCHOR_PLAN for path in plans)
            or not any(value["batch"]["sha256"] == ANCHOR_BATCH for value in facts)
            or {Path(value["plan"]["path"]) for value in facts} != set(plans)):
        raise ValueError("declaration dropped an earlier plan, failed batch or successful v2 graph")
    return [value["batch"] for value in facts], facts


def _value(*, source: dict[str, Any], catalogue: Path, parent: dict[str, Any],
           metadata: Path, previous: list[Path], batches: list[Path], count: int,
           declared_at: str, memo: dict[Path, dict[str, Any]]) -> dict[str, Any]:
    if (source["lab_commit"] != DISCOVERY_LAB or source["gitlinks"] != {"neqo-qcsd": DISCOVERY_NATIVE}):
        raise ValueError("v3 discovery changes the declared original browser Source")
    verify_snapshot(source)
    modules = _modules(Path(source["root"]))
    receipt, candidates = modules["class_catalogue"].load_candidate_catalogue_receipt(catalogue)
    old = [_previous(path, frozenset(), memo) for path in previous]
    if not old or any(value["original_prefix"] != parent or value["catalogue"] != reference(catalogue)
            or value["source"] != source or value["browser_image"] != DISCOVERY_IMAGE
            or value["source_metadata"] != reference(metadata) for value in old):
        raise ValueError("declaration ancestry changes original prefix, catalogue or browser provenance")
    validate_source_metadata(load(read(metadata)), source, modules["util"].SOURCE_METADATA_KEYS)
    refs, history = _history(batches, previous, memo)
    if any(_utc(item["closed_at"]) > _utc(declared_at) for item in history) or _utc(declared_at) > _utc(now()):
        raise ValueError("v3 declaration precedes its retained actual history")
    return {"schema_version": 3, "artifact_type": PLAN_TYPE, "contract": CONTRACT,
        "declared_at": declared_at, "selection_policy": SELECTION,
        "catalogue": reference(catalogue), "catalogue_payload_sha256": receipt["payload_sha256"],
        "original_prefix": parent, "previous_plans": [reference(path) for path in previous],
        "reserved_candidates": reserved_candidates(old), "source": source, "browser_image": DISCOVERY_IMAGE,
        "source_metadata": reference(metadata), "producer_sources": {
            name: reference(Path(__file__).parent / name) for name in ORIGINAL_PRODUCER_SHA256},
        "candidates": select_candidates([row.as_dict() for row in candidates], parent["domains"], old, count),
        "candidate_deadline_seconds": MAX_CANDIDATE_SECONDS, "backend_navigation_timeout_ms": 60000,
        "max_origin_passes": modules["class_acquisition"].MAX_ORIGIN_PASSES,
        "max_approved_origins": modules["class_acquisition"].MAX_APPROVED_ORIGINS,
        "passive_render_contract": modules["discovery_evidence"].passive_render_contract(),
        "discovery_only": True, "calls_prepare": False, "root_resurvey": False,
        "browser_image_execution_verified": False, "history_batches": refs, "history": history, **ZERO}


def declare(*, source: Path, lab_commit: str, catalogue: Path, parent_context: Path,
            browser_image: str, source_metadata: Path, count: int, previous_plans: list[Path],
            previous_batches: list[Path], output: Path) -> Path:
    if browser_image != DISCOVERY_IMAGE:
        raise ValueError("v3 browser image differs from the original closed image")
    snapshot = source_snapshot(source, lab_commit)
    parent = parent_binding(parent_context, _modules(source))
    value = _value(source=snapshot, catalogue=catalogue, parent=parent, metadata=source_metadata,
        previous=previous_plans, batches=previous_batches, count=count, declared_at=now(), memo={})
    protected = [source, catalogue, parent_context, source_metadata, Path(__file__).parent,
        *previous_plans, *(Path(ref["path"]).parent for ref in value["history_batches"])]
    root = fresh_directory(output, protected)
    create_json(root / "adapter-plan.json", adapter_plan(parent))
    create_json(root / "plan.json", value)
    check_plan(root / "plan.json")
    return root / "plan.json"


def _check_plan(path: Path, seen: frozenset[Path], memo: dict[Path, dict[str, Any]]) -> dict[str, Any]:
    path = regular(path)
    if path in seen:
        raise ValueError("catalogue declaration lineage contains a cycle")
    value = load(read(path))
    if (not isinstance(value, dict) or set(value) != PLAN_KEYS
            or type(value["schema_version"]) is not int or value["schema_version"] != 3
            or value["artifact_type"] != PLAN_TYPE or value["contract"] != CONTRACT
            or value["selection_policy"] != SELECTION or not zero_credit(value)):
        raise ValueError("v3 declaration changes its explicit prospective input-only role")
    _producer(value)
    previous = [reopen(ref)[0] for ref in value["previous_plans"]]
    for old in previous:
        _previous(old, seen | {path}, memo)
    parent = parent_binding(Path(value["original_prefix"]["context"]["path"]).parent,
                            _modules(Path(value["source"]["root"])))
    expected = _value(source=value["source"], catalogue=reopen(value["catalogue"])[0], parent=parent,
        metadata=reopen(value["source_metadata"])[0], previous=previous,
        batches=[open_evidence(ref)[0] for ref in value["history_batches"]], count=len(value["candidates"]),
        declared_at=value["declared_at"], memo=memo)
    if value != expected:
        raise ValueError("v3 declaration changed its order, full reservations, actual history or fixed bounds")
    return value


def check_plan(path: Path) -> dict[str, Any]:
    return _check_plan(path, frozenset(), {})


def transport_roots(plan: dict[str, Any]) -> list[Path]:
    """Specific RO roots for an already checked plan, including old producer pairs."""
    roots = {regular(Path(plan["source"]["root"]), directory=True), Path(__file__).absolute().parent}
    pending = [plan]
    seen = set()
    while pending:
        value = pending.pop()
        def walk(item: Any) -> None:
            if isinstance(item, dict):
                if {"path", "sha256"} <= set(item):
                    path = (reopen(item)[0] if set(item) == {"path", "sha256", "mode"}
                            else open_evidence(item)[0])
                    roots.add(path.parent)
                for child in item.values(): walk(child)
            elif isinstance(item, list):
                for child in item: walk(child)
        walk(value)
        parents = list(value["previous_plans"])
        if value["schema_version"] == 2:
            parents.append(value["retry"]["original_plan"])
        for ref in parents:
            path, raw = reopen(ref)
            if path not in seen:
                seen.add(path)
                pending.append(load(raw))
    roots |= {Path(ref["path"]).parent for ref in plan["history_batches"]}
    return sorted(root for root in roots if not any(root != other and root.is_relative_to(other) for other in roots))


class DiscoveryDeadlineExceeded(RuntimeError):
    pass


@contextmanager
def deadline(seconds: int):
    if not hasattr(signal, "setitimer") or signal.getitimer(signal.ITIMER_REAL)[0] > 0:
        raise ValueError("discovery requires an unused POSIX wall timer")
    old = signal.getsignal(signal.SIGALRM)
    def expire(_number, _frame):
        raise DiscoveryDeadlineExceeded("declared graph discovery deadline expired")
    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def actual_runtime(plan: dict[str, Any], modules: dict[str, Any]) -> dict[str, Any]:
    util = modules["util"]
    if (os.environ.get("QCSD_LAB_IMAGE_DIGEST") != plan["browser_image"]
            or os.environ.get("QCSD_LAB_SOURCE_METADATA") != str(util.DEFAULT_SOURCE_METADATA)):
        raise ValueError("discovery must run inside its declared browser image")
    expected = load(reopen(plan["source_metadata"])[1])
    validate_source_metadata(expected, plan["source"], util.SOURCE_METADATA_KEYS)
    actual = load(read(util.DEFAULT_SOURCE_METADATA))
    if actual != expected:
        raise ValueError("actual browser image Source differs from its exported metadata")
    return {"image_digest": plan["browser_image"], "source_metadata": actual,
            "installed_metadata_sha256": sha(read(util.DEFAULT_SOURCE_METADATA)),
            "execution_role": "actual-browser-image-navigation-seeded-graph-input-only-v3"}


def validate_discovery(value: dict[str, Any], modules: dict[str, Any]) -> dict[str, Any]:
    evidence = modules["discovery_evidence"]
    if (not isinstance(value, dict) or set(value) != {field.name for field in fields(modules["discover"].DiscoveryResult)}
            or value["passive_render_contract"] != evidence.passive_render_contract()
            or value["passive_render_contract_sha256"] != evidence.PASSIVE_RENDER_CONTRACT_SHA256
            or value["render_observation_sha256"] != evidence.evidence_sha256(value["render_observation"])
            or value["discovery_event_audit_sha256"] != evidence.evidence_sha256(value["discovery_event_audit"])):
        raise ValueError("whole graph evidence hashes or render policy differ")
    manifest = project_resources(value["resources"], value["approved_origins"])
    modules["manifest"].validate_manifest(manifest)
    evidence.verify_discovery_event_audit(value["discovery_event_audit"],
        render_observation=value["render_observation"], resources=value["resources"],
        exclusions=value["exclusions"], approved_origins=value["approved_origins"],
        observed_request_count=value["observed_request_count"],
        expected_observed_origins=value["observed_origins"])
    return manifest


def navigation_seeds(raw: dict[str, Any], candidate: dict[str, Any], modules: dict[str, Any]) -> list[str]:
    """Derive only authenticated homepage seeds, never the global page union."""
    navigation = modules["rapid_page_evidence"]._navigation(raw, candidate["domain"])
    acquisition = modules["class_acquisition"]
    pages = acquisition.select_page_candidates(candidate["domain"],
        registrable_domain=navigation.registrable_domain, discovered_links=navigation.links)
    by_page = acquisition._navigation_origins_by_page(navigation, pages)
    if candidate["source_url"] != "https://" + candidate["domain"] + "/" or candidate["source_url"] not in by_page:
        raise ValueError("navigation does not authenticate the declared catalogue homepage")
    return list(by_page[candidate["source_url"]])


def collect_navigation(backend: Any, root: Path, candidate: dict[str, Any], runtime: dict[str, Any],
                       modules: dict[str, Any], plan_path: Path) -> tuple[dict[str, Any], list[str]]:
    start_ns = time.monotonic_ns()
    started = create_json(root / "navigation-started.json", {"schema_version": 1,
        "stage": "catalogue-boundary-navigation-before-convergence", "plan": reference(plan_path),
        "candidate": candidate, "runtime": runtime, "started_at": now(), **ZERO})
    result = backend.discover_navigation(candidate["domain"])
    raw = modules["rapid_page_evidence"]._navigation_dict(result)
    result_ref = create_json(root / "navigation-result.json", raw)
    seeds = navigation_seeds(raw, candidate, modules)
    completed = create_json(root / "navigation-completed.json", {"schema_version": 1,
        "stage": "catalogue-boundary-navigation-before-convergence", "started": started,
        "result": result_ref, "candidate": candidate, "runtime": runtime,
        "navigation_seed_origins": seeds, "completed_at": now(),
        "elapsed_ns": time.monotonic_ns() - start_ns, **ZERO})
    return {"started": started, "result": result_ref, "completed": completed}, seeds


def verify_navigation(records: Any, root: Path, candidate: dict[str, Any], runtime: dict[str, Any],
                      modules: dict[str, Any], plan_ref: dict[str, str], not_before: datetime) -> tuple[list[str], datetime]:
    if not isinstance(records, dict) or set(records) != {"started", "result", "completed"}:
        raise ValueError("navigation references differ")
    values = {}
    for name, ref in records.items():
        path, raw = reopen(ref)
        if path != root / ("navigation-" + name + ".json"):
            raise ValueError("navigation evidence leaves its attempt namespace")
        values[name] = load(raw)
    started, completed = values["started"], values["completed"]
    if (set(started) != {"schema_version", "stage", "plan", "candidate", "runtime", "started_at", *ZERO}
            or set(completed) != {"schema_version", "stage", "started", "result", "candidate", "runtime",
                "navigation_seed_origins", "completed_at", "elapsed_ns", *ZERO}
            or type(started["schema_version"]) is not int or started["schema_version"] != 1
            or type(completed["schema_version"]) is not int or completed["schema_version"] != 1
            or started["stage"] != "catalogue-boundary-navigation-before-convergence"
            or completed["stage"] != started["stage"] or started["plan"] != plan_ref
            or started["candidate"] != candidate or completed["candidate"] != candidate
            or started["runtime"] != runtime or completed["runtime"] != runtime
            or completed["started"] != records["started"] or completed["result"] != records["result"]
            or not zero_credit(started) or not zero_credit(completed)
            or type(completed["elapsed_ns"]) is not int or completed["elapsed_ns"] <= 0
            or not not_before <= _utc(started["started_at"]) <= _utc(completed["completed_at"]) <= _utc(now())):
        raise ValueError("navigation identity, runtime, credit or chronology differs")
    seeds = navigation_seeds(values["result"], candidate, modules)
    if completed["navigation_seed_origins"] != seeds:
        raise ValueError("navigation seeds differ from their original homepage ledger")
    return seeds, _utc(completed["completed_at"])


def discover(plan_path: Path, index: int, output: Path) -> int:
    """Physical Root-only command. No preparation, GET, qualifier or admission."""
    plan = check_plan(plan_path)
    if type(index) is not int or not 1 <= index <= len(plan["candidates"]):
        raise ValueError("candidate index is outside the declared batch")
    modules = _modules(Path(plan["source"]["root"]))
    runtime = actual_runtime(plan, modules)
    candidate = plan["candidates"][index - 1]
    root = fresh_directory(output, [plan_path.parent, *transport_roots(plan)])
    started_ns = time.monotonic_ns()
    create_json(root / "started.json", {"schema_version": 1, "plan": reference(plan_path),
        "candidate": candidate, "runtime": runtime, "started_at": now(), **ZERO})
    create(root / "image-source-metadata.json", read(modules["util"].DEFAULT_SOURCE_METADATA))
    passes = []
    navigation_records = None
    stage = "navigation"
    class ObservedBackend:
        def discover(self, url, approved):
            ordinal = len(passes) + 1
            prefix = "pass-" + f"{ordinal:02d}"
            pass_started = time.monotonic_ns()
            begin = create_json(root / (prefix + "-started.json"), {
                "ordinal": ordinal, "source_url": url, "approved_origins": list(approved),
                "started_at": now(), "runtime": actual_runtime(plan, modules), **ZERO})
            result = backend.discover(url, approved)
            raw_value = asdict(result)
            result_ref = create_json(root / (prefix + "-result.json"), raw_value)
            validate_discovery(raw_value, modules)
            end = create_json(root / (prefix + "-completed.json"), {
                "ordinal": ordinal, "started": begin, "result": result_ref, "completed_at": now(),
                "elapsed_ns": time.monotonic_ns() - pass_started,
                "runtime": actual_runtime(plan, modules), "successful_graph_input_pass": True, **ZERO})
            passes.append({"started": begin, "result": result_ref, "completed": end})
            return result
    try:
        with deadline(plan["candidate_deadline_seconds"]):
            backend = modules["class_acquisition"].ExistingAcquisitionBackend(timeout_ms=plan["backend_navigation_timeout_ms"])
            navigation_records, seeds = collect_navigation(backend, root, candidate, runtime, modules, plan_path)
            stage = "complete-occurrence-convergence"
            approved, result = modules["class_acquisition"]._converge_origins(
                ObservedBackend(), candidate["source_url"], seed_origins=seeds)
            value = asdict(result)
            manifest = validate_discovery(value, modules)
            if value["source_url"] != candidate["source_url"] or approved != value["approved_origins"]:
                raise ValueError("final whole graph changes declared page or approved union")
            manifest_ref = create_json(root / "native-input.json", manifest)
            final_runtime = actual_runtime(plan, modules)
            verify_snapshot(plan["source"])
            if final_runtime != runtime:
                raise ValueError("discovery Source/runtime changed while collecting")
            envelope = {"schema_version": 3, "artifact_type": INPUT_TYPE, "contract": CONTRACT,
                "plan": reference(plan_path), "original_prefix": plan["original_prefix"],
                "candidate": candidate, "runtime": runtime, "passes": passes,
                "navigation": navigation_records, "navigation_seed_origins": seeds,
                "final_discovery": passes[-1]["result"], "native_manifest": manifest_ref,
                "resource_graph_sha256": sha(canonical(value["resources"])),
                "approved_origin_union": approved, "observed_origins": value["observed_origins"],
                "completed_at": now(), "elapsed_ns": time.monotonic_ns() - started_ns,
                "resource_count": len(manifest["resources"]), "all_occurrences_and_edges_retained": True,
                "discovery_safe_headers_retained": True, "http3_get_performed": False,
                "browser_qualification_claim": False, "challenge_absence_claim": False,
                "response_stability_claim": False, "admission_state": "unqualified-graph-input-only", **ZERO}
            create_json(root / "whole-graph-input.json", envelope)
    except Exception as error:
        create_json(root / "failed.json", {"schema_version": 1, "plan": reference(plan_path),
            "candidate": candidate, "completed_at": now(), "elapsed_ns": time.monotonic_ns() - started_ns,
            "error_type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc(),
            "completed_passes": passes, "completed_navigation": navigation_records,
            "failure_stage": stage, "outcome": "operational-discovery-failure-no-admission", **ZERO})
        return 1
    return 0


def verify_input(path: Path) -> dict[str, Any]:
    """HOST reopening of a closed graph input, without browser or GET actions."""
    value = load(read(path))
    keys = {"schema_version", "artifact_type", "contract", "plan", "original_prefix", "candidate", "runtime",
        "navigation", "navigation_seed_origins",
        "passes", "final_discovery", "native_manifest", "resource_graph_sha256", "approved_origin_union",
        "observed_origins", "completed_at", "elapsed_ns", "resource_count", "all_occurrences_and_edges_retained",
        "discovery_safe_headers_retained", "http3_get_performed", "browser_qualification_claim",
        "challenge_absence_claim", "response_stability_claim", "admission_state", *ZERO}
    if (not isinstance(value, dict) or set(value) != keys or type(value["schema_version"]) is not int
            or value["schema_version"] != 3 or value["artifact_type"] != INPUT_TYPE or value["contract"] != CONTRACT
            or not zero_credit(value) or value["all_occurrences_and_edges_retained"] is not True
            or value["discovery_safe_headers_retained"] is not True or value["http3_get_performed"] is not False
            or value["browser_qualification_claim"] is not False or value["challenge_absence_claim"] is not False
            or value["response_stability_claim"] is not False or value["admission_state"] != "unqualified-graph-input-only"
            or type(value["elapsed_ns"]) is not int or value["elapsed_ns"] <= 0):
        raise ValueError("whole graph input changes its input-only role")
    plan = check_plan(reopen(value["plan"])[0])
    modules = _modules(Path(plan["source"]["root"]))
    if value["original_prefix"] != plan["original_prefix"] or value["candidate"] not in plan["candidates"]:
        raise ValueError("whole graph input changes its original prefix or selected identity")
    actual_metadata = read(path.with_name("image-source-metadata.json"))
    if load(actual_metadata) != load(reopen(plan["source_metadata"])[1]):
        raise ValueError("retained actual image Source differs from its declared export")
    runtime = {"image_digest": plan["browser_image"], "source_metadata": load(actual_metadata),
        "installed_metadata_sha256": sha(actual_metadata),
        "execution_role": "actual-browser-image-navigation-seeded-graph-input-only-v3"}
    if value["runtime"] != runtime or not value["passes"] or len(value["passes"]) > plan["max_origin_passes"]:
        raise ValueError("whole graph input lacks its exact runtime or finite pass prefix")
    started = load(read(path.with_name("started.json")))
    if (started["plan"] != value["plan"] or started["candidate"] != value["candidate"]
            or started["runtime"] != runtime or not zero_credit(started)
            or _utc(started["started_at"]) < _utc(plan["declared_at"])):
        raise ValueError("attempt start changes declared identity, runtime or chronology")
    seeds, last_time = verify_navigation(value["navigation"], path.absolute().parent,
        value["candidate"], runtime, modules, value["plan"], _utc(started["started_at"]))
    if value["navigation_seed_origins"] != seeds:
        raise ValueError("whole graph envelope changes authenticated navigation seeds")
    approved = {modules["discover"].origin(value["candidate"]["source_url"]), *seeds}
    final = None
    results = []
    for ordinal, item in enumerate(value["passes"], 1):
        if set(item) != {"started", "result", "completed"}:
            raise ValueError("whole graph pass reference fields differ")
        started_path, raw = reopen(item["started"])
        started = load(raw)
        completed_path, raw = reopen(item["completed"])
        completed = load(raw)
        result_path, raw = reopen(item["result"])
        result = load(raw)
        if (started_path.parent != path.absolute().parent or result_path.parent != started_path.parent
                or completed_path.parent != started_path.parent
                or started["ordinal"] != ordinal or completed["ordinal"] != ordinal
                or started["source_url"] != value["candidate"]["source_url"]
                or result["source_url"] != started["source_url"]
                or started["approved_origins"] != sorted(approved) or result["approved_origins"] != sorted(approved)
                or completed["started"] != item["started"] or completed["result"] != item["result"]
                or completed["runtime"] != runtime or started["runtime"] != runtime
                or not zero_credit(started) or not zero_credit(completed)
                or completed["successful_graph_input_pass"] is not True
                or type(completed["elapsed_ns"]) is not int or completed["elapsed_ns"] <= 0):
            raise ValueError("whole graph pass changes inputs, runtime, closure or credit")
        start_time = datetime.fromisoformat(started["started_at"].replace("Z", "+00:00"))
        end_time = datetime.fromisoformat(completed["completed_at"].replace("Z", "+00:00"))
        if not last_time <= start_time <= end_time:
            raise ValueError("whole graph pass chronology changed")
        last_time = end_time
        validate_discovery(result, modules)
        expandable = result["expandable_origins"]
        if (not isinstance(expandable, list) or expandable != sorted(set(expandable))
                or any(modules["discover"].origin(origin) != origin for origin in expandable)
                or not set(expandable) <= {modules["discover"].origin(origin) for origin in result["observed_origins"]}):
            raise ValueError("whole graph pass omits its observed expandable-origin proof")
        expanded = approved | set(expandable)
        if len(expanded) > plan["max_approved_origins"]:
            raise ValueError("whole graph origin union exceeds the declared backend contract")
        if expanded == approved and ordinal != len(value["passes"]):
            raise ValueError("whole graph retained extra passes after convergence")
        if ordinal == len(value["passes"]) and expanded != approved:
            raise ValueError("whole graph final pass has not converged")
        approved = expanded
        final = result
        results.append(result)
    class RecordedBackend:
        def __init__(self):
            self.index = 0
        def discover(self, url, expected_approved):
            if self.index >= len(results):
                raise ValueError("retained discovery ended before convergence")
            row = results[self.index]
            self.index += 1
            if row["source_url"] != url or row["approved_origins"] != list(expected_approved):
                raise ValueError("retained discovery differs from original backend arguments")
            return modules["discover"].DiscoveryResult(**row)
    replay = RecordedBackend()
    replay_approved, replay_final = modules["class_acquisition"]._converge_origins(
        replay, value["candidate"]["source_url"], seed_origins=seeds)
    if replay.index != len(results) or replay_approved != sorted(approved) or asdict(replay_final) != final:
        raise ValueError("retained discovery changes the exact Source convergence result")
    manifest_path, raw = reopen(value["native_manifest"])
    if (manifest_path != path.with_name("native-input.json").absolute()
            or value["final_discovery"] != value["passes"][-1]["result"]
            or value["approved_origin_union"] != sorted(approved) or value["observed_origins"] != final["observed_origins"]
            or load(raw) != validate_discovery(final, modules)
            or value["resource_graph_sha256"] != sha(canonical(final["resources"]))
            or type(value["resource_count"]) is not int or value["resource_count"] != len(final["resources"])
            or last_time > datetime.fromisoformat(value["completed_at"].replace("Z", "+00:00"))):
        raise ValueError("whole graph final binding pruned or rewrote its graph")
    return {"resource_count": value["resource_count"], "pass_count": len(value["passes"]),
            "approved_origin_count": len(approved), "input_ref": reference(path), **ZERO}
