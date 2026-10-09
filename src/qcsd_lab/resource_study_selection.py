"""Prospective exact twenty-URL selections from authenticated class pools.

This module neither performs network operations nor establishes eligibility.
Absent selection metadata retains the historical/default preparation contract.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from urllib.parse import urlsplit

from . import resource_study_inputs as inputs
from .resource_study_supplements import load_inventory_candidates

TYPE = "qcsd-resource-domain-explicit-selection-v1"
BINDING = "qcsd-resource-domain-explicit-selection-binding-v1"
LIMIT = 16 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z")
FIELDS = {"record_type", "schema_version", "hostname", "source_sha256",
          "supplements", "pool_sha256", "urls", "scientific_credit"}
BINDING_FIELDS = {"record_type", "manifest_path", "manifest_sha256", "job_path",
                  "job_sha256", "context_files"}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _digest(value):
    if type(value) is not str or not SHA.fullmatch(value):
        raise ValueError("selection SHA256 differs")
    return value


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError("selection JSON repeats a field")
        result[key] = value
    return result


def _json(raw):
    def nonfinite(value):
        raise ValueError("selection JSON contains a nonfinite value: " + value)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=nonfinite)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("selection evidence must be UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ValueError("selection evidence must be an object")
    return value


def _path(path):
    path = Path(path).absolute()
    if ".." in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("selection path contains a link or traversal")
    return path


def _relative(root, relative):
    if type(relative) is not str:
        raise ValueError("selection artifact path must be a string")
    name = PurePosixPath(relative)
    if name.is_absolute() or not name.parts or ".." in name.parts or str(name) != relative:
        raise ValueError("selection artifact path must be canonical and relative")
    return _path(_path(root) / relative)


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_mode, info.st_nlink)


def _read(path, digest=None):
    path = _path(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o444):
            raise ValueError("selection evidence must be owned immutable unlinked files")
        raw = stream.read(LIMIT + 1)
        after = os.fstat(stream.fileno())
    if len(raw) > LIMIT or _stamp(before) != _stamp(after) or _stamp(after) != _stamp(path.lstat()):
        raise ValueError("selection evidence changed or exceeds its byte limit")
    if digest is not None and _sha(raw) != _digest(digest):
        raise ValueError("selection evidence SHA256 changed")
    return raw


def _supplement(root, ref, files):
    """Replay the existing inventory parser, preserving original file metadata."""
    if not isinstance(ref, dict) or set(ref) != {"path", "sha256", "catalogue_sha256"}:
        raise ValueError("selection supplement reference differs")
    admission_raw = _read(_relative(root, ref["path"]), _digest(ref["sha256"]))
    admission = _json(admission_raw)
    digest = _digest(ref["catalogue_sha256"])
    if (set(admission) != {"catalogue_sha256", "scientific_credit", "reason"}
            or admission["catalogue_sha256"] != digest or admission["scientific_credit"] is not False
            or admission["reason"] != "explicit operator reserve inventory import"):
        raise ValueError("selection supplement admission differs")
    files[ref["path"]] = ref["sha256"]
    relative = f"inputs/supplements/{digest}/catalogue.json"
    raw = _read(_relative(root, relative), digest)
    catalogue = _json(raw)
    if _sha(inputs.canonical_json(catalogue)) != digest:
        raise ValueError("selection supplement catalogue is not canonical")
    files[relative] = digest
    refs = catalogue.get("inventory_files")
    if not isinstance(refs, list) or not refs:
        raise ValueError("selection supplement lacks inventories")
    paths = []
    for index, original in enumerate(refs, 1):
        if (not isinstance(original, dict)
                or set(original) != {"path", "sha256", "mode", "size", "record_count"}
                or type(original["path"]) is not str or not Path(original["path"]).is_absolute()
                or ".." in Path(original["path"]).parts or type(original["mode"]) is not str
                or not re.fullmatch(r"0[0-7]{3}", original["mode"])
                or type(original["size"]) is not int or original["size"] < 0
                or type(original["record_count"]) is not int or original["record_count"] < 0):
            raise ValueError("selection inventory provenance differs")
        relative = f"inputs/supplements/{digest}/inventory-{index:03d}.json"
        path = _relative(root, relative)
        raw = _read(path, _digest(original["sha256"]))
        if len(raw) != original["size"]:
            raise ValueError("selection inventory size differs")
        paths.append(path)
        files[relative] = original["sha256"]
    actual = load_inventory_candidates(paths)
    for observed, original in zip(actual["inventory_files"], refs):
        if any(observed[k] != original[k] for k in ("sha256", "size", "record_count")):
            raise ValueError("selection inventory content provenance differs")
    path_map = {str(p): original["path"] for p, original in zip(paths, refs)}
    actual["inventory_files"] = refs
    for row in actual["candidates"]:
        row["sources"] = [path_map[path] for path in row["sources"]]
        for occurrence in row["source_occurrences"]:
            occurrence["inventory"] = refs[occurrence["inventory_index"] - 1]
    for occurrence in actual["excluded_records"]:
        occurrence["inventory"] = refs[occurrence["inventory_index"] - 1]
    if actual != catalogue:
        raise ValueError("selection supplement catalogue differs from its source inventories")
    return catalogue


def _pool(root, hostname, supplements=None):
    root = _path(root)
    if inputs._hostname(hostname) != hostname:
        raise ValueError("selection hostname must be canonical")
    files = {}
    raw = _read(root / "study.json")
    plan = _json(raw)
    files["study.json"] = _sha(raw)
    source_sha = _digest(plan.get("source_sha256"))
    raw = _read(root / "inputs/supplied-resources.json", source_sha)
    files["inputs/supplied-resources.json"] = source_sha
    catalogue = inputs.candidate_catalogue(root / "inputs/supplied-resources.json")
    if catalogue["source_sha256"] != source_sha:
        raise ValueError("selection original source changed")
    raw = _read(root / "inputs/candidates.json")
    if _json(raw) != catalogue:
        raise ValueError("selection original candidate catalogue differs")
    files["inputs/candidates.json"] = _sha(raw)
    candidate = next((r for r in catalogue["candidates"] if r["hostname"] == hostname), None)
    urls = list(candidate["urls"]) if candidate is not None else []
    if supplements is None:
        supplements = []
        for index, path in enumerate(sorted((root / "inputs/supplement-admissions").glob("*.json")), 1):
            if path.name != f"{index:06d}.json":
                raise ValueError("selection supplement sequence differs")
            raw = _read(path)
            supplements.append({"path": path.relative_to(root).as_posix(), "sha256": _sha(raw),
                                "catalogue_sha256": _json(raw)["catalogue_sha256"]})
    if not isinstance(supplements, list):
        raise ValueError("selection supplements must be an ordered list")
    for index, ref in enumerate(supplements, 1):
        if not isinstance(ref, dict) or ref.get("path") != f"inputs/supplement-admissions/{index:06d}.json":
            raise ValueError("selection supplement context must be a frozen ordered prefix")
        imported = _supplement(root, ref, files)
        row = next((r for r in imported["candidates"] if r["hostname"] == hostname), None)
        if row:
            urls.extend(url for url in row["urls"] if url not in urls)
    context = {"hostname": hostname, "source_sha256": source_sha,
               "supplements": deepcopy(supplements), "urls": urls}
    return {**context, "pool_sha256": _sha(inputs.canonical_json({**context, "files": files})),
            "files": files}


def _validate(root, manifest, hostname):
    if (not isinstance(manifest, dict) or set(manifest) != FIELDS
            or manifest["record_type"] != TYPE or type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1 or manifest["hostname"] != hostname
            or manifest["scientific_credit"] is not False):
        raise ValueError("explicit selection manifest contract differs")
    pool = _pool(root, hostname, manifest["supplements"])
    if (manifest["source_sha256"] != pool["source_sha256"]
            or _digest(manifest["pool_sha256"]) != pool["pool_sha256"]):
        raise ValueError("explicit selection frozen pool differs")
    urls = manifest["urls"]
    if (not isinstance(urls, list) or len(urls) != inputs.RESOURCES_PER_SESSION
            or any(type(url) is not str or inputs.normalize_url(url) != url
                   or urlsplit(url).hostname != hostname for url in urls)
            or len(set(urls)) != inputs.RESOURCES_PER_SESSION
            or any(url not in pool["urls"] for url in urls)):
        raise ValueError("selection needs twenty distinct exact-host pool URLs")
    if urls != sorted(urls, key=pool["urls"].index):
        raise ValueError("explicit selection must preserve frozen pool order")
    return pool


def make_manifest(root, hostname, urls):
    """Describe a prospective selection; this read-only API grants no credit."""
    pool = _pool(root, hostname)
    value = {"record_type": TYPE, "schema_version": 1, "hostname": hostname,
             "source_sha256": pool["source_sha256"], "supplements": pool["supplements"],
             "pool_sha256": pool["pool_sha256"], "urls": list(urls), "scientific_credit": False}
    _validate(root, value, hostname)
    return value


def load_selection(root, path, expected_sha256, hostname):
    """Read stable immutable bytes and authenticate their recorded pool context."""
    raw = _read(path, _digest(expected_sha256))
    value = _json(raw)
    _validate(root, value, hostname)
    return {"manifest": value, "raw": raw, "sha256": _sha(raw)}


def freeze_selection(root, selected):
    """Publish the exact reviewed bytes once under their digest, without rewrite."""
    raw = selected["raw"]
    if (not isinstance(raw, bytes) or _sha(raw) != _digest(selected["sha256"])
            or _json(raw) != selected["manifest"]):
        raise ValueError("selection changed before freezing")
    _validate(root, selected["manifest"], selected["manifest"]["hostname"])
    relative = f"inputs/resource-selections/{selected['sha256']}.json"
    path = _relative(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + "." + os.urandom(8).hex())
    try:
        with temporary.open("xb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        temporary.chmod(0o444)
        os.link(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)
    _read(path, selected["sha256"])
    return {"manifest_path": relative, "manifest_sha256": selected["sha256"]}


def _binding(enrollment):
    value = enrollment.get("resource_selection")
    if (not isinstance(value, dict) or set(value) != BINDING_FIELDS or value["record_type"] != BINDING
            or not isinstance(value["context_files"], dict) or not value["context_files"]):
        raise ValueError("selection enrollment binding is incomplete")
    for key in ("manifest_sha256", "job_sha256"): _digest(value[key])
    return value


def selection_artifact_paths(enrollment):
    """Expose optional selection files for the ordinary receipt inventory."""
    if "resource_selection" not in enrollment:
        return {}
    value = _binding(enrollment)
    return {"resource_selection_manifest": value["manifest_path"],
            "resource_selection_job": value["job_path"],
            **{f"resource_selection_context_{index:03d}": path
               for index, path in enumerate(sorted(value["context_files"]))}}


def bind_preparation(root, enrollment, binding, job_path):
    """Attach the selected input authority to an actual completed preparation."""
    if ("resource_selection" in enrollment or not isinstance(binding, dict)
            or set(binding) != {"manifest_path", "manifest_sha256"}):
        raise ValueError("selection preparation binding already exists or differs")
    value = _json(_read(_relative(root, binding["manifest_path"]), binding["manifest_sha256"]))
    pool = _validate(root, value, enrollment["hostname"])
    path = _path(job_path)
    relative = path.relative_to(_path(root)).as_posix()
    digest = _sha(_read(path))
    result = deepcopy(enrollment)
    result["resource_selection"] = {"record_type": BINDING, **binding,
                                    "job_path": relative, "job_sha256": digest,
                                    "context_files": pool["files"]}
    additions = {**pool["files"], binding["manifest_path"]: binding["manifest_sha256"], relative: digest}
    for name, expected in additions.items():
        previous = result["files"].get(name, expected)
        if previous != expected: raise ValueError("selection preparation inventory conflicts")
        result["files"][name] = expected
    validate_selection_proof(root, result)
    return result


def validate_selection_proof(root, enrollment, receipt=None):
    """Join frozen pool/selection/job/actual input/workload; no raw-run replay."""
    if "resource_selection" not in enrollment:
        paths = (receipt or {}).get("artifact_paths", {})
        if (any(name.startswith("resource_selection_") for name in enrollment)
                or any(name.startswith("resource_selection_") for name in paths)
                or any(name.startswith("inputs/resource-selections/") for name in enrollment.get("files", {}))):
            raise ValueError("partial selection proof without enrollment authority")
        return None
    binding = _binding(enrollment)
    manifest_path = binding["manifest_path"]
    if manifest_path != f"inputs/resource-selections/{binding['manifest_sha256']}.json":
        raise ValueError("selection manifest is outside its digest path")
    manifest = _json(_read(_relative(root, manifest_path), binding["manifest_sha256"]))
    pool = _validate(root, manifest, enrollment["hostname"])
    if binding["context_files"] != pool["files"]:
        raise ValueError("selection enrollment context differs")
    files = enrollment.get("files")
    if not isinstance(files, dict):
        raise ValueError("selection enrollment file inventory differs")
    proof = {**pool["files"], manifest_path: binding["manifest_sha256"],
             binding["job_path"]: binding["job_sha256"]}
    for relative, digest in proof.items():
        if files.get(relative) != digest:
            raise ValueError("selection proof is absent from enrollment inventory")
        _read(_relative(root, relative), digest)
    job_path = _relative(root, binding["job_path"])
    job = _json(_read(job_path, binding["job_sha256"]))
    base = _relative(root, enrollment["preparation_dir"])
    if (job_path.name != "job.json" or job_path.parent / "prepared" != base
            or set(job) != {"hostname", "urls", "output", "runtime"}
            or job["hostname"] != manifest["hostname"] or job["urls"] != manifest["urls"]
            or job["output"] != str(base) or job["runtime"] != enrollment["runtime"]
            or enrollment["urls"] != manifest["urls"]):
        raise ValueError("selection differs from the actual preparation job")
    def enrolled_json(relative):
        return _json(_read(_relative(root, relative), _digest(files.get(relative))))
    relative = (base / "preparation-get/input.json").relative_to(_path(root)).as_posix()
    actual = enrolled_json(relative)
    workload = enrolled_json(enrollment["workload_path"])
    prepared = enrolled_json(enrollment["paths"]["prepared_workload"])
    for value in (actual, workload, prepared):
        rows = value.get("resources")
        if (not isinstance(rows, list) or len(rows) != 20
                or any(not isinstance(row, dict) or type(row.get("id")) is not int for row in rows)
                or [row["id"] for row in rows] != list(range(20))
                or [row.get("url") for row in rows] != manifest["urls"]):
            raise ValueError("selection differs from actual Native input/workload")
    preparation = prepared.get("preparation")
    if (not isinstance(preparation, dict) or prepared["resources"] != workload["resources"]
            or preparation.get("runtime") != enrollment["runtime"]
            or files[enrollment["workload_path"]] != enrollment["workload_sha256"]):
        raise ValueError("selected workload/runtime provenance differs")
    if receipt is not None:
        required = selection_artifact_paths(enrollment)
        paths, inventory = receipt.get("artifact_paths", {}), receipt.get("files", {})
        if (not isinstance(paths, dict) or not isinstance(inventory, dict)
                or {k: v for k, v in paths.items() if k.startswith("resource_selection_")} != required
                or any(inventory.get(relative) != proof[relative] for relative in required.values())):
            raise ValueError("receipt selection proof inventory differs")
    return {"manifest_sha256": binding["manifest_sha256"], "pool_sha256": manifest["pool_sha256"],
            "selected_urls": list(manifest["urls"]), "scientific_credit": False}
