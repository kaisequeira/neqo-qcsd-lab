"""Read-only transport derived from authenticated fixed-resource preparations.

The retained GET producer is deliberately untouched. Transport reopens its
original Source, graph, raw execution and prospective context before deriving
paths; it never accepts caller-provided mounts or rewrites preparation records.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


def _path(path: Path, *, directory: bool = False) -> Path:
    if (not path.is_absolute() or ".." in path.parts
        or any(p.is_symlink() for p in (path, *path.parents))
        or (not path.is_dir() if directory else not path.is_file())
        or any(c in str(path) for c in ("\n", "\r", "\0", ":"))
        or path.resolve(strict=True) != path):
        raise ValueError("static evidence transport requires canonical regular absolute paths")
    return path


def _json(path: Path) -> Any:
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("static transport JSON repeats a key")
            value[key] = item
        return value
    return json.loads(_path(path).read_bytes(), object_pairs_hook=pairs)


def manifest_roots(manifest: Mapping[str, Any]) -> list[Path]:
    """Return no new mounts for browser data; authenticate every static root."""
    from . import supplied_static_admission as admission
    from . import supplied_static_preparation as preparation
    from . import supplied_static_capture_amendment as amendment

    declared = manifest.get("preparation")
    if not isinstance(declared, Mapping) or "data_role" not in declared:
        return []
    if amendment.is_amended(declared):
        proof = amendment.validate_preparation(declared, manifest["resources"])
        roots = set(amendment.preparation_roots(declared))
    elif preparation.is_static(declared):
        proof = preparation.validate_static_preparation(declared, manifest["resources"])
        roots = set(preparation.preparation_roots(declared))
    else:
        raise ValueError("static transport encountered an unknown preparation role")
    context_path = preparation.open_reference(proof["context"])
    context = admission.load_context(_path(context_path.parent, directory=True))
    if context_path != context.root / "provenance.json":
        raise ValueError("static GET context is outside its official namespace")
    roots.add(context.root)
    # Successors preserve original immutable context declarations. Bind every
    # ancestor using the existing public context validator, without admitting
    # unrelated later candidates or deriving arbitrary terminal-prefix mounts.
    while context.provenance["parent_context"] is not None:
        path = preparation.open_reference(context.provenance["parent_context"])
        context = admission.load_context(_path(path.parent, directory=True))
        if path != context.root / "provenance.json":
            raise ValueError("static parent context changed its official namespace")
        roots.add(context.root)
    roots = {_path(Path(root), directory=True) for root in roots}
    return sorted(root for root in roots
                  if not any(root != parent and root.is_relative_to(parent) for parent in roots))


def campaign_roots(root: Path, action: str, target: Path) -> list[Path]:
    """Read the bound run/resume workload paths before installed preflight.

    This derives transport only. The installed ordinary campaign/result,
    Source, qualification, DNS and capture validators retain authority.
    """
    from .capture_session import slug
    from .orchestrator import _campaign_config_root, _trusted_regular_input
    root = _path(root, directory=True)
    paths = []
    if action == "run":
        import yaml
        target = _path(target)
        if not target.is_relative_to(root):
            raise ValueError("run transport campaign must be inside the Lab root")
        config = _campaign_config_root(target, frozen_inputs=None)
        campaign = yaml.safe_load(target.read_bytes())
        workloads = campaign.get("workloads") if isinstance(campaign, dict) else None
        if not isinstance(workloads, dict) or not workloads:
            raise ValueError("static run transport lacks its declared workload mapping")
        for name in workloads:
            if not isinstance(name, str) or slug(name) != name:
                raise ValueError("static run workload identity is unsafe")
            paths.append(_trusted_regular_input(config / "workloads" / (name + ".json"),
                                               root=config, label="workload manifest"))
    elif action == "resume":
        target = _path(target, directory=True)
        if not target.is_relative_to(root / "results"):
            raise ValueError("static resume transport requires the official result directory")
        experiment = _json(target / "experiment.json")
        for row in experiment["configuration"]["workloads"]:
            relative = row["manifest"]
            if (not isinstance(relative, str) or Path(relative).is_absolute()
                or ".." in Path(relative).parts or Path(relative).as_posix() != relative):
                raise ValueError("static resumed manifest path is unsafe")
            paths.append(target / relative)
    else:
        raise ValueError("static evidence transport supports only run or resume")
    roots = set()
    for path in paths:
        roots.update(manifest_roots(_json(path)))
    return sorted(roots)
