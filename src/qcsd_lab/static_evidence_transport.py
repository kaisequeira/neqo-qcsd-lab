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
    from . import rapid_selected_capture_input as selected
    if selected.is_selected(declared):
        roots = {_path(Path(root), directory=True) for root in selected.preparation_roots(declared, manifest["resources"])}
        return sorted(root for root in roots if not any(root != parent and root.is_relative_to(parent) for parent in roots))
    from . import selected_capture_amendment as selected_amendment
    if selected_amendment.is_amended(declared):
        selected_amendment.validate_preparation(declared, manifest["resources"])
        roots = {_path(Path(root), directory=True) for root in selected_amendment.preparation_roots(declared)}
        return sorted(root for root in roots if not any(root != parent and root.is_relative_to(parent) for parent in roots))
    from . import supplied_static_budget_successor as budget
    from . import static_budget_capture as budget_capture
    from . import static_budget_capture_amendment as budget_amendment
    if budget.is_budget(declared) or budget_amendment.is_amended(declared):
        validator = budget.validate_preparation if budget.is_budget(declared) else budget_amendment.validate_preparation
        validator(declared, manifest["resources"])
        selected = budget_capture.preparation_roots if budget.is_budget(declared) else budget_amendment.preparation_roots
        roots = {_path(Path(root), directory=True) for root in selected(declared)}
        return sorted(root for root in roots if not any(root != parent and root.is_relative_to(parent) for parent in roots))
    from . import whole_graph_supplement as whole
    from . import whole_graph_capture_amendment as whole_amendment
    if whole_amendment.is_amended(declared):
        whole_amendment.validate_preparation(declared, manifest["resources"])
        roots = {_path(Path(root), directory=True) for root in whole_amendment.preparation_roots(declared)}
        return sorted(root for root in roots if not any(root != parent and root.is_relative_to(parent) for parent in roots))
    if whole.is_whole(declared):
        whole.validate_preparation(declared, manifest["resources"])
        roots = {_path(Path(root), directory=True) for root in whole.preparation_roots(declared)}
        return sorted(root for root in roots if not any(root != parent and root.is_relative_to(parent) for parent in roots))
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
    # The selected preparation reopens the sealed inherited decision prefix,
    # including complete GETs and operational deferrals outside the context.
    # Derive only those authenticated roots, never later active attempts.
    while True:
        for reference in context.provenance["inherited_terminals"]:
            terminal = preparation.open_reference(reference)
            admission.verify_terminal(terminal, context)
            record = admission.receipts._unpack(_path(terminal).read_bytes(), admission.TERMINAL_TYPE)
            roots.add(_path(terminal.parent, directory=True))
            if record["get_evidence_root"] is not None:
                roots.add(_path(Path(record["get_evidence_root"]), directory=True))
            if record["namespace"] is not None:
                roots.update(_path(preparation.open_reference(record["namespace"][key]).parent, directory=True)
                             for key in ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"))
        if context.provenance["parent_context"] is None:
            break
        path = preparation.open_reference(context.provenance["parent_context"])
        context = admission.load_context(_path(path.parent, directory=True))
        if path != context.root / "provenance.json":
            raise ValueError("static parent context changed its official namespace")
        roots.add(context.root)
    roots = {_path(Path(root), directory=True) for root in roots}
    return sorted(root for root in roots
                  if not any(root != parent and root.is_relative_to(parent) for parent in roots))


def amended_canary_roots(plan: Mapping[str, Any], directory: Path) -> list[Path]:
    """Authenticate the derived workload before transporting amendment inputs.

    The lineage file remains the immutable original GET preparation. Only an
    explicit closed amendment may add its Source/client/declaration roots.
    """
    from . import supplied_static_capture_amendment as amendment
    from . import supplied_static_preparation as preparation
    from . import supplied_static_graph as graph

    original_path = _path(directory / "lineage/original-manifest.json")
    original = _json(original_path)
    if graph.digest(original_path.read_bytes()) != plan.get("original_workload_sha256"):
        raise ValueError("amended canary changed its original lineage manifest")
    execution = _path(Path(plan["execution_root"]), directory=True)
    relative = Path(plan["workload_relative"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("amended canary workload is outside its execution root")
    target = _path(execution / relative)
    manifest = _json(target)
    if (graph.digest(target.read_bytes()) != plan.get("workload_sha256")
        or manifest.get("resources") != original.get("resources")
        or not amendment.is_amended(manifest.get("preparation"))
        or manifest["preparation"]["data_role"] != plan.get("data_role")):
        raise ValueError("amended canary changed its declared complete derived graph")
    receipt_path = preparation.open_reference(plan.get("static_capture_amendment"))
    closed = amendment._closed(receipt_path)
    matching = [row for row in closed["workloads"]
                if preparation.open_reference(row["capture_manifest"]) == target]
    if (len(matching) != 1 or matching[0]["capture_manifest"]["sha256"] != plan["workload_sha256"]
        or preparation.open_reference(matching[0]["original_manifest"]).read_bytes() != original_path.read_bytes()
        or closed["declaration"] != manifest["preparation"][amendment.FIELD]
        or Path(closed["runtime"]["execution_root"]) != execution
        or closed["runtime"]["runtime_source_root"] != plan.get("clean_runtime_root")):
        raise ValueError("amended canary changed its closed declaration or runtime")
    return manifest_roots(manifest)


def campaign_roots(root: Path, action: str, target: Path) -> list[Path]:
    """Read the bound run/resume workload paths before installed preflight.

    This derives transport only. The installed ordinary campaign/result,
    Source, qualification, DNS and capture validators retain authority.
    """
    from .capture_session import slug
    from .orchestrator import _campaign_config_root, _trusted_regular_input
    root = _path(root, directory=True)
    paths = []
    configuration = None
    if action == "run":
        import yaml
        target = _path(target)
        if not target.is_relative_to(root):
            raise ValueError("run transport campaign must be inside the Lab root")
        config = _campaign_config_root(target, frozen_inputs=None)
        campaign = yaml.safe_load(target.read_bytes())
        configuration = campaign
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
        configuration = experiment["configuration"]
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
    if isinstance(configuration, Mapping) and "qualification_delivery_compatibility" in configuration:
        from .application_response_policy import application_body_identity_policy
        from .qualification_control_authority import roots as witness_roots
        roots.update(witness_roots(configuration["qualification_delivery_compatibility"],
                                  body_policy=application_body_identity_policy(configuration)))
    return sorted(roots)
