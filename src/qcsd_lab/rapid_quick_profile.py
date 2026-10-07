"""Prospective direct launch bindings over a once-verified complete cohort.

Historical admission/runtime receipts remain archived. A flight reopens current
material inputs; its ordinary installed packet/deep verifier still grants credit.
"""
from __future__ import annotations

from dataclasses import asdict, replace
from pathlib import Path

from . import rapid_lane_evidence as lanes
from . import rapid_rolling_capture as rolling
from . import rapid_site_admission as receipts
from . import rapid_slot_chunks as geometry

CAPSULE_TYPE = "qcsd-prospective-direct-quick-launch-profile-v1"
MODE_CAPSULE_TYPE = "qcsd-prospective-direct-quick-launch-profile-v2"
PLAN_TYPE = "qcsd-prospective-direct-quick-formal-plan-v1"
FIELD = "direct_quick_launch_profile"
CONTRACT = "current-material-bindings-complete-graphs-fixed-settings-full-deep-50x5x64-v1"
NATIVE = "818d89398a5b0bc725e424b648d878185d18125d"
EMPTY_SHA256 = lanes._sha(b"")
PLAN_FIELDS = {"study_version", "cohort_generation", "bindings", "runtime", "runtime_artifacts", "acquisition_provenance_sha256",
    "qualification_spec_sha256", "data_role", "capture_limits", "application_body_identity_policy",
    "qualification_delivery_compatibility", "tamaraw_configuration_policy", "buflo_duration_policy", "static_capture_amendment",
    "ordinary_capture_contract"}


def is_payload(value):
    return isinstance(value, dict) and value.get(FIELD) == CONTRACT


def is_profile(value):
    return isinstance(value, dict) and value.get("artifact_type") in {CAPSULE_TYPE, MODE_CAPSULE_TYPE}


def is_plan(path):
    return lanes._load(lanes._read(path)).get("receipt_type") == PLAN_TYPE


def _open(reference, context=None):
    import stat
    path = Path(reference["path"])
    if (any(item.is_symlink() for item in (path, *path.parents)) or not stat.S_ISREG(path.stat().st_mode)):
        raise ValueError("quick profile immutable reference is not a regular unlinked file")
    raw = lanes._read(path) if context is None else context.watch_file(path)
    if (set(reference) != {"path", "sha256"} or not path.is_absolute()
        or ".." in path.parts or lanes._sha(raw) != reference["sha256"]):
        raise ValueError("quick profile immutable reference changed")
    return path


def _runtime_once(spec, canonical_ref):
    """Check the current closed installation, without reopening its ancestors."""
    from . import rapid_rolling_readiness as evidence
    canonical_path = _open(canonical_ref)
    canonical = lanes._load(lanes._read(canonical_path))
    root = canonical_path.parent
    source = lanes._load(lanes._read(spec.source_manifest))
    client_sha = lanes._sha(lanes._read(spec.client_binary))
    if (canonical.get("installed_byte_verification_completed") is not True
        or canonical.get("scientific_credit") is not False
        or canonical.get("collection_image_digest") != spec.collection_image_digest
        or canonical.get("source") != source
        or source.get("lab_dirty") is not False or source.get("neqo_dirty") is not False
        or source.get("lab_patch_sha256") != EMPTY_SHA256 or source.get("neqo_patch_sha256") != EMPTY_SHA256
        or source.get("neqo_commit") != NATIVE or source.get("neqo_pinned_commit") != NATIVE
        or canonical.get("installed_client_sha256") != client_sha
        or canonical.get("exported_source_manifest_sha256") != lanes._sha(lanes._read(spec.source_manifest))):
        raise ValueError("quick profile requires the actual current Native818 installation")
    inventory_ref = rolling._ref(root / "source-inventory.json")
    if inventory_ref["sha256"] != canonical["source_inventory_sha256"]:
        raise ValueError("quick profile source inventory differs from its installed closure")
    inventory = lanes._load(lanes._read(root / "source-inventory.json"))
    if (inventory != evidence._inventory(spec.runtime_source_root)
        or inventory != evidence._inventory(root / "image-context/source")
        or lanes._read(root / "runtime-export/source.json") != lanes._read(spec.source_manifest)
        or lanes._read(root / "runtime-export/neqo-qcsd-client") != lanes._read(spec.client_binary)):
        raise ValueError("quick profile changed complete current source or installed exports")
    operations = canonical.get("actual_operation_completions")
    if not isinstance(operations, dict) or len(operations) != 12:
        raise ValueError("quick profile requires the closed current installation operations")
    for name, record in operations.items():
        completed_raw = lanes._read(root / (name + "-completed.json"))
        completed = lanes._load(completed_raw)
        if (record["record_sha256"] != lanes._sha(completed_raw)
            or record["started_record_sha256"] != lanes._sha(lanes._read(root / (name + "-started.json")))
            or type(completed.get("returncode")) is not int or completed["returncode"] != 0
            or completed.get("invocation_error") is not None
            or completed["stdout_sha256"] != lanes._sha(lanes._read(root / (name + ".stdout.log")))
            or completed["stderr_sha256"] != lanes._sha(lanes._read(root / (name + ".stderr.log")))):
            raise ValueError("quick profile current installation operation changed")
    return canonical, inventory_ref


def _permitted_slots(seed):
    return sorted({slot for row in seed["lanes"] for slot in range(
        row.get("slot_start", (row["block"] - 1) * row["visits_per_workload"]),
        row.get("slot_start", (row["block"] - 1) * row["visits_per_workload"]) + row["visits_per_workload"])})


def _source_layout(root, context=None):
    """Current member names/modes only; file bytes are independently material."""
    import stat
    root = lanes._regular_directory(root)
    files, directories = set(), {".": stat.S_IMODE(root.stat().st_mode)}
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if path.is_symlink():
            raise ValueError("quick current source membership contains a link")
        if path.is_file():
            files.add(relative.as_posix())
        elif path.is_dir():
            directories[relative.as_posix()] = stat.S_IMODE(path.stat().st_mode)
        else:
            raise ValueError("quick current source membership contains a special file")
    if context is not None:
        for name in directories:
            context.watch_directory(root if name == "." else root / name)
    return files, directories


def _traffic_files(seed):
    from . import rapid_capture_traffic as traffic
    return traffic.files(traffic.policy(seed.get(traffic.FIELD)))


def _mode_readiness_domain(seed, mode, reference, recipe, deep, source, files, context):
    """Join direct canary records; never reopen historical trees or experiments."""
    from . import rapid_rolling_readiness as evidence
    directory = Path(reference["plan"]["path"]).parent
    if (Path(reference["plan"]["path"]).name != "plan.json"
        or Path(reference["deep_receipt"]["path"]) != directory / (mode + "-deep-verification.json")):
        raise ValueError("quick explicit mode original receipt domain differs")
    canonical_ref = {"path": str(directory / "canonical-runtime.json"), "sha256": recipe.get("canonical_runtime_sha256")}
    canonical_path = _open(canonical_ref, context)
    files.add(canonical_path)
    canonical = lanes._load(lanes._read(canonical_path))
    collection = canonical.get("checks", {}).get("collection", {})
    image = seed["runtime"]["collection_image_digest"]
    client_sha = seed["runtime_artifacts"]["client_binary"]["sha256"]
    if (canonical != recipe.get("canonical_runtime") or canonical.get("source") != source
        or canonical.get("collection_image_digest") != image or canonical.get("installed_client_sha256") != client_sha
        or canonical.get("exported_source_manifest_sha256") != seed["runtime_artifacts"]["source_manifest"]["sha256"]
        or canonical.get("installed_byte_verification_completed") is not True or canonical.get("scientific_credit") is not False
        or collection.get("source") != source or collection.get("image_digest") != image
        or collection.get("client_sha256") != client_sha):
        raise ValueError("quick explicit mode original canonical/source/client/image differs")
    campaign = recipe["campaigns"][0]
    execution, clean = Path(recipe["execution_root"]), Path(recipe["clean_runtime_root"])
    campaign_path = evidence._child(execution, campaign.get("campaign_relative"))
    files.add(_open({"path": str(campaign_path), "sha256": campaign.get("campaign_sha256")}, context))
    declared = Path(deep.get("root", ""))
    if (type(campaign.get("visits")) is not int or campaign["visits"] != 1
        or deep.get("name") != campaign.get("name") or deep.get("purpose") != "smoke"
        or declared.parent != Path("/lab/results") / campaign.get("name", "")
        or deep.get("canonical_runtime_sha256") != canonical_ref["sha256"]
        or deep.get("selection_sha256") != recipe.get("selection_sha256")
        or not isinstance(recipe.get("selection_sha256"), str) or len(recipe["selection_sha256"]) != 64
        or any(char not in "0123456789abcdef" for char in recipe["selection_sha256"])
        or deep.get("workload_sha256") != recipe.get("workload_sha256")
        or any(type(deep.get(key)) is not int or deep[key] != 0 for key in (
            "formal_accepted_trace_count", "study_pilot_accepted_trace_count", "site_credit"))):
        raise ValueError("quick explicit mode original deep receipt domain differs")
    site = next((row for row in seed["sites"] if row["workload_id"] == recipe.get("workload_id")
                 and row["workload_sha256"] == recipe.get("workload_sha256")), None)
    if site is None:
        raise ValueError("quick explicit mode original readiness workload differs")
    graph_path = Path(seed["runtime"]["workload_root"]) / (site["workload_id"] + ".json")
    files.add(_open({"path": str(graph_path), "sha256": site["workload_sha256"]}, context))
    resources = lanes._load(lanes._read(graph_path))["resources"]
    from urllib.parse import urlsplit
    graph = {"resource_count": len(resources), "resource_records_sha256": lanes._sha(lanes._json(resources)),
        "origins": sorted({urlsplit(row["url"]).scheme + "://" + urlsplit(row["url"]).netloc for row in resources})}
    if recipe.get("full_graph") != graph or deep.get("full_graph") != graph:
        raise ValueError("quick explicit mode original complete graph differs")
    capture = evidence._operation(reference["capture"], directory, mode + "-capture")
    verified = evidence._operation(reference["deep"], directory, mode + "-deep")
    expected_capture = ["env", f"QCSD_LAB_COLLECTION_IMAGE={image}",
        f"QCSD_RAPID_IMAGE_SOURCE_QCSD={clean / 'qcsd-lab'}",
        f"QCSD_RAPID_DNS_RECEIPT_PATH={directory / 'dns-receipts' / (mode + '.json')}",
        str(execution / "qcsd-lab"), "run", str(campaign_path)]
    command = verified["command"]
    tail = [image, "-I", "-B", "/recipe.py", "verify-image", "--plan", "/diagnostic/plan.json",
        "--plan-sha256", reference["plan"]["sha256"], "--mode", mode, "--result", str(declared)]
    prefix = command[3:-len(tail)]
    options = {"--name", "--network", "--user", "--security-opt", "--cap-drop", "--env", "--volume", "--workdir", "--entrypoint"}
    if len(prefix) % 2 or any(prefix[i] not in options for i in range(0, len(prefix), 2)):
        raise ValueError("quick explicit mode original deep Docker argv differs")
    def option(name, expected):
        return command.count(name) == 1 and command.index(name) + 1 < len(command) and command[command.index(name) + 1] == expected
    mounts = [command[i + 1] for i, item in enumerate(command[:-1]) if item == "--volume"]
    if (capture["command"] != expected_capture or capture["command"] != campaign.get("run_argv")
        or command[:3] != ["docker", "run", "--rm"] or command[-len(tail):] != tail
        or not option("--network", "none") or not option("--entrypoint", "/opt/qcsd-venv/bin/python3")
        or [item for i, item in enumerate(command[1:]) if command[i] == "--env" and item.startswith("QCSD_LAB_IMAGE_DIGEST=")]
            != [f"QCSD_LAB_IMAGE_DIGEST={image}"]
        or any(mounts.count(value) != 1 for value in (str(clean) + ":/runtime-src:ro",
            str(execution) + ":/lab:ro", str(directory) + ":/diagnostic:rw"))
        or verified["start"] < capture["end"]
        or not verified["start"] <= evidence._timestamp(deep.get("completed_at")) <= verified["end"]):
        raise ValueError("quick explicit mode actual commands or causal completion order differ")
    for suffix, key in ((":/recipe.py:ro", "recipe_sha256"), (":/helpers.py:ro", "helper_sha256")):
        matching = [item for item in mounts if item.endswith(suffix)]
        if len(matching) != 1:
            raise ValueError("quick explicit mode original verifier transport differs")
        files.add(_open({"path": matching[0].removesuffix(suffix), "sha256": recipe.get(key)}, context))


def _mode_selection(seed, mode, context=None):
    """Reopen one original ready mode's direct records, without ancestor audits."""
    rows = [row for row in seed["lanes"] if row["mode"] == mode]
    reference = seed.get("readiness", {}).get(mode)
    if (mode not in rolling.plan.MODES or not rows or any(row.get("role") != "formal" for row in rows)
        or not isinstance(reference, dict) or set(reference) != {"schema_version", "plan", "capture", "deep", "deep_receipt"}
        or type(reference["schema_version"]) is not int or reference["schema_version"] != 1
        or {name for row in rows for name in row["workload_ids"]} != {site["workload_id"] for site in seed["sites"]}):
        raise ValueError("quick explicit mode lacks its own original formal lanes and actual readiness")
    files = {_open(reference[name], context) for name in ("plan", "deep_receipt")}
    recipe = lanes._load(lanes._read(_open(reference["plan"], context)))
    deep = lanes._load(lanes._read(_open(reference["deep_receipt"], context)))
    campaigns = recipe.get("campaigns")
    if (not isinstance(campaigns, list) or len(campaigns) != 1
        or not isinstance(campaigns[0], dict) or campaigns[0].get("mode") != mode):
        raise ValueError("quick explicit mode original recipe mode differs")
    for action in ("capture", "deep"):
        operation = reference[action]
        if not isinstance(operation, dict) or set(operation) != {"started", "completed", "stdout", "stderr"}:
            raise ValueError("quick explicit mode readiness operation differs")
        files.update(_open(item, context) for item in operation.values())
        start = lanes._load(lanes._read(_open(operation["started"], context)))
        end = lanes._load(lanes._read(_open(operation["completed"], context)))
        if (not isinstance(start.get("command"), list) or type(end.get("returncode")) is not int or end["returncode"] != 0
            or end.get("invocation_error") is not None
            or end.get("stdout_sha256") != operation["stdout"]["sha256"]
            or end.get("stderr_sha256") != operation["stderr"]["sha256"]
            or not receipts._utc(start["started_at"]) <= receipts._utc(end["completed_at"])
            or action == "capture" and start["command"] != campaigns[0].get("run_argv")):
            raise ValueError("quick explicit mode lacks closed actual readiness operations")
    artifacts = seed["runtime_artifacts"]
    files.update(_open(artifacts[name], context) for name in ("source_manifest", "client_binary"))
    if any(artifacts[name]["path"] != seed["runtime"][name] for name in ("source_manifest", "client_binary")):
        raise ValueError("quick explicit mode original runtime artifact paths differ")
    source = lanes._load(lanes._read(_open(artifacts["source_manifest"], context)))
    identity = ("lab_commit", "neqo_commit", "neqo_pinned_commit", "lab_dirty", "neqo_dirty", "lab_patch_sha256", "neqo_patch_sha256")
    if (deep.get("mode") != mode
        or deep.get("valid") is not True or deep.get("status") != "complete" or type(deep.get("accepted_samples")) is not int
        or deep["accepted_samples"] != 1 or deep.get("scientific_credit") is not False
        or deep.get("plan_sha256") != reference["plan"]["sha256"]
        or deep.get("workload_sha256") not in {site["workload_sha256"] for site in seed["sites"]}
        or any(deep.get("source", {}).get(key) != source.get(key) for key in identity)
        or source.get("neqo_commit") != NATIVE or source.get("neqo_pinned_commit") != NATIVE
        or source.get("lab_dirty") is not False or source.get("neqo_dirty") is not False
        or source.get("lab_patch_sha256") != EMPTY_SHA256 or source.get("neqo_patch_sha256") != EMPTY_SHA256
        or recipe.get("expected_lab_commit") != source.get("lab_commit") or recipe.get("expected_native_commit") != NATIVE
        or recipe.get("traffic_hashes") != {key: digest for key, (_, digest) in _traffic_files(seed).items()}
        or recipe.get("capture_limits") != {**seed.get("capture_limits", {}), "max_attempts": 1}
        or deep.get("application_body_identity_policy") != seed.get("application_body_identity_policy")
        or mode == "tamaraw" and deep.get("tamaraw_configuration_policy") != seed.get("tamaraw_configuration_policy")):
        raise ValueError("quick explicit mode differs from its genuine original Native/settings readiness")
    _mode_readiness_domain(seed, mode, reference, recipe, deep, source, files, context)
    return {"mode": mode, "readiness": reference}, rows, files


def publish_profile(spec, canonical_ref, output, *, workloads=None, runtime_spec=None, mode=None, _context=None):
    """Check direct immutable membership/settings, then declare the new profile.

    The original enrolled plan is archived, rather than recursively granted its
    historical contract. Complete live replay remains independently audited.
    """
    if is_plan(spec.plan_receipt):
        raise ValueError("quick profile must start from an original qualified cohort plan")
    seed = lanes.plan_payload(lanes._read(spec.plan_receipt))
    cohort_frame = lanes._load(lanes._read(spec.cohort))
    cohort = receipts._unpack(lanes._read(spec.cohort), cohort_frame["receipt_type"])
    declared_ids = cohort.get("selected_candidate_ids", [row["candidate_id"] for row in cohort.get("decisions", [])
        if row.get("outcome") in {"admitted", "eligible"}])
    if (seed.get("study_version") != 6 or seed.get("cohort_generation") != "rolling-50"
        or seed.get("bindings", {}).get("cohort_sha256") != lanes._sha(lanes._read(spec.cohort))
        or seed.get("qualification_spec_sha256") != lanes._sha(lanes._read(spec.qualification_spec))
        or any(row["candidate_id"] not in declared_ids for row in seed["sites"])
        or not seed.get("lanes") or any(row["role"] != "formal" for row in seed["lanes"])):
        raise ValueError("quick profile requires exact original enrolled complete class identities/settings")
    sites = prepared_sites(seed["sites"])
    selection, mode_rows, mode_files = (None, None, set()) if mode is None else _mode_selection(seed, mode, _context)
    permitted_slots = _permitted_slots(seed if mode_rows is None else {"lanes": mode_rows})
    if not permitted_slots or not set(permitted_slots) <= set(range(64)):
        raise ValueError("quick profile cannot expand the seed's declared remaining logical slots")
    original = spec
    if runtime_spec is not None:
        if (lanes._read(runtime_spec.client_binary) != lanes._read(original.client_binary)
            or any(lanes._sha(lanes._read(runtime_spec.execution_root / name)) != digest for name, digest in _traffic_files(seed).values())):
            raise ValueError("quick runtime renewal changed Native client bytes or fixed traffic")
        if any(getattr(runtime_spec, name) != getattr(original, name) for name in (
            "data_root", "acquisition_root", "cohort", "qualification_spec")):
            raise ValueError("quick runtime renewal changed its complete cohort input layout")
        spec = replace(runtime_spec, plan_receipt=original.plan_receipt)
        seed = {**seed, "runtime": {key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS}}
        if "runtime_artifacts" in seed:
            seed["runtime_artifacts"] = {name: rolling._ref(getattr(spec, name)) for name in seed["runtime_artifacts"]}
    selected = set(workloads or (site.workload_id for site in sites))
    if not selected or not selected <= {site.workload_id for site in sites}:
        raise ValueError("quick profile selection is not an admitted complete workload")
    sites = tuple(site for site in sites if site.workload_id in selected)
    if not 1 <= len(sites) <= 5:
        raise ValueError("quick cohort requires one through five complete admitted sites")
    canonical, inventory_ref = _runtime_once(spec, canonical_ref)
    files = {getattr(spec, name) for name in ("cohort", "qualification_spec", "source_manifest",
        "client_binary", "base_launcher", "host_launcher")}
    files.update({_open(canonical_ref), _open(inventory_ref), original.plan_receipt})
    files.update(mode_files)
    inventory = lanes._load(lanes._read(_open(inventory_ref)))
    files.update(spec.runtime_source_root / name for name in inventory)
    files.update(spec.execution_root / relative for relative, _ in _traffic_files(seed).values())
    source_members, source_directories = _source_layout(spec.runtime_source_root, _context)
    if source_members != set(inventory):
        raise ValueError("quick profile current source member names differ from installed inventory")
    graphs = {}
    for site in sites:
        path = spec.workload_root / (site.workload_id + ".json")
        manifest = lanes._load(lanes._read(path))
        resources = manifest["resources"]
        from urllib.parse import urlsplit
        origins = sorted({f'{urlsplit(row["url"]).scheme}://{urlsplit(row["url"]).netloc}' for row in resources})
        if (lanes._sha(lanes._read(path)) != site.workload_sha256 or len(origins) < 2
            or not resources or len({row["id"] for row in resources}) != len(resources)):
            raise ValueError("quick profile requires the unchanged complete multi-origin graph")
        graphs[site.workload_id] = {"resource_count": len(resources), "origins": origins,
            "resources_sha256": lanes._sha(lanes._json(resources))}
        files.add(path)
    value = {"schema_version": 1, "artifact_type": CAPSULE_TYPE, "contract": CONTRACT,
        "base_spec": spec.serializable(), "runtime": {key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS},
        "qualification_spec": rolling._ref(spec.qualification_spec), "current_canonical": dict(canonical_ref),
        "original_canonical": dict(canonical_ref), "source_inventory": inventory_ref,
        "source": canonical["source"], "client_sha256": canonical["installed_client_sha256"],
        "source_directory_modes": source_directories,
        "sites": [asdict(site) for site in sites], "graphs": graphs, "seed_payload": seed,
        "permitted_slots": permitted_slots,
        "material_files": [rolling._ref(path) for path in sorted(files)],
        "material_modes": {str(path): __import__("stat").S_IMODE(path.stat().st_mode) for path in sorted(files)},
        "archive_references": {"original_plan": rolling._ref(original.plan_receipt), "cohort": rolling._ref(original.cohort)},
        "class_target": 50, "modes": list(rolling.plan.MODES), "visits_per_class_mode": 64,
        "formal_trace_target": 16000, "published_at": receipts._now(), "reason": "prospective direct launch prerequisites",
        "formal_accepted_trace_count": 0, "scientific_credit": False}
    if selection is not None:
        value.update(schema_version=2, artifact_type=MODE_CAPSULE_TYPE, mode_selection=selection)
    if _context is not None:
        for item in value["material_files"]:
            _open(item, _context)
        _context.check()
    receipts.durable_create(Path(output), lanes._json(value))
    return rolling._ref(Path(output))


def validate_profile(reference, *, runtime=None, before=None, _context=None):
    from .rapid_operation_facts import current_context
    _context = current_context() if _context is None else _context
    path = _open(reference, _context)
    key = ("direct-quick-profile", str(path), reference["sha256"], lanes._sha(lanes._json(runtime)), before)
    if _context is not None and _context.has(key):
        return _context.get(key)
    value = lanes._load(lanes._read(path))
    fields = {"schema_version", "artifact_type", "contract", "base_spec", "runtime", "qualification_spec", "current_canonical",
        "original_canonical", "source_inventory", "source", "client_sha256", "sites", "graphs", "seed_payload", "material_files",
        "material_modes", "permitted_slots", "archive_references", "class_target", "modes", "visits_per_class_mode", "formal_trace_target", "published_at",
        "source_directory_modes", "reason", "formal_accepted_trace_count", "scientific_credit"}
    explicit_mode = value.get("artifact_type") == MODE_CAPSULE_TYPE
    if explicit_mode:
        fields.add("mode_selection")
    if (set(value) != fields or not is_profile(value) or type(value.get("schema_version")) is not int
        or value["schema_version"] != (2 if explicit_mode else 1) or value.get("contract") != CONTRACT
        or (value.get("class_target"), value.get("visits_per_class_mode"), value.get("formal_trace_target")) != (50, 64, 16000)
        or value.get("modes") != list(rolling.plan.MODES) or value.get("scientific_credit") is not False
        or value.get("formal_accepted_trace_count") != 0
        or runtime is not None and value["runtime"] != dict(runtime)
        or not receipts._utc(value["published_at"]) <= receipts._utc(before or receipts._now())):
        raise ValueError("quick profile explicit prospective contract differs")
    for item in value["material_files"]:
        material = _open(item, _context)
        if __import__("stat").S_IMODE(material.stat().st_mode) != value["material_modes"][str(material)]:
            raise ValueError("quick profile current material permissions changed")
    source = lanes._load(lanes._read(Path(value["base_spec"]["source_manifest"])))
    if (source != value["source"] or source.get("neqo_commit") != NATIVE or source.get("neqo_pinned_commit") != NATIVE
        or source.get("lab_dirty") is not False or source.get("neqo_dirty") is not False
        or source.get("lab_patch_sha256") != EMPTY_SHA256 or source.get("neqo_patch_sha256") != EMPTY_SHA256
        or lanes._sha(lanes._read(Path(value["base_spec"]["client_binary"]))) != value["client_sha256"]):
        raise ValueError("quick profile current source changed")
    canonical = lanes._load(lanes._read(_open(value["current_canonical"], _context)))
    if (canonical.get("source") != source or canonical.get("collection_image_digest") != value["runtime"]["collection_image_digest"]
        or canonical.get("installed_client_sha256") != value["client_sha256"]
        or canonical.get("source_inventory_sha256") != value["source_inventory"]["sha256"]
        or canonical.get("exported_source_manifest_sha256") != lanes._sha(lanes._read(Path(value["base_spec"]["source_manifest"])))
        or canonical.get("installed_byte_verification_completed") is not True or canonical.get("scientific_credit") is not False):
        raise ValueError("quick profile direct current installation fields disagree")
    inventory = lanes._load(lanes._read(_open(value["source_inventory"], _context)))
    source_root = Path(value["base_spec"]["runtime_source_root"])
    source_files = {str(source_root / name): item for name, item in inventory.items()}
    materials = {item["path"]: item for item in value["material_files"]}
    if (len(materials) != len(value["material_files"]) or not source_files
        or any(path not in materials or set(item) != {"sha256", "executable"}
            or materials[path]["sha256"] != item["sha256"]
            or bool(value["material_modes"][path] & 0o111) != item["executable"] for path, item in source_files.items())):
        raise ValueError("quick profile omitted or changed current installed source bytes")
    source_members, source_directories = _source_layout(source_root, _context)
    if source_members != set(inventory) or source_directories != value["source_directory_modes"]:
        raise ValueError("quick profile current source member names or directory modes changed")
    required = {value["base_spec"][name] for name in ("cohort", "qualification_spec", "source_manifest", "client_binary", "base_launcher", "host_launcher")}
    required.update(item["path"] for item in (value["current_canonical"], value["source_inventory"], *value["archive_references"].values()))
    required.update(str(Path(value["base_spec"]["workload_root"]) / (row["workload_id"] + ".json")) for row in value["sites"])
    required.update(source_files)
    required.update(str(Path(value["base_spec"]["execution_root"]) / name) for name, _ in _traffic_files(value["seed_payload"]).values())
    original_plan = _open(value["archive_references"]["original_plan"], _context)
    original_payload = lanes.plan_payload(lanes._read(original_plan))
    selection, mode_rows, mode_files = (None, None, set())
    if explicit_mode:
        if not isinstance(value["mode_selection"], dict) or set(value["mode_selection"]) != {"mode", "readiness"}:
            raise ValueError("quick explicit mode selection fields differ")
        selection, mode_rows, mode_files = _mode_selection(original_payload, value["mode_selection"]["mode"], _context)
        required.update(str(item) for item in mode_files)
        if (selection != value["mode_selection"]
            or lanes._sha(lanes._read(Path(original_payload["runtime"]["client_binary"]))) != value["client_sha256"]):
            raise ValueError("quick explicit mode changed original readiness or Native client bytes")
    if (required != {item["path"] for item in value["material_files"]}
        or set(value["material_modes"]) != {item["path"] for item in value["material_files"]}):
        raise ValueError("quick profile omitted complete material identities")
    expected_seed = {**original_payload, "runtime": value["runtime"]}
    if "runtime_artifacts" in expected_seed:
        expected_seed["runtime_artifacts"] = {name: rolling._ref(Path(value["base_spec"][name])) for name in expected_seed["runtime_artifacts"]}
    if (lanes._json(value["seed_payload"]) != lanes._json(expected_seed)
        or str(original_plan) != value["base_spec"]["plan_receipt"]
        or value["archive_references"]["cohort"] != rolling._ref(Path(value["base_spec"]["cohort"]))
        or any(row not in original_payload["sites"] for row in value["sites"])
        or value["permitted_slots"] != _permitted_slots(original_payload if mode_rows is None else {"lanes": mode_rows})):
        raise ValueError("quick profile differs from its exact archived membership/settings seed")
    from urllib.parse import urlsplit
    for row in value["sites"]:
        manifest_path = Path(value["base_spec"]["workload_root"]) / (row["workload_id"] + ".json")
        manifest = lanes._load(lanes._read(manifest_path))
        resources = manifest["resources"]
        graph = {"resource_count": len(resources), "origins": sorted({f'{urlsplit(item["url"]).scheme}://{urlsplit(item["url"]).netloc}' for item in resources}),
            "resources_sha256": lanes._sha(lanes._json(resources))}
        if (graph != value["graphs"][row["workload_id"]] or len(graph["origins"]) < 2
            or lanes._sha(lanes._read(manifest_path)) != row["workload_sha256"]):
            raise ValueError("quick profile changed or pruned a complete multi-origin graph")
    return _context.remember(key, value) if _context is not None else value


def bind(spec, context):
    context.watch_file(spec.plan_receipt)
    value = lanes.plan_payload(lanes._read(spec.plan_receipt))
    validate_profile(value["scheduling"], _context=context)
    for row in value["lanes"]:
        context.watch_file(spec.campaign_dir / (row["campaign_name"] + ".yml"))


def verify_plan(spec, *, _context=None, **unused):
    value = receipts._unpack(lanes._read(spec.plan_receipt), PLAN_TYPE)
    if not is_payload(value):
        raise ValueError("quick plan lacks its declared prospective profile")
    capsule = validate_profile(value["scheduling"], runtime={key: spec.serializable()[key] for key in rolling.RUNTIME_FIELDS},
                               before=value["declared_at"], _context=_context)
    base = capsule["base_spec"]
    if any(spec.serializable()[key] != item for key, item in base.items() if key != "plan_receipt"):
        raise ValueError("quick plan changed its directly bound cohort/runtime/input layout")
    if value["sites"] != capsule["sites"] or value["bindings"] != capsule["seed_payload"]["bindings"]:
        raise ValueError("quick plan changed admitted site identities or immutable cohort bindings")
    seed = capsule["seed_payload"]
    mode = capsule["mode_selection"]["mode"] if capsule["artifact_type"] == MODE_CAPSULE_TYPE else seed["lanes"][0]["mode"]
    protected = {key: item for key, item in seed.items() if key in PLAN_FIELDS}
    if (set(value) != set(protected) | {FIELD, "scheduling", "sites", "readiness", "declared_at", "formal_accepted_trace_count", "scientific_credit", "planned_trace_count", "lanes"}
        or any(lanes._json(value[key]) != lanes._json(item) for key, item in protected.items())
        or value["readiness"] != {mode: value["scheduling"]}
        or value["formal_accepted_trace_count"] != 0 or value["scientific_credit"] is not False):
        raise ValueError("quick plan changed its frozen settings or explicit new-profile fields")
    sites = prepared_sites(value["sites"])
    allowed_modes = {mode} if capsule["artifact_type"] == MODE_CAPSULE_TYPE else {row["mode"] for row in seed["lanes"]}
    for row in value["lanes"]:
        lane = geometry.checked_lane({key: item for key, item in row.items() if key != "campaign_sha256"})
        if lane.mode not in allowed_modes or tuple(lane.workload_ids) != tuple(site.workload_id for site in sites):
            raise ValueError("quick plan changes its qualified setting or complete class set")
        if capsule["artifact_type"] == MODE_CAPSULE_TYPE and not any(
            row["mode"] == mode and row["shard"] == lane.shard
            and set(lane.workload_ids) <= set(row["workload_ids"]) for row in seed["lanes"]):
            raise ValueError("quick explicit mode plan changed its original class shard")
        if lane.slot_policy_sha256 != value["scheduling"]["sha256"]:
            raise ValueError("quick plan lane is not bound to its exact profile")
        if not set(range(lane.slot_start, lane.slot_start + lane.visits_per_workload)) <= set(capsule["permitted_slots"]):
            raise ValueError("quick plan invents a slot outside its declared remaining ledger")
        if lanes._sha(lanes._render_lane_campaign(spec, lane, sites)) != row["campaign_sha256"]:
            raise ValueError("quick plan changed its fixed rendered setting")
    lanes.plan._check_workload_files(sites, spec.workload_root)
    if value["planned_trace_count"] != sum(lanes._lane({"plan_payload": value}, row["campaign_name"]).sample_count for row in value["lanes"]):
        raise ValueError("quick plan lost its declared complete trace count")
    return sites, value


def prepared_lane(value):
    return geometry.checked_lane(value)


def prepared_sites(rows):
    from .rapid_undefended_capture import OrdinarySite
    return tuple((OrdinarySite if row["qualification_set"] is None else rolling.plan.Site)(**row) for row in rows)


def release_fence(path, value, facts, preflight, *, include_dns=True):
    import stat
    files, source_trees = {Path(path), *(Path(name) for name in preflight["input_files"])}, {}
    files.update(Path(item["path"]) for item in value["lane_specs"])
    for spec, _, intent_path, _, _, lane, _ in facts:
        payload = lanes.plan_payload(lanes._read(spec.plan_receipt))
        capsule = validate_profile(payload["scheduling"])
        source_trees[capsule["base_spec"]["runtime_source_root"]] = capsule
        files.update(Path(item["path"]) for item in capsule["material_files"])
        files.update({Path(payload["scheduling"]["path"]), spec.plan_receipt, intent_path,
            intent_path.parent / "lineage.json", spec.campaign_dir / (lane.campaign_name + ".yml")})
        if include_dns:
            files.add(intent_path.parent / "dns.json")
    observed = {str(item): {"sha256": lanes._sha(lanes._read(item)),
        "executable": bool(item.stat().st_mode & 0o111), "mode": stat.S_IMODE(item.stat().st_mode)} for item in sorted(files)}
    trees = {}
    for root, capsule in source_trees.items():
        inventory = lanes._load(lanes._read(Path(capsule["source_inventory"]["path"])))
        trees[root] = {"files": {name: observed[str(Path(root) / name)] for name in inventory},
            "directories": capsule["source_directory_modes"]}
    return {"files": observed, "trees": trees}


def require_worker(payload, lane, sites, spec):
    checked_sites, checked = verify_plan(spec)
    if payload != checked or tuple(sites) != checked_sites or lane not in [lanes._lane({"plan_payload": checked}, row["campaign_name"]) for row in checked["lanes"]]:
        raise ValueError("quick worker differs from its exact prospective plan")


def require_disjoint(facts):
    seen = set()
    profiles = set()
    for _, payload, lane, _ in facts:
        profiles.add(payload["scheduling"]["sha256"])
        slots = {(name, lane.mode, lane.slot_start + local) for name in lane.workload_ids for local in range(lane.visits_per_workload)}
        if seen & slots:
            raise ValueError("quick workers duplicate an accepted logical slot")
        seen.update(slots)
    if len(profiles) != 1:
        raise ValueError("quick workers must share one immutable full-graph profile")


def mount_roots(reference, *, _context=None):
    value = validate_profile(reference, _context=_context)
    roots = {Path(reference["path"]).parent}
    roots.update(Path(value["base_spec"][key]) for key in ("data_root", "runtime_source_root", "module_root", "execution_root"))
    roots.update(Path(item["path"]).parent for item in value["material_files"])
    return sorted(lanes._regular_directory(root) for root in roots)


def publish_plan(spec, reference, output, *, slot_start, slot_count, generation=1):
    capsule = validate_profile(reference)
    if (type(slot_start) is not int or type(slot_count) is not int or not 0 <= slot_start < 64
        or not 1 <= slot_count <= 16 or slot_start + slot_count > 64):
        raise ValueError("quick plan requires one through sixteen declared slots inside 0 through 63")
    if not set(range(slot_start, slot_start + slot_count)) <= set(capsule["permitted_slots"]):
        raise ValueError("quick plan cannot expand the seed's declared remaining ledger")
    seed = capsule["seed_payload"]
    mode = capsule["mode_selection"]["mode"] if capsule["artifact_type"] == MODE_CAPSULE_TYPE else seed["lanes"][0]["mode"]
    if capsule["artifact_type"] == CAPSULE_TYPE and any(row["mode"] != mode for row in seed["lanes"]):
        raise ValueError("quick profile requires one independently ready fixed setting")
    sites = capsule["sites"]
    original_rows = [row for row in seed["lanes"] if row["mode"] == mode and (
        capsule["artifact_type"] == CAPSULE_TYPE or {site["workload_id"] for site in sites} <= set(row["workload_ids"]))]
    if not original_rows:
        raise ValueError("quick explicit mode plan lacks its original complete class shard")
    original_lane = original_rows[0]
    lane = geometry.ChunkLane("formal", slot_start + 1, original_lane["shard"], mode, "",
        tuple(row["workload_id"] for row in sites), slot_count, None if mode == "undefended" else sites[0]["qualification_set"],
        slot_start, reference["sha256"])
    lane = replace(lane, campaign_name=geometry.name(lane, generation), generation=generation)
    value = {key: item for key, item in seed.items() if key in PLAN_FIELDS}
    value.update({FIELD: CONTRACT, "scheduling": dict(reference), "sites": sites, "readiness": {mode: dict(reference)},
        "declared_at": receipts._now(), "formal_accepted_trace_count": 0, "scientific_credit": False,
        "planned_trace_count": lane.sample_count})
    site_objects = prepared_sites(sites)
    raw_campaign = geometry.render(lane, site_objects, static_capture_limits=value.get("capture_limits"),
        buflo_duration_policy=value.get("buflo_duration_policy"), application_body_identity_policy=value.get("application_body_identity_policy"),
        qualification_delivery_compatibility=value.get("qualification_delivery_compatibility"),
        tamaraw_configuration_policy=value.get("tamaraw_configuration_policy") if mode == "tamaraw" else None)
    value["lanes"] = [{**asdict(lane), "campaign_sha256": lanes._sha(raw_campaign)}]
    campaign = spec.campaign_dir / (lane.campaign_name + ".yml")
    receipts.durable_create(campaign, raw_campaign)
    rolling._write(Path(output), PLAN_TYPE, value)
    return Path(output)
