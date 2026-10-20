"""Explicit same-class resource-v1 preparation inputs; no admission or credit.

The original cohort context remains immutable provenance. This separate input
authority declares a new common twenty-resource workload, rather than claiming
that those URLs came from the historical pool. Every preparation still uses the
original backend, ordinary GET/qualification and complete preparation verifier.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
from pathlib import Path, PurePosixPath

from .resource_study_inputs import MODES, canonical_json

INPUT_TYPE = "qcsd-resource-domain-resource-version-preparation-input-v1"
CONTEXT_TYPE = "qcsd-resource-domain-resource-version-input-context-v1"
BINDING_TYPE = "qcsd-resource-domain-resource-version-preparation-binding-v1"
AUTHORITY_KEY = "resource_version_input_authority"
INPUT_CONTEXT = "inputs/resource-version-input-context.json"
INPUT_PLAN = "inputs/resource-versions/preparation-input.json"
APPLICATION_MANIFEST = "inputs/resource-versions/application-manifest.json"


def _read(path, digest=None):
    """Retain the original file guard and collect every parsed v1 dependency."""
    from .resource_study_selection import _read as original_read
    from .resource_study_store import _observe_authority
    raw = original_read(path, digest)
    _observe_authority("file", path, raw)
    return raw


def _need(value, message):
    if not value:
        raise ValueError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _path(value):
    _need(type(value) is str and value and "\\" not in value,
          "resource-version input path must be literal")
    path = PurePosixPath(value)
    _need(path.is_absolute() and str(path) == value and ".." not in path.parts,
          "resource-version input path must be absolute and canonical")
    return Path(value)


def validate_input_plan(value, prior, application_manifest_raw, *, root=None):
    """Authenticate new input intent against the complete original cohort head.

    Readiness is deliberately not required here. It remains an independent
    per-mode admission/capture predicate. An absent mode needs an exact current
    global donor, never an invented historical same-host member.
    """
    from . import resource_study_resource_versions as versions
    from .resource_study_selection import validate_frozen_application_manifest_bytes, _json
    from .resource_study_store import _digest, _hostname
    _need(type(value) is dict and set(value) == {
        "record_type", "schema_version", "hostname", "application_manifest",
        "mode_roots", "mode_templates", "scientific_credit"}
        and value["record_type"] == INPUT_TYPE
        and type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["scientific_credit"] is False, "resource-version preparation input schema differs")
    host = value["hostname"]
    _need(_hostname(host) == host, "resource-version input hostname is not canonical")
    cells, old_roots = versions._prior(prior)
    siblings = [cell for key, cell in cells.items() if key[0] == host]
    _need(siblings and host in prior["class_transition"]["class_selection"]["selected_hostnames"],
          "resource-version input must retain an admitted selected hostname")
    ref = value["application_manifest"]
    _need(type(ref) is dict and set(ref) == {"path", "sha256"},
          "resource-version input needs the exact application manifest reference")
    _path(ref["path"]); _digest(ref["sha256"])
    _need(type(application_manifest_raw) is bytes and _sha(application_manifest_raw) == ref["sha256"],
          "resource-version application manifest SHA differs")
    manifest = _json(application_manifest_raw)
    rows = manifest.get("resources")
    _need(type(rows) is list and all(type(row) is dict and "url" in row for row in rows),
          "resource-version application resources differ")
    urls = [row["url"] for row in rows]
    validate_frozen_application_manifest_bytes(application_manifest_raw, host, urls)
    old = siblings[0]["definition"]
    _need(all(cell["definition"]["urls"] == old["urls"]
              and cell["definition"]["workload_sha256"] == old["workload_sha256"] for cell in siblings),
          "resource-version old modes already have mixed workloads")
    _need((urls, ref["sha256"]) != (old["urls"], old["workload_sha256"]),
          "resource-version preparation must declare a changed workload")
    mappings = value["mode_roots"]
    _need(type(mappings) is list and len(mappings) == 5
          and all(type(row) is dict and set(row) == {"mode", "root"} for row in mappings)
          and [row["mode"] for row in mappings] == sorted(MODES),
          "resource-version input must map all five modes exactly once")
    roots = {_path(row["root"]) for row in mappings}
    _need(all(str(path) not in old_roots
              and all(Path(old_root) not in path.parents and path not in Path(old_root).parents
                      for old_root in old_roots) for path in roots),
          "resource-version preparation roots must be fresh and separate from all old members")
    if root is not None:
        _need(Path(root).absolute() in roots, "preparation root is outside the explicit all-five plan")
    templates = value["mode_templates"]
    _need(type(templates) is list and all(type(cell) is dict for cell in templates),
          "resource-version absent-mode templates must be explicit")
    missing = {mode for mode in MODES if (host, mode) not in cells}
    _need(len(templates) == len(missing)
          and {cell.get("mode") for cell in templates} == missing,
          "resource-version input needs templates only for absent modes")
    donors = {}
    for cell in templates:
        versions._cell(cell)
        _need(cells.get((cell["hostname"], cell["mode"])) == cell,
              "resource-version absent-mode template is not an actual current global cell")
        donors[cell["mode"]] = cell
    baselines = {mode: cells.get((host, mode), donors.get(mode)) for mode in MODES}
    for path in roots:
        selected = [baselines[row["mode"]]["definition"]["native"]
                    for row in mappings if row["root"] == str(path)]
        _need(all(native == selected[0] for native in selected),
              "one preparation root cannot change or combine distinct old Native strata")
    return {"input": deepcopy(value), "urls": urls, "baselines": deepcopy(baselines)}


def load_input_plan(path, expected_sha256):
    """Read strict immutable input and manifest bytes, without live operations."""
    from .resource_study_selection import _json, _digest
    raw = _read(_path(str(path)), _digest(expected_sha256))
    value = _json(raw)
    ref = value.get("application_manifest", {})
    _need(type(ref) is dict and set(ref) == {"path", "sha256"},
          "resource-version input lacks its manifest reference")
    application_raw = _read(_path(ref["path"]), _digest(ref["sha256"]))
    return value, raw, application_raw


def _baseline_refs(baselines):
    return {mode: {"path": "inputs/resource-versions/baseline-enrollments/"
                         + cell["enrollment_sha256"] + ".json",
                   "sha256": cell["enrollment_sha256"]} for mode, cell in baselines.items()}


def _baseline_enrollment(raw, cell):
    from .resource_study_selection import _json
    from .resource_study_store import _scientific_runtime
    value = _json(raw); definition = cell["definition"]; mode = cell["mode"]
    _need(_sha(raw) == cell["enrollment_sha256"] and value.get("hostname") == cell["hostname"]
          and value.get("urls") == definition["urls"]
          and value.get("workload_sha256") == definition["workload_sha256"]
          and list(_scientific_runtime(value.get("runtime"))) == definition["native"]
          and value.get("mode_settings", {}).get(mode) == definition["settings"]
          and value.get("mode_policies", {}).get(mode) == definition["policies"],
          "resource-version baseline enrollment differs from its actual current member")
    return value


def initialize_resource_cohort(parent, root, input_path, input_sha256):
    """Create fresh original cohort inputs plus a distinct unissued v1 context."""
    from . import resource_study_cohorts as cohorts
    from .resource_study_store import StudyStore, _create
    from .resource_study_selection import _relative
    e = cohorts._epochs()
    parent, root = StudyStore(Path(parent).absolute()), Path(root).absolute()
    value, raw, application_raw = load_input_plan(input_path, input_sha256)
    # Validate every operand before the original create-only initializer writes.
    with e._lock(parent.root):
        records = e._records(parent)
        _need(records, "resource-version preparation requires a current cohort head")
        checked = validate_input_plan(value, records[-1], application_raw, root=root)
        baseline_raw = {}
        for mode, cell in checked["baselines"].items():
            data = _read(_relative(Path(cell["root"]), cell["enrollment_path"]), cell["enrollment_sha256"])
            _baseline_enrollment(data, cell)
            baseline_raw[mode] = data
        predecessor_sha = e._sha(records[-1])
    original = cohorts.initialize_cohort(parent.root, root)
    store = StudyStore(root)
    context, context_sha = cohorts._input_context(root, store.plan())
    _need(context["predecessor_sha256"] == predecessor_sha,
          "actual parent changed before resource-version initialization")
    cohorts._require_current_input_context(context)
    _create(root / INPUT_PLAN, raw)
    _create(root / APPLICATION_MANIFEST, application_raw)
    baseline_refs = _baseline_refs(checked["baselines"])
    copied = set()
    for mode, ref in baseline_refs.items():
        if ref["path"] not in copied:
            _create(root / ref["path"], baseline_raw[mode]); copied.add(ref["path"])
    binding = {"record_type": CONTEXT_TYPE, "schema_version": 1, "root": str(root),
        "study_sha256": store._file("study.json")[1]["sha256"],
        "original_context_sha256": context_sha, "input_plan_sha256": _sha(raw),
        "application_manifest_sha256": _sha(application_raw),
        "baseline_enrollments": baseline_refs, "scientific_credit": False}
    _create(root / INPUT_CONTEXT, canonical_json(binding))
    read_context(root, store.plan())
    return {"record_type": "qcsd-resource-domain-resource-version-initialization-v1",
        "original_initialization": original, "input_context": {
            "path": INPUT_CONTEXT, "sha256": _sha(canonical_json(binding))},
        "root": str(root), "hostname": value["hostname"],
        "prepared": False, "admitted": False, "scientific_credit": False}


def read_context(root, plan=None):
    """Pure frozen context replay; never read a ledger or the original host paths."""
    from . import resource_study_cohorts as cohorts
    from .resource_study_selection import _relative, _json
    root = Path(root).absolute()
    actual_plan = _json(_read(_relative(root, "study.json")))
    _need(plan is None or canonical_json(plan) == canonical_json(actual_plan),
          "resource-version plan differs from the immutable study")
    original, original_sha = cohorts._input_context(root, actual_plan)
    _need(_sha(_read(_relative(root, cohorts.INPUT_CONTEXT))) == original_sha,
          "resource-version original local context bytes changed during replay")
    raw = _read(_relative(root, INPUT_CONTEXT)); context = _json(raw)
    input_raw = _read(_relative(root, INPUT_PLAN)); value = _json(input_raw)
    application_raw = _read(_relative(root, APPLICATION_MANIFEST))
    checked = validate_input_plan(value, original["predecessor"], application_raw, root=root)
    baseline_refs = _baseline_refs(checked["baselines"])
    expected = {"record_type": CONTEXT_TYPE, "schema_version": 1, "root": str(root),
        "study_sha256": _sha(_read(_relative(root, "study.json"))),
        "original_context_sha256": original_sha, "input_plan_sha256": _sha(input_raw),
        "application_manifest_sha256": _sha(application_raw),
        "baseline_enrollments": baseline_refs, "scientific_credit": False}
    _need(canonical_json(context) == canonical_json(expected),
          "resource-version local context/root/input bytes differ")
    baseline_values = {mode: _baseline_enrollment(_read(_relative(root, ref["path"]), ref["sha256"]),
                                               checked["baselines"][mode])
                       for mode, ref in baseline_refs.items()}
    return {**checked, "context": context, "original_context": original,
            "baseline_enrollments": baseline_values,
            "application_manifest_raw": application_raw}, _sha(raw)


def candidate(context):
    """Truthful new source occurrences, explicitly distinct from the old pool."""
    from .resource_study_selection import _json
    value = context["input"]; binding = context["context"]
    return {"hostname": value["hostname"], "urls": list(context["urls"]),
        "url_count": 20, "eligible": True, "sources": [value["application_manifest"]["path"]],
        "source_occurrences": [{"resource_version_input_sha256": binding["input_plan_sha256"],
            "application_manifest_sha256": binding["application_manifest_sha256"],
            "resource_index": index, "resource": deepcopy(row)} for index, row in enumerate(
                _json(context["application_manifest_raw"])["resources"], 1)]}


def require_current_context(store, parent, prior, input_ref):
    """Constructor guard under the caller's original current-parent lock.

    Historical readers use read_context instead; an old valid admission is not
    made stale by a later head. This method neither acquires another epoch lock
    nor substitutes a claimed head for the caller's actual records read.
    """
    from .resource_study_cohorts import _same
    _need(type(input_ref) is dict and set(input_ref) == {"path", "sha256"},
          "resource-version input reference differs")
    context, sha = read_context(store.root, store.plan())
    value, raw, application_raw = load_input_plan(input_ref["path"], input_ref["sha256"])
    original = context["original_context"]
    _need(_same(value, context["input"])
          and _sha(raw) == context["context"]["input_plan_sha256"]
          and application_raw == context["application_manifest_raw"]
          and _same(original["predecessor"], prior)
          and original["parent"] == {"root": str(parent.root),
              "study_sha256": parent._file("study.json")[1]["sha256"]},
          "resource-version preparation is not bound to the actual admission parent/input")
    return context, sha


def _runtime(context, root, runtime):
    from .resource_study_store import _scientific_runtime
    modes = [row["mode"] for row in context["input"]["mode_roots"] if row["root"] == str(root)]
    actual = list(_scientific_runtime(runtime))
    _need(modes and all(context["baselines"][mode]["definition"]["native"] == actual for mode in modes),
          "resource-only preparation cannot change its exact old per-mode Native stratum")
    _need(all(context["baseline_enrollments"][mode]["runtime"] == runtime for mode in modes),
          "resource-only preparation must reuse its exact actual old per-mode runtime")
    return modes


def preparation_options(context, root):
    """Preserve only the original mapped BF treatment's explicit options.

    Capped qualification, when genuinely required by that old donor, still runs
    its original complete branch. No aggregate-to-ordinary reinterpretation or
    new all-five qualification prerequisite is introduced.
    """
    modes = [row["mode"] for row in context["input"]["mode_roots"] if row["root"] == str(root)]
    if "buflo" not in modes:
        return {}
    from . import buflo_duration_budget as duration
    from .resource_study_native import (BUFLO_CAPPED_SELECTION_TYPE, BUFLO_CAPPED_SELECTION_POLICY,
                                        _buflo_chaff_cap)
    baseline = context["baseline_enrollments"]["buflo"]
    _need("buflo_small_response_aggregate_selection" not in baseline,
          "resource-version v1 cannot reinterpret an aggregate donor as ordinary BuFLO")
    options = {}
    if "buflo_chaff_selection" in baseline:
        selection = baseline["buflo_chaff_selection"]
        _need(type(selection) is dict and set(selection) == {
            "schema_version", "record_type", "selection_policy", "cap_bytes"}
            and type(selection["schema_version"]) is int and selection["schema_version"] == 1
            and selection["record_type"] == BUFLO_CAPPED_SELECTION_TYPE
            and selection["selection_policy"] == BUFLO_CAPPED_SELECTION_POLICY,
            "resource-version old capped selection declaration differs")
        options["buflo_chaff_cap_bytes"] = _buflo_chaff_cap(selection["cap_bytes"])
    policy = baseline["mode_policies"]["buflo"].get("buflo_duration_policy")
    if policy is not None and policy != duration.CADENCE64_POLICY:
        options["buflo_duration_policy"] = duration.preparation_policy(policy)
    return options


def bind_preparation(store, enrollment, job_path):
    from .resource_study_cohorts import INPUT_CONTEXT as ORIGINAL_CONTEXT
    from .resource_study_selection import _relative
    _need(AUTHORITY_KEY not in enrollment and "runtime_cohort_input_authority" not in enrollment
          and "resource_selection" not in enrollment and "frozen_application_manifest" not in enrollment,
          "new resource authority cannot alias an old preparation input contract")
    context, sha = read_context(store.root, store.plan())
    relative = Path(job_path).relative_to(store.root).as_posix()
    job_sha = _sha(_read(_relative(store.root, relative)))
    value = deepcopy(enrollment)
    value[AUTHORITY_KEY] = {"record_type": BINDING_TYPE, "context_path": INPUT_CONTEXT,
        "context_sha256": sha, "job_path": relative, "job_sha256": job_sha}
    for name, digest in {INPUT_CONTEXT: sha, INPUT_PLAN: context["context"]["input_plan_sha256"],
            APPLICATION_MANIFEST: context["context"]["application_manifest_sha256"],
            ORIGINAL_CONTEXT: context["context"]["original_context_sha256"], relative: job_sha,
            **{ref["path"]: ref["sha256"] for ref in context["context"]["baseline_enrollments"].values()}}.items():
        _need(value["files"].get(name, digest) == digest, "resource-version preparation file conflicts")
        value["files"][name] = digest
    validate_enrollment(store, value, plan=store.plan())
    return value


def validate_enrollment(store, enrollment, *, plan):
    """Pure input/job/Native workload proof; original GET/raw validators follow."""
    from .resource_study_cohorts import INPUT_CONTEXT as ORIGINAL_CONTEXT
    from .resource_study_lineage import bind_enrollment
    from .resource_study_selection import _relative, _json
    _need(type(enrollment) is dict and type(enrollment.get("files")) is dict,
          "resource-version enrollment inventory is absent")
    binding = enrollment.get(AUTHORITY_KEY)
    _need(type(binding) is dict and set(binding) == {
        "record_type", "context_path", "context_sha256", "job_path", "job_sha256"}
        and binding["record_type"] == BINDING_TYPE and binding["context_path"] == INPUT_CONTEXT,
        "resource-version preparation binding is partial or unsupported")
    _need(not ({"resource_selection", "runtime_cohort_input_authority", "frozen_application_manifest"}
               & enrollment.keys()), "resource-version input cannot claim historical input authority")
    context, sha = read_context(store.root, plan)
    _need(binding["context_sha256"] == sha and enrollment.get("hostname") == context["input"]["hostname"],
          "resource-version enrollment context or hostname differs")
    proof = {INPUT_CONTEXT: sha, INPUT_PLAN: context["context"]["input_plan_sha256"],
        APPLICATION_MANIFEST: context["context"]["application_manifest_sha256"],
        ORIGINAL_CONTEXT: context["context"]["original_context_sha256"],
        binding["job_path"]: binding["job_sha256"],
        **{ref["path"]: ref["sha256"] for ref in context["context"]["baseline_enrollments"].values()}}
    for name, digest in proof.items():
        _need(enrollment["files"].get(name) == digest, "resource-version input missing from enrollment files")
        _read(_relative(store.root, name), digest)
    baseline_prefix = "inputs/resource-versions/baseline-enrollments/"
    _need({name for name in enrollment["files"] if name.startswith(baseline_prefix)}
          == {name for name in proof if name.startswith(baseline_prefix)},
          "resource-version enrollment has unbound baseline inputs")
    expected = bind_enrollment(store, {**enrollment, "files": {}}, plan=plan)
    _need(enrollment.get("class_selection") == expected["class_selection"]
          and all(enrollment["files"].get(name) == digest for name, digest in expected["files"].items()),
          "resource-version enrollment lost original selected50/source/address context")
    _need(enrollment.get("urls") == context["urls"]
          and enrollment.get("source_occurrences") == candidate(context)["source_occurrences"]
          and enrollment.get("workload_sha256") == context["context"]["application_manifest_sha256"],
          "resource-version enrollment changed new ordered20/source occurrences/workload")
    modes = _runtime(context, store.root, enrollment["runtime"])
    for mode in modes:
        old = context["baselines"][mode]["definition"]
        _need(enrollment.get("mode_settings", {}).get(mode) == old["settings"]
              and enrollment.get("mode_policies", {}).get(mode) == old["policies"]
              and type(enrollment.get("mode_readiness", {}).get(mode)) is bool,
              "resource-only preparation changed original mode settings or policies")
    options = preparation_options(context, store.root)
    _need("buflo_small_response_aggregate_selection" not in enrollment,
          "resource-version v1 preparation cannot add aggregate treatment")
    if "buflo_chaff_cap_bytes" in options:
        _need(enrollment.get("buflo_chaff_selection") == context["baseline_enrollments"]["buflo"]["buflo_chaff_selection"],
              "resource-version preparation dropped or changed its original BF cap treatment")
        from .resource_study_native import validate_buflo_capped_enrollment
        validate_buflo_capped_enrollment(store.root, enrollment)
    else:
        _need("buflo_chaff_selection" not in enrollment,
              "resource-version preparation added an unrequested BF cap treatment")
    job_path = _relative(store.root, binding["job_path"])
    base = _relative(store.root, enrollment["preparation_dir"])
    job = _json(_read(job_path, binding["job_sha256"]))
    _need(job_path.name == "job.json" and job_path.parent / "prepared" == base
          and set(job) == {"hostname", "urls", "output", "runtime"}
          and job == {"hostname": enrollment["hostname"], "urls": context["urls"],
                      "output": str(base), "runtime": enrollment["runtime"]},
          "resource-version selection differs from the actual original preparation job")
    def enrolled(relative):
        raw = _read(_relative(store.root, relative), enrollment["files"].get(relative))
        _need(relative in enrollment["files"], "resource-version Native input is unbound")
        return raw, _json(raw)
    actual = enrolled((base / "preparation-get/input.json").relative_to(store.root).as_posix())[1]
    workload_raw, workload = enrolled(enrollment["workload_path"])
    prepared = enrolled(enrollment["paths"]["prepared_workload"])[1]
    for value in (actual, workload, prepared):
        rows = value.get("resources")
        _need(type(rows) is list and len(rows) == 20
              and all(type(row) is dict and type(row.get("id")) is int for row in rows)
              and [row["id"] for row in rows] == list(range(20))
              and [row.get("url") for row in rows] == context["urls"],
              "resource-version differs from actual Native input/workload")
    _need(workload_raw == context["application_manifest_raw"]
          and prepared["resources"] == workload["resources"]
          and prepared.get("preparation", {}).get("runtime") == enrollment["runtime"],
          "resource-version actual prepared manifest or runtime differs")
    return context


def artifact_paths(enrollment):
    if AUTHORITY_KEY not in enrollment:
        return {}
    from .resource_study_cohorts import INPUT_CONTEXT as ORIGINAL_CONTEXT
    result = {"resource_version_input_context": INPUT_CONTEXT,
        "resource_version_preparation_input": INPUT_PLAN,
        "resource_version_application_manifest": APPLICATION_MANIFEST,
        "resource_version_original_cohort_context": ORIGINAL_CONTEXT,
        "resource_version_preparation_job": enrollment[AUTHORITY_KEY]["job_path"]}
    # The context has already been validated by the original lineage call.
    # Derive the complete baseline path set from its enrolled immutable files.
    baselines = sorted(relative for relative in enrollment["files"]
                       if relative.startswith("inputs/resource-versions/baseline-enrollments/"))
    for index, relative in enumerate(baselines, 1):
        result["resource_version_baseline_" + str(index)] = relative
    return result


def validate_receipt(root, enrollment, receipt):
    paths = artifact_paths(enrollment)
    actual = receipt.get("artifact_paths", {})
    _need({name: path for name, path in actual.items() if name.startswith("resource_version_")} == paths
          and all(receipt.get("files", {}).get(path) == enrollment["files"].get(path)
                  for path in paths.values()), "receipt lacks its exact resource-version preparation artifacts")


def enroll(root, runtime, hostnames, input_path, input_sha256, *, backend=None):
    """One original ordinary preparation, with exact new resources and old mode science."""
    from . import resource_study_cohorts as cohorts
    from .resource_study import create_json
    from .resource_study_epochs import _verify_preparation
    from .resource_study_lineage import bind_enrollment, validate_enrollment as validate_lineage
    from .resource_study_storage import require_storage
    from .resource_study_store import StudyStore
    store = StudyStore(root)
    context, _ = read_context(root, store.plan())
    value, raw, application_raw = load_input_plan(input_path, input_sha256)
    _need(_sha(raw) == context["context"]["input_plan_sha256"]
          and value == context["input"] and application_raw == context["application_manifest_raw"]
          and hostnames == [value["hostname"]], "resource-version prepare operands differ from initialized input")
    cohorts._require_current_input_context(context["original_context"])
    _runtime(context, store.root, runtime)
    _need(not store.enrolled(), "resource-version preparation requires a fresh unenrolled root")
    with store._transaction() as connection:
        _need(connection.execute("SELECT 1 FROM attempts LIMIT 1").fetchone() is None,
              "resource-version preparation cannot replace attempted inputs")
    if backend is None:
        from .resource_study_runtime import PreparationRuntime
        backend = PreparationRuntime(store.root, runtime)
    host = value["hostname"]
    attempt = store.root / "enrollment-attempts" / host / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    try:
        require_storage(store.root, reserve_bytes=store.plan().get("storage_reserve_bytes", 2 * 1024**3))
        enrollment = backend.prepare(candidate(context), attempt, **preparation_options(context, store.root))
        enrollment = bind_enrollment(store, enrollment)
        enrollment = bind_preparation(store, enrollment, attempt / "job.json")
        validate_lineage(store, enrollment)
        _verify_preparation(store, host, enrollment=enrollment)
        cohorts._require_current_input_context(context["original_context"])
        store.enroll(enrollment)
        result = {"hostname": host, "status": "enrolled", "resources": 20}
    except (OSError, ValueError, RuntimeError) as error:
        create_json(attempt / "excluded.json", {"hostname": host, "status": "not-enrolled",
            "reason": str(error), "exception": type(error).__name__, "scientific_credit": False})
        result = {"hostname": host, "status": "not-enrolled", "reason": str(error)}
    return {"enrollment": [result], "progress": store.status()}
