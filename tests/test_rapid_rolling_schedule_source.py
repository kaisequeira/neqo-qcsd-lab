"""Compare real retained code; no installed-runtime or qualification pass is mocked."""
from __future__ import annotations

import ast
import copy
import subprocess
from pathlib import Path

import pytest

from qcsd_lab import chaff_qualification as qualification
from qcsd_lab import rapid_lane_evidence as lanes
from qcsd_lab import rapid_rolling_schedule as schedule


LANES = "src/qcsd_lab/rapid_lane_evidence.py"
ROLLING = "src/qcsd_lab/rapid_rolling_capture.py"
NEW_HELPER = "src/qcsd_lab/rapid_rolling_schedule.py"


@pytest.fixture(scope="module")
def source_bytes():
    root = Path(__file__).resolve().parents[1]
    paths = {*root.joinpath("src/qcsd_lab").glob("*.py"),
             *root.joinpath("tools").glob("*.py"),
             *(root / name for name in qualification.IMPLEMENTATION_STATIC_FILES),
             *(root / relative for relative, _ in lanes.TRAFFIC_FILES.values()),
             root / ".dockerignore", root / "Dockerfile", root / "pyproject.toml", root / "uv.lock",
             root / "neqo-qcsd/Cargo.toml", root / "neqo-qcsd/Cargo.lock",
             root / "neqo-qcsd/neqo-bin/src/qcsd/mod.rs"}
    result = {}
    base = "083a4a4129f9fb8366f3aba5bf397c90ec62395c"
    for path in paths:
        name = path.relative_to(root).as_posix()
        if name == NEW_HELPER:
            continue
        if name.startswith("neqo-qcsd/"):
            result[name] = path.read_bytes()
        else:
            retained = subprocess.run(["git", "show", f"{base}:{name}"], cwd=root,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            if retained.returncode == 0:
                result[name] = retained.stdout
    # The new control helper is tested as an addition, never assigned to the
    # earlier installed source. The minimal Native fixture still uses real bytes.
    result.pop(NEW_HELPER, None)
    return result


def test_actual_integrated_source_changes_only_named_control_units(source_bytes):
    root = Path(__file__).resolve().parents[1]
    current = {path: (root / path).read_bytes() for path in source_bytes}
    current[NEW_HELPER] = (root / NEW_HELPER).read_bytes()
    facts = schedule.source_changes(source_bytes, current, client_sha256="a" * 64)
    assert set(facts["changed_sources"]) >= {"qcsd-lab", LANES, ROLLING, NEW_HELPER}
    unchanged = schedule.source_changes(source_bytes, source_bytes, client_sha256="a" * 64)
    for key in ("dependency_groups", "acquisition_source_groups", "qualification_dependencies"):
        assert facts[key] == unchanged[key]


def definition(raw, name):
    matches = [node for node in ast.parse(raw).body
               if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
    assert len(matches) == 1, name
    return copy.deepcopy(matches[0])


def replace_definition(raw, name, *replacements):
    node = definition(raw, name)
    lines = raw.decode().splitlines(keepends=True)
    start = min([node.lineno, *(item.lineno for item in node.decorator_list)]) - 1
    replacement = "\n\n".join(ast.unparse(item) for item in replacements) + "\n"
    changed = ("".join(lines[:start]) + replacement + "".join(lines[node.end_lineno:])).encode()
    ast.parse(changed)
    assert changed != raw
    return changed


def body(text):
    return ast.parse(text).body


def factor_enrollment(raw):
    original = definition(raw, "verify_enrollment")
    worker = copy.deepcopy(original)
    worker.name = "_verify_enrollment"

    class RecursiveFacts(ast.NodeTransformer):
        def visit_Assign(self, node):
            if (isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "verify_enrollment"):
                node.value.func.id = "_verify_enrollment"
                node.targets[0].elts.append(ast.Name(id="_", ctx=ast.Store()))
            return self.generic_visit(node)

    worker = RecursiveFacts().visit(worker)
    worker.body[-1] = body("return value, classes, policy")[0]
    wrapper = copy.deepcopy(original)
    wrapper.body = body("batch, classes, _ = _verify_enrollment(path, _verified=_verified)\nreturn batch, classes")
    return replace_definition(raw, original.name, wrapper, worker)


def factor_sites(raw):
    original = definition(raw, "_sites")
    worker = copy.deepcopy(original)
    worker.name = "_sites_from_enrollment"
    worker.args.args = [ast.arg(arg=name) for name in ("batch", "all_classes", "qualifier_spec", "workload_root")]
    worker.args.defaults = []
    worker.args.kw_defaults = [None]
    worker.body = worker.body[1:]
    wrapper = copy.deepcopy(original)
    wrapper.body = body("batch, all_classes = verify_enrollment(enrollment)\n"
                        "return _sites_from_enrollment(batch, all_classes, qualifier_spec, workload_root, require_current=require_current)")
    return replace_definition(raw, original.name, wrapper, worker)


def factor_bindings(raw):
    original = definition(raw, "_bindings")
    worker = copy.deepcopy(original)
    worker.name = "_bindings_from_enrollment"
    worker.args.args = [ast.arg(arg="enrollment"), ast.arg(arg="policy")]
    worker.body = [worker.body[-1]]
    wrapper = copy.deepcopy(original)
    wrapper.body = body("_, _, policy = _verify_enrollment(enrollment)\n"
                        "return _bindings_from_enrollment(enrollment, policy)")
    return replace_definition(raw, original.name, wrapper, worker)


def checked(old, new):
    return schedule.source_changes(old, new, client_sha256="e" * 64)


def test_unchanged_real_sources_derive_complete_dependency_and_acquisition_groups(source_bytes):
    facts = checked(source_bytes, dict(source_bytes))
    assert set(facts) == {"changed_sources", "control_projection", "dependency_groups",
                          "acquisition_source_groups", "qualification_dependencies"}
    assert facts["changed_sources"] == {}
    assert {"measurement", "acceptance", "chaff", "traffic", "native"} <= set(facts["dependency_groups"])
    assert set(facts["acquisition_source_groups"]) == {
        "curated", "fallback", "navigation", "page", "preparation", "browser_policy", "collector", "attempt"}
    assert facts["qualification_dependencies"]


def test_real_enrollment_performance_factoring_preserves_protected_dependencies(source_bytes):
    new = dict(source_bytes)
    raw = factor_bindings(factor_sites(factor_enrollment(new[ROLLING])))
    new[ROLLING] = raw
    facts = checked(source_bytes, new)
    assert set(facts["changed_sources"]) == {ROLLING}
    unchanged = checked(source_bytes, source_bytes)
    for key in ("dependency_groups", "acquisition_source_groups", "qualification_dependencies"):
        assert facts[key] == unchanged[key]


def test_exact_named_parallel_intent_and_formal_guard_are_control_only(source_bytes):
    new = dict(source_bytes)
    node = definition(new[LANES], "prepare_lane_intent")
    # Represent the prospective explicit parallel opt-in without changing any
    # module import, constant, neighboring validator or historical receipt.
    node.body.insert(0, body("parallel_opt_in = actuator == 'parallel-formal-worker'")[0])
    new[LANES] = replace_definition(new[LANES], node.name, node)
    guard = b'"${rapid_capture_version}" != "v5" ||\n'
    assert new["qcsd-lab"].count(guard) == 1
    new["qcsd-lab"] = new["qcsd-lab"].replace(
        guard, b'( "${rapid_capture_version}" != "v5" && "${rapid_capture_version}" != "v6" ) ||\n')
    facts = checked(source_bytes, new)
    assert set(facts["changed_sources"]) == {LANES, "qcsd-lab"}
    assert facts["dependency_groups"] == checked(source_bytes, source_bytes)["dependency_groups"]


def test_only_registered_new_control_helper_is_an_allowed_addition(source_bytes):
    root = Path(__file__).resolve().parents[1]
    new = {**source_bytes, NEW_HELPER: (root / NEW_HELPER).read_bytes()}
    facts = checked(source_bytes, new)
    assert set(facts["changed_sources"]) == {NEW_HELPER}


@pytest.mark.parametrize("path", [
    "neqo-qcsd/neqo-bin/src/qcsd/mod.rs",
    "neqo-qcsd/Cargo.lock",
    "config/defense-params/buflo-live.json",
    "src/qcsd_lab/capture_session.py",
    "src/qcsd_lab/fidelity.py",
    "src/qcsd_lab/chaff_qualification.py",
    "src/qcsd_lab/class_acquisition.py",
    "src/qcsd_lab/cdp_targets.py",
    "src/qcsd_lab/rapid_site_admission.py",
])
def test_native_traffic_measurement_acceptance_chaff_and_acquisition_changes_reject(source_bytes, path):
    assert path in source_bytes
    new = dict(source_bytes)
    # Byte-sensitive inventories must reject even a Rust/traffic comment; the
    # Python mutation is executable eager state, not an ignored AST comment.
    suffix = b"\nSCHEDULING_REUSE_UNDECLARED = True\n" if path.endswith(".py") else b"\n// changed protected bytes\n"
    new[path] += suffix
    with pytest.raises(ValueError):
        checked(source_bytes, new)


@pytest.mark.parametrize("addition", [b"\nimport shutil as scheduling_transport\n", b"\nSCHEDULING_GUARD = False\n"])
def test_named_control_file_does_not_exempt_imports_or_constants(source_bytes, addition):
    new = {**source_bytes, LANES: source_bytes[LANES] + addition}
    with pytest.raises(ValueError):
        checked(source_bytes, new)


def test_unlisted_validator_in_a_control_file_stays_protected(source_bytes):
    new = dict(source_bytes)
    node = definition(new[LANES], "_validate_image_proof")
    node.body.insert(0, body("return ()")[0])
    new[LANES] = replace_definition(new[LANES], node.name, node)
    with pytest.raises(ValueError):
        checked(source_bytes, new)


@pytest.mark.parametrize("path", ["src/qcsd_lab/unreviewed_schedule.py", "tools/unreviewed_schedule.py"])
def test_arbitrary_new_source_file_cannot_enter_the_bridge(source_bytes, path):
    new = {**source_bytes, path: b"def bypass():\n    return True\n"}
    with pytest.raises(ValueError):
        checked(source_bytes, new)


def test_shell_bytes_outside_named_parallel_regions_remain_protected(source_bytes):
    new = dict(source_bytes)
    new["qcsd-lab"] += b"\nexit 0 # unreviewed capture bypass\n"
    with pytest.raises(ValueError):
        checked(source_bytes, new)
