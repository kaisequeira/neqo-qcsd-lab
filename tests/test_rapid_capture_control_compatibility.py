"""Reviewed real control sources keep acquisition and qualification unchanged."""
from __future__ import annotations

import copy
import subprocess
from pathlib import Path

import pytest

from qcsd_lab import chaff_qualification as qualification
from qcsd_lab import rapid_capture_control_compatibility as control
from qcsd_lab import rapid_runtime_compatibility as historical


@pytest.fixture(scope="module")
def sources():
    root = Path(__file__).parents[1]
    # Before authoring is committed, HEAD is the serial baseline. In a clone of
    # the committed package, use the parent of its first addition instead of
    # treating the new control source itself as the historical serial source.
    additions = subprocess.check_output(["git", "log", "--diff-filter=A", "--format=%H", "--",
        "src/qcsd_lab/rapid_formal_parallel.py"], cwd=root).decode().splitlines()
    baseline = f"{additions[-1]}^" if additions else "HEAD"
    paths = {*(root / "src/qcsd_lab").glob("*.py"), *(root / "tools").glob("*.py"),
             *(root / name for name in qualification.IMPLEMENTATION_STATIC_FILES)}
    new = {path.relative_to(root).as_posix(): path.read_bytes() for path in paths}
    old = dict(new)
    for name in control.NEW_FILES:
        old.pop(name, None)
    for name in (*control.CONTROL_DEFINITIONS, "qcsd-lab"):
        old[name] = subprocess.check_output(["git", "show", f"{baseline}:{name}"], cwd=root)
    for current in (old, new):
        current["config/defense-params/buflo-live.json"] = b'{"fixed": true}\n'
        current["neqo-qcsd/neqo-bin/src/qcsd/mod.rs"] = b"// unchanged Native bytes\n"
    return old, new


def runtime(sources, *, successor=False):
    hashes = historical._source_inventory(sources)
    source = {"image_digest": None, "lab_commit": ("d" if successor else "b") * 40,
        "lab_dirty": False, "lab_patch_sha256": qualification.EMPTY_SHA256,
        "neqo_commit": "c" * 40, "neqo_pinned_commit": "c" * 40,
        "neqo_dirty": False, "neqo_patch_sha256": qualification.EMPTY_SHA256}
    implementation = {"schema_version": 2, "artifact_type": "qcsd-chaff-qualification-implementation",
        "domain": qualification.IMPLEMENTATION_RECEIPT_DOMAIN, "source": source,
        "source_files": {path: hashes[path] for path in qualification.IMPLEMENTATION_FILES},
        "installed_modules": {path: {"path": f"/installed/{path}", "sha256": hashes[path]}
                              for path in qualification.IMPLEMENTATION_PYTHON_FILES},
        "installed_entrypoint": {"path": "/installed/qcsd-lab", "sha256": hashes["qcsd-lab"]},
        "neqo_qcsd_client": {"path": "/usr/local/bin/neqo-qcsd-client", "sha256": "e" * 64}}
    implementation["sha256"] = qualification._implementation_aggregate(implementation)
    image = "sha256:" + ("f" if successor else "a") * 64
    return {"schema_version": 1, "artifact_type": "qcsd-rapid-v5-installed-runtime-preflight",
        "collection_image_digest": image, "runtime_source": {**source, "image_digest": image},
        "source_manifest_sha256": historical._sha(historical._json(source)), "client_sha256": "e" * 64,
        "base_launcher_sha256": hashes["qcsd-lab"], "host_launcher_sha256": hashes["qcsd-lab"],
        "qualification_implementation": implementation,
        "traffic_hashes": {"buflo": historical._sha(sources["config/defense-params/buflo-live.json"])},
        "formal_accepted_trace_count": 0, "scientific_credit": False}


def groups(sources):
    hashes = historical._source_inventory(sources)
    result = {}
    for group, modules in control._expected_acquisition_modules().items():
        result[group] = {}
        for name in modules:
            path = ("src/" if name.startswith("qcsd_lab.") else "") + name.replace(".", "/") + ".py"
            result[group][name] = "e" * 64 if name == "neqo-qcsd-client" else hashes[path]
    return result


def review(old, new, inventory):
    changes, _ = control.source_changes(old, new)
    return {"schema_version": 1, "artifact_type": control.REVIEW_TYPE,
            "repair_scope": control.REVIEW_SCOPE,
            "reason": "Install the explicitly reviewed two-worker control path prospectively.",
            "changes": changes, "acquisition_source_groups": inventory}


def bridge(old, new, *, inventory=None, current=None, declaration=None):
    inventory = inventory if inventory is not None else groups(old)
    return control.validate_compatibility(runtime(old), current or runtime(new, successor=True),
        old, new, declaration or review(old, new, inventory), acquisition_source_groups=inventory)


def test_real_parallel_diff_keeps_all_eight_acquisition_groups_and_qualification_primitive(sources):
    old, new = sources
    value = bridge(old, new)
    assert value["contract"] == control.CONTRACT != historical.CONTRACT
    assert value["acquisition_source_groups"] == groups(old) == groups(new)
    assert value["qualification_dependencies"] == historical.qualification_dependencies(old)
    assert value["qualification_dependencies"] == historical.qualification_dependencies(new)
    units = set(value["changed_sources"]["qcsd-lab"]["units"])
    assert {"parallel-dispatch", "parallel-workers", "usage"} <= units
    assert units <= {name for name, _, _ in control.SHELL_REGIONS} | set(control.SHELL_GUARDS)
    assert value["formal_accepted_trace_count"] == 0 and value["scientific_credit"] is False
    control.validate_current_implementation(runtime(old)["qualification_implementation"],
        runtime(new, successor=True)["qualification_implementation"], value)
    with pytest.raises(ValueError):
        historical.validate_compatibility(runtime(old), runtime(new, successor=True), old, new,
            {"schema_version": 1, "artifact_type": historical.REVIEW_TYPE,
             "repair_scope": "collector-lifecycle-only", "reason": "Not historical scope", "changes": {}})


@pytest.mark.parametrize("mutation", ["missing_group", "missing_module", "wrong_client", "wrong_digest"])
def test_acquisition_group_omission_or_changed_bytes_cannot_be_declared_compatible(sources, mutation):
    old, new = sources
    inventory = groups(old)
    if mutation == "missing_group":
        del inventory["collector"]
    elif mutation == "missing_module":
        del inventory["attempt"]["tools.rapid_acquire"]
    elif mutation == "wrong_client":
        inventory["page"]["neqo-qcsd-client"] = "0" * 64
    else:
        inventory["navigation"]["qcsd_lab.util"] = "0" * 64
    with pytest.raises(ValueError, match="acquisition|client"):
        bridge(old, new, inventory=inventory)


@pytest.mark.parametrize("path", [
    "src/qcsd_lab/prepare.py", "src/qcsd_lab/chaff_qualification.py",
    "src/qcsd_lab/capture_acceptance_policy.py", "src/qcsd_lab/fidelity.py",
    "src/qcsd_lab/verification.py", "tools/rapid_acquire.py", "Dockerfile",
    "config/defense-params/buflo-live.json", "neqo-qcsd/neqo-bin/src/qcsd/mod.rs",
])
def test_parallel_contract_rejects_method_response_acceptance_and_acquisition_changes(sources, path):
    old, original = sources
    new = dict(original)
    new[path] += b"\n# an unrelated source change\n"
    with pytest.raises(ValueError):
        bridge(old, new)


def test_named_module_does_not_exempt_imports_constants_or_other_validator(sources):
    old, original = sources
    for before, after in ((b"import fcntl\n", b"import fcntl\nimport importlib\n"),
                          (b'INTENT_TYPE = "', b'INTENT_TYPE = "changed-'),
                          (b"def _host_intent(", b"def _weakened_host_intent(")):
        new = dict(original)
        path = "src/qcsd_lab/rapid_lane_evidence.py"
        assert before in new[path]
        new[path] = new[path].replace(before, after, 1)
        with pytest.raises(ValueError, match="protected"):
            control.source_changes(old, new)


def test_launcher_regions_preserve_normal_and_qualification_code(sources):
    old, original = sources
    new = dict(original)
    new["qcsd-lab"] = new["qcsd-lab"].replace(b"WSL_HOST_BUILD_MIN_AVAILABLE_BYTES=1\n",
        b"WSL_HOST_BUILD_MIN_AVAILABLE_BYTES=2\n", 1)
    with pytest.raises(ValueError, match="protected"):
        control.source_changes(old, new)
    new["qcsd-lab"] = original["qcsd-lab"] + control.SHELL_REGIONS[1][1]
    with pytest.raises(ValueError, match="unique"):
        control.source_changes(old, new)


def test_installation_transport_does_not_exempt_an_arbitrary_epoch_guard(sources):
    old, new = sources
    before = next(value for value in control.SHELL_GUARDS["rapid-epoch-authority-guard"] if value in new["qcsd-lab"])
    changed = dict(new)
    changed["qcsd-lab"] = new["qcsd-lab"].replace(before, b"  if true; then\n", 1)
    with pytest.raises(ValueError, match="authority guard"):
        control.source_changes(old, changed)
    changed["qcsd-lab"] = new["qcsd-lab"] + before
    with pytest.raises(ValueError, match="authority guard"):
        control.source_changes(old, changed)


@pytest.mark.parametrize("role", ["native", "client", "traffic", "host_launcher", "module_path"])
def test_runtime_or_installed_role_change_is_not_control_compatibility(sources, role):
    old, new = sources
    current = runtime(new, successor=True)
    receipt = current["qualification_implementation"]
    if role == "native":
        for source in (current["runtime_source"], receipt["source"]):
            source["neqo_commit"] = source["neqo_pinned_commit"] = "0" * 40
    elif role == "client":
        current["client_sha256"] = receipt["neqo_qcsd_client"]["sha256"] = "0" * 64
    elif role == "traffic":
        current["traffic_hashes"]["buflo"] = "0" * 64
    elif role == "host_launcher":
        current["host_launcher_sha256"] = "0" * 64
    else:
        receipt["installed_modules"]["src/qcsd_lab/manifest.py"]["path"] = "/wrong/manifest.py"
    receipt["sha256"] = qualification._implementation_aggregate(receipt)
    with pytest.raises(ValueError):
        bridge(old, new, current=current)


def test_inexact_review_and_unregistered_new_file_are_rejected(sources):
    old, new = sources
    declaration = review(old, new, groups(old))
    declaration["changes"]["qcsd-lab"]["units"] = ["entire-launcher"]
    with pytest.raises(ValueError, match="review"):
        bridge(old, new, declaration=declaration)
    changed = dict(new)
    changed["src/qcsd_lab/unregistered_capture_waiver.py"] = b"pass\n"
    with pytest.raises(ValueError, match="unregistered"):
        control.source_changes(old, changed)


@pytest.mark.parametrize("mutation", ["scientific_credit", "missing_projection", "unsupported_unit", "missing_native_role"])
def test_tampered_bridge_cannot_enter_current_implementation_gate(sources, mutation):
    old, new = sources
    value = copy.deepcopy(bridge(old, new))
    if mutation == "scientific_credit":
        value["scientific_credit"] = True
    elif mutation == "missing_projection":
        del value["control_projection"]["qcsd-lab"]
    elif mutation == "unsupported_unit":
        value["control_projection"]["qcsd-lab"]["new_units"]["normal-run-and-qualification"] = "0" * 64
    else:
        del value["native_source"]["neqo_commit"]
    value["sha256"] = historical._sha(control.DOMAIN.encode() + b"\0" + historical._json(
        {key: item for key, item in value.items() if key != "sha256"}))
    with pytest.raises(ValueError, match="malformed|projection|source role"):
        control.validate_current_implementation(runtime(old)["qualification_implementation"],
            runtime(new, successor=True)["qualification_implementation"], value)
