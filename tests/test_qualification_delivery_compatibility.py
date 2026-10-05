"""HOST-only prospective consumer guards; fixture runtimes are not installed.

The unchanged sustained-response validator owns epoch/body/120 checks. These
fixtures exercise the new Source/client/group/policy/reuse fences only, with
the runtime and named-set physical boundaries explicitly substituted.
"""
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import importlib.util
import json
from pathlib import Path

import pytest

from qcsd_lab import qualification_delivery_compatibility as compat
from qcsd_lab import chaff_qualification as legacy
from qcsd_lab import response_budget_qualification as budget
from qcsd_lab import rapid_operation_facts as facts

ROOT = Path(__file__).parents[1]


def sources():
    names = set(legacy.IMPLEMENTATION_FILES) | compat.EXTRA_PROTECTED
    values = {name: (ROOT / name).read_bytes() for name in names}
    values["neqo-qcsd/example-native.rs"] = b"fn unchanged_native() {}\n"
    values["config/frozen-profile.json"] = b'{"packet_size":1200}\n'
    values[compat.MODULE] = Path(compat.__file__).read_bytes()
    return values


def source(lab):
    return {"lab_commit": lab * 40, "neqo_commit": "c" * 40, "neqo_pinned_commit": "c" * 40,
            "lab_dirty": False, "neqo_dirty": False,
            "lab_patch_sha256": legacy.EMPTY_SHA256, "neqo_patch_sha256": legacy.EMPTY_SHA256,
            "image_digest": None}


def implementation(code, lab="1"):
    value = {"schema_version": legacy.IMPLEMENTATION_RECEIPT_SCHEMA_VERSION,
        "artifact_type": "qcsd-chaff-qualification-implementation", "domain": legacy.IMPLEMENTATION_RECEIPT_DOMAIN,
        "source": source(lab), "source_files": {name: compat.evidence._sha(code[name]) for name in legacy.IMPLEMENTATION_FILES},
        "installed_modules": {name: {"path": "/installed/" + name, "sha256": compat.evidence._sha(code[name])}
                              for name in legacy.IMPLEMENTATION_PYTHON_FILES},
        "installed_entrypoint": {"path": "/usr/local/bin/qcsd-lab", "sha256": compat.evidence._sha(code["qcsd-lab"])},
        "neqo_qcsd_client": {"path": "/usr/local/bin/neqo-qcsd-client", "sha256": "f" * 64}}
    value["sha256"] = legacy._implementation_aggregate(value)
    return value


def canonical(receipt, image="2"):
    return {"source": receipt["source"], "checks": {"collection": {"qualification_implementation_sha256": receipt["sha256"]}},
            "installed_client_sha256": receipt["neqo_qcsd_client"]["sha256"],
            "collection_image_digest": "sha256:" + image * 64,
            "verified_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat()}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(budget.canonical_bytes(value))
    return compat._ref(path)


def group_fixture(tmp_path, monkeypatch):
    code = sources()
    receipt = implementation(code)
    producer = canonical(receipt)
    base = tmp_path / "workloads/site-a.json"
    from qcsd_lab.supplied_static_preparation import ROLE
    base_ref = write(base, {"preparation": {"data_role": ROLE, "max_response_bytes": 16_777_216}, "resources": []})
    sidecar = {"implementation_receipt": receipt, "qualification_source": {**receipt["source"], "image_digest": producer["collection_image_digest"]},
        "qualification_image_digest": producer["collection_image_digest"], "response_budget_source": budget._budget_source(),
        "qualification_policy": {"max_response_bytes": 16_777_216},
        "request_header_primitive": legacy.response_only_request_header_primitive()}
    sidecar_ref = write(tmp_path / "group/site-a.json", sidecar)
    group = {"artifact_type": budget.NAMED_ARTIFACT_TYPE, "schema_version": 1,
        "qualification_sidecar_schema_version": 3, "workload_ids": ["site-a"],
        "workloads": [{"runtime_manifest_sha256": "a" * 64}]}
    group_ref = write(tmp_path / "group/_qualification-set.json", group)
    calls = []
    monkeypatch.setattr(budget, "load_named_qualification_set", lambda path, **kwargs: calls.append((path, kwargs)))
    return code, receipt, producer, base_ref, sidecar_ref, sidecar, group_ref, calls


def test_original_group_labels_and_explicit_historical_reader_retained(tmp_path, monkeypatch):
    code, receipt, producer, base, sidecar, original, group, calls = group_fixture(tmp_path, monkeypatch)
    records, actual = compat._qualified_group(group, [{"workload_id": "site-a", "base_manifest": base}], producer, code)
    assert actual == receipt and records[0]["sidecar"] == sidecar
    assert records[0]["base_manifest"] == base
    assert calls[0][1]["require_current_implementation"] is False
    assert json.loads(Path(sidecar["path"]).read_bytes())["qualification_source"] == original["qualification_source"]


@pytest.mark.parametrize("mutation", ["cap", "producer-module", "producer-image", "group-schema", "base-bytes", "order"])
def test_group_reuse_refuses_independent_input_mutations(mutation, tmp_path, monkeypatch):
    code, receipt, producer, base, sidecar_ref, sidecar, group, calls = group_fixture(tmp_path, monkeypatch)
    workloads = [{"workload_id": "site-a", "base_manifest": base}]
    if mutation == "cap":
        sidecar["qualification_policy"]["max_response_bytes"] = 67_108_864
        write(Path(sidecar_ref["path"]), sidecar)
    elif mutation == "producer-module":
        sidecar["response_budget_source"]["module_sha256"] = "0" * 64
        write(Path(sidecar_ref["path"]), sidecar)
    elif mutation == "producer-image":
        sidecar["qualification_source"]["image_digest"] = "sha256:" + "0" * 64
        write(Path(sidecar_ref["path"]), sidecar)
    elif mutation == "group-schema":
        value = json.loads(Path(group["path"]).read_bytes()); value["qualification_sidecar_schema_version"] = True
        group = write(Path(group["path"]), value)
    elif mutation == "base-bytes":
        Path(base["path"]).write_bytes(b"changed-base")
    else:
        workloads[0]["workload_id"] = "unlisted-site"
    with pytest.raises(ValueError):
        compat._qualified_group(group, workloads, producer, code)


def test_named_consumer_ast_only_and_original_native_config_preserved():
    import ast

    old = sources()
    relative = "src/qcsd_lab/application_response_policy.py"
    # Construct the pre-policy fixture even when this test runs in the composed
    # consumer Source, where the named prospective units already exist.
    lines = old[relative].splitlines(keepends=True)
    units = ast.parse(old[relative]).body
    for unit in sorted(units, key=lambda node: node.lineno, reverse=True):
        function = isinstance(unit, ast.FunctionDef) and unit.name == "application_body_identity_policy"
        constant = isinstance(unit, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "APPLICATION_BODY_IDENTITY_FIELD"
            for target in unit.targets
        )
        if function or constant:
            del lines[unit.lineno - 1:unit.end_lineno]
    old[relative] = b"".join(lines)
    new = deepcopy(old)
    old.pop(compat.MODULE)
    new[relative] += b'\nAPPLICATION_BODY_IDENTITY_FIELD = "application_body_identity_policy"\n'
    new[relative] += b'\ndef application_body_identity_policy(configuration):\n    return configuration.get(APPLICATION_BODY_IDENTITY_FIELD)\n'
    compared = compat.source_comparison(old, new)
    assert compared["native_file_count"] == 1
    assert set(compared["changed_consumer_units"]) == {relative}


@pytest.mark.parametrize("path", ["src/qcsd_lab/chaff_qualification.py", "src/qcsd_lab/response_budget_qualification.py",
    "src/qcsd_lab/capture_session.py", "neqo-qcsd/example-native.rs", "config/frozen-profile.json"])
def test_changed_qualification_or_request_native_dependency_rejected(path):
    old = sources(); new = deepcopy(old); old.pop(compat.MODULE)
    new[path] += b"\n# altered\n"
    with pytest.raises(ValueError, match="qualification primitive"):
        compat.source_comparison(old, new)


def test_unnamed_policy_algorithm_and_unknown_closed_tag_rejected():
    old = sources(); new = deepcopy(old); old.pop(compat.MODULE)
    new["src/qcsd_lab/application_response_policy.py"] += b"\nUNREVIEWED_BODY_RULE = True\n"
    with pytest.raises(ValueError, match="unnamed"):
        compat.source_comparison(old, new)
    for policy in (None, "unknown", "exact-prepared-application-body-v1"):
        with pytest.raises(ValueError, match="explicit"):
            compat._policy(policy, {"path": "/witness", "sha256": "0" * 64})


def test_original_consumer_implementation_labels_not_substituted():
    old = sources(); receipt = implementation(old); current = deepcopy(old)
    new_receipt = implementation(current, lab="3")
    result = compat._consumer_implementation(receipt, canonical(new_receipt, image="4"), current)
    assert result == new_receipt
    assert receipt["source"]["lab_commit"] == "1" * 40
    with pytest.raises(ValueError, match="real installed runtime"):
        compat._consumer_implementation(receipt, canonical(new_receipt | {"sha256": "0" * 64}), current)


def test_changed_installed_client_rejected_before_group_reproof(monkeypatch):
    code = sources(); receipt = implementation(code)
    old, new = canonical(receipt), deepcopy(canonical(receipt))
    new["installed_client_sha256"] = "0" * 64
    monkeypatch.setattr(compat, "_runtime", lambda role: (old if role == "old" else new, code))
    monkeypatch.setattr(compat, "_qualified_group", lambda *args: pytest.fail("changed client reached the group validator"))
    with pytest.raises(ValueError, match="actual Native/client"):
        compat._derive("old", "new", {}, [])


def test_ambient_env_and_mismatched_context_cannot_select_new_hook(monkeypatch):
    ref = {"path": "/witness", "sha256": "0" * 64}
    monkeypatch.setenv(compat.ENV, ref["path"])
    with pytest.raises(ValueError, match="ambient"):
        compat.validate_current_implementation({}, {}, ref, actual_image="sha256:" + "1" * 64)


def test_explicit_context_still_requires_actual_current_image():
    ref = {"path": "/witness", "sha256": "0" * 64}
    token = compat._ACTIVE.set((ref, compat.POLICY))
    try:
        with pytest.raises(ValueError, match="actual current installed image"):
            compat.validate_current_implementation({}, {}, ref, actual_image=None)
    finally:
        compat._ACTIVE.reset(token)


def test_absent_witness_preserves_exact_reader_kwargs(monkeypatch):
    calls = []
    marker = object()
    monkeypatch.setattr(budget, "load_response_qualified_chaff", lambda path, **kwargs: calls.append((path, kwargs)) or marker)
    assert compat.load_response_qualified_chaff("sidecar", workload_id="site", require_current_implementation=True) is marker
    assert calls == [("sidecar", {"workload_id": "site", "require_current_implementation": True})]


def test_explicit_scope_restores_environment_and_closes_owned_raw(monkeypatch, tmp_path):
    watched = tmp_path / "immutable"; watched.write_bytes(b"before")
    ref = {"path": "/witness", "sha256": "0" * 64}
    def validation(reference, **kwargs):
        facts.current_context().watch_file(watched)
        return ({}, {}, {})
    monkeypatch.setattr(compat, "validate", validation)
    monkeypatch.delenv(compat.ENV, raising=False)
    with pytest.raises(ValueError, match="changed"):
        with compat.qualification_context(ref, body_policy=compat.POLICY):
            watched.write_bytes(b"after")
    assert compat._ACTIVE.get() is None
    assert compat.ENV not in compat.os.environ


def test_declaration_rechecks_raw_before_create_only_publication(monkeypatch, tmp_path):
    watched = tmp_path / "immutable"
    watched.write_bytes(b"before")
    group = write(tmp_path / "group.json", {})
    output = tmp_path / "witness.json"
    monkeypatch.setattr(compat, "_raw_dependencies", lambda *args: ([watched], []))
    monkeypatch.setattr(compat, "_bind", lambda context, *args: context.watch_file(watched))
    def derive(*args):
        watched.write_bytes(b"changed during original validation")
        return {}, {}, {}
    monkeypatch.setattr(compat, "_derive", derive)
    with pytest.raises(ValueError, match="changed"):
        compat.declare(output, producer={}, consumer={}, qualification_group=group,
            workloads=[], body_policy=compat.POLICY)
    assert not output.exists()


def test_raw_selector_closes_sealed_ancestor_deferrals_without_later_attempts(tmp_path):
    """Synthetic receipt selector seam only; original proof validation is separate."""
    from qcsd_lab import supplied_static_admission as admission
    from qcsd_lab.supplied_static_preparation import ROLE
    outer = {}
    for name in ("outer_started", "outer_completed", "outer_stdout", "outer_stderr"):
        outer[name] = write(tmp_path / "outer" / (name + ".json"), {})
    raw_get = tmp_path / "deferred-get"
    raw_get.mkdir()
    terminal = write(tmp_path / "parent/attempts/candidate-000001/terminal.json",
        admission.receipts._bind(admission.TERMINAL_TYPE, {
            "prepared_workload": None, "get_evidence_root": str(raw_get), "namespace": outer}))
    leaf_refs = {name: write(tmp_path / "parent" / (name + ".json"), {})
                 for name in ("source_list", "profile", "candidate_order")}
    parent = write(tmp_path / "parent/provenance.json",
        admission.receipts._bind(admission.PROVENANCE_TYPE, {
            **leaf_refs, "parent_context": None, "inherited_terminals": [terminal]}))
    current_refs = {name: write(tmp_path / "current" / (name + ".json"), {})
                    for name in ("source_list", "profile", "candidate_order")}
    current = write(tmp_path / "current/provenance.json",
        admission.receipts._bind(admission.PROVENANCE_TYPE, {
            **current_refs, "parent_context": parent, "inherited_terminals": [terminal]}))
    complete_get = tmp_path / "complete-get"
    proof = write(complete_get / "full-get-proof.json", {"context": current})
    base = write(tmp_path / "workloads/site.json", {"preparation": {
        "data_role": ROLE, "static_get_evidence": {
            "root": str(complete_get), "proof": proof, "namespace": outer}}})
    # The raw selector must not scan this mutable, unsealed next candidate.
    later = tmp_path / "current/attempts/candidate-000002/terminal.json"
    write(later, {"unsealed": True})
    runtime = {name: str(tmp_path / "runtime" / name) for name in compat.RUNTIME_KEYS}
    for name in ("runtime_source_root", "module_root"):
        Path(runtime[name]).mkdir(parents=True)
    for name in ("source_manifest", "client_binary", "base_launcher", "host_launcher"):
        write(Path(runtime[name]), {})
    canonical_ref = write(tmp_path / "runtime-records/canonical.json", {})
    group = write(tmp_path / "group/manifest.json", {})
    role = {"canonical": canonical_ref, "runtime": runtime}
    files, trees = compat._raw_dependencies(group, {
        "producer": role, "consumer": role, "qualification_group": group,
        "qualified_inputs": [{"workload_id": "site", "base_manifest": base}]})
    assert Path(terminal["path"]) in files
    assert Path(parent["path"]) in files and Path(current["path"]) in files
    assert raw_get in trees and complete_get in trees
    assert all(Path(ref["path"]) in files for ref in outer.values())
    assert later not in files
    assert tmp_path / "current" not in trees and tmp_path / "outer" not in trees


def test_portable_default_equality_and_explicit_witness_dispatch(monkeypatch):
    path = ROOT / "tools/_rapid_class_mode_flight/flight/operator.py"
    spec = importlib.util.spec_from_file_location("delivery_compat_portable", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    c = canonical(implementation(sources()))
    sidecar = {"workload_id": "site", "base_manifest": {"sha256": "a" * 64},
        "qualification_source": {**c["source"], "image_digest": c["collection_image_digest"]},
        "qualification_image_digest": c["collection_image_digest"],
        "implementation_receipt": {"sha256": c["checks"]["collection"]["qualification_implementation_sha256"],
                                   "neqo_qcsd_client": {"sha256": c["installed_client_sha256"]}}}
    module.current_sidecar(sidecar, c, workload_id="site", workload_sha256="a" * 64)
    changed = deepcopy(c); changed["collection_image_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="current Source"):
        module.current_sidecar(sidecar, changed, workload_id="site", workload_sha256="a" * 64)
    calls = []
    monkeypatch.setattr(compat, "validate_sidecar", lambda *args, **kwargs: calls.append(kwargs))
    module.current_sidecar(sidecar, changed, workload_id="site", workload_sha256="a" * 64,
        delivery_compatibility={"path": "/witness", "sha256": "1" * 64}, body_policy=compat.POLICY)
    assert calls[0]["body_policy"] == compat.POLICY and calls[0]["workload_sha256"] == "a" * 64
