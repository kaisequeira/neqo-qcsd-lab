"""HOST policy/reader controls; synthetic runs do not claim Native execution.

The optional saved Dropbox oracle reads the authentic failed GET without
changing it. No test performs discovery, DNS, capture or a Native subprocess.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import application_response_policy as app
from qcsd_lab import supplied_static_get as get
from qcsd_lab import supplied_static_graph as graph
from qcsd_lab import whole_graph_supplement as whole
from tests.test_supplied_static_get import actual_contract_fixture, load, write, reseal_outputs
from tests.test_supplied_static_preparation import fixed_graph
from tests.test_whole_graph_supplement import supplemented

SAVED_ROOT_ENV = "QCSD_WHOLE_GET_REQUIRED_PARENT_FAILED_ROOT"
OLD_WHOLE_SHA256 = "4c5065dc90214fcc3d128776e33c780f8228916255c692dde8390b855262bec0"
SAVED_FILES = {
    "declaration.json": ("6029563f9ba7ed9af43f557d900a0013cf7d8ca832d136661c3852f02639473b", 0o444),
    "neutral-input.json": ("a514525d045bb048c77efc46dc3f0a169ec5f456716fdae9481bfbd448c71013", 0o444),
    "native-input.json": ("64f779db191d69296cfa62cab77fec6803fa15baa522893467a874834a9d654d", 0o444),
    "native-started.json": ("f485705af67e73d4cfb2ad29fe5fe6673e7021127979df63796bd482ec85b4c1", 0o444),
    "native-completed.json": ("57463617f7b02cb8de496faa04a3a404f44d886d0fa4d8b6c55e129d35a90100", 0o444),
    "native.stderr.log": ("0c663e8eeaaa9aeb056f623a89413fc7d90c6be83033a47fe113c7d27facaffd", 0o644),
}


def neutral_graph():
    def row(identifier, edges, url):
        return {"id": identifier, "type": "Document" if identifier == 0 else "Other",
                "url": url, "headers": [["x-query", "café?exact=1"]],
                "depends_on": edges, "content_length": None, "data_length": 0,
                "known_valid": False, "chaff_priority": False}
    return {"resources": [row(0, [], "https://a.example/"),
        row(1, [0], "https://b.example/repeat?exact=1"),
        row(2, [1], "https://b.example/repeat?exact=1"),
        row(3, [], "https://b.example/independent"),
        row(4, [3], "https://a.example/leaf")]}


def test_prospective_flags_require_roots_and_parents_preserving_full_neutral_graph():
    neutral = neutral_graph()
    snapshot = deepcopy(neutral)
    primary, full = whole._manifests(neutral, policy=whole.REQUIRED_PARENT_MANIFEST_POLICY)
    assert neutral == snapshot and primary == {"resources": [snapshot["resources"][0]]}
    assert [row["known_valid"] for row in full["resources"]] == [True, True, False, True, False]
    for source, output in zip(snapshot["resources"], full["resources"], strict=True):
        assert {key: value for key, value in output.items() if key != "known_valid"} == {
            key: value for key, value in source.items() if key != "known_valid"}
    assert full["resources"][1]["url"] == full["resources"][2]["url"]
    full["resources"][1]["headers"][0][1] = "changed"
    assert neutral == snapshot


def test_legacy_projection_keeps_original_root_only_flags_and_input_bytes():
    neutral = neutral_graph()
    primary, full = whole._manifests(neutral)
    explicit = whole._manifests(neutral, policy=whole.LEGACY_MANIFEST_POLICY)
    assert (primary, full) == explicit
    assert [row["known_valid"] for row in full["resources"]] == [True, False, False, False, False]


@pytest.mark.parametrize("key", ["known_valid", "chaff_priority"])
def test_prospective_builder_refuses_non_neutral_qualification_flags(key):
    neutral = neutral_graph()
    neutral["resources"][1][key] = True
    with pytest.raises(ValueError, match="neutral input"):
        whole._manifests(neutral, policy=whole.REQUIRED_PARENT_MANIFEST_POLICY)


@pytest.mark.parametrize("declaration", [
    {}, {"schema_version": True}, {"schema_version": 0}, {"schema_version": 3},
    {"schema_version": 1, "manifest_policy": whole.REQUIRED_PARENT_MANIFEST_POLICY},
    {"schema_version": 2}, {"schema_version": 2, "manifest_policy": None},
    {"schema_version": 2, "manifest_policy": whole.LEGACY_MANIFEST_POLICY},
    {"schema_version": 2, "manifest_policy": "arbitrary-policy"},
])
def test_manifest_policy_switch_refuses_unsupported_versions_and_cross_labels(declaration):
    with pytest.raises(ValueError):
        whole._declaration_manifest_policy(declaration)


def response_manifest():
    _, value = whole._manifests(neutral_graph(), policy=whole.REQUIRED_PARENT_MANIFEST_POLICY)
    value["preparation"] = {"application_response_policy": app.COMPLETED_TERMINAL_HTTP_ERRORS_POLICY,
        "source_url": value["resources"][0]["url"], "final_url": value["resources"][0]["url"],
        "expected_responses": [{"resource_id": row["id"], "status": 200 if row["known_valid"] else 404,
            "bytes": 1, "body_sha256": "a" * 64} for row in value["resources"]]}
    return value


def test_existing_response_guard_allows_only_terminal_auxiliary_leaves():
    value = response_manifest()
    facts = app.validate_prepared_response_graph(value)
    assert facts["terminal_http_error_resource_ids"] == [2, 4]


@pytest.mark.parametrize("identifier,known_valid,status", [(0, False, 404), (1, False, 404),
    (1, True, 404), (3, False, 404), (3, True, 404), (2, False, 302)])
def test_existing_response_guard_refuses_parent_root_and_redirect_errors(identifier, known_valid, status):
    value = response_manifest()
    value["resources"][identifier]["known_valid"] = known_valid
    value["preparation"]["expected_responses"][identifier]["status"] = status
    with pytest.raises(ValueError):
        app.validate_prepared_response_graph(value)


def prospective_declaration(root):
    neutral = load(root / "neutral-input.json")
    _, full = whole._manifests(neutral, policy=whole.REQUIRED_PARENT_MANIFEST_POLICY)
    declaration = load(root / "declaration.json")
    declaration.update(schema_version=2, manifest_policy=whole.REQUIRED_PARENT_MANIFEST_POLICY,
        producer_sources=whole.producer_sources(), full_input_sha256=graph.digest(graph.canonical_bytes(full)))
    write(root / "native-input.json", full)
    write(root / "declaration.json", declaration)
    for child in (root, root / "bootstrap"):
        started = load(child / "native-started.json")
        started["declaration_sha256"] = graph.digest((root / "declaration.json").read_bytes())
        write(child / "native-started.json", started)
    run = load(root / "native/run.json")
    run["workload_hash_sha256"] = declaration["full_input_sha256"]
    write(root / "native/run.json", run)
    reseal_outputs(root)
    return declaration, full


def test_current_v2_declaration_joins_exact_input_and_full_synthetic_raw_proof(supplemented):
    root, context, _ = supplemented
    declaration, full = prospective_declaration(root)
    loaded, _, _, rebuilt, _ = whole._declaration(root, context, 2)
    assert loaded["manifest_policy"] == whole.REQUIRED_PARENT_MANIFEST_POLICY and rebuilt == full
    assert rebuilt["resources"][1]["known_valid"] is True
    proof = whole.build_proof(root, context=context, position=2)
    assert proof["resource_count"] == 3 and proof["full_list_coverage"] is True
    assert proof["scientific_credit"] is False and proof["formal_accepted_trace_count"] == 0
    assert proof["files"]["declaration.json"] == graph.digest(graph.canonical_bytes(declaration))


@pytest.mark.parametrize("change", ["legacy-hash", "legacy-producer", "extra-field", "pruned-input", "changed-edge"])
def test_v2_declaration_refuses_relabelled_old_authority_or_changed_graph(supplemented, change):
    root, context, _ = supplemented
    old = load(root / "declaration.json")
    declaration, full = prospective_declaration(root)
    if change == "legacy-hash": declaration["full_input_sha256"] = old["full_input_sha256"]
    elif change == "legacy-producer": declaration["producer_sources"]["qcsd_lab.whole_graph_supplement"] = OLD_WHOLE_SHA256
    elif change == "extra-field": declaration["claimed_qualification"] = True
    else:
        if change == "pruned-input": full["resources"].pop()
        else: full["resources"][2]["depends_on"] = [0]
        write(root / "native-input.json", full)
    write(root / "declaration.json", declaration)
    with pytest.raises(ValueError):
        whole.build_proof(root, context=context, position=2)


def test_v1_failure_reopening_preserves_original_root_only_full_input(supplemented):
    root, context, _ = supplemented
    before = {name: (root / name).read_bytes() for name in
              ("declaration.json", "neutral-input.json", "native-input.json")}
    declaration, _, _, full, _ = whole._declaration(root, context, 2)
    assert declaration["schema_version"] == 1 and "manifest_policy" not in declaration
    assert full["resources"][1]["known_valid"] is False
    completion = load(root / "native-completed.json")
    completion["returncode"] = 1
    write(root / "native-completed.json", completion)
    failure = whole.failure_proof(root, context=context, position=2)
    assert failure["phase"] == "full" and failure["outcome"] == "operational-deferred"
    assert failure["scientific_credit"] is False and failure["formal_accepted_trace_count"] == 0
    assert {name: (root / name).read_bytes() for name in before} == before


@pytest.mark.parametrize("change", ["only-native-input", "input-and-declaration-hash"])
def test_v1_cannot_promote_retained_input_to_new_required_parent_flags(supplemented, change):
    root, context, _ = supplemented
    whole.reopen_get(root, context=context, position=2)
    neutral = load(root / "neutral-input.json")
    _, full = whole._manifests(neutral, policy=whole.REQUIRED_PARENT_MANIFEST_POLICY)
    write(root / "native-input.json", full)
    if change == "input-and-declaration-hash":
        declaration = load(root / "declaration.json")
        declaration["full_input_sha256"] = graph.digest(graph.canonical_bytes(full))
        write(root / "declaration.json", declaration)
    with pytest.raises(ValueError):
        whole.build_proof(root, context=context, position=2)


@pytest.fixture
def saved_failed_root():
    raw = os.environ.get(SAVED_ROOT_ENV)
    if raw is None:
        pytest.skip("authentic saved Dropbox GET is an optional HOST oracle")
    root = Path(raw)
    assert root.is_absolute() and root.is_dir()
    for name, (digest, mode) in SAVED_FILES.items():
        path = root / name
        assert graph.digest(get._read(path)) == digest and path.stat().st_mode & 0o7777 == mode
    return root


def test_saved_dropbox_137_six_origin_projection_preserves_original_failure(saved_failed_root):
    root = saved_failed_root
    neutral_raw = get._read(root / "neutral-input.json")
    native_raw = get._read(root / "native-input.json")
    declaration = load(root / "declaration.json")
    neutral = json.loads(neutral_raw)
    policy = whole._declaration_manifest_policy(declaration)
    assert policy == whole.LEGACY_MANIFEST_POLICY
    assert declaration["producer_sources"]["qcsd_lab.whole_graph_supplement"] == OLD_WHOLE_SHA256
    assert whole._manifests(neutral, policy=policy)[1] == json.loads(native_raw)
    _, prospective = whole._manifests(neutral, policy=whole.REQUIRED_PARENT_MANIFEST_POLICY)
    assert len(prospective["resources"]) == 137
    assert len({get._origin(row["url"]) for row in prospective["resources"]}) == 6
    assert prospective["resources"][2]["known_valid"] is True
    assert prospective["resources"][17]["depends_on"] == [0, 2]
    for old, new in zip(neutral["resources"], prospective["resources"], strict=True):
        assert {key: value for key, value in old.items() if key != "known_valid"} == {
            key: value for key, value in new.items() if key != "known_valid"}
    completion = load(root / "native-completed.json")
    assert completion["returncode"] == 1 and completion["timed_out"] is False and completion["outputs"] == {}
    assert b"non-primary dependency or chaff resource 2" in get._read(root / "native.stderr.log")
    assert get._read(root / "neutral-input.json") == neutral_raw and get._read(root / "native-input.json") == native_raw


def test_saved_v1_failed_raw_reopens_under_exact_retained_reader_family(saved_failed_root):
    root = saved_failed_root
    declaration = load(root / "declaration.json")
    context = whole.load_context(Path(declaration["context"]["path"]).parent)
    completion_raw = get._read(root / "native-completed.json")
    failure = whole.failure_proof(root, context=context, position=declaration["position"])
    assert failure["phase"] == "full" and failure["outcome"] == "operational-deferred"
    assert failure["scientific_credit"] is False and failure["formal_accepted_trace_count"] == 0
    assert get._read(root / "native-completed.json") == completion_raw
