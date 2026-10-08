"""Finite Source68/SDK973 reader compatibility; no GET or capture credit.

The old files below are restored byte for byte from the executing prospective
reader and authenticated against their genuine retained hashes. No source
identity is relabelled. The optional oracle checks recorded reader metadata only.
"""
from copy import deepcopy
import ast
import hashlib
import os
from pathlib import Path

import pytest

from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab import rapid_per_class_selected_enrollment as ledger
from qcsd_lab import rapid_site_admission as receipts
from qcsd_lab import rapid_supplemental_cohort as cohort
from qcsd_lab import whole_graph_input as inputs
from qcsd_lab import whole_graph_supplement as whole
from qcsd_lab.rapid_operation_facts import OperationFacts

OLD_INPUT = "7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c"
NEW_INPUT = "53a988148197bac97578cc89b5ca528f2cda6ea818b53a772f6f1302ae5c5ba8"
OLD_COHORT = "e6fbd49f3e85f2cbb8e666eb8fd030971c950d2d135373e0590d8d3e833c62ad"
NEW_COHORT = "2391723d90e339680c9d6b7d0ce31ab84b437f1a963ed1b166eb1237a49ed091"
OLD_TARGET = "096362d42f28bad11bf698948e93d9078534718ce5f6a04ab97ff30156a78593"
NEW_TARGET = "f661fbfb19641d6aa19586d2a587475878d080734f33602a0a02df461615ac53"
FAMILY = {
    inputs.__name__: OLD_INPUT,
    whole.__name__: "dd7c5973f6876acdadb079b5b33bd719918cffd0a5ad9847e7b54493d157af98",
    ledger.__name__: "4f7f3a6fd67f077165496b92d62e9b81f1e0168d01ad3f11607b144a6124bee0",
    cohort.__name__: OLD_COHORT,
}
OLD_FAILURE = b"    value = get._load(get._read(path))\n    plan = load_plan(reopen(value[\"plan\"]))\n    if plan[\"schema_version\"] == 13:\n        if (path.name != \"failed.json\" or not zero(value)\n                or value.get(\"candidate\") not in plan[\"candidates\"]\n                or value.get(\"outcome\") != \"operational-discovery-failure-no-admission\"):\n            raise ValueError(\"V13 discovery failure changes its declared zero-credit role\")\n        _verify_external(_producer(plan), \"verify-failure\", \"--failure\", path.absolute(), timeout=None)\n        return value\n    if plan[\"schema_version\"] >= 4:\n"
NEW_FAILURE = b"    value = get._load(get._read(path))\n    plan_path = reopen(value[\"plan\"])\n    plan = get._load(get._read(plan_path))\n    if isinstance(plan, dict) and plan.get(\"artifact_type\") == V13_PLAN_TYPE:\n        operator = _producer(plan)\n        if (not zero(plan) or path.name != \"failed.json\" or not zero(value)\n                or value.get(\"candidate\") not in plan[\"candidates\"]\n                or value.get(\"outcome\") != \"operational-discovery-failure-no-admission\"):\n            raise ValueError(\"V13 discovery failure changes its declared zero-credit role\")\n        _verify_external(operator, \"verify-failure\", \"--failure\", path.absolute(), timeout=None)\n        return value\n    plan = load_plan(plan_path)\n    if plan[\"schema_version\"] >= 4:\n"
SDK973_FAMILY_ADDITION = b"    }, {\n        \"qcsd_lab.whole_graph_input\": \"7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c\",\n        \"qcsd_lab.whole_graph_supplement\": \"dd7c5973f6876acdadb079b5b33bd719918cffd0a5ad9847e7b54493d157af98\",\n        \"qcsd_lab.rapid_per_class_selected_enrollment\": \"4f7f3a6fd67f077165496b92d62e9b81f1e0168d01ad3f11607b144a6124bee0\",\n        \"qcsd_lab.rapid_supplemental_cohort\": \"e6fbd49f3e85f2cbb8e666eb8fd030971c950d2d135373e0590d8d3e833c62ad\",\n"
TARGET_RESTORATION = (
    (b"        'whole_graph_input.py': '53a988148197bac97578cc89b5ca528f2cda6ea818b53a772f6f1302ae5c5ba8',\n", b"        'whole_graph_input.py': '7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c',\n"),
    (b"        'rapid_supplemental_cohort.py': '2391723d90e339680c9d6b7d0ce31ab84b437f1a963ed1b166eb1237a49ed091',\n", b"        'rapid_supplemental_cohort.py': 'e6fbd49f3e85f2cbb8e666eb8fd030971c950d2d135373e0590d8d3e833c62ad',\n"),
    (b"def _v13_input_reader_source_projection(raw):\n    \"\"\"Restore every Source62 byte after finite prospective V13 registration.\"\"\"\n    if hashlib.sha256(raw).hexdigest() == '53a988148197bac97578cc89b5ca528f2cda6ea818b53a772f6f1302ae5c5ba8':\n        current = b\"    value = get._load(get._read(path))\\n    plan_path = reopen(value[\\\"plan\\\"])\\n    plan = get._load(get._read(plan_path))\\n    if isinstance(plan, dict) and plan.get(\\\"artifact_type\\\") == V13_PLAN_TYPE:\\n        operator = _producer(plan)\\n        if (not zero(plan) or path.name != \\\"failed.json\\\" or not zero(value)\\n                or value.get(\\\"candidate\\\") not in plan[\\\"candidates\\\"]\\n                or value.get(\\\"outcome\\\") != \\\"operational-discovery-failure-no-admission\\\"):\\n            raise ValueError(\\\"V13 discovery failure changes its declared zero-credit role\\\")\\n        _verify_external(operator, \\\"verify-failure\\\", \\\"--failure\\\", path.absolute(), timeout=None)\\n        return value\\n    plan = load_plan(plan_path)\\n    if plan[\\\"schema_version\\\"] >= 4:\\n\"\n        original = b\"    value = get._load(get._read(path))\\n    plan = load_plan(reopen(value[\\\"plan\\\"]))\\n    if plan[\\\"schema_version\\\"] == 13:\\n        if (path.name != \\\"failed.json\\\" or not zero(value)\\n                or value.get(\\\"candidate\\\") not in plan[\\\"candidates\\\"]\\n                or value.get(\\\"outcome\\\") != \\\"operational-discovery-failure-no-admission\\\"):\\n            raise ValueError(\\\"V13 discovery failure changes its declared zero-credit role\\\")\\n        _verify_external(_producer(plan), \\\"verify-failure\\\", \\\"--failure\\\", path.absolute(), timeout=None)\\n        return value\\n    if plan[\\\"schema_version\\\"] >= 4:\\n\"\n        if raw.count(current) != 1:\n            raise ValueError('closed HOST V13 failure reader hunk is not unique')\n        raw = raw.replace(current, original, 1)\n        if hashlib.sha256(raw).hexdigest() != '7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c':\n            raise ValueError('closed HOST failure reader changes protected V13 bytes')\n", b"def _v13_input_reader_source_projection(raw):\n    \"\"\"Restore every Source62 byte after finite prospective V13 registration.\"\"\"\n"),
    (b"def _v13_cohort_reader_source_projection(raw):\n    if hashlib.sha256(raw).hexdigest() == '2391723d90e339680c9d6b7d0ce31ab84b437f1a963ed1b166eb1237a49ed091':\n        addition = b\"    }, {\\n        \\\"qcsd_lab.whole_graph_input\\\": \\\"7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c\\\",\\n        \\\"qcsd_lab.whole_graph_supplement\\\": \\\"dd7c5973f6876acdadb079b5b33bd719918cffd0a5ad9847e7b54493d157af98\\\",\\n        \\\"qcsd_lab.rapid_per_class_selected_enrollment\\\": \\\"4f7f3a6fd67f077165496b92d62e9b81f1e0168d01ad3f11607b144a6124bee0\\\",\\n        \\\"qcsd_lab.rapid_supplemental_cohort\\\": \\\"e6fbd49f3e85f2cbb8e666eb8fd030971c950d2d135373e0590d8d3e833c62ad\\\",\\n\"\n        if raw.count(addition) != 1:\n            raise ValueError('retained SDK973 cohort reader family is not unique')\n        raw = raw.replace(addition, b'', 1)\n        if hashlib.sha256(raw).hexdigest() != 'e6fbd49f3e85f2cbb8e666eb8fd030971c950d2d135373e0590d8d3e833c62ad':\n            raise ValueError('SDK973 cohort registration changes protected bytes')\n", b"def _v13_cohort_reader_source_projection(raw):\n"),
    (b"def _v12_input_reader_source_projection(raw):\n    \"\"\"Recover every exact V11 reader byte after finite V12 registration.\"\"\"\n    if hashlib.sha256(raw).hexdigest() in ('5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa',\n            '53a988148197bac97578cc89b5ca528f2cda6ea818b53a772f6f1302ae5c5ba8',\n            '7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c'):\n", b"def _v12_input_reader_source_projection(raw):\n    \"\"\"Recover every exact V11 reader byte after finite V12 registration.\"\"\"\n    if hashlib.sha256(raw).hexdigest() in ('5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa',\n            '7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c'):\n"),
    (b"def _v11_input_reader_source_projection(raw):\n    \"\"\"Restore exact Source53 bytes after reviewed V11/V12 registration.\"\"\"\n    if hashlib.sha256(raw).hexdigest() in (\n            '5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa',\n            '53a988148197bac97578cc89b5ca528f2cda6ea818b53a772f6f1302ae5c5ba8',\n", b"def _v11_input_reader_source_projection(raw):\n    \"\"\"Restore exact Source53 bytes after reviewed V11/V12 registration.\"\"\"\n    if hashlib.sha256(raw).hexdigest() in (\n            '5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa',\n"),
    (b"    if (relative == 'src/qcsd_lab/rapid_supplemental_cohort.py'\n            and before['sha256'] in ('12eec36c6bcd6ab27790f8f6d77ca724d775f108d0bb08f41214b61310a092be',\n                '39383c717f267bcb27c5d5a7585cbef3a9138f7845ccedf04033014519b2a029',\n                'c80f566a5b477ed4011f437b740edf49c9ba9496b1e073f3828e76f6b686630d',\n                'e6fbd49f3e85f2cbb8e666eb8fd030971c950d2d135373e0590d8d3e833c62ad')):\n        old_raw = Path(before['path']).read_bytes()\n        if before['sha256'] in ('39383c717f267bcb27c5d5a7585cbef3a9138f7845ccedf04033014519b2a029',\n                'c80f566a5b477ed4011f437b740edf49c9ba9496b1e073f3828e76f6b686630d',\n                'e6fbd49f3e85f2cbb8e666eb8fd030971c950d2d135373e0590d8d3e833c62ad'):\n", b"    if (relative == 'src/qcsd_lab/rapid_supplemental_cohort.py'\n            and before['sha256'] in ('12eec36c6bcd6ab27790f8f6d77ca724d775f108d0bb08f41214b61310a092be',\n                '39383c717f267bcb27c5d5a7585cbef3a9138f7845ccedf04033014519b2a029',\n                'c80f566a5b477ed4011f437b740edf49c9ba9496b1e073f3828e76f6b686630d')):\n        old_raw = Path(before['path']).read_bytes()\n        if before['sha256'] in ('39383c717f267bcb27c5d5a7585cbef3a9138f7845ccedf04033014519b2a029',\n                'c80f566a5b477ed4011f437b740edf49c9ba9496b1e073f3828e76f6b686630d'):\n"),
    (b"    if relative == 'src/qcsd_lab/whole_graph_input.py':\n        old_raw, new_raw = Path(before['path']).read_bytes(), Path(after['path']).read_bytes()\n        if before['sha256'] in ('5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa',\n                '7dd9513e8eaf9adddb16c42c201af1aa1fbab045b25c6189ec2d4ccf53c4463c'):\n", b"    if relative == 'src/qcsd_lab/whole_graph_input.py':\n        old_raw, new_raw = Path(before['path']).read_bytes(), Path(after['path']).read_bytes()\n        if before['sha256'] == '5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa':\n"),
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def executing(module, sha):
    path = Path(module.__file__)
    assert path.stat().st_mode & 0o7777 == 0o644
    raw = path.read_bytes()
    assert digest(raw) == sha
    return path, raw


@pytest.fixture
def sdk973(tmp_path):
    """Exact historical four-file family in a relocated read-only-source layout."""
    raw_input = executing(inputs, NEW_INPUT)[1]
    assert raw_input.count(NEW_FAILURE) == 1
    raw_input = raw_input.replace(NEW_FAILURE, OLD_FAILURE, 1)
    assert digest(raw_input) == OLD_INPUT
    raw_cohort = executing(cohort, NEW_COHORT)[1]
    assert raw_cohort.count(SDK973_FAMILY_ADDITION) == 1
    raw_cohort = raw_cohort.replace(SDK973_FAMILY_ADDITION, b"", 1)
    assert digest(raw_cohort) == OLD_COHORT
    raw = {
        inputs.__name__: raw_input,
        whole.__name__: executing(whole, FAMILY[whole.__name__])[1],
        ledger.__name__: executing(ledger, FAMILY[ledger.__name__])[1],
        cohort.__name__: raw_cohort,
    }
    package = tmp_path / "sdk973/src/qcsd_lab"
    package.mkdir(parents=True)
    refs = {}
    for name, content in raw.items():
        path = package / (name.rsplit(".", 1)[1] + ".py")
        path.write_bytes(content)
        path.chmod(0o644)
        refs[name] = inputs.reference(path)
        assert refs[name]["sha256"] == FAMILY[name]
        assert refs[name]["mode"] == "0644"
    return refs


def test_exact_sdk973_family_and_direct_reader_pairs_remain_supported(sdk973):
    assert cohort._recognized_reader_sources(sdk973)
    current = cohort.reader_sources()
    assert current[inputs.__name__]["sha256"] == NEW_INPUT
    assert current[cohort.__name__]["sha256"] == NEW_COHORT
    authenticated = fixed._acquisition_reader_sources()
    for name, before in sdk973.items():
        relative = "src/qcsd_lab/" + Path(before["path"]).name
        assert fixed._compatible_acquisition_code(
            relative, fixed.reference(Path(before["path"])),
            fixed.reference(Path(current[name]["path"])))
        assert authenticated[relative]["sha256"] == current[name]["sha256"]


@pytest.mark.parametrize(("method", "expected"), [
    ("_v13_input_reader_source_projection", "5f66a4965c382ba9254f0c5fbb7fd797e592f3b818d52d904db2daacf69f47f5"),
    ("_v12_input_reader_source_projection", "7477a9735dd949cc894bf3a457c69638851615c64ca0f4c5723bf439f98b33bf"),
    ("_v11_input_reader_source_projection", "455aa51a397f025d4a6b0145c5a963d6455c0af51159b03535c69b506150d47b"),
])
def test_full_input_inverse_precedes_each_historical_projection(sdk973, method, expected):
    current = executing(inputs, NEW_INPUT)[1]
    previous = Path(sdk973[inputs.__name__]["path"]).read_bytes()
    project = getattr(fixed, method)
    assert project(current) == project(previous)
    assert digest(project(current)) == expected


def test_full_cohort_inverse_keeps_source62_science(sdk973):
    current = executing(cohort, NEW_COHORT)[1]
    previous = Path(sdk973[cohort.__name__]["path"]).read_bytes()
    assert fixed._v13_cohort_reader_source_projection(current) == fixed._v13_cohort_reader_source_projection(previous)
    assert digest(fixed._v13_cohort_reader_source_projection(current)) == "12eec36c6bcd6ab27790f8f6d77ca724d775f108d0bb08f41214b61310a092be"


def test_fixed_target_full_byte_inverse_preserves_all_scientific_units():
    current = executing(fixed, NEW_TARGET)[1]
    previous = current
    for new, old in reversed(TARGET_RESTORATION):
        assert previous.count(new) == 1
        previous = previous.replace(new, old, 1)
    assert digest(previous) == OLD_TARGET
    # Compare raw AST units independently of the stock memo-shape validator.
    # Both compatibility-only collections contain the reviewed reader adapters;
    # every other node, including scientific memo decorators, remains intact.
    excluded = set(fixed._LEGACY_READER_UNITS["target"]) | set(fixed._READER_COMPATIBILITY_HELPERS["target"])

    def scientific(raw):
        tree = ast.parse(raw)
        tree.body = [node for node in tree.body
                     if not isinstance(node, ast.FunctionDef) or node.name not in excluded]
        return ast.dump(tree, include_attributes=False)

    assert scientific(current) == scientific(previous)
    changed = current + b"\ndef unreviewed_admission_science():\n    return True\n"
    assert scientific(changed) != scientific(previous)


@pytest.mark.parametrize("name", list(FAMILY))
@pytest.mark.parametrize("mutation", ["bytes", "full-mode"])
def test_retained_family_refuses_refreshed_unknown_bytes_or_mode(sdk973, name, mutation):
    assert cohort._recognized_reader_sources(sdk973)
    path = Path(sdk973[name]["path"])
    if mutation == "bytes":
        path.write_bytes(path.read_bytes() + b"\n# unreviewed reader material\n")
    else:
        path.chmod(0o4644)
    changed = deepcopy(sdk973)
    changed[name] = inputs.reference(path)
    assert not cohort._recognized_reader_sources(changed)


@pytest.mark.parametrize("name", [inputs.__name__, cohort.__name__])
def test_historical_family_cannot_mix_current_roles(sdk973, name):
    assert cohort._recognized_reader_sources(sdk973)
    changed = deepcopy(sdk973)
    # Copy the genuine current role into the same historical package: this keeps
    # the location guard intact and tests the exact family join itself.
    path = Path(changed[name]["path"])
    path.write_bytes(Path(cohort.reader_sources()[name]["path"]).read_bytes())
    changed[name] = inputs.reference(path)
    assert not cohort._recognized_reader_sources(changed)


def test_exact_old_files_must_share_one_package_parent(sdk973, tmp_path):
    assert cohort._recognized_reader_sources(sdk973)
    changed = deepcopy(sdk973)
    old_path = Path(changed[whole.__name__]["path"])
    path = tmp_path / "other" / old_path.name
    path.parent.mkdir()
    path.write_bytes(old_path.read_bytes())
    path.chmod(0o644)
    changed[whole.__name__] = inputs.reference(path)
    assert changed[whole.__name__]["sha256"] == FAMILY[whole.__name__]
    assert not cohort._recognized_reader_sources(changed)


@pytest.mark.parametrize("mutation", ["bytes", "full-mode"])
def test_final_action_fence_reopens_authenticated_old_reader(sdk973, mutation):
    action = OperationFacts()
    action.begin_action()
    with action.scope():
        assert cohort._recognized_reader_sources(sdk973)
        path = Path(sdk973[inputs.__name__]["path"])
        if mutation == "bytes":
            path.write_bytes(path.read_bytes() + b"\n# after authenticated family read\n")
        else:
            path.chmod(0o4644)
        with pytest.raises(ValueError):
            action.check()


@pytest.mark.parametrize(("module", "sha", "method"), [
    (inputs, NEW_INPUT, "_v13_input_reader_source_projection"),
    (cohort, NEW_COHORT, "_v13_cohort_reader_source_projection"),
])
def test_inverse_refuses_unregistered_current_material(module, sha, method):
    raw = executing(module, sha)[1]
    with pytest.raises(ValueError):
        getattr(fixed, method)(raw + b"\n# unknown prospective source\n")


def test_optional_actual_sdk973_context_reader_metadata():
    value = os.environ.get("QCSD_SDK973_COHORT_PROVENANCE")
    if not value:
        pytest.skip("optional authentic closed-context reader metadata; no raw-run proof")
    path = Path(value)
    assert path.stat().st_mode & 0o7777 == 0o600
    raw = path.read_bytes()
    assert digest(raw) == "eebf59b6d51b923e0df78715494bafefc6bf363ddea451c1874e644746dc2d65"
    payload = receipts._unpack(raw, cohort.CONTEXT_TYPE)
    assert inputs.zero(payload)
    assert payload["contract"] == cohort.CONTRACT
    assert payload["data_role"] == whole.ROLE
    assert {name: ref["sha256"] for name, ref in payload["reader_sources"].items()} == FAMILY
    assert all(ref["mode"] == "0644" for ref in payload["reader_sources"].values())
    assert cohort._recognized_reader_sources(payload["reader_sources"])
