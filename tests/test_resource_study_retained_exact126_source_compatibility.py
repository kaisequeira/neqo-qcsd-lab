"""Exact retained-core Source compatibility; no capture, Raw or credit.

The two historical profiles are genuine frozen full178 Source DTOs. Temporary
files below are explicit guard fixtures. The historical-asset effect stops
before qualification/ready evidence; neither fixture constitutes an enrollment.
"""
from copy import deepcopy
import hashlib
import json
from types import ModuleType

import pytest

from qcsd_lab import resource_study as study
from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_native as native
from qcsd_lab import resource_study_reader_compatibility as reader


EXACT126_CORE_SOURCE_CONTRACT = {'files': {'capture.py': 'c37a0444c62e77068891281fa72200bdc2c07192ee8e4e05a9832bfe1a681c99',
           'fidelity.py': '460c7ee9540eb17d22eac54f73f5462c06a674110d72ede707555b11792847a8',
           'kernel_tx.py': '5f05c57af4dbf3ec37ef6fd9dcf43984b2d48e477a4e8ca435556ce4e2612125',
           'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf',
           'resource_study_inputs.py': '899b78d50063eea6c30140397b2342d900701d44aed8f1bfe9afb30abe9ffd2b',
           'resource_study_lineage.py': 'b2e13cc9134c94e0882acbb615fc7b5ebb349cd459c3deeefeafa83b173c05aa',
           'resource_study_native.py': 'b9f2694f20d2582c57f62b70483b2242d188778fffee0560fd9d937704191cca',
           'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20',
           'resource_study_selection.py': '673a19748010c951f8e604d9b16c5ddc633a26b116499e07fdd63ec8617240e4',
           'resource_study_verify.py': 'a9a609130d6d0ecb26e4e866abbaad0ba26367acf869a9ba1ec2a0817b18deee'},
 'implementation': 'resource-study-raw-v1',
 'record_type': 'qcsd-resource-domain-runtime-cohort-verifier-contract-v1',
 'schema_version': 1,
 'transitive_source_files': 178,
 'transitive_source_scope': 'complete declared package-import closure; conservative dormant branches '
                            'included',
 'transitive_source_sha256': '481948769f83a7e2f5a4eead30269f8970d608c33b25664df2fa05b37ca996cf'}
EXACT127_EXECUTION_CONTRACT = {'files': {'capture.py': 'c37a0444c62e77068891281fa72200bdc2c07192ee8e4e05a9832bfe1a681c99',
           'fidelity.py': '460c7ee9540eb17d22eac54f73f5462c06a674110d72ede707555b11792847a8',
           'kernel_tx.py': '5f05c57af4dbf3ec37ef6fd9dcf43984b2d48e477a4e8ca435556ce4e2612125',
           'process_scheduler.py': '8171b841d4aa26d63c9de740f79641bd4071ad1c9587dfc0d7068d5dac4328bf',
           'resource_study_inputs.py': '899b78d50063eea6c30140397b2342d900701d44aed8f1bfe9afb30abe9ffd2b',
           'resource_study_lineage.py': 'b2e13cc9134c94e0882acbb615fc7b5ebb349cd459c3deeefeafa83b173c05aa',
           'resource_study_native.py': 'b9f2694f20d2582c57f62b70483b2242d188778fffee0560fd9d937704191cca',
           'resource_study_network.py': 'd1be85c769642739238ffc1823d41ed28353e3d9c38a1e84b54f8973bd614c20',
           'resource_study_selection.py': '673a19748010c951f8e604d9b16c5ddc633a26b116499e07fdd63ec8617240e4',
           'resource_study_verify.py': 'a9a609130d6d0ecb26e4e866abbaad0ba26367acf869a9ba1ec2a0817b18deee'},
 'implementation': 'resource-study-raw-v1',
 'record_type': 'qcsd-resource-domain-runtime-cohort-verifier-contract-v1',
 'schema_version': 1,
 'transitive_source_files': 178,
 'transitive_source_scope': 'complete declared package-import closure; conservative dormant branches '
                            'included',
 'transitive_source_sha256': '45c8a75be4a88cadc05f53af55ac4a6c201aed573752501422e14e2a9ce0b661'}
ACTUAL144_RUNTIME_IDENTITY_DATA = {'canonical_sha256': '769852911e8dd78386d11ac72cf2fac93ccfdf179c9d64470be527131fe0c902',
 'client_sha256': 'f25f450f6130aba2c357a7a24dab185ea5fed797fee12a1e86fc357544169b7c',
 'collection_image_digest': 'sha256:f2eddcaebe3a21db32755f9ec957ed3dc73ac7ee08c7ecb90e2c35c0bc7fb5a3',
 'native_commit': '42118eabf7b4a78328b655d9bccbae286c481a7c',
 'platform': 'linux/arm64',
 'prepare_image_digest': 'sha256:5068be72a0d8226c056c83c882494a1c97ea8b00f153e3c6cffb237c03b2a71e',
 'source': {'image_digest': None,
            'lab_commit': '24ab3344bc25302f1f1909eedd4ef0a90168ccde',
            'lab_dirty': False,
            'lab_patch_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'neqo_commit': '42118eabf7b4a78328b655d9bccbae286c481a7c',
            'neqo_dirty': False,
            'neqo_patch_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'neqo_pinned_commit': '42118eabf7b4a78328b655d9bccbae286c481a7c'}}
ORIGINAL127_ASSETS_SOURCE = 'def retained_mode_assets(root, enrollment, *, provisional=False):\n    """Pure current launch binding; final raw readiness is replayed at admission."""\n    binding = enrollment.get(RETAINED_MODE_KEY)\n    if (type(binding) is not dict or set(binding) != {\'record_type\', \'study_root\', \'preparation_dir\', \'core_sha256\', \'readiness_sha256\'}\n            or binding[\'record_type\'] != RETAINED_MODE_BINDING):\n        raise ValueError(\'retained-mode preparation binding is incomplete\')\n    study = Path(binding[\'study_root\']); relative = _retained_relative(binding[\'preparation_dir\'])\n    base = study / relative; root = Path(root).absolute()\n    if root not in (study, base):\n        raise ValueError(\'retained-mode enrollment has a foreign root\')\n    core = json.loads(retained_mode_read(base / \'core.json\', binding[\'core_sha256\']))\n    if (type(core) is not dict or set(core) != {\'record_type\', \'schema_version\', \'input\', \'input_sha256\', \'historical_enrollment_path\', \'assets\', \'historical_binding\'}\n            or core[\'record_type\'] != RETAINED_MODE_CORE or type(core[\'schema_version\']) is not int or core[\'schema_version\'] != 1\n            or core[\'input\'][\'root\'] != str(study)\n            or core[\'input\'][\'runtime\'] != _retained_runtime(enrollment.get(\'runtime\'))\n            or core[\'input\'][\'mode\'] != \'buflo\' or core[\'input\'][\'hostname\'] != enrollment.get(\'hostname\')\n            or hashlib.sha256(retained_mode_read(base / \'input.json\')).hexdigest() != core[\'input_sha256\']\n            or json.loads(retained_mode_read(base / \'input.json\')) != core[\'input\']):\n        raise ValueError(\'retained-mode core/input/current runtime changed\')\n    _, canonical_sha = _retained_ref(core[\'input\'][\'canonical_runtime\'])\n    if canonical_sha != enrollment[\'runtime\'][\'canonical_sha256\']:\n        raise ValueError(\'retained canonical reference differs from exact current runtime SHA\')\n    canonical = json.loads(retained_mode_read(base / \'canonical-runtime.json\', canonical_sha))\n    if (type(canonical) is not dict\n            or canonical.get(\'installed_client_sha256\') != enrollment[\'runtime\'][\'client_sha256\']\n            or canonical.get(\'platform\') != enrollment[\'runtime\'][\'platform\']\n            or canonical.get(\'collection_image_digest\') != enrollment[\'runtime\'][\'collection_image_digest\']\n            or canonical.get(\'prepare_image_digest\') != enrollment[\'runtime\'][\'prepare_image_digest\']\n            or canonical.get(\'source\') != enrollment[\'runtime\'][\'source\']):\n        raise ValueError(\'retained canonical bytes differ from exact current runtime fields\')\n    from .resource_study_cohorts import verifier_contract\n    if core[\'input\'][\'source_contract\'] != verifier_contract():\n        raise ValueError(\'retained-mode current Source contract changed\')\n    old_path = base / _retained_relative(core[\'historical_enrollment_path\'])\n    old = json.loads(retained_mode_read(old_path, core[\'input\'][\'historical_enrollment\'][\'sha256\']))\n    assets = core[\'assets\']\n    if type(assets) is not dict or not assets:\n        raise ValueError(\'retained-mode core lacks its frozen historical assets\')\n    for old_relative, row in assets.items():\n        _retained_relative(old_relative)\n        if type(row) is not dict or set(row) != {\'path\', \'sha256\'} or old[\'files\'].get(old_relative) != row[\'sha256\']:\n            raise ValueError(\'retained historical asset has foreign provenance\')\n        retained_mode_read(base / _retained_relative(row[\'path\']), row[\'sha256\'])\n    # Replay historical validators in their copied original relative namespace.\n    historical_root = base / \'historical\'\n    history = _retained_old_assets(historical_root, old, core[\'input\'][\'science\'])\n    if history[\'historical_binding\'] != core[\'historical_binding\']:\n        raise ValueError(\'retained historical parameter profile changed\')\n    prefix = \'\' if root == base else relative + \'/\'\n    expected_paths = {key: prefix + \'historical/\' + value if value is not None else None\n                      for key, value in old[\'paths\'].items()}\n    science = core[\'input\'][\'science\']\n    if (enrollment.get(\'paths\') != expected_paths or enrollment.get(\'urls\') != science[\'urls\']\n            or enrollment.get(\'workload_sha256\') != science[\'workload_sha256\']\n            or enrollment.get(\'workload_path\') != expected_paths[\'manifest\']\n            or enrollment.get(\'mode_settings\', {}).get(\'buflo\') != science[\'settings\']\n            or enrollment.get(\'mode_policies\', {}).get(\'buflo\') != science[\'policies\']\n            or enrollment.get(\'mode_readiness\') != {mode: mode == \'buflo\' and not provisional for mode in MODES}\n            or \'buflo_chaff_selection\' in enrollment or \'buflo_small_response_aggregate_selection\' in enrollment\n            or enrollment.get(\'scientific_credit\') is not False):\n        raise ValueError(\'retained current enrollment changes frozen selected-mode parameters\')\n    expected_files = {prefix + row[\'path\']: row[\'sha256\'] for row in assets.values()}\n    expected_files.update({prefix + \'core.json\': binding[\'core_sha256\'],\n        prefix + \'input.json\': core[\'input_sha256\'],\n        prefix + \'canonical-runtime.json\': canonical_sha,\n        prefix + core[\'historical_enrollment_path\']: core[\'input\'][\'historical_enrollment\'][\'sha256\']})\n    for name, digest in expected_files.items():\n        if enrollment.get(\'files\', {}).get(name) != digest:\n            raise ValueError(\'retained current enrollment omits an exact asset/core digest\')\n    if provisional:\n        if binding[\'readiness_sha256\'] is not None:\n            raise ValueError(\'pre-readiness enrollment cannot claim a later readiness result\')\n    else:\n        if type(binding[\'readiness_sha256\']) is not str or _SHA256.fullmatch(binding[\'readiness_sha256\']) is None:\n            raise ValueError(\'final retained enrollment lacks positive fresh readiness\')\n        result = json.loads(retained_mode_read(base / \'readiness-result.json\', binding[\'readiness_sha256\']))\n        if (set(result) != {\'record_type\', \'schema_version\', \'core_sha256\', \'runtime\', \'receipt\', \'flight\', \'scientific_credit\'}\n                or result[\'record_type\'] != RETAINED_MODE_RESULT or type(result[\'schema_version\']) is not int or result[\'schema_version\'] != 1\n                or result[\'core_sha256\'] != binding[\'core_sha256\'] or result[\'runtime\'] != enrollment[\'runtime\']\n                or result[\'scientific_credit\'] is not False\n                or enrollment[\'files\'].get(prefix + \'readiness-result.json\') != binding[\'readiness_sha256\']):\n            raise ValueError(\'final retained readiness result is foreign or mutable\')\n        for item in [result[\'receipt\'], *result[\'flight\'].values()]:\n            path, digest = _retained_ref(item)\n            if not path.is_relative_to(study):\n                raise ValueError(\'readiness evidence escaped its owning study\')\n            retained_mode_read(path, digest)\n    return {\'binding\': binding, \'base\': base, \'study_root\': study, \'core\': core,\n            \'historical\': old, \'chaff_key\': history[\'chaff_key\'],\n            \'historical_binding\': history[\'historical_binding\']}'


def _bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def _put(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o444)
    return hashlib.sha256(raw).hexdigest()


def _guard_fixture(tmp_path):
    """Real immutable file guards plus a labelled historical-validator effect."""
    root = tmp_path / "study"
    base = root / "retained-mode-preparations/example.test/fixture"
    runtime = deepcopy(ACTUAL144_RUNTIME_IDENTITY_DATA)
    canonical = {"installed_client_sha256": runtime["client_sha256"], "platform": runtime["platform"],
        "collection_image_digest": runtime["collection_image_digest"],
        "prepare_image_digest": runtime["prepare_image_digest"], "source": runtime["source"]}
    # This synthetic canonical is never claimed to be installed or admitted.
    canonical_sha = _put(base / "canonical-runtime.json", _bytes(canonical))
    runtime["canonical_sha256"] = canonical_sha
    anchor = b"explicit historical-validator boundary fixture\n"
    anchor_sha = _put(base / "historical/fixture.asset", anchor)
    historical = {"files": {"fixture.asset": anchor_sha}}
    historical_sha = _put(base / "historical-enrollment.json", _bytes(historical))
    inputs = {"root": str(root), "runtime": runtime, "mode": "buflo", "hostname": "example.test",
        "canonical_runtime": {"path": str(base / "canonical-runtime.json"), "sha256": canonical_sha},
        "historical_enrollment": {"path": str(base / "historical-enrollment.json"), "sha256": historical_sha},
        "science": {}, "source_contract": deepcopy(EXACT126_CORE_SOURCE_CONTRACT)}
    input_sha = _put(base / "input.json", _bytes(inputs))
    core = {"record_type": native.RETAINED_MODE_CORE, "schema_version": 1, "input": inputs,
        "input_sha256": input_sha, "historical_enrollment_path": "historical-enrollment.json",
        "assets": {"fixture.asset": {"path": "historical/fixture.asset", "sha256": anchor_sha}},
        "historical_binding": {"explicit_fixture": True}}
    core_sha = _put(base / "core.json", _bytes(core))
    enrollment = {"runtime": runtime, "hostname": "example.test", "retained_parameter_preparation": {
        "record_type": native.RETAINED_MODE_BINDING, "study_root": str(root),
        "preparation_dir": "retained-mode-preparations/example.test/fixture",
        "core_sha256": core_sha, "readiness_sha256": "a" * 64}}
    return root, enrollment


class HistoricalAssetBoundaryReached(Exception):
    pass


def test_original127_assets_reject_exact126_but_new_shared_guard_reaches_both_paths(tmp_path, monkeypatch):
    root, enrollment = _guard_fixture(tmp_path)
    calls = []
    def historical_boundary(*args):
        calls.append(args)
        raise HistoricalAssetBoundaryReached
    monkeypatch.setattr(native, "_retained_old_assets", historical_boundary)
    # Execute the whole exact original127 assets function with the same current
    # Source environment. Its original equality is the causal failure.
    old = ModuleType("_exact_original127_retained_assets_fixture")
    old.__dict__.update(native.__dict__)
    exec(compile(ORIGINAL127_ASSETS_SOURCE, "<exact-original127-retained-mode-assets>", "exec"), old.__dict__)
    with pytest.raises(ValueError, match="retained-mode current Source contract changed"):
        old.retained_mode_assets(root, enrollment)
    assert calls == []
    with pytest.raises(HistoricalAssetBoundaryReached):
        native.retained_mode_assets(root, enrollment)
    assert len(calls) == 1
    # The original seal entry uses exactly this shared guard before any capture
    # publication, raw verification, clock or network effect.
    with pytest.raises(HistoricalAssetBoundaryReached):
        study.seal_retained_mode(root, {"purpose": "formal"}, enrollment,
            enrollment["runtime"], {})
    assert len(calls) == 2
    assert not (root / "corpus").exists()


def test_exact126_core_keeps_qualifier_and_uses_current128_execution():
    actual = cohorts.verifier_contract()
    qualified = reader.qualify_execution(actual)
    assert reader.EXECUTION_KIND == "128"
    assert actual["transitive_source_files"] == 178
    assert reader.prior_exact126_execution_contract() == EXACT126_CORE_SOURCE_CONTRACT
    assert reader.prior_exact127_execution_contract() == EXACT127_EXECUTION_CONTRACT
    assert reader.require_supported(EXACT126_CORE_SOURCE_CONTRACT, qualified) is True
    assert reader.require_supported(EXACT127_EXECUTION_CONTRACT, qualified) is True
    binding = native.retained_mode_source_binding(deepcopy(EXACT126_CORE_SOURCE_CONTRACT))
    assert binding == reader.execution_binding(EXACT126_CORE_SOURCE_CONTRACT, qualified)
    assert binding["admission_reader"] == EXACT126_CORE_SOURCE_CONTRACT
    assert binding["execution_reader"] == actual
    assert binding["execution_reader_is_admission_reader"] is False
    assert binding["historical_receipts_requalified_by_compatibility"] is False
    assert binding["authority_issued"] is False and binding["scientific_credit_added"] == 0
    binding["admission_reader"]["files"]["resource_study_native.py"] = "0" * 64
    assert reader.prior_exact126_execution_contract() == EXACT126_CORE_SOURCE_CONTRACT


def test_current_core_still_requires_exact_current_qualified_reader():
    actual = cohorts.verifier_contract()
    binding = native.retained_mode_source_binding(actual)
    assert binding["admission_reader"] == binding["execution_reader"] == actual
    assert binding["execution_reader_is_admission_reader"] is True
    for historical in (EXACT126_CORE_SOURCE_CONTRACT, EXACT127_EXECUTION_CONTRACT):
        with pytest.raises(ValueError):
            reader.qualify_execution(historical)


@pytest.mark.parametrize("kind", ["primary", "transitive", "count", "schema-bool", "extra", "foreign125", "foreign127"])
def test_no_other_or_mutated_core_Source_contract_is_a_capability(kind):
    value = deepcopy(EXACT126_CORE_SOURCE_CONTRACT)
    if kind == "primary": value["files"]["resource_study_native.py"] = "0" * 64
    elif kind == "transitive": value["transitive_source_sha256"] = "0" * 64
    elif kind == "count": value["transitive_source_files"] = 177
    elif kind == "schema-bool": value["schema_version"] = True
    elif kind == "extra": value["future_authority"] = True
    elif kind == "foreign125": value = reader.prior_exact125_execution_contract()
    else: value = deepcopy(EXACT127_EXECUTION_CONTRACT)
    # Even a generally supported historical reader is not a retained-core grant.
    with pytest.raises(ValueError):
        native.retained_mode_source_binding(value)


def test_changed_current_execution_cannot_qualify_the_retained_core(monkeypatch):
    value = deepcopy(cohorts.verifier_contract())
    value["files"]["resource_study_native.py"] = "0" * 64
    monkeypatch.setattr(cohorts, "verifier_contract", lambda: value)
    with pytest.raises(ValueError):
        native.retained_mode_source_binding(EXACT126_CORE_SOURCE_CONTRACT)
