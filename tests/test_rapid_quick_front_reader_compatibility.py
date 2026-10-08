"""Complete finite Source restoration for old ordinary readers; no trace credit."""
import hashlib
from pathlib import Path

import pytest

from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab import rapid_front_quick_compatibility as compatibility
from qcsd_lab import rapid_front_quick_profile as front
from qcsd_lab import rapid_mixed_implementation_target as mixed
from qcsd_lab import rapid_parallel_partial_lane as partial
from qcsd_lab import rapid_quick_profile as quick
from qcsd_lab import rapid_capture_traffic as traffic


def _bytes(module):
    return Path(module.__file__).read_bytes()


@pytest.mark.parametrize("role,module,expected", [
    ("quick", quick, "35808d483b82a4da1cd9c22e4a9ef967986dd7ab4ede448f8cd98db9d0c3b25c"),
    ("mixed", mixed, "3b0a8faf8afeb95c8deb8a8feb560214d0fc02e4655b20781776834bd00ba365"),
])
def test_entire_predecessor_restored_and_unknown_science_cannot_hide(role, module, expected):
    restored = compatibility.restore(role, _bytes(module))
    assert hashlib.sha256(restored).hexdigest() == expected
    assert compatibility.restore(role, restored) == restored
    for raw in (_bytes(module) + b"\ndef additional_admission(): return True\n",
                restored + b"\ndef additional_admission(): return True\n"):
        with pytest.raises(ValueError):
            compatibility.restore(role, raw)


def test_current_dispatcher_and_helper_authentication_closes_bytes_and_full_modes(tmp_path, monkeypatch):
    assert fixed._mixed_epoch() is mixed
    assert compatibility.checked_dispatcher(fixed.reference(Path(quick.__file__)))
    with monkeypatch.context() as local:
        changed = tmp_path / "rapid_quick_profile.py"
        changed.write_bytes(_bytes(quick) + b"\n# changed dispatcher\n")
        changed.chmod(0o644)
        local.setattr(quick, "__file__", str(changed))
        with pytest.raises(ValueError):
            compatibility.checked_dispatcher(fixed.reference(changed))
    with monkeypatch.context() as local:
        changed = tmp_path / "rapid_front_quick_profile.py"
        changed.write_bytes(_bytes(front))
        changed.chmod(0o600)
        local.setattr(front, "__file__", str(changed))
        with pytest.raises(ValueError):
            compatibility.checked_dispatcher(fixed.reference(Path(quick.__file__)))


@pytest.mark.parametrize("change", ["mode", "bytes", "unknown-head"])
def test_historical_mixed_module_pair_preserves_old_sources_and_refuses_mutations(tmp_path, change):
    predecessor = tmp_path / "rapid_mixed_implementation_target.py"
    predecessor.write_bytes(compatibility.restore("mixed", _bytes(mixed)))
    predecessor.chmod(0o644)
    old = fixed.reference(predecessor)
    current = fixed.reference(Path(mixed.__file__))
    assert compatibility.compatible_mixed_module(old, current)
    sources = mixed._sources()
    sources["mixed"] = old
    assert mixed._source_files(sources)
    if change == "mode":
        predecessor.chmod(0o600)
    elif change == "bytes":
        predecessor.write_bytes(predecessor.read_bytes() + b"\ndef accept_other(): return True\n")
    else:
        predecessor.write_bytes(b"unknown historical module\n")
    sources["mixed"] = fixed.reference(predecessor)
    with pytest.raises(ValueError):
        mixed._source_files(sources)


def test_original_ordinary_traffic_reader_uses_only_exact_quick_restore(tmp_path, monkeypatch):
    digest = "4eb2d2ce5a35005f342befe9fb86dd6dad27980b2635e5372fda227902764542"
    old = tmp_path / "old-traffic.py"
    old.write_bytes(mixed.legacy_source_projection("traffic", _bytes(traffic), historical_sha256=digest))
    old.chmod(0o644)
    producer = fixed._sources()
    producer["traffic"] = fixed.reference(old)
    assert fixed._compatible_sources(producer)
    altered = tmp_path / "rapid_quick_profile.py"
    altered.write_bytes(_bytes(quick) + b"\ndef arbitrary_acceptance(): return True\n")
    altered.chmod(0o644)
    monkeypatch.setattr(quick, "__file__", str(altered))
    with pytest.raises(ValueError):
        fixed._compatible_sources(producer)


def test_front_partial_guard_set_is_complete_current_source_and_keeps_old_sets():
    from qcsd_lab import rapid_lane_evidence, rapid_rolling_capture, rapid_rolling_schedule, rapid_slot_chunks
    modules = (rapid_lane_evidence, quick, rapid_rolling_capture, rapid_rolling_schedule, rapid_slot_chunks)
    observed = {module.__name__.rsplit(".", 1)[-1]: hashlib.sha256(_bytes(module)).hexdigest()
                for module in modules}
    assert observed == partial._DIRECT_QUICK_FRONT_V3_GUARDS
    assert partial._DIRECT_QUICK_V1_GUARDS["rapid_quick_profile"] == "79a8c80fc8e701e2bd97fd7dd3ddd996dceb2c7145201d1844a0a2b15d11d99e"
    assert partial._DIRECT_QUICK_V2_GUARDS["rapid_quick_profile"] == "35808d483b82a4da1cd9c22e4a9ef967986dd7ab4ede448f8cd98db9d0c3b25c"


def test_launcher_adds_only_the_front_v3_classifier_to_the_original_retrying_launcher():
    root = Path(quick.__file__).resolve().parents[2]
    raw = (root / "qcsd-lab").read_bytes()
    addition = b'          "${rapid_scheduling_kind}" == "qcsd-prospective-direct-quick-fixed-front-launch-profile-v3" ||\n'
    assert raw.count(addition) == 1
    assert hashlib.sha256(raw.replace(addition, b"", 1)).hexdigest() == \
        "b11e4bd0897229fe9e02dad861ba0c774cc6586fbbd7eebfd8c41009a96d8e71"
    with pytest.raises(ValueError):
        compatibility.restore("unregistered-role", raw)

_FIXED_RESTORATION = [
    [
        "                       'aef299755e14c577e366fffa8df0f281f5f10bdef0937abb6fea52e51dd4ae90',\n                       '80783154a4c0097fa8729b69c3ea5dd6ca8f617dd655ce286c7e929874ba8f45',\n                       'e57126d7a6e179a82f6f997dd8935a543fbf3378718466ad0eb5033b4811890a',\n                       '13b8610c344176087bc8c85a29d8912c8aed14320999130e2f0a28e394c6bb86'})\n    epoch_dynamic = (role == 'dynamic' and producer['sha256'] in {\n        '17d9b19159a521e7c18cea732ba8ed44dff6044a18442807a716e793586cb3a3',\n        'e5c49b345c0e5acb1af442dbaae7d2caabfcdcf09892239d5ebb78f5d03a318a',\n",
        "                       'aef299755e14c577e366fffa8df0f281f5f10bdef0937abb6fea52e51dd4ae90',\n                       '80783154a4c0097fa8729b69c3ea5dd6ca8f617dd655ce286c7e929874ba8f45',\n                       'e57126d7a6e179a82f6f997dd8935a543fbf3378718466ad0eb5033b4811890a',\n                       '13b8610c344176087bc8c85a29d8912c8aed14320999130e2f0a28e394c6bb86',\n                       'f661fbfb19641d6aa19586d2a587475878d080734f33602a0a02df461615ac53'})\n    epoch_dynamic = (role == 'dynamic' and producer['sha256'] in {\n        '17d9b19159a521e7c18cea732ba8ed44dff6044a18442807a716e793586cb3a3',\n        'e5c49b345c0e5acb1af442dbaae7d2caabfcdcf09892239d5ebb78f5d03a318a',\n"
    ],
    [
        "\ndef _mixed_epoch():\n    from . import rapid_mixed_implementation_target as mixed\n    declared = reference(Path(mixed.__file__))\n    if (declared['sha256'] != '3b0a8faf8afeb95c8deb8a8feb560214d0fc02e4655b20781776834bd00ba365'\n            or declared['mode'] != 0o644):\n        raise ValueError('mixed target reader differs from its exact reviewed module')\n    return mixed\n",
        "\ndef _mixed_epoch():\n    from . import rapid_mixed_implementation_target as mixed\n    from . import rapid_front_quick_compatibility as quick_front\n    declared = reference(Path(mixed.__file__))\n    compatibility = reference(Path(quick_front.__file__))\n    _open(compatibility)\n    if (Path(quick_front.__file__) != Path(__file__).with_name('rapid_front_quick_compatibility.py')\n            or compatibility['sha256'] != '12693bb5ccf8903c75fdb4d2ba318628d1da2e18ab743cad77012dde88fe6580'\n            or type(compatibility['mode']) is not int or compatibility['mode'] != 0o644\n            or declared['sha256'] != 'fcb97be28badbe1379c7a1ae30030fcefa57143b947765065fd64688084e3a7c'\n            or declared['mode'] != 0o644):\n        raise ValueError('mixed target reader differs from its exact reviewed module')\n    return mixed\n"
    ],
    [
        "                # Pin its complete Source so a new receipt type cannot alias an\n                # old one while the historical projection is in use.\n                from . import rapid_quick_profile as quick\n                quick_ref = reference(Path(quick.__file__))\n                _open(quick_ref)\n                if (quick_ref['sha256'] != '35808d483b82a4da1cd9c22e4a9ef967986dd7ab4ede448f8cd98db9d0c3b25c'\n                        or quick_ref['mode'] != 0o644):\n                    raise ValueError('fixed target quick dispatcher Source or full mode changed')\n        elif any(producer[name][key] != expected[key] for key in ('sha256', 'mode')):\n            raise ValueError('fixed target relevant producer/reader code bytes or modes differ')\n    return True\n",
        "                # Pin its complete Source so a new receipt type cannot alias an\n                # old one while the historical projection is in use.\n                from . import rapid_quick_profile as quick\n                from . import rapid_front_quick_compatibility as quick_front\n                quick_ref = reference(Path(quick.__file__))\n                _open(quick_ref)\n                _mixed_epoch()\n                quick_front.checked_dispatcher(quick_ref)\n        elif any(producer[name][key] != expected[key] for key in ('sha256', 'mode')):\n            raise ValueError('fixed target relevant producer/reader code bytes or modes differ')\n    return True\n"
    ]
]


def _original_fixed(raw):
    # This test owns its literal inverse independently of production projections.
    for before, after in _FIXED_RESTORATION:
        before, after = before.encode(), after.encode()
        assert raw.count(after) == 1
        raw = raw.replace(after, before, 1)
    return raw


def test_fixed_target_retains_every_original_scientific_unit_and_full_predecessor():
    import ast
    current = _bytes(fixed)
    original = _original_fixed(current)
    assert hashlib.sha256(original).hexdigest() == "529e4b7506b8889c01b3399e932502892cdfc634f39eb1c514b01259e0b7cf7c"
    excluded = set(fixed._LEGACY_READER_UNITS["target"]) | set(fixed._READER_COMPATIBILITY_HELPERS["target"])
    def science(raw):
        tree = ast.parse(raw)
        tree.body = [node for node in tree.body if not
            (isinstance(node, ast.FunctionDef) and node.name in excluded)]
        return ast.dump(tree, include_attributes=False)
    assert science(current) == science(original)
    changed = current + b"\ndef additional_admission_science(): return True\n"
    assert science(changed) != science(original)
    assert hashlib.sha256(_original_fixed(changed)).hexdigest() != hashlib.sha256(original).hexdigest()
