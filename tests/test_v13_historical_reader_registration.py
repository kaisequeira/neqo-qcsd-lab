"""Finite Source63/Source64 registration projects exact old scientific bytes.

Local reader-byte controls confer no admission/capture credit and execute no
historical producer, Git, browser, Native client or network operation.
"""
import hashlib
import os
from pathlib import Path

import pytest

from qcsd_lab import whole_graph_input as inputs
from qcsd_lab import whole_graph_supplement as supplement
from qcsd_lab import rapid_supplemental_cohort as cohort
from qcsd_lab import rapid_per_class_selected_enrollment as enrollment
from qcsd_lab import rapid_fixed_condition_target as target


OLD_INPUT = '5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa'
OLD_SUPPLEMENT = '293365724af2b6cd13d8be4060e7d3bc8c9e65533d37c59a7e41ee021178704b'
OLD_COHORT = '39383c717f267bcb27c5d5a7585cbef3a9138f7845ccedf04033014519b2a029'
PAIR = (b"            ('5681d5124c8d36e5f3e415373ea2cb73f60efd374494de851ccbbd959b60d6aa',\n"
        b"             '293365724af2b6cd13d8be4060e7d3bc8c9e65533d37c59a7e41ee021178704b'),\n")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def source63_bytes():
    old_input = Path(inputs.__file__).read_bytes().replace(
        b'236ab7ee22009bbb9ecd0a519c322307243847fb6be8ada7ad6692cd84e4dcf8',
        b'd12b4278665f5b26a5c927e572254b7dcd8bbd4294811ba57a56c91b05e28ac1', 1)
    old_supplement = Path(supplement.__file__).read_bytes().replace(PAIR, b'', 1)
    raw = Path(cohort.__file__).read_bytes()
    start = raw.index(b'def _recognized_reader_sources('); end = raw.index(b'def is_context(', start)
    original = b'''def _recognized_reader_sources(value: dict) -> bool:
    """Reopen the one retained Source62 cohort reader family without new credit."""
    current = reader_sources()
    if value == current:
        return True
    retained = {
        "qcsd_lab.whole_graph_input": "5f66a4965c382ba9254f0c5fbb7fd797e592f3b818d52d904db2daacf69f47f5",
        "qcsd_lab.whole_graph_supplement": "164ab24211a5fa535ee838b9b50862c1c3f5b64fd240c755d8ba4fae6a1869b7",
        "qcsd_lab.rapid_per_class_selected_enrollment": "4f7f3a6fd67f077165496b92d62e9b81f1e0168d01ad3f11607b144a6124bee0",
        "qcsd_lab.rapid_supplemental_cohort": "12eec36c6bcd6ab27790f8f6d77ca724d775f108d0bb08f41214b61310a092be",
    }
    if not isinstance(value, dict) or set(value) != set(retained):
        return False
    paths = {}
    for name, digest in retained.items():
        ref = value[name]
        paths[name] = inputs.reopen(ref)
        if (ref["sha256"] != digest or ref["mode"] != "0644"
                or paths[name].name != name.rsplit(".", 1)[1] + ".py"):
            return False
    if len({path.parent for path in paths.values()}) != 1:
        return False
    from . import rapid_fixed_condition_target as fixed
    for name, path in paths.items():
        fixed._compatible_acquisition_code("src/qcsd_lab/" + path.name,
                                          fixed.reference(path),
                                          fixed.reference(inputs.reopen(current[name])))
    return True


'''
    old_cohort = raw[:start] + original + raw[end:]
    assert tuple(map(digest, (old_input, old_supplement, old_cohort))) == (OLD_INPUT, OLD_SUPPLEMENT, OLD_COHORT)
    return {'whole_graph_input.py': old_input, 'whole_graph_supplement.py': old_supplement,
            'rapid_supplemental_cohort.py': old_cohort}


def test_current_and_old_source63_projections_restore_identical_exact_source62_bytes():
    old = source63_bytes()
    rows = (
        (inputs, target._v13_input_reader_source_projection,
         '5f66a4965c382ba9254f0c5fbb7fd797e592f3b818d52d904db2daacf69f47f5'),
        (supplement, target._v13_supplement_reader_source_projection,
         '164ab24211a5fa535ee838b9b50862c1c3f5b64fd240c755d8ba4fae6a1869b7'),
        (cohort, target._v13_cohort_reader_source_projection,
         '12eec36c6bcd6ab27790f8f6d77ca724d775f108d0bb08f41214b61310a092be'),
    )
    for module, project, expected in rows:
        current = Path(module.__file__).read_bytes()
        assert project(current) == project(old[Path(module.__file__).name])
        assert digest(project(current)) == expected
        with pytest.raises(ValueError): project(current + b'\n# unreviewed byte mutation\n')


def test_source63_reader_alias_is_exact_and_full_modes_remain_bound(tmp_path):
    old = source63_bytes(); current = target._acquisition_reader_sources()
    for name, raw in old.items():
        path = tmp_path / name; path.write_bytes(raw); path.chmod(0o644)
        before = target.reference(path); after = current['src/qcsd_lab/' + name]
        assert target._compatible_acquisition_code('src/qcsd_lab/' + name, before, after)
        path.chmod(0o600)
        with pytest.raises(ValueError):
            target._compatible_acquisition_code('src/qcsd_lab/' + name, target.reference(path), after)


def test_current_and_source63_cohort_dispatch_restore_identical_historical_units():
    relative = 'src/qcsd_lab/whole_graph_supplement.py'
    current = Path(supplement.__file__).read_bytes()
    original = source63_bytes()['whole_graph_supplement.py']
    assert target._cohort_acquisition_source_projection(current, relative) == (
        target._cohort_acquisition_source_projection(original, relative))
    with pytest.raises(ValueError):
        target._cohort_acquisition_source_projection(
            current + b'\n# unreviewed byte mutation\n', relative)


def test_source63_cohort_family_is_complete_and_mixed_family_is_refused(tmp_path):
    old = source63_bytes(); old['rapid_per_class_selected_enrollment.py'] = Path(enrollment.__file__).read_bytes()
    refs = {}
    for name, raw in old.items():
        path = tmp_path / name; path.write_bytes(raw); path.chmod(0o644)
        refs['qcsd_lab.' + path.stem] = inputs.reference(path)
    assert cohort._recognized_reader_sources(refs)
    mixed = {**refs, 'qcsd_lab.whole_graph_input': inputs.reference(Path(inputs.__file__))}
    assert cohort._recognized_reader_sources(mixed) is False


def test_source63_get_pair_accepts_only_the_registered_complete_pair():
    current = supplement.producer_sources()
    old = {**current, 'qcsd_lab.whole_graph_input': OLD_INPUT,
           'qcsd_lab.whole_graph_supplement': OLD_SUPPLEMENT}
    assert supplement._recognized_producer_sources(old)
    for key in ('qcsd_lab.whole_graph_input', 'qcsd_lab.whole_graph_supplement'):
        assert supplement._recognized_producer_sources({**old, key: current[key]}) is False
    assert supplement._recognized_producer_sources({**old, 'qcsd_lab.whole_graph_input': '0' * 64}) is False


def test_genuine_source63_target_preserves_scientific_units_and_full_modes(tmp_path):
    supplied = os.environ.get('QCSD_SOURCE63_TARGET_PATH')
    if not supplied:
        pytest.skip('genuine frozen Source63 target path was not supplied')
    before = target.reference(Path(supplied))
    assert before['sha256'] == 'e57126d7a6e179a82f6f997dd8935a543fbf3378718466ad0eb5033b4811890a'
    current_path = Path(target.__file__)
    assert target._compatible_code_ref('target', before, target.reference(current_path))
    changed = tmp_path / 'target.py'
    raw = current_path.read_bytes()
    declared = b'CLASSES, SLOTS, TOTAL = 50, 64, 16000'
    assert raw.count(declared) == 1
    changed.write_bytes(raw.replace(declared, b'CLASSES, SLOTS, TOTAL = 50, 63, 16000', 1))
    changed.chmod(0o644)
    with pytest.raises(ValueError):
        target._compatible_code_ref('target', before, target.reference(changed))
    changed.write_bytes(raw)
    changed.chmod(0o600)
    with pytest.raises(ValueError):
        target._compatible_code_ref('target', before, target.reference(changed))
