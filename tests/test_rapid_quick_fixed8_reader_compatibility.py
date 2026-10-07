"""The older fixed8 reader remains bound to exact quick-dispatch-only Source changes."""

import hashlib
from pathlib import Path

import pytest

from qcsd_lab import rapid_fixed_condition_target as fixed
from qcsd_lab import rapid_operation_facts as facts
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import rapid_rolling_schedule as scheduling
from qcsd_lab import rapid_capture_traffic as traffic
from qcsd_lab import rapid_quick_profile as quick


def _source(module):
    return Path(module.__file__).read_bytes()


def test_quick_dispatch_preserves_legacy_rolling_and_facts_projections():
    assert hashlib.sha256(_source(rolling)).hexdigest() == 'b9f316d212cf024e3d09ab4fa1a61035233f68f50f8a7c03c7450495cf81d2b0'
    assert hashlib.sha256(_source(facts)).hexdigest() == 'b71aeb8ea29056d13c1153ea16cd3d1445d8ca355c7e4e1928df5dfa560449f8'
    # Both projections require reconstructing the entire exact predecessor
    # before their older, narrow AST projection can admit a historical reader.
    assert fixed._epoch_dispatch_source_projection(_source(rolling))
    assert fixed._parallel_facts_source_projection(_source(facts))


@pytest.mark.parametrize('module,projection,change', [
    (rolling, fixed._epoch_dispatch_source_projection,
     (b'    sites, payload = verify_capture_plan(spec, require_current=True, _context=_context)\n',
      b'    sites, payload = verify_capture_plan(spec, require_current=False, _context=_context)\n')),
    (facts, fixed._parallel_facts_source_projection,
     (b'        self._reference(reference)\n', b'        self._reference(reference, optional=True)\n')),
])
def test_other_reader_change_cannot_hide_behind_quick_dispatch(module, projection, change):
    original, changed = change
    raw = _source(module)
    assert original in raw
    with pytest.raises(ValueError):
        projection(raw.replace(original, changed, 1))


def test_quick_scheduling_dispatch_keeps_old_reader_projection_and_rejects_other_changes():
    raw = _source(scheduling)
    assert hashlib.sha256(raw).hexdigest() == '3563882347e3ddb2df93846538bc8f95c833b158b62435964f35586046d03f5b'
    assert fixed._parallel_schedule_source_projection(raw)
    protected = b'epoch_workers.CAPSULE_TYPE'
    assert protected in raw
    with pytest.raises(ValueError, match='outside the exact old/new Source pair'):
        fixed._parallel_schedule_source_projection(raw.replace(protected, b'epoch_workers.CAPSULE_KIND', 1))


def test_legacy_traffic_reader_accepted_only_for_exact_addition_and_full_mode(tmp_path, monkeypatch):
    current = _source(traffic)
    addition = (
        b'        from . import rapid_quick_profile as quick\n'
        b'        if quick.is_payload(payload):\n'
        b'            quick.validate_profile(payload["scheduling"])\n'
        b'            return value\n'
    )
    assert current.count(addition) == 1
    old = current.replace(addition, b'', 1)
    assert hashlib.sha256(old).hexdigest() == '4eb2d2ce5a35005f342befe9fb86dd6dad27980b2635e5372fda227902764542'
    path = tmp_path / 'old-traffic.py'
    path.write_bytes(old)
    path.chmod(0o644)
    producer = fixed._sources()
    producer['traffic'] = fixed.reference(path)
    assert fixed._compatible_sources(producer)
    path.chmod(0o600)
    producer['traffic'] = fixed.reference(path)
    with pytest.raises(ValueError, match='full modes'):
        fixed._compatible_sources(producer)
    path.chmod(0o644)
    path.write_bytes(old.replace(b'BuFLO200', b'BuFLO201', 1))
    producer['traffic'] = fixed.reference(path)
    with pytest.raises(ValueError, match='exact quick dispatch pair'):
        fixed._compatible_sources(producer)
    path.write_bytes(old)
    producer['traffic'] = fixed.reference(path)
    altered_quick = tmp_path / 'altered-quick.py'
    altered_quick.write_bytes(_source(quick) + b'\n# changed dispatcher Source\n')
    altered_quick.chmod(0o644)
    monkeypatch.setattr(quick, '__file__', str(altered_quick))
    with pytest.raises(ValueError, match='quick dispatcher Source'):
        fixed._compatible_sources(producer)
