"""Execute the launcher's exact flat scheduling format selector on HOST.

The selected installed/scientific validator is stubbed at its process boundary;
these cases grant no actual runtime, qualification, capture or scheduling proof.
"""
import json
from pathlib import Path
import re
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def selector():
    text = (ROOT / "qcsd-lab").read_text()
    start = text.index('    if [[ "${rapid_scheduling_kind}" == "qcsd-rapid-v6-prospective-parallel-scheduling"')
    end = text.index('      rapid_scheduling_python=', start)
    condition = text[start:end]
    assert condition.rstrip().endswith('then')
    return condition


@pytest.mark.parametrize('kind,expected', [
    ('qcsd-rapid-v6-prospective-parallel-scheduling', 'current'),
    ('qcsd-rapid-v6-current-static-parallel-scheduling', 'current'),
    ('qcsd-rapid-v6-current-original-static-parallel-scheduling', 'current'),
    ('qcsd-rapid-v5-collection-runtime-launch-capsule-v1', 'historical'),
    ('qcsd-rapid-v5-capture-control-installation-v2', 'historical'),
    ('qcsd-rapid-v6-current-original-static-parallel-scheduling-extra', 'historical'),
    ('unknown', 'historical'),
])
def test_exact_shell_selector_routes_only_known_flat_formats(tmp_path, kind, expected):
    path = tmp_path / 'capsule.json'
    path.write_text(json.dumps({'artifact_type': kind}))
    script = ('set -euo pipefail\nrapid_scheduling_kind="$(python3 -I -c '
              "'import json,sys; print(json.load(open(sys.argv[1])).get(\"artifact_type\",\"\"))' "
              '"$1")"\n' + selector() +
              '\nprintf current\nelse\nprintf historical\nfi\n')
    result = subprocess.run(['bash', '-c', script, 'selector', str(path)], check=False,
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert result.returncode == 0 and result.stdout == expected and result.stderr == ''


def test_flat_branch_keeps_installed_schedule_validation_and_bound_runtime_checks():
    text = (ROOT / 'qcsd-lab').read_text()
    start = text.index(selector()) + len(selector())
    end = text.index('    else\n    rapid_compatibility_rows=', start)
    body = text[start:end]
    assert 'capsule=s.validate_schedule(_ref(path))' in body
    assert 'capsule["runtime"]["execution_root"]!=sys.argv[2]' in body
    assert 'capsule["runtime"]["collection_image_digest"]!=sys.argv[3]' in body
    assert 'for root in s.mount_roots(_ref(path)): print(root)' in body
    assert 'value["payload"]' not in body
