"""Combined public controls; original physics/installed proof boundaries controlled.

The ordinary fixture uses real files, plan readers and full closing fences.
The CLI forwarding case substitutes only the downstream publication boundary.
No fixture grants qualification, capture equivalence or scientific credit.
"""
import importlib.util
from pathlib import Path

import pytest

from qcsd_lab import application_response_policy as app
from qcsd_lab import rapid_rolling_capture as rolling
from qcsd_lab import tamaraw_fixed_configuration as fixed
from tests.test_rapid_ordinary_parallel import current


def test_closed_fixed_tamaraw_cannot_replace_current_ordinary_canary(current):
    output = current.root / 'refused-fixed-tamaraw-plan.json'
    with pytest.raises(ValueError, match='own current serial complete-graph canary'):
        rolling.publish_plan(current.root,
            current.spec.cohort, current.spec.qualification_spec, output,
            readiness={'undefended': current.canary}, runtime_inputs=current.runtime,
            application_body_identity_policy=app.COMPLETE_APPLICATION_DELIVERY_POLICY,
            tamaraw_configuration_policy=fixed.POLICY)
    assert not output.exists()


@pytest.mark.parametrize('policy', [None, fixed.POLICY])
def test_combined_public_parser_and_plan_dispatch_preserve_explicit_condition(policy, current, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    entry = root / 'tools/rapid_rolling_capture.py'
    spec = importlib.util.spec_from_file_location('combined_public_rolling_control', entry)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    output, spec_output = current.root / 'public-plan.json', current.root / 'public-spec.json'
    args = ['plan', '--evidence-root', str(current.root), '--enrollment', str(current.spec.cohort),
        '--qualification-spec', str(current.spec.qualification_spec), '--output', str(output),
        '--spec-output', str(spec_output), '--application-body-identity-policy',
        app.COMPLETE_APPLICATION_DELIVERY_POLICY]
    if policy is not None:
        args += ['--tamaraw-configuration-policy', policy]
    parsed = tool._parser().parse_args(args)
    observed = []
    def publication(*values, **kwargs):
        observed.append(kwargs)
        assert kwargs['application_body_identity_policy'] == app.COMPLETE_APPLICATION_DELIVERY_POLICY
        assert kwargs['tamaraw_configuration_policy'] == policy
        assert kwargs['qualification_delivery_compatibility'] is None
        assert kwargs['scheduling'] is None
        return current.spec.plan_receipt
    # Isolate exact public forwarding; installed/canary authority is not inferred.
    monkeypatch.setattr(rolling, 'publish_plan', publication)
    monkeypatch.setattr(rolling, 'capture_spec', lambda *args: current.spec)
    monkeypatch.setattr(rolling, 'verify_capture_plan', lambda *args, **kwargs: (current.sites, current.payload))
    monkeypatch.setattr(tool, '_spec', lambda path, value: str(path))
    result = tool.run(parsed)
    assert len(observed) == 1 and result['scientific_credit'] is False
    assert not output.exists() and not spec_output.exists()
    ordinary = tool._parser().parse_args(['ordinary-parallel-plan', '--spec', str(current.spec.plan_receipt),
        '--scheduling', str(current.canonical_ref['path']), '--output', str(output),
        '--spec-output', str(spec_output)])
    assert ordinary.command == 'ordinary-parallel-plan'
    with pytest.raises(SystemExit):
        tool._parser().parse_args(args + ['--tamaraw-configuration-policy', 'unregistered'])
