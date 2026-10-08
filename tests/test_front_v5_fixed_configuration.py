"""Prospective structural controls; no saved V4 failure receives credit."""
from copy import deepcopy
import hashlib
from pathlib import Path
import tomllib
import pytest

from qcsd_lab import front_fixed_configuration as front
from qcsd_lab import capture_acceptance_policy as capture
from qcsd_lab import rapid_capture_traffic as traffic


def test_complete_native_configuration_bytes_and_fixed_marker(tmp_path):
    raw = front.configuration_bytes()
    assert hashlib.sha256(raw).hexdigest() == "910c4988276b74e25cfba20bcaefdaf2f7b25032e6110711145e197ddb4d6996"
    assert tomllib.loads(raw.decode()) == front.resolved_configuration()
    path = tmp_path / front.INPUT
    path.write_bytes(raw)
    assert front.validate_configuration(path) == path
    path.write_bytes(raw.replace(b"n_client_packets = 450", b"n_client_packets = 900"))
    with pytest.raises(ValueError):
        front.validate_configuration(path)


def test_v5_does_not_relabel_old_v4_or_infer_missing_policy():
    assert front.policy({}) is None
    for value in (None, True, capture.FRONT_RESERVE_POLICY, "unknown"):
        with pytest.raises(ValueError):
            front.policy({front.FIELD: value})
    assert front.resolved_configuration()["tail_wait_us"] == 0
    assert front.resolved_configuration()["initial_max_stream_data"] == 16
    assert front.target_identity()["historical_front_condition_carried"] is False


def test_explicit_canary_front_and_buflo_choices_cannot_mix():
    plan = {front.FIELD: front.POLICY, "static_capture_amendment": {"path": "/synthetic/zero-credit", "sha256": "0" * 64},
            "campaigns": [{"mode": "front"}]}
    assert traffic.front_declared(plan, canary=True, mode="front") == front.POLICY
    for change in ({traffic.FIELD: "rapid-v7-fixed-64ms-640s-duration-budget-v1"},
                   {"campaigns": [{"mode": "buflo"}]}, {"campaigns": []}):
        with pytest.raises(ValueError):
            traffic.front_declared({**plan, **change}, canary=True, mode="front")
    selected = traffic.canary_files(plan, "front")
    assert selected["front_configuration_sha256"] == (front.CONFIGURATION_PATH, front.CONFIGURATION_SHA256)
    assert selected["front_configuration_provenance_sha256"] == (front.PROVENANCE_PATH, front.PROVENANCE_SHA256)
    assert "front_configuration_sha256" not in traffic.files()


def test_campaign_requires_front_only_full_current_body():
    from qcsd_lab.capture_session import Defense
    defense = Defense(name="front", kind="front", baseline=False)
    kwargs = dict(selected_policy=front.POLICY, profile="research-1200", defenses=[defense],
                  body_policy="complete-current-application-delivery-v1")
    front.validate_campaign(**kwargs)
    for change in ({"body_policy": "exact-prepared-application-body-v1"}, {"profile": "research"},
                   {"defenses": []}, {"qualification_compatibility": {}}):
        with pytest.raises(ValueError):
            front.validate_campaign(**{**kwargs, **change})


def test_public_amendment_choice_is_explicit_and_front_only():
    from qcsd_lab import supplied_static_capture_amendment as amendment
    assert amendment.policies(front_policy=front.POLICY) == {capture.FRONT_FIELD: front.POLICY}
    assert amendment.policies(front_policy=capture.FRONT_RESERVE_POLICY) == {capture.FRONT_FIELD: capture.FRONT_RESERVE_POLICY}
    for kwargs in ({"front_policy": front.POLICY, "buflo_policy": capture.BUFLO_KERNEL_PREPARATION_POLICY},
                   {"front_policy": front.POLICY, "buflo_duration_policy": "rapid-v7-fixed-64ms-640s-duration-budget-v1"},
                   {"front_policy": "unknown"}):
        with pytest.raises(ValueError):
            amendment.policies(**kwargs)
