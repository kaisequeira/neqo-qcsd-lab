"""Legacy receipt reopening and the new helper's mandatory executable binding."""

from copy import deepcopy

import pytest

from qcsd_lab import chaff_qualification as qualification
from tests.test_chaff_qualification import _response_only_sidecar

HELPER = "src/qcsd_lab/application_response_policy.py"


def test_current_qualification_implementation_binds_response_policy_helper():
    receipt = _response_only_sidecar()["implementation_receipt"]
    assert receipt["schema_version"] == 2
    assert HELPER in receipt["source_files"]
    assert receipt["installed_modules"][HELPER]["sha256"] == receipt["source_files"][HELPER]
    qualification._validate_implementation_receipt(receipt, require_current=False)


def test_resealed_current_receipt_cannot_omit_policy_helper():
    receipt = _response_only_sidecar()["implementation_receipt"]
    receipt["source_files"].pop(HELPER)
    receipt["installed_modules"].pop(HELPER)
    receipt["sha256"] = qualification._implementation_aggregate(receipt)
    with pytest.raises(ValueError, match="file receipt"):
        qualification._validate_implementation_receipt(receipt, require_current=False)


def test_historical_implementation_shape_reopens_without_current_authority():
    receipt = deepcopy(_response_only_sidecar()["implementation_receipt"])
    receipt["schema_version"] = 1
    receipt["domain"] = "qcsd-chaff-qualification-implementation-v1"
    receipt["source_files"].pop(HELPER)
    receipt["installed_modules"].pop(HELPER)
    receipt["sha256"] = qualification._implementation_aggregate(receipt)
    qualification._validate_implementation_receipt(receipt, require_current=False)
    with pytest.raises(ValueError, match="historical qualification"):
        qualification._validate_implementation_receipt(receipt, require_current=True)
