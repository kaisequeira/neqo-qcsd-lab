"""Actual installed receipt regression; no qualification or image action runs."""
from copy import deepcopy
import json
import os
from pathlib import Path

import pytest

from qcsd_lab import qualification_delivery_compatibility as delivery


@pytest.fixture
def actual_installed_inputs():
    declaration_path = os.environ.get("QCSD_DELIVERY_ENTRYPOINT_ACTUAL_INPUT")
    if declaration_path is None:
        pytest.skip("retained actual witness input must be explicitly supplied")
    declaration = json.loads(delivery.evidence._read(Path(declaration_path)))
    canonical = json.loads(delivery.evidence._reference(declaration["consumer"]["canonical"])[1])
    group_path, _ = delivery.evidence._reference(declaration["qualification_group"])
    sidecar = json.loads(delivery.evidence._read(group_path.parent / (declaration["workloads"][0]["workload_id"] + ".json")))
    original = sidecar["implementation_receipt"]
    source = Path(declaration["consumer"]["runtime"]["runtime_source_root"])
    sources = {name: delivery.evidence._read(source / name) for name in original["source_files"]}
    return original, canonical, sources


def test_actual_console_entrypoint_is_distinct_from_shell_launcher(actual_installed_inputs):
    original, canonical, sources = actual_installed_inputs
    assert original["installed_entrypoint"]["path"] == "/usr/local/bin/qcsd-lab-internal"
    assert original["installed_entrypoint"]["sha256"] != delivery.evidence._sha(sources["qcsd-lab"])
    before = deepcopy(original)
    result = delivery._consumer_implementation(original, canonical, sources)
    assert original == before
    assert result["installed_entrypoint"] == original["installed_entrypoint"]
    assert result["source_files"]["qcsd-lab"] == delivery.evidence._sha(sources["qcsd-lab"])
    assert result["sha256"] == canonical["checks"]["collection"]["qualification_implementation_sha256"]


def test_changed_console_entrypoint_refuses_actual_installed_aggregate(actual_installed_inputs):
    original, canonical, sources = actual_installed_inputs
    changed = deepcopy(original)
    changed["installed_entrypoint"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="differs from its real installed runtime"):
        delivery._consumer_implementation(changed, canonical, sources)


def test_changed_current_module_refuses_actual_installed_aggregate(actual_installed_inputs):
    original, canonical, sources = actual_installed_inputs
    changed = dict(sources)
    changed["src/qcsd_lab/application_response_policy.py"] += b"\n# changed current module\n"
    with pytest.raises(ValueError, match="differs from its real installed runtime"):
        delivery._consumer_implementation(original, canonical, changed)


def test_changed_installed_receipt_digest_is_not_a_metadata_exemption(actual_installed_inputs):
    original, canonical, sources = actual_installed_inputs
    changed = deepcopy(canonical)
    changed["checks"]["collection"]["qualification_implementation_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="differs from its real installed runtime"):
        delivery._consumer_implementation(original, changed, sources)
