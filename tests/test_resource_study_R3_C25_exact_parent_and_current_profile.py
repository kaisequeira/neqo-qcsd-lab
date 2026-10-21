"""Two new metadata/source cases only; ROOT already ran predecessor23.

No capture, raw replay, prepared object, current parent or credit is fabricated.
"""
import ast
import hashlib
from pathlib import Path

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_reader_compatibility as compatibility
from qcsd_lab import resource_study_semantic_refusals as semantic


SETUP = Path("/Users/joshkai/Documents/neqo-obfuscation/mac-migration-20261009/setup")
CONSUMER = "ROOT_Source109_catalog_existing_members_checkpoint_consumer_025.py"
WORKFLOW = "ROOT_Source109_catalog_existing_members_new_only_workflow_025.py"


def literals(raw):
    values = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign):
            try:
                value = ast.literal_eval(node.value)
            except (TypeError, ValueError):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    values[target.id] = value
    return values


def test_exact_actual_C25_distinct_C_W_row_preserves_dated_and_metadata_identity():
    row = semantic.PARENT_SOURCES[CONSUMER]
    consumer = (SETUP / CONSUMER).read_bytes()
    workflow = (SETUP / WORKFLOW).read_bytes()
    values = literals(consumer)
    assert row["consumer"] == (CONSUMER, hashlib.sha256(consumer).hexdigest())
    assert row["workflow"] == (WORKFLOW, hashlib.sha256(workflow).hexdigest())
    assert row["consumer"][1] == "a70aad199269a6742d8aebe315ac01c3d1b8c46b436c71d8f76445e229a09baa"
    assert row["workflow"][1] == "34968ee684575447d82f23b2fab060162bbaf55bf6073a1d13cb5d613a3b903a"
    assert values["WORKFLOW_NAME"] == WORKFLOW
    assert row["checkpoint_type"] == values["TYPE"]
    assert row["transfer_type"] == values["TRANSFER"]
    assert row["graph"] == "0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905"
    assert row["contract"] == "b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b"
    assert len(semantic.PARENT_SOURCES) == 14
    assert "ROOT_Source109_catalog_existing_members_checkpoint_consumer_026.py" not in semantic.PARENT_SOURCES


def test_real_current_cohorts_contract_and_registry_after_exact_C25_literal_forward():
    actual = cohorts._fresh_verifier_contract()
    expected = compatibility._profile(compatibility.execution_files())
    assert actual == expected
    assert actual["transitive_source_files"] == len(cohorts.RAW_DEPENDENCIES) == 177
    assert actual["transitive_source_sha256"] == "98360b70e78f468d0393bab41abdee9dce5d9c8c8e7d6b2038c63b1069a558d7"
    assert hashlib.sha256(cohorts.canonical_json(actual)).hexdigest() == "3d1a38fb37fd6de292f042105830ca9245381a3650ce1ecf5ce936e102290e6f"
    qualified = compatibility.qualify_execution(actual)
    compatibility.require_supported(compatibility.prior_exact109_execution_contract(), qualified)
