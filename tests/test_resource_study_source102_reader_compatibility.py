"""Exact historical102/101 profiles retained under106; no runtime or credit."""
from copy import deepcopy
import hashlib

import pytest

from qcsd_lab import resource_study_cohorts as cohorts
from qcsd_lab import resource_study_reader_compatibility as readers


def test_exact_source102_owned_catalog_history_supported_and_changed_hash_refuses():
    current=cohorts.verifier_contract();qualified=readers.qualify_execution(current)
    old=readers.prior_catalog_owned102_execution_contract()
    assert old["transitive_source_files"]==174
    assert old["transitive_source_sha256"]=="d623f182b23130d356077d26b5bddf48a1faffd78c15d129458aca680856df1e"
    assert hashlib.sha256(readers._encoded(old)).hexdigest()=="c2c66100f7f5192805d793ee19a0b4957537da0aeeaa5ac36791e2d40f1b5c5d"
    assert readers.PRIOR_CATALOG_OWNED102_EXECUTION_FILES[readers.HELPER_NAME]=="8340e523c255331fd9c4a0eb79b5421bfe45f81a1c9b296983d81eb9558d2237"
    assert readers.require_supported(old,qualified)is True
    assert readers.admission_contract(old,qualified)==old and old!=current
    with pytest.raises(ValueError,match="unsupported or changed Source108 execution reader"):
        readers.qualify_execution(old)
    changed=deepcopy(old);changed["transitive_source_sha256"]="e"*64
    with pytest.raises(ValueError,match="admission reader"):
        readers.require_supported(changed,qualified)


def test_exact_source101_history_supported_but_not_current_and_100_099_094_preserved():
    current=cohorts.verifier_contract();qualified=readers.qualify_execution(current)
    old=readers.prior_catalog101_execution_contract()
    assert old["transitive_source_sha256"]=="1a9b1941bc318e41a82253aacf63c7f299aa7edd09824ef7a72aa97974d59a03"
    assert hashlib.sha256(readers._encoded(old)).hexdigest()=="d1ee2b4bd8c9ed45400ebbf403b955bbd1671a9cbfc8f1d74964c1838c2a935e"
    assert readers.PRIOR_CATALOG101_EXECUTION_FILES[readers.HELPER_NAME]=="afb9d6415557d52520f07822bf73ddc89a7cae966b05c9470bb44fa67565dbc8"
    assert readers.require_supported(old,qualified)is True
    with pytest.raises(ValueError,match="unsupported or changed Source108 execution reader"):
        readers.qualify_execution(old)
    for historical,graph,contract in(
        (readers.prior_closure100_execution_contract(),"f7eba25bda8d47a4fb52c7dbb9a147abaee356f6782cb0657226a1ee9f239cea","d2f24388e956aecc45934beff746a1d43dec6414f80e31569cb5af7abc505371"),
        (readers.prior_resource_version_cli099_execution_contract(),"08d3d00ca43099e56366d5b540ab9b04e11494b3d67f484600fbc2a1bac21529","01b7e9fee1fe5873a0eba70fc09088708169f0c7ac20c48af9bcca46590719ae"),
        (readers.prior_native130_qpack_parser094_execution_contract(),"0911d3f1cdbfbd56c3596a76e47f61fe5591d5e8caa07e7c51b53fc8afa78905","b762657c74120761955bc66edce5fdd4dff8fa507f5973203bead399c3c9e52b"),
    ):
        assert readers.require_supported(historical,qualified)is True
        assert historical["transitive_source_sha256"]==graph
        assert hashlib.sha256(readers._encoded(historical)).hexdigest()==contract
    binding=readers.execution_binding(old,qualified)
    assert binding["admission_reader"]==old and binding["execution_reader"]==current
    assert binding["source102_catalog_single_owned_startup_authority"]is True
    assert binding["execution_reader_is_admission_reader"]is False and binding["authority_issued"]is False
    assert binding["scientific_credit_added"]==0
