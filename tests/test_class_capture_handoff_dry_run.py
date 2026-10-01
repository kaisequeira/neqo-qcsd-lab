"""Zero-credit bridge from sealed compact capture results to the handoff.

The source results contain twelve synthetic packets/traces, not public-site
captures.  Only frozen-campaign replay is replaced: the compact fixture has no
real cohort, qualification, or Docker build authority.  Result sealing,
accepted-artifact verification, handoff export, and deep handoff verification
use their production implementations.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from qcsd_lab import kernel_tx, kernel_tx_runtime
import qcsd_lab.verification as verification
import tests.test_class_handoff as fixture
import tests.test_kernel_tx as kernel_fixture
from qcsd_lab.class_study import STUDY_ID
from qcsd_lab.experiment import (
    KERNEL_TX_EVIDENCE_RECEIPT_KEY,
    accepted_sample_hashes,
    input_digest,
)
from qcsd_lab.util import atomic_json, sha256_file
from qcsd_lab.verification import VerifiedResult, seal_result, verify_result


_RUNTIME_KINDS = {
    "front": "front",
    "tamaraw": "tamaraw",
    "traffic-morphing": "traffic_morphing",
    "wtf-pad": "wtf_pad",
    "walkie-talkie": "walkie_talkie",
    "buflo": "buflo",
    "cs-buflo": "cs_buflo",
}


def _install_sealable_kernel_tx_sidecar(
    receipt: VerifiedResult,
    sample: dict,
    run_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replace the old handoff-only sidecar with coherent synthetic raw evidence.

    Router packet extraction is the external tshark seam; the production
    kernel-TX evidence builder and validator still reconcile every item.
    """

    raw = json.loads(run_path.read_text(encoding="utf-8"))["runner_wakeup_metrics"]["buflo_kernel_tx"]
    template, router_receipt, packets = kernel_fixture._evidence(raw)
    retained = sample["diagnostics"][KERNEL_TX_EVIDENCE_RECEIPT_KEY]
    directory = receipt.root / retained["directory"]
    capture = directory / "router-capture.pcapng"
    router_receipt["pcapng_sha256"] = sha256_file(capture)
    evidence = kernel_tx.build_kernel_tx_evidence(
        runner_receipt=raw,
        runner_run_json_sha256=sha256_file(run_path),
        qdisc_evidence=template["qdisc"],
        router_capture_receipt=router_receipt,
        router_packets=packets,
        controlled_network_receipt=template["controlled_network_receipt"],
        controlled_network_receipt_sha256=template["controlled_network_receipt_sha256"],
        controlled_observer_binding=template["controlled_observer_binding"],
    )
    atomic_json(directory / "router-receipt.json", router_receipt)
    atomic_json(directory / "kernel-tx-evidence.json", evidence)
    for name in ("router-receipt.json", "kernel-tx-evidence.json"):
        retained["artifacts"][name] = sha256_file(directory / name)
    monkeypatch.setattr(kernel_tx_runtime, "extract_router_udp_packets", lambda _path: packets)


def _sealed_compact_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: str = "front",
) -> tuple[fixture._StudyDimensions, tuple[VerifiedResult, ...]]:
    runtime_kind = _RUNTIME_KINDS[mode]
    dimensions = replace(
        fixture._TINY,
        study_id=STUDY_ID,
        result_names=tuple(
            f"{STUDY_ID}-formal-{block:02d}-1200" for block in range(1, 4)
        ),
        modes=("undefended", mode),
        runtime_kinds={"undefended": "none", mode: runtime_kind},
    )
    monkeypatch.setattr(fixture, "_TINY", dimensions)
    if mode not in {"front", "tamaraw"}:
        installer = {
            "buflo": fixture._install_buflo_candidate_evidence,
            "cs-buflo": fixture._install_cs_buflo_candidate_evidence,
        }.get(mode, lambda _root: None)
        dimensions, receipts, _fixture_verifier = fixture._candidate_fixture(
            tmp_path,
            mode=mode,
            runtime_kind=runtime_kind,
            install_evidence=installer,
        )
    else:
        receipts, _fixture_verifier = fixture._fixture(tmp_path)

    # The compact cohort and qualification bytes are placeholders.  Keep the
    # actual result schema, checksum seal, accepted-sample verifier, and
    # downstream handoff contract in force.
    monkeypatch.setattr(verification, "_validate_frozen_contract", lambda *_a, **_k: None)
    for receipt in receipts:
        root = receipt.root
        experiment = receipt.experiment
        configuration = experiment["configuration"]
        configuration.pop("defense_runtime_inputs")
        if mode == "tamaraw":
            configuration["defenses"][1] = {
                "name": mode,
                "kind": runtime_kind,
                "baseline": False,
            }
        configuration["class_study_id"] = STUDY_ID
        configuration["public_origin_policy"] = {
            "environment": "QCSD_PUBLIC_ORIGIN_ONLY",
            "required_value": "1",
            "resolution": "resolve-once-reject-any-non-public-connect-exact-address",
        }
        (root / "failures").mkdir()
        if mode != "front":
            # The handoff's compact candidate fixture predates canonical
            # experiment paths.  Normalize its synthetic samples before the
            # real result sealer sees them, and retain the workload scope that
            # a real fitted runner records in each resolved defense.
            for sample in experiment["samples"]:
                if sample["defense"] not in {"front", mode} or sample["baseline"]:
                    continue
                if mode == "tamaraw":
                    sample["defense"] = mode
                    sample["runtime_kind"] = runtime_kind
                    fixture._bind_fixture_run(receipt, sample)
                old_path = sample["path"]
                new_path = old_path.removesuffix("/front") + f"/{mode}"
                (root / old_path).rename(root / new_path)
                sample["path"] = new_path
                run_path = root / new_path / "neqo/run.json"
                run = json.loads(run_path.read_text(encoding="utf-8"))
                if mode not in {"tamaraw", "buflo", "cs-buflo"}:
                    run["resolved_configuration"]["defense"]["workload_id"] = sample[
                        "workload_id"
                    ]
                atomic_json(run_path, run)
                if mode == "buflo":
                    _install_sealable_kernel_tx_sidecar(
                        receipt, sample, run_path, monkeypatch
                    )
                sample["artifacts"] = accepted_sample_hashes(root, sample)
        experiment["input_digest"] = input_digest(
            root,
            source=experiment["source"],
            configuration=configuration,
            samples=experiment["samples"],
        )
        atomic_json(root / "experiment.json", experiment)
        (root / "evidence.sha256").unlink()  # replace fixture placeholder with a real seal
        seal_result(root)
    return dimensions, tuple(verify_result(receipt.root) for receipt in receipts)


def _export_and_verify(
    tmp_path: Path,
    dimensions: fixture._StudyDimensions,
    receipts: tuple[VerifiedResult, ...],
) -> Path:
    destination = tmp_path / "diagnostic-handoff"
    exported = fixture._export_class_handoff(
        [receipt.root for receipt in receipts],
        destination,
        dimensions=dimensions,
        source_verifier=verify_result,
        trace_extractor=fixture._trace,
        classic_pcap_writer=fixture._classic_writer,
        correctness_validator=fixture._correctness_validator,
        performance_extractor=fixture._performance_extractor,
        cohort_loader=fixture._cohort_loader,
        assembly_validator=fixture._assembly_validator,
    )
    assert exported == fixture._verify_class_handoff(
        exported,
        dimensions=dimensions,
        deep=True,
        source_verifier=verify_result,
        trace_extractor=fixture._trace,
        classic_pcap_writer=fixture._classic_writer,
        correctness_validator=fixture._correctness_validator,
        performance_extractor=fixture._performance_extractor,
        cohort_loader=fixture._cohort_loader,
        assembly_validator=fixture._assembly_validator,
    )
    return exported


def test_sealed_defended_results_export_and_deep_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dimensions, receipts = _sealed_compact_results(tmp_path, monkeypatch)
    handoff = _export_and_verify(tmp_path, dimensions, receipts)
    dataset = json.loads((handoff / "dataset.json").read_text(encoding="utf-8"))

    assert dataset["sample_count"] == 12
    assert dataset["counts_by_mode"] == {"front": 6, "undefended": 6}
    assert dataset["runtime_contract"]["defense_runtime_inputs"] == {
        "undefended": {
            "identity_type": "source-bound-no-defense",
            "runtime_kind": "none",
        },
        "front": {
            "identity_type": "source-bound-built-in",
            "runtime_kind": "front",
        },
    }


def test_handoff_rejects_tampered_sealed_defended_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dimensions, receipts = _sealed_compact_results(tmp_path, monkeypatch)
    handoff = _export_and_verify(tmp_path, dimensions, receipts)
    defended = next(
        sample for sample in receipts[0].experiment["samples"] if sample["defense"] == "front"
    )
    run = receipts[0].root / defended["path"] / "neqo/run.json"
    run.write_bytes(run.read_bytes() + b"\n")

    with pytest.raises(ValueError, match="modified authoritative evidence"):
        fixture._verify_class_handoff(
            handoff,
            dimensions=dimensions,
            deep=True,
            source_verifier=verify_result,
            trace_extractor=fixture._trace,
            classic_pcap_writer=fixture._classic_writer,
            correctness_validator=fixture._correctness_validator,
            performance_extractor=fixture._performance_extractor,
            cohort_loader=fixture._cohort_loader,
            assembly_validator=fixture._assembly_validator,
        )


@pytest.mark.parametrize(
    "mode",
    (
        "tamaraw",
        "traffic-morphing",
        "wtf-pad",
        "walkie-talkie",
        "buflo",
        "cs-buflo",
    ),
)
def test_sealed_runtime_kind_results_export_and_deep_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    dimensions, receipts = _sealed_compact_results(
        tmp_path, monkeypatch, mode=mode
    )
    handoff = _export_and_verify(tmp_path, dimensions, receipts)
    dataset = json.loads((handoff / "dataset.json").read_text(encoding="utf-8"))
    candidate = dataset["runtime_contract"]["defense_runtime_inputs"][mode]
    record = receipts[0].experiment["configuration"]["defenses"][1]

    assert dataset["counts_by_mode"] == {mode: 6, "undefended": 6}
    if mode == "tamaraw":
        assert candidate == {
            "identity_type": "source-bound-built-in",
            "runtime_kind": "tamaraw",
        }
    else:
        assert candidate == {
            "identity_type": "hash-bound-parameter-artifact",
            "runtime_kind": _RUNTIME_KINDS[mode],
            "parameters_sha256": record["parameters_sha256"],
            "provenance_sha256": record["provenance_sha256"],
            "input_policy": record["input_policy"],
        }
    rows = [
        json.loads(line)
        for line in (handoff / "samples.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(rows) == 12
    assert all(row["kernel_tx_evidence"] is None for row in rows if row["mode"] != "buflo")
    if mode == "buflo":
        assert all(row["kernel_tx_evidence"] is not None for row in rows if row["mode"] == mode)
