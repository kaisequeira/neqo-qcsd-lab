from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import replace
from pathlib import Path

import pytest

from qcsd_lab.acquisition_timing import (
    ACTION_TIMING_CONTRACT,
    SHORT_TERMINAL_RELEASE_BASELINE_SCHEDULING_CONTRACT,
)
from qcsd_lab.cdp_targets import (
    CDP_TARGET_INSTRUMENTATION_POLICY,
    NORMAL_SHUTDOWN_DISPOSAL_POLICY,
    NORMAL_SHUTDOWN_DISPOSAL_SUMMARY_SCHEMA_VERSION,
    SRCDOC_PSEUDO_DOCUMENT_POLICY,
    SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION,
)
from qcsd_lab.class_acquisition import (
    CHECKPOINT_SCHEMA_VERSION as ACQUISITION_CHECKPOINT_SCHEMA_VERSION,
    COMPLETION_SCHEMA_VERSION as ACQUISITION_COMPLETION_SCHEMA_VERSION,
    DOCUMENT_RESPONSE_SCHEMA_VERSION,
    SCHEMA_VERSION as ACQUISITION_SCHEMA_VERSION,
    TERMINAL_SCHEMA_VERSION as ACQUISITION_TERMINAL_SCHEMA_VERSION,
)
from qcsd_lab.class_handoff import SCHEMA_VERSION as HANDOFF_SCHEMA_VERSION
from qcsd_lab.class_fitting import PRIMARY_ORIGIN_PREFIX_SCHEMA_VERSION
from qcsd_lab.chaff_qualification import (
    PRIMARY_ORIGIN_CAPACITY_SCOPE,
    PRIMARY_ORIGIN_PREFIX_RECEIPT_SCHEMA_VERSION,
)
from qcsd_lab.h3_prebaseline import PREBASELINE_H3_SCREEN_V2_CONTRACT
from qcsd_lab.class_study import (
    CANDIDATE_COUNT,
    CANDIDATES_PER_STRATUM,
    CLASS20_PROFILE,
    CLASS20_STUDY_ID,
    COMPATIBILITY_MODES,
    EVIDENCE_ROLES,
    FINAL_CLASS_COUNT,
    FORMAL_MODES,
    PILOT_COUNT,
    RECEIPT_TYPE,
    RESERVE_COUNT,
    STUDY_ID,
    SUCCESSOR_GENERATION_MAX,
    TRANCO_RANK_STRATA,
    ClassCandidate,
    ClassStudyProfile,
    bind_receipt,
    build_study_receipt,
    campaign_sample_counts,
    canonical_json_bytes,
    canonical_json_sha256,
    class_study_id_from_campaign_name,
    deterministic_candidate_order,
    deterministic_profile_candidate_order,
    formal_split_counts,
    is_class_study_campaign_name,
    is_class_study_id,
    is_successor_study_id,
    load_study_receipt,
    load_class20_profile_contract,
    parse_class_study_id,
    parse_class_study_campaign_name,
    select_cohort,
    select_profile_pilot,
    successor_study_id,
    validate_evidence_role,
    validate_hash_bound_receipt,
    validate_study_receipt,
    write_study_receipt,
)
from qcsd_lab.experiment import (
    KERNEL_TX_EVIDENCE_FILES,
    KERNEL_TX_EVIDENCE_RECEIPT_SOURCE,
)
from qcsd_lab.discovery_evidence import (
    DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION,
    PASSIVE_RENDER_CONTRACT,
    PASSIVE_RENDER_CONTRACT_SHA256,
    REQUEST_STAGE_OBSERVATION_POLICY,
    RENDER_OBSERVATION_SCHEMA_VERSION,
)
from qcsd_lab.pinned_cdp import PROBE_SCHEMA_VERSION as PINNED_CDP_PROBE_SCHEMA_VERSION

LIST_SHA = "a" * 64
OTHER_LIST_SHA = "b" * 64


def test_prospective_walkie_talkie_prefix_scope_amendment_is_exact() -> None:
    root = Path(__file__).resolve().parents[1]
    study = json.loads((root / "config/class-study/v1/study.json").read_text())

    assert PRIMARY_ORIGIN_PREFIX_SCHEMA_VERSION == 4
    assert PRIMARY_ORIGIN_PREFIX_RECEIPT_SCHEMA_VERSION == 4
    assert PRIMARY_ORIGIN_CAPACITY_SCOPE == "primary-origin-capacity-v1"
    assert study["prospective_walkie_talkie_prefix_amendment"] == {
        "schema_version": 1,
        "date": "2026-10-01",
        "scope": "fresh-source-bound-class-study-walkie-talkie-prefix-qualification",
        "qualification_scope": PRIMARY_ORIGIN_CAPACITY_SCOPE,
        "prefix_spec_schema_version": PRIMARY_ORIGIN_PREFIX_SCHEMA_VERSION,
        "prefix_qualification_receipt_schema_version": (
            PRIMARY_ORIGIN_PREFIX_RECEIPT_SCHEMA_VERSION
        ),
        "frozen_application_graph": (
            "validate-complete-prepared-resource-graph-and-bind-exact-manifest-hash;"
            "never-prune-secondary-or-outside-prefix-resources"
        ),
        "capacity_connection": "one-primary-origin-quic-connection",
        "stage_projection": (
            "compute-full-graph-dependency-batches-then-filter-each-stage-to-primary-origin-"
            "without-renumbering-or-collapsing-empty-stages"
        ),
        "unproven_application_resources": {
            "fields": ["resource_id", "url", "status", "bytes", "body_sha256", "reason"],
            "order": "resource_id-ascending",
            "reason_precedence": "secondary-origin-before-outside-prefix-components",
            "qualification_credit": "none-for-ledger-resources",
        },
        "proof_boundary": (
            "primary-origin-staged-capacity-only;full-page-and-secondary-origin-behaviour-"
            "require-separate-end-to-end-verification"
        ),
        "historical_prefix_spec_schema_versions": [2, 3],
        "historical_prefix_receipt_schema_versions": [2, 3],
        "historical_policy": (
            "verify-only-no-retroactive-capacity-credit-or-current-source-authority"
        ),
        "formal_evidence_policy": "new-source-build-and-cohort-required-no-historical-promotion",
    }


def test_prospective_acquisition_publication_namespace_is_version_paired() -> None:
    root = Path(__file__).resolve().parents[1]
    study = json.loads((root / "config/class-study/v1/study.json").read_text())
    layout = study["canonical_workspace_layout"]

    assert study["prospective_acquisition_publication_namespace_amendment"] == {
        "schema_version": 1,
        "date": "2026-10-01",
        "scope": "fresh-source-bound-acquisition-publication-only",
        "version_source": "allocator-authorised-positive-acquisition-cohort-version-N",
        "acquisition_root": "artifacts/classifier-multiorigin100-v1-acquisition-vN",
        "stability_root": "artifacts/classifier-multiorigin100-v1-stability-vN",
        "workload_root": "config/workloads-vN",
        "pairing_policy": (
            "same-N-create-only-direct-sibling-of-each-unsuffixed-root-no-symlink-component"
        ),
        "historical_unsuffixed_roots": "verify-only-never-fresh-source-publication",
        "historical_evidence_policy": "no-retroactive-promotion-or-relabeling",
    }
    assert layout["scope"] == (
        "prospective-versioned-publication-and-historical-unsuffixed-path-map"
    )
    assert layout["fresh_path_policy"] == "paired-direct-vN-siblings-no-symlink-component"
    assert layout["acquisition_root_versioned_sibling"] == (
        "artifacts/classifier-multiorigin100-v1-acquisition-v[1-9][0-9]*"
    )
    assert layout["stability_root_versioned_sibling"] == (
        "artifacts/classifier-multiorigin100-v1-stability-v[1-9][0-9]*"
    )
    assert layout["workload_root_versioned_sibling"] == "config/workloads-v[1-9][0-9]*"
    assert layout["unsuffixed_publication_roots"] == "historical-verify-only-never-fresh-write"


def test_checked_in_handoff_contract_matches_current_exporter_and_kernel_sidecar() -> None:
    root = Path(__file__).resolve().parents[1]
    study = json.loads((root / "config/class-study/v1/study.json").read_text())
    evaluation = study["classifier_contract"]
    kernel = evaluation["handoff_kernel_tx_evidence"]
    amendment = study["prospective_acquisition_amendment"]
    page_admission = study["page_admission"]

    assert amendment["schema_version"] == 8
    assert amendment["date"] == "2026-10-01"
    assert study["prospective_udp_direction_amendment"] == {
        "schema_version": 1,
        "date": "2026-10-01",
        "scope": "fresh-source-bound-acquisition-fitting-qualification-and-capture-only",
        "reason": (
            "ordinary-public-http3-servers-can-send-udp-payloads-above-the-client-outgoing-"
            "defense-ceiling;retain-the-1200-byte-client-send-target-and-observe-complete-"
            "incoming-datagrams-up-to-the-standard-advertised-receive-limit"
        ),
        "outgoing_udp_payload_ceiling_bytes": 1200,
        "incoming_udp_payload_limit_bytes": 65527,
        "preparation_udp_payload_qualification_schema_version": 2,
        "historical_udp_payload_qualification_schema_1": (
            "verify-only-absolute-1200-byte-ceiling-never-retroactively-admit"
        ),
        "packet_fragment_policy": "missing-complete-udp-payload-length-fails-capture-integrity",
        "formal_evidence_policy": "new-source-build-and-cohort-required-no-historical-promotion",
    }
    assert page_admission["outgoing_udp_payload_ceiling_bytes"] == 1200
    assert page_admission["incoming_udp_payload_limit_bytes"] == 65527
    assert "udp_payload_ceiling_bytes" not in page_admission
    assert amendment["acquisition_schema_version"] == 12
    assert ACQUISITION_SCHEMA_VERSION == 13
    assert amendment["checkpoint_schema_version"] == ACQUISITION_CHECKPOINT_SCHEMA_VERSION == 3
    assert amendment["terminal_schema_version"] == 4
    assert ACQUISITION_TERMINAL_SCHEMA_VERSION == 5
    assert amendment["completion_schema_version"] == 4
    assert ACQUISITION_COMPLETION_SCHEMA_VERSION == 5
    assert amendment["document_response_schema_version"] == DOCUMENT_RESPONSE_SCHEMA_VERSION == 2
    assert amendment["pinned_cdp_probe_schema_version"] == PINNED_CDP_PROBE_SCHEMA_VERSION == 18
    assert amendment["render_observation_schema_version"] == RENDER_OBSERVATION_SCHEMA_VERSION
    assert amendment["discovery_event_audit_schema_version"] == DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION
    assert amendment["request_stage_observation_policy"] == REQUEST_STAGE_OBSERVATION_POLICY
    assert (
        amendment["passive_render_contract_schema_version"]
        == PASSIVE_RENDER_CONTRACT["schema_version"]
    )
    assert amendment["retired_v96_contract"] == {
        "acquisition_schema_version": 6,
        "completion_schema_version": 3,
        "pinned_cdp_probe_schema_version": 14,
        "authority": "historical-verify-only-never-current-admission",
    }
    assert amendment["retired_v100_contract"] == {
        "acquisition_schema_version": 7,
        "checkpoint_schema_version": 3,
        "terminal_schema_version": 4,
        "completion_schema_version": 4,
        "pinned_cdp_probe_schema_version": 16,
        "discovery_event_audit_schema_version": 5,
        "cdp_target_instrumentation_policy": (
            "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v19"
        ),
        "authority": "historical-verify-only-never-current-admission",
    }
    assert amendment["retired_v101_contract"] == amendment["retired_v100_contract"]
    assert amendment["retired_v102_contract"] == {
        "acquisition_schema_version": 8,
        "checkpoint_schema_version": 3,
        "terminal_schema_version": 4,
        "completion_schema_version": 4,
        "pinned_cdp_probe_schema_version": 17,
        "discovery_event_audit_schema_version": 7,
        "cdp_target_instrumentation_policy": (
            "playwright-1.57-filtered-public-cdp-guarded-shared-worker-tab-and-egress-v20"
        ),
        "authority": "historical-verify-only-never-current-admission",
    }
    assert amendment["retired_v127_contract"] == {
        "acquisition_schema_version": 9,
        "checkpoint_schema_version": 3,
        "terminal_schema_version": 4,
        "completion_schema_version": 4,
        "pinned_cdp_probe_schema_version": 18,
        "discovery_event_audit_schema_version": 8,
        "stability_probe_profile": "t+30s-t+24h-t+72h",
        "authority": "historical-verify-only-never-current-admission",
    }
    assert amendment["retired_v129_contract"] == {
        "acquisition_schema_version": 10,
        "checkpoint_schema_version": 3,
        "terminal_schema_version": 4,
        "completion_schema_version": 4,
        "pinned_cdp_probe_schema_version": 18,
        "discovery_event_audit_schema_version": 8,
        "stability_probe_profile": (
            "two-prepared-observations-at-t+30s-and-t+5m-without-prebaseline-http3-screen"
        ),
        "authority": "historical-verify-only-never-current-admission",
    }
    assert amendment["retired_v130_contract"] == {
        "acquisition_schema_version": 11,
        "checkpoint_schema_version": 3,
        "terminal_schema_version": 4,
        "completion_schema_version": 4,
        "pinned_cdp_probe_schema_version": 18,
        "discovery_event_audit_schema_version": 8,
        "prebaseline_h3_screen_schema_version": 1,
        "authority": "historical-verify-only-never-current-admission",
    }
    assert page_admission["prebaseline_h3_screen_contract"] == {
        "schema_version": 2,
        "policy": "prebaseline-exact-selected-page-neqo-h3-reachability-v2",
        "control_url": "https://cloudflare-quic.com/",
        "timeout_seconds": 12,
        "control_probe_order": "before-and-after-selected-page-attempts",
        "control_success": "both-known_valid-true",
        "candidate_attempts_per_selected_page": 2,
        "maximum_selected_pages": 5,
        "pass": "at-least-one-exact-selected-page-known_valid-on-both-attempts",
        "site_rejection": (
            "all-exact-selected-pages-fail-both-attempts-with-classified-"
            "http3-connectivity-timeout-or-idle-timeout"
        ),
        "uncertain_outcome": "mixed-ambiguous-or-control-failure-blocks",
        "resolver_addresses": "diagnostic-only-no-neqo-pin-claim",
    }
    assert page_admission["prebaseline_h3_screen_contract"] == PREBASELINE_H3_SCREEN_V2_CONTRACT
    assert page_admission["passive_render_contract"] == PASSIVE_RENDER_CONTRACT
    assert page_admission["passive_render_contract_sha256"] == PASSIVE_RENDER_CONTRACT_SHA256
    assert page_admission["cdp_target_instrumentation_policy"] == CDP_TARGET_INSTRUMENTATION_POLICY
    assert page_admission["render_observation_schema_version"] == RENDER_OBSERVATION_SCHEMA_VERSION
    assert (
        page_admission["discovery_event_audit_schema_version"]
        == DISCOVERY_EVENT_AUDIT_SCHEMA_VERSION
    )
    assert (
        page_admission["request_stage_observation_policy"]
        == REQUEST_STAGE_OBSERVATION_POLICY
    )
    assert page_admission["srcdoc_pseudo_document_contract"] == {
        "schema_version": SRCDOC_PSEUDO_DOCUMENT_SUMMARY_SCHEMA_VERSION,
        "policy": SRCDOC_PSEUDO_DOCUMENT_POLICY,
    }
    assert page_admission["normal_shutdown_disposal_contract"] == {
        "schema_version": NORMAL_SHUTDOWN_DISPOSAL_SUMMARY_SCHEMA_VERSION,
        "policy": NORMAL_SHUTDOWN_DISPOSAL_POLICY,
        "required_state": "terminal",
    }

    assert page_admission["acquisition_action_timing_contract"] == ACTION_TIMING_CONTRACT
    assert (
        page_admission["baseline_scheduling_contract"]
        == SHORT_TERMINAL_RELEASE_BASELINE_SCHEDULING_CONTRACT
    )
    assert evaluation["handoff_schema_version"] == HANDOFF_SCHEMA_VERSION == 3
    assert kernel == {
        "row_field": "kernel_tx_evidence",
        "null_for_runtime_kinds": [
            "none",
            "front",
            "tamaraw",
            "traffic_morphing",
            "wtf_pad",
            "walkie_talkie",
            "cs_buflo",
        ],
        "required_for_runtime_kind": "buflo",
        "required_runner_wakeup_schema_version": 17,
        "required_kernel_tx_runner_receipt_schema_version": 8,
        "accepted_sample_inventory_relationship": (
            "separate-checksum-bound-sidecar-does-not-change-the-five-file-accepted-"
            "sample-inventory"
        ),
        "sidecar_source": KERNEL_TX_EVIDENCE_RECEIPT_SOURCE,
        "sidecar_files": sorted(KERNEL_TX_EVIDENCE_FILES),
    }


def _candidates() -> tuple[ClassCandidate, ...]:
    candidates = []
    for stratum_index, stratum in enumerate(TRANCO_RANK_STRATA):
        for offset in range(CANDIDATES_PER_STRATUM):
            sequence = stratum_index * CANDIDATES_PER_STRATUM + offset
            candidates.append(
                ClassCandidate(
                    candidate_id=f"class-{sequence:03d}",
                    domain=f"site-{sequence:03d}.example",
                    rank=stratum.minimum_rank + offset,
                    eligible=True,
                )
            )
    return tuple(candidates)


def _forced_pair_graph() -> tuple[tuple[str, str], ...]:
    pilot = select_cohort(_candidates(), tranco_list_sha256=LIST_SHA).pilot
    selected = tuple(
        candidate
        for stratum in TRANCO_RANK_STRATA
        for candidate in tuple(item for item in pilot if item.stratum == stratum)[4:]
    )
    return tuple(
        (selected[index].candidate_id, selected[index + 1].candidate_id)
        for index in range(0, len(selected), 2)
    )


def _receipt(*, pair_graph: tuple[tuple[str, str], ...] | None = None) -> dict:
    return build_study_receipt(
        _candidates(),
        tranco_list_id="TEST-LIST-ID",
        tranco_list_sha256=LIST_SHA,
        feasible_pairs=pair_graph,
    )


def test_contract_defines_exact_modes_roles_and_campaign_arithmetic() -> None:
    assert COMPATIBILITY_MODES == (
        "undefended",
        "static",
        "front",
        "tamaraw",
        "traffic-morphing",
        "wtf-pad",
        "walkie-talkie",
        "buflo",
        "cs-buflo",
    )
    assert FORMAL_MODES == tuple(mode for mode in COMPATIBILITY_MODES if mode != "static")
    assert EVIDENCE_ROLES == (
        "pilot-fitting",
        "pilot-compatibility",
        "authoritative-fitting",
        "certification",
        "canary",
        "formal",
    )
    assert validate_evidence_role("formal") == "formal"
    with pytest.raises(ValueError, match="unsupported"):
        validate_evidence_role("qualification")

    assert campaign_sample_counts() == {
        "nine_mode_regression": 18,
        "controlled_gate": 160,
        "pilot_fitting": 480,
        "pilot_full_qualification": 720,
        "pilot_compatibility": 1_080,
        "authoritative_fitting": 2_000,
        "final_full_qualification": 600,
        "final_certification": 900,
        "per_block_canaries": 1_000,
        "formal": 16_000,
    }
    splits = formal_split_counts()
    assert splits == {
        "train": {"blocks": tuple(range(1, 9)), "visits_per_class_mode": 16, "samples": 12_800},
        "validation": {"blocks": (9,), "visits_per_class_mode": 2, "samples": 1_600},
        "test": {"blocks": (10,), "visits_per_class_mode": 2, "samples": 1_600},
    }
    assert sum(split["samples"] for split in splits.values()) == 16_000


def test_class_study_identity_grammar_is_exact_and_generator_bounded() -> None:
    digest = "a" * 64
    successor = "classifier-multiorigin100-v2-g01-aaaaaaaaaaaa"

    assert successor_study_id(generation=1, identity_sha256=digest) == successor
    assert parse_class_study_id(STUDY_ID).generation == 0
    parsed = parse_class_study_id(successor)
    assert parsed.successor is True
    assert parsed.generation == 1
    assert parsed.identity_prefix == "a" * 12
    assert is_class_study_id(STUDY_ID)
    assert is_class_study_id(successor)
    assert is_successor_study_id(successor)
    assert not is_successor_study_id(STUDY_ID)

    maximum = successor_study_id(
        generation=SUCCESSOR_GENERATION_MAX,
        identity_sha256="f" * 64,
    )
    assert parse_class_study_id(maximum).generation == SUCCESSOR_GENERATION_MAX

    invalid = (
        "classifier-multiorigin100-v2-aaaaaaaaaaaa",
        "classifier-multiorigin100-v2-g00-aaaaaaaaaaaa",
        "classifier-multiorigin100-v2-g100-aaaaaaaaaaaa",
        "classifier-multiorigin100-v2-g01-AAAAAAAAAAAA",
        "classifier-multiorigin100-v2-g01-aaaaaaaaaaa",
        "classifier-multiorigin100-v2-g01-aaaaaaaaaaaa-extra",
        f"prefix-{STUDY_ID}",
    )
    for value in invalid:
        assert not is_class_study_id(value)
        with pytest.raises(ValueError, match="class-study"):
            parse_class_study_id(value)

    for generation in (True, 0, SUCCESSOR_GENERATION_MAX + 1):
        with pytest.raises(ValueError, match="generation"):
            successor_study_id(generation=generation, identity_sha256=digest)
    for invalid_digest in ("a" * 63, "A" * 64, "not-a-digest"):
        with pytest.raises(ValueError, match="digest"):
            successor_study_id(generation=1, identity_sha256=invalid_digest)


def test_class_study_campaign_name_grammar_binds_the_complete_study_id() -> None:
    successor = "classifier-multiorigin100-v2-g01-0123456789ab"
    accepted = {
        f"{STUDY_ID}-pilot-fitting-1200": STUDY_ID,
        f"{STUDY_ID}-pilot-compatibility-1080-1200": STUDY_ID,
        f"{STUDY_ID}-authoritative-fitting-1200": STUDY_ID,
        f"{STUDY_ID}-certification-900-1200": STUDY_ID,
        f"{STUDY_ID}-canary-10-1200": STUDY_ID,
        f"{STUDY_ID}-formal-01-1200": STUDY_ID,
        f"{successor}-authoritative-fitting-2000-1200": successor,
        f"{successor}-certification-900-1200": successor,
        f"{successor}-canary-01-1200": successor,
        f"{successor}-formal-10-1200": successor,
    }
    for name, expected in accepted.items():
        assert class_study_id_from_campaign_name(name) == expected
        assert is_class_study_campaign_name(name)
    parsed = parse_class_study_campaign_name(f"{successor}-formal-10-1200")
    assert (parsed.study_id, parsed.evidence_role, parsed.block) == (
        successor,
        "formal",
        10,
    )

    invalid = (
        f"{STUDY_ID}-authoritative-fitting-2000-1200",
        f"{successor}-pilot-fitting-1200",
        f"{successor}-authoritative-fitting-1200",
        f"{successor}-formal-00-1200",
        f"{successor}-formal-11-1200",
        f"{successor}-formal-01-1200-extra",
        "classifier-multiorigin100-v2-active-formal-01-1200",
    )
    for name in invalid:
        assert not is_class_study_campaign_name(name)
        with pytest.raises(ValueError, match="campaign name"):
            class_study_id_from_campaign_name(name)


def test_class20_campaign_names_are_exact_and_do_not_extend_v1_receipt_identity() -> None:
    stage_roles = {
        "pilot-fitting-120-1200": "pilot-fitting",
        "authoritative-fitting-400-1200": "authoritative-fitting",
        "certification-180-1200": "certification",
    }
    for suffix, role in stage_roles.items():
        name = f"{CLASS20_STUDY_ID}-{suffix}"
        parsed = parse_class_study_campaign_name(name)
        assert (parsed.study_id, parsed.evidence_role, parsed.block) == (
            CLASS20_STUDY_ID,
            role,
            None,
        )
        assert class_study_id_from_campaign_name(name) == CLASS20_STUDY_ID
        assert is_class_study_campaign_name(name)
    for role in ("canary", "formal"):
        for block in range(1, 11):
            name = f"{CLASS20_STUDY_ID}-{role}-{block:02d}-1200"
            parsed = parse_class_study_campaign_name(name)
            assert (parsed.study_id, parsed.evidence_role, parsed.block) == (
                CLASS20_STUDY_ID,
                role,
                block,
            )

    # The old receipt/experiment/evaluation validators are explicitly scoped
    # to v1 and its hash-derived successors until they receive a v2 branch.
    assert not is_class_study_id(CLASS20_STUDY_ID)
    with pytest.raises(ValueError, match="identity"):
        parse_class_study_id(CLASS20_STUDY_ID)

    invalid = (
        f"{CLASS20_STUDY_ID}-pilot-fitting-1200",
        f"{CLASS20_STUDY_ID}-pilot-fitting-121-1200",
        f"{CLASS20_STUDY_ID}-pilot-compatibility-270-1200",
        f"{CLASS20_STUDY_ID}-pilot-compatibility-1080-1200",
        f"{CLASS20_STUDY_ID}-authoritative-fitting-2000-1200",
        f"{CLASS20_STUDY_ID}-certification-900-1200",
        f"{CLASS20_STUDY_ID}-canary-00-1200",
        f"{CLASS20_STUDY_ID}-canary-11-1200",
        f"{CLASS20_STUDY_ID}-formal-1-1200",
        f"{CLASS20_STUDY_ID}-formal-01-1200-extra",
        f"prefix-{CLASS20_STUDY_ID}-formal-01-1200",
    )
    for name in invalid:
        assert not is_class_study_campaign_name(name)
        with pytest.raises(ValueError, match="campaign name"):
            parse_class_study_campaign_name(name)


def test_hash_order_and_unconstrained_selection_are_deterministic() -> None:
    candidates = _candidates()
    first = deterministic_candidate_order(candidates, tranco_list_sha256=LIST_SHA)
    assert first == deterministic_candidate_order(reversed(candidates), tranco_list_sha256=LIST_SHA)
    assert first != deterministic_candidate_order(candidates, tranco_list_sha256=OTHER_LIST_SHA)

    selection = select_cohort(candidates, tranco_list_sha256=LIST_SHA)
    assert len(selection.candidates) == CANDIDATE_COUNT
    assert len(selection.pilot) == PILOT_COUNT
    assert len(selection.final) == FINAL_CLASS_COUNT
    assert len(selection.reserves) == RESERVE_COUNT
    assert selection.matching is None
    assert set(selection.final).isdisjoint(selection.reserves)
    assert set(selection.final) | set(selection.reserves) == set(selection.pilot)
    assert Counter(candidate.stratum.id for candidate in selection.candidates) == {
        stratum.id: CANDIDATES_PER_STRATUM for stratum in TRANCO_RANK_STRATA
    }
    assert Counter(candidate.stratum.id for candidate in selection.pilot) == {
        stratum.id: 24 for stratum in TRANCO_RANK_STRATA
    }
    assert Counter(candidate.stratum.id for candidate in selection.final) == {
        stratum.id: 20 for stratum in TRANCO_RANK_STRATA
    }
    assert Counter(candidate.stratum.id for candidate in selection.reserves) == {
        stratum.id: 4 for stratum in TRANCO_RANK_STRATA
    }


def test_class20_profile_is_source_bound_and_keeps_v1_order_unchanged(monkeypatch) -> None:
    import qcsd_lab.class_study as study

    profile = load_class20_profile_contract()
    assert profile == CLASS20_PROFILE
    assert profile.formal_sample_count == 16_000
    assert profile.final_count * len(profile.formal_modes) * 10 * 10 == 16_000
    with pytest.raises(ValueError, match="registered dimensions"):
        ClassStudyProfile(**{**vars(profile), "pilot_count": 31})

    catalogue = _candidates()
    frozen = deterministic_candidate_order(catalogue, tranco_list_sha256=LIST_SHA)
    interleaved = deterministic_profile_candidate_order(
        reversed(catalogue), tranco_list_sha256=LIST_SHA, profile=profile
    )
    assert frozen == deterministic_candidate_order(
        catalogue, tranco_list_sha256=LIST_SHA,
        order_seed_study_id=profile.catalogue_order_seed,
    )
    assert len(interleaved) == 600
    assert [candidate.stratum.id for candidate in interleaved[:5]] == [
        stratum.id for stratum in TRANCO_RANK_STRATA
    ]
    assert interleaved == deterministic_profile_candidate_order(
        catalogue, tranco_list_sha256=LIST_SHA, profile=profile
    )
    for stratum in TRANCO_RANK_STRATA:
        assert tuple(candidate for candidate in interleaved if candidate.stratum == stratum) == (
            tuple(candidate for candidate in frozen if candidate.stratum == stratum)
        )

    monkeypatch.setattr(study, "_CLASS20_OVERLAY_SHA256", "0" * 64)
    with pytest.raises(ValueError, match="source-pinned bytes"):
        load_class20_profile_contract()


def test_class20_profile_loads_from_lab_root_with_installed_module(monkeypatch) -> None:
    import qcsd_lab.class_study as study

    root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr(study, "LAB_ROOT", root, raising=False)
    monkeypatch.setattr(
        study,
        "__file__",
        "/opt/qcsd-venv/lib/python3.11/site-packages/qcsd_lab/class_study.py",
    )

    assert load_class20_profile_contract() == CLASS20_PROFILE


def test_class20_profile_inherits_exact_primary_origin_prefix_scope() -> None:
    root = Path(__file__).resolve().parents[1]
    overlay = json.loads((root / "config/class-study/v2/study.json").read_bytes())
    base = json.loads((root / "config/class-study/v1/study.json").read_bytes())
    prefix = overlay["walkie_talkie_prefix_qualification"]
    assert overlay["base_study_contract"]["inheritance"] == (
        "unchanged-browser-safety-request-replay-defence-and-primary-origin-"
        "prefix-qualification-rules-only"
    )
    assert prefix == {
        "inherited_amendment": "prospective_walkie_talkie_prefix_amendment",
        "qualification_scope": PRIMARY_ORIGIN_CAPACITY_SCOPE,
        "prefix_spec_schema_version": PRIMARY_ORIGIN_PREFIX_SCHEMA_VERSION,
        "prefix_qualification_receipt_schema_version": (
            PRIMARY_ORIGIN_PREFIX_RECEIPT_SCHEMA_VERSION
        ),
        "capacity_connection": "one-primary-origin-quic-connection",
        "proof_boundary": (
            "primary-origin-staged-capacity-only;full-page-and-secondary-origin-behaviour-"
            "require-separate-end-to-end-verification"
        ),
    }
    amendment = base[prefix["inherited_amendment"]]
    for key, value in prefix.items():
        if key != "inherited_amendment":
            assert amendment[key] == value


@pytest.mark.parametrize(
    "field,invalid",
    (
        ("inherited_amendment", "other_amendment"),
        ("qualification_scope", "whole-page-capacity"),
        ("prefix_spec_schema_version", 3),
        ("prefix_qualification_receipt_schema_version", 3),
        ("capacity_connection", "multiple-quic-connections"),
        ("proof_boundary", "full-page-capacity"),
    ),
)
def test_class20_profile_rejects_changed_prefix_scope_even_with_matching_hash(
    tmp_path: Path, monkeypatch, field: str, invalid: object,
) -> None:
    import qcsd_lab.class_study as study

    source = Path(__file__).resolve().parents[1] / "config/class-study/v2/study.json"
    profile = tmp_path / "config/class-study/v2/study.json"
    profile.parent.mkdir(parents=True)
    payload = json.loads(source.read_bytes())
    payload["walkie_talkie_prefix_qualification"][field] = invalid
    profile.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    monkeypatch.setattr(study, "LAB_ROOT", tmp_path, raising=False)
    monkeypatch.setattr(
        study, "_CLASS20_OVERLAY_SHA256", hashlib.sha256(profile.read_bytes()).hexdigest()
    )
    with pytest.raises(ValueError, match="invalid registered contract"):
        load_class20_profile_contract()


def test_class20_pilot_uses_30_confirmed_eligible_sites_without_rank_minima() -> None:
    catalogue = _candidates()
    frozen = deterministic_candidate_order(catalogue, tranco_list_sha256=LIST_SHA)
    allowed: set[str] = set()
    for stratum, take in zip(TRANCO_RANK_STRATA, (2, 0, 0, 10, 18), strict=True):
        group = tuple(candidate for candidate in frozen if candidate.stratum == stratum)
        allowed.update(candidate.candidate_id for candidate in group[:take])
    assessed = tuple(
        replace(candidate, eligible=candidate.candidate_id in allowed)
        for candidate in catalogue
    )
    pilot = select_profile_pilot(
        assessed, tranco_list_sha256=LIST_SHA, profile=CLASS20_PROFILE
    )
    assert len(pilot) == 30
    assert Counter(candidate.stratum.id for candidate in pilot) == {
        TRANCO_RANK_STRATA[0].id: 2,
        TRANCO_RANK_STRATA[3].id: 10,
        TRANCO_RANK_STRATA[4].id: 18,
    }
    assert pilot == select_profile_pilot(
        reversed(assessed), tranco_list_sha256=LIST_SHA, profile=CLASS20_PROFILE
    )
    with pytest.raises(ValueError, match="needs 30 confirmed eligible"):
        select_profile_pilot(
            tuple(replace(candidate, eligible=False) for candidate in catalogue),
            tranco_list_sha256=LIST_SHA,
            profile=CLASS20_PROFILE,
        )


def test_boolean_eligibility_is_the_only_unconstrained_selection_input() -> None:
    candidates = list(_candidates())
    baseline = select_cohort(candidates, tranco_list_sha256=LIST_SHA)
    rejected = baseline.pilot[0]
    candidates[candidates.index(rejected)] = replace(rejected, eligible=False)

    changed = select_cohort(candidates, tranco_list_sha256=LIST_SHA)
    assert rejected not in changed.pilot
    assert len(changed.pilot) == PILOT_COUNT
    assert changed == select_cohort(reversed(candidates), tranco_list_sha256=LIST_SHA)


def test_optional_pair_graph_deterministically_selects_and_covers_final_cohort() -> None:
    graph = _forced_pair_graph()
    selection = select_cohort(
        _candidates(), tranco_list_sha256=LIST_SHA, feasible_pairs=reversed(graph)
    )
    assert selection.feasible_pairs is not None
    assert selection.matching is not None
    assert len(selection.matching) == FINAL_CLASS_COUNT // 2
    matched = [candidate_id for pair in selection.matching for candidate_id in pair]
    assert len(matched) == len(set(matched)) == FINAL_CLASS_COUNT
    assert set(matched) == {candidate.candidate_id for candidate in selection.final}
    assert Counter(candidate.stratum.id for candidate in selection.final) == {
        stratum.id: 20 for stratum in TRANCO_RANK_STRATA
    }

    # The graph intentionally leaves the four earliest pilot members in each
    # stratum without an edge, proving that it is a permitted selection input.
    unconstrained = select_cohort(_candidates(), tranco_list_sha256=LIST_SHA)
    assert selection.final != unconstrained.final
    assert selection == select_cohort(
        reversed(_candidates()), tranco_list_sha256=LIST_SHA, feasible_pairs=graph
    )


def test_selection_rejects_bad_inventories_and_infeasible_pair_graphs() -> None:
    candidates = _candidates()
    with pytest.raises(ValueError, match=f"exactly {CANDIDATE_COUNT}"):
        select_cohort(candidates[:-1], tranco_list_sha256=LIST_SHA)

    duplicate = (*candidates[:-1], replace(candidates[-1], rank=candidates[0].rank))
    with pytest.raises(ValueError, match="duplicate Tranco rank"):
        select_cohort(duplicate, tranco_list_sha256=LIST_SHA)

    eligible = list(candidates)
    ordered = deterministic_candidate_order(eligible, tranco_list_sha256=LIST_SHA)
    first_stratum = [
        candidate for candidate in ordered if candidate.stratum == TRANCO_RANK_STRATA[0]
    ]
    for candidate in first_stratum[: CANDIDATES_PER_STRATUM - 23]:
        eligible[eligible.index(candidate)] = replace(candidate, eligible=False)
    with pytest.raises(ValueError, match="23 eligible"):
        select_cohort(eligible, tranco_list_sha256=LIST_SHA)

    with pytest.raises(ValueError, match="cannot select a perfect"):
        select_cohort(candidates, tranco_list_sha256=LIST_SHA, feasible_pairs=())
    with pytest.raises(ValueError, match="unknown candidate"):
        select_cohort(
            candidates,
            tranco_list_sha256=LIST_SHA,
            feasible_pairs=((candidates[0].candidate_id, "not-a-candidate"),),
        )


def test_study_receipt_is_self_contained_hash_bound_and_semantically_validated() -> None:
    graph = _forced_pair_graph()
    receipt = _receipt(pair_graph=graph)
    assert receipt["receipt_type"] == RECEIPT_TYPE
    assert receipt["payload_sha256"] == canonical_json_sha256(receipt["payload"])
    selection = validate_study_receipt(receipt)
    assert len(selection.candidates) == CANDIDATE_COUNT
    assert len(selection.final) == 100
    assert receipt == _receipt(pair_graph=tuple(reversed(graph)))

    tampered = json.loads(json.dumps(receipt))
    tampered["payload"]["inventories"]["final"][0] = "forged-class"
    with pytest.raises(ValueError, match="SHA-256"):
        validate_study_receipt(tampered)

    # Rehashing an altered payload cannot bypass independently derived mode,
    # cohort, split, and count invariants.
    forged_payload = json.loads(json.dumps(receipt["payload"]))
    forged_payload["modes"]["formal"].append("static")
    rehashed = bind_receipt(forged_payload, receipt_type=RECEIPT_TYPE)
    with pytest.raises(ValueError, match="derived contract"):
        validate_study_receipt(rehashed)


@pytest.mark.parametrize("historical_schema", (1, 2, 3, 4))
def test_hash_envelope_accepts_legitimate_historical_payload_schemas(
    historical_schema: int,
) -> None:
    payload = {"acquisition_schema_version": historical_schema}
    receipt = bind_receipt(payload, receipt_type="historical-acquisition")

    assert validate_hash_bound_receipt(
        receipt,
        expected_type="historical-acquisition",
    ) == payload


@pytest.mark.parametrize("schema_alias", (True, 1.0, "1"))
def test_hash_envelope_requires_an_exact_integer_schema_version(
    schema_alias: object,
) -> None:
    receipt = bind_receipt({"historical_schema": 1}, receipt_type="test-receipt")
    receipt["schema_version"] = schema_alias

    with pytest.raises(ValueError, match="schema version"):
        validate_hash_bound_receipt(receipt, expected_type="test-receipt")


def test_canonical_receipt_writer_is_create_only_and_load_revalidates(tmp_path: Path) -> None:
    receipt = _receipt()
    destination = tmp_path / "cohort.json"
    assert write_study_receipt(destination, receipt) == destination
    assert destination.read_bytes() == canonical_json_bytes(receipt)
    loaded, selection = load_study_receipt(destination)
    assert loaded == receipt
    assert len(selection.final) == 100

    original = destination.read_bytes()
    with pytest.raises(FileExistsError, match="create-only"):
        write_study_receipt(destination, receipt)
    assert destination.read_bytes() == original


def test_receipt_rejects_candidate_and_envelope_tampering_even_when_rehashed() -> None:
    receipt = _receipt()
    extra_field = json.loads(json.dumps(receipt))
    extra_field["unexpected"] = True
    with pytest.raises(ValueError, match="envelope"):
        validate_study_receipt(extra_field)

    payload = json.loads(json.dumps(receipt["payload"]))
    payload["candidates"][0]["stratum"] = TRANCO_RANK_STRATA[-1].id
    forged = bind_receipt(payload, receipt_type=RECEIPT_TYPE)
    with pytest.raises(ValueError, match="incorrect rank stratum"):
        validate_study_receipt(forged)

    # Origin multiplicity is preserved in the prepared workload, not admitted
    # as a cohort-selection field.  This prevents either a single-origin or a
    # multi-origin preference from being smuggled into a rehashed receipt.
    payload = json.loads(json.dumps(receipt["payload"]))
    payload["candidates"][0]["origin_count"] = 2
    forged = bind_receipt(payload, receipt_type=RECEIPT_TYPE)
    with pytest.raises(ValueError, match="candidate fields"):
        validate_study_receipt(forged)

    payload = json.loads(json.dumps(receipt["payload"]))
    payload["campaign_sample_counts"]["formal"] -= 1
    forged = bind_receipt(payload, receipt_type=RECEIPT_TYPE)
    with pytest.raises(ValueError, match="derived contract"):
        validate_study_receipt(forged)


def test_canonical_json_rejects_non_json_numbers() -> None:
    with pytest.raises(ValueError):
        canonical_json_bytes({"not_json": float("nan")})
