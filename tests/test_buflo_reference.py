from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
from pathlib import Path

import pytest

from qcsd_lab.buflo_reference import (
    BUFLO_PAPER_RESULTS,
    BUFLO_PROFILES,
    BUFLO_REFERENCE_ID,
    CSBUFLO_CPSP_ARCHIVE_REFERENCE,
    CSBUFLO_EARLY_TERMINATION_RESULTS,
    CSBUFLO_MAIN_RESULTS,
    CSBUFLO_PADDING_PROFILES,
    CSBUFLO_REFERENCE_ID,
    CSBUFLO_WPES14_PARAMETERS,
    BufloDirectionOrder,
    BufloProfile,
    BufloSourcePacket,
    CsBufloEmptyRatePolicy,
    CsBufloPadding,
    DeterministicCsBufloJitter,
    audit_csbuflo_archive,
    csbuflo_channel_idle,
    csbuflo_crossed_threshold,
    csbuflo_done_transmitting,
    csbuflo_estimate_directional_rho_us,
    csbuflo_estimate_rho_us,
    csbuflo_fixed_writes_to_padding_target,
    csbuflo_maybe_adapt_rate,
    csbuflo_padding_target_bytes,
    csbuflo_rate_intervals_us,
    reference_document_json,
    run_reference_gate,
    transform_buflo,
    validate_reference_receipt,
)

REFERENCE_ROOT = Path(__file__).resolve().parents[1] / "config" / "reference" / "buflo-csbuflo"


def test_all_eight_published_buflo_profiles_are_explicit() -> None:
    assert [(p.tau_ms, p.rho_ms, p.packet_size_bytes) for p in BUFLO_PROFILES] == [
        (0, 40, 1_000),
        (0, 40, 1_500),
        (0, 20, 1_000),
        (0, 20, 1_500),
        (10_000, 40, 1_000),
        (10_000, 40, 1_500),
        (10_000, 20, 1_000),
        (10_000, 20, 1_500),
    ]
    assert len({profile.key for profile in BUFLO_PROFILES}) == 8


@pytest.mark.parametrize("profile", BUFLO_PROFILES)
def test_empty_buflo_trace_includes_tick_zero_and_tau(profile: BufloProfile) -> None:
    result = transform_buflo((), profile)
    expected_ticks = profile.tau_ms // profile.rho_ms + 1

    assert len(result) == 2 * expected_ticks
    assert [item.direction for item in result[:2]] == ["outgoing", "incoming"]
    assert result[0].monotonic_ms == 0
    assert result[-1].monotonic_ms == profile.tau_ms
    assert all(item.length_bytes == profile.packet_size_bytes for item in result)
    assert all(item.real_payload_bytes == 0 for item in result)
    assert all(item.dummy_payload_bytes == profile.payload_capacity_bytes for item in result)


def test_buflo_transform_buffers_fragments_and_shapes_both_directions() -> None:
    profile = BUFLO_PROFILES[0]
    result = transform_buflo(
        (
            BufloSourcePacket(0, "outgoing", 100),
            BufloSourcePacket(5, "incoming", 1_000),
        ),
        profile,
    )

    assert [(item.monotonic_ms, item.direction) for item in result] == [
        (0, "outgoing"),
        (0, "incoming"),
        (40, "outgoing"),
        (40, "incoming"),
    ]
    assert [(item.real_payload_bytes, item.dummy_payload_bytes) for item in result] == [
        (48, 900),
        (0, 948),
        (0, 948),
        (948, 0),
    ]


def test_buflo_source_order_is_explicit_and_event_equivalent_to_live_order() -> None:
    profile = BUFLO_PROFILES[0]
    source = transform_buflo(
        (BufloSourcePacket(0, "outgoing", 100),),
        profile,
        direction_order=BufloDirectionOrder.SOURCE_INCOMING_FIRST,
    )
    live = transform_buflo((BufloSourcePacket(0, "outgoing", 100),), profile)

    assert [item.direction for item in source] == ["incoming", "outgoing"]
    assert [item.direction for item in live] == ["outgoing", "incoming"]
    assert sorted(source, key=lambda item: item.direction) == sorted(
        live, key=lambda item: item.direction
    )


def test_buflo_transform_drains_large_source_payload_over_later_ticks() -> None:
    profile = BUFLO_PROFILES[0]
    result = transform_buflo((BufloSourcePacket(0, "outgoing", 2_000),), profile)
    outgoing = [item for item in result if item.direction == "outgoing"]

    assert [item.monotonic_ms for item in outgoing] == [0, 40, 80]
    assert [item.real_payload_bytes for item in outgoing] == [948, 948, 52]
    assert sum(item.real_payload_bytes for item in outgoing) == 1_948


def test_buflo_transform_ignores_ack_payload_but_rejects_invalid_source() -> None:
    profile = BUFLO_PROFILES[0]
    ack = transform_buflo((BufloSourcePacket(0, "outgoing", 52),), profile)
    assert all(item.real_payload_bytes == 0 for item in ack)

    # Pinned Trace.addPacket drops a pure ACK before Folklore's source cursor,
    # so even an arbitrarily late ACK cannot extend a tau=0 schedule.
    late_ack = transform_buflo((BufloSourcePacket(10_000, "incoming", 52),), profile)
    assert late_ack == transform_buflo((), profile)

    # The same source-side filtering must hold when real traffic drains over
    # multiple ticks and a later pure ACK would otherwise keep the cursor live.
    real = (BufloSourcePacket(0, "outgoing", 2_000),)
    mixed_late_ack = transform_buflo(
        (*real, BufloSourcePacket(10_000, "incoming", 52)), profile
    )
    assert mixed_late_ack == transform_buflo(real, profile)

    with pytest.raises(ValueError, match="chronological"):
        transform_buflo(
            (
                BufloSourcePacket(2, "outgoing", 100),
                BufloSourcePacket(1, "incoming", 100),
            ),
            profile,
        )
    with pytest.raises(ValueError, match="smaller than"):
        transform_buflo((BufloSourcePacket(0, "outgoing", 51),), profile)


def test_csbuflo_artifact_defaults_are_distinct_from_nominal_wire_size() -> None:
    parameters = CSBUFLO_WPES14_PARAMETERS
    assert parameters.initial_rho_us == 8_192
    assert (parameters.lower_rho_us, parameters.upper_rho_us) == (4_096, 32_768)
    assert parameters.first_adaptation_boundary_bytes == 16_384
    assert parameters.write_size_bytes == 548
    assert parameters.nominal_wire_packet_bytes == 600
    assert parameters.quiet_time_us == 2_000_000
    assert parameters.max_rate_samples == 1_000


def test_csbuflo_rate_estimator_uses_bursts_bounds_upper_median_and_floor_power() -> None:
    assert csbuflo_rate_intervals_us((0, 5_000, None, 10_000, 19_000)) == (5_000, 9_000)
    # The pinned artifact resolves an even median as the upper element:
    # upper-median(5000, 10000) = 10000, quantized down to 8192.
    assert csbuflo_estimate_rho_us((0, 5_000, 15_000), 4_096) == 8_192
    # A zero observed interval is clamped to the artifact's lower bound.
    assert csbuflo_estimate_rho_us((0, 0), 8_192) == 4_096
    # Algorithm 2 retains the current value when no eligible pair exists.
    assert csbuflo_estimate_rho_us((0, None, 10_000), 8_192) == 8_192
    # The pinned prototype instead chooses its upper bound for an empty window.
    assert (
        csbuflo_estimate_rho_us(
            (0, None, 10_000),
            8_192,
            empty_policy=CsBufloEmptyRatePolicy.ARTIFACT_UPPER_BOUND,
        )
        == 32_768
    )

    with pytest.raises(ValueError, match="monotonic"):
        csbuflo_estimate_rho_us((10, 9), 8_192)


def test_csbuflo_estimator_caps_and_separates_direction_windows() -> None:
    timestamps = [0, 32_768]
    for _ in range(1_000):
        timestamps.append(timestamps[-1] + 8_192)
    intervals = csbuflo_rate_intervals_us(tuple(timestamps))
    assert len(intervals) == 1_000
    assert set(intervals) == {8_192}

    estimates = csbuflo_estimate_directional_rho_us(
        {
            "outgoing": (0, 5_000, 15_000),
            "incoming": (0, 20_000),
        },
        {"outgoing": 4_096, "incoming": 8_192},
    )
    assert estimates == {"outgoing": 8_192, "incoming": 16_384}

    with pytest.raises(ValueError, match="exactly outgoing and incoming"):
        csbuflo_estimate_directional_rho_us(
            {"outgoing": (0, 5_000)},
            {"outgoing": 8_192},
        )


def test_csbuflo_adapts_once_at_each_total_byte_boundary_and_clears_stats() -> None:
    before = csbuflo_maybe_adapt_rate(
        total_sent_bytes=16_383,
        boundary_bytes=16_384,
        rho_stats_us=(0, 20_000),
        current_rho_us=8_192,
    )
    assert not before.adapted
    assert before.rho_star_us == 8_192
    assert before.next_boundary_bytes == 16_384
    assert before.retained_stats_us == (0, 20_000)

    at_boundary = csbuflo_maybe_adapt_rate(
        total_sent_bytes=16_384,
        boundary_bytes=16_384,
        rho_stats_us=(0, 20_000),
        current_rho_us=8_192,
    )
    assert at_boundary.adapted
    assert at_boundary.rho_star_us == 16_384
    assert at_boundary.next_boundary_bytes == 32_768
    assert at_boundary.retained_stats_us == ()


def test_csbuflo_jitter_is_seeded_discrete_and_bounded() -> None:
    expected = (6_717, 3_112, 8_273, 13_598, 983, 1_474, 11_223, 1_966)
    assert DeterministicCsBufloJitter(7).delays_us(8_192, len(expected)) == expected
    assert DeterministicCsBufloJitter(7).delays_us(8_192, len(expected)) == expected
    assert all(0 <= value <= 16_384 for value in expected)


def test_csbuflo_payload_and_total_padding_targets_are_not_conflated() -> None:
    assert csbuflo_padding_target_bytes(1_000, 24, CsBufloPadding.PAYLOAD) == 1_024
    assert csbuflo_padding_target_bytes(1_000, 1_100, CsBufloPadding.PAYLOAD) == 3_072
    assert csbuflo_padding_target_bytes(1_000, 1_100, CsBufloPadding.TOTAL) == 4_096
    assert csbuflo_fixed_writes_to_padding_target(1_000, 24, "payload") == 0
    assert csbuflo_fixed_writes_to_padding_target(1_000, 1_100, "payload") == 2
    assert csbuflo_fixed_writes_to_padding_target(1_000, 1_100, "total") == 4

    with pytest.raises(ValueError, match="positive"):
        csbuflo_padding_target_bytes(0, 0, "total")

    profiles = {
        profile.name: (profile.client.value, profile.server.value)
        for profile in CSBUFLO_PADDING_PROFILES
    }
    assert profiles["CPSP"] == ("payload", "payload")
    assert profiles["CTSP"] == ("total", "payload")


def test_csbuflo_power_of_two_crossing_extends_algorithm_at_first_packet() -> None:
    assert not csbuflo_crossed_threshold(0)
    assert csbuflo_crossed_threshold(548)
    assert csbuflo_crossed_threshold(1_096)
    assert not csbuflo_crossed_threshold(1_644)
    with pytest.raises(ValueError, match="smaller than"):
        csbuflo_crossed_threshold(100)


def test_csbuflo_idle_and_done_rules_require_every_conjunct() -> None:
    assert not csbuflo_channel_idle(
        on_load_event=False,
        last_site_response_us=0,
        now_us=2_000_000,
    )
    assert csbuflo_channel_idle(
        on_load_event=False,
        last_site_response_us=0,
        now_us=2_000_001,
    )
    assert csbuflo_channel_idle(
        on_load_event=True,
        last_site_response_us=None,
        now_us=0,
    )

    complete = {
        "output_buffer_bytes": 0,
        "on_load_event": True,
        "last_site_response_us": None,
        "now_us": 0,
        "padding_done": False,
        "total_sent_bytes": 1_096,
    }
    assert csbuflo_done_transmitting(**complete)
    assert not csbuflo_done_transmitting(**{**complete, "output_buffer_bytes": 1})
    assert not csbuflo_done_transmitting(**{**complete, "total_sent_bytes": 1_644})
    assert csbuflo_done_transmitting(
        **{**complete, "total_sent_bytes": 1_644, "padding_done": True}
    )
    assert not csbuflo_done_transmitting(
        **{
            **complete,
            "on_load_event": False,
            "last_site_response_us": 0,
            "now_us": 2_000_000,
            "padding_done": True,
        }
    )


def test_published_tables_preserve_metric_conventions_and_variant_ordering() -> None:
    assert len(BUFLO_PAPER_RESULTS) == 8
    for result in BUFLO_PAPER_RESULTS:
        assert result.bandwidth_ratio == pytest.approx(1.0 + result.extra_bandwidth_percent / 100.0)
    assert min(result.latency_seconds for result in BUFLO_PAPER_RESULTS) == 1.2
    assert max(result.latency_seconds for result in BUFLO_PAPER_RESULTS) == 6.0

    ctsp = next(
        result
        for result in CSBUFLO_MAIN_RESULTS
        if result.sites == 200 and result.padding_profile == "CTSP"
    )
    cpsp = next(
        result
        for result in CSBUFLO_MAIN_RESULTS
        if result.sites == 200 and result.padding_profile == "CPSP"
    )
    assert (ctsp.bandwidth_ratio, ctsp.latency_ratio) == (2.796, 3.271)
    assert (cpsp.bandwidth_ratio, cpsp.latency_ratio) == (2.289, 2.708)
    assert ctsp.panchenko_percent < cpsp.panchenko_percent
    assert len(CSBUFLO_EARLY_TERMINATION_RESULTS) == 4


def _overhead_text() -> str:
    return (
        "/capture/1_1.cap: 200, 100, 2.000000\n"
        "/capture/1_2.cap: 330, 300, 1.100000\n"
        "/capture/1_3.cap: 10, 0, inf\n"
    )


def test_csbuflo_archive_auditor_accepts_text_directory_and_tar_without_download(
    tmp_path: Path,
) -> None:
    extracted = tmp_path / "published" / "overhead.txt"
    extracted.parent.mkdir()
    extracted.write_text(_overhead_text(), encoding="utf-8")

    direct = audit_csbuflo_archive(extracted)
    directory = audit_csbuflo_archive(tmp_path)
    assert directory.total_records == direct.total_records
    assert directory.included_records == direct.included_records
    assert directory.zero_baseline_records == direct.zero_baseline_records
    assert directory.defended_bytes == direct.defended_bytes
    assert directory.baseline_bytes == direct.baseline_bytes
    assert directory.bandwidth_ratio == direct.bandwidth_ratio
    assert direct.total_records == 3
    assert direct.included_records == 2
    assert direct.finite_baseline_records == 2
    assert direct.zero_baseline_records == 1
    # Invalid zero-baseline pairs are excluded on both sides of E[D]/E[U].
    assert (direct.defended_bytes, direct.baseline_bytes) == (530, 400)
    assert direct.excluded_defended_bytes == 10
    assert direct.bandwidth_ratio == pytest.approx(1.325)
    assert direct.extra_bandwidth_percent == pytest.approx(32.5)
    assert direct.all_defended_bytes == 540
    assert direct.all_rows_ratio == pytest.approx(1.35)

    archive_path = tmp_path / "published.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(extracted, arcname="artifact/overhead.txt")
    archived = audit_csbuflo_archive(archive_path)
    assert archived.total_records == direct.total_records
    assert archived.defended_bytes == direct.defended_bytes
    assert archived.bandwidth_ratio == direct.bandwidth_ratio


def test_csbuflo_archive_auditor_rejects_reported_ratio_tampering(tmp_path: Path) -> None:
    path = tmp_path / "overhead.txt"
    path.write_text("/capture/1_1.cap: 200, 100, 1.900000\n", encoding="utf-8")
    with pytest.raises(ValueError, match="ratio mismatch"):
        audit_csbuflo_archive(path)


def test_pinned_csbuflo_archive_reference_is_exact() -> None:
    expected = CSBUFLO_CPSP_ARCHIVE_REFERENCE
    assert (
        expected.total_records,
        expected.included_records,
        expected.zero_baseline_records,
        expected.defended_bytes,
        expected.baseline_bytes,
    ) == (4_000, 3_824, 176, 7_592_598_380, 3_326_013_453)
    assert expected.bandwidth_ratio == pytest.approx(2.282792444255336)


@pytest.mark.parametrize("reference_id", [BUFLO_REFERENCE_ID, CSBUFLO_REFERENCE_ID])
def test_checked_in_reference_document_and_receipt_validate(reference_id: str) -> None:
    reference = REFERENCE_ROOT / f"{reference_id}.json"
    validation = validate_reference_receipt(reference)

    assert validation.reference_id == reference_id
    assert validation.reference_path == reference.resolve()
    assert len(validation.reference_sha256) == 64
    assert len(validation.receipt_sha256) == 64
    assert validation.verified_external_sources == ()
    assert reference.read_text(encoding="utf-8") == reference_document_json(reference_id)
    document = json.loads(reference.read_text(encoding="utf-8"))
    assert (
        document["doi"]
        == {
            BUFLO_REFERENCE_ID: "10.1109/SP.2012.28",
            CSBUFLO_REFERENCE_ID: "10.1145/2665943.2665949",
        }[reference_id]
    )
    if reference_id == CSBUFLO_REFERENCE_ID:
        assert document["paper_internal_discrepancies"] == [
            {
                "classification": "known-internal-paper-prose-vs-algorithm-conflict",
                "paper_algorithm_location": "Algorithm-2-lines-382-and-395-396",
                "paper_algorithm_rule": "2**floor(log2(median-eligible-interval))",
                "paper_prose_location": "WPES-2014-lines-450-455",
                "paper_prose_rule": "round-up-rho-to-a-power-of-two",
                "resolution_basis": (
                    "algorithm-pseudocode-and-formula-control-the-independent-oracle"
                ),
                "resolved_rule": "2**floor(log2(upper-integer-median-interval))",
            }
        ]


def test_reference_receipt_rejects_reference_and_source_tampering(tmp_path: Path) -> None:
    reference_id = BUFLO_REFERENCE_ID
    source_reference = REFERENCE_ROOT / f"{reference_id}.json"
    source_receipt = REFERENCE_ROOT / f"{reference_id}.receipt.json"
    reference = tmp_path / source_reference.name
    receipt = tmp_path / source_receipt.name
    shutil.copy2(source_reference, reference)
    shutil.copy2(source_receipt, receipt)

    # Whitespace preserves the canonical JSON value but changes the bound bytes.
    reference.write_text(reference.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        validate_reference_receipt(reference)

    shutil.copy2(source_reference, reference)
    receipt_value = json.loads(receipt.read_text(encoding="utf-8"))
    receipt_value["sources"][0]["sha256"] = "0" * 64
    receipt.write_text(json.dumps(receipt_value), encoding="utf-8")
    with pytest.raises(ValueError, match="sources are not canonical"):
        validate_reference_receipt(reference)


def test_reference_receipt_optionally_verifies_external_source_hashes(tmp_path: Path) -> None:
    reference = REFERENCE_ROOT / f"{BUFLO_REFERENCE_ID}.json"
    wrong_source = tmp_path / "trafanal.pdf"
    wrong_source.write_bytes(b"not the pinned primary paper")

    with pytest.raises(ValueError, match="external reference source SHA-256 mismatch"):
        validate_reference_receipt(
            reference,
            external_sources={"dyer-paper-pdf": wrong_source},
        )
    with pytest.raises(ValueError, match="unknown external"):
        validate_reference_receipt(reference, external_sources={"unknown": wrong_source})


def test_checked_in_external_conformance_receipt_records_every_gate() -> None:
    receipt = json.loads(
        (REFERENCE_ROOT / "buflo-csbuflo-conformance-v1.receipt.json").read_text(encoding="utf-8")
    )
    assert receipt["passed"] is True
    buflo = receipt["buflo_author_conformance"]
    assert buflo["source_order"] == ["incoming", "outgoing"]
    assert buflo["live_order"] == ["outgoing", "incoming"]
    assert len(buflo["profiles"]) == 8
    assert all(profile["source_match"] for profile in buflo["profiles"])
    cs_author = receipt["csbuflo_author_conformance"]
    assert cs_author["source_match"] is True
    assert cs_author["author_object_normalization"] == (
        "objcopy --strip-debug --remove-section=.comment"
    )
    assert cs_author["golden_vectors"] == {
        "estimator": {
            "clamped": 32_768,
            "empty": 32_768,
            "empty_next_boundary": 32_768,
            "pre_boundary": 8_192,
            "pre_boundary_next_boundary": 16_384,
            "upper_median": 8_192,
        },
        "early_termination": {
            "client_buffered_mode": 0,
            "client_idle_start_mode": 1,
            "client_idle_start_us": 5_000_000,
            "client_no_transcript_mode": 1,
            "client_onload_mode": -1,
            "client_queued_write_mode": 1,
            "client_quiet_before_mode": 1,
            "client_quiet_boundary_mode": -1,
            "server_buffered_mode": 0,
            "server_onload_mode": -1,
            "server_quiet_boundary_mode": -1,
        },
        "jitter": {
            "raw_0": 0,
            "raw_1": 81,
            "raw_100": 8_192,
            "raw_200": 16_384,
            "raw_201_modulo": 0,
            "stmode_fixed": 8_192,
        },
        "padding": {
            "client_payload_0_0": 0,
            "client_payload_1000_1048": 2_048,
            "client_payload_1000_1100": 3_072,
            "client_total_0_0": 0,
            "client_total_1000_1048": 2_048,
            "client_total_1000_1100": 4_096,
            "server_payload_1000_1100": 3_072,
            "server_total_1000_1100": 4_096,
        },
        "padding_done": {"after_set": 1, "after_unset": 0, "initial": 0},
        "quiet": {
            "buffered_resets_idle": 0,
            "onload_idle": 1,
            "quiet_after": 1,
            "quiet_before": 0,
        },
        "termination": {
            "client_buffered_mode": 0,
            "client_complete_mode": -1,
            "client_exact_tolerance_mode": 0,
            "server_buffered_mode": 0,
            "server_buffered_padding_done": 1,
            "server_complete_mode": -1,
            "server_complete_padding_done": 0,
        },
    }
    extraction = cs_author["source_extraction"]
    assert cs_author["independent_oracle_match"] is True
    assert extraction["active_padding_profile"] == "CPSP-payload-at-both-endpoints"
    assert extraction["payload_padding_source_executed"] is True
    assert extraction["total_padding_source_expression_executed"] is True
    assert extraction["total_padding_active_in_pinned_runtime"] is False
    assert extraction["jitter_source_function_executed"] is True
    assert extraction["early_termination_source_state_machine_executed"] is True
    assert extraction["early_termination_quiet_comparison"] == ("inclusive-elapsed-us>=2000000")
    assert extraction["padding_done_active_consumer_count"] == 0
    assert extraction["padding_done_flag_author_object_executed"] is True
    assert extraction["quiet_function_author_object_executed"] is True
    assert extraction["termination_predicates_and_state_actions_executed"] is True
    assert extraction["full_network_loop_executed"] is False
    assert set(extraction["segment_sha256"]) == {
        "client_early_termination_branch",
        "client_padding_done_define",
        "client_padding_done_notification",
        "client_payload_padding",
        "client_terminal_branch",
        "client_total_padding_inactive",
        "jitter_function",
        "server_early_termination_branch",
        "server_payload_padding",
        "server_terminal_branch",
        "server_total_padding_inactive",
        "target_queue_define",
    }
    archive = receipt["csbuflo_archive_conformance"]
    assert (
        archive["total_records"],
        archive["included_records"],
        archive["zero_baseline_records"],
        archive["defended_bytes"],
        archive["baseline_bytes"],
    ) == (4_000, 3_824, 176, 7_592_598_380, 3_326_013_453)
    assert archive["bandwidth_ratio"] == pytest.approx(2.282792444255336)
    estimator = receipt["csbuflo_estimator_contract"]
    assert estimator["max_samples_per_direction"] == 1_000
    assert estimator["direction_windows"] == ["outgoing", "incoming"]
    assert estimator["rate_quantization"] == (
        "2**floor(log2(upper-integer-median-interval))"
    )
    assert estimator["rate_quantization_resolution"] == "paper-Algorithm-2-floor-formula"
    discrepancy = receipt["csbuflo_paper_internal_discrepancies"]
    assert discrepancy == [
        {
            "classification": "known-internal-paper-prose-vs-algorithm-conflict",
            "paper_algorithm_location": "Algorithm-2-lines-382-and-395-396",
            "paper_algorithm_rule": "2**floor(log2(median-eligible-interval))",
            "paper_prose_location": "WPES-2014-lines-450-455",
            "paper_prose_rule": "round-up-rho-to-a-power-of-two",
            "resolution_basis": "algorithm-pseudocode-and-formula-control-the-independent-oracle",
            "resolved_rule": "2**floor(log2(upper-integer-median-interval))",
        }
    ]
    assert {source["source_id"] for source in receipt["external_sources"]} >= {
        "dyer-paper-pdf",
        "csbuflo-paper-pdf",
        "csbuflo-preprint-pdf",
        "csbuflo-clientloop-c",
        "csbuflo-serverloop-c",
        "csbuflo-cpsp-trace-archive",
    }
    source_hashes = {
        source["source_id"]: source["sha256"] for source in receipt["external_sources"]
    }
    assert source_hashes["csbuflo-clientloop-c"] == (
        "6f0148c8891756e39980edf47f2d5fbc254d2da7b4a8096a678cf3bb7777a36e"
    )
    assert source_hashes["csbuflo-serverloop-c"] == (
        "abc798cecb918d5c89ccec825224d543862e95a9650334bb0b5d4dd99e17a3a9"
    )


def test_checked_in_dlsvm_provenance_receipt_binds_resolved_variant() -> None:
    reference_path = REFERENCE_ROOT / "dlsvm-ccs-2012-v1.json"
    receipt_path = REFERENCE_ROOT / "dlsvm-ccs-2012-v1.receipt.json"
    reference_bytes = reference_path.read_bytes()
    reference = json.loads(reference_bytes)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

    assert receipt["reference_file"] == {
        "path": reference_path.name,
        "sha256": hashlib.sha256(reference_bytes).hexdigest(),
    }
    distance = reference["ccs_2012_specification"]["distance"]
    assert (
        distance["insertion_cost"],
        distance["deletion_cost"],
        distance["substitution_cost"],
        distance["transposition_cost"],
    ) == (2.0, 2.0, 2.0, 0.1)
    assert distance["code_review_resolution"].startswith("restricted-optimal-string-alignment")
    kernel = reference["ccs_2012_specification"]["kernel"]
    assert (kernel["gamma"], kernel["svm_c"]) == (1.0, 4.0)
    hosted = reference["official_follow_up_artifact"]
    assert hosted["classification"].endswith("not-byte-exact-CCS-2012-end-to-end-backend")
    assert reference["formal_qcsd_scaling"]["exact_unique_pair_count"] == 455_750
    assert {source["source_id"] for source in receipt["sources"]} >= {
        "cai-ccs-2012-paper-pdf",
        "wang-goldberg-wpes-2013-report-pdf",
        "wang-ca-osad-wrapper",
        "wang-cllev-cpp",
        "wang-clgen-stratify-cpp",
    }


def test_reference_gate_is_fail_closed_and_create_only(tmp_path: Path) -> None:
    output = tmp_path / "gate.json"
    with pytest.raises(ValueError, match="root is not a regular directory"):
        run_reference_gate(tmp_path / "missing", output)
    assert not output.exists()

    output.write_text("already present", encoding="utf-8")
    with pytest.raises(FileExistsError, match="already exists"):
        run_reference_gate(tmp_path / "missing", output)
    assert output.read_text(encoding="utf-8") == "already present"
