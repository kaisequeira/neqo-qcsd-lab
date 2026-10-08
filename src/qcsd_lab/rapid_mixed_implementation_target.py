"""Prospective per-mode implementations with an exact unchanged V1 import.

The BuFLO64 condition and optional FRONT V5 condition are new epochs. Original accepted rows retain their old
proof, Source, image, client, graph and condition labels. Declarations and
migration confer no new measurement credit or qualification authority.
"""
from datetime import datetime, timezone
from copy import deepcopy
import json
from pathlib import Path
import re

from . import rapid_fixed_condition_target as fixed
from .rapid_operation_facts import current_context

TARGET_TYPE = 'qcsd-prospective-fifty-site-per-mode-implementation-target-v2'
PROGRESS_TYPE = 'qcsd-original-verified-per-mode-implementation-slot-progress-v2'
CORPUS_TYPE = 'qcsd-exact-fifty-site-per-mode-implementation-sixty-four-slot-corpus-v2'
CONTRACT = 'exact-per-mode-implementation-conditions-original-graphs-and-16000-independent-slots-v2'
UNCHANGED = ('undefended', 'front', 'tamaraw', 'cs-buflo')
BUFLO_POLICY = 'rapid-v7-fixed-64ms-640s-duration-budget-v1'
PARAMETER_SHA256 = '5c35c9a6c0ce9d424b3e9cfc9e05a48713b9260fd1385dfba2d79048f58f283e'
PROVENANCE_SHA256 = '4276f8e06e8a5129e6f94463f64743edfd6cc06dd9519223196fa4eafdea362c'
INCOMING_POLICY = 'rapid-v7-half-period-32000us-ack-start-v1'
PREPARATION_POLICY = 'rapid-v7-buflo-cadence64ms-kernel-preparation-cutoff-release-plus-4000us-reserve-1000us-v1'
FRONT_POLICY = 'rapid-v7-front-450-600-sigma1-4-incoming10000us-padding-10pct-window10000us-reserve1000us-v5'
FRONT_CONFIGURATION_SHA256 = '910c4988276b74e25cfba20bcaefdaf2f7b25032e6110711145e197ddb4d6996'
FRONT_PROVENANCE_SHA256 = '9eb410e829fd6aafdc530af390045617283c4ec360ed73a0bd5b5af31be7e927'
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')


# Exact reviewed new-to-old inverses. Every accepted pair restores the entire
# historical module, including all original scientific guards and diagnostics.
_LEGACY_MODULE_INVERSES = {
    "acceptance": ("7eb599484082c59798e92466b5a56f267f772a98900975bcc41957d6b381e262", "d5a307212ae90fa1b8aaa47f05ecc9250d2bccf9d6cca169405648e027927964", (
        ("\nPOLICY = \"rapid-v5-half-period-10000us-v1\"\nACK_START_POLICY = \"rapid-v5-half-period-10000us-ack-start-v2\"\nFIELD = \"buflo_incoming_credit_release_policy\"\nBUFLO_KERNEL_PREPARATION_FIELD = \"buflo_kernel_preparation_policy\"\nBUFLO_KERNEL_PREPARATION_POLICY = \"rapid-v6-buflo-kernel-preparation-cutoff-release-plus-4000us-reserve-1000us-v1\"\nTAMARAW_FIELD = \"tamaraw_capture_policy\"\nTAMARAW_POLICY = \"rapid-v5-tamaraw-owned-retry-outgoing-10000us-v1\"\nTAMARAW_CREDIT_SEMANTICS = \"explicit-physical-ownership-with-pending-retry-v1\"\nFRONT_FIELD = \"front_capture_policy\"\nFRONT_POLICY = \"rapid-v5-front-bounded-outgoing-congestion-omission-1pct-v1\"\nFRONT_PADDING_POLICY = \"rapid-v5-front-bounded-outgoing-padding-omission-1pct-v2\"\n", "\nPOLICY = \"rapid-v5-half-period-10000us-v1\"\nACK_START_POLICY = \"rapid-v5-half-period-10000us-ack-start-v2\"\nCADENCE64_ACK_START_POLICY = \"rapid-v7-half-period-32000us-ack-start-v1\"\nCADENCE64_KERNEL_PREPARATION_POLICY = \"rapid-v7-buflo-cadence64ms-kernel-preparation-cutoff-release-plus-4000us-reserve-1000us-v1\"\nFIELD = \"buflo_incoming_credit_release_policy\"\nBUFLO_KERNEL_PREPARATION_FIELD = \"buflo_kernel_preparation_policy\"\nBUFLO_KERNEL_PREPARATION_POLICY = \"rapid-v6-buflo-kernel-preparation-cutoff-release-plus-4000us-reserve-1000us-v1\"\nTAMARAW_FIELD = \"tamaraw_capture_policy\"\nTAMARAW_POLICY = \"rapid-v5-tamaraw-owned-retry-outgoing-10000us-v1\"\nTAMARAW_CREDIT_SEMANTICS = \"explicit-physical-ownership-with-pending-retry-v1\"\nFRONT_LIGHT_POLICY = \"rapid-v7-front-450-600-sigma1-4-incoming10000us-padding-10pct-window10000us-reserve1000us-v5\"\nFRONT_LIGHT_CONFIGURATION_SHA256 = \"910c4988276b74e25cfba20bcaefdaf2f7b25032e6110711145e197ddb4d6996\"\nFRONT_FIELD = \"front_capture_policy\"\nFRONT_POLICY = \"rapid-v5-front-bounded-outgoing-congestion-omission-1pct-v1\"\nFRONT_PADDING_POLICY = \"rapid-v5-front-bounded-outgoing-padding-omission-1pct-v2\"\n"),
        ("    \"\"\"Opt into preparation reserve without changing physical traffic deadlines.\"\"\"\n    if BUFLO_KERNEL_PREPARATION_FIELD not in preparation:\n        return None\n    if (type(preparation[BUFLO_KERNEL_PREPARATION_FIELD]) is not str\n        or preparation[BUFLO_KERNEL_PREPARATION_FIELD] != BUFLO_KERNEL_PREPARATION_POLICY\n        or preparation.get(FIELD) != ACK_START_POLICY\n        or validate_buflo_preparation_policy(preparation) != ACK_START_POLICY):\n        raise ValueError(\"BuFLO kernel preparation reserve requires the explicit ACK-start rapid contract\")\n    return BUFLO_KERNEL_PREPARATION_POLICY\n\n\ndef apply_buflo_kernel_preparation_policy(manifest: Mapping[str, Any], *, policy: str) -> dict[str, Any]:\n    \"\"\"Derive a fresh opt-in before hashing and qualification; never rewrite evidence.\"\"\"\n    if type(policy) is not str or policy != BUFLO_KERNEL_PREPARATION_POLICY:\n        raise ValueError(\"BuFLO kernel preparation requires an explicit supported policy\")\n    preparation = manifest.get(\"preparation\")\n    if (not isinstance(preparation, Mapping) or BUFLO_KERNEL_PREPARATION_FIELD in preparation\n", "    \"\"\"Opt into preparation reserve without changing physical traffic deadlines.\"\"\"\n    if BUFLO_KERNEL_PREPARATION_FIELD not in preparation:\n        return None\n    policy = preparation[BUFLO_KERNEL_PREPARATION_FIELD]\n    incoming = CADENCE64_ACK_START_POLICY if policy == CADENCE64_KERNEL_PREPARATION_POLICY else ACK_START_POLICY\n    if (type(preparation[BUFLO_KERNEL_PREPARATION_FIELD]) is not str\n        or policy not in {BUFLO_KERNEL_PREPARATION_POLICY, CADENCE64_KERNEL_PREPARATION_POLICY}\n        or preparation.get(FIELD) != incoming\n        or validate_buflo_preparation_policy(preparation) != incoming):\n        raise ValueError(\"BuFLO kernel preparation reserve requires the explicit ACK-start rapid contract\")\n    return policy\n\n\ndef apply_buflo_kernel_preparation_policy(manifest: Mapping[str, Any], *, policy: str) -> dict[str, Any]:\n    \"\"\"Derive a fresh opt-in before hashing and qualification; never rewrite evidence.\"\"\"\n    if type(policy) is not str or policy not in {BUFLO_KERNEL_PREPARATION_POLICY, CADENCE64_KERNEL_PREPARATION_POLICY}:\n        raise ValueError(\"BuFLO kernel preparation requires an explicit supported policy\")\n    preparation = manifest.get(\"preparation\")\n    if (not isinstance(preparation, Mapping) or BUFLO_KERNEL_PREPARATION_FIELD in preparation\n"),
        ("        \"rolling_preparation_after_release_us\": 4_000, \"outgoing_physical_window_us\": 5_000,\n        \"preparation_reserve_us\": 1_000, \"tick_zero_before_release\": True,\n        \"allow_omissions\": False, \"paper_equivalent\": False, \"scientific_credit\": False}\n    if not isinstance(marker, Mapping) or not _exact_json(marker, expected):\n        raise ValueError(\"invalid source-bound BuFLO kernel preparation reserve marker\")\n    return marker\n", "        \"rolling_preparation_after_release_us\": 4_000, \"outgoing_physical_window_us\": 5_000,\n        \"preparation_reserve_us\": 1_000, \"tick_zero_before_release\": True,\n        \"allow_omissions\": False, \"paper_equivalent\": False, \"scientific_credit\": False}\n    if isinstance(marker, Mapping) and marker.get(\"policy\") == CADENCE64_KERNEL_PREPARATION_POLICY:\n        expected.update(policy=CADENCE64_KERNEL_PREPARATION_POLICY, period_us=64_000)\n    if not isinstance(marker, Mapping) or not _exact_json(marker, expected):\n        raise ValueError(\"invalid source-bound BuFLO kernel preparation reserve marker\")\n    return marker\n"),
        ("    buflo = isinstance(defense, Mapping) and defense.get(\"kind\") == \"buflo\"\n    wakeups = run.get(\"runner_wakeup_metrics\")\n    raw = wakeups.get(\"buflo_kernel_tx\") if isinstance(wakeups, Mapping) else None\n    new_raw = isinstance(raw, Mapping) and raw.get(\"schema_version\") == 12\n    if BUFLO_KERNEL_PREPARATION_FIELD in run:\n        if declared is None or not buflo:\n            raise ValueError(\"native BuFLO preparation reserve lacks matching prepared source\")\n        marker = validate_buflo_kernel_preparation_marker(run[BUFLO_KERNEL_PREPARATION_FIELD])\n        incoming = run.get(FIELD)\n        if (not new_raw or type(wakeups.get(\"schema_version\")) is not int or wakeups[\"schema_version\"] != 21\n            or not _exact_json(raw.get(\"preparation_policy\"), marker)\n            or not isinstance(incoming, Mapping) or incoming.get(\"policy\") != ACK_START_POLICY\n            or buflo_incoming_release_window(run) != 10_000):\n            raise ValueError(\"BuFLO reserve run marker differs from its opted-in raw kernel receipt\")\n    elif declared is not None and buflo:\n        raise ValueError(\"prepared BuFLO kernel reserve lacks its native marker\")\n    elif new_raw or isinstance(wakeups, Mapping) and wakeups.get(\"schema_version\") == 21:\n        raise ValueError(\"new BuFLO kernel reserve receipt lacks its prepared and native markers\")\n\n\n", "    buflo = isinstance(defense, Mapping) and defense.get(\"kind\") == \"buflo\"\n    wakeups = run.get(\"runner_wakeup_metrics\")\n    raw = wakeups.get(\"buflo_kernel_tx\") if isinstance(wakeups, Mapping) else None\n    new_raw = isinstance(raw, Mapping) and type(raw.get(\"schema_version\")) is int and raw[\"schema_version\"] in {12, 13}\n    if BUFLO_KERNEL_PREPARATION_FIELD in run:\n        if declared is None or not buflo:\n            raise ValueError(\"native BuFLO preparation reserve lacks matching prepared source\")\n        marker = validate_buflo_kernel_preparation_marker(run[BUFLO_KERNEL_PREPARATION_FIELD])\n        prospective = declared == CADENCE64_KERNEL_PREPARATION_POLICY\n        if marker[\"policy\"] != declared:\n            raise ValueError(\"Native BuFLO preparation policy differs from its prospective prepared source\")\n        incoming = run.get(FIELD)\n        if (not new_raw or type(wakeups.get(\"schema_version\")) is not int or wakeups[\"schema_version\"] != (22 if prospective else 21)\n            or raw.get(\"schema_version\") != (13 if prospective else 12)\n            or not _exact_json(raw.get(\"preparation_policy\"), marker)\n            or not isinstance(incoming, Mapping) or incoming.get(\"policy\") != (CADENCE64_ACK_START_POLICY if prospective else ACK_START_POLICY)\n            or buflo_incoming_release_window(run) != (32_000 if prospective else 10_000)):\n            raise ValueError(\"BuFLO reserve run marker differs from its opted-in raw kernel receipt\")\n    elif declared is not None and buflo:\n        raise ValueError(\"prepared BuFLO kernel reserve lacks its native marker\")\n    elif new_raw or isinstance(wakeups, Mapping) and wakeups.get(\"schema_version\") in {21, 22}:\n        raise ValueError(\"new BuFLO kernel reserve receipt lacks its prepared and native markers\")\n\n\n"),
        ("    if FRONT_FIELD not in preparation:\n        return None\n    value = preparation[FRONT_FIELD]\n    if (type(value) is not str or value not in {FRONT_POLICY, FRONT_PADDING_POLICY, FRONT_WINDOW_POLICY, FRONT_RESERVE_POLICY}\n        or preparation.get(\"primary_document_identity_policy\") != VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY\n        or preparation.get(\"application_response_policy\") != COMPLETED_TERMINAL_HTTP_ERRORS_POLICY\n        or preparation.get(\"qualified_chaff_origin_policy\") != APPROVED_ORIGINS_CHAFF_POLICY):\n", "    if FRONT_FIELD not in preparation:\n        return None\n    value = preparation[FRONT_FIELD]\n    if (type(value) is not str or value not in {FRONT_POLICY, FRONT_PADDING_POLICY, FRONT_WINDOW_POLICY, FRONT_RESERVE_POLICY, FRONT_LIGHT_POLICY}\n        or preparation.get(\"primary_document_identity_policy\") != VARIABLE_PRIMARY_DOCUMENT_BODY_POLICY\n        or preparation.get(\"application_response_policy\") != COMPLETED_TERMINAL_HTTP_ERRORS_POLICY\n        or preparation.get(\"qualified_chaff_origin_policy\") != APPROVED_ORIGINS_CHAFF_POLICY):\n"),
        ("        \"packet_size\": 1200, \"n_client_packets\": 900, \"n_server_packets\": 1200,\n        \"paper_equivalent\": False, \"scientific_credit\": False,\n    }\n    if isinstance(marker, Mapping) and marker.get(\"policy\") in (FRONT_PADDING_POLICY, FRONT_WINDOW_POLICY, FRONT_RESERVE_POLICY):\n        expected.update(schema_version=2, policy=FRONT_PADDING_POLICY)\n        del expected[\"outgoing_omission_reason\"]\n        expected[\"outgoing_omission_reasons\"] = [\"CongestionLimited\", \"DeadlineExpired\"]\n        expected[\"require_pure_padding\"] = True\n        if marker[\"policy\"] in (FRONT_WINDOW_POLICY, FRONT_RESERVE_POLICY):\n            expected.update(schema_version=3, policy=FRONT_WINDOW_POLICY,\n                outgoing_omission_ratio_denominator=10, outgoing_release_window_us=10000,\n                historical_outgoing_release_window_us=5000)\n            if marker[\"policy\"] == FRONT_RESERVE_POLICY:\n                expected.update(schema_version=4, policy=FRONT_RESERVE_POLICY,\n                    outgoing_construction_window_us=9000, outgoing_preparation_reserve_us=1000,\n                    expired_construction_target=\"not-built-not-sent\")\n    if (not isinstance(marker, Mapping) or set(marker) != set(expected)\n        or any(type(marker[key]) is not type(value) or marker[key] != value\n               for key, value in expected.items())):\n", "        \"packet_size\": 1200, \"n_client_packets\": 900, \"n_server_packets\": 1200,\n        \"paper_equivalent\": False, \"scientific_credit\": False,\n    }\n    if isinstance(marker, Mapping) and marker.get(\"policy\") in (FRONT_PADDING_POLICY, FRONT_WINDOW_POLICY, FRONT_RESERVE_POLICY, FRONT_LIGHT_POLICY):\n        expected.update(schema_version=2, policy=FRONT_PADDING_POLICY)\n        del expected[\"outgoing_omission_reason\"]\n        expected[\"outgoing_omission_reasons\"] = [\"CongestionLimited\", \"DeadlineExpired\"]\n        expected[\"require_pure_padding\"] = True\n        if marker[\"policy\"] in (FRONT_WINDOW_POLICY, FRONT_RESERVE_POLICY, FRONT_LIGHT_POLICY):\n            expected.update(schema_version=3, policy=FRONT_WINDOW_POLICY,\n                outgoing_omission_ratio_denominator=10, outgoing_release_window_us=10000,\n                historical_outgoing_release_window_us=5000)\n            if marker[\"policy\"] in (FRONT_RESERVE_POLICY, FRONT_LIGHT_POLICY):\n                expected.update(schema_version=4, policy=FRONT_RESERVE_POLICY,\n                    outgoing_construction_window_us=9000, outgoing_preparation_reserve_us=1000,\n                    expired_construction_target=\"not-built-not-sent\")\n                if marker[\"policy\"] == FRONT_LIGHT_POLICY:\n                    expected.update(schema_version=5, policy=FRONT_LIGHT_POLICY,\n                        n_client_packets=450, n_server_packets=600, peak_minimum_seconds=1.0,\n                        peak_maximum_seconds=4.0, control_interval_us=10000,\n                        incoming_release_window_us=10000, configuration_sha256=FRONT_LIGHT_CONFIGURATION_SHA256)\n    if (not isinstance(marker, Mapping) or set(marker) != set(expected)\n        or any(type(marker[key]) is not type(value) or marker[key] != value\n               for key, value in expected.items())):\n"),
        ("\ndef validate_front_capture_run(run: Mapping[str, Any]) -> Mapping[str, Any]:\n    marker = validate_front_capture_marker(run.get(FRONT_FIELD))\n    resolved = run.get(\"resolved_configuration\")\n    defense = resolved.get(\"defense\") if isinstance(resolved, Mapping) else None\n    expected = {\"kind\": \"front\", \"n_client_packets\": 900, \"n_server_packets\": 1200,\n", "\ndef validate_front_capture_run(run: Mapping[str, Any]) -> Mapping[str, Any]:\n    marker = validate_front_capture_marker(run.get(FRONT_FIELD))\n    if marker[\"policy\"] == FRONT_LIGHT_POLICY:\n        from .front_fixed_configuration import POLICY as CONFIGURATION_POLICY, configuration_sha256, validate_run\n        if CONFIGURATION_POLICY != FRONT_LIGHT_POLICY or configuration_sha256() != FRONT_LIGHT_CONFIGURATION_SHA256:\n            raise ValueError(\"FRONT V5 configuration authority differs from its exact registered bytes\")\n        validate_run(run, selected_policy=CONFIGURATION_POLICY)\n        if (run.get(\"primary_document_identity_policy\") != \"variable-primary-document-body-v1\"\n            or run.get(\"application_response_policy\") != \"completed-terminal-http-errors-v1\"\n            or run.get(\"defense_parameters\") is not None):\n            raise ValueError(\"FRONT V5 capture differs from its complete source-bound configuration\")\n        return marker\n    resolved = run.get(\"resolved_configuration\")\n    defense = resolved.get(\"defense\") if isinstance(resolved, Mapping) else None\n    expected = {\"kind\": \"front\", \"n_client_packets\": 900, \"n_server_packets\": 1200,\n"),
        ("            or isinstance(diagnostics, Mapping) and \"buflo_incoming_startup\" in diagnostics)\n\n\ndef validate_buflo_startup_receipt(value: Any, *, require_armed: bool = True) -> Mapping[str, Any]:\n    \"\"\"Validate the actual DTO, including an honest unarmed failure snapshot.\"\"\"\n    fixed = {\"schema_version\": 1, \"policy\": STARTUP_POLICY, \"time_basis\": STARTUP_TIME_BASIS,\n             \"period_us\": 20_000, \"packet_size_bytes\": 1_200}\n    keys = {*fixed, \"armed\", \"startup_suppressed_opportunities\", *_STARTUP_NULLABLE}\n    if (not isinstance(value, Mapping) or set(value) != keys\n        or any(type(value[key]) is not type(expected) or value[key] != expected\n", "            or isinstance(diagnostics, Mapping) and \"buflo_incoming_startup\" in diagnostics)\n\n\ndef validate_buflo_startup_receipt(value: Any, *, require_armed: bool = True, period_us: int = 20_000) -> Mapping[str, Any]:\n    \"\"\"Validate the actual DTO, including an honest unarmed failure snapshot.\"\"\"\n    if type(period_us) is not int or period_us not in {20_000, 64_000}:\n        raise ValueError(\"unsupported source-bound BuFLO startup cadence\")\n    fixed = {\"schema_version\": 1, \"policy\": STARTUP_POLICY, \"time_basis\": STARTUP_TIME_BASIS,\n             \"period_us\": period_us, \"packet_size_bytes\": 1_200}\n    keys = {*fixed, \"armed\", \"startup_suppressed_opportunities\", *_STARTUP_NULLABLE}\n    if (not isinstance(value, Mapping) or set(value) != keys\n        or any(type(value[key]) is not type(expected) or value[key] != expected\n"),
        ("        or value[\"ready_resource_id\"] == 0 or value[\"request_stream_final_size\"] == 0\n        or value[\"eligible_exact_capacity_bytes\"] < 1_200\n        or value[\"ready_at_us\"] < value[\"ack_observed_at_us\"]\n        or value[\"armed_at_us\"] != (value[\"ready_at_us\"] // 20_000 + 1) * 20_000\n        or value[\"armed_at_us\"] > _U64_MAX\n        or value[\"startup_suppressed_opportunities\"] != value[\"armed_at_us\"] // 20_000):\n        raise ValueError(\"BuFLO incoming startup violates its ACK, capacity or strict cadence barrier\")\n    return value\n\n", "        or value[\"ready_resource_id\"] == 0 or value[\"request_stream_final_size\"] == 0\n        or value[\"eligible_exact_capacity_bytes\"] < 1_200\n        or value[\"ready_at_us\"] < value[\"ack_observed_at_us\"]\n        or value[\"armed_at_us\"] != (value[\"ready_at_us\"] // period_us + 1) * period_us\n        or value[\"armed_at_us\"] > _U64_MAX\n        or value[\"startup_suppressed_opportunities\"] != value[\"armed_at_us\"] // period_us):\n        raise ValueError(\"BuFLO incoming startup violates its ACK, capacity or strict cadence barrier\")\n    return value\n\n"),
        ("    if FIELD not in preparation:\n        return None\n    policy = preparation[FIELD]\n    if (not isinstance(policy, str) or policy not in {POLICY, ACK_START_POLICY}\n        or preparation.get(\"primary_document_identity_policy\") != \"variable-primary-document-body-v1\"\n        or preparation.get(\"application_response_policy\") != \"completed-terminal-http-errors-v1\"\n        or policy == ACK_START_POLICY\n        and preparation.get(\"qualified_chaff_origin_policy\") != \"prepared-approved-origins-v1\"):\n        raise ValueError(\"BufLO incoming release policy requires the explicit rapid preparation contract\")\n    return policy\n\n\ndef incoming_release_window_from_policy(marker: Any) -> int:\n    policy = marker.get(\"policy\") if isinstance(marker, Mapping) else None\n    expected = {\"schema_version\": 1, \"source\": \"bound-preparation-v1\", \"policy\": policy,\n                \"incoming_release_window_us\": 10_000, \"period_us\": 20_000,\n                \"cell_bytes\": 1_200, \"scientific_credit\": False}\n    if (not isinstance(policy, str) or policy not in {POLICY, ACK_START_POLICY}\n        or not isinstance(marker, Mapping) or set(marker) != set(expected)\n        or any(type(marker[key]) is not type(value) or marker[key] != value\n               for key, value in expected.items())):\n        raise ValueError(\"invalid BufLO incoming release policy receipt\")\n    return 10_000\n\n\ndef buflo_incoming_release_window(run: Mapping[str, Any]) -> int:\n", "    if FIELD not in preparation:\n        return None\n    policy = preparation[FIELD]\n    if (not isinstance(policy, str) or policy not in {POLICY, ACK_START_POLICY, CADENCE64_ACK_START_POLICY}\n        or preparation.get(\"primary_document_identity_policy\") != \"variable-primary-document-body-v1\"\n        or preparation.get(\"application_response_policy\") != \"completed-terminal-http-errors-v1\"\n        or policy in {ACK_START_POLICY, CADENCE64_ACK_START_POLICY}\n        and preparation.get(\"qualified_chaff_origin_policy\") != \"prepared-approved-origins-v1\"):\n        raise ValueError(\"BufLO incoming release policy requires the explicit rapid preparation contract\")\n    if policy == CADENCE64_ACK_START_POLICY and preparation.get(BUFLO_KERNEL_PREPARATION_FIELD) != CADENCE64_KERNEL_PREPARATION_POLICY:\n        raise ValueError(\"prospective 64ms BuFLO requires its exact preparation reserve\")\n    return policy\n\n\ndef incoming_release_window_from_policy(marker: Any) -> int:\n    policy = marker.get(\"policy\") if isinstance(marker, Mapping) else None\n    period_us = 64_000 if policy == CADENCE64_ACK_START_POLICY else 20_000\n    expected = {\"schema_version\": 1, \"source\": \"bound-preparation-v1\", \"policy\": policy,\n                \"incoming_release_window_us\": period_us // 2, \"period_us\": period_us,\n                \"cell_bytes\": 1_200, \"scientific_credit\": False}\n    if (not isinstance(policy, str) or policy not in {POLICY, ACK_START_POLICY, CADENCE64_ACK_START_POLICY}\n        or not isinstance(marker, Mapping) or set(marker) != set(expected)\n        or any(type(marker[key]) is not type(value) or marker[key] != value\n               for key, value in expected.items())):\n        raise ValueError(\"invalid BufLO incoming release policy receipt\")\n    return period_us // 2\n\n\ndef buflo_incoming_release_window(run: Mapping[str, Any]) -> int:\n"),
        ("        or run.get(\"primary_document_identity_policy\") != \"variable-primary-document-body-v1\"\n        or run.get(\"application_response_policy\") != \"completed-terminal-http-errors-v1\"):\n        raise ValueError(\"BufLO incoming release policy is outside its native rapid contract\")\n    if run[FIELD][\"policy\"] == ACK_START_POLICY:\n        if (not isinstance(resolved, Mapping) or resolved_kind != \"buflo\"\n            or type(resolved.get(\"control_interval_us\")) is not int\n            or resolved[\"control_interval_us\"] != 5_000):\n            raise ValueError(\"BuFLO ACK-start policy changes the fixed outgoing deadline\")\n        summary = run.get(\"buflo_summary\")\n        validate_buflo_startup_receipt(summary.get(\"incoming_startup\") if isinstance(summary, Mapping) else None)\n    elif _startup_present(run):\n        raise ValueError(\"BuFLO incoming startup lacks its V2 policy\")\n    return window\n", "        or run.get(\"primary_document_identity_policy\") != \"variable-primary-document-body-v1\"\n        or run.get(\"application_response_policy\") != \"completed-terminal-http-errors-v1\"):\n        raise ValueError(\"BufLO incoming release policy is outside its native rapid contract\")\n    if run[FIELD][\"policy\"] in {ACK_START_POLICY, CADENCE64_ACK_START_POLICY}:\n        if (not isinstance(resolved, Mapping) or resolved_kind != \"buflo\"\n            or type(resolved.get(\"control_interval_us\")) is not int\n            or resolved[\"control_interval_us\"] != 5_000):\n            raise ValueError(\"BuFLO ACK-start policy changes the fixed outgoing deadline\")\n        prospective = run[FIELD][\"policy\"] == CADENCE64_ACK_START_POLICY\n        if prospective:\n            from .buflo_duration_budget import CADENCE64_RECEIPT, CADENCE64_PARAMETER_SHA256, RUN_FIELD, validate_receipt\n            validate_receipt(parameters.get(RUN_FIELD))\n            wakeups = run.get(\"runner_wakeup_metrics\")\n            raw = wakeups.get(\"buflo_kernel_tx\") if isinstance(wakeups, Mapping) else None\n            marker = validate_buflo_kernel_preparation_marker(run.get(BUFLO_KERNEL_PREPARATION_FIELD))\n            if (not _exact_json(parameters[RUN_FIELD], CADENCE64_RECEIPT)\n                or run.get(\"method\") != \"GET\"\n                or parameters.get(\"sha256\") != CADENCE64_PARAMETER_SHA256\n                or not isinstance(parameters.get(\"path\"), str) or not parameters[\"path\"]\n                or defense.get(\"parameters\") != parameters[\"path\"]\n                or parameters.get(\"implementation_scope\") != \"client_only_quic\"\n                or parameters.get(\"paper_equivalent\") is not False\n                or marker[\"policy\"] != CADENCE64_KERNEL_PREPARATION_POLICY\n                or not isinstance(raw, Mapping) or type(raw.get(\"schema_version\")) is not int\n                or raw[\"schema_version\"] != 13\n                or not isinstance(wakeups, Mapping) or type(wakeups.get(\"schema_version\")) is not int\n                or wakeups[\"schema_version\"] != 22\n                or not _exact_json(raw.get(\"preparation_policy\"), marker)):\n                raise ValueError(\"64ms BuFLO lacks matching Native parameters, preparation and13/22 receipts\")\n        summary = run.get(\"buflo_summary\")\n        validate_buflo_startup_receipt(summary.get(\"incoming_startup\") if isinstance(summary, Mapping) else None,\n            period_us=64_000 if prospective else 20_000)\n    elif _startup_present(run):\n        raise ValueError(\"BuFLO incoming startup lacks its V2 policy\")\n    return window\n"),
        ("        buflo_incoming_release_window(run)\n        if run[FIELD][\"policy\"] != policy:\n            raise ValueError(\"native BufLO incoming release policy differs from its prepared source opt-in\")\n        if policy == ACK_START_POLICY:\n            validate_buflo_startup_evidence(run, runner_directory=runner_directory, prepared=prepared)\n    elif FIELD in run:\n        raise ValueError(\"native BufLO incoming release policy lacks matching prepared source opt-in\")\n", "        buflo_incoming_release_window(run)\n        if run[FIELD][\"policy\"] != policy:\n            raise ValueError(\"native BufLO incoming release policy differs from its prepared source opt-in\")\n        if policy in {ACK_START_POLICY, CADENCE64_ACK_START_POLICY}:\n            validate_buflo_startup_evidence(run, runner_directory=runner_directory, prepared=prepared)\n    elif FIELD in run:\n        raise ValueError(\"native BufLO incoming release policy lacks matching prepared source opt-in\")\n"),
        ("    return path\n\n\ndef validate_buflo_startup_schedule(startup: Mapping[str, Any], rows: list[Mapping[str, Any]]) -> None:\n    \"\"\"Reopen the actual target sets; suppressed startup opportunities have no rows.\"\"\"\n    validate_buflo_startup_receipt(startup)\n    targets: dict[str, list[int]] = {\"outgoing\": [], \"incoming\": []}\n    for row in rows:\n        direction = row.get(\"direction\")\n", "    return path\n\n\ndef validate_buflo_startup_schedule(startup: Mapping[str, Any], rows: list[Mapping[str, Any]], *, period_us: int = 20_000) -> None:\n    \"\"\"Reopen the actual target sets; suppressed startup opportunities have no rows.\"\"\"\n    validate_buflo_startup_receipt(startup, period_us=period_us)\n    targets: dict[str, list[int]] = {\"outgoing\": [], \"incoming\": []}\n    for row in rows:\n        direction = row.get(\"direction\")\n"),
        ("    for direction, first in ((\"outgoing\", 0), (\"incoming\", startup[\"armed_at_us\"])):\n        ordered = sorted(targets[direction])\n        if (not ordered or ordered[0] != first\n            or any(current - previous != 20_000\n                   for previous, current in zip(ordered, ordered[1:]))):\n            raise ValueError(\"BuFLO startup schedule violates its actual first tick or active cadence\")\n    if (len(targets[\"outgoing\"]) - len(targets[\"incoming\"]) != startup[\"startup_suppressed_opportunities\"]\n", "    for direction, first in ((\"outgoing\", 0), (\"incoming\", startup[\"armed_at_us\"])):\n        ordered = sorted(targets[direction])\n        if (not ordered or ordered[0] != first\n            or any(current - previous != period_us\n                   for previous, current in zip(ordered, ordered[1:]))):\n            raise ValueError(\"BuFLO startup schedule violates its actual first tick or active cadence\")\n    if (len(targets[\"outgoing\"]) - len(targets[\"incoming\"]) != startup[\"startup_suppressed_opportunities\"]\n"),
        ("                                  schedule_rows: list[Mapping[str, Any]] | None = None) -> Mapping[str, Any]:\n    \"\"\"Re-derive terminal ACK coverage from paired production/reduction records.\"\"\"\n    marker = run.get(FIELD)\n    if not isinstance(marker, Mapping) or marker.get(\"policy\") != ACK_START_POLICY:\n        raise ValueError(\"BuFLO startup evidence requires its source-bound V2 marker\")\n    buflo_incoming_release_window(run)\n    startup = run[\"buflo_summary\"][\"incoming_startup\"]\n", "                                  schedule_rows: list[Mapping[str, Any]] | None = None) -> Mapping[str, Any]:\n    \"\"\"Re-derive terminal ACK coverage from paired production/reduction records.\"\"\"\n    marker = run.get(FIELD)\n    if not isinstance(marker, Mapping) or marker.get(\"policy\") not in {ACK_START_POLICY, CADENCE64_ACK_START_POLICY}:\n        raise ValueError(\"BuFLO startup evidence requires its source-bound V2 marker\")\n    buflo_incoming_release_window(run)\n    startup = run[\"buflo_summary\"][\"incoming_startup\"]\n"),
        ("    if schedule_rows is None:\n        with _regular_child(Path(runner_directory), \"schedule.csv\").open(newline=\"\", encoding=\"utf-8\") as source:\n            schedule_rows = list(csv.DictReader(source))\n    validate_buflo_startup_schedule(startup, schedule_rows)\n    return startup\n", "    if schedule_rows is None:\n        with _regular_child(Path(runner_directory), \"schedule.csv\").open(newline=\"\", encoding=\"utf-8\") as source:\n            schedule_rows = list(csv.DictReader(source))\n    validate_buflo_startup_schedule(startup, schedule_rows,\n        period_us=64_000 if marker[\"policy\"] == CADENCE64_ACK_START_POLICY else 20_000)\n    return startup\n"),
    )),
    "duration": ("93aebb8c7fafc5788ad56003fa76457f0d7c7ffa369dad0b425f2a7edcc471b1", "eba7deab77a6d63c784c8b2adc5731ab0cc3e5106823f7f4a8dca7be8b893864", (
        ("    \"max_events\": 10_000,\n    \"duration_budget_us\": 200_000_000,\n}\n_SHA256 = re.compile(r\"[0-9a-f]{64}\\Z\")\n\n\n", "    \"max_events\": 10_000,\n    \"duration_budget_us\": 200_000_000,\n}\n# Separate prospective policy; historical constants and canonical bytes stay exact.\nCADENCE64_POLICY = \"rapid-v7-fixed-64ms-640s-duration-budget-v1\"\nCADENCE64_INPUT_POLICY = \"reviewed-buflo-fixed-cadence64-duration640-study-candidate-v1\"\nCADENCE64_PARAMETER_PATH = \"config/defense-params/buflo-cadence64-budget640.json\"\nCADENCE64_PARAMETER_SEMANTICS = (\n    \"qcsd-udp1200-client-only-adaptation-with-explicit-fixed-64ms-cadence-\"\n    \"640-second-event-budget-and-versioned-terminal-subcell-policy\"\n)\nCADENCE64_PARAMETERS = {**PARAMETERS, \"interval_us\": 64_000, PARAMETER_FIELD: CADENCE64_POLICY}\nCADENCE64_RECEIPT = {**RECEIPT, \"policy\": CADENCE64_POLICY, \"interval_us\": 64_000,\n                     \"duration_budget_us\": 640_000_000}\n_SHA256 = re.compile(r\"[0-9a-f]{64}\\Z\")\n\n\n"),
        ("PARAMETER_SHA256 = hashlib.sha256(parameter_bytes()).hexdigest()\n\n\ndef _exact(value: Any, expected: Mapping[str, Any], label: str) -> None:\n    if (not isinstance(value, Mapping) or set(value) != set(expected)\n        or any(type(value[key]) is not type(item) or value[key] != item\n               for key, item in expected.items())):\n        raise ValueError(f\"{label} requires its exact typed fixed 200-second contract\")\n\n\ndef validate_parameters(value: Any, *, ceiling: int = 1_200) -> None:\n    _exact(value, PARAMETERS, \"BuFLO duration parameters\")\n    if type(ceiling) is not int or ceiling < 1_200:\n        raise ValueError(\"BuFLO duration parameters exceed the UDP ceiling\")\n\n\ndef validate_receipt(value: Any) -> None:\n    _exact(value, RECEIPT, \"Native BuFLO duration receipt\")\n\n\ndef _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:\n    value = {}\n    for key, item in pairs:\n        if key in value:\n            raise ValueError(\"BuFLO duration parameters contain a duplicate key\")\n        value[key] = item\n    return value\n\n\ndef parse_parameters(raw: bytes) -> Mapping[str, Any]:\n    if type(raw) is not bytes:\n        raise ValueError(\"BuFLO duration parameter evidence must be exact bytes\")\n    value = json.loads(raw, object_pairs_hook=_unique_object)\n    validate_parameters(value)\n    return value\n\n\ndef validate_native_receipt(run: Mapping[str, Any], raw: bytes, *,\n                            expected_path: str | None = None) -> dict[str, Any]:\n    \"\"\"Join the actual raw marker to the exact hashed parsed parameter file.\n\n    The recorded parameter path may be an execution-namespace path; the frozen\n    artifact bytes provide the content proof. A live caller can additionally\n    require its actual supplied path. No timing or completion guard is waived.\n    \"\"\"\n    parse_parameters(raw)\n    parameter = run.get(\"defense_parameters\")\n    resolved = run.get(\"resolved_configuration\")\n    defense = resolved.get(\"defense\") if isinstance(resolved, Mapping) else None\n", "PARAMETER_SHA256 = hashlib.sha256(parameter_bytes()).hexdigest()\n\n\ndef cadence64_parameter_bytes() -> bytes:\n    return (json.dumps(CADENCE64_PARAMETERS, indent=2, allow_nan=False) + \"\\n\").encode()\n\n\nCADENCE64_PARAMETER_SHA256 = hashlib.sha256(cadence64_parameter_bytes()).hexdigest()\n\n\ndef _exact(value: Any, expected: Mapping[str, Any], label: str) -> None:\n    if (not isinstance(value, Mapping) or set(value) != set(expected)\n        or any(type(value[key]) is not type(item) or value[key] != item\n               for key, item in expected.items())):\n        raise ValueError(f\"{label} requires its exact typed fixed 200-second contract\")\n\n\ndef validate_parameters(value: Any, *, ceiling: int = 1_200) -> None:\n    expected = CADENCE64_PARAMETERS if isinstance(value, Mapping) and value.get(PARAMETER_FIELD) == CADENCE64_POLICY else PARAMETERS\n    _exact(value, expected, \"BuFLO duration parameters\")\n    if type(ceiling) is not int or ceiling < 1_200:\n        raise ValueError(\"BuFLO duration parameters exceed the UDP ceiling\")\n\n\ndef validate_receipt(value: Any) -> None:\n    expected = CADENCE64_RECEIPT if isinstance(value, Mapping) and value.get(\"policy\") == CADENCE64_POLICY else RECEIPT\n    _exact(value, expected, \"Native BuFLO duration receipt\")\n\n\ndef _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:\n    value = {}\n    for key, item in pairs:\n        if key in value:\n            raise ValueError(\"BuFLO duration parameters contain a duplicate key\")\n        value[key] = item\n    return value\n\n\ndef parse_parameters(raw: bytes) -> Mapping[str, Any]:\n    if type(raw) is not bytes:\n        raise ValueError(\"BuFLO duration parameter evidence must be exact bytes\")\n    value = json.loads(raw, object_pairs_hook=_unique_object)\n    validate_parameters(value)\n    return value\n\n\ndef validate_native_receipt(run: Mapping[str, Any], raw: bytes, *,\n                            expected_path: str | None = None) -> dict[str, Any]:\n    \"\"\"Join the actual raw marker to the exact hashed parsed parameter file.\n\n    The recorded parameter path may be an execution-namespace path; the frozen\n    artifact bytes provide the content proof. A live caller can additionally\n    require its actual supplied path. No timing or completion guard is waived.\n    \"\"\"\n    parsed = parse_parameters(raw)\n    parameter = run.get(\"defense_parameters\")\n    resolved = run.get(\"resolved_configuration\")\n    defense = resolved.get(\"defense\") if isinstance(resolved, Mapping) else None\n"),
        ("        or defense.get(\"parameters\") != parameter[\"path\"]\n        or expected_path is not None and parameter[\"path\"] != expected_path):\n        raise ValueError(\"Native BuFLO duration receipt differs from its hashed parsed parameters\")\n    validate_receipt(parameter.get(RUN_FIELD))\n    return {RUN_FIELD: dict(parameter[RUN_FIELD]),\n            \"buflo_duration_budget_parameter_sha256\": digest}\n\n", "        or defense.get(\"parameters\") != parameter[\"path\"]\n        or expected_path is not None and parameter[\"path\"] != expected_path):\n        raise ValueError(\"Native BuFLO duration receipt differs from its hashed parsed parameters\")\n    expected = CADENCE64_RECEIPT if parsed[PARAMETER_FIELD] == CADENCE64_POLICY else RECEIPT\n    _exact(parameter.get(RUN_FIELD), expected, \"Native BuFLO duration receipt\")\n    return {RUN_FIELD: dict(parameter[RUN_FIELD]),\n            \"buflo_duration_budget_parameter_sha256\": digest}\n\n"),
        ("    digest = metrics.get(\"buflo_duration_budget_parameter_sha256\")\n    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:\n        raise ValueError(\"BuFLO schedule budget has no exact parameter-byte identity\")\n    return 10_000, 200_000_000\n\n\ndef capture_limits(mode: str, original: Mapping[str, Any], *, policy: str | None) -> dict[str, Any]:\n    \"\"\"Derive recorder limits after an explicit prospective plan amendment.\"\"\"\n    if policy is not None and (type(policy) is not str or policy != POLICY):\n        raise ValueError(\"unknown BuFLO duration budget policy\")\n    result = dict(original)\n    if policy == POLICY and mode == \"buflo\":\n        if (type(result.get(\"timeout_seconds\")) is not int or result[\"timeout_seconds\"] != 120\n            or type(result.get(\"capture_seconds\")) is not int or result[\"capture_seconds\"] != 180):\n            raise ValueError(\"BuFLO duration limits must derive from the original 120/180-second limits\")\n        result.update(timeout_seconds=240, capture_seconds=300)\n    return result\n\n\n", "    digest = metrics.get(\"buflo_duration_budget_parameter_sha256\")\n    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:\n        raise ValueError(\"BuFLO schedule budget has no exact parameter-byte identity\")\n    receipt = metrics[RUN_FIELD]\n    return receipt[\"max_events\"], receipt[\"duration_budget_us\"]\n\n\ndef capture_limits(mode: str, original: Mapping[str, Any], *, policy: str | None) -> dict[str, Any]:\n    \"\"\"Derive recorder limits after an explicit prospective plan amendment.\"\"\"\n    if policy is not None and (type(policy) is not str or policy not in {POLICY, CADENCE64_POLICY}):\n        raise ValueError(\"unknown BuFLO duration budget policy\")\n    result = dict(original)\n    if policy in {POLICY, CADENCE64_POLICY} and mode == \"buflo\":\n        if (type(result.get(\"timeout_seconds\")) is not int or result[\"timeout_seconds\"] != 120\n            or type(result.get(\"capture_seconds\")) is not int or result[\"capture_seconds\"] != 180):\n            raise ValueError(\"BuFLO duration limits must derive from the original 120/180-second limits\")\n        if policy == CADENCE64_POLICY:\n            result.update(timeout_seconds=680, capture_seconds=740)\n        else:\n            result.update(timeout_seconds=240, capture_seconds=300)\n    return result\n\n\n"),
    )),
    "front_preparation": ("350dfd5a67a7b8169714573304f9dbd8a673296c2bc6a4fe4d12a3f213a5a83e", "ad755419af203f8bdc63c542c3171cffcee139ca74672ef09a71fe8e540a904d", (
        ("import json\nfrom typing import Any\n\nfrom .capture_acceptance_policy import FRONT_RESERVE_POLICY\n\n_U64_MAX = 2**64 - 1\n_ACTION_FIELDS = {\"type\", \"endpoint\", \"packet\", \"slot\", \"deadline_after_us\", \"allow_stream_data\"}\n", "import json\nfrom typing import Any\n\nfrom .capture_acceptance_policy import FRONT_RESERVE_POLICY, FRONT_LIGHT_POLICY, validate_front_capture_run\n\n_U64_MAX = 2**64 - 1\n_ACTION_FIELDS = {\"type\", \"endpoint\", \"packet\", \"slot\", \"deadline_after_us\", \"allow_stream_data\"}\n"),
        ("                     omissions: Mapping[int, Mapping[str, str]],\n                     events: list[dict[str, str]]) -> tuple[dict[int, dict[str, Any]], set[int]]:\n    \"\"\"Bind every original action to its shorter construction and original socket windows.\"\"\"\n    start = run[\"defense_start_monotonic_ns\"]\n    actions, windows = {}, {}\n    for event in events:\n", "                     omissions: Mapping[int, Mapping[str, str]],\n                     events: list[dict[str, str]]) -> tuple[dict[int, dict[str, Any]], set[int]]:\n    \"\"\"Bind every original action to its shorter construction and original socket windows.\"\"\"\n    marker = validate_front_capture_run(run)\n    if marker[\"policy\"] not in {FRONT_RESERVE_POLICY, FRONT_LIGHT_POLICY}:\n        raise ValueError(\"FRONT construction evidence requires its exact V4 or V5 source policy\")\n    expected_policy = marker[\"policy\"]\n    start = run[\"defense_start_monotonic_ns\"]\n    actions, windows = {}, {}\n    for event in events:\n"),
        ("                                      if expired else {\"transport_action\"})\n            if (event.get(\"outcome\") not in {\"registered\", \"expired_before_registration\"}\n                or set(detail) != fields or type(detail.get(\"schema_version\")) is not int\n                or detail[\"schema_version\"] != 1 or detail.get(\"policy\") != FRONT_RESERVE_POLICY\n                or type(detail.get(\"preparation_reserve_us\")) is not int or detail[\"preparation_reserve_us\"] != 1000):\n                raise ValueError(\"FRONT V4 construction window changes its closed contract\")\n            action = detail[\"original_action\" if expired else \"transport_action\"]\n", "                                      if expired else {\"transport_action\"})\n            if (event.get(\"outcome\") not in {\"registered\", \"expired_before_registration\"}\n                or set(detail) != fields or type(detail.get(\"schema_version\")) is not int\n                or detail[\"schema_version\"] != 1 or detail.get(\"policy\") != expected_policy\n                or type(detail.get(\"preparation_reserve_us\")) is not int or detail[\"preparation_reserve_us\"] != 1000):\n                raise ValueError(\"FRONT V4 construction window changes its closed contract\")\n            action = detail[\"original_action\" if expired else \"transport_action\"]\n"),
    )),
    "traffic": ("7210b7da27e5d1129e0a2c754fe903e5f151057b5ff0393f814e0ae311e47082", "e6572e50928332ce97a7470c56fb9e1f6dbab018a06737eba9bd5d1d90a3f2c2", (
        ("FIELD = \"buflo_duration_policy\"\nPROVENANCE_PATH = budget.PARAMETER_PATH + \".provenance.json\"\nPROVENANCE_SHA256 = \"b69339c0b59f09f6e629eb8a44909c09d0d55dfb9e030f1909dad8280bf63278\"\n\n\ndef policy(value: Any) -> str | None:\n    if value is not None and (type(value) is not str or value != budget.POLICY):\n        raise ValueError(\"capture traffic requires the exact prospective BuFLO200 policy\")\n    return value\n\n", "FIELD = \"buflo_duration_policy\"\nPROVENANCE_PATH = budget.PARAMETER_PATH + \".provenance.json\"\nPROVENANCE_SHA256 = \"b69339c0b59f09f6e629eb8a44909c09d0d55dfb9e030f1909dad8280bf63278\"\nCADENCE64_PROVENANCE_PATH = budget.CADENCE64_PARAMETER_PATH + \".provenance.json\"\nCADENCE64_PROVENANCE_SHA256 = \"4276f8e06e8a5129e6f94463f64743edfd6cc06dd9519223196fa4eafdea362c\"\n\n\ndef parameter_files(selected: str) -> tuple[tuple[str, str], tuple[str, str]]:\n    \"\"\"Return one explicitly selected finite parameter/provenance pair.\"\"\"\n    selected = policy(selected)\n    if selected == budget.POLICY:\n        return ((budget.PARAMETER_PATH, budget.PARAMETER_SHA256),\n                (PROVENANCE_PATH, PROVENANCE_SHA256))\n    if selected == budget.CADENCE64_POLICY:\n        return ((budget.CADENCE64_PARAMETER_PATH, budget.CADENCE64_PARAMETER_SHA256),\n                (CADENCE64_PROVENANCE_PATH, CADENCE64_PROVENANCE_SHA256))\n    raise ValueError(\"prospective BuFLO parameters require an explicit policy\")\n\n\ndef policy(value: Any) -> str | None:\n    if value is not None and (type(value) is not str or value not in {budget.POLICY, budget.CADENCE64_POLICY}):\n        raise ValueError(\"capture traffic requires the exact prospective BuFLO200 policy\")\n    return value\n\n"),
        ("    from .rapid_lane_evidence import TRAFFIC_FILES\n    result = dict(TRAFFIC_FILES)\n    if policy(selected) is not None:\n        result[\"buflo_parameters_sha256\"] = (budget.PARAMETER_PATH, budget.PARAMETER_SHA256)\n        result[\"buflo_parameter_provenance_sha256\"] = (PROVENANCE_PATH, PROVENANCE_SHA256)\n    return result\n\n\n", "    from .rapid_lane_evidence import TRAFFIC_FILES\n    result = dict(TRAFFIC_FILES)\n    if policy(selected) is not None:\n        parameter, provenance = parameter_files(selected)\n        result[\"buflo_parameters_sha256\"] = parameter\n        result[\"buflo_parameter_provenance_sha256\"] = provenance\n    return result\n\n\n"),
        ("    from .supplied_static_preparation import reference\n    if policy(selected) is None:\n        return {}\n    roots = [Path(runtime[name]) for name in (\"execution_root\", \"runtime_source_root\", \"module_root\")]\n    for root in roots:\n        for relative, digest in ((budget.PARAMETER_PATH, budget.PARAMETER_SHA256),\n                                 (PROVENANCE_PATH, PROVENANCE_SHA256)):\n            from .rapid_lane_evidence import _read, _sha\n            if _sha(_read(root / relative)) != digest:\n                raise ValueError(\"BuFLO200 traffic changed its exact frozen parameter/provenance bytes\")\n    return {\"parameters\": reference(roots[0] / budget.PARAMETER_PATH),\n            \"provenance\": reference(roots[0] / PROVENANCE_PATH)}\n", "    from .supplied_static_preparation import reference\n    if policy(selected) is None:\n        return {}\n    parameter, provenance = parameter_files(selected)\n    roots = [Path(runtime[name]) for name in (\"execution_root\", \"runtime_source_root\", \"module_root\")]\n    for root in roots:\n        for relative, digest in (parameter, provenance):\n            from .rapid_lane_evidence import _read, _sha\n            if _sha(_read(root / relative)) != digest:\n                raise ValueError(\"BuFLO200 traffic changed its exact frozen parameter/provenance bytes\")\n    return {\"parameters\": reference(roots[0] / parameter[0]),\n            \"provenance\": reference(roots[0] / provenance[0])}\n"),
        ("def files(selected: str | None = None) -> dict[str, tuple[str, str]]:", "def front_declared(payload: Mapping[str, Any], *, canary: bool = False, mode: str | None = None) -> str | None:\n    from . import front_fixed_configuration as front\n    selected = front.policy(payload)\n    if selected is None:\n        return None\n    if \"static_capture_amendment\" not in payload or FIELD in payload:\n        raise ValueError(\"fixed FRONT requires its separate explicit FRONT-only amendment\")\n    if canary:\n        campaigns = payload.get(\"campaigns\")\n        if (not isinstance(campaigns, list) or len(campaigns) != 1\n            or not isinstance(campaigns[0], Mapping) or campaigns[0].get(\"mode\") != \"front\"\n            or mode is not None and mode != \"front\"):\n            raise ValueError(\"fixed FRONT canary requires only its amended FRONT setting\")\n    elif type(payload.get(\"study_version\")) is not int or payload[\"study_version\"] != 6:\n        raise ValueError(\"fixed FRONT formal plan requires the prospective full-graph study\")\n    return selected\n\n\ndef files(selected: str | None = None, *, front_selected: str | None = None) -> dict[str, tuple[str, str]]:"),
        ("    return result\n\n\ndef plan_files", "    from . import front_fixed_configuration as front\n    if front.validate_policy(front_selected) is not None:\n        if selected is not None:\n            raise ValueError(\"fixed FRONT and BuFLO traffic cannot share a selected plan\")\n        result.update(front_configuration_sha256=(front.CONFIGURATION_PATH, front.CONFIGURATION_SHA256),\n            front_configuration_provenance_sha256=(front.PROVENANCE_PATH, front.PROVENANCE_SHA256),\n            front_configuration_source_sha256=(\"src/qcsd_lab/front_fixed_configuration.py\", \"512bdfeda75bdd305394e4e4580fe065744604f0d3a8e913c521dffef2448cca\"))\n    return result\n\n\ndef plan_files"),
        ("    return files(declared(payload))", "    return files(declared(payload), front_selected=front_declared(payload))"),
        ("    return files(canary_policy(payload, mode))", "    return files(canary_policy(payload, mode), front_selected=front_declared(payload, canary=True, mode=mode))"),
    )),
    "capture_plan": ("98ffc2bc611d6b334cadd0199441a5c8014da4083aff06de6e1c64db30907b05", "4382ae162d65c3383ce87c055a64e503dd8c5c57c6c386a2eec4840675c87178", (
        ("            raise ValueError(\"fixed Tamaraw configuration requires its own complete-graph serial setting\")\n        document[FIELD] = validate_policy(tamaraw_configuration_policy)\n    if buflo_duration_policy is not None:\n        from .buflo_duration_budget import POLICY, PARAMETER_PATH, capture_limits\n        if (type(buflo_duration_policy) is not str or buflo_duration_policy != POLICY\n            or lane.study_version != 6 or lane.role != \"formal\" or static_capture_limits is None):\n            raise ValueError(\"BuFLO200 campaign requires its prospective static formal contract\")\n        if lane.mode == \"buflo\":\n            document[\"defenses\"][0][\"parameters\"] = \"../defense-params/\" + Path(PARAMETER_PATH).name\n        document[\"limits\"] = capture_limits(lane.mode, document[\"limits\"], policy=buflo_duration_policy)\n    if lane.qualification_set is not None:\n        document[\"chaff_qualification_set\"] = lane.qualification_set\n    return yaml.safe_dump(document, sort_keys=False, width=100).encode(\"utf-8\")\n", "            raise ValueError(\"fixed Tamaraw configuration requires its own complete-graph serial setting\")\n        document[FIELD] = validate_policy(tamaraw_configuration_policy)\n    if buflo_duration_policy is not None:\n        from . import buflo_duration_budget as duration\n        from .rapid_capture_traffic import parameter_files\n        if (type(buflo_duration_policy) is not str or buflo_duration_policy not in {duration.POLICY, duration.CADENCE64_POLICY}\n            or lane.study_version != 6 or lane.role != \"formal\" or static_capture_limits is None):\n            raise ValueError(\"BuFLO200 campaign requires its prospective static formal contract\")\n        if lane.mode == \"buflo\":\n            document[\"defenses\"][0][\"parameters\"] = \"../defense-params/\" + Path(parameter_files(buflo_duration_policy)[0][0]).name\n        document[\"limits\"] = duration.capture_limits(lane.mode, document[\"limits\"], policy=buflo_duration_policy)\n    if lane.qualification_set is not None:\n        document[\"chaff_qualification_set\"] = lane.qualification_set\n    return yaml.safe_dump(document, sort_keys=False, width=100).encode(\"utf-8\")\n"),
        ("                         tamaraw_configuration_policy: str | None = None) -> bytes:", "                         tamaraw_configuration_policy: str | None = None,\n                         front_configuration_policy: str | None = None) -> bytes:"),
        ("            tamaraw_configuration_policy=tamaraw_configuration_policy)", "            tamaraw_configuration_policy=tamaraw_configuration_policy,\n            front_configuration_policy=front_configuration_policy)"),
        ("    if buflo_duration_policy is not None:\n", "    if front_configuration_policy is not None:\n        from .front_fixed_configuration import validate_policy, FIELD\n        from .application_response_policy import COMPLETE_APPLICATION_DELIVERY_POLICY\n        if (lane.mode != \"front\" or lane.study_version != 6 or lane.role != \"formal\"\n            or static_capture_limits is None or qualification_delivery_compatibility is not None\n            or application_body_identity_policy != COMPLETE_APPLICATION_DELIVERY_POLICY\n            or tamaraw_configuration_policy is not None or buflo_duration_policy is not None):\n            raise ValueError(\"fixed FRONT configuration requires only its complete-graph formal setting\")\n        document[FIELD] = validate_policy(front_configuration_policy)\n    if buflo_duration_policy is not None:\n"),
    )),
    "chunks": ("bb731e069743406b87ddbb0f4667411a3db16456cb0132947a21287ed6c87f63", "c0eced6275b929cb7b75ccf37e8e8105839bd64ac1566474db3e010c774622f0", (
        ("    if lane.mode != \"tamaraw\" and \"tamaraw_configuration_policy\" in options:\n        options = {**options, \"tamaraw_configuration_policy\": None}\n", "    if lane.mode != \"tamaraw\" and \"tamaraw_configuration_policy\" in options:\n        options = {**options, \"tamaraw_configuration_policy\": None}\n    if lane.mode != \"front\" and \"front_configuration_policy\" in options:\n        options = {**options, \"front_configuration_policy\": None}\n"),
        ("            \"tamaraw_configuration_policy\": value.get(\"tamaraw_configuration_policy\"),\n", "            \"tamaraw_configuration_policy\": value.get(\"tamaraw_configuration_policy\"),\n            \"front_configuration_policy\": value.get(\"front_configuration_policy\"),\n"),
    )),
    "dynamic": ("dce570b9ba7d1ac1ce35431e8a83ba0a93a0daaa4acbe8c0ee61e99e2e27c567", "12ba6b327f278ddef1faaade56b22d5a5b80a388fbf636f9e3cb648607108225", (
        ("def _compatible_reader_sources(producer):\n    \"\"\"Authenticate original reader locations without changing their identity.\"\"\"\n    from . import rapid_fixed_condition_target as target\n    current = _reader_sources()\n    if not isinstance(producer, dict) or set(producer) != set(current):\n        raise ValueError('chunk partial reader unit set changed')\n    package = Path(producer[__name__]['path']).parent\n    if package.name != 'qcsd_lab' or package.parent.name != 'src':\n        raise ValueError('chunk partial original reader lacks its explicit Source package')\n    for name, expected in current.items():\n        ref = producer[name]\n        if (set(ref) != {'path', 'sha256', 'mode'}\n                or Path(ref['path']) != package / (name.rsplit('.', 1)[-1] + '.py')):\n            raise ValueError('chunk partial original reader locations are inconsistent')\n        if name == __name__:\n            target._compatible_code_ref('dynamic', ref, expected)\n        elif name == 'qcsd_lab.rapid_rolling_schedule':\n            if (reference(ref['path']) != ref or reference(expected['path']) != expected\n                    or ref['mode'] != expected['mode'] or ref['sha256'] != expected['sha256'] and\n                    target._parallel_schedule_source_projection(Path(ref['path']).read_bytes()) !=\n                    target._parallel_schedule_source_projection(Path(expected['path']).read_bytes())):\n                raise ValueError('chunk partial scheduling reader changed protected code or full modes')\n        elif (reference(ref['path']) != ref or reference(expected['path']) != expected\n                or any(ref[key] != expected[key] for key in ('sha256', 'mode'))):\n            raise ValueError('chunk partial original/current reader code bytes or full modes changed')\n    return str(package.parent.parent)\n\n", "def _compatible_reader_sources(producer):\n    \"\"\"Authenticate original reader locations without changing their identity.\"\"\"\n    from . import rapid_fixed_condition_target as target\n    current = _reader_sources()\n    if not isinstance(producer, dict) or set(producer) != set(current):\n        raise ValueError('chunk partial reader unit set changed')\n    package = Path(producer[__name__]['path']).parent\n    if package.name != 'qcsd_lab' or package.parent.name != 'src':\n        raise ValueError('chunk partial original reader lacks its explicit Source package')\n    for name, expected in current.items():\n        ref = producer[name]\n        if (set(ref) != {'path', 'sha256', 'mode'}\n                or Path(ref['path']) != package / (name.rsplit('.', 1)[-1] + '.py')):\n            raise ValueError('chunk partial original reader locations are inconsistent')\n        if name == __name__:\n            target._compatible_code_ref('dynamic', ref, expected)\n        elif name == 'qcsd_lab.rapid_rolling_schedule':\n            if (reference(ref['path']) != ref or reference(expected['path']) != expected\n                    or ref['mode'] != expected['mode'] or ref['sha256'] != expected['sha256'] and\n                    target._parallel_schedule_source_projection(Path(ref['path']).read_bytes()) !=\n                    target._parallel_schedule_source_projection(Path(expected['path']).read_bytes())):\n                raise ValueError('chunk partial scheduling reader changed protected code or full modes')\n        elif name in ('qcsd_lab.rapid_slot_chunks', 'qcsd_lab.rapid_capture_plan'):\n            role = 'chunks' if name == 'qcsd_lab.rapid_slot_chunks' else 'capture_plan'\n            if (reference(ref['path']) != ref or reference(expected['path']) != expected\n                    or ref['mode'] != expected['mode']):\n                raise ValueError('chunk partial original/current reader bytes or full modes changed')\n            if ref['sha256'] != expected['sha256'] and not target._mixed_epoch().compatible_legacy_reader(role, ref, expected):\n                raise ValueError('chunk partial reader differs from its finite exact historical bytes')\n        elif (reference(ref['path']) != ref or reference(expected['path']) != expected\n                or any(ref[key] != expected[key] for key in ('sha256', 'mode'))):\n            raise ValueError('chunk partial original/current reader code bytes or full modes changed')\n    return str(package.parent.parent)\n\n"),
    )),
}


def legacy_source_projection(role, raw, *, historical_sha256):
    """Restore only one registered full-byte legacy reader with exact modes."""
    import hashlib
    if role not in _LEGACY_MODULE_INVERSES or type(raw) is not bytes:
        raise ValueError('mixed legacy source role or bytes are malformed')
    old, current, edits = _LEGACY_MODULE_INVERSES[role]
    digest = hashlib.sha256(raw).hexdigest()
    traffic_legacy = '4eb2d2ce5a35005f342befe9fb86dd6dad27980b2635e5372fda227902764542'
    if historical_sha256 not in ({old, traffic_legacy} if role == 'traffic' else {old}):
        raise ValueError('mixed source projection historical SHA is outside the finite registered set')
    if digest == current:
        for before, after in reversed(edits):
            before, after = before.encode(), after.encode()
            if raw.count(after) != 1:
                raise ValueError('mixed source inverse is absent or ambiguous')
            raw = raw.replace(after, before, 1)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != old:
            raise ValueError('mixed source inverse changes protected historical code')
    if role == 'traffic' and historical_sha256 == traffic_legacy and digest == old:
        addition = (
            b'        from . import rapid_quick_profile as quick\n'
            b'        if quick.is_payload(payload):\n'
            b'            quick.validate_profile(payload["scheduling"])\n'
            b'            return value\n'
        )
        if raw.count(addition) != 1:
            raise ValueError('mixed historical traffic quick dispatch is ambiguous')
        raw = raw.replace(addition, b'', 1)
        digest = hashlib.sha256(raw).hexdigest()
    if digest != historical_sha256:
        raise ValueError('mixed source projection does not restore exact historical bytes')
    return raw


def compatible_legacy_reader(role, before, current):
    """Authenticate finite historical code refs, never a runtime/source wildcard."""
    fixed._open(before); fixed._open(current)
    old, successor, _edits = _LEGACY_MODULE_INVERSES[role]
    known = {old}
    if role == 'traffic':
        known.add('4eb2d2ce5a35005f342befe9fb86dd6dad27980b2635e5372fda227902764542')
    if current['sha256'] != successor or before['sha256'] not in known:
        return False
    if type(before['mode']) is not int or type(current['mode']) is not int or before['mode'] != 0o644 or current['mode'] != 0o644:
        raise ValueError('mixed historical reader full mode differs')
    restored = legacy_source_projection(role, Path(current['path']).read_bytes(), historical_sha256=before['sha256'])
    if restored != Path(before['path']).read_bytes():
        raise ValueError('mixed historical reader differs after exact full-byte inverse')
    if role == 'traffic' and before['sha256'] != old:
        from . import rapid_quick_profile as quick
        actual = fixed.reference(Path(quick.__file__))
        fixed._open(actual)
        if actual['sha256'] != '35808d483b82a4da1cd9c22e4a9ef967986dd7ab4ede448f8cd98db9d0c3b25c' or actual['mode'] != 0o644:
            raise ValueError('mixed historical traffic quick dispatcher changed bytes/full mode')
    return True

RECEIPT = {'schema_version': 1, 'policy': BUFLO_POLICY, 'interval_us': 64000,
    'minimum_duration_us': 10000000, 'packet_size': 1200, 'max_events': 10000,
    'duration_budget_us': 640000000}
TARGET_KEYS = {'contract', 'target_identity', 'target_id', 'enrollment', 'classes',
    'membership_dependencies', 'conditions', 'implementations', 'retained_progress',
    'retained_history', 'history_counts_as_target_credit', 'parent', 'declared_at',
    'published_at', 'sources', 'scientific_credit'}
PROGRESS_KEYS = {'contract', 'target', 'target_id', 'parent', 'proofs', 'classes',
    'accepted_rows', 'remaining_vectors', 'target_accepted_count', 'retained_progress',
    'imported_accepted_count', 'retained_history', 'history_counts_as_target_credit',
    'final_target', 'sources', 'published_at', 'aggregate_status'}


def _kind(reference):
    raw = json.loads(fixed._open(reference).read_bytes())
    if not isinstance(raw, dict):
        raise ValueError('mixed target input is not an artifact document')
    return raw.get('artifact_type')


def is_target(reference):
    return _kind(reference) == TARGET_TYPE


def is_progress(reference):
    return _kind(reference) == PROGRESS_TYPE


def is_declaration(value):
    return isinstance(value, dict) and value.get('contract') == CONTRACT


def _sources():
    from . import front_fixed_configuration as front
    from . import front_preparation_evidence as preparation
    return {'base': fixed._sources(), 'mixed': fixed.reference(Path(__file__)),
        'front_configuration': fixed.reference(Path(front.__file__)),
        'front_preparation': fixed.reference(Path(preparation.__file__))}


def _source_files(value):
    current = _sources()
    fixed._keys(value, set(current), 'mixed epoch Source units')
    fixed._compatible_sources(value['base'])
    for role in ('mixed', 'front_configuration', 'front_preparation'):
        fixed._open(value[role]); fixed._open(current[role])
        if any(value[role][key] != current[role][key] for key in ('sha256', 'mode')):
            raise ValueError('mixed epoch reader module bytes or full mode changed')
    return [*value['base'].values(), *[value[role] for role in ('mixed', 'front_configuration', 'front_preparation')]]


def _implementation(reference):
    """Reopen genuine installed/runtime Source binding; never infer from Main."""
    source = fixed._measurement_source(reference)
    runtime = source['binding']['runtime_identity']
    manifest = runtime['source']
    identity = {'native_head': manifest['neqo_commit'],
        'client_sha256': runtime['client_sha256'],
        'image_digest': runtime['collection_image_digest']}
    _implementation_identity(identity)
    if (manifest['neqo_pinned_commit'] != identity['native_head']
            or manifest.get('lab_dirty') is not False
            or manifest.get('neqo_dirty') is not False):
        raise ValueError('mixed implementation lacks its clean exact Native Source')
    return {'reference': reference, 'identity': identity,
        'measurement_source': {**manifest, 'image_digest': identity['image_digest']}}


def _implementation_identity(value):
    fixed._keys(value, {'native_head', 'client_sha256', 'image_digest'}, 'per-mode implementation identity')
    if (not isinstance(value['native_head'], str) or fixed.HEAD.fullmatch(value['native_head']) is None
            or not isinstance(value['client_sha256'], str) or fixed.SHA.fullmatch(value['client_sha256']) is None
            or not isinstance(value['image_digest'], str) or IMAGE.fullmatch(value['image_digest']) is None):
        raise ValueError('per-mode implementation identity needs exact Native/client/image digests')
    return value


def _implementations(refs):
    fixed._keys(refs, fixed.MODES, 'five exact per-mode implementation references')
    return {mode: _implementation(refs[mode]) for mode in fixed.MODES}


def _implementation_files(reference):
    source = fixed._measurement_source(reference)
    return [reference, *source['files'].values(), *source['binding']['read_dependencies']]


def identity(value):
    fixed._keys(value, {'namespace', 'conditions', 'implementations', 'classes', 'slots', 'total'}, 'mixed target identity')
    fixed._keys(value['conditions'], fixed.MODES, 'mixed condition hashes')
    fixed._keys(value['implementations'], fixed.MODES, 'mixed implementation identities')
    if (not isinstance(value['namespace'], str)
            or re.fullmatch(r'[a-z0-9][a-z0-9-]{1,95}', value['namespace']) is None
            or any(not isinstance(v, str) or fixed.SHA.fullmatch(v) is None for v in value['conditions'].values())
            or any(type(value[key]) is not int or value[key] != expected for key, expected in
                (('classes', fixed.CLASSES), ('slots', fixed.SLOTS), ('total', fixed.TOTAL)))):
        raise ValueError('mixed target requires its exact50×5×64 prospective identity')
    for implementation in value['implementations'].values():
        _implementation_identity(implementation)
    return value


def mode_implementation(declaration, mode):
    if mode not in fixed.MODES:
        raise ValueError('mixed target mode is not registered')
    return identity(declaration['target_identity'])['implementations'][mode]


def buflo64_condition(value):
    """Only the finite 64ms/640s tuple is permitted by this new epoch."""
    parameter = value.get('defense_parameters')
    defense = value.get('defense')
    policies = value.get('capture_policies')
    if (value.get('mode') != 'buflo' or not isinstance(defense, dict)
            or defense.get('kind') != 'buflo' or defense.get('baseline') is not False
            or defense.get('parameters_sha256') != PARAMETER_SHA256
            or defense.get('provenance_sha256') != PROVENANCE_SHA256
            or not isinstance(parameter, dict) or parameter.get('kind') != 'buflo'
            or parameter.get('sha256') != PARAMETER_SHA256
            or parameter.get('implementation_scope') != 'client_only_quic'
            or parameter.get('paper_equivalent') is not False
            or not fixed._typed_equal(parameter.get('buflo_duration_budget'), RECEIPT)
            or not isinstance(policies, dict)):
        raise ValueError('mixed BuFLO condition requires exact prospective64ms/640s parameters')
    incoming = policies.get(fixed.BUFLO_FIELD)
    preparation = policies.get(fixed.BUFLO_KERNEL_PREPARATION_FIELD)
    expected_incoming = {'schema_version': 1, 'source': 'bound-preparation-v1',
        'policy': INCOMING_POLICY, 'period_us': 64000, 'cell_bytes': 1200,
        'incoming_release_window_us': 32000, 'scientific_credit': False}
    expected_preparation = {'schema_version': 1, 'source': 'bound-preparation-v1',
        'policy': PREPARATION_POLICY, 'period_us': 64000, 'cell_bytes': 1200,
        'nominal_selection_lead_us': 5000, 'rolling_preparation_after_release_us': 4000,
        'outgoing_physical_window_us': 5000, 'preparation_reserve_us': 1000,
        'tick_zero_before_release': True, 'allow_omissions': False,
        'paper_equivalent': False, 'scientific_credit': False}
    if (not fixed._typed_equal(incoming, expected_incoming)
            or not fixed._typed_equal(preparation, expected_preparation)
            or not fixed._typed_equal(value.get('resolved_configuration', {}).get('defense'),
                {'kind': 'buflo', 'parameters': {'sha256': PARAMETER_SHA256}})
            or value.get('application_body_identity_policy') != 'complete-current-application-delivery-v1'):
        raise ValueError('mixed BuFLO condition lacks its exact new source-bound timing/body identity')
    return value


def front5_condition(value):
    """Bind the complete finite FRONT tuple and its pure-padding V5 marker."""
    from . import front_fixed_configuration as front
    from .capture_acceptance_policy import validate_front_capture_marker
    if (front.POLICY != FRONT_POLICY
            or front.CONFIGURATION_SHA256 != FRONT_CONFIGURATION_SHA256
            or front.PROVENANCE_SHA256 != FRONT_PROVENANCE_SHA256
            or front.configuration_sha256() != FRONT_CONFIGURATION_SHA256
            or value.get('mode') != 'front'
            or not fixed._typed_equal(value.get('defense'), {'name': 'front', 'kind': 'front', 'baseline': False})
            or value.get('defense_parameters') is not None
            or value.get('tamaraw_configuration_policy') is not None
            or value.get('application_body_identity_policy') != 'complete-current-application-delivery-v1'
            or value.get('application_response_policy') != 'completed-terminal-http-errors-v1'
            or value.get('primary_document_identity_policy') != 'variable-primary-document-body-v1'
            or not isinstance(value.get('capture_policies'), dict)
            or set(value['capture_policies']) != {fixed.FRONT_FIELD}
            or not fixed._typed_equal(value.get('resolved_configuration'), front.resolved_configuration())):
        raise ValueError('mixed FRONT requires its complete finite450/600 sigma1–4 and10ms configuration')
    marker = validate_front_capture_marker(value['capture_policies'][fixed.FRONT_FIELD])
    if (marker.get('policy') != FRONT_POLICY
            or marker.get('configuration_sha256') != FRONT_CONFIGURATION_SHA256):
        raise ValueError('mixed FRONT lacks its exact V5 source-bound Native marker')
    front.validate_run({'resolved_configuration': value['resolved_configuration'], fixed.FRONT_FIELD: marker},
        selected_policy=FRONT_POLICY)
    return value


def _front_amended(declarations, old):
    return not fixed._typed_equal(declarations['front'], old['conditions']['front'])


def capture_limits(original, condition):
    buflo64_condition(condition)
    limits = fixed.budgets.valid_limits(original)
    if (type(limits.get('timeout_seconds')) is not int or limits['timeout_seconds'] != 120
            or type(limits.get('capture_seconds')) is not int or limits['capture_seconds'] != 180):
        raise ValueError('mixed BuFLO caps must derive from original120/180 seconds')
    return {**limits, 'timeout_seconds': 680, 'capture_seconds': 740}


def _retained(progress_ref):
    if _kind(progress_ref) != fixed.PROGRESS_TYPE:
        raise ValueError('mixed epoch imports only an original V1 fixed-target progress')
    progress = fixed.validate_progress(progress_ref)
    if _kind(progress['target']) != fixed.TARGET_TYPE:
        raise ValueError('mixed epoch retained target must keep its original V1 role')
    old = fixed.validate_target(progress['target'])
    if any(row['mode'] == 'buflo' for row in progress['accepted_rows']):
        raise ValueError('mixed epoch requires BuFLO empty; old BuFLO credit cannot be promoted')
    return progress, old


def _unchanged(retained, old, declarations, implementations, rows):
    if rows[:len(old['classes'])] != old['classes'] or len(rows) < len(old['classes']):
        raise ValueError('mixed epoch changed retained class order, original graphs or admission caps')
    front_amended = _front_amended(declarations, old)
    for mode in UNCHANGED:
        if mode == 'front' and front_amended:
            continue
        if (not fixed._typed_equal(declarations[mode], old['conditions'][mode])
                or implementations[mode]['identity']['native_head'] != old['target_identity']['native_head']
                or implementations[mode]['identity']['client_sha256'] != old['target_identity']['client_sha256']):
            raise ValueError('mixed epoch changed an unchanged-mode condition or Native/client')
    if front_amended:
        if any(row['mode'] == 'front' for row in retained['accepted_rows']):
            raise ValueError('mixed FRONT amendment requires Front empty; old Front credit cannot be promoted')
        before_front = old['conditions']['front']['identity']
        after_front = front5_condition(declarations['front']['identity'])
        from . import front_fixed_configuration as front
        from .capture_acceptance_policy import FRONT_RESERVE_POLICY, validate_front_capture_marker
        old_marker = validate_front_capture_marker(before_front.get('capture_policies', {}).get(fixed.FRONT_FIELD))
        expected_old_defense = {'kind': 'front', 'n_client_packets': 900, 'n_server_packets': 1200,
            'packet_size': 1200, 'peak_minimum_seconds': 0.1, 'peak_maximum_seconds': 2.5}
        if (old_marker['policy'] != FRONT_RESERVE_POLICY
                or not fixed._typed_equal(before_front.get('resolved_configuration', {}).get('defense'), expected_old_defense)
                or type(before_front['resolved_configuration'].get('control_interval_us')) is not int
                or before_front['resolved_configuration']['control_interval_us'] != 5000):
            raise ValueError('mixed FRONT V5 requires the exact original V4 Native tuple and source marker')
        expected_front = deepcopy(before_front)
        expected_front['resolved_configuration']['control_interval_us'] = 10000
        expected_front['resolved_configuration']['defense'] = front.resolved_configuration()['defense']
        expected_front['capture_policies'][fixed.FRONT_FIELD] = after_front['capture_policies'][fixed.FRONT_FIELD]
        if not fixed._typed_equal(after_front, expected_front):
            raise ValueError('mixed FRONT changed values outside its declared count/sigma/control/window amendment')
        if (implementations['front']['identity']['native_head'] == old['target_identity']['native_head']
                or implementations['front']['identity']['client_sha256'] == old['target_identity']['client_sha256']):
            raise ValueError('new FRONT condition requires its actual successor Native/client identities')
    buflo64_condition(declarations['buflo']['identity'])
    before = old['conditions']['buflo']['identity']; after = declarations['buflo']['identity']
    expected = deepcopy(before)
    if (before['defense'].get('parameters_sha256') != fixed.duration.PARAMETER_SHA256
            or not fixed._typed_equal(before['defense_parameters'].get('buflo_duration_budget'), fixed.duration.RECEIPT)):
        raise ValueError('mixed BF64 epoch requires its exact original20ms/200s predecessor condition')
    expected['defense'].update(parameters_sha256=PARAMETER_SHA256,
        provenance_sha256=PROVENANCE_SHA256)
    if 'input_policy' in after['defense']:
        expected['defense']['input_policy'] = 'reviewed-buflo-fixed-cadence64-duration640-study-candidate-v1'
    expected['resolved_configuration']['defense']['parameters'] = {'sha256': PARAMETER_SHA256}
    expected['defense_parameters'].update(sha256=PARAMETER_SHA256, buflo_duration_budget=dict(RECEIPT))
    expected['capture_policies'].update({fixed.BUFLO_FIELD: after['capture_policies'][fixed.BUFLO_FIELD],
        fixed.BUFLO_KERNEL_PREPARATION_FIELD: after['capture_policies'][fixed.BUFLO_KERNEL_PREPARATION_FIELD]})
    if not fixed._typed_equal(after, expected):
        raise ValueError('mixed BF64 epoch changed values outside its declared cadence/budget/marker amendment')
    new = implementations['buflo']['identity']
    if (new['native_head'] == old['target_identity']['native_head']
            or new['client_sha256'] == old['target_identity']['client_sha256']):
        raise ValueError('new BuFLO condition requires its actual successor Native/client identities')


@fixed._owned
def publish_target(*, namespace, retained_progress, buflo_condition, implementations,
                   output, enrollment=None, parent=None, front_condition=None):
    retained, old = _retained(retained_progress)
    enrollment = old['enrollment'] if enrollment is None else enrollment
    condition_refs = {**{m: old['conditions'][m]['reference'] for m in UNCHANGED}, 'buflo': buflo_condition}
    if front_condition is not None:
        condition_refs['front'] = front_condition
    declarations = fixed._conditions(condition_refs)
    bound = _implementations(implementations)
    rows, dependencies = fixed._classes(enrollment)
    _unchanged(retained, old, declarations, bound, rows)
    declared = datetime.now(timezone.utc).isoformat()
    definition = identity({'namespace': namespace,
        'conditions': {m: declarations[m]['identity_sha256'] for m in fixed.MODES},
        'implementations': {m: bound[m]['identity'] for m in fixed.MODES},
        'classes': fixed.CLASSES, 'slots': fixed.SLOTS, 'total': fixed.TOTAL})
    if parent is not None:
        previous = validate_target(parent)
        if (not fixed._typed_equal(definition, previous['target_identity'])
                or declarations != previous['conditions'] or bound != previous['implementations']
                or retained_progress != previous['retained_progress']
                or rows[:len(previous['classes'])] != previous['classes']
                or len(rows) <= len(previous['classes'])):
            raise ValueError('mixed target extension relabelled an implementation or original class')
        declared = previous['declared_at']
    sources = _sources()
    value = {'contract': CONTRACT, 'target_identity': definition, 'target_id': fixed._digest(definition),
        'enrollment': enrollment, 'classes': rows, 'membership_dependencies': dependencies,
        'conditions': declarations, 'implementations': bound, 'retained_progress': retained_progress,
        'retained_history': old['retained_history'], 'history_counts_as_target_credit': False,
        'parent': parent, 'declared_at': declared, 'published_at': datetime.now(timezone.utc).isoformat(),
        'sources': sources, 'scientific_credit': False}
    files = [retained_progress, enrollment, *implementations.values(), buflo_condition,
        *([] if front_condition is None else [front_condition]),
        *_source_files(sources), *old['retained_history']]
    for reference in implementations.values(): files.extend(_implementation_files(reference))
    for condition in declarations.values():
        descriptor = fixed._document(condition['reference'], fixed.CONDITION_TYPE)
        files.extend([condition['reference'], descriptor['configuration'], descriptor['run']])
    if parent is not None: files.append(parent)
    fixed._membership_close(dependencies)
    return fixed._write(output, TARGET_TYPE, value, files)


@fixed._owned
def validate_target(reference, _seen=None):
    context = current_context(); key = ('mixed-target-validated', fixed._digest(reference))
    if context.has(key): return context.get(key)
    seen = set() if _seen is None else _seen
    if reference['path'] in seen: raise ValueError('mixed target ancestry is cyclic')
    seen.add(reference['path']); value = fixed._document(reference, TARGET_TYPE)
    fixed._keys(value, TARGET_KEYS, 'mixed target declaration')
    _source_files(value['sources'])
    retained, old = _retained(value['retained_progress'])
    rows, dependencies = fixed._classes(value['enrollment'])
    declarations = fixed._conditions({m: r['reference'] for m, r in value['conditions'].items()})
    bound = _implementations({m: r['reference'] for m, r in value['implementations'].items()})
    definition = identity(value['target_identity'])
    _unchanged(retained, old, declarations, bound, rows)
    if (value['contract'] != CONTRACT or value['scientific_credit'] is not False
            or value['history_counts_as_target_credit'] is not False
            or not fixed._typed_equal(value['classes'], rows)
            or not fixed._compatible_membership(value['membership_dependencies'], dependencies, value['sources']['base'])
            or not fixed._typed_equal(value['conditions'], declarations)
            or not fixed._typed_equal(value['implementations'], bound)
            or value['target_id'] != fixed._digest(definition)
            or definition['conditions'] != {m: r['identity_sha256'] for m, r in declarations.items()}
            or not fixed._typed_equal(definition['implementations'], {m: r['identity'] for m, r in bound.items()})
            or value['retained_history'] != old['retained_history']
            or not fixed._time(old['published_at']) <= fixed._time(value['declared_at'])
                <= fixed._time(value['published_at']) <= datetime.now(timezone.utc)):
        raise ValueError('mixed target authority, implementations, conditions or original graphs changed')
    fixed._membership_close(dependencies)
    if value['parent'] is not None:
        previous = validate_target(value['parent'], seen)
        if (not fixed._typed_equal(definition, previous['target_identity'])
                or value['conditions'] != previous['conditions'] or bound != previous['implementations']
                or value['retained_progress'] != previous['retained_progress']
                or value['declared_at'] != previous['declared_at']
                or rows[:len(previous['classes'])] != previous['classes']
                or len(rows) <= len(previous['classes'])
                or fixed._time(value['published_at']) < fixed._time(previous['published_at'])):
            raise ValueError('mixed target extension changed its original epoch')
    return context.remember(key, value)


def _select(declaration, proofs):
    retained, old = _retained(declaration['retained_progress'])
    if (not isinstance(proofs, list) or proofs[:len(retained['proofs'])] != retained['proofs']):
        raise ValueError('mixed progress must retain the complete original proof prefix')
    members = {r['candidate_id']: r for r in declaration['classes']}
    rows = []; slots = set(); physical = set()
    for proof_index, proof in enumerate(proofs):
        audit = fixed.validate_audit(proof)
        for original in audit['rows']:
            mode = original['mode']; member = members.get(original['candidate_id'])
            if mode not in fixed.MODES or member is None:
                raise ValueError('mixed trace lacks an exact declared mode/class')
            condition = declaration['conditions'][mode]['identity']
            implementation = mode_implementation(declaration, mode)
            if (original['workload_id'] != member['workload_id']
                    or original['original_graph_sha256'] != member['original_graph_sha256']
                    or not fixed._capture_limits_equal(original['capture_limits'], fixed._capture_limits(
                        mode, member['capture_limits'], condition))
                    or original['client_sha256'] != implementation['client_sha256']
                    or original['measurement_source']['neqo_commit'] != implementation['native_head']
                    or original['measurement_source']['neqo_pinned_commit'] != implementation['native_head']
                    or not fixed._typed_equal(original['condition'], condition)
                    or type(original['logical_visit']) is not int
                    or not 0 <= original['logical_visit'] < fixed.SLOTS):
                raise ValueError('mixed trace changed full graph, caps, per-mode Native/client, condition or slot')
            row = {**original, 'class_index': member['class_index'], 'proof': proof,
                'condition_sha256': fixed._digest(original['condition'])}
            imported = proof_index < len(retained['proofs'])
            if imported:
                if (mode not in UNCHANGED or len(rows) >= len(retained['accepted_rows'])
                        or not fixed._typed_equal(row, retained['accepted_rows'][len(rows)])):
                    raise ValueError('mixed import altered an original accepted row or promoted old BuFLO')
            else:
                if original['measurement_source'] != declaration['implementations'][mode]['measurement_source']:
                    raise ValueError('new mixed trace changed its declared per-mode image or measurement Source')
                amended = mode == 'buflo' or mode == 'front' and _front_amended(declaration['conditions'], old)
                if amended and fixed._time(original['intent_started_at']) < fixed._time(declaration['declared_at']):
                    raise ValueError('mixed target cannot retrocredit an earlier amended-mode intent')
            key = (member['class_index'], mode, original['logical_visit'])
            sample = (original['result_root'], original['sample_id'])
            if key in slots or sample in physical:
                raise ValueError('mixed target repeats an original physical sample or logical slot')
            slots.add(key); physical.add(sample); rows.append(row)
    if rows[:len(retained['accepted_rows'])] != retained['accepted_rows']:
        raise ValueError('mixed progress lost an original accepted row')
    return rows, retained


@fixed._owned
def initialize_progress(*, target, proofs, output):
    declaration = validate_target(target)
    retained, _ = _retained(declaration['retained_progress'])
    if proofs != retained['proofs']:
        raise ValueError('mixed migration imports exactly original proofs; new captures append afterward')
    rows, retained = _select(declaration, proofs)
    sources = _sources()
    value = {'contract': CONTRACT, 'target': target, 'target_id': declaration['target_id'], 'parent': None,
        'proofs': proofs, 'classes': declaration['classes'], 'accepted_rows': rows,
        'remaining_vectors': fixed._vectors(declaration['classes'], rows), 'target_accepted_count': len(rows),
        'retained_progress': declaration['retained_progress'], 'imported_accepted_count': len(retained['accepted_rows']),
        'retained_history': declaration['retained_history'], 'history_counts_as_target_credit': False,
        'final_target': fixed.TOTAL, 'sources': sources, 'published_at': datetime.now(timezone.utc).isoformat(),
        'aggregate_status': fixed._aggregate(declaration['classes'], rows)}
    return fixed._write(output, PROGRESS_TYPE, value, [target, declaration['retained_progress'],
        *proofs, *_source_files(sources)])


@fixed._owned
def validate_progress(reference, _seen=None):
    context = current_context(); key = ('mixed-progress-validated', fixed._digest(reference))
    if context.has(key): return context.get(key)
    seen = set() if _seen is None else _seen
    if reference['path'] in seen: raise ValueError('mixed progress ancestry is cyclic')
    seen.add(reference['path']); value = fixed._document(reference, PROGRESS_TYPE)
    fixed._keys(value, PROGRESS_KEYS, 'mixed target progress')
    declaration = validate_target(value['target']); _source_files(value['sources'])
    rows, retained = _select(declaration, value['proofs'])
    if (value['contract'] != CONTRACT or value['target_id'] != declaration['target_id']
            or not fixed._typed_equal(value['classes'], declaration['classes'])
            or not fixed._typed_equal(value['accepted_rows'], rows)
            or not fixed._typed_equal(value['remaining_vectors'], fixed._vectors(declaration['classes'], rows))
            or type(value['target_accepted_count']) is not int or value['target_accepted_count'] != len(rows)
            or value['retained_progress'] != declaration['retained_progress']
            or type(value['imported_accepted_count']) is not int
            or value['imported_accepted_count'] != len(retained['accepted_rows'])
            or value['retained_history'] != declaration['retained_history']
            or value['history_counts_as_target_credit'] is not False
            or type(value['final_target']) is not int or value['final_target'] != fixed.TOTAL
            or value['aggregate_status'] != fixed._aggregate(declaration['classes'], rows)
            or not fixed._time(declaration['published_at']) <= fixed._time(value['published_at']) <= datetime.now(timezone.utc)
            or any(fixed._time(fixed.validate_audit(p)['completed_at']) > fixed._time(value['published_at']) for p in value['proofs'])):
        raise ValueError('mixed progress changed imported proofs, accepted conditions or remaining slots')
    if value['parent'] is not None:
        previous = validate_progress(value['parent'], seen)
        if (previous['target_id'] != value['target_id']
                or value['proofs'][:len(previous['proofs'])] != previous['proofs']
                or rows[:len(previous['accepted_rows'])] != previous['accepted_rows']
                or value['classes'][:len(previous['classes'])] != previous['classes']
                or fixed._time(value['published_at']) < fixed._time(previous['published_at'])):
            raise ValueError('mixed progress rewrote retained proof/class/slot ancestry')
    elif value['proofs'] != retained['proofs']:
        raise ValueError('initial mixed progress added captures outside original migration')
    return context.remember(key, value)


@fixed._owned
def append_progress(*, progress, proofs, output, target=None):
    previous = validate_progress(progress)
    target_ref = previous['target'] if target is None else target
    declaration = validate_target(target_ref)
    if (declaration['target_id'] != previous['target_id']
            or declaration['classes'][:len(previous['classes'])] != previous['classes']):
        raise ValueError('mixed append changed fixed conditions, implementations or class mapping')
    if not isinstance(proofs, list): raise ValueError('mixed new proof list has another schema')
    all_proofs = previous['proofs'] + proofs; rows, _ = _select(declaration, all_proofs)
    if rows[:len(previous['accepted_rows'])] != previous['accepted_rows']:
        raise ValueError('mixed append relabelled original accepted rows')
    sources = _sources()
    value = {**previous, 'target': target_ref, 'parent': progress, 'proofs': all_proofs,
        'classes': declaration['classes'], 'accepted_rows': rows, 'target_accepted_count': len(rows),
        'remaining_vectors': fixed._vectors(declaration['classes'], rows), 'sources': sources,
        'published_at': datetime.now(timezone.utc).isoformat(),
        'aggregate_status': fixed._aggregate(declaration['classes'], rows)}
    return fixed._write(output, PROGRESS_TYPE, value, [progress, target_ref, *all_proofs, *_source_files(sources)])


@fixed._owned
def input_files(progress):
    value = validate_progress(progress); files = {}
    def add(reference):
        fixed._open(reference); old = files.get(reference['path'])
        if old is not None and old != reference: raise ValueError('mixed dependency aliases disagree')
        files[reference['path']] = reference
    add(progress)
    for reference in fixed.input_files(value['retained_progress']): add(reference)
    def target_inputs(reference):
        add(reference); declaration = validate_target(reference)
        for item in [declaration['enrollment'], declaration['retained_progress'],
                *_source_files(declaration['sources']), *declaration['retained_history'],
                *declaration['membership_dependencies']['files']]: add(item)
        for tree in declaration['membership_dependencies']['trees']:
            for name, member in tree['members'].items():
                if member['kind'] == 'file': add({'path': str(Path(tree['path']) / name),
                    'sha256': member['sha256'], 'mode': member['mode']})
        for condition in declaration['conditions'].values():
            add(condition['reference']); raw = fixed._document(condition['reference'], fixed.CONDITION_TYPE)
            add(raw['configuration']); add(raw['run'])
        for implementation in declaration['implementations'].values():
            add(implementation['reference'])
            source = fixed._measurement_source(implementation['reference'])
            for item in source['files'].values(): add(item)
            for item in source['binding']['read_dependencies']: add(item)
        for row in declaration['classes']: add(row['original_manifest'])
        if declaration['parent'] is not None: target_inputs(declaration['parent'])
    target_inputs(value['target'])
    for proof in value['proofs']:
        add(proof); audit = fixed.validate_audit(proof)
        for item in [audit['source_binding'], *audit['read_dependencies']]: add(item)
        source = fixed._measurement_source(audit['source_binding'])
        for item in source['files'].values(): add(item)
        for item in source['binding']['read_dependencies']: add(item)
    if value['parent'] is not None:
        for item in input_files(value['parent']): add(item)
    return [files[key] for key in sorted(files)]


@fixed._owned
def directory_dependencies(progress):
    value = validate_progress(progress); result = {}
    def add(row):
        key = (row['path'], row['kind']); old = result.get(key)
        if old is not None and old != row: raise ValueError('mixed directory aliases disagree')
        result[key] = row
    for row in fixed.directory_dependencies(value['retained_progress']): add(row)
    def target_trees(reference):
        declaration = validate_target(reference)
        for tree in declaration['membership_dependencies']['trees']:
            add({'path': tree['path'], 'kind': 'complete-membership-tree',
                'ignore_git': tree['ignore_git'], 'members': tree['members']})
        for implementation in declaration['implementations'].values():
            source = fixed._measurement_source(implementation['reference'])
            for row in source['binding']['directory_dependencies']: add({'kind': 'shallow-directory', **row})
        if declaration['parent'] is not None: target_trees(declaration['parent'])
    target_trees(value['target'])
    for proof in value['proofs']:
        for row in fixed.validate_audit(proof)['directory_dependencies']: add({'kind': 'shallow-directory', **row})
    if value['parent'] is not None:
        for row in directory_dependencies(value['parent']): add(row)
    return [result[key] for key in sorted(result)]


@fixed._owned
def publish_final(progress, output):
    facts = fixed.final_coverage(progress); value = validate_progress(progress)
    declaration = validate_target(value['target'])
    files = input_files(progress); directories = directory_dependencies(progress)
    fixed._check_action()
    return fixed._write(output, CORPUS_TYPE, {'contract': CONTRACT, **facts,
        'implementations': declaration['implementations'], 'retained_progress': value['retained_progress'],
        'imported_accepted_count': value['imported_accepted_count'], 'accepted_rows': value['accepted_rows'],
        'read_dependencies': files, 'directory_dependencies': directories, 'sources': _sources(),
        'published_at': datetime.now(timezone.utc).isoformat(), 'scientific_credit': True}, files)
